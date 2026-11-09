---
title: "Sensitive Data Stored Unencrypted in Private Storage (MASWE-0001)"
date: 2026-11-08 12:04:00 +0000
summary: "Testing Android and iOS apps for plaintext tokens, secrets and PII in the sandbox: SharedPreferences, Room, WebView, Data Protection, Keychain, App Groups."
refs: [MASWE-0001, MASVS-STORAGE-1, MASVS-STORAGE-2, CWE-312, CWE-922]
tags: [android, ios, masvs-storage, data-protection, sandbox, frida]
---

Part of the [MASVS-STORAGE-1 series](/mobile/masvs-storage-1-secure-storage-guide/). This note covers the most common storage weakness in mobile apps: sensitive data written into the app's own sandbox without encryption, or with protection that does not hold up. It includes every OWASP Knowledge, Test and Best Practice item linked to [MASWE-0001](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/), for both Android and iOS.

## Contents

- [Overview](#overview)
- [Modes of introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Internal storage (MASTG-KNOW-0041)](#android-internal-storage-mastg-know-0041)
  - [Android: Shared Preferences (MASTG-KNOW-0036)](#android-shared-preferences-mastg-know-0036)
  - [Android: SQLite databases (MASTG-KNOW-0037)](#android-sqlite-databases-mastg-know-0037)
  - [Android: WebViews (MASTG-KNOW-0018)](#android-webviews-mastg-know-0018)
  - [Android: Accessing the app sandbox](#android-accessing-the-app-sandbox)
  - [iOS: App Sandbox Directories (MASTG-KNOW-0108)](#ios-app-sandbox-directories-mastg-know-0108)
  - [iOS: File System APIs and Data Protection (MASTG-KNOW-0091)](#ios-file-system-apis-and-data-protection-mastg-know-0091)
  - [iOS: Keychain Services (MASTG-KNOW-0057)](#ios-keychain-services-mastg-know-0057)
  - [iOS: App Extensions, App Groups and Shared Keychain (MASTG-KNOW-0082)](#ios-app-extensions-app-groups-and-shared-keychain-mastg-know-0082)
  - [iOS: Accessing the app sandbox](#ios-accessing-the-app-sandbox)
- [Tests](#tests)
  - [MASTG-TEST-0207: Runtime Storage of Unencrypted Data in the App Sandbox (Android)](#mastg-test-0207-runtime-storage-of-unencrypted-data-in-the-app-sandbox-android)
  - [MASTG-TEST-0287: Runtime Storage of Unencrypted Data via the SharedPreferences API (Android)](#mastg-test-0287-runtime-storage-of-unencrypted-data-via-the-sharedpreferences-api-android)
  - [MASTG-TEST-0304: References to Sensitive Data Unencrypted via Android Room Database (Android)](#mastg-test-0304-references-to-sensitive-data-unencrypted-via-android-room-database-android)
  - [MASTG-TEST-0305: Sensitive Data Stored Unencrypted via DataStore (Android)](#mastg-test-0305-sensitive-data-stored-unencrypted-via-datastore-android)
  - [MASTG-TEST-0306: References to Sensitive Data Stored Unencrypted via Android Room DB (Android)](#mastg-test-0306-references-to-sensitive-data-stored-unencrypted-via-android-room-db-android)
  - [MASTG-TEST-0320: WebViews Not Cleaning Up Sensitive Data (Android)](#mastg-test-0320-webviews-not-cleaning-up-sensitive-data-android)
  - [MASTG-TEST-0299: Data Protection Classes for Files in Private Storage (iOS)](#mastg-test-0299-data-protection-classes-for-files-in-private-storage-ios)
  - [MASTG-TEST-0300: References to APIs for Storing Unencrypted Data in Private Storage (iOS)](#mastg-test-0300-references-to-apis-for-storing-unencrypted-data-in-private-storage-ios)
  - [MASTG-TEST-0301: Runtime Use of APIs for Storing Unencrypted Data in Private Storage (iOS)](#mastg-test-0301-runtime-use-of-apis-for-storing-unencrypted-data-in-private-storage-ios)
  - [MASTG-TEST-0302: Sensitive Data Unencrypted in Private Storage Files (iOS)](#mastg-test-0302-sensitive-data-unencrypted-in-private-storage-files-ios)
  - [MASTG-TEST-0388: References to Sensitive Data Stored Unprotected in Shared App Group Containers (iOS)](#mastg-test-0388-references-to-sensitive-data-stored-unprotected-in-shared-app-group-containers-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0050: Store Data Encrypted in App Sandbox Directory (Android)](#mastg-best-0050-store-data-encrypted-in-app-sandbox-directory-android)
  - [MASTG-BEST-0028: WebViews Cache Cleanup (Android)](#mastg-best-0028-webviews-cache-cleanup-android)
  - [MASTG-BEST-0024: Store Data Encrypted in App Sandbox Directory (iOS)](#mastg-best-0024-store-data-encrypted-in-app-sandbox-directory-ios)
  - [MASTG-BEST-0068: Secure Data Sharing Between App Extensions and Containing Apps (iOS)](#mastg-best-0068-secure-data-sharing-between-app-extensions-and-containing-apps-ios)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

Every Android and iOS app gets a private directory that other apps cannot read: `/data/data/<package>/` (or `/data/user/<id>/<package>/`) on Android, and the Data container under `/var/mobile/Containers/Data/Application/<UUID>/` on iOS. Developers tend to treat that sandbox as the security boundary and write session tokens, PII, and sometimes passwords into it in plaintext.

The sandbox is a boundary against **other apps**. It is not a boundary against:

- **A rooted or jailbroken device**, whether rooted by the user, by malware with a privilege-escalation exploit, or by an attacker who has the device.
- **Backups**: adb backup or device-to-device transfer on Android, and iTunes/Finder or iCloud backups on iOS, unless the data is excluded (MASWE-0006).
- **Forensic extraction** of a seized or stolen device. On iOS this is constrained by Data Protection, which is why the protection class of each file matters.
- **The app's own mistakes**: files shared through a misconfigured `FileProvider`, the deprecated world-readable file modes, App Group containers shared with extensions, or Keychain items with weak accessibility attributes.

MASWE-0001 is an **L2** requirement. For apps in that profile (banking, health, identity, the EU Digital Identity Wallet), sensitive data in the sandbox must be encrypted with a key held by the platform keystore and removed when it is no longer needed. Sensitive data here means PII, passwords, cryptographic keys and session tokens. For an L1 app, the same plaintext data is still worth reporting, at lower severity. Credentials and long-lived tokens in plaintext are reportable at any level.

## Modes of introduction

The weakness typically gets in through one of these patterns. Each one maps to a test further down.

| Mode | What it looks like | Where to look |
|------|--------------------|---------------|
| **Data stored unencrypted** | Token, password or PII written as-is to preferences, a database, a plain file, a plist, or `UserDefaults`. | MASTG-TEST-0207, 0287, 0304, 0305, 0306, 0300, 0301, 0302 |
| **Hardcoded encryption key** | Data is "encrypted", but with a key embedded in code or resources. | MASTG-TEST-0212/0213/0214 (see [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/)) |
| **Key stored on the filesystem** | Data is encrypted, but the key sits in another preference file, database or plist in the same sandbox. | Filesystem review: find the key, decrypt the data |
| **Insufficient encryption** | ECB mode, static IV with CTR/GCM, DES/3DES, a key derived from a constant, or Base64/XOR passed off as encryption. | Static review of crypto calls (MASVS-CRYPTO) |
| **Insufficient access restrictions** | `MODE_WORLD_READABLE`/`MODE_WORLD_WRITEABLE`, a `FileProvider` exposing `<root-path>` or the whole data directory, files with `NSFileProtectionNone`, Keychain items with `kSecAttrAccessibleAlways`, sensitive data in an App Group container. | MASTG-TEST-0299, 0388; manifest and `res/xml/*paths*.xml` review |
| **Data not removed after use** | WebView cache/cookies/localStorage, HTTP caches (`Cache.db`, OkHttp cache), temp files, and databases that survive logout. | MASTG-TEST-0320; logout lifecycle check |

## Impact

- **Compromise of sensitive data.** An attacker who can read the sandbox can extract PII, documents and financial data, which can lead to identity theft, fraud or regulatory exposure for the app owner.
- **Authentication or authorisation bypass.** Session and refresh tokens, stored passwords, PINs and keys let the attacker take over the account, often from a different device and without triggering MFA, because a refresh token already counts as an authenticated session.

The impact grows with token lifetime, how much of the user's data the app caches, and whether the stolen secret works off-device.

## Mitigations

- **Minimise local storage.** Do not persist what you can fetch. Keep PII server-side and render it when needed. Hold short-lived secrets in memory only. Delete caches, tokens and databases on logout.
- **Restrict file access.** Android: use `MODE_PRIVATE` only. Share files through a `FileProvider` with narrow `<files-path>`/`<cache-path>` entries and per-URI grants, never `<root-path>`. iOS: give Keychain items the strictest workable accessibility attribute (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, or `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` for high-value secrets), and keep App Group containers free of secrets.
- **Remove data when no longer needed.** Clear WebView storage, HTTP caches and temp files when the user leaves a sensitive flow and on logout.
- **Use the platform keystore for keys.** Generate keys inside the Android Keystore (StrongBox where available) or keep them in the iOS Keychain / Secure Enclave. Never derive them from constants or store them next to the data.
- **Encrypt data at rest.** Use envelope encryption: a data-encryption key (DEK) protects the data and is itself wrapped by a non-exportable key-encryption key (KEK) in the keystore. On Android, `EncryptedFile` and `EncryptedSharedPreferences` implement this pattern, and SQLCipher covers databases. On iOS, set Data Protection to `.complete` (`NSFileProtectionComplete`) where the app's background work allows it, and add app-level encryption for L2 data.

> **Warning:** The Jetpack Security crypto library (`androidx.security:security-crypto`, which provides `EncryptedFile` and `EncryptedSharedPreferences`) has been [deprecated](https://developer.android.com/privacy-and-security/cryptography#jetpack_security_crypto_library). OWASP's position, which we share, is that it remains a reasonable choice until Google ships an official replacement. For new code, a thin wrapper around a Keystore-held AES-GCM key is equally valid and has no deprecated dependency.

## Knowledge

The Android and iOS mechanisms below are what you need to understand before running the tests: where data lands on disk, which APIs write it, and what protection the platform applies by default.

### Android: Internal storage (MASTG-KNOW-0041)

Every installed app gets a private data directory, usually called its *sandbox* or *internal storage*. The [internal storage](https://developer.android.com/training/data-storage/app-specific#internal) model is simple: the directory belongs to the app's Linux UID (`u0_aNNN`), other apps cannot read it under the normal sandbox, and the system deletes it when the app is uninstalled. That is an *access control*, not encryption. Anything the app writes there is stored as written, and anyone who gets past the access control (root, a backup, a forensic image, a debuggable build) reads it in the clear. That gap is exactly what MASWE-0001 is about.

#### Where the sandbox lives

| Path | What it is |
|---|---|
| `/data/user/0/<pkg>/` | Credential-encrypted (CE) storage for the primary user. This is what `Context.getDataDir()` returns. |
| `/data/data/<pkg>/` | Legacy path; a symlink to `/data/user/0/` on modern Android. Both names refer to the same files. |
| `/data/user/<N>/<pkg>/` | The same app's sandbox for secondary users and work profiles (`adb shell pm list users` gives you `N`). |
| `/data/user_de/0/<pkg>/` | Device-encrypted (DE) storage, used by Direct Boot-aware apps via `createDeviceProtectedStorageContext()`. Readable before the user first unlocks the device. |

On devices using file-based encryption (FBE, introduced in Android 7.0 and required for devices that launch with Android 10 or later), CE storage stays encrypted until the user unlocks the device for the first time after boot. After that first unlock, the kernel decrypts files transparently for any process that is allowed to open them, and that includes root. So FBE protects a powered-off or freshly rebooted device. It does nothing against a rooted device, malware that has gained root, or a forensic extraction done after the first unlock. Secrets an app puts in DE storage are weaker still, because they are readable before the user has authenticated at all. If you find `user_de` paths in use, check what goes there.

#### Directory layout

A typical sandbox looks like this (`ls -la /data/data/<pkg>/` as root):

| Directory | Written by | What to look for |
|---|---|---|
| `shared_prefs/` | `SharedPreferences`, `EncryptedSharedPreferences`, Tink keysets, many SDKs | Tokens, user IDs, feature flags, PINs, cached profile JSON |
| `databases/` | `SQLiteDatabase`, `SQLiteOpenHelper`, Room, SDK databases (analytics, crash, push) | Tables of messages, transactions, PII; `-wal`, `-shm` and `-journal` companions |
| `files/` | `filesDir`, `openFileOutput()`, DataStore (`files/datastore/`), Realm, downloaded documents | Cached API responses, PDFs, images, serialised objects, logs |
| `cache/` | `cacheDir`, OkHttp/Coil/Glide caches, current WebView HTTP cache | Full HTTP responses including JSON bodies, often with PII |
| `code_cache/` | Runtime/JIT artefacts, some packers | Rarely user data. Cleared on app or platform upgrade. |
| `no_backup/` | `noBackupFilesDir` | Data the developer deliberately kept out of backups. Often installation IDs, FCM tokens and keysets, so it is a good place to look for secrets. |
| `app_webview/` | WebView (Chromium profile) | Cookies, Local Storage, IndexedDB, WebSQL, service-worker caches |
| `app_<name>/` | `Context.getDir("<name>", MODE_PRIVATE)` | Anything. `getDir` always adds the `app_` prefix, which is why WebView's directory is `app_webview`. |
| `lib/` (symlink) | Native libraries from the APK | Not user data, but confirms SQLCipher (`libsqlcipher.so`) or other native crypto |

Apps can also write straight into the root of the data directory, so always list the top level too and don't limit yourself to these subfolders.

#### APIs that write to the sandbox

```kotlin
// All of these land under /data/user/0/<pkg>/ and none of them encrypt anything.
File(filesDir, "profile.json").writeText(json)                         // files/profile.json
openFileOutput("session.txt", Context.MODE_PRIVATE).use { it.write(b) } // files/session.txt
File(cacheDir, "resp.bin").writeBytes(body)                            // cache/resp.bin
File(noBackupFilesDir, "install_id").writeText(id)                     // no_backup/install_id
File(getDir("secure", Context.MODE_PRIVATE), "k.bin").writeBytes(k)    // app_secure/k.bin
getDatabasePath("app.db")                                              // databases/app.db
createDeviceProtectedStorageContext().filesDir                         // /data/user_de/0/<pkg>/files
```

When you review decompiled code, it is easy to dismiss these calls because "internal storage is private". Don't. The question MASWE-0001 asks is what is written, not where it is written.

#### File modes and permissions

- `MODE_PRIVATE` (value `0`) is the default and the only mode you should accept. Files are created owned by the app's UID with no "other" permission bits. `SharedPreferences` files typically show as `-rw-rw----`, but the group is the app's own GID, so they are still private. `MODE_APPEND` (`0x8000`) is also fine.
- `MODE_WORLD_READABLE` (`1`) and `MODE_WORLD_WRITEABLE` (`2`) were deprecated in API 17. For apps targeting API 24 (Android 7.0) or higher, passing either one throws a `SecurityException`. On a modern device you will only see them working in apps with an old `targetSdkVersion`. In decompiled code the constants are usually inlined, so `getSharedPreferences("x", 1)` or `openFileOutput("f", 2)` is the same finding.
- `MODE_MULTI_PROCESS` (`4`) is deprecated and unreliable. It is not a security issue in itself, but it suggests old code.
- Since Android 7.0, apps targeting API 24 or higher have their private directory set to `0700`. This hides even the metadata (file names and sizes) from other apps. Sending a `file://` URI that points into the sandbox to another app throws `FileUriExposedException`. Use `FileProvider` instead.
- Since Android 9, apps targeting API 28 or higher run in per-app SELinux sandboxes, which stops them from making their data world-accessible even if they `chmod` it. Android 11 adds app data isolation, so other apps' data directories are not even visible.
- Developers can still make files world-accessible on purpose. Look for `File.setReadable(true, false)`, `setWritable(true, false)`, `android.system.Os.chmod(...)` and `Runtime.exec("chmod ...")`. On current targets, SELinux usually blocks other apps anyway, but the intent is a finding and it does work on older targets.
- `android:sharedUserId` (deprecated in API 29) lets apps signed with the same key share a UID and therefore each other's sandboxes. If the app declares it, every app in that shared UID group can read this app's files.

To verify modes on a device:

```bash
adb shell su -c "ls -laR /data/data/<pkg>/" | grep -vE '^(d|l|total)' | awk '$1 ~ /^.......r/ || $1 ~ /^........w/'
```

Any line printed has "other" read or write bits set, which is worth investigating.

#### What the sandbox does and does not protect against

The sandbox stops other ordinary apps on an unrooted, patched device. It does **not** protect against:

- **Root.** This means a rooted test or user device, malware carrying a root exploit, or a compromised device bought second-hand.
- **Physical extraction.** Forensic tools target after-first-unlock (AFU) devices, where CE storage is already decrypted.
- **Backups.** These include `adb backup` on older targets, Auto Backup to the user's Google account, and device-to-device transfer. Each one copies the sandbox to somewhere else.
- **Debuggable builds.** `run-as` gives anyone with USB access to an unlocked phone the app's UID, with no root needed.
- **App-level leaks that read the sandbox for an attacker.** Examples are a WebView with file access enabled, a `FileProvider` that exposes too much, or a path traversal in a download or unzip routine.

This is why MASVS L2 (and MASWE-0001's `L2` profile) expects sensitive data at rest to be encrypted with keys protected by the Android Keystore, rather than relying on the sandbox alone.

#### Sharing files: FileProvider misconfiguration

[`FileProvider`](https://developer.android.com/reference/androidx/core/content/FileProvider) is the right way to hand a private file to another app. It issues `content://` URIs with per-URI, temporary read/write grants. It is also a common way for private files to leak. Decode the APK and review the provider:

```bash
apktool d app.apk -o app_src
grep -n -A6 'FileProvider' app_src/AndroidManifest.xml
# the meta-data android.support.FILE_PROVIDER_PATHS points to e.g. @xml/file_paths
cat app_src/res/xml/file_paths.xml
```

```xml
<!-- Vulnerable: exposes the whole sandbox and the whole filesystem -->
<paths>
    <files-path name="all_files" path="." />
    <root-path name="root" path="" />
</paths>

<!-- Better: one dedicated subdirectory holding only shareable exports -->
<paths>
    <cache-path name="exports" path="exports/" />
</paths>
```

What to check:

- `<root-path>` maps the provider to `/`, so `shared_prefs/`, `databases/` and everything else in the sandbox become addressable. `path="."` on `files-path`, `cache-path` or the external variants maps a whole base directory: for `files-path` that includes DataStore files, Realm databases and anything else in `files/`, including files added in later releases.
- The provider must be `android:exported="false"` with `android:grantUriPermissions="true"`. `FileProvider` refuses to start if exported. A custom `ContentProvider` that serves files has no such guard.
- Look for code paths where attacker-influenced input (an Intent extra, a deep-link parameter, a file name received from the server) is passed to `FileProvider.getUriForFile()`, and the resulting URI is returned with `FLAG_GRANT_READ_URI_PERMISSION` via `setResult()` or an implicit Intent. That combination lets a malicious app ask for `../shared_prefs/auth.xml` and receive a readable grant to it.

#### Encrypting files with Keystore-backed keys

The platform answer to "the sandbox is not enough" is to encrypt data with a key held by the [Android Keystore](https://developer.android.com/privacy-and-security/keystore). Key material generated inside the Keystore is non-exportable, may be hardware-backed (TEE, or StrongBox with `setIsStrongBoxBacked(true)` on API 28+), and can be bound to conditions such as `setUnlockedDeviceRequired(true)` (API 28+) or user authentication. There are two common patterns:

- **Direct.** Use an AES-256-GCM Keystore key and encrypt each value or file with it. This is simple and fine for small secrets.
- **Envelope (DEK/KEK).** Generate a random data-encryption key (DEK), encrypt bulk data with it in-process, and store the DEK only after wrapping it with a Keystore key-encryption key (KEK). `EncryptedFile`, `EncryptedSharedPreferences`, Tink's `AndroidKeysetManager` and a well-built SQLCipher setup all work this way.

Jetpack Security's [`EncryptedFile`](https://developer.android.com/reference/androidx/security/crypto/EncryptedFile) implements the envelope pattern with Tink's streaming AEAD (`AES256_GCM_HKDF_4KB`). It has a quirk: `openFileOutput()` refuses to overwrite an existing file, so apps have to delete the file first. Like the rest of `androidx.security:security-crypto`, it is deprecated (see the caveat under Shared Preferences below). A sound replacement is Tink directly, or `Cipher` with a Keystore key. A correct example is in the Best Practices section.

What turns encryption back into a MASWE-0001 failure (and usually a MASWE-0003 or MASWE-0004 one too):

- A hard-coded key or passphrase (`SecretKeySpec("0123456789abcdef".toByteArray(), "AES")`). See [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/).
- A generated key stored in the clear next to the data, for example in `shared_prefs` or in an unencrypted Tink keyset (an `AndroidKeysetManager` built without `withMasterKeyUri(...)`). See [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/).
- "Encryption" that is really encoding or obfuscation: Base64, hex, XOR with a constant, ROT, or a reversible custom scheme.
- Weak modes: AES/ECB, unauthenticated CBC with a fixed IV, DES/3DES, or a key derived from a device identifier.

#### Static indicators

```bash
jadx -d jadx_out app.apk
grep -rnE 'openFileOutput|getFilesDir|getCacheDir|getNoBackupFilesDir|getDir\(|FileOutputStream|createDeviceProtectedStorageContext' jadx_out/sources | grep -v '/androidx/'
grep -rnE 'MODE_WORLD_(READABLE|WRITEABLE)|setReadable\(true, ?false\)|setWritable\(true, ?false\)|Os\.chmod' jadx_out/sources
grep -rnE 'EncryptedFile|MasterKey|AndroidKeyStore|KeyGenParameterSpec|AndroidKeysetManager' jadx_out/sources | grep -v '/androidx/security/'
```

Filtering out `androidx/` and other library packages cuts most of the noise. Read what is left with the data-flow question in mind: where does the value written here come from?

### Android: Shared Preferences (MASTG-KNOW-0036)

[`SharedPreferences`](https://developer.android.com/training/data-storage/shared-preferences) persists small key–value maps as XML files in `shared_prefs/`. It is the most common place we find tokens in the clear, because it is the easiest API to reach for. Android now recommends Jetpack DataStore as its replacement (covered below), but most production apps and nearly every third-party SDK still use `SharedPreferences`.

#### How it stores data

```kotlin
val prefs = getSharedPreferences("auth", Context.MODE_PRIVATE)
prefs.edit()
    .putString("username", "administrator")
    .putString("password", "supersecret")
    .putLong("expires_at", 1767225600L)
    .apply()       // asynchronous disk write; commit() is synchronous
```

This results in `/data/data/<pkg>/shared_prefs/auth.xml`:

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="username">administrator</string>
    <string name="password">supersecret</string>
    <long name="expires_at" value="1767225600" />
</map>
```

Points that matter in testing:

- The file name is the first argument to `getSharedPreferences()`. `PreferenceManager.getDefaultSharedPreferences()` (the framework version is deprecated in API 29, the AndroidX one is not, and both are everywhere) writes to `<pkg>_preferences.xml`. An `Activity`'s `getPreferences()` uses the activity class name.
- Strings are stored verbatim and XML-escaped (a newline becomes `&#10;`). `putStringSet()` produces a `<set>` element. Numbers and booleans appear as `value=` attributes. Nothing is ever encrypted.
- `MODE_PRIVATE` controls who can open the file and nothing else. The world-readable and world-writeable modes are deprecated in API 17 and throw `SecurityException` for apps targeting API 24 or higher.
- The whole file is loaded into memory on first access and kept for the life of the process, so secrets in prefs also stay in the heap.
- `apply()` writes asynchronously. If you snapshot the sandbox immediately after an action, the file may not have been written yet. Background the app, or wait a couple of seconds, before you take the second copy.

#### EncryptedSharedPreferences

[`EncryptedSharedPreferences`](https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences) (in `androidx.security:security-crypto`) wraps the same API. It encrypts preference **names** with AES-256-SIV, which is deterministic so that lookups work, and **values** with AES-256-GCM. Both keysets are Tink keysets, stored in the same XML file and wrapped by a Keystore master key whose default alias is `_androidx_security_master_key_`. You can recognise the file on disk straight away:

```xml
<map>
    <string name="__androidx_security_crypto_encrypted_prefs_key_keyset__">12a901aae3...</string>
    <string name="__androidx_security_crypto_encrypted_prefs_value_keyset__">1288014fb7...</string>
    <string name="AXMsIOxwJrhhUoIZ27TdJdrqJz2tPLoLe9sPyru8rHPHqKPn">ASATJH7V90PhGTCL+BDD...</string>
</map>
```

What it does and does not buy you:

- It protects against **offline** access: a pulled file, a backup or a forensic image. The values cannot be decrypted without the Keystore key, which never leaves the device's secure hardware or keystore daemon.
- It does **not** protect against code running *inside* the app on a compromised device. With Frida you can simply call `getString()` on the live instance. Rate that accordingly. It is not a failure of this weakness, which concerns data at rest.
- Deterministic key encryption leaks whether two files share the same preference names, though not what the names are.

> **Warning:** The Jetpack Security Crypto library, including `EncryptedSharedPreferences`, `EncryptedFile` and `MasterKey`, is [deprecated](https://developer.android.com/privacy-and-security/cryptography#jetpack_security_crypto_library). All APIs were deprecated in `1.1.0` and Android states there will be no further releases. For an existing app that must keep using `SharedPreferences`, it remains a practical mitigation and a test should still pass it. It should not be the long-term plan, though: new code should use DataStore with an encryption layer, or Tink or a Keystore `Cipher` directly. Exclude encrypted preference files from Auto Backup. A file restored onto a new device cannot be decrypted, because the Keystore key did not travel with it, and `create()` will throw.

#### Home-made "secure preferences"

Before Jetpack Security existed, many apps used libraries such as `secure-preferences` or rolled their own wrapper. When you see values in `shared_prefs` that look random, do not assume they are encrypted. Check:

- Are they just Base64 or hex? Decode them (`base64 -d`, `xxd -r -p`).
- Where does the key come from? Hard-coded, derived from `ANDROID_ID` or the package name, or stored in another pref, all count as failures.
- Which mode is used? An AES/ECB result shows repeating 16-byte blocks for repeated plaintext.

#### Jetpack DataStore

[DataStore](https://developer.android.com/topic/libraries/architecture/datastore) is the recommended replacement for `SharedPreferences`. It has a coroutine and Flow API, atomic writes (temp file plus rename), and no blocking reads on the UI thread. It comes in two flavours:

| Flavour | API | File on disk | Format |
|---|---|---|---|
| Preferences DataStore | `preferencesDataStore(name = "settings")`, `PreferenceDataStoreFactory.create(...)` | `files/datastore/settings.preferences_pb` | Protocol Buffers map of key to typed value |
| Proto / typed DataStore | `dataStore(fileName = "user.pb", serializer = ...)`, `DataStoreFactory.create(serializer, produceFile = { context.dataStoreFile("user.pb") })` | `files/datastore/user.pb` (whatever name was chosen) | Whatever the app's `Serializer<T>` writes: protobuf, JSON, CBOR |

**DataStore does not encrypt anything by default.** A token stored with `stringPreferencesKey("auth_token")` lands in a protobuf file that `strings` will show you, and `protoc --decode_raw` turns it back into readable structure:

```bash
protoc --decode_raw < settings.preferences_pb
```

```text
1 {
  1: "auth_token"
  2 {
    5: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"
  }
}
```

The only place encryption can happen is the `Serializer<T>` used by a typed DataStore: `readFrom()` and `writeTo()` either call an AEAD or they don't. Preferences DataStore uses an internal serializer you cannot wrap, so an app that wants encrypted DataStore normally switches to a typed DataStore with an encrypting serializer. AndroidX added a `androidx.datastore:datastore-tink` artifact in `1.3.0-alpha07`, with an `AeadSerializer` that wraps an existing serializer in Tink AEAD encryption. At the time of writing it is an alpha artifact, so expect most apps to have their own wrapper, and review that wrapper's key handling as you would any custom crypto.

### Android: SQLite databases (MASTG-KNOW-0037)

Android ships SQLite and exposes it through [`android.database.sqlite`](https://developer.android.com/training/data-storage/sqlite) (`SQLiteDatabase`, `SQLiteOpenHelper`). Room and most SDK databases sit on top of the same engine. A stock SQLite file is plaintext. Every table, every index and often deleted rows can be read with `sqlite3`.

```kotlin
val db = openOrCreateDatabase("privateNotSoSecure", Context.MODE_PRIVATE, null)
db.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR, Password VARCHAR);")
db.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');")
db.close()
// -> /data/data/<pkg>/databases/privateNotSoSecure, readable with sqlite3
```

#### Companion files and data remanence

A database is more than the main file. Always pull the whole `databases/` directory:

- `<name>-journal`: the rollback journal (classic `DELETE` journal mode). It holds pre-change copies of pages during a transaction.
- `<name>-wal` and `<name>-shm`: the [write-ahead log](https://www.sqlite.org/wal.html) and its shared-memory index. The framework enables WAL by default on most devices, and Room uses it by default. **Recent writes may exist only in the `-wal` file** until a checkpoint, so if you copy just `app.db` you may see an empty table and falsely pass the app. Copy all three files together, or checkpoint first (`PRAGMA wal_checkpoint(FULL);` in a copy).
- Deleted rows are not overwritten unless `PRAGMA secure_delete` is on or the database is vacuumed. They sit in free pages and in old WAL frames. A "we delete the token on logout" claim needs checking with `strings` on the raw files, not just a `SELECT`.
- Lock files and `<name>-mj*` super-journals appear occasionally. They are rarely interesting.

#### Room

[Room](https://developer.android.com/training/data-storage/room) is the Jetpack ORM. You declare `@Entity` classes, `@Dao` interfaces and an abstract `RoomDatabase`, and the annotation processor (KSP or kapt) generates an `AppDatabase_Impl` class containing the literal `CREATE TABLE` statements. Two things follow for testers:

- **Room adds no encryption.** `Room.databaseBuilder(context, AppDatabase::class.java, "app.db").build()` produces a normal SQLite file in `databases/app.db` with WAL enabled, plus a `room_master_table` holding the schema hash.
- The generated `_Impl` class shows the exact schema even when the app is obfuscated, because the SQL strings survive R8. Grepping for `CREATE TABLE IF NOT EXISTS` in jadx output gives you every table and column name without running the app.

Encryption is added by swapping the `SupportSQLiteOpenHelper.Factory` with `.openHelperFactory(...)`, normally SQLCipher's. Since Room 2.7 there is also the driver API (`setDriver(BundledSQLiteDriver())`), which bypasses the framework `android.database.sqlite` classes entirely. That changes which classes your hooks must target.

#### SQLCipher

[SQLCipher](https://www.zetetic.net/sqlcipher/) is the de facto standard for encrypted SQLite on Android. It encrypts every page with AES-256 and authenticates it with HMAC. Identify it by:

- The library: the current `net.zetetic:sqlcipher-android` (package `net.zetetic.database.sqlcipher`, Room integration through `SupportOpenHelperFactory`), or the legacy, deprecated `net.zetetic:android-database-sqlcipher` (package `net.sqlcipher.database`, `SupportFactory`).
- A `libsqlcipher.so` under `lib/<abi>/` in the APK.
- The file header. A plain SQLite database begins with the 16-byte string `SQLite format 3\0`. A SQLCipher database (default settings) is random from byte 0.

```bash
head -c 16 app.db | xxd
# 00000000: 5351 4c69 7465 2066 6f72 6d61 7420 3300  SQLite format 3.   <- plaintext
# 00000000: 8f3a c51e 77d0 1b9c 2e44 a3f1 60b7 0d58  .:..w....D..`..X   <- encrypted (or not SQLite)
```

An encrypted database is only as strong as its passphrase handling. A fixed string in the code (`SupportOpenHelperFactory("SuperPassword123".toByteArray())`), a passphrase derived from `ANDROID_ID`, or a random passphrase saved unencrypted in `shared_prefs` all reduce the encryption to obfuscation. A sound design generates 32 random bytes once, wraps them with a Keystore key, and stores only the wrapped blob. To recover a passphrase during a test, hook the factory constructor (`net.zetetic.database.sqlcipher.SupportOpenHelperFactory.$init`) or `SQLiteDatabase.openOrCreateDatabase` in the SQLCipher package and dump the `byte[]` or `String` argument.

Other embedded databases follow the same rule. Realm writes `files/default.realm` and is unencrypted unless `RealmConfiguration.Builder().encryptionKey(key64bytes)` is used. Couchbase Lite, ObjectBox and MMKV each have their own optional encryption, and you should verify each one the same way.

#### Inspecting a database

```bash
sqlite3 app.db '.tables'
sqlite3 app.db '.schema'
sqlite3 -header -column app.db 'SELECT * FROM session;'
sqlite3 app.db '.dump' | grep -iE 'token|passw|secret|iban|@'
strings -n 6 app.db app.db-wal | grep -iE 'bearer|eyJ[A-Za-z0-9_-]{10,}'   # also catches deleted data
```

With objection on a non-rooted, repackaged build, `sqlite connect databases/app.db` downloads the file and lets you query it in the REPL (`sqlite execute query SELECT * FROM session`).

### Android: WebViews (MASTG-KNOW-0018)

A [`WebView`](https://developer.android.com/develop/ui/views/layout/webapps/webview) embeds a browser engine inside the app. Since Android 4.4 it has been Chromium-based, and since Android 5.0 it has been updated through the Play Store independently of the OS (as the Android System WebView, or through Chrome on Android 7–9). That matters for testing: the storage layout and behaviour depend on the WebView version on your test device, not on the Android version. Record it (`adb shell dumpsys webviewupdate`) in your evidence.

For MASWE-0001 the key fact is that **a WebView is a full browser profile living inside the app sandbox**. Whatever a page stores (cookies, Local Storage, IndexedDB, cached responses) persists under the app's data directory, unencrypted, and outlives the screen that created it unless the app deliberately clears it. The other WebView settings matter too, because some of them let web content read the sandbox.

#### URL loading and WebViewClient

Any newly loaded page can try to abuse the WebView's bridges or settings, so the first control is what content the WebView will load at all. With no `WebViewClient` set, navigation hands off to the default browser, which shares no cookies or bridges with the app. Once the app calls `setWebViewClient(...)`, every navigation happens *inside* the WebView. From then on the app must restrict where it can go, by overriding `shouldOverrideUrlLoading` (and `shouldInterceptRequest` for sub-resources) with an allow-list of trusted origins. Without that, a link in user-generated content, an open redirect on the trusted site or a malicious deep-link parameter can put attacker content into the app's WebView, with whatever file access and bridges it has. Web-class bugs (XSS, open redirect) on the loaded site then become mobile bugs.

#### Safe Browsing and threat-checking APIs

Since Android 8.0 WebView supports Google Safe Browsing. It is on by default in recent versions and controlled by the `android.webkit.WebView.EnableSafeBrowsing` manifest meta-data. Android 8.1 added the [`SafeBrowsing` API](https://developer.android.com/about/versions/oreo/android-8.1#safebrowsing) (`WebView.startSafeBrowsing`, `WebViewClient.onSafeBrowsingHit`), which lets the app decide how to react to a known-bad URL, for example by always going "back to safety" instead of letting the user click through. URLs can also be checked outside a WebView through the SafetyNet Safe Browsing client, or with third-party services such as the VirusTotal API. Be careful not to send URLs that carry tokens or PII to any lookup service.

#### JavaScript and native bridges

JavaScript is off by default (`setJavaScriptEnabled(false)`). Enabling it is normal, but it means any script the page runs (including injected script) executes with the WebView's capabilities. There are three bridge mechanisms, in decreasing order of safety:

- **`WebViewCompat.addWebMessageListener`** (AndroidX WebKit) is Android's recommended bridge. It is asynchronous and allow-list based: the injected object only appears in frames whose origin matches the configured `allowedOriginRules`, and every message arrives with its source origin and an `isMainFrame` flag.
- **`WebViewCompat.postWebMessage` / `WebMessageChannel`** is a `postMessage`-style channel to the main frame. It is origin-aware, but targeting `*` (required for `data:`, `file:` and `loadData()` content) removes that protection.
- **`addJavascriptInterface(obj, "name")`** is the legacy synchronous bridge. The object is injected into *every* frame, iframes included, with no origin control, and `WebView.getUrl()` cannot tell you which frame called it. Every `@JavascriptInterface` method should be treated as callable by any content that ends up in the WebView. On old platform versions, reflection through the injected object gave remote code execution. MASTG cites API levels below 21, and apps targeting below API 17 did not even need the `@JavascriptInterface` annotation.

For storage, the question is whether any bridge method returns sandbox data, such as `getToken()`, `readFile(path)` or `getUserProfile()`. If one does, the "private" data is one injected script away from leaving the device.

#### Local file and content access settings

These settings decide whether web content can read files, including the app's private files.

| Setting | What it allows | Default |
|---|---|---|
| `setAllowFileAccess` | Loading `file://` URLs (other than `file:///android_asset/` and `file:///android_res/`, which always work) | `true` for apps targeting API 29 or lower, `false` for API 30+ |
| `setAllowFileAccessFromFileURLs` | Script on a `file://` page reading other `file://` URLs via XHR | `false` since API 16. Deprecated in API 30. Ignored when universal access is `true`. |
| `setAllowUniversalAccessFromFileURLs` | Script on a `file://` page reading any origin (`file://`, `content://`, `https://`) | `false` since API 16. Deprecated in API 30. |
| `setAllowContentAccess` | Loading `content://` URLs, including the app's own **non-exported** providers | `true` |

A `file://` page can reach anything the app's UID can read: the whole sandbox, the app's external directories and, depending on storage permissions, shared storage. The combination of `allowFileAccess`, `javaScriptEnabled` and `allowUniversalAccessFromFileURLs`, together with any way for an attacker to get a `file://` page loaded (an exported activity that passes an Intent URL to `loadUrl()`, or a downloaded HTML file), lets script `XMLHttpRequest` the file `file:///data/data/<pkg>/shared_prefs/auth.xml` and post it to a remote server. No root is needed. The Fetch API refuses `file://` and `content://` regardless of these settings, but XHR does not. Universal access does not expose other sites' cookies, which stay in `CookieManager` behind `HttpOnly` and CORS. The danger is the local files.

Likewise, `allowContentAccess=true` (the default) lets the WebView load `content://<own-authority>/...` from a `FileProvider` the app never exported. If that provider maps `.` or `root-path`, the WebView can display any private file.

The safe pattern for local content is [`WebViewAssetLoader`](https://developer.android.com/reference/androidx/webkit/WebViewAssetLoader). It serves assets and selected internal directories over `https://appassets.androidplatform.net/...`, so they get a normal web origin, and lets you turn off `allowFileAccess` and `allowContentAccess` entirely.

#### What WebViews persist to the sandbox

Most web data lives in a Chromium profile directory (`app_webview/Default/` on current versions). The layout varies by version, so treat the table as a map of where to look rather than a guarantee.

| Data | Typical location | Format / notes |
|---|---|---|
| Cookies (persistent; do not assume session cookies never reach disk) | `app_webview/Default/Cookies` | SQLite. The `value` column is plaintext on Android. |
| Local Storage | `app_webview/Default/Local Storage/leveldb/` | LevelDB `.log` and `.ldb` files. Latin-1 values are stored as single bytes and other text as UTF-16LE, so grep for both. |
| Session Storage | `app_webview/Default/Session Storage/` | LevelDB. Can survive on disk after the page is gone. |
| IndexedDB | `app_webview/Default/IndexedDB/https_<host>_0.indexeddb.leveldb/` (+ `.blob`) | LevelDB with V8-serialised values. Large values may be compressed, so a grep miss is not proof of absence. |
| WebSQL (deprecated; `setDatabaseEnabled` deprecated in API 35) | `app_webview/Default/databases/` | SQLite, one file per origin. |
| Service worker / Cache API | `app_webview/Default/Service Worker/` | CacheStorage entries, full responses. |
| OPFS, SQLite Wasm | Inside Chromium's storage layer | Not ordinary files. Not removable with Java file APIs. |
| HTTP disk cache | `cache/WebView/Default/HTTP Cache/` on current versions (older: `app_webview/Cache`, `cache/org.chromium.android_webview`) | Full response bodies and headers for anything the server allowed to be cached. |
| HTTP auth credentials, legacy form data | `WebViewDatabase` storage (e.g. `app_webview/` databases) | Written via `WebViewDatabase.setHttpAuthUsernamePassword()`. Legacy `setSavePassword` (deprecated API 18) and `setSaveFormData` (deprecated API 26, no effect on O+ where Autofill takes over) wrote form data on old versions. |

Two details catch testers out. First, `WebView.setDataDirectorySuffix("x")` (API 28) moves the profile to `app_webview_x/`. Second, the HTTP cache is under `cache/`, not under `app_webview/`. Search `app_webview*` **and** `cache/`.

#### Storage settings and defaults

- [`WebSettings.setCacheMode`](https://developer.android.com/reference/android/webkit/WebSettings#setCacheMode(int)): the default `LOAD_DEFAULT` obeys HTTP cache headers. `LOAD_NO_CACHE` loads from the network instead of the cache. `LOAD_CACHE_ELSE_NETWORK` and `LOAD_CACHE_ONLY` favour stale data. Do not take `LOAD_NO_CACHE` on trust as "nothing is written". Check the cache directory after use.
- [`setDomStorageEnabled`](https://developer.android.com/reference/android/webkit/WebSettings#setDomStorageEnabled(boolean)) turns on Local and Session Storage. Many apps set it to `true` because web frameworks need it. Note that IndexedDB is not controlled by this flag.
- [`setDatabaseEnabled`](https://developer.android.com/reference/android/webkit/WebSettings#setDatabaseEnabled(boolean)) controls WebSQL only. It was deprecated along with WebSQL in API 35 and controls neither IndexedDB nor OPFS.
- `setAppCacheEnabled` was removed from the SDK in API 33 and has no effect on current WebView releases, although old code compiled against a lower `compileSdk` may still call it.
- `CookieManager.setAcceptCookie` defaults to `true`. Third-party cookies are off by default for apps targeting API 21 or higher (`setAcceptThirdPartyCookies`).

#### Clearing stored data

There is no single API that wipes a WebView profile while keeping the rest of the app's data. `ActivityManager.clearApplicationUserData()` clears everything, including the user's other data, and kills the app. Apps must not delete `app_webview` by hand while WebView is in use. Cleanup is therefore piecemeal:

| API | Clears | Does not clear |
|---|---|---|
| `WebView.clearCache(true)` | Memory and disk HTTP cache, for **all** WebViews in the app | Cookies, DOM storage, IndexedDB, OPFS |
| `WebStorage.getInstance().deleteAllData()` / `deleteOrigin(origin)` | Local/Session Storage and WebSQL | IndexedDB, OPFS (per MASTG; verify on your WebView version) |
| `CookieManager.getInstance().removeAllCookies(cb)` then `flush()` | All cookies (asynchronously). `removeSessionCookies` clears only session cookies. | Everything else |
| `WebViewDatabase.getInstance(ctx).clearHttpAuthUsernamePassword()` | Saved HTTP auth credentials | Everything else |
| `WebView.clearFormData()`, `clearHistory()`, `clearSslPreferences()` | The autocomplete popup, back/forward list, SSL error decisions | Stored data on disk |

IndexedDB and OPFS (including SQLite Wasm databases) can only be removed by deleting the whole profile. For apps that need per-session isolation, AndroidX WebKit's multi-profile API (`ProfileStore`, `WebViewCompat.setProfile`, feature `MULTI_PROFILE`) gives each named profile its own storage. A non-default profile that no WebView is using can then be deleted. Firefox Focus's cleanup routine is a good real-world reference. It calls every API above and then recursively deletes the known WebView directories itself.

#### Why WebView cleanup is hard to test

You need to know how many WebView instances exist and how each is configured. You need to know which storage areas each page actually uses, which depends on the page's JavaScript and the server's cache headers. You need to know how long each sensitive item is supposed to live. And you need to know whether the cleanup still runs when the process is killed rather than closed: `onDestroy()` and `onStop()` are not guaranteed after a system kill or a swipe from recents. A sound implementation also sweeps at the next start. That is why the test below combines API hooking with a search of the files on disk.

#### Alternatives to WebView

[Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs/overview/) and [Trusted Web Activities](https://developer.android.com/develop/ui/views/layout/webapps/trusted-web-activities) render web content in the user's browser. Cookies and storage then belong to the browser's profile, not the app's sandbox, and the app gets no JavaScript bridge. For login flows and third-party content they remove this whole class of findings.

### Android: Accessing the app sandbox

Every dynamic test in this note starts with a copy of `/data/user/0/<pkg>/`. Choose the method that matches your target build. Set the package name once:

```bash
PKG=org.example.app
adb shell pm list packages | grep -i example     # confirm the exact package name
adb shell pm dump $PKG | grep -E 'dataDir|flags=' # dataDir and whether DEBUGGABLE / ALLOW_BACKUP are set
```

#### Rooted device or emulator

On an emulator system image *without* Google Play (the "Google APIs" or AOSP images), `adb root` restarts `adbd` as root, and you can pull directly:

```bash
adb root
adb pull /data/data/$PKG ./sandbox_before
```

On a Magisk-rooted phone, `adbd` stays unprivileged, so you copy through `su` into a world-readable staging location first:

```bash
adb shell su -c "tar -cf /data/local/tmp/sb.tar -C /data/data/$PKG . && chmod 644 /data/local/tmp/sb.tar"
adb pull /data/local/tmp/sb.tar && adb shell su -c "rm /data/local/tmp/sb.tar"
mkdir sandbox && tar -xf sb.tar -C sandbox
```

`tar` keeps the directory structure and avoids `adb pull` problems with file names containing spaces (WebView has several). If the device's toybox lacks `tar`, use `cp -r` into `/data/local/tmp` instead.

#### run-as on debuggable builds

If the app has `android:debuggable="true"` (the debug build you were given, or a release build shipped by mistake), `run-as` drops you into its UID and data directory. No root is needed:

```bash
adb shell run-as $PKG ls -la
adb exec-out run-as $PKG cat shared_prefs/auth.xml > auth.xml
adb exec-out run-as $PKG tar -cf - . > sandbox.tar        # whole sandbox in one go
```

`exec-out` matters because it gives you a binary-clean stream, where `adb shell` would mangle line endings. A *release* build where this works is a finding in its own right: anyone with brief physical access to an unlocked phone can copy the sandbox.

#### objection on a non-rooted device

[objection](https://github.com/sensepost/objection) runs inside the app process, either via a running `frida-server` or a Frida Gadget patched into the APK (`objection patchapk -s app.apk`), and so has exactly the app's file access:

```bash
objection -n $PKG start          # older releases: objection --gadget $PKG explore
# inside the REPL
env                                            # filesDirectory, cacheDirectory, dataDir ...
ls /data/user/0/org.example.app/shared_prefs
filesystem download /data/user/0/org.example.app/shared_prefs/auth.xml auth.xml
filesystem download /data/user/0/org.example.app/databases dbs --folder
```

Repackaging changes the signing key, which can break apps that check their own signature or use Play Integrity. If that happens, fall back to a rooted device.

#### Backups

`adb backup` used to be the classic way in without root. It is now of limited use:

- It is deprecated and needs on-device confirmation. Apps with `android:allowBackup="false"` are skipped.
- For apps targeting API 31 (Android 12) or higher, app data is excluded from `adb backup` unless the app is debuggable.
- It honours `fullBackupContent` and `dataExtractionRules` exclusions, and never includes `cache/`, `code_cache/` or `no_backup/`.

```bash
adb backup -f app.ab -noapk $PKG
java -jar abe.jar unpack app.ab app.tar      # Android Backup Extractor
tar -tf app.tar | head                       # apps/<pkg>/sp/, apps/<pkg>/db/, apps/<pkg>/f/
```

When it works, it is a strong piece of evidence, because it demonstrates extraction from a stock, non-rooted device. Separately, check what Auto Backup and device-to-device transfer would carry. Note that for apps targeting API 31 or higher, `allowBackup="false"` does not stop device-to-device transfer. Only `dataExtractionRules` controls that.

#### Searching what you pulled

Plain `grep -rn` finds most things, but values are often encoded. We keep a small script that searches a directory for one known value in its common encodings (raw, UTF-16LE, hex, URL-encoding, and standard and URL-safe Base64 at all three byte alignments, so it also matches inside longer blobs):

```python
#!/usr/bin/env python3
"""Search a pulled sandbox for a known value in common encodings."""
import base64, binascii, pathlib, sys, urllib.parse

value, root = sys.argv[1], pathlib.Path(sys.argv[2])
raw = value.encode()
needles = {
    "raw": raw,
    "utf-16le": value.encode("utf-16-le"),
    "hex": binascii.hexlify(raw),
    "HEX": binascii.hexlify(raw).upper(),
    "url": urllib.parse.quote(value, safe="").encode(),
}
# Base64 at all three byte alignments; trim characters that depend on
# neighbouring bytes so the needle matches inside a longer blob.
for pad, skip in ((0, 0), (1, 2), (2, 3)):
    for name, enc in (("b64", base64.b64encode), ("b64url", base64.urlsafe_b64encode)):
        b = enc(b"\0" * pad + raw).rstrip(b"=")
        needles[f"{name}+{pad}"] = b[skip:len(b) - 3]

for path in root.rglob("*"):
    if path.is_file():
        data = path.read_bytes()
        hits = [n for n, x in needles.items() if len(x) >= 4 and x in data]
        if hits:
            print(f"{path}: {', '.join(hits)}")
```

```bash
python3 find_value.py 'alice@example.com' ./sandbox
# sandbox/shared_prefs/profile.xml: raw
# sandbox/files/cache.json: b64+1
```

Also run `file` across the tree (`find sandbox -type f -exec file {} +`) to spot gzip, zip, SQLite and protobuf files that need unpacking before you search them.

### iOS: App Sandbox Directories (MASTG-KNOW-0108)

[OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0108/)

Every third-party iOS app is confined to its own sandbox. The kernel's sandbox profile (`container`) stops one app reading another app's files, and the user has no shell or file browser that reaches below the Files app. That isolation is the reason developers assume the sandbox is a safe place for secrets. It is not a confidentiality control on its own: the sandbox stops *other apps*, not someone holding the device, a forensic tool, a jailbreak, a backup, or an attacker who already has code execution inside your process. MASWE-0001 is about what is left when that isolation is bypassed.

#### Bundle container vs Data container

An installed app is split across two directories, each named with a random UUID that changes on every reinstall (and the Data UUID can change on updates, so never hard-code it in scripts):

```text
Bundle container: /private/var/containers/Bundle/Application/<BUNDLE-UUID>/
App bundle:       /private/var/containers/Bundle/Application/<BUNDLE-UUID>/MyApp.app
Data container:   /private/var/mobile/Containers/Data/Application/<DATA-UUID>/
Extension data:   /private/var/mobile/Containers/Data/PluginKitPlugin/<UUID>/
App Group:        /private/var/mobile/Containers/Shared/AppGroup/<UUID>/
```

The **Bundle container** holds `MyApp.app` exactly as shipped in the IPA: the Mach-O binary, `Info.plist`, `embedded.mobileprovision`, `Frameworks/`, `PlugIns/*.appex` (extensions), asset catalogues and any bundled databases or JSON. It is read-only at runtime, sealed by the code signature and not backed up. Anything sensitive in here was put there at build time — that is MASWE-0004 territory ([Sensitive Data Hardcoded in the App Package](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/)), not this note.

The **Data container** is where everything the app writes at runtime ends up, and it is the focus of every test below. App extensions (share, widget, notification service, keyboard and so on) do **not** use the containing app's Data container: each runs with its own container under `Containers/Data/PluginKitPlugin/`, and the only way the app and its extensions see the same files is an App Group container (see MASTG-KNOW-0082 below).

Each container has a hidden `.com.apple.mobile_container_manager.metadata.plist` at its root whose `MCMMetadataIdentifier` key holds the bundle ID (or App Group ID). That is the most reliable way to map a UUID to an app on a jailbroken device.

#### Data container layout

| Path (relative to Data container) | Intended use | Backed up | User-visible | What you typically find in a test |
|---|---|---|---|---|
| `Documents/` | User-created content | Yes | Only if `UIFileSharingEnabled` / `LSSupportsOpeningDocumentsInPlace` are set | Realm's `default.realm` (its default location), exported PDFs, downloaded statements, "temporary" JSON that never got cleaned up |
| `Library/` | App-internal support files | Yes (except `Caches`) | No | Custom subfolders created by SDKs |
| `Library/Application Support/` | Persistent internal data | Yes | No | Core Data `*.sqlite` + `-wal` + `-shm` (the `NSPersistentContainer` default), GRDB/SQLite databases, SDK state |
| `Library/Preferences/` | `UserDefaults` | Yes | No | `<bundle-id>.plist` (binary plist) — tokens, user IDs, emails, feature flags, "isLoggedIn", sometimes passwords |
| `Library/Caches/` | Regenerable data | No | No | `<bundle-id>/Cache.db` (URL loading system cache), image caches, `WebKit/` caches, analytics queues |
| `Library/Cookies/` | Persistent HTTP cookies | Yes | No | `Cookies.binarycookies` — persistent session cookies |
| `Library/WebKit/` | `WKWebView` website data | Yes | No | LocalStorage, IndexedDB, service worker data for web content |
| `Library/SplashBoard/Snapshots/` (path varies by iOS version) | App-switcher snapshots | No | No | Screenshots of whatever was on screen when backgrounded |
| `tmp/` | Scratch files | No | No | Upload staging, decrypted copies of files, PDF previews, crash-prone leftovers |
| `SystemData/` | OS-managed | — | No | Rarely relevant |

Three points matter for this weakness:

- **"Not backed up" and "purgeable" are not security properties.** `Library/Caches/` and `tmp/` are excluded from backups and may be purged under storage pressure, but on a normal device they persist for days or weeks. A tester with file system access sees them exactly like any other folder.
- **`Library/Preferences/<bundle-id>.plist` is never encrypted by the app.** It is written by the `cfprefsd` daemon on the app's behalf, as a binary plist, under the default Data Protection class. It is the single most common place to find a plaintext token on iOS.
- **The Keychain is not in the sandbox.** Keychain items live in a system database (`/private/var/Keychains/keychain-2.db`) managed by `securityd`, encrypted per item. Nothing you copy out of the Data container contains Keychain data, which is why you dump it separately.

Two other caches show up in the sandbox but belong to other weaknesses: app-switcher snapshots (screenshots of sensitive screens) and the system keyboard's autocorrect cache (which lives outside the sandbox under `/private/var/mobile/Library/Keyboard/`). Note them if you see them; test them under their own MASWEs.

#### Who can actually reach the sandbox

When you rate a finding you need to say *how* an attacker gets to the file. On iOS, the realistic paths are:

- **Jailbroken device or forensic acquisition.** Full file system access. Devices vulnerable to a bootrom exploit (checkm8 affects A5–A11 SoCs, i.e. up to iPhone X) can be imaged by commercial forensic tools. What the tool can decrypt depends on the device state: **before first unlock (BFU)** only `NSFileProtectionNone` files and `kSecAttrAccessibleAlways*` Keychain items are readable; **after first unlock (AFU)**, with the screen locked, everything in the default class (`CompleteUntilFirstUserAuthentication`) and `AfterFirstUnlock*` Keychain items is also readable. Only `NSFileProtectionComplete` / `WhenUnlocked*` data stays sealed while the device is locked. This is the whole point of the protection classes.
- **Device backups (Finder/iTunes, iCloud).** `Documents/`, `Library/` (minus `Caches`) and preferences are backed up by default. An encrypted local backup also carries Keychain items that are not `ThisDeviceOnly`. No jailbreak is required, only an unlocked device and the passcode to trust the computer. Backup exposure is tested separately, but it is often the most practical way to prove a MASWE-0001 finding is reachable on a stock device.
- **`UIFileSharingEnabled` / document picker.** If the app exposes `Documents/` in the Files app or via Finder file sharing, anything there is one drag-and-drop away for anyone with the unlocked phone, and is readable by other apps through a document picker the user approves.
- **Code execution in the app process.** A repackaged build, a malicious SDK, or a vulnerable WebView bridge reads the sandbox as the app does — file protection does not help here (the app's own process can always read its files when the class allows), which is why app-level encryption with a Keychain key is the L2 expectation.
- **Debug builds.** Any build with `get-task-allow` can be inspected and its container downloaded through Xcode. Ensure a debug or "enterprise QA" build never reaches end users.

### iOS: File System APIs and Data Protection (MASTG-KNOW-0091)

[OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0091/)

#### APIs that write to the sandbox

iOS apps reach the file system through a handful of layers. All of them end up as ordinary files under the Data container, so the same protection rules apply:

| Layer | Typical APIs | Notes for testers |
|---|---|---|
| Foundation file APIs | `FileManager.createFile(atPath:contents:attributes:)`, `Data.write(to:options:)`, `String.write(to:atomically:encoding:)`, `FileHandle.write(contentsOf:)`, `OutputStream` | Most common. `Data.write` accepts protection options; `String.write` does not, so it always uses the default class |
| POSIX / BSD | `open`, `write`, `pwrite`, `fopen`, `fwrite`, `close` | Used by C/C++ libraries, SQLite, Realm, cross-platform engines (React Native, Flutter plugins, Unity) |
| Document model | `UIDocument`, `NSFileCoordinator` | Same files, same protection rules |
| Key-value | `UserDefaults` / `NSUserDefaults`, `UserDefaults(suiteName:)` | Written by `cfprefsd`, not by the app process — file hooks in the app will not see the write |
| Databases | Core Data (`NSPersistentContainer`), `sqlite3_*`, FMDB, GRDB, SQLite.swift, Realm, Couchbase Lite, SwiftData | Plaintext by default. SQLite WAL mode adds `-wal` and `-shm` side files that also contain data |
| Serialisation | `NSKeyedArchiver`, `PropertyListEncoder`, `JSONEncoder` + `Data.write`, Swift `Codable` | Encoding, not encryption. `NSKeyedArchiver` output is a binary plist you can read with `plutil` |
| URL loading system | `URLCache` (`Library/Caches/<bundle-id>/Cache.db`), `HTTPCookieStorage` (`Library/Cookies/`), `URLCredentialStorage` (Keychain) | `URLSession.shared` and `.default` configurations cache responses to disk unless told not to |
| WebKit | `WKWebView` with `WKWebsiteDataStore.default()` | Cookies, LocalStorage, IndexedDB and HTTP cache persist across launches |

The directory helpers you will see in code are `FileManager.default.urls(for:in:)` with `.documentDirectory`, `.libraryDirectory`, `.applicationSupportDirectory` or `.cachesDirectory`, plus `FileManager.default.temporaryDirectory` / `NSTemporaryDirectory()` for `tmp/`. On iOS 16+ you will also see the `URL.documentsDirectory`, `URL.applicationSupportDirectory`, `URL.cachesDirectory` and `URL.temporaryDirectory` static properties.

#### Data Protection classes

Every file on the data partition is encrypted with its own per-file key. That key is wrapped by a **class key**, and the class determines when the class key is available in memory. Class keys are derived from the hardware UID key and, for every class except `None`, the user's passcode. Without a passcode set, the passcode component is missing and the lock-state guarantees below do not hold — test devices must have a passcode.

| File protection class (Swift / ObjC) | Apple class | Contents readable | `Data.WritingOptions` | Use for |
|---|---|---|---|---|
| `FileProtectionType.complete` / `NSFileProtectionComplete` | A | Only while unlocked. The class key is discarded shortly (about 10 seconds) after lock | `.completeFileProtection` | Credentials, health/financial data, decrypted documents |
| `.completeUnlessOpen` / `NSFileProtectionCompleteUnlessOpen` | B | Files already open stay readable after lock; new files can be created while locked; closed files cannot be reopened while locked | `.completeFileProtectionUnlessOpen` | Downloads or recordings that must finish in the background |
| `.completeUntilFirstUserAuthentication` / `NSFileProtectionCompleteUntilFirstUserAuthentication` | C | From the first unlock after boot until the next reboot, including while locked | `.completeFileProtectionUntilFirstUserAuthentication` | **The default.** Data that background tasks need |
| `.none` / `NSFileProtectionNone` | D | Always, including before first unlock. Protected only by the UID key | `.noFileProtection` | Practically nothing sensitive. Some system and SDK files use it so they work at boot |

The protection class is metadata on the file, not on the folder you look at, and there is no visible difference in the content: you cannot tell a `Complete` file from a `None` file by copying both off an unlocked device. You have to query the attribute at runtime (see "Accessing the app sandbox").

#### The default class and how it changes

Since iOS 7, files created by third-party apps default to `NSFileProtectionCompleteUntilFirstUserAuthentication` (class C). That default protects a powered-off or freshly rebooted phone, and nothing more: once the owner has unlocked the device once, every default-class file is readable to an AFU acquisition even while the screen is locked.

There are four ways the class of a file is set:

1. **Per write.** `Data.write(to:options:)` with one of the protection options, or `FileManager.createFile(atPath:contents:attributes:)` with `[.protectionKey: FileProtectionType.complete]`.
2. **After the fact.** `FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath:)` or `URLResourceValues` / `(url as NSURL).setResourceValue(_:forKey: .fileProtectionKey)`. The file existed with the default class until this call ran.
3. **App-wide default.** The **Data Protection capability** in Xcode adds the `com.apple.developer.default-data-protection` entitlement (for example `NSFileProtectionComplete`) to the app, which changes the default for files the app creates. Check for it in the signed entitlements, not in `Info.plist`. Existing files keep the class they were created with; changing the entitlement in an update does not re-key old files.
4. **Store-specific options.** Core Data takes `NSPersistentStoreFileProtectionKey` in the store description options; Apple's SQLite accepts `SQLITE_OPEN_FILEPROTECTION_COMPLETE` (and the `_COMPLETEUNLESSOPEN`, `_COMPLETEUNTILFIRSTUSERAUTHENTICATION`, `_NONE` variants) in `sqlite3_open_v2` flags; Realm writes its own files and must be configured separately.

Pitfalls you will regularly see in code review:

- **`String.write(to:atomically:encoding:)` and most third-party writers ignore protection.** They create the file with the default class. A later `setAttributes` fixes the class only if it is actually called on every code path.
- **Atomic replace can drop a class set with `setAttributes`.** An atomic write creates a new temporary file and renames it over the old one. Unless the write itself specifies the class, the replacement may come up with the default class. Verify at runtime after a second write, not just after the first.
- **Side files.** SQLite `-wal`, `-shm` and `-journal` files, Realm `.lock` and `.management/` files, and `tmp/` copies all hold data. They must be protected as well, and they are frequently forgotten.
- **`Complete` breaks background work.** A notification service extension, a background fetch or a `BGTaskScheduler` task that runs while the device is locked cannot open `Complete` files (`NSFileReadNoPermissionError` / `EPERM`). Developers who hit this often "fix" it by switching to `None`. Look for that commit in the code and treat it as a red flag. The correct options are `CompleteUnlessOpen` for files written while locked, or storing only non-sensitive data for the background path. `UIApplication.shared.isProtectedDataAvailable` and the `protectedDataWillBecomeUnavailableNotification` / `protectedDataDidBecomeAvailableNotification` notifications let the app react to lock state.
- **The Simulator does not implement Data Protection.** It runs on the Mac's file system. Use it for quick content inspection, never to evaluate protection classes.

#### Higher-level stores, briefly

- **`UserDefaults`.** Stores a binary plist at `Library/Preferences/<bundle-id>.plist`; shared suites (`UserDefaults(suiteName: "group.…")`) write `Library/Preferences/group.<id>.plist` inside the App Group container. No encryption, default protection class, backed up. Intended for small non-sensitive settings. Any token, password, PIN, PII or key in here is a finding.
- **Core Data / SwiftData.** SQLite under `Library/Application Support/` by default. Tables are prefixed `Z` (`ZUSER`, `ZMESSAGE`), primary keys are `Z_PK`. Unencrypted unless the app adds a layer such as SQLCipher-backed stores or encrypts attribute values itself. Recent writes are often only in the `-wal` file until a checkpoint, so always copy all three files.
- **Raw SQLite (FMDB, GRDB, SQLite.swift).** Same story. SQLCipher is the usual encrypted replacement; the question then becomes where the passphrase comes from (hardcoded string, `UserDefaults`, or Keychain).
- **Realm.** `Documents/default.realm` by default, plaintext unless `Realm.Configuration(encryptionKey:)` is given a 64-byte key. Realm's encryption is only as good as where that key lives. MongoDB deprecated its Atlas Device SDKs (Realm) in 2024; the local database is still open source and still widely shipped, so you will keep meeting it.
- **`URLCache` / `Cache.db`.** `URLSession` with the `.default` configuration (and `URLSession.shared`) caches responses to `Library/Caches/<bundle-id>/Cache.db`, with large bodies spilled into `fsCachedData/`. API responses containing PII, account data or tokens end up there unless the server sends `Cache-Control: no-store`, the app uses `URLSessionConfiguration.ephemeral`, sets `urlCache = nil`, or refuses caching in `urlSession(_:dataTask:willCacheResponse:completionHandler:)`. `WKWebView` content is cached separately under `Library/Caches/<bundle-id>/WebKit/` or `Library/Caches/WebKit/`, depending on iOS version.
- **Cookies.** Persistent cookies (anything with `Expires`/`Max-Age`) are written to `Library/Cookies/Cookies.binarycookies`. A long-lived session cookie there is equivalent to a token in `UserDefaults`.
- **`WKWebView` website data.** The default data store keeps cookies, LocalStorage, IndexedDB and cache under `Library/WebKit/` and the caches folder. Hybrid apps that keep auth state in `localStorage` leave it there in plaintext. Use `WKWebsiteDataStore.nonPersistent()` for sensitive flows, or clear with `WKWebsiteDataStore.default().removeData(ofTypes:modifiedSince:completionHandler:)` on logout.

#### User exposure

Two `Info.plist` keys turn `Documents/` from private into user-visible storage:

- `UIFileSharingEnabled` ("Application supports iTunes file sharing") — the folder appears in Finder file sharing on a connected Mac/PC.
- `LSSupportsOpeningDocumentsInPlace` ("Supports opening documents in place") — together with the first key, the folder appears in the Files app under "On My iPhone".

Check both in the built app (`plutil -p Payload/MyApp.app/Info.plist | grep -E 'UIFileSharingEnabled|LSSupportsOpeningDocumentsInPlace'`). If they are `true`, anything the app writes to `Documents/` — including databases, config and cached exports — is readable and writable by anyone holding the unlocked device, with no jailbreak. `UIDocumentPickerViewController` exports are user-driven and fine; databases in a shared `Documents/` are not.

### iOS: Keychain Services (MASTG-KNOW-0057)

[OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/)

#### What the Keychain is and is not

The Keychain is iOS's secure store for small secrets: passwords, tokens, keys, certificates. Items are rows in `/private/var/Keychains/keychain-2.db`, managed by `securityd`; each item's secret attributes are encrypted with a per-item key, wrapped by a class key that follows the same lock-state rules as file Data Protection. Access is mediated by entitlements: a process can only read items in the access groups it is entitled to (its own `application-identifier`, its `keychain-access-groups`, and its App Group IDs).

Two properties surprise developers and are worth checking in every test:

- **Keychain items survive app deletion.** Uninstalling the app does not remove its Keychain items; a reinstall can read them again. Apps that use the Keychain for session tokens should clear stale items on first launch (commonly by keeping a "has run" flag in `UserDefaults` — which *is* deleted on uninstall). For testing, it also means "clean state" requires clearing the Keychain, not just reinstalling.
- **The Keychain protects data at rest, not from the app's own process.** If the code can call `SecItemCopyMatching`, so can Frida inside that process. The Keychain moves secrets out of the sandbox and binds them to lock state and, optionally, to user presence; it does not make them unreadable to runtime instrumentation without access control flags.

#### Accessibility attributes

`kSecAttrAccessible` decides when an item can be decrypted and whether it can leave the device. If the app sets neither `kSecAttrAccessible` nor `kSecAttrAccessControl`, the item gets `kSecAttrAccessibleWhenUnlocked`.

| Attribute | Stored value (`pdmn`) | Readable when | Leaves the device (encrypted backup restore to new device, iCloud Keychain) | File class analogue |
|---|---|---|---|---|
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | `akpu` | Unlocked, and only while a passcode is set. Items are deleted if the passcode is removed; cannot be created without a passcode | No | `Complete` (stricter) |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | `aku` | Unlocked | No | `Complete` |
| `kSecAttrAccessibleWhenUnlocked` (default) | `ak` | Unlocked | Yes | `Complete` |
| `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | `cku` | After first unlock, until reboot | No | `CompleteUntilFirstUserAuthentication` |
| `kSecAttrAccessibleAfterFirstUnlock` | `ck` | After first unlock, until reboot | Yes | `CompleteUntilFirstUserAuthentication` |
| `kSecAttrAccessibleAlwaysThisDeviceOnly` (deprecated, iOS 12) | `dku` | Always, including before first unlock | No | `None` |
| `kSecAttrAccessibleAlways` (deprecated, iOS 12) | `dk` | Always, including before first unlock | Yes | `None` |

There is no Keychain equivalent of `CompleteUnlessOpen`.

The short codes in the second column are what you see when you dump raw attribute dictionaries from a hooked `SecItemAdd` or from the Keychain database (`pdmn` is the accessibility key; `class` = `genp`/`inet`/`keys`/`cert`, `acct` = account, `svce` = service, `agrp` = access group, `accc` = access control, `sync` = synchronizable, `v_Data` = the secret). Learn them; they make Frida output readable at a glance.

The two `Always` variants are deprecated but still honoured, so legacy code and old SDKs that use them still compile (with a warning) and still produce items readable in BFU state. `ThisDeviceOnly` items are wrapped with a device-bound key in backups and will not restore to another device; items without it migrate through encrypted backups, and through iCloud Keychain if the app also sets `kSecAttrSynchronizable`. For a refresh token or a key that encrypts local files, migration to a new device is rarely what you want.

#### Access control flags

`kSecAttrAccessControl` (created with `SecAccessControlCreateWithFlags`) combines an accessibility level with authentication requirements. It is mutually exclusive with `kSecAttrAccessible` in the same query: the accessibility is passed as the second argument to `SecAccessControlCreateWithFlags` instead.

- `.userPresence` — biometrics or device passcode.
- `.biometryAny` — any enrolled biometric; survives new enrolments.
- `.biometryCurrentSet` — invalidated when biometric enrolment changes (a new face or finger added).
- `.devicePasscode` — passcode only.
- `.or` / `.and` — combine constraints.
- `.privateKeyUsage` — for Secure Enclave keys; the private key can be used but never exported.
- `.applicationPassword` — an app-supplied password as an additional factor.

Unlike Android's per-key authentication validity window, iOS has no per-item timeout: an item without an access control flag is readable whenever its accessibility class allows. `LAContext.touchIDAuthenticationAllowableReuseDuration` only lets a recent device unlock satisfy the check, and is capped at five minutes.

#### Sharing and access groups

Items carry a `kSecAttrAccessGroup`. By default an item goes into the first group in the app's `keychain-access-groups` entitlement or, if there is none, the app's `application-identifier` (`TEAMID.bundle.id`). To share an item with an extension or another app from the same team, both declare the same `keychain-access-groups` entry (`$(AppIdentifierPrefix)com.example.shared`) and the code sets `kSecAttrAccessGroup` to the expanded value (`ABCDE12345.com.example.shared`). App Group identifiers (`group.…`) the app is entitled to can also be used as Keychain access groups. Access groups are team-scoped by code signing; another developer's app cannot join them.

#### A correct example

The MASTG example stores a secret bound to the current biometric set. The version below fixes the issues in the original (inconsistent account names between save and read, redeclared variables, and the deprecated `kSecUseOperationPrompt`, which since iOS 14 is replaced by an `LAContext` with `localizedReason` passed through `kSecUseAuthenticationContext`):

```swift
import LocalAuthentication
import Security

enum KeychainError: Error { case status(OSStatus) }

let service = "com.example.app.auth"
let account = "refresh-token"

func saveToken(_ token: Data) throws {
    var cfError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,   // accessibility goes here...
        .biometryCurrentSet,
        &cfError
    ) else { throw cfError!.takeRetainedValue() as Error }

    let match: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account
    ]
    SecItemDelete(match as CFDictionary)                    // replace any stale item

    var add = match
    add[kSecAttrAccessControl as String] = access           // ...not in kSecAttrAccessible
    add[kSecValueData as String] = token
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else { throw KeychainError.status(status) }
}

// Blocks while the biometric prompt is shown: call off the main thread.
func readToken() throws -> Data {
    let context = LAContext()
    context.localizedReason = "Unlock your account"
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecUseAuthenticationContext as String: context
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let data = result as? Data else {
        throw KeychainError.status(status)
    }
    return data
}
```

For MASWE-0001 the Keychain matters in two roles: as the place where secrets should live instead of the sandbox, and as the place where the key used to encrypt sandbox files should live. A test that finds an AES key in `UserDefaults` next to the ciphertext it protects has found the "Encryption Key Stored on Filesystem" mode of introduction, not encryption.

### iOS: App Extensions, App Groups and Shared Keychain (MASTG-KNOW-0082)

[OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0082/)

#### Why extensions widen the storage surface

App extensions — share, action, widget (WidgetKit), notification service and content, keyboard, Intents/App Intents, file provider, and others — are separate binaries in `MyApp.app/PlugIns/*.appex`. Each runs as its own process with its own sandbox (`Containers/Data/PluginKitPlugin/<UUID>/`), usually while the containing app is not running at all. They are signed by the same team and ship in the same IPA, so they are not a third-party threat in themselves. The storage problem is what developers do to get data from the app to the extension: they need a shared place, and the shared place is frequently less protected than the app's own storage.

The OS also restricts extensions (no long-running background work, limited API availability, memory limits), and some of them run in awkward states: a notification service extension may run while the device is locked, and a custom keyboard runs inside every other app the user types into. Those constraints push developers towards weaker protection classes in shared storage.

#### App Group shared containers

An App Group is a shared container that the app and its extensions opt into with the `com.apple.security.application-groups` entitlement, listing the same identifier (`group.com.example.app`). The identifier is bound to the team through the provisioning profile, so only binaries signed by that team and provisioned with that group can open it. On disk it is `/private/var/mobile/Containers/Shared/AppGroup/<UUID>/`, with the group ID in that container's `.com.apple.mobile_container_manager.metadata.plist`.

Members use it through:

- `UserDefaults(suiteName: "group.com.example.app")` — written to `Library/Preferences/group.com.example.app.plist` inside the group container.
- `FileManager.default.containerURL(forSecurityApplicationGroupIdentifier:)` — returns the container root; the app creates whatever layout it likes below it.
- `NSPersistentContainer` / SwiftData with a store URL inside the group container — a shared Core Data database.
- Background `URLSession` transfers started by an extension, which need `sharedContainerIdentifier` so the app can pick up the downloaded file.

Properties that drive the tests:

- **No per-member access control.** Every member of the group can read and write everything in the container. A widget that only needs a balance figure can read the refresh token the app put there for the share extension.
- **Same Data Protection rules, same default.** Files in the group container default to `CompleteUntilFirstUserAuthentication`. The shared `UserDefaults` plist is plaintext under that default.
- **Its own backup and lifetime.** The group container is backed up and persists until the last app in the group is deleted, so it can outlive a logout that only cleaned the app's own container.
- **It is easy to miss.** A tester who only pulls `Containers/Data/Application/<UUID>/` will not see any of it.

#### Shared Keychain access groups

For secrets that both sides need, the right channel is a shared Keychain access group (`keychain-access-groups` entitlement, or an App Group ID used as an access group). It gives the secret Keychain-level encryption, an accessibility class and optional access control, independent of the file container. The developer still has to choose the accessibility class with the extension in mind — a notification service extension that decrypts push payloads while the device is locked needs `AfterFirstUnlockThisDeviceOnly`, which is a reasonable trade-off for that key; using it for everything is not.

#### What to collect for a test

- The entitlements of the app and of every `.appex` (`application-groups`, `keychain-access-groups`, and `com.apple.developer.default-data-protection`).
- Which group IDs each binary actually references in code.
- The contents and protection classes of each group container on the device after exercising the app *and* triggering each extension (share something, add the widget, receive a push).

The `NSExtensionActivationRule` in an extension's `Info.plist` controls when a share or action extension is offered to the user; it is a UI filter, not an access control on stored data, so it does not affect the storage assessment.

### iOS: Accessing the app sandbox

You need to do three things repeatedly in the tests below: find the containers, copy their contents off the device, and read each file's protection class **on the device** (copying a file off loses its protection class).

#### Jailbroken device

Get a shell (OpenSSH from your jailbreak's package manager) over USB:

```bash
iproxy 2222 22 &          # libimobiledevice; newer versions also accept 2222:22
ssh -p 2222 root@localhost   # rootless jailbreaks may require mobile + sudo
```

Find the bundle ID first (from the host: `frida-ps -Uai` lists installed apps with identifiers), then map it to container UUIDs using the metadata plists. `grep` works on these binary plists because the identifier is stored as an ASCII string:

```bash
BID=com.example.app
for d in /var/mobile/Containers/Data/Application/*/ \
         /var/mobile/Containers/Shared/AppGroup/*/ \
         /var/mobile/Containers/Data/PluginKitPlugin/*/; do
  grep -q "$BID" "$d/.com.apple.mobile_container_manager.metadata.plist" 2>/dev/null && echo "$d"
done
```

This matches the app's Data container, its extensions' containers (their IDs start with the app's bundle ID) and App Groups whose ID contains the bundle ID. App Group IDs do not have to contain the bundle ID, so cross-check against the `application-groups` entitlement and grep for those IDs too. If `ipainstaller` is installed, `ipainstaller -i com.example.app` prints the Bundle and Data paths directly.

Copy the containers to your host (tar keeps the tree intact and is faster than `scp -r` for many small files):

```bash
DATA=/var/mobile/Containers/Data/Application/<DATA-UUID>
mkdir -p loot/data && ssh -p 2222 root@localhost "tar -C $DATA -cf - ." | tar -xf - -C loot/data
```

A quick lock-state check is also possible from the shell: lock the phone, wait 15 seconds, and try to `cat` a file. A `Complete` file fails to open (typically `Operation not permitted`); a default-class or `None` file reads fine. It is a useful sanity check of what the attribute claims.

#### objection

objection (Frida-based) runs inside the app process, so it works on jailbroken devices and on non-jailbroken devices with a Frida Gadget-injected, re-signed build (`objection patchipa --source app.ipa --codesign-signature <identity>`), within the app's own sandbox only. Recent releases use `objection -n <name> start`; older ones `objection -g <name> explore`.

```text
env                                   # BundlePath, DocumentDirectory, LibraryDirectory, CachesDirectory
cd /var/mobile/Containers/Data/Application/<DATA-UUID>/Library/Preferences
ls                                    # includes an NSFileProtection column per file
ios plist cat com.example.app.plist   # decode a (binary) plist
ios nsuserdefaults get                # dump standard UserDefaults
ios cookies get                       # HTTPCookieStorage cookies
file download Cache.db ./Cache.db     # pull a file to the host
sqlite connect Cache.db               # query an SQLite database in place
ios keychain dump --json kc.json      # the app's accessible Keychain items
ios keychain clear                    # reset the app's Keychain items for a clean run
```

The `NSFileProtection` column of `ls` is the quickest way to read protection classes; it shows `n/a` for directories and some special files.

#### Frida: enumerate files with their protection class

For a full-tree listing that you can save and diff (TEST-0299, TEST-0302), use a small script that runs in the app and asks `NSFileManager` for each file's attributes. Edit `GROUPS` to match the `application-groups` entitlement:

```javascript
// list-protection.js  —  frida -U -F -l list-protection.js -o files.tsv
const GROUPS = ["group.com.example.app"];
const fm = ObjC.classes.NSFileManager.defaultManager();

function walk(root) {
  const en = fm.enumeratorAtPath_(root);
  if (en === null) return;
  let rel;
  while ((rel = en.nextObject()) !== null) {
    const path = root + "/" + rel.toString();
    const attrs = fm.attributesOfItemAtPath_error_(path, NULL);
    if (attrs === null) continue;
    if (attrs.objectForKey_("NSFileType").toString() !== "NSFileTypeRegular") continue;
    const prot = attrs.objectForKey_("NSFileProtectionKey");
    console.log([prot ? prot.toString() : "n/a", attrs.objectForKey_("NSFileSize"), path].join("\t"));
  }
}

const home = ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_("HOME").toString();
walk(home);
GROUPS.forEach(g => {
  const url = fm.containerURLForSecurityApplicationGroupIdentifier_(g);
  if (url !== null) walk(url.path().toString());
});
```

Run it attached to the already-running app (`-F` attaches to the frontmost app) after you have exercised it, not at spawn. Extension containers under `PluginKitPlugin/` are outside the app's sandbox; attach to the extension process while it runs (`frida-ps -U` shows it) or list them from an SSH shell.

#### Non-jailbroken devices and the Simulator

- **Debug / development-signed builds.** Xcode → Window → Devices and Simulators → select the app → gear icon → **Download Container…** gives you an `.xcappdata` package (Show Package Contents → `AppData/`). Recent Xcode versions also expose this through `xcrun devicectl device copy from`; check `--help` for the domain options in your version. This only works for apps with `get-task-allow`, so it is for testing your own builds, not App Store binaries.
- **Re-signed builds with Frida Gadget.** objection and the Frida script above work inside the app; you can read anything the app can read, including App Group containers it is entitled to.
- **Simulator.** `xcrun simctl get_app_container booted com.example.app data` prints the Data container path on the Mac; `... groups` lists App Group containers. Good for content triage; useless for protection classes.
- **Backups.** A Finder/iTunes backup gives you the backed-up parts of the container from any stock device. It is the realistic attacker path for many findings; see the backup MASWE for the procedure.

#### Reading what you pulled

```bash
# Property lists (UserDefaults, NSKeyedArchiver output, app plists)
plutil -p loot/data/Library/Preferences/com.example.app.plist
plutil -convert xml1 -o - file.plist               # full XML, includes <data> blobs as base64

# SQLite (Core Data, Cache.db, SDK stores) — copy -wal/-shm alongside the .sqlite
sqlite3 -readonly Model.sqlite '.tables'
sqlite3 -readonly Model.sqlite '.schema ZUSER'
sqlite3 -readonly Model.sqlite '.dump' | grep -iE 'token|password|bearer|eyJ'
sqlite3 -readonly Cache.db "SELECT r.request_key, length(d.receiver_data)
  FROM cfurl_cache_response r JOIN cfurl_cache_receiver_data d ON r.entry_ID = d.entry_ID;"

# Anything else
file -b some.bin; xxd some.bin | head
grep -rIlE 'eyJ[A-Za-z0-9_-]{10,}\.|Bearer |password|refresh_token' loot/
strings -a default.realm | grep -iE 'token|@'      # or open it in Realm Studio
```

If `sqlite3` reports `file is not a database` on something called `.sqlite` or `.db`, the store is probably SQLCipher-encrypted — note it and move on to where the key comes from. `Cookies.binarycookies` is Apple's binary cookie format; several open-source parsers exist, or use objection's `ios cookies get` live.

#### Dumping the Keychain

- **objection** `ios keychain dump` shows the items the app's entitlements can reach, with their accessibility (`WhenUnlocked`, `AfterFirstUnlockThisDeviceOnly`, …) and decoded data where possible. It runs inside the app, so it works with a Gadget build too. Decoding has varied between Frida/objection versions; if data shows as "failed to decode", use the raw Frida hook in TEST-0301 instead.
- **keychain-dumper** on a jailbroken device dumps every item on the device using a wildcard entitlement, including the access group (`Entitlement Group`) of each item — useful to catch items written by extensions or other apps in the same team.
- **Clean state.** Because items survive reinstall, run objection's `ios keychain clear` before a differential test (it removes the items the app can reach), or reset the device.

## Tests

OWASP links eleven tests to MASWE-0001: six for Android and five for iOS. They fall into three types:

- **Static** ("References to…"): find the storage APIs and sensitive values in the decompiled code.
- **Dynamic** ("Runtime…"): hook the APIs while you exercise the app and capture what is written.
- **Filesystem**: inspect what is actually on disk after the flows.

Run all three types. A static hit only proves the API is used, and a clean filesystem after one flow does not prove another flow is clean.

### MASTG-TEST-0207: Runtime Storage of Unencrypted Data in the App Sandbox (Android)

**Platform:** Android · **Type:** dynamic, filesystem · **Knowledge:** MASTG-KNOW-0041 · **Best practice:** MASTG-BEST-0050 · [OWASP page](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/)

#### Overview

This is the API-agnostic baseline test. You don't care *how* the app writes data, whether through `SharedPreferences`, SQLite, Room, DataStore, raw `FileOutputStream`, a native library or a third-party SDK. You snapshot the sandbox, use the app, snapshot again, and inspect everything that changed. It catches what the API-specific tests miss: an analytics SDK's database, an OkHttp cache full of JSON responses, a crash reporter's queued reports, a PDF statement saved to `files/`.

#### Prerequisites

- A definition of what counts as sensitive for this app: credentials, tokens, keys, PII, financial and health data, and anything the client's data classification lists. Without one, you cannot evaluate the result.
- A rooted device or emulator, or a debuggable build or objection (see "Accessing the app sandbox" above).
- A list of the test inputs you will use, each one distinctive enough to search for (`alice.gt.test+0207@example.com`, `Passw0rd-0207!`, a fake card number with a recognisable pattern).

#### Steps

1. Install the app (`adb install app.apk`, or `adb install-multiple base.apk split_*.apk` for split APKs).
2. Launch it once and close it, so that first-run files (SDK init, empty databases) are in the baseline rather than polluting your diff. Then take a reference copy and a hash manifest:

   ```bash
   PKG=org.example.app
   adb shell su -c "find /data/data/$PKG -type f -exec sha256sum {} +" | sort -k2 > before.sha
   adb shell touch /data/local/tmp/test_start      # timestamp marker, as in the OWASP demo
   ```

3. Use the app as a real user would. Register, log in, tick "remember me", view the profile, open statements and messages, make a payment, change settings, use any WebView screens, then log out. Enter your distinctive values wherever the app accepts input. Note which values you entered in which flows.
4. Background the app (`adb shell input keyevent KEYCODE_HOME`) and wait a few seconds so that `apply()`, WAL and cache writes reach disk. Then take the second snapshot and diff it:

   ```bash
   adb shell su -c "find /data/data/$PKG -type f -exec sha256sum {} +" | sort -k2 > after.sha
   diff <(awk '{print $2}' before.sha) <(awk '{print $2}' after.sha)   # added/removed files
   join -1 2 -2 2 before.sha after.sha | awk '$2 != $3 {print $1}'      # modified files
   # or the OWASP demo's approach:
   adb shell su -c "find /data/data/$PKG -type f -newer /data/local/tmp/test_start" > changed.txt
   ```

5. Pull the full sandbox (pull all of it, not just the changed files: the diff is there to prioritise, and you still need the context) and search it:

   ```bash
   adb shell su -c "tar -cf /data/local/tmp/sb.tar -C /data/data/$PKG . && chmod 644 /data/local/tmp/sb.tar"
   adb pull /data/local/tmp/sb.tar && mkdir -p sandbox && tar -xf sb.tar -C sandbox
   grep -rnaiF -e 'alice.gt.test+0207@example.com' -e 'Passw0rd-0207!' sandbox/
   python3 find_value.py 'Passw0rd-0207!' sandbox/
   gitleaks dir -v sandbox/          # gitleaks >= 8.19; older: gitleaks detect --no-git -s sandbox/ -v
   find sandbox -type f -exec file {} + | grep -viE 'ASCII|empty|XML'   # databases, archives, protobufs to unpack
   ```

6. Unpack anything opaque before deciding it is safe. Open SQLite files with `sqlite3` (together with their `-wal`), decode protobufs with `protoc --decode_raw`, `gunzip` or `unzip` archives, and decode Base64 blobs. Then run the search again.
7. Repeat the search after logout and again after a force-stop and relaunch, to see what survives.

#### Observation

Record:

- the list of files created or modified during the session (path, size, mode, owner);
- for each file containing sensitive data, the file path, the matching value, the encoding it was found in, and the user flow that produced it;
- the Android version, WebView version and app version tested.

#### Evaluation

The test **fails** if any file in the sandbox contains sensitive data in a form that can be recovered without a key held by the Android Keystore. That includes:

- plaintext values in any file type;
- values that are only encoded, compressed or obfuscated (Base64, hex, URL-encoding, UTF-16, XOR with a constant, gzip/zip, protobuf). These obscure the data. They do not protect it.
- values that are encrypted with a key you can also find in the sandbox or in the APK. Reference MASWE-0003 or MASWE-0004 alongside.

It **passes** if the sensitive inputs appear only as ciphertext whose key is held by the Android Keystore (or a server), or do not appear at all.

Common false positives: your own value echoed in a non-sensitive context (a search-history entry the client considers acceptable), placeholder or test values in SDK config files, public keys and certificates, and hashed identifiers sent to analytics. Raise these as Informational or drop them, with a reason. Common false negatives: values sitting in a `-wal` file you did not pull, data written after your snapshot because of `apply()`, and data only written on specific flows you didn't exercise (password reset, offline mode, error paths).

#### Demo

OWASP's MASTG-DEMO-0010 writes a password to internal storage:

```kotlin
private fun mastgTestWriteIntFile() {
    val file = File(context.filesDir, "secret.txt")
    FileOutputStream(file).use { it.write("secr3tPa\$\$W0rd\n".toByteArray()) }
}
```

The demo's `run_before.sh` creates `/data/local/tmp/test_start`. `run_after.sh` lists every file newer than it and pulls each one:

```bash
adb shell "find /data/user/0/org.owasp.mastestapp/ -type f -newer /data/local/tmp/test_start" > output.txt
mkdir -p new_files && while read -r line; do adb pull "$line" ./new_files/; done < output.txt
```

```text
$ cat output.txt
/data/user/0/org.owasp.mastestapp/files/secret.txt
$ cat new_files/secret.txt
secr3tPa$$W0rd
```

The test fails: an unencrypted password sits in `files/secret.txt`. The demo runs `adb shell` with `adbd` as root (an emulator after `adb root`). On a Magisk device, wrap the commands in `su -c` and pull through `/data/local/tmp`.

### MASTG-TEST-0287: Runtime Storage of Unencrypted Data via the SharedPreferences API (Android)

**Platform:** Android · **Type:** dynamic, hooks, manual · **Knowledge:** MASTG-KNOW-0036 · **Best practice:** MASTG-BEST-0050 · [OWASP page](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0287/)

#### Overview

This test targets the single most common source of MASWE-0001 findings. It hooks the `SharedPreferences` write methods at runtime, so you see every key and value *as it is written*, with a stack trace showing which code wrote it. It also traces the crypto APIs, so you can tell whether a value went through a `Cipher` first. The XML files on disk are then used to confirm the result. Hooking has two advantages over reading the files alone. It attributes each value to a code location (the app versus an SDK, and which class), which is what the developers need to fix it. And it shows the plaintext of values that *are* encrypted, so you can judge whether they were sensitive in the first place.

The writes you care about go through `android.app.SharedPreferencesImpl$EditorImpl`, the framework implementation behind every `SharedPreferences.Editor`. That includes `EncryptedSharedPreferences`, which calls it underneath with ciphertext. The main methods are `putString(String, String)` and `putStringSet(String, Set)`. Hook `putInt`, `putLong` and `putBoolean` too if PINs or flags are in scope.

#### Prerequisites

- The sensitive-data definition and distinctive test inputs, as for MASTG-TEST-0207.
- A rooted device or emulator with `frida-server` running, or a Gadget-patched APK. Frooky (`pip install frooky`) if you want the OWASP JSON-driven workflow, or plain Frida.
- `jq` and gitleaks on the host.

#### Steps

1. Install the app.
2. Hook the write and crypto APIs. With **Frooky**, use the hook file from MASTG-DEMO-0059:

   ```json
   {
     "category": "STORAGE",
     "hooks": [
       { "class": "android.app.SharedPreferencesImpl$EditorImpl", "methods": ["putString", "putStringSet"] },
       { "class": "javax.crypto.Cipher", "methods": ["getInstance", "init", "update", "doFinal"] },
       { "class": "java.security.KeyStore", "methods": ["getEntry", "setEntry"] },
       { "class": "javax.crypto.KeyGenerator", "methods": ["getInstance", "generateKey"] },
       { "class": "android.util.Base64", "methods": ["encodeToString", "decode"] }
     ]
   }
   ```

   ```bash
   frooky -U -f $PKG --platform android hooks.json > output.json   # NDJSON: one event per line
   ```

   Or with **plain Frida**:

   ```javascript
   // prefs-trace.js   usage: frida -U -f <pkg> -l prefs-trace.js
   Java.perform(function () {
     const Log = Java.use('android.util.Log');
     const Exception = Java.use('java.lang.Exception');
     const bt = () => Log.getStackTraceString(Exception.$new()).split('\n').slice(1, 6).join('\n    ');

     const Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
     Editor.putString.implementation = function (k, v) {
       console.log(`[putString] ${k} = ${v}\n    ${bt()}`);
       return this.putString(k, v);
     };
     Editor.putStringSet.implementation = function (k, s) {
       console.log(`[putStringSet] ${k} = ${s === null ? null : s.toString()}\n    ${bt()}`);
       return this.putStringSet(k, s);
     };

     const Cipher = Java.use('javax.crypto.Cipher');
     Cipher.doFinal.overload('[B').implementation = function (input) {
       console.log(`[Cipher.doFinal] ${this.getAlgorithm()} in=${input.length} bytes`);
       return this.doFinal(input);
     };
   });
   ```

   For a quick look without writing a script, `frida-trace -U -f $PKG -j 'android.app.SharedPreferencesImpl$EditorImpl!put*'` traces all `put*` methods.

3. Exercise the app thoroughly: login, "remember me", profile, settings, logout, and every flow where you enter sensitive data.
4. Pull `shared_prefs/` (and, for completeness, the whole sandbox):

   ```bash
   adb shell su -c "cat /data/data/$PKG/shared_prefs/*.xml"
   adb shell su -c "tar -cf /data/local/tmp/sp.tar -C /data/data/$PKG shared_prefs && chmod 644 /data/local/tmp/sp.tar"
   adb pull /data/local/tmp/sp.tar && tar -xf sp.tar
   ```

5. Reduce the Frooky trace to a readable timeline and scan both the trace and the XML for secrets:

   ```bash
   jq -r 'select(.type=="hook") | "\(.class | split(".") | last).\(.method)(\([.inputParameters[]?.value | tostring | .[0:60]] | join(", ")))  <- \(.stackTrace[1] // "")"' output.json
   gitleaks stdin -v < output.json
   gitleaks dir -v shared_prefs/
   ```

#### Observation

- Every `putString` and `putStringSet` call with its key, value, and the first app frame of the stack trace.
- The interleaved crypto calls (`Cipher.getInstance`, `init` with the key class, `doFinal` input and output, `Base64.encodeToString`), which show whether a value was encrypted before it was written.
- The contents of every XML file in `shared_prefs/`.

#### Evaluation

The test **fails** if a sensitive value is written via `SharedPreferences` without being encrypted first. In practice, you establish that in three steps (plus a fourth if the first three are inconclusive):

1. **High-level trace inspection.** Follow the timeline. A `putString` whose value is *not* immediately preceded by `Cipher.doFinal` (and usually `Base64.encodeToString` of that output) is being written in the clear.
2. **Pattern matching.** gitleaks and your own value search flag recognisable secrets (JWTs, `ghp_` tokens, `AKIA` keys, PEM blocks) in the trace or the XML.
3. **Manual verification.** Use the stack trace to open the calling method in jadx, then trace the value back to its source to confirm both that it is sensitive and that no encryption is applied. For values that look encrypted, check where the key comes from: `Cipher.init` with an `android.security.keystore2.AndroidKeyStoreSecretKey` (or `AndroidKeyStore*` on older versions) is a Keystore key, while a `javax.crypto.spec.SecretKeySpec` means the key material exists in app memory and probably on disk or in the APK.
4. **Detailed trace inspection.** Link values across events. The `doFinal` output bytes should equal the input to `Base64.encodeToString`, whose return value is the string passed to `putString`.

It **passes** if every sensitive value is encrypted with a Keystore-protected key (for example, via `EncryptedSharedPreferences` or a Keystore AES-GCM key) before it reaches the file. Writes of the `__androidx_security_crypto_encrypted_prefs_*_keyset__` entries are expected. They are the Tink keysets, themselves wrapped by the Keystore master key.

Watch for SDKs. A third-party SDK that stores an access token in its own prefs file is still the app's finding, but the remediation is different (configure or replace the SDK), so attribute it in the report.

#### Demo

MASTG-DEMO-0059 (fail case) writes three values: a GitHub token in plaintext, an AWS key encrypted with a Keystore AES-GCM key, and a set of PEM private keys in plaintext:

```kotlin
val prefs = context.getSharedPreferences("MasSharedPref_Sensitive_Data", Context.MODE_PRIVATE)
prefs.edit {
    putString("UnencryptedGitHubToken", githubToken)               // plaintext
    putString("EncryptedAwsKey", encrypt(awsKey))                  // AES/GCM, AndroidKeyStore key
    putStringSet("UnencryptedPreSharedKeys", preSharedKeys)        // plaintext
}
```

The reduced trace (`evaluation.txt` in the demo) shows the difference clearly:

```text
SharedPreferencesImpl$EditorImpl.putString(UnencryptedGitHubToken, ghp_1234567890abcdefghijklmnopqrstuvABCD)
Cipher.getInstance(AES/GCM/NoPadding)
KeyStore.getEntry(mastgKey, void)
Cipher.init(1, <android.security.keystore2.AndroidKeyStoreSecretKey>, <SecureRandom>)
Cipher.doFinal(AKIAABCDEFGHIJKLMNOP)
Base64.encodeToString(0x53e09f5c462870a2..., 0)
SharedPreferencesImpl$EditorImpl.putString(EncryptedAwsKey, U+CfXEYocKIURmVE91Lenat45CMUe7+...)
SharedPreferencesImpl$EditorImpl.putStringSet(UnencryptedPreSharedKeys, -----BEGIN PRIVATE KEY-----...)
```

The GitHub token and the private keys are written with no preceding `Cipher` call, so the test fails. The AWS key is fine. On disk:

```xml
<map>
    <string name="EncryptedAwsKey">biRVGn5dDNR9qcRSqLRVNqmf3NU85RNm6P6qDNEpUZ4q...</string>
    <set name="UnencryptedPreSharedKeys">
        <string>-----BEGIN PRIVATE KEY-----&#10;MIIEvAIBADANBgkqhkiG9w0BAQEF...</string>
        ...
    </set>
    <string name="UnencryptedGitHubToken">ghp_1234567890abcdefghijklmnopqrstuvABCD</string>
</map>
```

gitleaks run over the trace flags `github-pat`, `private-key` (twice) and `aws-access-token`. The last one is the plaintext *input* to `Cipher.doFinal` captured by the hook, not something on disk. That is a reminder to correlate gitleaks hits with the event that produced them before reporting.

MASTG-DEMO-0060 is the passing counterpart. The same data is written through `EncryptedSharedPreferences.create(context, name, masterKey, AES256_SIV, AES256_GCM)`. The hooks show the inner `SharedPreferencesImpl$EditorImpl.putString` called from `EncryptedSharedPreferences$Editor.putEncryptedObject` with ciphertext only, and the XML contains just the two keysets and opaque `AXMsIO...` name/value pairs.

### MASTG-TEST-0304: References to Sensitive Data Unencrypted via Android Room Database (Android)

**Platform:** Android · **Type:** static, code · **Knowledge:** MASTG-KNOW-0037 · [OWASP page](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0304/)

> **Note:** At the time of writing, OWASP has reserved this test as a *placeholder*: there is no published procedure, and its demo (MASTG-DEMO-0068, "Sensitive Data in Unencrypted SQLite") is also a placeholder. Despite the "Room" in its title, OWASP's description scopes it to the **framework SQLite API** (`SQLiteOpenHelper`, `Context.openOrCreateDatabase`), and Room is covered by MASTG-TEST-0306. The procedure below is ours, written to that scope.

#### Overview

This test establishes, from the code, whether the app writes sensitive data to SQLite through the framework API without an encryption layer such as SQLCipher. Static analysis tells you *which* tables and columns hold what, including on code paths that are hard to trigger dynamically. A short dynamic check on the database file then confirms the result.

#### Prerequisites

- The APK (and, if you have it, source), jadx and apktool.
- The sensitive-data definition.
- For confirmation, a way to pull `databases/` (see "Accessing the app sandbox").

#### Steps

1. Decompile and find database creation and writes in app code (filter out library packages):

   ```bash
   jadx -d jadx_out app.apk
   grep -rnE 'extends SQLiteOpenHelper|openOrCreateDatabase\(|SQLiteDatabase\.openDatabase\(|getWritableDatabase\(' jadx_out/sources | grep -vE '/(androidx|com/google)/'
   grep -rnE 'CREATE TABLE' jadx_out/sources | grep -vE '/(androidx|com/google)/'
   grep -rnE '\.(insert|insertOrThrow|insertWithOnConflict|replace|update)\(|execSQL\(' jadx_out/sources | grep -vE '/(androidx|com/google)/'
   ```

2. For each schema, list the columns and decide which are sensitive (`token`, `password`, `pin`, `iban`, `dob`, `message_body`). Follow the `ContentValues.put("column", value)` calls back to their sources.
3. Look for an encryption layer:

   ```bash
   grep -rlE 'net/zetetic|net/sqlcipher' jadx_out/sources | head
   unzip -l app.apk | grep -E 'lib/.*/libsqlcipher\.so'
   ```

   If SQLCipher is present, find where the passphrase comes from (the argument to `getWritableDatabase(passphrase)`, `SQLiteDatabase.openOrCreateDatabase(file, passphrase, ...)` or `SupportOpenHelperFactory(passphrase)`). Classify it as hard-coded, derived from a device identifier, stored in prefs, or Keystore-wrapped.
4. Confirm on the device. Pull the database *with* its `-wal`, `-shm` and `-journal` files, check the header, then query:

   ```bash
   head -c 16 databases/tokens.db | xxd
   sqlite3 databases/tokens.db '.schema' 'SELECT * FROM tokens;'
   ```

#### Observation

- The database names, schemas and the code locations that write sensitive columns.
- Whether SQLCipher (or another encrypted engine) is in use for each database, and how its key is obtained.
- The header bytes and sample rows from the on-device file.

#### Evaluation

The test **fails** if a sensitive value is written to a SQLite database that is not encrypted, or is encrypted with a passphrase that is hard-coded, derived from predictable data, or stored unprotected in the sandbox. It **passes** if sensitive columns live only in databases encrypted with a passphrase protected by the Keystore, or if sensitive values are individually encrypted with a Keystore key before insertion (field-level encryption is legitimate, but check that *every* sensitive column is covered and that indexes or full-text search tables don't hold plaintext copies).

#### Demo

Our own minimal sample (OWASP's demo is a placeholder):

```kotlin
class TokenDbHelper(context: Context) : SQLiteOpenHelper(context, "tokens.db", null, 1) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("CREATE TABLE tokens(user TEXT PRIMARY KEY, token TEXT NOT NULL)")
    }
    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit
}

fun saveToken(context: Context, user: String, token: String) {
    val values = ContentValues().apply { put("user", user); put("token", token) }
    TokenDbHelper(context).writableDatabase.insertWithOnConflict("tokens", null, values, SQLiteDatabase.CONFLICT_REPLACE)
}
```

```text
$ grep -rnE 'CREATE TABLE|insertWithOnConflict' jadx_out/sources/com/example/
jadx_out/sources/com/example/data/TokenDbHelper.java:14:    sQLiteDatabase.execSQL("CREATE TABLE tokens(user TEXT PRIMARY KEY, token TEXT NOT NULL)");
jadx_out/sources/com/example/data/TokenStore.java:22:    writableDatabase.insertWithOnConflict("tokens", null, contentValues, 5);
$ grep -rlE 'net/zetetic|net/sqlcipher' jadx_out/sources | wc -l
0
$ head -c 16 tokens.db | xxd
00000000: 5351 4c69 7465 2066 6f72 6d61 7420 3300  SQLite format 3.
$ sqlite3 tokens.db 'SELECT * FROM tokens;'
alice|eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2ln
```

Fail: a bearer token sits in a plaintext SQLite file, and there is no encryption library in the APK.

### MASTG-TEST-0305: Sensitive Data Stored Unencrypted via DataStore (Android)

**Platform:** Android · **Type:** static, dynamic · [OWASP page](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0305/)

> **Note:** At the time of writing, this test and its demo (MASTG-DEMO-0069) are OWASP *placeholders*. The scope OWASP gives is whether the app uses Jetpack DataStore (Preferences or Proto) to store sensitive data without encryption, and whether a secure serializer is absent. The procedure below is ours.

#### Overview

DataStore is the modern replacement for `SharedPreferences`. Teams migrating to it often assume it is "more secure". It isn't: both flavours write plaintext protobuf, or whatever the serializer emits, to `files/datastore/`. This test identifies every DataStore, determines what it stores, and checks whether the serializer encrypts.

#### Prerequisites

- APK and jadx; `protoc` on the host for decoding.
- Sandbox access for the dynamic part.
- The sensitive-data definition.

#### Steps

1. **Static: find the stores and their keys.**

   ```bash
   grep -rnE 'preferencesDataStore\(|PreferenceDataStoreFactory|DataStoreFactory|dataStoreFile\(|preferencesDataStoreFile\(' jadx_out/sources | grep -v '/androidx/'
   grep -rnE '(string|stringSet|int|long|boolean)PreferencesKey\("' jadx_out/sources | grep -v '/androidx/'
   ```

   Key names (`stringPreferencesKey("auth_token")`) survive obfuscation as string literals and usually say what is stored.
2. **Static: inspect the serializers.** For typed DataStores, find classes implementing `androidx.datastore.core.Serializer` (look for `readFrom`/`writeTo` methods with `InputStream`/`OutputStream` parameters, or classes passed to `DataStoreFactory.create`). Check whether `writeTo` encrypts (an `Aead.encrypt`, `Cipher.doFinal`, or `AeadSerializer` from `androidx.datastore:datastore-tink`) and `readFrom` decrypts. Check where the key comes from.
3. **Dynamic: exercise the app, then pull and decode the files.**

   ```bash
   adb shell su -c "ls -la /data/data/$PKG/files/datastore/"
   adb shell su -c "cat /data/data/$PKG/files/datastore/session.preferences_pb" > session.preferences_pb
   protoc --decode_raw < session.preferences_pb
   strings -n 6 session.preferences_pb
   ```

4. **Optional: attribute writes.** DataStore writes to a scratch file and renames it, so hooking the file-stream constructor shows which code is writing:

   ```javascript
   Java.perform(function () {
     const FOS = Java.use('java.io.FileOutputStream');
     FOS.$init.overload('java.io.File', 'boolean').implementation = function (f, append) {
       const p = f.getAbsolutePath();
       if (p.indexOf('/datastore/') !== -1) {
         console.log('[DataStore write] ' + p + '\n' +
           Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
       }
       return this.$init(f, append);
     };
   });
   ```

#### Observation

- Every DataStore file, its flavour (Preferences or typed), its keys or fields, and the serializer class.
- The decoded contents of each file after the app has been exercised.

#### Evaluation

The test **fails** if any DataStore file contains sensitive data in plaintext or decodable form. Protobuf is an encoding, not protection. It also fails if the serializer encrypts with a hard-coded key or a key stored alongside the data. It **passes** if sensitive values are held only in a typed DataStore whose serializer applies authenticated encryption with a Keystore-protected key (for example Tink AEAD with an `android-keystore://` master key, or `AeadSerializer`), or if they are encrypted individually with a Keystore key before being placed in the store.

#### Demo

Our own minimal sample (OWASP's demo is a placeholder):

```kotlin
val Context.sessionStore by preferencesDataStore(name = "session")
private val AUTH_TOKEN = stringPreferencesKey("auth_token")

suspend fun saveToken(context: Context, token: String) {
    context.sessionStore.edit { prefs -> prefs[AUTH_TOKEN] = token }
}
```

```text
$ adb shell su -c "ls /data/data/org.example.app/files/datastore/"
session.preferences_pb
$ protoc --decode_raw < session.preferences_pb
1 {
  1: "auth_token"
  2 {
    5: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2ln"
  }
}
```

Fail: the token is readable straight from the protobuf. Field `5` of the value message is the string case of DataStore's `Value` type.

### MASTG-TEST-0306: References to Sensitive Data Stored Unencrypted via Android Room DB (Android)

**Platform:** Android · **Type:** static, code · [OWASP page](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0306/)

> **Note:** At the time of writing, this test and its demo (MASTG-DEMO-0070) are OWASP *placeholders*. OWASP's scope is whether the app uses Room to store sensitive data without an encryption layer such as SQLCipher, which leaves the database file in plaintext in the sandbox. The procedure below is ours.

#### Overview

Room is the default persistence layer in modern Android apps, so a Room database is usually where the app keeps its offline copy of the user's data: messages, transactions, profile and sometimes tokens. Room has no built-in encryption, so the questions are which entities hold sensitive fields and whether an encrypting `SupportSQLiteOpenHelper.Factory` (SQLCipher's) is installed on the builder.

#### Prerequisites

- APK and jadx; sandbox access for confirmation; the sensitive-data definition.

#### Steps

1. **Find the databases and builders.**

   ```bash
   grep -rnE 'Room\.(databaseBuilder|inMemoryDatabaseBuilder)\(' jadx_out/sources | grep -v '/androidx/'
   grep -rlE 'extends RoomDatabase' jadx_out/sources | grep -v '/androidx/'
   ```

   The third argument to `databaseBuilder` is the file name under `databases/`.
2. **Recover the schema from the generated code.** Room generates `<YourDatabase>_Impl` with the literal DDL, and it survives obfuscation:

   ```bash
   grep -rnoE 'CREATE TABLE IF NOT EXISTS `[^`]+` \([^"]+' jadx_out/sources | grep -v room_master_table
   ```

   Read the column names and pick out the sensitive ones. Cross-check with `@Entity` classes if you have source.
3. **Look for an encryption layer on each builder.** Follow the builder chain for `.openHelperFactory(...)`. `net.zetetic.database.sqlcipher.SupportOpenHelperFactory` (current SQLCipher) and `net.sqlcipher.database.SupportFactory` (legacy) mean encryption. No factory, or `FrameworkSQLiteOpenHelperFactory`, means plaintext. If the builder uses `.setDriver(...)` (Room 2.7+), check which driver: `BundledSQLiteDriver` and `AndroidSQLiteDriver` are both unencrypted.
4. **Trace the passphrase**, as in MASTG-TEST-0304, step 3.
5. **Confirm on the device.** Pull `databases/<name>`, `-wal` and `-shm` together, then check the header and query the sensitive tables. To watch values as Room binds them (framework-backed Room only), hook `android.database.sqlite.SQLiteProgram.bindString(int, String)`.

#### Observation

- Each Room database file name, its builder location, entities and sensitive columns.
- Whether an encrypting open-helper factory is set, and the passphrase source.
- Header bytes and sample rows from the pulled file (including WAL content).

#### Evaluation

The test **fails** if a Room database holding sensitive columns is built without an encrypting factory, or with one whose passphrase is hard-coded, predictable or stored unprotected. It **passes** if every Room database holding sensitive data uses SQLCipher (or equivalent) with a random passphrase wrapped by a Keystore key, or if the sensitive fields are encrypted with a Keystore key before Room sees them (for example with a `TypeConverter` that calls an AEAD). Watch for `@Fts4` tables and indices on encrypted fields: they duplicate content.

#### Demo

Our own minimal sample (OWASP's demo is a placeholder):

```kotlin
@Entity(tableName = "session")
data class Session(
    @PrimaryKey val userId: String,
    @ColumnInfo(name = "access_token") val accessToken: String,
    @ColumnInfo(name = "refresh_token") val refreshToken: String
)

@Dao
interface SessionDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun save(session: Session)
}

@Database(entities = [Session::class], version = 1)
abstract class AppDatabase : RoomDatabase() {
    abstract fun sessionDao(): SessionDao
}

val db = Room.databaseBuilder(context, AppDatabase::class.java, "app.db").build()   // no openHelperFactory
```

```text
$ grep -rnoE 'CREATE TABLE IF NOT EXISTS `[^`]+` \([^"]+' jadx_out/sources | grep -v room_master_table
jadx_out/sources/com/example/data/AppDatabase_Impl.java:41:CREATE TABLE IF NOT EXISTS `session` (`userId` TEXT NOT NULL, `access_token` TEXT NOT NULL, `refresh_token` TEXT NOT NULL, PRIMARY KEY(`userId`))
$ grep -rn 'openHelperFactory' jadx_out/sources/com/example/ | wc -l
0
$ ls databases/
app.db  app.db-shm  app.db-wal
$ sqlite3 databases/app.db 'SELECT userId, substr(access_token,1,24), substr(refresh_token,1,12) FROM session;'
alice|eyJhbGciOiJIUzI1NiJ9.eyJz|rt_7f3a9c0d2
```

Fail: access and refresh tokens are stored in a plaintext Room database. Note that `sqlite3` opened `app.db` with its `-wal` alongside. Copy only `app.db` and you may see an empty table.

### MASTG-TEST-0320: WebViews Not Cleaning Up Sensitive Data (Android)

**Platform:** Android · **Type:** dynamic, hooks · **Knowledge:** MASTG-KNOW-0018 · **Best practice:** MASTG-BEST-0028 · [OWASP page](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0320/)

#### Overview

This test checks that sensitive data a WebView stores is removed once it is no longer needed. The usual triggers are logout, leaving the web-based flow, and app exit. The failure conditions OWASP lists are a storage area that is enabled without its matching cleanup call:

| Storage enabled when… | Cleanup expected |
|---|---|
| `setCacheMode()` is anything other than `LOAD_NO_CACHE` (the default is `LOAD_DEFAULT`), or legacy `setAppCacheEnabled(true)` | `WebView.clearCache(true)` |
| `setDomStorageEnabled(true)` | `WebStorage.getInstance().deleteAllData()` (or `deleteOrigin`) |
| `setDatabaseEnabled(true)` | `WebStorage.getInstance().deleteAllData()` |
| `CookieManager.setAcceptCookie()` not explicitly `false` (the default is `true`) | `CookieManager.removeAllCookies(...)` |

Web content uses these stores whether or not the app's own code calls the APIs: a page calling `localStorage.setItem()` writes to disk regardless. That is why the test combines API hooking with a search of the files on disk. IndexedDB, OPFS and the service-worker cache are not covered by any of these cleanup APIs. If the page uses them, only deleting the whole profile removes the data, so add them to your search.

#### Prerequisites

- The list of sensitive values the WebView handles (session cookies, tokens in Local Storage, PII rendered in pages), and when each should be gone.
- A rooted device or emulator with `frida-server`.
- The WebView version (`adb shell dumpsys webviewupdate | grep -i 'current webview'`).

#### Steps

1. Install the app.
2. Hook the storage-enablement and cleanup APIs. `WebSettings`, `CookieManager` and `WebStorage` are abstract. Their implementations live in the WebView provider's own class loader under `com.android.webview.chromium`, with class names that may be minified (MASTG-DEMO-0082 shows `WebStorage`'s implementation as `com.android.webview.chromium.e`). Method names survive because they implement the public API. So enumerate by method name and switch class loader, as the OWASP demo does:

   ```javascript
   // webview-storage.js   usage: frida -U -n "<App name>" -l webview-storage.js
   function bt() {
     return Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new())
       .split('\n').slice(1, 6).join('\n    ');
   }

   function hookImpl(method) {
     const groups = Java.enumerateMethods('com.android.webview.chromium.*!' + method);
     if (groups.length === 0) { console.log('not loaded yet: ' + method); return; }
     groups.forEach(function (group) {
       const factory = Java.ClassFactory.get(group.loader);
       group.classes.forEach(function (c) {
         factory.use(c.name)[method].overloads.forEach(function (ov) {
           ov.implementation = function () {
             const args = Array.prototype.map.call(arguments, String).join(', ');
             console.log('[' + method + '] (' + args + ')\n    ' + bt());
             return ov.apply(this, arguments);
           };
         });
         console.log('hooked ' + c.name + '.' + method);
       });
     });
   }

   Java.perform(function () {
     Java.use('android.webkit.WebStorage').getInstance();   // makes the provider classes loadable
     ['setCacheMode', 'setDomStorageEnabled', 'setDatabaseEnabled', 'setAllowFileAccess',
      'setAllowUniversalAccessFromFileURLs', 'setAllowContentAccess',
      'setAcceptCookie', 'removeAllCookies', 'removeSessionCookies',
      'deleteAllData', 'deleteOrigin'].forEach(hookImpl);

     const WebView = Java.use('android.webkit.WebView');
     WebView.clearCache.implementation = function (includeDiskFiles) {
       console.log('[clearCache] (' + includeDiskFiles + ')\n    ' + bt());
       return this.clearCache(includeDiskFiles);
     };
   });
   ```

   Attach (`-n`) rather than spawn. If a method reports "not loaded yet", open any WebView screen once and reload the script (`%reload` in the Frida REPL).
3. Exercise every WebView flow while entering your sensitive values: log in through it, view account pages, submit forms.
4. Close the app the way a user would (back out, or log out and then leave). Wait a few seconds. Repeat the run, this time ending with a hard kill (`adb shell am force-stop $PKG`, or swipe it away from recents), to see whether cleanup survives an abrupt exit.
5. Pull the WebView profile and the app cache, and search them:

   ```bash
   adb shell su -c "cd /data/data/$PKG && tar -cf /data/local/tmp/wv.tar app_webview* cache && chmod 644 /data/local/tmp/wv.tar"
   adb pull /data/local/tmp/wv.tar && mkdir -p wv && tar -xf wv.tar -C wv
   grep -rlaF -e 'SECRET_TOKEN_123456' -e 'DL-987654321' wv/
   python3 find_value.py 'DL-987654321' wv/          # also catches UTF-16LE Local Storage values
   sqlite3 -header -column 'wv/app_webview/Default/Cookies' \
     "SELECT host_key, name, value, is_secure, is_httponly, CASE has_expires WHEN 0 THEN 'session' ELSE datetime(expires_utc/1000000 - 11644473600, 'unixepoch') END AS expires FROM cookies;"
   ls -R 'wv/app_webview/Default/IndexedDB' 'wv/cache/WebView' 2>/dev/null | head
   ```

6. If you need finer detail on *when* files are written or deleted, trace file operations in the profile directory (MASTG-TECH-0143). Use `lsof` for open files, or `strace` (pushed to the device, needs root) for syscalls:

   ```bash
   adb shell su -c 'lsof -p $(pidof org.example.app) | grep -E "app_webview|/cache/WebView"'
   adb shell su -c '/data/local/tmp/strace -f -e trace=openat,unlinkat,renameat -p $(pidof org.example.app)' 2>&1 | grep app_webview
   ```

#### Observation

1. The storage-enablement APIs called (with arguments) and their call sites.
2. The cleanup APIs called, their call sites and lifecycle point (`onStop`, `onDestroy`, logout handler, next launch).
3. The list of sensitive values expected to be cleaned up, and when.
4. The search results over `app_webview*/` and `cache/` after a normal close and after a forced kill, including cookie rows and any IndexedDB origins present.

#### Evaluation

The test **fails** if sensitive data used in the WebView is still present in the WebView storage (the `app_webview*/` profile or the WebView HTTP cache under `cache/`) after the point at which it should have been removed, typically after logout or app close. Evidence for the fail can be a cleanup call that is missing for an enabled store, or one that exists but does not run on the path you tested (a forced kill). Report both.

It **passes** if, after the relevant lifecycle point, none of the sensitive values can be found and the hooks show the right cleanup APIs being called for every store that was enabled. Either cleanup must also be robust to abrupt termination (for example, a sweep at next launch before any WebView is shown), or nothing sensitive must be persisted in the first place (`Cache-Control: no-store` from the server, no DOM storage, no cookies).

Judgement calls: a session cookie for a still-logged-in user is expected while the session is active. The finding is that it survives logout. Cached static assets (fonts, images, JavaScript) are not sensitive. Server-rendered pages with account data are.

#### Demo

MASTG-DEMO-0082 enables JavaScript and DOM storage, and has the page store two values in `localStorage`:

```kotlin
webView.settings.apply {
    javaScriptEnabled = true
    domStorageEnabled = true
}
// page script:  localStorage.setItem('sensitive_token', 'SECRET_TOKEN_123456');
//               localStorage.setItem('driving_license_id', 'DL-987654321');
webView.loadDataWithBaseURL("https://mas.owasp.org/", html, "text/html", "utf-8", null)
```

The activity cleans up when it stops:

```kotlin
override fun onStop() {
    WebStorage.getInstance().deleteAllData()
    super.onStop()
}
```

The hook output shows both the enablement and the cleanup, with call sites:

```text
ContentSettingsAdapter.setDomStorageEnabled called, enabled is true.
  org.owasp.mastestapp.MastgTestWebView.mastgTest(MastgTestWebView.kt:20)
WebStorage.deleteAllData called.
  com.android.webview.chromium.e.deleteAllData(Native Method)
  org.owasp.mastestapp.MainActivityWebView.onStop(MainActivityWebView.kt:41)
```

After the app closes, `adb shell 'grep -nri -E "SECRET_TOKEN_123456|DL-987654321" /data/data/org.owasp.mastestapp/app_webview'` returns nothing, so the test **passes**. Comment out the `deleteAllData()` line and rerun, and the values remain in the Local Storage LevelDB log. The test then **fails**:

```text
Binary file /data/data/org.owasp.mastestapp/app_webview/Default/Local Storage/leveldb/000003.log matches
```

Note that the demo only exercises DOM storage. In a real app, repeat the same reasoning for cookies, the HTTP cache and IndexedDB, and test the forced-kill path, because `onStop()` is not guaranteed to run.

### MASTG-TEST-0299: Data Protection Classes for Files in Private Storage (iOS)

**Platform:** iOS · **Type:** dynamic, filesystem · **Best practice:** MASTG-BEST-0024 · [OWASP page](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0299/)

#### Overview

This test records the Data Protection class of every file the app (and its extensions) create or modify during normal use, across the Data container and every App Group container. It answers one question: which sensitive files are readable when the device is locked, or before it has ever been unlocked since boot? A sensitive file at `NSFileProtectionNone` is readable by a BFU forensic acquisition and by anything that gets file system access at boot, before the owner has entered a passcode.

The test does not tell you whether content is encrypted by the app — a plaintext file at `NSFileProtectionComplete` passes this test and still fails MASTG-TEST-0302. Run them together.

#### Prerequisites

- A **physical** device with a passcode set. The Simulator does not enforce Data Protection; a device without a passcode gives misleading results.
- In-process access: a jailbroken device with `frida-server`, or a re-signed build with Frida Gadget (objection `patchipa`). SSH on a jailbroken device additionally lets you list extension containers.
- A clean install: delete the app, clear its Keychain items (objection `ios keychain clear` from a previous session) and reinstall, so every file you see came from this session.
- A list of what counts as sensitive for this app (credentials, tokens, keys, PII, financial or health data, message content). OWASP calls this the `identify-sensitive-data` prerequisite; agree it with the client up front.
- The app's and extensions' `application-groups` entitlements (see MASTG-TEST-0388, step 2) so you know which group containers to list.

#### Steps

1. Install the app (`ideviceinstaller -i app.ipa`, `xcrun devicectl device install app --device <id> app.ipa`, or Sideloadly for a re-signed IPA).
2. Exercise the app thoroughly: register, log in, view profile and statements, send messages, use offline mode, trigger any crypto or biometric features, log out and back in. Trigger each extension too (share into the app, add its widget, send a push to a notification service extension).
3. With the app in the foreground, attach the Frida enumeration script from "Accessing the app sandbox":

   ```bash
   frida -U -F -l list-protection.js -o files.tsv
   ```

   Or, interactively, use objection's `ls` in each directory and read the `NSFileProtection` column.
4. For extension containers under `Containers/Data/PluginKitPlugin/`, attach the same script to the extension process while it runs, or list the directory over SSH and check individual files with objection from the extension's process.
5. Filter the results:

   ```bash
   awk -F'\t' '$1 == "NSFileProtectionNone"' files.tsv
   awk -F'\t' '$1 == "NSFileProtectionCompleteUntilFirstUserAuthentication"' files.tsv | cut -f3
   ```

6. Pull each flagged file and check whether it holds sensitive data (`plutil -p`, `sqlite3`, `strings`, see "Reading what you pulled").
7. Optional, jailbroken only: confirm the behaviour empirically. Lock the device, wait 15 seconds, then try to read the file over SSH. A `Complete` file should fail to open; `None` and default-class files will read.
8. Check whether the app sets an app-wide default: `codesign -d --entitlements - Payload/MyApp.app/MyApp | grep -A1 default-data-protection`.

#### Observation

For each file: absolute path, container (Data, App Group ID, extension), protection class, size, and a note on whether it holds sensitive data and what kind. Keep the raw `files.tsv` as evidence, plus the content extracts for files you flag.

#### Evaluation

The test **fails** if any file containing sensitive data has the protection class `NSFileProtectionNone`, in the Data container, an App Group container or an extension container.

Record but grade separately:

- Sensitive data at the default `CompleteUntilFirstUserAuthentication` that the app never needs while the device is locked (no background processing touches it). This passes the OWASP criterion but is the common real-world gap: it is readable in AFU state. For L2 apps, recommend `Complete`.
- An app-wide `com.apple.developer.default-data-protection` entitlement of `NSFileProtectionComplete` combined with individual files explicitly downgraded to `None` — usually a background-task workaround; find out what needs it.

Common false positives: SDK and system files at `None` that are not sensitive (crash reporter state, `.com.apple.mobile_container_manager.metadata.plist`, some `SplashBoard` files, analytics queues containing only event names). Inspect content before reporting.

#### Demo

A minimal app that writes the same session blob three ways (adapted from the MASTestApp demo pattern; OWASP does not publish a demo for this test):

```swift
struct MastgTest {
  static func mastgTest(completion: @escaping (String) -> Void) {
    let blob = Data(#"{"user":"alice","token":"eyJhbGciOiJIUzI1NiJ9.demo.sig"}"#.utf8)
    let fm = FileManager.default
    let docs = fm.urls(for: .documentDirectory, in: .userDomainMask)[0]
    let support = try! fm.url(for: .applicationSupportDirectory, in: .userDomainMask,
                              appropriateFor: nil, create: true)

    // FAIL: explicitly unprotected, readable before first unlock
    try? blob.write(to: docs.appendingPathComponent("session.json"), options: .noFileProtection)

    // FAIL: same blob in the App Group container, also unprotected
    if let group = fm.containerURL(forSecurityApplicationGroupIdentifier: "group.org.owasp.mastestapp") {
      try? blob.write(to: group.appendingPathComponent("session.json"), options: .noFileProtection)
    }

    // Passes this test (class A) but still plaintext: fails MASTG-TEST-0302
    try? blob.write(to: support.appendingPathComponent("session.json"), options: .completeFileProtection)

    completion("written")
  }
}
```

Running `list-protection.js` after tapping the button (UUIDs shortened):

```text
NSFileProtectionCompleteUntilFirstUserAuthentication  1022  /var/mobile/Containers/Data/Application/976D…/Library/Preferences/org.owasp.mastestapp.MASTestApp-iOS.plist
NSFileProtectionNone                                    56  /var/mobile/Containers/Data/Application/976D…/Documents/session.json
NSFileProtectionComplete                                56  /var/mobile/Containers/Data/Application/976D…/Library/Application Support/session.json
NSFileProtectionNone                                    56  /private/var/mobile/Containers/Shared/AppGroup/1B2C…/session.json
```

Both `session.json` files at `NSFileProtectionNone` contain a bearer token: the test fails twice. The `Application Support` copy passes this test.

### MASTG-TEST-0300: References to APIs for Storing Unencrypted Data in Private Storage (iOS)

**Platform:** iOS · **Type:** static, code · **Best practice:** MASTG-BEST-0024 · [OWASP page](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0300/)

#### Overview

This test finds every place where the app, its frameworks and its extensions can write data to the sandbox, and every place where it uses the Keychain, then decides for each sensitive value whether it is encrypted (with a key from the Keychain) or stored in the Keychain itself. Static analysis gives you coverage of code paths you may never trigger dynamically — error handlers, migration code, "remember me" branches, debug menus — and tells you the accessibility attributes the code intends to use.

#### Prerequisites

- The IPA. For App Store builds it must be decrypted first (FairPlay). Check each Mach-O: `otool -l <binary> | grep -A4 LC_ENCRYPTION_INFO` — `cryptid 1` means encrypted; dump it from a jailbroken device with a FairPlay decryption tool such as frida-ios-dump or bagbak.
- Xcode command-line tools (`nm`, `otool`, `codesign`, `swift-demangle`) and radare2 (`r2`, `rabin2`). Source code access makes the test much faster; use it if available.
- The sensitive-data list for the app.

#### Steps

1. Unpack and list every binary you need to analyse — the main executable, each embedded framework, and each extension:

   ```bash
   unzip -q app.ipa -d ipa && APP=$(ls -d ipa/Payload/*.app)
   ls "$APP/Frameworks" "$APP/PlugIns" 2>/dev/null
   otool -L "$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")"
   ```

   Third-party storage stacks are often recognisable from the framework list alone: `Realm.framework`, `RealmSwift.framework`, `SQLCipher`, `GRDB`, `FMDB`, `CouchbaseLite`, plus `libsqlite3.dylib` and `CoreData.framework` in `otool -L`.
2. List imported symbols in each binary and filter for storage, Keychain and crypto APIs:

   ```bash
   B="$APP/MyApp"
   xcrun nm -u "$B" | xcrun swift-demangle | grep -E \
     'NSUserDefaults|UserDefaults|NSFileManager|createFile|Data\.write|writeToFile|writeToURL|NSFileHandle|NSPersistentContainer|NSPersistentStore|sqlite3_open|_open$|_fopen$|Realm|SecItemAdd|SecItemUpdate|SecItemCopyMatching|kSecAttrAccessible|kSecAttrAccessControl|kSecAttrAccessGroup|SecAccessControlCreateWithFlags|NSFileProtection|CCCrypt|CryptoKit|SecKeyCreateEncryptedData'
   ```

   The constants are especially informative: an import of `_kSecAttrAccessibleAlways` or `_kSecAttrAccessibleAfterFirstUnlock` tells you the code *uses* that accessibility level somewhere; `_NSFileProtectionNone` tells you some code sets a file to class D via `FileManager` attributes. Their absence is not proof — `Data.WritingOptions` protection levels are plain integers (`.noFileProtection` = `0x10000000`, `.completeFileProtection` = `0x20000000`, `.completeFileProtectionUnlessOpen` = `0x30000000`, `.completeFileProtectionUntilFirstUserAuthentication` = `0x40000000`) and leave no symbol.
3. Look for the storage keys and file names that reveal *what* is stored:

   ```bash
   rabin2 -zz "$B" | grep -iE 'token|password|passcode|pin|secret|session|refresh|apikey|\.sqlite|\.realm|\.plist|\.json|\.db'
   ```

4. Locate call sites with radare2 and read the code around each one (`r2 -A "$B"`):

   ```text
   ii~+SecItemAdd,kSecAttrAccessible,UserDefaults,NSFileProtection   # imports and their addresses
   axt @ sym.imp.SecItemAdd                                          # who calls it
   izz~+authToken                                                    # where a key string lives
   axt @ <string address>                                            # who uses that string
   pdf @ <calling function>                                          # read the function
   ```

   For each call site, establish which value is written, where (directory, file name or defaults key), with what protection (`Data.WritingOptions` immediate, `FileProtectionType` constant, `kSecAttrAccessible` value), and whether it passed through `CCCrypt`, CryptoKit `AES.GCM.seal`/`ChaChaPoly.seal` or `SecKeyCreateEncryptedData` first.
5. Check the entitlements and plist settings that change storage behaviour:

   ```bash
   codesign -d --entitlements - "$B"          # default-data-protection, keychain-access-groups, application-groups
   plutil -p "$APP/Info.plist" | grep -E 'UIFileSharingEnabled|LSSupportsOpeningDocumentsInPlace'
   ```

6. If you have source, search it directly. A quick grep, then Semgrep for the defaults case:

   ```bash
   grep -rnE 'UserDefaults|\.write\(to:|createFile\(atPath|noFileProtection|FileProtectionType\.none|kSecAttrAccessibleAlways|kSecAttrAccessibleAfterFirstUnlock|encryptionKey:|sqlite3_open' --include='*.swift' --include='*.m' .
   ```

   ```yaml
   rules:
     - id: ios-sensitive-value-in-userdefaults
       languages: [swift]
       severity: WARNING
       message: Possible secret stored in UserDefaults (plaintext plist in the sandbox)
       patterns:
         - pattern: $DEFAULTS.set($VALUE, forKey: "$KEY")
         - metavariable-regex:
             metavariable: $KEY
             regex: (?i).*(token|password|passcode|pin|secret|session|apikey|cookie).*
   ```

#### Observation

- A table of write locations: binary, function/address, API, destination (directory and file name or defaults key), value written (if determinable), protection option, and whether an encryption call precedes it.
- A table of Keychain uses: binary, function, operation (`SecItemAdd` / `SecItemUpdate` / `SecItemCopyMatching`), item class, service/account, accessibility attribute or access control flags, access group, `kSecAttrSynchronizable`.
- Relevant entitlements and `Info.plist` keys.

#### Evaluation

The test **fails** if sensitive data is written to private storage without being encrypted first, or if a secret that belongs in the Keychain (credentials, tokens, keys) is stored anywhere else.

Concretely, flag:

- Secrets written with `UserDefaults` (standard or suite), `NSKeyedArchiver`/`Codable` plus `Data.write`, Core Data/SQLite/Realm without encryption, or into `Library/Caches`/`tmp`.
- Encryption whose key is hardcoded in the binary, derived from a constant or the device identifier, or stored in `UserDefaults` or a file next to the ciphertext. That is the "Hardcoded Encryption Key" and "Encryption Key Stored on Filesystem" modes; cross-reference MASWE-0003 ([Cryptographic Keys Not Stored in the Platform Keystore](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/)).
- Keychain items holding long-lived credentials or file-encryption keys with `kSecAttrAccessibleAlways*` (deprecated, readable before first unlock) or without a `ThisDeviceOnly` variant where migration to another device is not intended.

Static results need confirmation: a reference to `kSecAttrAccessibleAlways` may be dead code or in an unused SDK path, and a `UserDefaults` write may store a non-sensitive flag. Confirm each candidate with MASTG-TEST-0301/0302 before rating.

#### Demo

Vulnerable sample covering the three most common patterns:

```swift
import Foundation
import Security

struct MastgTest {
  static func mastgTest(completion: @escaping (String) -> Void) {
    let token = "eyJhbGciOiJIUzI1NiJ9.demo.sig"

    // 1. Plaintext plist: Library/Preferences/<bundle-id>.plist
    UserDefaults.standard.set(token, forKey: "authToken")

    // 2. Plaintext file at class D
    let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
      .appendingPathComponent("session.json")
    try? Data(token.utf8).write(to: url, options: .noFileProtection)

    // 3. Keychain, but readable before first unlock and migrates via backups
    let item: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrAccount as String: "refresh",
      kSecValueData as String: Data(token.utf8),
      kSecAttrAccessible as String: kSecAttrAccessibleAlways   // deprecated since iOS 12
    ]
    SecItemAdd(item as CFDictionary, nil)
    completion("stored")
  }
}
```

Imports of interest (`xcrun nm -u MASTestApp | xcrun swift-demangle | grep -E 'SecItem|kSecAttr|UserDefaults|Data.write'`, abridged; Swift symbol names vary by toolchain):

```text
_OBJC_CLASS_$_NSUserDefaults
_SecItemAdd
_kSecAttrAccessible
_kSecAttrAccessibleAlways
_kSecAttrAccount
_kSecValueData
Foundation.Data.write(to: Foundation.URL, options: __C.NSDataWritingOptions) throws -> ()
```

`_kSecAttrAccessibleAlways` alone is enough to open a finding candidate. In radare2, `axt` on `sym.imp.SecItemAdd` leads to the `mastgTest` function; around the `Data.write` call you will see the options argument loaded as an immediate, for example `mov w2, 0x10000000` (`.noFileProtection`), and the string search `izz~authToken` leads to the `setObject:forKey:` call site. All three findings are confirmed: a bearer token in a plaintext plist, in a class D file, and in a Keychain item with deprecated `Always` accessibility.

### MASTG-TEST-0301: Runtime Use of APIs for Storing Unencrypted Data in Private Storage (iOS)

**Platform:** iOS · **Type:** dynamic, hooks · **Best practice:** MASTG-BEST-0024 · [OWASP page](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0301/)

#### Overview

The dynamic counterpart to MASTG-TEST-0300, intended to be run with MASTG-TEST-0302. You hook the file, preferences, Keychain and crypto APIs at runtime and watch what the app actually writes, with what protection, and whether it was encrypted on the way. This defeats obfuscation and catches code in frameworks you did not analyse statically.

Hook at more than one layer. Some writes never reach an `open` call in the app process: `UserDefaults` changes are sent to the `cfprefsd` daemon, which writes the plist itself; `URLCache` and WebKit storage are partly handled by other processes. Conversely, libraries written in C/C++ (SQLite, Realm, cross-platform runtimes) never touch the Objective-C APIs and only show up in `open`. On recent iOS versions parts of Foundation are implemented in Swift, so a Swift `Data.write` may not pass through `-[NSData writeToURL:options:error:]` — the libc `open` hook remains the reliable backstop.

#### Prerequisites

- A device (jailbroken with `frida-server`, or a Frida Gadget build), Frida 17+ on the host (for older Frida, replace `Module.getGlobalExportByName(name)` with `Module.findExportByName(null, name)`).
- A clean install and Keychain, as in MASTG-TEST-0299.
- The sensitive-data list, and test credentials you can recognise in output (use a distinctive password such as `Gt-Probe-7731`).

#### Steps

1. Install the app.
2. Spawn it with the tracing script so you catch writes made at launch:

   ```bash
   frida -U -f com.example.app -l storage-trace.js -o trace.log
   ```

   ```javascript
   // storage-trace.js
   const O_WRONLY = 0x1, O_RDWR = 0x2, O_CREAT = 0x200;
   const SANDBOX = /\/mobile\/Containers\/(Data|Shared)\//;
   const PROT = { 0x0: "default", 0x10000000: "None", 0x20000000: "Complete",
                  0x30000000: "CompleteUnlessOpen", 0x40000000: "CompleteUntilFirstUserAuthentication" };

   function bt(ctx) {
     return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 6)
       .map(a => "    " + DebugSymbol.fromAddress(a)).join("\n");
   }
   function preview(obj) {
     if (obj === null) return "(null)";
     if (obj.isKindOfClass_(ObjC.classes.NSData)) {
       const s = ObjC.classes.NSString.alloc().initWithData_encoding_(obj, 4); // UTF-8
       return s !== null ? s.toString().slice(0, 200) : `<${obj.length()} bytes binary>`;
     }
     return obj.toString().slice(0, 200);
   }

   Interceptor.attach(Module.getGlobalExportByName("open"), {
     onEnter(args) {
       const path = args[0].readCString(), flags = args[1].toInt32();
       if (SANDBOX.test(path) && (flags & (O_WRONLY | O_RDWR | O_CREAT)))
         console.log(`[open w] ${path}\n${bt(this.context)}`);
     }
   });

   Interceptor.attach(ObjC.classes.NSData["- writeToURL:options:error:"].implementation, {
     onEnter(args) {
       const opts = args[3].toInt32() & 0xf0000000;
       console.log(`[NSData write] ${new ObjC.Object(args[2])} protection=${PROT[opts]}\n` +
                   `  data: ${preview(new ObjC.Object(args[0]))}`);
     }
   });

   Interceptor.attach(ObjC.classes.NSFileManager["- createFileAtPath:contents:attributes:"].implementation, {
     onEnter(args) {
       const attrs = args[4].isNull() ? null : new ObjC.Object(args[4]);
       const prot = attrs ? attrs.objectForKey_("NSFileProtectionKey") : null;
       console.log(`[createFile] ${new ObjC.Object(args[2])} protection=${prot || "default"}\n` +
                   `  data: ${args[3].isNull() ? "(none)" : preview(new ObjC.Object(args[3]))}`);
     }
   });

   Interceptor.attach(ObjC.classes.NSUserDefaults["- setObject:forKey:"].implementation, {
     onEnter(args) {
       const v = args[2].isNull() ? null : new ObjC.Object(args[2]);
       console.log(`[UserDefaults] ${new ObjC.Object(args[3])} = ${preview(v)}`);
     }
   });

   ["SecItemAdd", "SecItemUpdate"].forEach(fn => {
     Interceptor.attach(Module.getGlobalExportByName(fn), {
       onEnter(args) {
         const q = new ObjC.Object(args[0]);
         const attrs = fn === "SecItemUpdate" ? new ObjC.Object(args[1]) : q;
         const get = (d, k) => { const v = d.objectForKey_(k); return v === null ? "-" : v.toString(); };
         console.log(`[${fn}] class=${get(q, "class")} svce=${get(q, "svce")} acct=${get(q, "acct")} ` +
                     `pdmn=${get(attrs, "pdmn")} accc=${attrs.objectForKey_("accc") ? "set" : "-"} ` +
                     `agrp=${get(q, "agrp")} sync=${get(attrs, "sync")}\n` +
                     `  v_Data: ${preview(attrs.objectForKey_("v_Data"))}`);
       }
     });
   });

   Interceptor.attach(Module.getGlobalExportByName("CCCrypt"), {
     onEnter(args) {
       console.log(`[CCCrypt] op=${args[0].toInt32() === 0 ? "encrypt" : "decrypt"} ` +
                   `alg=${args[1].toInt32()} keyLen=${args[4].toInt32()}\n${bt(this.context)}`);
     }
   });
   ```

3. Exercise the app as in MASTG-TEST-0299, using recognisable test values. Note the time of each action so you can line it up with the log.
4. Optionally add hooks for what you found statically: `-[NSFileHandle writeData:]`, `sqlite3_exec` / `sqlite3_prepare_v2` (log the SQL), `-[RLMRealmConfiguration setEncryptionKey:]` (the Realm key), `SecKeyCreateEncryptedData`, or `-[NSURLCache storeCachedResponse:forRequest:]`. CryptoKit is pure Swift; trace it with `frida-trace -U -f com.example.app -i '*CryptoKit*seal*'` or by hooking the resolved Swift symbols.
5. Correlate: for every `[open w]` line, find the matching higher-level call (backtrace) and the file content you collect in MASTG-TEST-0302; for every encrypted write, find which `SecItemCopyMatching`/`SecItemAdd` produced the key.

#### Observation

- Every Keychain write with item class, service/account, accessibility (`pdmn` short code), whether access control is set, access group and synchronisable flag, and the stored value or its type.
- Every file and defaults write with path or key, protection class requested, a preview of the data, and the backtrace showing the calling code.
- Crypto calls that precede writes, with key length.

#### Evaluation

The test **fails** if sensitive data is written to private storage without encryption, or if a secret is stored somewhere other than the Keychain.

Proving encryption from hooks alone is not always possible. Use the correlation:

- Plaintext sensitive value visible in a `[UserDefaults]`, `[NSData write]` or `[createFile]` preview: fail.
- A `[CCCrypt] op=encrypt` (or CryptoKit seal) immediately before a write, with the key obtained from `SecItemCopyMatching` on a `ThisDeviceOnly` item: good. The same pattern with the key read from `UserDefaults`, a file, or a constant in the binary: fail — the key is stored alongside the data.
- Keychain writes with `pdmn=dk` or `pdmn=dku` for credentials or keys: fail (deprecated `Always`). `pdmn=ak`/`ck` for long-lived secrets: report as a weakness (migrates through backups), not as a MASWE-0001 failure on its own.
- Base64, hex or `NSKeyedArchiver` output is not encryption. Decode previews before deciding.

#### Demo

Running `storage-trace.js` against the MASTG-TEST-0300 sample (backtraces trimmed):

```text
[UserDefaults] authToken = eyJhbGciOiJIUzI1NiJ9.demo.sig
[NSData write] file:///var/mobile/Containers/Data/Application/976D…/Documents/session.json protection=None
  data: eyJhbGciOiJIUzI1NiJ9.demo.sig
[open w] /var/mobile/Containers/Data/Application/976D…/Documents/session.json
    0x19a8dfd68 Foundation!_NSOpenFileDescriptor_Protected
    0x19a8cb884 Foundation!_NSWriteDataToFileWithExtendedAttributes
    0x104ab0418 MASTestApp!static MastgTest.mastgTest(completion:)
[SecItemAdd] class=genp svce=- acct=refresh pdmn=dk accc=- agrp=- sync=-
  v_Data: eyJhbGciOiJIUzI1NiJ9.demo.sig
```

Note there is no `[open w]` line for the preferences plist — `cfprefsd` wrote it — which is why the `UserDefaults` hook exists. Three failures: plaintext token to defaults, plaintext token to a class D file, and a token in the Keychain with `pdmn=dk` (`kSecAttrAccessibleAlways`) and no `CCCrypt` call anywhere in the flow.

### MASTG-TEST-0302: Sensitive Data Unencrypted in Private Storage Files (iOS)

**Platform:** iOS · **Type:** dynamic, filesystem · **Best practice:** MASTG-BEST-0024 · [OWASP page](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0302/)

#### Overview

A differential analysis: snapshot the app's storage (Data container, App Group containers, extension containers) and its Keychain items, use the app, snapshot again, and examine everything that is new or changed. It complements MASTG-TEST-0301: hooks tell you *how* data was written; this test tells you *what is on disk* afterwards, including data written by daemons and native code your hooks missed.

#### Prerequisites

- A jailbroken device with SSH (simplest), or a Gadget build where you pull files with objection `file download` and list them with the Frida script. On debug builds you can use Xcode's Download Container for the snapshots, but it does not include App Group or extension containers.
- `tar`, `shasum`, `plutil`, `sqlite3`, `jq` on the host; `tar` on the device.
- Clean state: fresh install and cleared Keychain (objection `ios keychain clear`), as items survive uninstall.
- Distinctive test values (username, password, PIN, profile data) so you can grep for them.

#### Steps

1. Install the app and launch it once so the containers exist; locate them (see "Accessing the app sandbox").
2. Take the baseline file snapshot:

   ```bash
   DATA=/var/mobile/Containers/Data/Application/<DATA-UUID>
   GROUP=/var/mobile/Containers/Shared/AppGroup/<GROUP-UUID>
   snap() {
     for pair in "data:$DATA" "group:$GROUP"; do
       name=${pair%%:*}; dir=${pair#*:}
       mkdir -p "snap-$1/$name"
       ssh -p 2222 root@localhost "tar -C '$dir' -cf - ." | tar -xf - -C "snap-$1/$name"
     done
     (cd "snap-$1" && find . -type f -exec shasum -a 256 {} + | sort -k2) > "snap-$1.sha256"
   }
   snap before
   ```

   Add extension containers to the loop if the app has extensions that write data.
3. Take the baseline Keychain snapshot from inside the app: `ios keychain dump --json kc-before.json` in objection (or `keychain_dumper > kc-before.txt` over SSH on a jailbroken device to include items from other access groups). Record accessibility and access control for each item.
4. Exercise the app and its extensions extensively with your test values, then send it to the background and bring it back (some apps flush state on backgrounding).
5. Take the second file snapshot: `snap after`. Also run the Frida listing from MASTG-TEST-0299 now if you want protection classes in the same report.
6. Diff the snapshots and list new, deleted and modified files:

   ```bash
   diff snap-before.sha256 snap-after.sha256 | grep '^[<>]'
   ```

   A path that appears only with `>` is new; only with `<` is deleted; with both, modified.
7. Take the second Keychain snapshot (`ios keychain dump --json kc-after.json`) and diff it:

   ```bash
   diff <(jq -S . kc-before.json) <(jq -S . kc-after.json)
   ```

8. Triage every new or modified file:

   ```bash
   cd snap-after
   grep -rIlE 'Gt-Probe-7731|alice@example\.com|eyJ[A-Za-z0-9_-]{10,}\.|Bearer |refresh_token' .   # plaintext hits
   diff ../snap-before.sha256 ../snap-after.sha256 | awk '/^>/ {print $3}' | xargs file           # inferred type (paths without spaces)
   for f in $(find . -name '*.plist'); do plutil -p "$f" | grep -iE 'token|pass|pin|secret|session'; done
   for f in $(find . -name '*.sqlite' -o -name '*.db'); do sqlite3 -readonly "$f" .dump 2>/dev/null | grep -iE 'Gt-Probe|eyJ|token'; done
   ```

9. Look past trivial encodings. For files or values that do not match in plaintext:
   - **Base64 / Base64URL:** `grep -oE '[A-Za-z0-9+/_-]{24,}={0,2}' file | while read b; do echo "$b" | base64 -d 2>/dev/null | strings -n 6; done`. JWTs decode one segment at a time.
   - **Hex:** `xxd -r -p <<< "<hex string>" | strings`.
   - **Binary plists and `NSKeyedArchiver` blobs:** `plutil -p`; nested `<data>` values are often another plist.
   - **Compressed:** `file` reports gzip/zip/zlib; decompress with `gunzip`, `unzip -l`, or `python3 -c 'import sys,zlib;print(zlib.decompress(open(sys.argv[1],"rb").read()))' f`.
   - **UTF-16 ("wide") strings:** `strings -el file` (16-bit little-endian).
   - **Simple XOR or custom obfuscation:** a file whose length matches your input exactly and that compresses well (`gzip -c f | wc -c` close to, or smaller than, the original) is not real encryption. Proper ciphertext is incompressible and usually carries a nonce/tag overhead.
   - **Encrypted SQLite:** `sqlite3` says `file is not a database` and the header is not `SQLite format 3` — note it and find the key source with MASTG-TEST-0301.

#### Observation

- New or modified files with path, size, SHA-256, inferred type, and status: plaintext / encoded (which encoding) / encrypted / unknown. Include the decoded sensitive value as evidence (redacted in the report).
- New or modified Keychain items with service, account, accessibility, access control and access group.

#### Evaluation

The test **fails** if sensitive data appears in plaintext or trivially encoded form (Base64, hex, URL encoding, escape sequences, binary plist, compression, wide characters, XOR or similar obfuscation) in any new or modified file.

Then review the Keychain diff: new items holding secrets are expected and good, provided their accessibility is appropriate; an item holding a key whose ciphertext you found on disk confirms encryption with a Keychain key. An encryption key found on disk next to its ciphertext, or in `UserDefaults`, is a failure even though the data file itself looks encrypted.

Common false positives: tokens that are public by design (push tokens, analytics install IDs, the Firebase API key, which is not a secret), cached public content, and your own username in a "last user" field where the client accepts it (still worth an Info note for shared-device use cases).

#### Demo

After logging in to the sample app with `alice` / `Gt-Probe-7731` and viewing the profile:

```text
$ diff snap-before.sha256 snap-after.sha256 | grep '^[<>]'
< 9f2c…  ./data/Library/Preferences/org.owasp.mastestapp.MASTestApp-iOS.plist
> 41ab…  ./data/Library/Preferences/org.owasp.mastestapp.MASTestApp-iOS.plist
> 7c1e…  ./data/Documents/session.json
> d03a…  ./data/Library/Caches/org.owasp.mastestapp.MASTestApp-iOS/Cache.db
> 52f9…  ./group/Library/Preferences/group.org.owasp.mastestapp.plist

$ plutil -p snap-after/data/Library/Preferences/org.owasp.mastestapp.MASTestApp-iOS.plist
{
  "authToken" => "eyJhbGciOiJIUzI1NiJ9.demo.sig"
  "lastUser" => "alice"
}

$ sqlite3 -readonly snap-after/data/Library/Caches/org.owasp.mastestapp.MASTestApp-iOS/Cache.db \
    "SELECT request_key FROM cfurl_cache_response;"
https://api.example.com/v1/profile
```

The preferences plist was modified to hold the bearer token in plaintext, a new `session.json` holds it again, and the URL cache stored the `/v1/profile` response (the body in `cfurl_cache_receiver_data` contains the user's name and email). The Keychain diff shows one new item, `acct=refresh` with `Always` accessibility. The test fails on the plist, the JSON file and the cached profile response.

### MASTG-TEST-0388: References to Sensitive Data Stored Unprotected in Shared App Group Containers (iOS)

**Platform:** iOS · **Type:** static, code, manual · **Best practice:** MASTG-BEST-0068 · [OWASP page](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0388/)

#### Overview

An app and its extensions share data through App Group containers, where every member of the group has equal read and write access and nothing is protected beyond its file protection class. This test checks, in the main binary and every `.appex`, whether credentials, tokens or other secrets are written to shared `UserDefaults`, the shared file container or a shared Core Data store instead of a shared Keychain access group, and whether what is written there is encrypted.

The typical pattern behind this finding: the app logs in, then copies the access token into `UserDefaults(suiteName:)` so a share extension or widget can call the API. It works, and it leaves the token in a plaintext plist in a container that outlives logout, is backed up, and is readable by every extension in the group.

#### Prerequisites

- The decrypted IPA, including the extension binaries under `PlugIns/*.appex` (check `cryptid` for each binary; extensions are FairPlay-encrypted separately).
- radare2/rabin2 and `codesign` (or `ldid`) on the host.
- The sensitive-data list.
- For the manual validation step, the ability to view the group container on a device (any method from "Accessing the app sandbox").

#### Steps

1. Enumerate every binary and its entitlements:

   ```bash
   APP=$(ls -d ipa/Payload/*.app)
   for b in "$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")" "$APP"/PlugIns/*.appex/*; do
     [ -f "$b" ] && file "$b" | grep -q Mach-O || continue
     echo "== $b"
     ldid -e "$b" | grep -A4 -E 'application-groups|keychain-access-groups'
   done
   ```

   On a Mac, `codesign -d --entitlements - "$b"` gives the same information (recent macOS versions print it in a bracketed text format rather than XML; the `grep` still works). Note which binaries share which group IDs and whether any of them declare `keychain-access-groups`.
2. In each binary, find App Group API references and group ID strings:

   ```bash
   rabin2 -zz "$b" | grep -E 'group\.|initWithSuiteName:|containerURLForSecurityApplicationGroupIdentifier:|NSPersistentContainer|sharedContainerIdentifier'
   ```

   `UserDefaults(suiteName:)` and `FileManager.containerURL(forSecurityApplicationGroupIdentifier:)` compile to Objective-C message sends, so their selectors show up as strings even in pure Swift code.
3. Find the call sites in radare2 (`r2 -A "$b"`): search the string (`izz~initWithSuiteName`), then `axt @ <address>` to reach the calling function, and `pdf` to read it. For each call site, determine the group ID used, the keys or file names written, and the value source.
4. Check whether the binaries also use the Keychain for shared secrets: imports of `SecItemAdd`/`SecItemCopyMatching` and `kSecAttrAccessGroup` (`xcrun nm -u "$b" | grep -E 'SecItem|kSecAttrAccessGroup'`).
5. **Manual validation** (the "Further Validation Required" step). Review each reported location in the disassembly or source to decide:
   - Is the value written to the shared container sensitive (credentials, access/refresh tokens, API keys, session cookies, PII)?
   - Is it encrypted before being written, or, for files, written with `NSFileProtectionComplete` (confirm with MASTG-TEST-0299)?
   - Is it a secret that should be in a shared Keychain access group instead?
6. Confirm on a device: exercise the app and each extension, then inspect the group container:

   ```bash
   plutil -p "<group container>/Library/Preferences/group.com.example.app.plist"
   ls -laR "<group container>"
   ```

#### Observation

A list of locations in the app and its extensions that access App Group containers — `UserDefaults(suiteName:)`, `containerURL(forSecurityApplicationGroupIdentifier:)`, `NSPersistentContainer` stores in the group container — with the group ID, the keys/files written and what they contain. Plus, per binary, whether `keychain-access-groups` is declared and whether the Keychain is used for the shared secrets.

#### Evaluation

The test **fails** if sensitive data is written to an App Group shared container — shared `UserDefaults`, the shared file container or a shared Core Data store — without adequate protection: secrets stored in plaintext, or in shared `UserDefaults` at all, instead of a shared Keychain access group.

Severity depends on what the secret unlocks and which members need it. A widget that only displays a cached balance is fine with a non-secret summary in the group container. An access token there is not, regardless of which extension "needs" it — the extension should read it from a shared Keychain item.

#### Demo

A share extension needs to upload to the API, so the main app copies the session token into the shared container (adapted pattern; OWASP does not publish a demo for this test):

```swift
// Main app, after login
let shared = UserDefaults(suiteName: "group.org.owasp.mastestapp")
shared?.set(session.accessToken, forKey: "accessToken")
shared?.set(session.refreshToken, forKey: "refreshToken")

// ShareExtension.appex
let token = UserDefaults(suiteName: "group.org.owasp.mastestapp")?.string(forKey: "accessToken")
```

Detection (abridged):

```text
== ipa/Payload/MASTestApp.app/MASTestApp
	<key>com.apple.security.application-groups</key>
	<array>
		<string>group.org.owasp.mastestapp</string>
	</array>
== ipa/Payload/MASTestApp.app/PlugIns/ShareExtension.appex/ShareExtension
	<key>com.apple.security.application-groups</key>
	<array>
		<string>group.org.owasp.mastestapp</string>
	</array>

$ rabin2 -zz .../ShareExtension | grep -E 'group\.|initWithSuiteName:'
... group.org.owasp.mastestapp
... initWithSuiteName:

$ plutil -p .../Shared/AppGroup/1B2C…/Library/Preferences/group.org.owasp.mastestapp.plist
{
  "accessToken" => "eyJhbGciOiJIUzI1NiJ9.demo.sig"
  "refreshToken" => "rt_7f3a9c…"
}
```

Neither binary declares `keychain-access-groups`. The refresh token — the long-lived credential — sits in a plaintext plist in the group container at the default protection class. The test fails; the fix is a shared Keychain item (MASTG-BEST-0068).

## Best practices

### MASTG-BEST-0050: Store Data Encrypted in App Sandbox Directory (Android)

[OWASP page](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0050/) · Knowledge: MASTG-KNOW-0036

The first question is whether the data needs to be stored on the device at all. A token that can be re-obtained, a profile that can be fetched on demand or a statement that can be rendered from the server are each one less thing to encrypt. For what must stay, encrypt it before it reaches the file, with authenticated encryption (AES-GCM or Tink AEAD) and a key that lives in the Android Keystore or is wrapped by one. Don't write your own cryptography, and don't keep the key, or anything it can be derived from, in the sandbox or the APK.

#### A small Keystore-backed helper

Most of the options below need the same building block: an AES-256-GCM key that is generated inside the Keystore and never leaves it.

```kotlin
object KeystoreBox {
    private const val ALIAS = "app_kek"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // .setUnlockedDeviceRequired(true)  // API 28+: unusable while the device is locked
                .build()
        )
        return generator.generateKey()
    }

    fun encrypt(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())             // Keystore picks a random 12-byte IV
        return cipher.iv + cipher.doFinal(plain)            // IV || ciphertext || tag
    }

    fun decrypt(blob: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob, 0, 12))
        return cipher.doFinal(blob, 12, blob.size - 12)
    }
}
```

To store a single value in ordinary `SharedPreferences`, use `Base64.encodeToString(KeystoreBox.encrypt(token.toByteArray()), Base64.NO_WRAP)`. This is exactly the "encrypted AWS key" path in MASTG-DEMO-0059 that passes.

#### SharedPreferences: EncryptedSharedPreferences (existing apps)

```kotlin
// implementation("androidx.security:security-crypto:1.1.0")  -- deprecated, see warning
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val securePrefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
securePrefs.edit { putString("refresh_token", refreshToken) }
```

> **Warning:** All of `androidx.security:security-crypto` is deprecated as of `1.1.0`, with no further releases planned. It is still an acceptable control for an existing app that must keep `SharedPreferences`, but plan a migration to DataStore with an encrypting serializer, or to Tink or `KeystoreBox` directly. Exclude the encrypted file from backups (see below). A restored copy cannot be decrypted on another device, and `create()` will throw.

#### DataStore with an encrypting serializer (new code)

DataStore doesn't encrypt by default. Use a typed DataStore and wrap its serializer in an AEAD. AndroidX ships `AeadSerializer` in `androidx.datastore:datastore-tink` (from `1.3.0-alpha07`). If you need to stay on stable artifacts, the equivalent wrapper is short:

```kotlin
// Tink AEAD whose keyset is itself encrypted by an Android Keystore master key
fun appAead(context: Context): Aead {
    AeadConfig.register()
    return AndroidKeysetManager.Builder()
        .withSharedPref(context, "datastore_keyset", "tink_keysets")
        .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
        .withMasterKeyUri("android-keystore://datastore_master_key")   // without this the keyset is stored in clear
        .build()
        .keysetHandle
        .getPrimitive(Aead::class.java)   // Tink 1.13+: getPrimitive(RegistryConfiguration.get(), Aead::class.java)
}

class EncryptedSerializer<T>(
    private val aead: Aead,
    private val delegate: Serializer<T>,
    private val associatedData: ByteArray = "datastore".toByteArray()
) : Serializer<T> {
    override val defaultValue: T get() = delegate.defaultValue

    override suspend fun readFrom(input: InputStream): T {
        val ciphertext = input.readBytes()
        if (ciphertext.isEmpty()) return defaultValue
        val plaintext = try {
            aead.decrypt(ciphertext, associatedData)
        } catch (e: GeneralSecurityException) {
            throw CorruptionException("Cannot decrypt DataStore", e)
        }
        return delegate.readFrom(plaintext.inputStream())
    }

    override suspend fun writeTo(t: T, output: OutputStream) {
        val buffer = ByteArrayOutputStream()
        delegate.writeTo(t, buffer)
        output.write(aead.encrypt(buffer.toByteArray(), associatedData))
    }
}

@Serializable
data class Session(val accessToken: String = "", val refreshToken: String = "")

object SessionSerializer : Serializer<Session> {
    override val defaultValue = Session()
    override suspend fun readFrom(input: InputStream): Session =
        Json.decodeFromString(Session.serializer(), input.readBytes().decodeToString())
    override suspend fun writeTo(t: Session, output: OutputStream) =
        output.write(Json.encodeToString(Session.serializer(), t).encodeToByteArray())
}

// Create exactly one instance per file, e.g. in your DI graph or a top-level singleton
val sessionStore: DataStore<Session> = DataStoreFactory.create(
    serializer = EncryptedSerializer(appAead(appContext), SessionSerializer),
    produceFile = { appContext.dataStoreFile("session.enc") }
)
```

#### SQLite and Room: SQLCipher with a Keystore-wrapped passphrase

```kotlin
// implementation("net.zetetic:sqlcipher-android:<4.x>@aar"); implementation("androidx.sqlite:sqlite:<2.x>")
fun dbPassphrase(context: Context): ByteArray {
    val wrapped = File(context.noBackupFilesDir, "db.key.enc")
    if (wrapped.exists()) return KeystoreBox.decrypt(wrapped.readBytes())
    val passphrase = ByteArray(32).also { SecureRandom().nextBytes(it) }
    wrapped.writeBytes(KeystoreBox.encrypt(passphrase))
    return passphrase
}

System.loadLibrary("sqlcipher")
val db = Room.databaseBuilder(context, AppDatabase::class.java, "app.db")
    .openHelperFactory(SupportOpenHelperFactory(dbPassphrase(context)))
    .build()
```

The passphrase is random per installation and is only ever stored wrapped by the Keystore key. The wrapped blob is in `no_backup/` because it is useless on any other device, and the database should be excluded from backup for the same reason. Never use a constant string, `ANDROID_ID` or the package signature as the passphrase.

#### Files: encrypt before writing

For individual files, either use `KeystoreBox` directly (fine for small files) or an envelope: a Tink `StreamingAead` from `AndroidKeysetManager`, or the deprecated `EncryptedFile` for large files:

```kotlin
val file = File(context.filesDir, "statement.pdf.enc")
file.writeBytes(KeystoreBox.encrypt(pdfBytes))
val pdf = KeystoreBox.decrypt(file.readBytes())
```

#### Keep encrypted stores out of backups

Keystore keys never leave the device, so a backed-up encrypted file is undecryptable after restore and can crash the app. Exclude those files explicitly, for both cloud backup and device-to-device transfer:

```xml
<!-- res/xml/data_extraction_rules.xml (Android 12+) -->
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="secure_prefs.xml" />
        <exclude domain="sharedpref" path="tink_keysets.xml" />
        <exclude domain="database" path="app.db" />
        <exclude domain="file" path="datastore/session.enc" />
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="secure_prefs.xml" />
        <exclude domain="sharedpref" path="tink_keysets.xml" />
        <exclude domain="database" path="app.db" />
        <exclude domain="file" path="datastore/session.enc" />
    </device-transfer>
</data-extraction-rules>

<!-- res/xml/backup_rules.xml (Android 11 and lower) -->
<full-backup-content>
    <exclude domain="sharedpref" path="secure_prefs.xml" />
    <exclude domain="sharedpref" path="tink_keysets.xml" />
    <exclude domain="database" path="app.db" />
    <exclude domain="file" path="datastore/session.enc" />
</full-backup-content>
```

```xml
<application
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:fullBackupContent="@xml/backup_rules"
    ... >
```

#### Remove data when it is no longer needed

Encryption does not replace deletion. On logout, delete what belongs to the session, using the platform APIs so that companion files go too:

```kotlin
context.deleteSharedPreferences("secure_prefs")      // API 24+
context.deleteDatabase("app.db")                     // also removes -wal, -shm, -journal
File(context.filesDir, "datastore/session.enc").delete()
context.cacheDir.deleteRecursively()
```

### MASTG-BEST-0028: WebViews Cache Cleanup (Android)

[OWASP page](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0028/) · Knowledge: MASTG-KNOW-0018

If a WebView handles sensitive data, nothing from that session should remain on disk, or in memory, once the WebView is no longer needed. Layer the controls in this order.

#### 1. Stop sensitive responses being cached, at the server

The most reliable control is not to let the data be stored in the first place. For any response carrying sensitive data, send:

```text
Cache-Control: no-store
```

OWASP's best practice cites `no-cache`. Strictly, `no-cache` still *allows* the response to be stored and only forces revalidation before reuse. It is `no-store` that tells the WebView not to write the response to its cache at all. Use `no-store` (optionally `no-store, private`) for authenticated pages and APIs.

#### 2. Configure the WebView for the least storage it needs

```kotlin
webView.settings.apply {
    cacheMode = WebSettings.LOAD_NO_CACHE   // supplementary; verify on disk that nothing is still written
    domStorageEnabled = false               // only if the pages work without localStorage/sessionStorage
    allowFileAccess = false                 // default false only for targetSdk 30+
    allowContentAccess = false              // default true
}
// Global for the app; only if the WebView does not rely on a cookie-based session
CookieManager.getInstance().setAcceptCookie(false)
```

Use `WebViewAssetLoader` for bundled content rather than `file://`. For third-party or login content that does not need a native bridge, use Custom Tabs, so that the data lives in the browser, not in the app's sandbox.

#### 3. Clear every store you enabled, at the right moment

```kotlin
object WebViewWiper {
    /** Call on the main thread: on logout, and when the sensitive WebView flow is finished. */
    fun wipe(context: Context, webView: WebView) {
        webView.clearCache(true)                          // app-wide memory + disk HTTP cache
        webView.clearHistory()
        webView.clearFormData()
        WebStorage.getInstance().deleteAllData()          // Local/Session Storage, WebSQL
        val cookies = CookieManager.getInstance()
        cookies.removeAllCookies { cookies.flush() }      // async; flush once removal is done
        WebViewDatabase.getInstance(context).clearHttpAuthUsernamePassword()
    }
}

override fun onDestroy() {
    if (isFinishing) WebViewWiper.wipe(this, webView)
    webView.destroy()
    super.onDestroy()
}
```

Clearing like this has two weaknesses that OWASP points out. It is indiscriminate: `clearCache(true)` also throws away harmless, useful cached assets such as images. And it is not guaranteed to run: `onDestroy()` and `onStop()` may never be called if the process is killed. To cover the second, record that a sensitive web session is in progress and sweep at the next launch, before any WebView is shown:

```kotlin
class App : Application() {
    override fun onCreate() {
        super.onCreate()
        val state = getSharedPreferences("webview_state", MODE_PRIVATE)
        if (state.getBoolean("dirty", false)) {
            Handler(Looper.getMainLooper()).post {
                val wv = WebView(this)
                WebViewWiper.wipe(this, wv)
                wv.destroy()
                state.edit { putBoolean("dirty", false) }
            }
        }
    }
}
// set "dirty" = true when the sensitive WebView flow starts, false after wipe()
```

#### 4. Handle the stores the APIs don't cover

The Android APIs cannot remove IndexedDB, OPFS or SQLite Wasm data without clearing the whole profile. Your options:

- Don't put sensitive data there. If the web app needs offline storage, encrypt it with a key the server provides per session.
- Have the page clean up after itself on logout (`indexedDB.deleteDatabase(name)`, `localStorage.clear()`, `caches.delete(name)`). This runs only if the page gets to run, so keep it as an extra, not the only control.
- Run the sensitive flow in a dedicated WebView profile (AndroidX WebKit multi-profile, feature `MULTI_PROFILE`) and delete that profile when the flow ends.
- As a last resort, `ActivityManager.clearApplicationUserData()` wipes everything, which is appropriate for a "remove all data from this device" action.

### MASTG-BEST-0024: Store Data Encrypted in App Sandbox Directory (iOS)

[OWASP page](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0024/)

#### Put each kind of data in the right place

| Data | Where | Why |
|---|---|---|
| Passwords, tokens, keys, PINs | Keychain | Encrypted per item, lock-state bound, never in a backup in readable form if `ThisDeviceOnly` |
| User-created documents meant to be seen in Files | `Documents/` | That is what it is for — but only if the user really owns the content |
| Databases, config, purchase state, SDK state | `Library/Application Support/` | Not user-visible or user-writable, even with file sharing enabled |
| Regenerable downloads, thumbnails | `Library/Caches/` | Excluded from backup, purgeable — still readable on the device |
| Scratch files, decrypted temporary copies | `tmp/`, deleted as soon as used | The OS purges it eventually; do not rely on that |

Never put databases, configuration or entitlement/purchase state in `Documents/` when `UIFileSharingEnabled` and `LSSupportsOpeningDocumentsInPlace` are set: the user (or anyone with the unlocked device) can read and replace them, and other apps can reach them through the document picker. Choosing the right directory is not protection in itself. For L2 apps, encrypt sensitive files with a key held in the Keychain.

#### Encrypt sensitive files with a Keychain-held key

CryptoKit's AES-GCM gives authenticated encryption with no parameters to get wrong. The key is created once and kept in the Keychain with a `ThisDeviceOnly` accessibility class; the ciphertext is written with `Complete` protection as a second layer:

```swift
import CryptoKit
import Foundation
import Security

enum SecureStoreError: Error { case keychain(OSStatus), sealFailed }

final class SecureFileStore {
    private let service = "com.example.app.file-key"
    private let account = "v1"

    private func key() throws -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data { return SymmetricKey(data: data) }
        guard status == errSecItemNotFound else { throw SecureStoreError.keychain(status) }

        let newKey = SymmetricKey(size: .bits256)
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: newKey.withUnsafeBytes { Data($0) }
        ]
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw SecureStoreError.keychain(addStatus) }
        return newKey
    }

    private func url(_ name: String) throws -> URL {
        try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                    appropriateFor: nil, create: true)
            .appendingPathComponent(name)
    }

    func write(_ plaintext: Data, to name: String) throws {
        guard let combined = try AES.GCM.seal(plaintext, using: key()).combined else {
            throw SecureStoreError.sealFailed
        }
        try combined.write(to: url(name), options: [.atomic, .completeFileProtection])
    }

    func read(_ name: String) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: Data(contentsOf: url(name)))
        return try AES.GCM.open(box, using: key())
    }
}
```

Notes for developers and reviewers:

- `WhenUnlockedThisDeviceOnly` means the data cannot be decrypted while the device is locked. If a background task must read it, use `AfterFirstUnlockThisDeviceOnly` for that key and document why.
- Serialise first-use key creation (an actor or a lock) so two threads do not create different keys.
- For databases, use the library's own encryption (SQLCipher, `Realm.Configuration(encryptionKey:)` with a 64-byte key from the Keychain) rather than encrypting the file from outside.
- Envelope encryption — a per-file data key wrapped by a Keychain or Secure Enclave key — is the scalable form of the same idea when there are many files or keys need rotating.

#### Set the strongest protection class the app can live with

```swift
// Per file
try data.write(to: url, options: [.atomic, .completeFileProtection])

// A directory the app writes into with other APIs
try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete],
                                      ofItemAtPath: directory.path)

// Core Data / SwiftData-backed store (covers -wal and -shm)
let container = NSPersistentContainer(name: "Model")
container.persistentStoreDescriptions.first?.setOption(FileProtectionType.complete as NSObject,
                                                       forKey: NSPersistentStoreFileProtectionKey)
container.loadPersistentStores { _, error in
    if let error { fatalError("Store failed to load: \(error)") }
}
```

App-wide, enable the **Data Protection** capability in Xcode with "Complete" (the `com.apple.developer.default-data-protection` entitlement) so files written by APIs that take no options start at `Complete`. Then deliberately downgrade only the files that background work needs, using `completeUnlessOpen` for writes that happen while locked. Never use `noFileProtection` for anything sensitive.

#### Stop the system writing sensitive data for you

- Use `URLSessionConfiguration.ephemeral` (or set `urlCache = nil`) for API sessions that return personal data, and send `Cache-Control: no-store` from the server.
- Use `WKWebsiteDataStore.nonPersistent()` for web views that render authenticated content.
- Keep tokens out of `UserDefaults` entirely; it is a settings store.

#### Remove data when it is no longer needed

On logout (and on account deletion), remove everything the session left behind, not just the token:

```swift
import WebKit

@MainActor
func wipeLocalSession() async {
    let fm = FileManager.default
    if let support = try? fm.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                 appropriateFor: nil, create: false) {
        try? fm.removeItem(at: support.appendingPathComponent("UserData", isDirectory: true))
    }
    (try? fm.contentsOfDirectory(at: fm.temporaryDirectory, includingPropertiesForKeys: nil))?
        .forEach { try? fm.removeItem(at: $0) }

    UserDefaults.standard.removeObject(forKey: "lastUser")
    URLCache.shared.removeAllCachedResponses()
    HTTPCookieStorage.shared.removeCookies(since: .distantPast)
    await WKWebsiteDataStore.default().removeData(ofTypes: WKWebsiteDataStore.allWebsiteDataTypes(),
                                                  modifiedSince: .distantPast)
    SecItemDelete([kSecClass as String: kSecClassGenericPassword,
                   kSecAttrService as String: "com.example.app.auth"] as CFDictionary)
}
```

Because Keychain items survive uninstall, also clear the app's session items on the first launch after a fresh install.

### MASTG-BEST-0068: Secure Data Sharing Between App Extensions and Containing Apps (iOS)

[OWASP page](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0068/)

Everything in an App Group container is readable and writable by every member of the group, with nothing but the file protection class standing between it and someone holding the device. Pick the channel by sensitivity.

#### Share secrets through a Keychain access group

Declare the same access group in the app and in each extension that needs the secret:

```xml
<key>keychain-access-groups</key>
<array>
    <string>$(AppIdentifierPrefix)com.example.shared</string>
</array>
```

At runtime the group must be the expanded string, including your Team ID prefix. A common way to avoid hard-coding it is an `AppIdentifierPrefix` key with the value `$(AppIdentifierPrefix)` in each target's `Info.plist`:

```swift
import Security

enum KeychainError: Error { case status(OSStatus) }

let accessGroup = (Bundle.main.object(forInfoDictionaryKey: "AppIdentifierPrefix") as! String)
    + "com.example.shared"

func storeSharedToken(_ token: String) throws {
    let base: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.example.app.session",
        kSecAttrAccount as String: "access-token",
        kSecAttrAccessGroup as String: accessGroup
    ]
    SecItemDelete(base as CFDictionary)
    var add = base
    add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    add[kSecValueData as String] = Data(token.utf8)
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else { throw KeychainError.status(status) }
}

func readSharedToken() throws -> String? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.example.app.session",
        kSecAttrAccount as String: "access-token",
        kSecAttrAccessGroup as String: accessGroup,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess, let data = result as? Data else { throw KeychainError.status(status) }
    return String(data: data, encoding: .utf8)
}
```

Choose the accessibility class with the extension's execution context in mind. A share extension runs while the user is interacting with the phone, so `WhenUnlockedThisDeviceOnly` works. A notification service extension may run while the device is locked; give *its* key `AfterFirstUnlockThisDeviceOnly` and keep that item separate from the long-lived refresh token, rather than lowering the class of everything.

Better still, do not share the long-lived credential at all: give the extension a narrowly scoped, short-lived token minted by your backend.

#### Protect anything sensitive in the shared file container

```swift
guard let shared = FileManager.default
        .containerURL(forSecurityApplicationGroupIdentifier: "group.com.example.app") else { return }
try payload.write(to: shared.appendingPathComponent("pending-upload.bin"),
                  options: [.atomic, .completeFileProtection])
```

For a shared Core Data store, point the store description at the group container *and* set `NSPersistentStoreFileProtectionKey`, as in MASTG-BEST-0024. If the content is sensitive enough that a locked-device read would matter, encrypt it with a key from the shared Keychain group before writing, using the same CryptoKit pattern.

#### Share as little as possible

- Give each extension only the App Group identifiers it needs. A widget does not need the share extension's group.
- Store derived, display-only values (a balance string, an unread count) for widgets rather than full API responses.
- Delete hand-off files as soon as the consumer has processed them, and clear shared `UserDefaults` and shared files on logout — the group container is not removed when the user logs out, and persists until the last app in the group is deleted.

## Rating findings

The rating depends on three things: what the data is, how long it stays valid, and what the attacker needs in order to read it. Any secret that is "encrypted" with a key stored next to it or hardcoded should be rated as if it were plaintext, and the key should be reported separately under [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/). Data that other apps can read without root, such as world-readable files, a `FileProvider` with `<root-path>`, or an App Group shared with a third-party extension, should be rated at least one level higher than the same data in a properly private location.

### Android

- **Critical:** Credentials or long-lived secrets that give direct account takeover (password, refresh token, private signing key, card PAN with CVV) stored in plaintext in the sandbox **and** reachable without root. That means a debuggable release build (`run-as`), `adb backup` working on an app targeting API 30 or lower, a `FileProvider` exposing `root-path` or `files-path path="."` to callers, a WebView with file access plus universal access that can be pointed at the sandbox, or world-readable files on an old `targetSdkVersion`.
- **High:** Plaintext session or refresh tokens, passwords, PINs, encryption keys or special-category PII (health, biometric templates, government ID numbers) in `shared_prefs/`, `databases/`, `files/`, DataStore or the WebView profile, extractable from a rooted device, a forensic AFU image or a cloud or device-transfer backup. Also High: data "encrypted" with a hard-coded key or passphrase, or a key stored in the clear next to it (an unencrypted Tink keyset, a SQLCipher passphrase in prefs). Cross-reference MASWE-0003 and MASWE-0004.
- **Medium:** Moderate PII (names, email addresses, phone numbers, transaction history, message content) stored unencrypted. Short-lived access tokens (minutes) stored in plaintext. Sensitive WebView data (cookies, Local Storage tokens, cached account pages) that survives logout or app exit. Sensitive data in DE storage (`user_de`) that is readable before first unlock.
- **Low:** Sensitive data correctly encrypted but retained longer than needed (not removed on logout). Use of the deprecated `EncryptedSharedPreferences` or `EncryptedFile` with no migration plan. Encrypted stores not excluded from backup (a robustness issue rather than a disclosure). WebView cleanup present but not robust to process kill, with only low-sensitivity data at stake.
- **Informational:** Non-sensitive identifiers (installation IDs, feature flags, analytics IDs) in plaintext. `MODE_WORLD_*` constants referenced only in dead code. Encrypted-at-rest data that can still be read at runtime with Frida on a rooted device. That last one is expected behaviour, not a MASWE-0001 failure, but worth one line in the report.
- **Adjust up** when the app targets a high-risk profile (banking, health, MASVS L2 or EUDIW), when the device population is likely to include rooted devices, or when the same secret also unlocks server-side access for other users (shared API keys).
- **Adjust down** when the data is useless off the device (bound to a Keystore key or device attestation) or expires before an attacker could realistically use it, and say so in the finding.

### iOS

- **Critical:** credentials or keys that give account takeover (password, refresh token, long-lived session token, private key, database or file-encryption key) stored in plaintext in `Documents/` while `UIFileSharingEnabled` and `LSSupportsOpeningDocumentsInPlace` are enabled, so anyone with the unlocked device can copy them through Files or Finder without a jailbreak. For L2 apps (banking, health, identity wallets), the same data at `NSFileProtectionNone` or in a `kSecAttrAccessibleAlways*` Keychain item, which a before-first-unlock acquisition recovers, also belongs here.
- **High:** plaintext passwords, refresh tokens, long-lived bearer tokens or persistent session cookies in `UserDefaults`, plists, Core Data/SQLite/Realm, `Cache.db`, `Cookies.binarycookies` or an App Group container (MASTG-TEST-0388). These are readable after first unlock while the device is locked, from backups for backed-up locations, and by any in-process attacker. Also High: data that is "encrypted" with a key that is hardcoded or stored in the sandbox next to it.
- **Medium:** sensitive PII, financial or health records (as opposed to credentials) in plaintext at the default protection class; short-lived access tokens (minutes, server-revocable) in plaintext; sensitive files explicitly set to `NSFileProtectionNone` whose content is not credential-grade; Keychain secrets using the deprecated `kSecAttrAccessibleAlways*`; API responses with PII persisted in `Cache.db` or WebKit storage and not cleared on logout.
- **Low:** low-impact personal data (display name, last username, email) in `UserDefaults`; long-lived Keychain secrets without a `ThisDeviceOnly` variant (they migrate to other devices through encrypted backups); app-encrypted data whose ciphertext sits at `NSFileProtectionNone` (the key is properly in the Keychain, so only the lock-state layer is lost); Keychain session items that survive uninstall and are reused on reinstall.
- **Info:** credentials correctly in the Keychain but at `AfterFirstUnlock` where `WhenUnlocked` would work; no app-wide `com.apple.developer.default-data-protection` entitlement while all sensitive files are individually protected; non-sensitive SDK files at `NSFileProtectionNone`.
- **Adjust for reachability and lifetime.** Raise one level when the data sits in a location included in backups and the app has no backup exclusion for it, or is exposed through file sharing; lower one level when the secret is device-bound, short-lived and revocable server-side. State the access path in the finding (AFU/BFU acquisition, backup, file sharing, jailbreak, in-process code) — that is what turns "token in a plist" into a defensible rating.
- **Check the test conditions before rating protection-class findings.** Results from the Simulator or from a device without a passcode say nothing about lock-state protection. Re-test on a passcode-protected physical device.

## References

- OWASP MASTG — [MASTG-KNOW-0041: Internal Storage](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0041/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0036: Shared Preferences](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0036/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0037: SQLite Database](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0037/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0207: Runtime Storage of Unencrypted Data in the App Sandbox](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0287: Runtime Storage of Unencrypted Data via the SharedPreferences API](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0287/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0304: References to Sensitive Data Unencrypted via Android Room Database](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0304/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0305: Sensitive Data Stored Unencrypted via DataStore](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0305/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0306: References to Sensitive Data Stored Unencrypted via Android Room DB](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0306/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0320: WebViews Not Cleaning Up Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0320/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-BEST-0050: Store Data Encrypted in App Sandbox Directory](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0050/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-BEST-0028: WebViews Cache Cleanup](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0028/) (CC BY-SA 4.0)
- OWASP MASTG — demos MASTG-DEMO-0010, MASTG-DEMO-0059, MASTG-DEMO-0060 and MASTG-DEMO-0082; techniques MASTG-TECH-0002 (Host-Device Data Transfer), MASTG-TECH-0008 (Accessing App Data Directories), MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0143 (Monitor File System Operations in WebViews) (CC BY-SA 4.0)
- [Android Developers — App-specific storage](https://developer.android.com/training/data-storage/app-specific)
- [Android Developers — Security best practices: internal storage](https://developer.android.com/privacy-and-security/security-best-practices#internal-storage)
- [Android Developers — Security tips: internal storage](https://developer.android.com/privacy-and-security/security-tips#internal-storage)
- [Android 7.0 behaviour changes — permissions on the file system](https://developer.android.com/about/versions/nougat/android-7.0-changes#permfilesys)
- [Android Developers — Save key-value data (SharedPreferences)](https://developer.android.com/training/data-storage/shared-preferences)
- [Android Developers — DataStore](https://developer.android.com/topic/libraries/architecture/datastore) and [DataStore release notes](https://developer.android.com/jetpack/androidx/releases/datastore)
- [Android Developers — Save data using SQLite](https://developer.android.com/training/data-storage/sqlite) and [Room](https://developer.android.com/training/data-storage/room)
- [Android Developers — Cryptography (Jetpack Security deprecation)](https://developer.android.com/privacy-and-security/cryptography#jetpack_security_crypto_library)
- [Android Developers — Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Android Developers — Back up user data with Auto Backup](https://developer.android.com/identity/data/autobackup)
- [AndroidX — FileProvider](https://developer.android.com/reference/androidx/core/content/FileProvider)
- [Android Developers — WebView](https://developer.android.com/reference/android/webkit/WebView), [WebSettings](https://developer.android.com/reference/android/webkit/WebSettings), [WebStorage](https://developer.android.com/reference/android/webkit/WebStorage), [CookieManager](https://developer.android.com/reference/android/webkit/CookieManager)
- [AndroidX — WebViewAssetLoader](https://developer.android.com/reference/androidx/webkit/WebViewAssetLoader)
- [Chromium — CORS and WebView API](https://chromium.googlesource.com/chromium/src/+/HEAD/android_webview/docs/cors-and-webview-api.md)
- [SQLite — Write-Ahead Logging](https://www.sqlite.org/wal.html) and [Temporary files](https://www.sqlite.org/tempfiles.html)
- [Zetetic — SQLCipher for Android](https://www.zetetic.net/sqlcipher/sqlcipher-for-android/)
- [Google Tink](https://developers.google.com/tink)
- Tools: [Frida](https://frida.re), [Frooky](https://github.com/cpholguera/frooky), [objection](https://github.com/sensepost/objection), [jadx](https://github.com/skylot/jadx), [apktool](https://apktool.org), [gitleaks](https://github.com/gitleaks/gitleaks)
- OWASP MASTG — [MASTG-KNOW-0108: App Sandbox Directories](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0108/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0091: File System APIs](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0091/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0057: Keychain Services](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0082: App Extensions](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0082/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0299: Data Protection Classes for Files in Private Storage](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0299/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0300: References to APIs for Storing Unencrypted Data in Private Storage](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0300/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0301: Runtime Use of APIs for Storing Unencrypted Data in Private Storage](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0301/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0302: Sensitive Data Unencrypted in Private Storage Files](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0302/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0388: References to Sensitive Data Stored Unprotected in Shared App Group Containers](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0388/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-BEST-0024: Store Data Encrypted in App Sandbox Directory](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0024/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-BEST-0068: Secure Data Sharing Between App Extensions and Containing Apps](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0068/) (CC BY-SA 4.0)
- [Apple Developer — Encrypting your app's files](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/encrypting_your_app_s_files)
- [Apple Developer — FileProtectionType](https://developer.apple.com/documentation/foundation/fileprotectiontype)
- [Apple Developer — Data Protection entitlement (`com.apple.developer.default-data-protection`)](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.default-data-protection)
- [Apple Developer — Using the file system effectively](https://developer.apple.com/documentation/foundation/using-the-file-system-effectively)
- [Apple Developer — File System Programming Guide: File System Basics](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html)
- [Apple Developer — UserDefaults](https://developer.apple.com/documentation/foundation/userdefaults)
- [Apple Developer — URLSessionConfiguration.ephemeral](https://developer.apple.com/documentation/foundation/urlsessionconfiguration/1410529-ephemeral)
- [Apple Developer — Keychain services](https://developer.apple.com/documentation/security/keychain_services)
- [Apple Developer — Restricting keychain item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility)
- [Apple Developer — kSecAttrAccessibleWhenUnlockedThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly)
- [Apple Developer — kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly)
- [Apple Developer — Accessing keychain items with Face ID or Touch ID](https://developer.apple.com/documentation/localauthentication/accessing_keychain_items_with_face_id_or_touch_id)
- [Apple Developer — Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
- [Apple Developer — Keychain Access Groups entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups)
- [Apple Developer — App Groups entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.application-groups)
- [Apple Developer — Configuring app groups](https://developer.apple.com/documentation/Xcode/configuring-app-groups)
- [Apple Developer — App Extension Programming Guide](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/index.html)
- [Apple Platform Security — Supporting extensions](https://support.apple.com/guide/security/supporting-extensions-secabd3504cd/web)
- [Apple Platform Security guide](https://support.apple.com/guide/security/welcome/web)
- [Frida — iOS documentation](https://frida.re/docs/ios/)
- [objection](https://github.com/sensepost/objection)
- [radare2 book](https://book.rada.re/)
- [Keychain-Dumper](https://github.com/ptoomey3/Keychain-Dumper)
- OWASP MASWE — [MASWE-0001: Sensitive Data Stored Unencrypted in Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/) (CC BY-SA 4.0)
- [Apple — Encrypting your app's files](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/encrypting_your_app_s_files)
- [Android Developers — Behaviour changes in Android 7.0: permissions on the private directory](https://developer.android.com/about/versions/nougat/android-7.0-changes#permfilesys)
- [Android Developers — Security tips: internal storage](https://developer.android.com/privacy-and-security/security-tips#internal-storage)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
