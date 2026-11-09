---
title: "Sensitive Data Stored Unencrypted Outside of Private Storage (MASWE-0002)"
date: 2026-11-08 12:03:00 +0000
subcategory: storage
summary: "Testing Android external/shared storage and iOS Files-app exposure for unencrypted sensitive data: MASTG-TEST-0200–0202, 0303 and the fixes."
refs: [MASWE-0002, MASVS-STORAGE-1, CWE-312, CWE-922]
tags: [android, ios, masvs-storage, external-storage, scoped-storage, mediastore]
---

This note is part of our [MASVS-STORAGE-1 series](/mobile/masvs-storage-1-secure-storage-guide/) and covers [MASWE-0002](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0002/): an app writes sensitive data, in the clear, to a location outside its private sandbox, where other apps, the user, or anyone holding the unlocked device can read it without the app being involved. On Android that means external storage in all its forms: app-specific external directories, the public `Download/`, `Documents/` and `Pictures/` folders, and anything written through `MediaStore`. On iOS it means sandbox locations the app has deliberately exposed, chiefly the `Documents` directory once file sharing or open-in-place is switched on. The private-storage counterpart is [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/), and key handling for any encryption you add is covered in [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/).

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: External Storage (MASTG-KNOW-0042)](#android-external-storage-mastg-know-0042)
  - [iOS: Document Picker, Document Interaction, and Open in Place (MASTG-KNOW-0122)](#ios-document-picker-document-interaction-and-open-in-place-mastg-know-0122)
- [Tests](#tests)
  - [MASTG-TEST-0200: Files Written to External Storage (Android)](#mastg-test-0200-files-written-to-external-storage-android)
  - [MASTG-TEST-0201: Runtime Use of APIs to Access External Storage (Android)](#mastg-test-0201-runtime-use-of-apis-to-access-external-storage-android)
  - [MASTG-TEST-0202: References to APIs and Permissions for Accessing External Storage (Android)](#mastg-test-0202-references-to-apis-and-permissions-for-accessing-external-storage-android)
  - [MASTG-TEST-0303: References to APIs for Storing Unencrypted Data in Shared Storage (iOS)](#mastg-test-0303-references-to-apis-for-storing-unencrypted-data-in-shared-storage-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The private sandbox (`/data/data/<package>/` on Android, the app's Data container on iOS) is the one place where the operating system guarantees, by default, that no other app can read your files. Everything outside it carries some degree of sharing, and the degree depends on the platform, the OS version, the app's target SDK, and the permissions held by *other* apps on the device.

On **Android**, "external storage" is a historical name. On most modern devices it is not a removable card at all but an emulated volume at `/storage/emulated/0` (also reachable as `/sdcard`), served through a FUSE layer that enforces scoped storage. It splits into two zones:

- **App-specific external storage** under `/storage/emulated/0/Android/data/<package>/` (`files/`, `cache/`) plus `Android/media/<package>/` and `Android/obb/<package>/`. Returned by `getExternalFilesDir()`, `getExternalCacheDir()` and friends. No permission is needed to use it; it is deleted on uninstall. Other apps cannot reach it on Android 11+, but they could on Android 10 and below given storage permission, and `adb`, a USB file-transfer connection, or a removed SD card can reach it on any version.
- **Shared storage**: everything else on the volume, notably `Download/`, `Documents/`, `Pictures/`, `DCIM/`, `Music/`, `Movies/`. Written through `MediaStore`, the Storage Access Framework (SAF), `DownloadManager`, or legacy file paths. Files here survive uninstall and are visible to other apps according to media type and permission (see the [knowledge section](#android-external-storage-mastg-know-0042)).

On **iOS** an app cannot write to an arbitrary shared folder. The sandbox stays private, but the app can open a window into it: `UIFileSharingEnabled` exposes `Documents/` to Finder (and iTunes File Sharing on Windows), and together with `LSSupportsOpeningDocumentsInPlace` it also appears in the Files app under *On My iPhone*. From there, the user, anyone with the unlocked device, and any app the user picks a file for via the document picker can read it. The app can also push files out through the document picker, `UIActivityViewController` or `UIDocumentInteractionController`. Those flows are user-mediated, but the copy that lands at the destination is out of the app's control.

The core requirement from MASWE-0002 is simple: **if sensitive data must live outside private storage, it must be encrypted before it is written, under a key that is not stored with it.** In practice, the right answer for most sensitive data is not to put it there at all.

## Modes of Introduction

These are the ways the weakness turns up in real apps, grouped as OWASP does, with the concrete patterns you will actually see:

- **Data stored unencrypted.** The common case. Typical forms:
  - "Export" or "Download" features that drop statements, invoices, medical reports or ID document images into `Download/` or `Documents/` through `MediaStore` or `DownloadManager.Request.setDestinationInExternalPublicDir()`.
  - Debug, support or crash logs written to `getExternalFilesDir()` "so support can ask the user to send them", often containing tokens, request bodies or user identifiers.
  - Image caches, camera captures and KYC selfies saved to `Pictures/` or `DCIM/` via `MediaStore.Images`, where every gallery app and cloud photo backup can see them.
  - SQLite databases, Realm files or JSON caches placed in app-specific external storage because they were large and the developer believed `Android/data` was private.
  - On iOS: databases, auth state, cached API responses or logs written to `Documents/` in an app that also sets `UIFileSharingEnabled`, often because a feature (importing files from a computer) needed file sharing and nobody re-examined what else lived in `Documents/`.
  - Third-party SDKs (analytics, crash reporting, offline maps, media players) that write their own caches to external storage. The app is still responsible for them.
- **Hardcoded encryption key.** The file is encrypted, but the key is a constant in the APK or IPA. Anyone who can read the file can also unzip the app and recover the key. Treat it as unencrypted. See [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/) for finding hardcoded secrets.
- **Encryption key stored on the filesystem.** The key sits next to the data (`/sdcard/Android/data/<pkg>/files/key.bin`), or in private storage where root, backup extraction or another weakness exposes it. Better than a shared key, but still not hardware-backed.
- **Insufficient encryption.** ECB mode, a static IV with CBC or GCM, DES/3DES, XOR, a home-grown cipher, or Base64 mistaken for encryption. A ZIP or a custom binary format is not encryption either.
- **Reuse of encryption key.** The same key, derived from the account or synced from the server, is used on every device the user owns. A file copied from external storage on one device then decrypts on another, which allows data cloning and breaks any assumption that a file is bound to the device that produced it.

## Impact

Who can read the file determines how bad it is. On Android, the realistic readers of shared storage are:

- **Other apps.** Any app holding `READ_MEDIA_IMAGES`/`READ_MEDIA_VIDEO`/`READ_MEDIA_AUDIO` (API 33+) or `READ_EXTERNAL_STORAGE` (API 32 and below) can read media files other apps put in the shared collections. Any app granted *All files access* (`MANAGE_EXTERNAL_STORAGE`), and file managers, cleaners and backup tools routinely are, can read every non-media file in shared storage. On Android 10 and below, apps with `READ_EXTERNAL_STORAGE` could also read other apps' app-specific external directories.
- **Physical access.** Anyone with the unlocked device can pull external storage over USB file transfer, or with `adb` if USB debugging is enabled. A portable (non-adopted) SD card can simply be removed and read in a PC, since it uses FAT/exFAT with no file permissions.
- **Sync and backup.** Photo backup apps upload `DCIM/` and `Pictures/` automatically, and user-chosen sync tools mirror `Download/` and `Documents/`. The data leaves the device without the app doing anything.
- **Persistence.** Shared-storage files survive uninstall. A user who removes the app to "clean up" leaves the data behind.

On iOS, exposed `Documents/` content can be read by anyone with the unlocked phone (Files app), anyone with a computer the device trusts (Finder), and any app the user is persuaded to pick the file for.

The consequences OWASP lists, made concrete:

- **Compromise of sensitive data.** Statements, ID scans, health records, chat exports, photos and voice notes are disclosed to other apps or people. For regulated data this is a reportable incident.
- **Authentication or authorisation bypass.** Passwords, session or refresh tokens, API keys and private keys read from a log or cache file let the reader impersonate the user or the app. A refresh token is usually worse than a password, because it skips MFA.
- **Bypass of protection mechanisms.** External storage is writable too. A file the app trusts (a database flag for premium features, a downloaded configuration, a cached policy, or, worst of all, a downloaded DEX/SO plugin) can be tampered with by another app or by the user. This is the [Man-in-the-Disk](https://blog.checkpoint.com/2018/08/12/man-in-the-disk-a-new-attack-surface-for-android-apps/) attack class: confidentiality is MASWE-0002's focus, but you should report integrity abuse alongside it whenever the app reads back what it wrote.

## Mitigations

- **Prefer private storage.** Internal storage (`filesDir`, `noBackupFilesDir`, `cacheDir`, databases) on Android, and `Library/Application Support` on iOS. Use external storage only for large, non-sensitive content or for files the user explicitly wants to share.
- **Limit platform file sharing.** Do not route sensitive data through SAF exports, `MediaStore`, the document picker, the share sheet, or an exposed `Documents/` folder unless that is the purpose of the feature, and then make it a deliberate, user-initiated action.
- **Encrypt before writing.** Anything sensitive that must go outside the sandbox is encrypted by the app first, using authenticated encryption (AES-GCM, or Tink's streaming AEAD for large files).
- **Protect the keys.** Generate keys in the Android Keystore or keep them in the iOS Keychain with a `ThisDeviceOnly` accessibility class. Never hardcode a key and never store it beside the data. Where a file must be portable (an export the user will open elsewhere), derive the key from a user-supplied passphrase with a slow KDF rather than shipping a shared key.
- **Treat anything read back from shared locations as untrusted input.** Validate it, verify its integrity (MAC or signature) where the app relies on it, and never load code from it.

> **Warning:** The Jetpack Security crypto library (`androidx.security:security-crypto`, including `EncryptedFile` and `EncryptedSharedPreferences`) has been [deprecated](https://developer.android.com/privacy-and-security/cryptography#jetpack_security_crypto_library). OWASP's position is that it remains acceptable until an official replacement ships. For new code, using Tink directly with a Keystore-wrapped keyset, or Keystore AES-GCM for small files, avoids the dependency. Both are shown in [Secure implementation](#secure-implementation).

## Knowledge

### Android: External Storage (MASTG-KNOW-0042)

Source: [MASTG-KNOW-0042](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0042/).

#### Volumes and paths you will see

| Path on device | What it is | Who else can read it |
|---|---|---|
| `/storage/emulated/0/` (`/sdcard`, `/storage/self/primary`) | Primary emulated shared volume | Depends on zone, see below |
| `/storage/emulated/0/Android/data/<pkg>/files/` | `getExternalFilesDir(type)` | Android ≤ 10: any app with storage permission. Android 11+: no other app; still `adb`/MTP/root |
| `/storage/emulated/0/Android/data/<pkg>/cache/` | `getExternalCacheDir()` | As above |
| `/storage/emulated/0/Android/media/<pkg>/` | `getExternalMediaDirs()` (deprecated API 30) | Indexed by MediaStore, so other apps with media permission can see the media |
| `/storage/emulated/0/Download/`, `Documents/`, `Pictures/`, `DCIM/` … | Shared storage, `getExternalStoragePublicDirectory()` / `MediaStore` | Other apps per media type and permission; *All files access* apps; user; survives uninstall |
| `/storage/XXXX-XXXX/` | Secondary volume (SD card, USB OTG). `getExternalFilesDirs()[1]` | If portable (FAT/exFAT): anyone who removes the card |
| `/storage/emulated/<userId>/` | Shared volume for another user or work profile | Separate per user |

List the volumes on a device with `adb shell ls /storage` or `adb shell sm list-volumes`. Adopted storage (an SD card formatted as internal) is encrypted and tied to the device. Portable storage is not.

#### Scoped storage across API levels

Scoped storage is the reason "external storage" means different things on different devices, and you need to know which regime your target runs under on every OS version it supports (`minSdkVersion` up to current):

| Device OS | App behaviour |
|---|---|
| Android 4.3 and below (API ≤ 18) | `READ_EXTERNAL_STORAGE` not enforced: every app can read all of external storage. |
| Android 4.4–9 (API 19–28) | App-specific external dirs need no permission for the owner, but **any app with `READ_EXTERNAL_STORAGE` can read them**, and with `WRITE_EXTERNAL_STORAGE` modify them. Public dirs are fully readable with the permission. |
| Android 10 (API 29) | Scoped storage applies to apps that target 29+, unless they set `android:requestLegacyExternalStorage="true"`. Legacy-mode apps still get the old, broad view, including other apps' app-specific dirs. |
| Android 11+ (API 30+) | Scoped storage enforced for apps targeting 30+. `requestLegacyExternalStorage` is ignored for them. `preserveLegacyExternalStorage="true"` keeps legacy mode only for an *already-installed* app being updated, until it is uninstalled. Other apps' `Android/data` and `Android/obb` are blocked, even with *All files access*, and the SAF folder picker refuses them. |
| Android 13+ (API 33+) | `READ_EXTERNAL_STORAGE` has no effect for apps targeting 33+. Media reads need `READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO` or `READ_MEDIA_AUDIO`. |
| Android 14+ (API 34+) | Users can grant partial media access (`READ_MEDIA_VISUAL_USER_SELECTED`), so a media permission no longer always means all photos. |

The practical consequence: data in `getExternalFilesDir()` is exposed to other apps on any device running Android 10 or below, so an app with `minSdkVersion` ≤ 29 cannot claim that location is private. On Android 11+ it is shielded from other apps but not from `adb`, USB file transfer, a removable card, or root.

#### Media attribution and the MediaStore

With scoped storage, `MediaStore` records the creating app in the `owner_package_name` column. An app can always read and write its own entries without permission. To read another app's entries it needs the media permission for that collection. If it opens a URI it does not own and lacks permission, it gets:

```text
java.lang.SecurityException: org.example.reader has no access to content://media/external_primary/images/media/1000000041
```

Ownership is per installation. After uninstall and reinstall, the app no longer owns its old files and needs a read permission to see them again, which is one reason "we'll clean it up on next launch" logic fails. The leftover files remain in shared storage.

The collections are `MediaStore.Images`, `MediaStore.Video`, `MediaStore.Audio`, `MediaStore.Downloads` (API 29+) and `MediaStore.Files`. The rules that matter for exposure:

- **Images, video, audio** written by app A are readable by **any** app holding the matching `READ_MEDIA_*` permission (or `READ_EXTERNAL_STORAGE` on 32 and below). Gallery, messaging and social apps commonly hold it.
- **Downloads and non-media files** written by app A are not returned to app B's MediaStore queries. B needs SAF (user picks the file) or *All files access*. On Android 9 and below, or in legacy mode, B just reads the path with `READ_EXTERNAL_STORAGE`.

You can inspect the MediaStore directly from `adb` (the shell user has access):

```bash
adb shell content query --uri content://media/external_primary/file \
  --projection _id:_data:owner_package_name:mime_type
adb shell "content query --uri content://media/external/file --projection _data:owner_package_name --where \"owner_package_name='com.example.app'\""
```

To reproduce what another app could see, install a small helper app and grant or revoke permissions:

```bash
adb shell pm grant com.example.reader android.permission.READ_MEDIA_IMAGES
adb shell pm revoke com.example.reader android.permission.READ_MEDIA_IMAGES
adb shell appops set --uid com.example.reader MANAGE_EXTERNAL_STORAGE allow   # All files access
```

#### APIs that resolve to external storage

| API | Location | Notes |
|---|---|---|
| `Context.getExternalFilesDir(type)` / `getExternalFilesDirs(type)` | App-specific external | No permission needed since API 19. `Dirs` variant includes SD cards |
| `Context.getExternalCacheDir()` / `getExternalCacheDirs()` | App-specific external cache | Not cleared automatically like `cacheDir` |
| `Context.getExternalMediaDirs()` | `Android/media/<pkg>` | Deprecated in API 30; content is media-scanned |
| `Environment.getExternalStorageDirectory()` | Volume root | Deprecated in API 29; on 30+ writing here needs *All files access* |
| `Environment.getExternalStoragePublicDirectory(type)` | `Download/`, `Pictures/`… | Deprecated in API 29; use `MediaStore` |
| `Environment.getDownloadCacheDirectory()` | System download cache | Flagged by the OWASP rule |
| `ContentResolver.insert(MediaStore.*.EXTERNAL_CONTENT_URI, …)` | Shared collections | No permission needed on 29+ for own files |
| `DownloadManager.Request.setDestinationInExternalPublicDir()` | Public dirs | Easy to miss in reviews |
| `Intent.ACTION_CREATE_DOCUMENT`, `ACTION_OPEN_DOCUMENT_TREE` (SAF) | Wherever the user picks, including cloud providers | User-mediated, but the destination is shared |

The classic vulnerable pattern needs no permission and runs on every Android version:

```kotlin
val file = File(context.getExternalFilesDir(null), "password.txt")
file.appendText(password)   // plaintext under /sdcard/Android/data/<pkg>/files/
```

#### Manifest permissions and flags

- `READ_EXTERNAL_STORAGE`: needed to read others' files on 19–32. Not needed for the app's own app-specific dirs or own MediaStore entries from 29 on. No effect when targeting 33+.
- `WRITE_EXTERNAL_STORAGE`: needed for writing outside app-specific dirs up to API 28. On 29 with scoped storage it gives no extra write reach. From 30 it is deprecated and has no effect unless legacy mode is retained. Correct modern usage is `android:maxSdkVersion="28"`.
- `MANAGE_EXTERNAL_STORAGE`: *All files access*, API 30+. A special app-access grant the user toggles in Settings. Google Play restricts it to file managers, backup, antivirus and similar categories. It gives read/write to all of shared storage, but not other apps' `Android/data` or `Android/obb`.
- `READ_MEDIA_IMAGES` / `READ_MEDIA_VIDEO` / `READ_MEDIA_AUDIO`: API 33+ replacements for media reads.
- `android:requestLegacyExternalStorage="true"`: opts out of scoped storage on Android 10 for apps targeting 29. Ignored when targeting 30+ on Android 11+.
- `android:preserveLegacyExternalStorage="true"`: keeps legacy mode across an update to targetSdk 30 until reinstall.
- `android:requestRawExternalStorageAccess`: Android 12+ hint about direct (non-FUSE) file-path access for apps doing heavy file I/O. The OWASP rule flags it as a signal of broad path-based storage use.

#### Pitfalls testers and developers get wrong

- **"`Android/data` is private."** Only from Android 11, and only from other apps. Check `minSdkVersion`.
- **"We need no permission, so it's safe."** Writing to app-specific external storage and inserting into MediaStore need no permission on modern Android. A missing `WRITE_EXTERNAL_STORAGE` tells you nothing about whether the app writes sensitive data outside the sandbox.
- **Integrity.** Anything in external storage may have been replaced by another app or the user. Android's [security guidance](https://developer.android.com/privacy-and-security/security-tips#external-storage) is explicit: validate input from external storage and never store executables or class files there.

### iOS: Document Picker, Document Interaction, and Open in Place (MASTG-KNOW-0122)

Source: [MASTG-KNOW-0122](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0122/) (with background from MASTG-KNOW-0108 *App Sandbox Directories* and MASTG-KNOW-0091 *File System APIs*).

iOS has no `/sdcard`. Every app's data lives in `/var/mobile/Containers/Data/Application/<UUID>/` with `Documents/`, `Library/` (including `Application Support/`, `Caches/`, `Preferences/`) and `tmp/`, and no other app can traverse it. Files leave the sandbox only through system-mediated mechanisms, and the user is always part of the decision. That makes the iOS side of MASWE-0002 narrower than Android's, but not empty.

#### Exposing the sandbox: Info.plist keys

| Key | Effect |
|---|---|
| `UIFileSharingEnabled` ("Application supports iTunes file sharing") | `Documents/` is shown in Finder (macOS) or iTunes/Apple Devices (Windows) for a connected, trusted device. Files can be copied off and replaced. |
| `LSSupportsOpeningDocumentsInPlace` ("Supports opening documents in place") | The app can open documents at their original location. Combined with `UIFileSharingEnabled`, its `Documents/` appears in the Files app under *On My iPhone/iPad*, where it is browsable and editable by the user and reachable by other apps through the document picker. |
| `UISupportsDocumentBrowser` | Used by document-browser apps (`UIDocumentBrowserViewController`). Treat it like the pair above when reviewing what sits in `Documents/`. |

Data Protection does not help here. Files in `Documents/` get `NSFileProtectionCompleteUntilFirstUserAuthentication` by default, and even `.complete` only protects them while the device is locked. Finder and the Files app read them on an unlocked device as normal plaintext. The whole of `Documents/` is exposed, including subfolders and the `Inbox/` directory where files received from other apps land. There is no supported way to hide a subfolder, so internal data simply must not live there.

#### Document picker

`UIDocumentPickerViewController` lets the user select files from iCloud Drive, third-party File Provider extensions and on-device locations, including other apps' exposed `Documents/` folders.

- **Import / export** copy files into or out of the sandbox. `init(forExporting:asCopy:)` (iOS 14+) replaced the deprecated `init(url:in:)` with `.exportToService`. An export places a plaintext copy wherever the user chooses, possibly a cloud provider.
- **Open / move** hand the app a *security-scoped URL* to a file outside its sandbox. The app must call `startAccessingSecurityScopedResource()` (and later `stopAccessingSecurityScopedResource()`) unless `UIDocument` manages access. Writes to such files should go through `NSFileCoordinator` (MASTG-KNOW-0127), because other processes may be reading the same file.
- An app can persist access to an opened external file with *bookmark data*. A bookmark stored in plaintext in an exposed location is itself a small leak of where the user keeps documents.

#### Document interaction

`UIDocumentInteractionController` previews a file or offers "Open in…", "Copy to…" and "Print". The system filters target apps by Uniform Type Identifier. When another app receives the file as a copy, the copy lands in the receiver's `Documents/Inbox/`. The sender keeps its original, often in `tmp/` or, worse, `Documents/`, and frequently forgets to delete it. The receiver must treat the imported file as untrusted input.

`UIActivityViewController` (the share sheet) is the more common modern path. It offers AirDrop, Mail, Messages, "Save to Files", and every installed share extension. Whatever the user chooses receives the plaintext.

#### Open in place

With `LSSupportsOpeningDocumentsInPlace`, a receiving app edits the original file where it lives (another app's exposed `Documents/`, iCloud Drive, a File Provider) through a security-scoped URL, instead of getting a copy. The receiving app must declare the document types it handles (`CFBundleDocumentTypes` / UTIs). From MASWE-0002's perspective, the key point is the side effect: the same key that enables open-in-place, together with file sharing, publishes the app's own `Documents/` to the Files app.

#### Where this leaves sensitive data on iOS

- `Library/Application Support/`, `Library/Caches/`, `tmp/`: never exposed by the keys above. Data here is MASWE-0001 territory.
- `Documents/` without the keys: private, but still included in device backups by default.
- `Documents/` with the keys: user-visible and user-modifiable, copyable by anyone holding the unlocked device or a trusted computer, and pickable by other apps. **This is where TEST-0303 looks.**
- App Group containers (`containerURL(forSecurityApplicationGroupIdentifier:)`) are shared with the developer's other apps and extensions. They are not public, but they widen the trust boundary, so check what goes there.

## Tests

### MASTG-TEST-0200: Files Written to External Storage (Android)

[MASTG-TEST-0200](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0200/) · Platform: Android · Type: dynamic, filesystem, manual

#### Overview

This is the API-agnostic test. You snapshot external storage, exercise the app, snapshot again and inspect every new or modified file. It does not matter whether the app used `FileOutputStream`, `MediaStore`, `DownloadManager`, native `fopen`, a Flutter plugin or an SDK: if a file appears, you find it. Its weakness is coverage, since you only see the flows you trigger, which is why it pairs with TEST-0201 and TEST-0202.

#### Prerequisites

- A device or emulator with `adb` and USB debugging. Root is not required: the `shell` user can read `/sdcard`, including `Android/data/<pkg>/`.
- The app installed with `adb install app.apk` (or `adb install-multiple base.apk split_*.apk` for split APKs). Add `-g` to grant runtime permissions up front so permission dialogs don't hide flows.
- Test accounts and test data that look realistic (card numbers, ID images, a recognisable password such as `GT-Canary-2026!`). Canary values make grepping reliable.
- Ideally two OS versions: the lowest the app supports (`minSdkVersion`) and the current one. Where data lands, and who can read it, varies by version.

#### Steps

1. Record the target and storage mode:

   ```bash
   adb shell dumpsys package com.example.app | grep -E 'targetSdk|minSdk|versionName'
   adb shell appops get com.example.app LEGACY_STORAGE
   adb shell appops get com.example.app MANAGE_EXTERNAL_STORAGE
   ```

2. Set a timestamp marker and a full baseline listing:

   ```bash
   adb shell touch /data/local/tmp/test_start
   adb shell "find /sdcard/ /storage/ -type f 2>/dev/null" | sort -u > before.txt
   ```

3. Exercise the app thoroughly: log in, use "remember me", view and export statements or documents, take and upload photos, open offline features, trigger errors, send a support log, change settings, log out. Enter your canary values everywhere.
4. Collect what changed, by timestamp and by diff (the diff also catches files whose mtime the app set in the past):

   ```bash
   adb shell "find /sdcard/ /storage/ -type f -newer /data/local/tmp/test_start 2>/dev/null" | sort -u > newer.txt
   adb shell "find /sdcard/ /storage/ -type f 2>/dev/null" | sort -u > after.txt
   comm -13 before.txt after.txt > created.txt
   sort -u newer.txt created.txt > changed.txt
   ```

5. Pull everything that changed and search it:

   ```bash
   mkdir -p pulled && while read -r f; do adb pull "$f" pulled/; done < changed.txt
   grep -rIl -E 'GT-Canary|Bearer |eyJ[A-Za-z0-9_-]{10,}|password|api[_-]?key|refresh_token' pulled/
   ```

6. Attribute shared-storage files to the app via MediaStore:

   ```bash
   adb shell "content query --uri content://media/external/file --projection _data:owner_package_name:date_added --where \"owner_package_name='com.example.app'\""
   ```

7. For every file, decide whether it is encrypted (see Evaluation).

Note that `/sdcard` and `/storage/emulated/0` are the same volume, so de-duplicate paths in the report. Searching `/storage/` also covers SD cards (`/storage/XXXX-XXXX/`).

#### Observation

A list of files created or modified on external storage during the session, their paths (app-specific vs shared), owning package, and their content. Keep the pulled files and `changed.txt` as evidence.

#### Evaluation

The test **fails** if any file the app wrote to external storage contains sensitive data (credentials, tokens, keys, personal data, financial, health or identity documents, business-sensitive data) that is not encrypted, or is "encrypted" in a way that offers no protection (hardcoded key, key stored alongside, Base64, ECB).

To decide whether a file is encrypted:

```bash
file pulled/*                      # "SQLite 3.x database", "JSON text", "Zip archive", "PDF document" = plaintext containers
xxd -l 64 pulled/report.bin        # look for magic bytes: PK\x03\x04, %PDF, SQLite format 3, {"
strings -n 6 pulled/report.bin | head
python3 -c 'import sys,math,collections; d=open(sys.argv[1],"rb").read(); c=collections.Counter(d); print(round(-sum(v/len(d)*math.log2(v/len(d)) for v in c.values()),2))' pulled/report.bin
```

Entropy close to 8.0 bits/byte means compressed or encrypted; around 4–6 is typical of text. High entropy alone is not proof: a JPEG or a ZIP is high-entropy but readable. If the file looks encrypted, locate the key with TEST-0202 or TEST-0201 backtraces. A key you can find in the APK means the test still fails.

The test **passes** if no sensitive data reaches external storage, or if it is protected with strong authenticated encryption under a key held in the Keystore (or derived from a user secret) and not recoverable from the device's shared storage or the app package.

Common false positives: non-sensitive media the user asked to save, public content the app downloaded (maps, videos), and SDK caches that hold only public assets. Record them as checked and move on.

#### Demo

Adapted from [MASTG-DEMO-0001](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0001/MASTG-DEMO-0001/). The app writes one file to app-specific external storage and one to `Download/` through MediaStore:

```kotlin
fun writeSecrets(context: Context) {
    // 1. app-specific external storage
    File(context.getExternalFilesDir(null), "secret.txt")
        .outputStream().use { it.write("secr3tPa\$\$W0rd\n".toByteArray()) }

    // 2. shared storage via MediaStore (no permission needed on API 29+)
    val values = ContentValues().apply {
        put(MediaStore.MediaColumns.DISPLAY_NAME, "secretFile75.txt")
        put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
        put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
    }
    val uri = context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
    uri?.let { context.contentResolver.openOutputStream(it)?.use { out ->
        out.write("MAS_API_KEY=8767086b9f6f976g-a8df76\n".toByteArray())
    } }
}
```

Running the before/after snapshot:

```text
$ adb shell "find /sdcard/ -type f -newer /data/local/tmp/test_start"
/sdcard/Android/data/org.owasp.mastestapp/files/secret.txt
/sdcard/Download/secretFile75.txt

$ cat pulled/secret.txt pulled/secretFile75.txt
secr3tPa$$W0rd
MAS_API_KEY=8767086b9f6f976g-a8df76
```

Both files are plaintext and sensitive, so the test fails. The second is the more serious: it sits in shared storage, outlives uninstall, and is readable by any *All files access* app.

### MASTG-TEST-0201: Runtime Use of APIs to Access External Storage (Android)

[MASTG-TEST-0201](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0201/) · Platform: Android · Type: dynamic, hooks, manual

#### Overview

Instead of looking at the filesystem after the fact, you hook the APIs as they are called and capture the path, the arguments and a backtrace. This answers the questions TEST-0200 cannot: which code wrote the file (the app or an SDK), and through which API. Two hooks give broad coverage:

- libc `open`/`openat`, filtered to external-storage paths. This catches every Java file API (`FileOutputStream`, `FileWriter`, `RandomAccessFile`, `Files.write`, Kotlin `writeText`), because they all end up in libc, and most native code too.
- `ContentResolver.insert()` / `openOutputStream()`, because MediaStore writes are performed by the media provider process. The target app only handles a `content://` URI and a file descriptor, so an `open` hook in the app never sees the real path.

#### Prerequisites

- A rooted device or emulator running `frida-server` matching your host `frida` version, or a repackaged APK with Frida Gadget for non-rooted devices.
- The app installed; package name known (`frida-ps -Uai`).
- The same canary test data as TEST-0200.

#### Steps

1. Save this as `storage-trace.js`. It logs write-mode opens on external paths and MediaStore inserts, with Java backtraces:

   ```javascript
   const EXT_PREFIXES = ['/sdcard', '/storage/', '/mnt/sdcard', '/mnt/media_rw'];
   const O_ACCMODE = 3; // O_WRONLY = 1, O_RDWR = 2

   function javaTrace() {
     const Log = Java.use('android.util.Log');
     const Exception = Java.use('java.lang.Exception');
     return Log.getStackTraceString(Exception.$new()).split('\n').slice(1, 14).join('\n');
   }

   const libc = Process.getModuleByName('libc.so');
   [['open', 0, 1], ['openat', 1, 2]].forEach(([name, pathIdx, flagIdx]) => {
     Interceptor.attach(libc.getExportByName(name), {
       onEnter(args) {
         const path = args[pathIdx].readCString();
         const flags = args[flagIdx].toInt32();
         if (path && EXT_PREFIXES.some(p => path.startsWith(p)) && (flags & O_ACCMODE) !== 0) {
           console.log(`\n[${name}] WRITE ${path}`);
           if (Java.available) Java.perform(() => console.log(javaTrace()));
         }
       }
     });
   });

   Java.perform(() => {
     const CR = Java.use('android.content.ContentResolver');
     CR.insert.overload('android.net.Uri', 'android.content.ContentValues').implementation = function (uri, values) {
       const result = this.insert(uri, values);
       console.log(`\n[ContentResolver.insert] ${uri} -> ${result}\n  values: ${values}`);
       console.log(javaTrace());
       return result;
     };
     CR.openOutputStream.overload('android.net.Uri', 'java.lang.String').implementation = function (uri, mode) {
       console.log(`\n[ContentResolver.openOutputStream] ${uri} mode=${mode}`);
       return this.openOutputStream(uri, mode);
     };
   });
   ```

2. Spawn the app with the script and log to a file:

   ```bash
   frida -U -f com.example.app -l storage-trace.js -o storage-trace.log
   ```

3. Exercise the app as in TEST-0200. Press `Ctrl+C` when done.
4. For each hit, note the path, the API and the first app-owned frame in the backtrace. Then pull the file (`adb pull`) and inspect its content. For MediaStore inserts, reconstruct the path from `relative_path` and `_display_name` (e.g. `Download/` + `secretFile.txt` → `/storage/emulated/0/Download/secretFile.txt`), or query the returned URI:

   ```bash
   adb shell content query --uri content://media/external/downloads/1000000143 --projection _data
   ```

5. Optionally open the backtrace locations in `jadx-gui` to see what data flows into the write and whether it is encrypted first.

If you prefer objection, `android hooking watch class_method android.app.ContextImpl.getExternalFilesDir --dump-args --dump-backtrace --dump-return` gives a quick view of who asks for the directory, though not of what gets written.

Noise and blind spots: the `open` hook also fires for the app reading its own OBB or for WebView caches, which is why the script filters to write modes. Native code can call the `syscall` instruction directly, and some frameworks write through a separate process. If TEST-0200 shows a file that the trace did not, that is the reason.

#### Observation

A log of every external-storage write: file path or `content://` URI, `ContentValues` (display name, MIME type, relative path), and a backtrace leading to the calling class and method.

#### Evaluation

The test **fails** if any traced write puts sensitive data on external storage unencrypted or weakly encrypted (same criteria as TEST-0200). The backtrace tells you whether the responsibility lies in first-party code or an SDK. Both are findings for the app.

The test **passes** if no sensitive data is written, or if every sensitive write goes through authenticated encryption with a properly protected key. A `CipherOutputStream`, Tink `StreamingAead` or `EncryptedFile` frame in the backtrace is a good indicator, which you should confirm by inspecting the pulled file.

#### Demo

Adapted from [MASTG-DEMO-0002](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0002/MASTG-DEMO-0002/), using the same sample code as the TEST-0200 demo. Trimmed output:

```text
[open] WRITE /storage/emulated/0/Android/data/org.owasp.mastestapp/files/secret.txt
	at libcore.io.Linux.open(Native Method)
	at libcore.io.IoBridge.open(IoBridge.java:560)
	at java.io.FileOutputStream.<init>(FileOutputStream.java:236)
	at org.owasp.mastestapp.MastgTest.mastgTestApi(MastgTest.kt:26)
	at org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:16)

[ContentResolver.insert] content://media/external/downloads -> content://media/external/downloads/1000000143
  values: _display_name=secretFile59.txt mime_type=text/plain relative_path=Download
	at org.owasp.mastestapp.MastgTest.mastgTestMediaStore(MastgTest.kt:44)
	at org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:17)

[ContentResolver.openOutputStream] content://media/external/downloads/1000000143 mode=w
```

Two writes, both from `MastgTest`: a password via `FileOutputStream` into app-specific external storage, and an API key via MediaStore into `/storage/emulated/0/Download/secretFile59.txt`. Pulling both confirms plaintext, so the test fails.

### MASTG-TEST-0202: References to APIs and Permissions for Accessing External Storage (Android)

[MASTG-TEST-0202](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0202/) · Platform: Android · Type: static, code, manual

#### Overview

A static sweep for every code location that obtains an external-storage path or writes through MediaStore/SAF, plus the manifest permissions and flags that widen storage access. It finds code paths you never triggered dynamically, including dead features, debug flags and SDK code. It does not tell you what is actually written or, for computed paths, exactly where, so each hit needs manual review or a dynamic follow-up.

#### Prerequisites

- The APK (pull it with `adb shell pm path com.example.app` then `adb pull <path>`; pull all splits).
- `jadx`, `apktool` or `aapt`/`aapt2`, `semgrep`, `grep`.
- For cross-platform apps: the JS bundle (`assets/index.android.bundle`) for React Native, or awareness that Flutter compiles Dart into `libapp.so`, so you will mostly see the plugin's Java side (`path_provider`'s `getExternalStorageDirectory`).

#### Steps

1. Decompile:

   ```bash
   jadx -d out app.apk                  # sources in out/sources, manifest in out/resources
   ```

2. Search the code for storage APIs:

   ```bash
   grep -rnE 'getExternalStorageDirectory|getExternalStoragePublicDirectory|getDownloadCacheDirectory|getExternalFilesDirs?\(|getExternalCacheDirs?\(|getExternalMediaDirs|MediaStore|setDestinationInExternal(Public|Files)Dir|ACTION_CREATE_DOCUMENT|ACTION_OPEN_DOCUMENT_TREE|"/sdcard|/storage/emulated' out/sources/
   ```

   Or use the OWASP semgrep rules (condensed here):

   ```yaml
   rules:
     - id: external-api-public
       languages: [java]
       severity: WARNING
       message: "[MASVS-STORAGE] Shared external storage location, encrypt if sensitive"
       pattern-either:
         - pattern: $X.getExternalStorageDirectory(...)
         - pattern: $X.getExternalStoragePublicDirectory(...)
         - pattern: $X.getDownloadCacheDirectory(...)
         - pattern: Intent.ACTION_CREATE_DOCUMENT
     - id: external-api-scoped
       languages: [java]
       severity: WARNING
       message: "[MASVS-STORAGE] App-specific external storage, readable by other apps on Android 10 and below"
       pattern-either:
         - pattern: $X.getExternalFilesDir(...)
         - pattern: $X.getExternalFilesDirs(...)
         - pattern: $X.getExternalCacheDir(...)
         - pattern: $X.getExternalCacheDirs(...)
         - pattern: $X.getExternalMediaDirs(...)
     - id: mediastore
       languages: [java]
       severity: WARNING
       message: "[MASVS-STORAGE] MediaStore write, data is shared with other apps"
       pattern-either:
         - pattern: import android.provider.MediaStore
         - pattern: $X.MediaStore
   ```

   ```bash
   semgrep --config storage-apis.yml out/sources/
   ```

3. Check native libraries for hardcoded external paths:

   ```bash
   unzip -o -q app.apk 'lib/*' -d apk && grep -l -a -E '/sdcard|/storage/emulated' apk/lib/*/*.so
   ```

4. Extract the manifest and SDK levels:

   ```bash
   aapt dump badging app.apk | grep -E "sdkVersion|targetSdkVersion"
   aapt d permissions app.apk
   grep -nE 'WRITE_EXTERNAL_STORAGE|READ_EXTERNAL_STORAGE|MANAGE_EXTERNAL_STORAGE|READ_MEDIA_|requestLegacyExternalStorage|preserveLegacyExternalStorage|requestRawExternalStorageAccess|maxSdkVersion' out/resources/AndroidManifest.xml
   ```

   (`apktool d -s app.apk -o apk_out` also works. It puts the SDK levels in `apk_out/apktool.yml` rather than the manifest.)
5. For every code hit, open the method in `jadx-gui`, follow the data that is written and decide whether it is sensitive and whether it is encrypted on the way. Use *Find usage* on the `File` or `Uri` returned by the API to reach the actual write.

#### Observation

A list of storage API call sites (file and line), the declared storage permissions and flags, `minSdkVersion`/`targetSdkVersion`, and for each call site what data it writes.

#### Evaluation

OWASP states the failure condition as: the manifest declares storage permissions, the code uses APIs that write to shared storage, **and** the data written is sensitive and unencrypted. Apply it with one correction from practice. On API 29+ neither `getExternalFilesDir()` nor a MediaStore insert of the app's own file needs any permission, so **the absence of `WRITE_EXTERNAL_STORAGE` must not lead you to pass a call site that writes sensitive plaintext**. The deciding factor is the data, not the permission. Permissions and flags change the severity:

- `MANAGE_EXTERNAL_STORAGE`, `requestLegacyExternalStorage="true"` with `targetSdk` 29, or `minSdkVersion` ≤ 29 mean the app writes to, or runs on, configurations where other apps can read more.
- `WRITE_EXTERNAL_STORAGE` without `maxSdkVersion="28"` is a hygiene finding on its own (Low/Info) when no sensitive writes exist.

The test **passes** when every call site writes non-sensitive data or encrypts sensitive data with a protected key before writing.

#### Demo

Three OWASP demos cover the main variants.

**Volume root with All files access** ([MASTG-DEMO-0003](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0003/MASTG-DEMO-0003/)):

```kotlin
val file = File(Environment.getExternalStorageDirectory(), "secret.txt")   // /storage/emulated/0/secret.txt
FileOutputStream(file).use { it.write("Secret not using scoped storage".toByteArray()) }
```

```xml
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
```

```text
MastgTest_reversed.java
  ❯❱ rules.mastg-android-data-unencrypted-shared-storage-no-user-interaction-external-api-public
       27┆ File externalStorageDir = Environment.getExternalStorageDirectory();
AndroidManifest_reversed.xml
  ❯❱ rules.mastg-android-data-unencrypted-shared-storage-no-user-interaction-manifest
        2┆ <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
```

To run it you must grant *All files access* (`adb shell appops set --uid org.owasp.mastestapp MANAGE_EXTERNAL_STORAGE allow`). The file then sits at the root of shared storage. It fails.

**App-specific external storage** ([MASTG-DEMO-0004](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0004/MASTG-DEMO-0004/)): `context.getExternalFilesDir(null)` plus `FileOutputStream`, writing a password, with no permission declared.

```text
  ❯❱ rules.mastg-android-data-unencrypted-shared-storage-no-user-interaction-external-api-scoped
       [MASVS-STORAGE] These locations might be accessible to other apps on Android 10 and below
       25┆ File externalStorageDir = this.context.getExternalFilesDir(null);
```

It fails because the content is a plaintext password. Note that it fails despite there being no permission in the manifest.

**MediaStore** ([MASTG-DEMO-0005](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0005/MASTG-DEMO-0005/)): an API key written to `Download/secretFile.txt` via `resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, …)`.

```text
  ❯❱ rules.mastg-android-data-unencrypted-shared-storage-no-user-interaction-mediastore
        8┆ import android.provider.MediaStore;
       35┆ Uri textUri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues);
```

The import hit is noise. The `insert` call is the finding, and the written content (an API key) makes it fail.

### MASTG-TEST-0303: References to APIs for Storing Unencrypted Data in Shared Storage (iOS)

[MASTG-TEST-0303](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0303/) · Platform: iOS · Type: static, code

#### Overview

The test asks two questions and fails only if the answer to both is yes. First, does the app expose its `Documents/` directory through `UIFileSharingEnabled` and/or `LSSupportsOpeningDocumentsInPlace`? Second, does it write unencrypted sensitive data there? `Documents/` is not inherently insecure. It is meant for user content. The weakness is putting tokens, databases, logs or other internal state in a folder the app has made user-visible. Data in `Library/Application Support/` or the Keychain is unaffected by these keys.

#### Prerequisites

- A decrypted IPA (App Store binaries are FairPlay-encrypted, so obtain a decrypted copy from a jailbroken device or use a development/ad-hoc build supplied for the test).
- macOS with `plutil`, `/usr/libexec/PlistBuddy`, `xcrun swift-demangle`; `radare2` (`rabin2`, `r2`); optionally `libimobiledevice` and `ifuse` for confirmation on a device.

#### Steps

1. Unpack the IPA and locate the binaries:

   ```bash
   unzip -q App.ipa -d ipa && cd ipa/Payload/App.app
   ls Frameworks PlugIns 2>/dev/null        # extensions and frameworks may also write files
   ```

2. Read the two keys (and the document-browser key) from `Info.plist`. PlistBuddy reads binary plists directly:

   ```bash
   for k in UIFileSharingEnabled LSSupportsOpeningDocumentsInPlace UISupportsDocumentBrowser; do
     printf '%s: ' "$k"; /usr/libexec/PlistBuddy -c "Print :$k" Info.plist 2>&1
   done
   plutil -p Info.plist | grep -E 'CFBundleDocumentTypes|NSFileProtection'
   ```

   A missing key prints `Print: Entry, ":UIFileSharingEnabled", Does Not Exist`, which means the default, `NO`.
3. If either sharing key is `true`, look for code that resolves or writes into `Documents/`. Start with imports and strings:

   ```bash
   rabin2 -i App | xcrun swift-demangle | grep -iE 'documentsDirectory|write\(to|createFile|FileHandle|OutputStream|NSSearchPathForDirectoriesInDomains|fopen|fwrite|fputs|open$'
   rabin2 -zz App | grep -E 'URLsForDirectory:inDomains:|createFileAtPath:contents:attributes:|writeToURL:options:error:|writeToFile:atomically:|Documents/|\.sqlite|\.realm|\.log'
   ```

   `FileManager.urls(for:in:)` is an Objective-C method, so its selector `URLsForDirectory:inDomains:` appears in the binary even for Swift apps. `Data.write(to:options:)`, `String.write(to:atomically:encoding:)` and `URL.documentsDirectory` (iOS 16+) appear as Swift imports, readable after demangling.
4. Follow call sites in radare2. Find the import address, list its cross-references and read the callers:

   ```bash
   r2 -A App
   [0x...]> ii~write
   [0x...]> axt @ <import address>
   [0x...]> pdf @ <caller>
   ```

   In each caller, establish which directory was resolved (`NSDocumentDirectory` is the constant `9`, `NSApplicationSupportDirectory` is `14`, passed to `URLsForDirectory:inDomains:`), what data is written, and whether a crypto call (`CryptoKit` `AES.GCM.seal`, `CCCrypt`, `SecKeyCreateEncryptedData`) runs first. Look for Keychain calls (`SecItemAdd`, `SecItemCopyMatching`) to see where any key lives.
5. Confirm on a device (recommended, though not part of the OWASP static test). With file sharing enabled, a non-jailbroken device paired to your Mac is enough:

   ```bash
   ideviceinstaller -l | grep -i example          # bundle ID
   mkdir -p mnt && ifuse --documents com.example.app mnt
   ls -laR mnt && grep -rIl -E 'GT-Canary|eyJ|token|password' mnt
   umount mnt
   ```

   Alternatively, open the device in Finder (*Files* tab) or the Files app on the device and browse *On My iPhone → App*. On a jailbroken device, `objection -g com.example.app explore` followed by `env` shows the container paths, and `ls`/`filesystem download` retrieves files.

#### Observation

The values of `UIFileSharingEnabled`, `LSSupportsOpeningDocumentsInPlace` (and `UISupportsDocumentBrowser`), plus a list of code locations that write, or could write, into `Documents/` and the data they write. If you did the on-device confirmation, add the actual file listing.

#### Evaluation

The test **fails** if both of the following hold:

- the app writes sensitive data unencrypted to `Documents/` (or an equivalent exposed path), and
- `Info.plist` enables user access to `Documents/` via `UIFileSharingEnabled` and/or `LSSupportsOpeningDocumentsInPlace`.

It **passes** if the keys are absent or `NO` (sensitive data in `Documents/` is then a MASWE-0001/backup question, not this one), or if `Documents/` contains only user-intended content and internal data lives in `Library/` or the Keychain, or if anything sensitive in `Documents/` is encrypted under a Keychain-held key. A common false positive is an app whose `Documents/` holds only files the user imported or created and expects to manage: that is the feature working as designed. Do flag it if those user documents are themselves highly sensitive (e.g. medical records) and the user cannot reasonably expect them to be exposed to a computer.

#### Demo

OWASP has no demo for this test yet. The following is our own minimal example. A session token is written to `Documents/` in an app that also enables Files access:

```swift
func cacheSession(token: String, refresh: String) throws {
    let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    let url = docs.appendingPathComponent("session.txt")
    try "access=\(token)\nrefresh=\(refresh)\n".write(to: url, atomically: true, encoding: .utf8)
}
```

```xml
<key>UIFileSharingEnabled</key>
<true/>
<key>LSSupportsOpeningDocumentsInPlace</key>
<true/>
```

Detection (illustrative, trimmed):

```text
$ /usr/libexec/PlistBuddy -c "Print :UIFileSharingEnabled" Info.plist
true
$ /usr/libexec/PlistBuddy -c "Print :LSSupportsOpeningDocumentsInPlace" Info.plist
true
$ rabin2 -zz App | grep URLsForDirectory
... URLsForDirectory:inDomains:
$ rabin2 -i App | xcrun swift-demangle | grep 'write(to'
... (extension in Foundation):Swift.StringProtocol.write<A>(to: Foundation.URL, atomically: Swift.Bool, encoding: Swift.String.Encoding) throws -> ()
$ ifuse --documents com.example.app mnt && cat mnt/session.txt
access=eyJhbGciOiJIUzI1NiJ9...
refresh=rt_9f2c...
```

Both conditions hold, so the test fails: anyone with the unlocked phone, or a computer it trusts, can copy a live refresh token in seconds without a jailbreak.

## Secure implementation

### Android

**1. Default to internal storage.** Most "we need a file" requirements are met by private storage, which needs no permission and is not reachable by other apps:

```kotlin
val f = File(context.filesDir, "statement-cache.json")        // /data/data/<pkg>/files
val nb = File(context.noBackupFilesDir, "device-state.bin")   // excluded from backup
context.openFileOutput("notes.dat", Context.MODE_PRIVATE).use { it.write(bytes) }
```

Private storage is not automatically "secure" either. Rooted devices and backups are covered in [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/).

**2. If it must go to external storage, encrypt it first with a Keystore key.** For small and medium files, AES-256-GCM with a non-exportable Keystore key:

```kotlin
private const val ALIAS = "ext_file_key"

private fun key(): SecretKey {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
    val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    gen.init(
        KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
    )
    return gen.generateKey()
}

fun writeEncrypted(file: File, plaintext: ByteArray) {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key())            // Keystore generates a fresh 12-byte IV
    cipher.updateAAD(file.name.toByteArray())          // bind ciphertext to its file name
    val ct = cipher.doFinal(plaintext)
    file.outputStream().use { out -> out.write(cipher.iv.size); out.write(cipher.iv); out.write(ct) }
}

fun readEncrypted(file: File): ByteArray {
    val blob = file.readBytes()
    val ivLen = blob[0].toInt()
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob, 1, ivLen))
    cipher.updateAAD(file.name.toByteArray())
    return cipher.doFinal(blob, 1 + ivLen, blob.size - 1 - ivLen)
}
```

Do not pass your own IV on encryption. Keystore keys require randomised encryption by default and will reject a caller-supplied IV. A Keystore key cannot leave the device and is lost on uninstall, which is the point: a copied file is useless elsewhere, and that also rules out the key-reuse mode of introduction. If a file must remain readable after reinstall or on another device, the key has to come from the user (passphrase plus a slow KDF) or from your server, not from the APK.

For large files, use Tink's streaming AEAD with its keyset wrapped by a Keystore master key, so you are not pushing megabytes through the Keystore:

```kotlin
StreamingAeadConfig.register()
val handle = AndroidKeysetManager.Builder()
    .withSharedPref(context, "ext_keyset", "crypto_prefs")
    .withKeyTemplate(KeyTemplates.get("AES256_GCM_HKDF_4KB"))
    .withMasterKeyUri("android-keystore://ext_master_key")
    .build()
    .keysetHandle
val aead = handle.getPrimitive(StreamingAead::class.java)   // newer Tink: getPrimitive(RegistryConfiguration.get(), StreamingAead::class.java)
FileOutputStream(File(context.getExternalFilesDir(null), "video.enc")).use { raw ->
    aead.newEncryptingStream(raw, "video.enc".toByteArray()).use { it.write(videoBytes) }
}
```

The deprecated-but-working Jetpack equivalent, which wraps the same Tink scheme:

```kotlin
val masterKey = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
val target = File(context.getExternalFilesDir(null), "report.enc")   // must not already exist
EncryptedFile.Builder(context, target, masterKey, EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB)
    .build()
    .openFileOutput().use { it.write(reportBytes) }
```

**3. Use shared storage only for what the user means to share, through MediaStore.** No permission is needed on API 29+ for the app's own files. Use `IS_PENDING` so other apps never see a half-written file:

```kotlin
val values = ContentValues().apply {
    put(MediaStore.MediaColumns.DISPLAY_NAME, "receipt-2026-11.pdf")
    put(MediaStore.MediaColumns.MIME_TYPE, "application/pdf")
    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
    put(MediaStore.MediaColumns.IS_PENDING, 1)
}
val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: return
resolver.openOutputStream(uri)?.use { it.write(pdfBytes) }
values.clear()
values.put(MediaStore.MediaColumns.IS_PENDING, 0)
resolver.update(uri, values, null, null)
```

Anything written this way is public, survives uninstall and may be synced to the cloud. Never put credentials, tokens, logs or raw identity documents here.

**4. Prefer user-chosen destinations (SAF) or direct sharing over dropping files in `Download/`.** For exports, let the user pick the location. For handing a file to another app, share it from private storage via `FileProvider` rather than copying it to shared storage first:

```kotlin
private val export = registerForActivityResult(ActivityResultContracts.CreateDocument("application/pdf")) { uri ->
    uri?.let { contentResolver.openOutputStream(it)?.use { out -> out.write(renderStatement()) } }
}
// export.launch("statement-2026-11.pdf")

val shareUri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", privateFile)
startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
    type = "application/pdf"
    putExtra(Intent.EXTRA_STREAM, shareUri)
    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
}, null))
```

For highly sensitive exports (full statements, health records), consider protecting the exported document with a user-supplied password, and tell the user where the file is going.

**5. Declare the narrowest permissions and drop legacy flags.**

```xml
<!-- Only for API 28 and below, where writing outside app dirs needed it -->
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" android:maxSdkVersion="28" />
<!-- Reading other apps' media, only if the feature needs it -->
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" android:maxSdkVersion="32" />
<uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />

<application
    android:label="@string/app_name">
    <!-- no requestLegacyExternalStorage / preserveLegacyExternalStorage -->
</application>
```

Avoid `MANAGE_EXTERNAL_STORAGE` unless the app is genuinely a file manager or backup tool. Prefer the Photo Picker (`ActivityResultContracts.PickVisualMedia()`), which needs no permission at all, to `READ_MEDIA_*`.

**6. Treat external files as hostile on read.** Verify a MAC or signature over anything the app relies on (configuration, cached entitlements), validate formats, and never load DEX, SO or other code from external storage. Delete temporary exports once the share or SAF write completes.

### iOS

**1. Keep internal data out of `Documents/`.** Use `Library/Application Support` for databases, caches of sensitive responses and state, set strong file protection, and exclude what should not be backed up:

```swift
var url = try FileManager.default
    .url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
    .appendingPathComponent("session.bin")
try sealedData.write(to: url, options: [.atomic, .completeFileProtection])
var values = URLResourceValues()
values.isExcludedFromBackup = true
try url.setResourceValues(values)
```

Credentials and tokens belong in the Keychain, not in files at all.

**2. Only enable file sharing when the feature needs it, and audit `Documents/` when you do.** If the app does not let users manage files from Finder or the Files app, leave `UIFileSharingEnabled` and `LSSupportsOpeningDocumentsInPlace` absent (both default to `NO`). If it does, `Documents/` must contain nothing but user documents. Move SDK caches, logs and databases elsewhere. Some SDKs default to `Documents/`, so check their configuration.

**3. Encrypt anything sensitive that must sit in an exposed location**, with CryptoKit and a key held in the Keychain:

```swift
import CryptoKit

func loadOrCreateFileKey(account: String = "file-key") throws -> SymmetricKey {
    var item: CFTypeRef?
    let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrAccount as String: account,
                                kSecReturnData as String: true]
    if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data {
        return SymmetricKey(data: data)
    }
    let key = SymmetricKey(size: .bits256)
    let add: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                              kSecAttrAccount as String: account,
                              kSecValueData as String: key.withUnsafeBytes { Data($0) },
                              kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    return key
}

func writeSealed(_ plaintext: Data, to url: URL, key: SymmetricKey) throws {
    guard let blob = try AES.GCM.seal(plaintext, using: key).combined else { throw CocoaError(.fileWriteUnknown) }
    try blob.write(to: url, options: [.atomic, .completeFileProtection])
}

func readSealed(from url: URL, key: SymmetricKey) throws -> Data {
    try AES.GCM.open(try AES.GCM.SealedBox(combined: Data(contentsOf: url)), using: key)
}
```

`ThisDeviceOnly` keeps the key out of backups and off other devices, so a copied file cannot be decrypted elsewhere.

**4. Export deliberately, from `tmp/`, and clean up.** Write the export to the temporary directory, hand it to the system UI and delete it afterwards:

```swift
let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("statement.pdf")
try pdfData.write(to: tmp, options: [.atomic, .completeFileProtection])

// Save to a location of the user's choosing (iOS 14+)
let picker = UIDocumentPickerViewController(forExporting: [tmp], asCopy: true)
present(picker, animated: true)

// Or offer the share sheet, trimming destinations that make no sense for the data
let share = UIActivityViewController(activityItems: [tmp], applicationActivities: nil)
share.excludedActivityTypes = [.copyToPasteboard, .assignToContact, .print]
share.completionWithItemsHandler = { _, _, _, _ in try? FileManager.default.removeItem(at: tmp) }
present(share, animated: true)
```

For the picker, delete the temporary file in `documentPicker(_:didPickDocumentsAt:)` and `documentPickerWasCancelled(_:)`. The same applies to files handed to `UIDocumentInteractionController`.

**5. Pasteboard, briefly.** `UIPasteboard.general` is another location outside private storage, shared with every app and, via Universal Clipboard, with the user's other devices. It is assessed under MASVS-PLATFORM rather than here. If the app must place a secret on it (a one-time code), use `setItems(_:options:)` with `.localOnly` and an `.expirationDate`.

## Rating findings

Rate on three factors: **what** the data is, **who** can read it on the OS versions the app supports (check `minSdkVersion` / the iOS deployment target), and **how much interaction** that reader needs. A hardcoded or co-located key counts as no encryption.

| Rating | Conditions |
|---|---|
| **Critical** | Long-lived authentication material (passwords, refresh tokens, private keys, API keys with write scope, or the keys protecting other stores) written in plaintext to Android shared storage (`Download/`, `Documents/`, volume root, media collections), where other apps can read it without user interaction on a supported OS version. The same for large volumes of regulated data (health records, identity documents) in public media collections. |
| **High** | Sensitive personal or financial data in Android shared storage. Credentials or tokens in app-specific external storage where `minSdkVersion` ≤ 29 (readable by any app with storage permission on those devices) or where the app uses `requestLegacyExternalStorage`. On iOS: tokens, credentials, or databases containing them in `Documents/` with `UIFileSharingEnabled` + `LSSupportsOpeningDocumentsInPlace`, extractable by anyone with the unlocked device or a trusted computer. Integrity-relevant files (entitlements, configuration, downloaded code) read back from shared storage without verification. |
| **Medium** | Sensitive personal data in app-specific external storage on an app with `minSdkVersion` ≥ 30, so exposure is limited to physical access, `adb`, USB transfer, or a removable SD card. On iOS: personal data, chat history or cached API responses in an exposed `Documents/`. Sensitive data "encrypted" with a hardcoded key or weak scheme in any shared location (rate the plaintext case, then step down at most one level if extracting the key takes real effort). Tamperable premium/feature state in external storage or an exposed `Documents/`. |
| **Low** | Low-sensitivity identifiers (user IDs, device IDs, analytics or verbose logs without secrets) in external storage. `MANAGE_EXTERNAL_STORAGE` or `requestLegacyExternalStorage` declared without a clear need, but with no sensitive writes found. Temporary exports left behind after a user-initiated share. |
| **Info** | `WRITE_EXTERNAL_STORAGE` without `maxSdkVersion="28"`. External-storage APIs used only for public or non-sensitive content. User-initiated exports of the user's own data via SAF, the document picker or the share sheet, with clear UX. |

Raise the rating when the leaked secret grants server-side access (account takeover beats local disclosure), when the data persists after uninstall, or when shared storage is synced to the cloud by default (`DCIM/`, `Pictures/`). Lower it when the data is short-lived and is reliably deleted within seconds, though "the app deletes it later" rarely survives a crash or force-stop, so verify it.

When reporting, include the exact path, the API and call site (from TEST-0201/0202), the OS versions on which other apps can read it, and the pulled file contents with secrets partially redacted.

## References

OWASP (CC BY-SA 4.0):

- [MASWE-0002: Sensitive Data Stored Unencrypted Outside of Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0002/) (CC BY-SA 4.0)
- [MASTG-KNOW-0042: External Storage](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0042/) (CC BY-SA 4.0)
- [MASTG-KNOW-0122: Document Picker, Document Interaction, and Open in Place](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0122/) (CC BY-SA 4.0)
- [MASTG-KNOW-0108: App Sandbox Directories](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0108/) (CC BY-SA 4.0)
- [MASTG-KNOW-0091: File System APIs](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0091/) (CC BY-SA 4.0)
- [MASTG-KNOW-0127: File Coordination APIs](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0127/) (CC BY-SA 4.0)
- [MASTG-TEST-0200: Files Written to External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0200/) (CC BY-SA 4.0)
- [MASTG-TEST-0201: Runtime Use of APIs to Access External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0201/) (CC BY-SA 4.0)
- [MASTG-TEST-0202: References to APIs and Permissions for Accessing External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0202/) (CC BY-SA 4.0)
- [MASTG-TEST-0303: References to APIs for Storing Unencrypted Data in Shared Storage](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0303/) (CC BY-SA 4.0)
- [MASTG-BEST-0024: Store Data Encrypted in App Sandbox Directory](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0024/) (CC BY-SA 4.0)
- MASTG demos [0001](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0001/MASTG-DEMO-0001/), [0002](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0002/MASTG-DEMO-0002/), [0003](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0003/MASTG-DEMO-0003/), [0004](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0004/MASTG-DEMO-0004/), [0005](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0005/MASTG-DEMO-0005/) (CC BY-SA 4.0)

Vendor documentation and research:

- [Android Developers: Data and file storage overview](https://developer.android.com/training/data-storage)
- [Android Developers: Access app-specific files](https://developer.android.com/training/data-storage/app-specific)
- [Android Developers: Access media files from shared storage](https://developer.android.com/training/data-storage/shared/media)
- [Android Developers: Access documents and other files from shared storage (SAF)](https://developer.android.com/training/data-storage/shared/documents-files)
- [Android Developers: Manage all files on a storage device](https://developer.android.com/training/data-storage/manage-all-files)
- [Android Developers: Storage use cases and best practices](https://developer.android.com/training/data-storage/use-cases)
- [Android Developers: Security tips, external storage](https://developer.android.com/privacy-and-security/security-tips#external-storage)
- [Android Developers: Photo picker](https://developer.android.com/training/data-storage/shared/photopicker)
- [Android Developers: Cryptography, Jetpack Security deprecation](https://developer.android.com/privacy-and-security/cryptography#jetpack_security_crypto_library)
- [Android Developers: Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Google Tink: Streaming AEAD](https://developers.google.com/tink/streaming-aead)
- [Apple: UIFileSharingEnabled](https://developer.apple.com/documentation/bundleresources/information-property-list/uifilesharingenabled)
- [Apple: LSSupportsOpeningDocumentsInPlace](https://developer.apple.com/documentation/bundleresources/information-property-list/lssupportsopeningdocumentsinplace)
- [Apple: UIDocumentPickerViewController](https://developer.apple.com/documentation/uikit/uidocumentpickerviewcontroller)
- [Apple: UIDocumentInteractionController](https://developer.apple.com/documentation/uikit/uidocumentinteractioncontroller)
- [Apple: UIActivityViewController](https://developer.apple.com/documentation/uikit/uiactivityviewcontroller)
- [Apple: Encrypting your app's files](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/encrypting_your_app_s_files)
- [Apple: CryptoKit AES.GCM](https://developer.apple.com/documentation/cryptokit/aes/gcm)
- [Check Point Research: Man-in-the-Disk](https://blog.checkpoint.com/2018/08/12/man-in-the-disk-a-new-attack-surface-for-android-apps/)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-922: Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
