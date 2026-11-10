---
title: "MASWE-0057: App Resources Integrity Not Verified"
date: 2026-11-10 20:06:00 +0000
subcategory: resilience
summary: "Testing whether Android and iOS apps detect tampered packages, assets and stored data: signer checks, HMAC with Keystore/Keychain keys, rollback."
refs: [MASWE-0057, MASVS-RESILIENCE-2, MASVS-CODE-4, CWE-471]
tags: [android, ios, masvs-resilience, anti-tampering, integrity, hmac]
---

This note is part of our [MASVS-RESILIENCE guide](/mobile/masvs-resilience-resilience-testing-guide/) and covers OWASP [MASWE-0057](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0057/): an app that trusts its own files without checking that they are still the files it wrote or shipped. There are two halves. The first is the app package: the APK or IPA is signed, and the operating system checks that signature at install time. Nothing re-checks it while the app runs, so apps that care add their own checks: a signer check, hashes of `classes.dex` or a JavaScript bundle, a look at their own code signature. The second half is the data the app stores: `SharedPreferences`, `UserDefaults`, files and databases. On a rooted or jailbroken device, after a backup is restored, or after a device-to-device transfer, these can hold anything, and an app that reads `isPremium=true` or `pinAttempts=0` from them and believes it has handed the decision to whoever controls the device. Below you get the mechanisms on both platforms, the two OWASP tests (static searches for integrity APIs), two of our own runtime tests (tampering with stored data and re-signing the app), corrected reference implementations, and rating guidance that reflects one point: **a client-side integrity check without a server-side decision can always be bypassed eventually**. These checks are defence in depth for apps in OWASP's **R** profile. They raise the attacker's cost and never replace server-side enforcement. MAC correctness (constant-time comparison, key separation, encrypt-then-MAC) is covered in depth in our [MASWE-0009 note](/mobile/maswe-0009-improper-use-of-mac/), and is linked rather than repeated here.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: File Integrity Checks (MASTG-KNOW-0029)](#android-file-integrity-checks-mastg-know-0029)
  - [Android: Shared Preferences (MASTG-KNOW-0036)](#android-shared-preferences-mastg-know-0036)
  - [iOS: Storage Integrity Checks (MASTG-KNOW-0086)](#ios-storage-integrity-checks-mastg-know-0086)
  - [Generic: Binary Patching (MASTG-KNOW-0109)](#generic-binary-patching-mastg-know-0109)
- [Tests](#tests)
  - [MASTG-TEST-0338: References to Storage Integrity Check APIs (Android)](#mastg-test-0338-references-to-storage-integrity-check-apis-android)
  - [MASTG-TEST-0387: References to Storage Integrity Check APIs (iOS)](#mastg-test-0387-references-to-storage-integrity-check-apis-ios)
  - [GT-RES-0057-1: Tampering with stored data at runtime (Android, iOS)](#gt-res-0057-1-tampering-with-stored-data-at-runtime-android-ios)
  - [GT-RES-0057-2: Repackaging and re-signing detection (Android, iOS)](#gt-res-0057-2-repackaging-and-re-signing-detection-android-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0066: Implementing Storage Integrity Checks on Android](#mastg-best-0066-implementing-storage-integrity-checks-on-android)
  - [MASTG-BEST-0065: Implementing Storage Integrity Checks on iOS](#mastg-best-0065-implementing-storage-integrity-checks-on-ios)
  - [Beyond the OWASP samples: binding, rollback and response](#beyond-the-owasp-samples-binding-rollback-and-response)
  - [Package and resource checks that are worth shipping](#package-and-resource-checks-that-are-worth-shipping)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app verifies the integrity of its resources."* MASWE-0057 maps to two MASVS controls, and both mappings matter:

- **MASVS-RESILIENCE-2** ("The app implements anti-tampering mechanisms"): detecting a modified package or modified stored state, as one layer among several.
- **MASVS-CODE-4** ("The app validates and sanitizes all untrusted inputs"): treating data read back from local storage as untrusted input. This mapping is why the legacy L1/L2 test MASTG-TEST-0002 now points here (see [Tests](#tests)).

The CWE is [CWE-471](https://cwe.mitre.org/data/definitions/471.html), Modification of Assumed-Immutable Data (MAID): the app assumes something cannot change (its bundled assets, a preference it wrote itself) and an attacker changes it. The weakness carries OWASP's **R** and **EUDIW** profiles. OWASP describes the threat as MAS-THREAT-0057, *"Attackers can alter the app's behavior through its resources"*, reached through two attacks:

| Attack | OWASP description | What it looks like in practice |
|---|---|---|
| MAS-ATTACK-0070 | Modifying the app's files or resources on a compromised device | Root or jailbreak access to `/data/data/<package>/` or `/var/mobile/Containers/Data/Application/<UUID>/`; replacing an asset in the installed bundle; repackaging the app with edited assets or code and re-signing it |
| MAS-ATTACK-0009 | Tampering with backup contents and restoring the modified backup to a device | Editing an unencrypted local iOS backup or an Android backup archive and restoring it, which works without root or jailbreak where the platform still allows the backup path |

OWASP's MASWE text is about non-executable resources: files in the sandbox, configuration, downloaded content and restored data. It explicitly sends package integrity to [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) (app attestation) and running-code integrity to [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/). The Knowledge page it inherits from the v1 guide (MASTG-KNOW-0029), though, treats `classes.dex` and native library checks as part of the same topic. In practice testers and developers handle both together, so this note covers both and keeps the split clear:

| Question | Where it lives |
|---|---|
| Does the app detect that its stored data (preferences, files, databases, Keychain items) was modified? | This note |
| Does the app detect that its package (APK/IPA contents, signer, bundled assets) was modified or re-signed? | This note, for checks the app runs on itself; [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) for server-verified app attestation (Play Integrity `appIntegrity`, App Attest) |
| Does the app detect hooks, patched code in memory or injected libraries while it runs? | [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) |
| Does the app verify code or bundles it downloads (OTA JavaScript bundles, plug-ins, DEX)? | [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/) |
| Is the HMAC itself built correctly (algorithm, key, constant-time comparison, encrypt-then-MAC)? | [MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/) |
| Is a signature over downloaded data verified correctly? | [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/) |
| Is the MAC key stored outside the platform keystore, or hardcoded? | [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/), [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/) |
| Is restored or stored data parsed unsafely (deserialisation, SQL, path traversal)? | [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/) |
| Is the stored data confidential enough to need encryption? | [STORAGE guide](/mobile/masvs-storage-1-secure-storage-guide/), [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/) |

### Why a purely local check can always be bypassed

Every integrity check on the device has the same structure: read something, compute a value, compare it with a reference, act on the result. An attacker who controls the device controls all four steps. They can change the data *and* the reference (the expected hash is in the same package), use the key the app uses (a Keystore or Keychain key cannot be exported, but the app can still be made to compute a MAC with it), replace the comparison result with a Frida hook, or patch out the reaction. No arrangement of local code changes that. What changes is the **cost**: a check implemented in native code, duplicated in several places, tied to obfuscation and runtime integrity checks, and whose failure is reported to a server rather than shown in a dialog, costs hours or days instead of minutes.

Local checks still add value in four situations, and those define where you should recommend them:

1. **Attackers without code execution in the app.** Restoring an edited backup, a device-to-device transfer, another app writing to shared storage, a user editing a file with a root file manager. None of these can hook the verification, so an HMAC with a non-exportable key stops them completely.
2. **Distribution at scale.** A "mod" that is a single edited preference file or a re-signed APK with one asset swapped can be published and used by thousands of people. A signer check or asset hash forces the modder to also patch code, which is more work and breaks with every app update.
3. **Telemetry.** A failed check reported to the backend feeds fraud and risk scoring even when the local reaction is bypassed later.
4. **Forcing the attacker into the code.** An attacker who has to patch or hook code now has to defeat obfuscation ([MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/)), runtime integrity checks ([MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/)) and attestation ([MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)) as well.

What a local check can never do is make a local value authoritative. Entitlements, balances, lockout counters and roles that matter must be decided on the server, and the device should hold at most a signed, expiring copy.

## Modes of Introduction

OWASP lists four modes. We add the ones we see most often in assessments.

- **Sandbox files not verified** (OWASP). Security-relevant values in `SharedPreferences`, `UserDefaults`, SQLite, Realm or JSON files read back and trusted as is: `is_premium`, `role`, `pin_attempts`, `lock_until`, `biometric_enabled`, `server_url`, `pinning_enabled`, feature flags that turn off checks.
- **Downloaded resources not verified** (OWASP). Remote configuration, rule sets, HTML or JavaScript templates and certificate pin sets fetched over HTTPS and then cached on disk with no signature. TLS protects the transfer, not the cached copy.
- **Restored data not revalidated** (OWASP). Values that come back from Auto Backup, iCloud or local backups, or device-to-device transfer, used without checking whether they still make sense for this device and this account.
- **Verification result ignored** (OWASP). The check runs, logs a warning and the app carries on. A variant we see often: the verifier returns the default value on failure, and the default grants something (for example `getBoolean("biometric_required", false)`).
- **Integrity key that is not secret.** HMAC keys hardcoded in the app, derived from the package name or `ANDROID_ID`, or stored in the same preference file as the tag. Anyone who reads the app can compute valid tags. OWASP's Android demo has exactly this flaw.
- **Tag not bound to its context.** The HMAC covers the value but not the preference name, user ID or record ID, so a valid `(value, tag)` pair can be copied to a different key or a different user's record.
- **No rollback protection.** The MAC is correct, but an older valid copy of the file (a trial counter before it expired, an entitlement before it was revoked) can be restored.
- **Missing tag treated as "old format".** Code that accepts an unprotected value if the tag is missing, for backwards compatibility, lets the attacker simply delete the tag.
- **No package self-check, or a check that cannot work.** No signer check at all in an R-profile app; or a check pinned to the upload key while the app is distributed with Play App Signing, so the team disabled it after it fired in production; or a CRC read from the ZIP central directory, which the attacker's repackaging tool recomputes for free.

## Impact

- **Bypass of protection mechanisms** (OWASP). Changing a configuration or state file turns off a control without touching code: a PIN retry counter reset to zero allows unlimited guessing of a local PIN ([MASWE-0020](/mobile/maswe-0020-local-authentication-bypass/)), a cached `pinning_enabled=false` disables certificate pinning, a flipped `root_check_passed` skips root detection.
- **Execution of unauthorised code** (OWASP). In hybrid apps, assets *are* code: React Native's `index.android.bundle` / `main.jsbundle`, Cordova and Capacitor `www/` folders, HTML templates loaded into a WebView, Lua scripts in games. Changing them changes the app's behaviour as surely as patching bytecode.
- **Business abuse.** Unlocked paid features, reset trials, inflated game currency or reward points, bypassed regional restrictions. The impact depends entirely on whether the server re-checks the value.
- **Distribution of modified apps.** A repackaged build with ads, credential theft or pinning removed, distributed outside the stores. The original publisher's name is on it.

## Mitigations

- **Verify security-relevant stored data before use** (OWASP): an HMAC with a key generated in the Android Keystore or kept in the Keychain with a `ThisDeviceOnly` accessibility class, compared in constant time, bound to the key name and owner, and checked before the value is used.
- **Authenticate downloaded content** (OWASP): a signature made on the server with a private key the app never sees, verified against a public key in the app, before the content is cached and again before it is used. A MAC is the wrong tool here (see [MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/)).
- **Treat restored data as untrusted** (OWASP): data restored to a new device will not verify (the Keystore or `ThisDeviceOnly` key did not travel with it), and the app must handle that by re-fetching from the server rather than crashing or falling back to permissive defaults.
- **Respond to failed checks** (OWASP): discard and re-fetch, restrict functionality, and report to the backend. Never continue with the tampered value.
- **Keep authoritative state on the server**, and give the device signed, expiring copies so a rollback only works until the copy expires.
- **Check the package from inside the app where the threat model justifies it**: signer certificate digest, hashes of critical assets and scripts, and on iOS the obvious signs of a re-signed build. Report the result to the server, and prefer server-verified app attestation ([MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)) for any decision that matters.

## Knowledge

OWASP does not link Knowledge pages from the weakness itself. Three are directly relevant: the Android "File Integrity Checks" page (MASTG-KNOW-0029), the Android "Shared Preferences" page from the STORAGE category (MASTG-KNOW-0036, which test 0338 cites), and the iOS "Storage Integrity Checks" page (MASTG-KNOW-0086). The generic "Binary Patching" page (MASTG-KNOW-0109) explains the attacker's side and gets a summary. The OWASP pages are short and some of their sample code is broken, so the sections below go well beyond them and point out what needs correcting.

### Android: File Integrity Checks (MASTG-KNOW-0029)

Source: [MASTG-KNOW-0029](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0029/).

OWASP splits the topic in two: **code integrity checks**, where the app checks its own bytecode, native libraries and important bundled files, and **file storage integrity checks**, where it protects files and `SharedPreferences` entries it writes. Both are below, followed by what is wrong with OWASP's sample code.

#### What the platform already guarantees: the APK signature

Every APK is signed, and Android checks the signature when the package is installed or updated. In brief (our [MASTG-KNOW-0003 note](/mobile/mastg-know-0003-app-signing/) has the full treatment):

- **v1 (JAR signing)** signs individual ZIP entries through `META-INF/MANIFEST.MF` and the `.SF`/`.RSA` files. It does not protect the ZIP metadata, which made attacks like Janus (CVE-2017-13156) possible on devices that only checked v1.
- **v2 (Android 7.0+)** and **v3 (Android 9+, adds key rotation through a proof-of-rotation lineage)** sign the whole file apart from the signing block, so any changed byte invalidates the signature. **v4 (Android 11+)** is a separate `.idsig` file used for incremental installation, backed by fs-verity, and always comes with a v2 or v3 signature.
- The signer is pinned for updates: an update must be signed by the same key, or by a key the v3 lineage authorises. A repackaged APK therefore cannot be installed over the original. The attacker has to get the user to uninstall first, or ship it under a different package name.

What the signature does **not** do:

- It is checked at install and update time. Android does not re-hash the APK every time the app starts, so on a rooted device a file changed in `/data/app/<...>/` after installation, or a bind mount over it, is not caught by the platform.
- It says nothing about *who* signed it. A repackaged APK signed with the attacker's key is perfectly valid. Only a check that compares the signer with the expected certificate (in the app, or better on the server through Play Integrity) tells the two apart.
- It does not cover anything outside the package: files in the sandbox, downloaded content, data restored from backup.

#### Checking the package from inside the app

Three kinds of self-check are common. You will meet them in jadx output and should know how each fails.

**Signer certificate check.** The app reads its own signing certificate at runtime and compares a SHA-256 digest with a constant. Since Android 9 (API 28) the correct API is `GET_SIGNING_CERTIFICATES` with `SigningInfo`:

```kotlin
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.annotation.RequiresApi
import java.security.MessageDigest

@RequiresApi(Build.VERSION_CODES.P)
fun signerDigests(ctx: Context): Set<String> {
    val pm = ctx.packageManager
    val info = if (Build.VERSION.SDK_INT >= 33)
        pm.getPackageInfo(ctx.packageName,
            PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()))
    else
        pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
    val si = info.signingInfo ?: return emptySet()
    // Single signer: use the lineage (original first, current last). Multiple signers: all must match.
    val certs = if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
    return certs.map { cert ->
        MessageDigest.getInstance("SHA-256").digest(cert.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }.toSet()
}
```

On API 28+ there is also a one-call form, `pm.hasSigningCertificate(packageName, sha256Bytes, PackageManager.CERT_INPUT_SHA256)`, which searches the package's verified signing history. The older `GET_SIGNATURES` flag is deprecated since API 28: with multiple signers it returns the certificates in no defined order, and it does not understand v3 rotation. Android's `SigningInfo` reference says to prefer `getSigningCertificateHistory()` unless `hasMultipleSigners()` is true, and to check every entry when there are multiple signers.

Two pitfalls make this check fail in production, and teams then disable it:

- **Play App Signing.** Apps on Google Play are re-signed by Google with the *app signing key*. The developer's *upload key* never reaches users. The expected digest must be the app signing key's SHA-256 from the Play Console (App integrity page), not the upload key's.
- **Key rotation.** After a v3 rotation the current signer changes. A check that only knows the old digest breaks, and one that compares only against `apkContentsSigners[0]` misses the lineage.

From the attacker's point of view this is the cheapest check to defeat: one boolean method in Java, found by searching jadx output for `GET_SIGNING_CERTIFICATES`, `signingInfo` or `hasSigningCertificate`, and forced to return `true` with Frida or a one-line smali patch. Moving it into native code, inlining it in several places and reporting the digest to the server (rather than comparing it locally) raises the cost. Server-verified attestation removes the local decision altogether ([MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)).

**Hashes of package contents.** The app opens its own APK (`ApplicationInfo.sourceDir`, or `Context.getPackageCodePath()`, which is `base.apk`; split APKs are listed in `ApplicationInfo.splitSourceDirs`) and hashes selected entries: `classes*.dex`, `lib/<abi>/*.so`, `AndroidManifest.xml`, `resources.arsc`, or assets such as a JavaScript bundle. The design questions:

- **Where is the reference value?** Not in the file being hashed, because changing it changes the hash. Assets and scripts can be hashed with reference values compiled into the DEX or a native library, which is sound for them. Self-hashing of DEX code needs the reference somewhere else (a native library, the server), and a repackager who changes both is back to square one. This is why OWASP and Google both point towards server-side verification.
- **What exactly is hashed?** OWASP's sample reads `ZipEntry.getCrc()`. That is the CRC-32 stored in the ZIP central directory, a non-cryptographic checksum that every repackaging tool recomputes automatically when it rebuilds the archive. It detects nothing an attacker does deliberately. Hash the entry's bytes with SHA-256 instead.
- **App bundles.** Apps installed from an Android App Bundle arrive as a base APK plus configuration splits (ABI, density, language), and the set differs per device. A check that expects one APK with every library in it fails on real devices. Hash per split, or hash only entries whose location you know.

**Native and obfuscated variants.** Commercial protectors and in-house RASP move these checks into native code, encrypt the reference values, and spread checks around the app. The tests in this note do not change: find the checks, trace them, and record how much effort it takes to neutralise them on your own test device.

#### Storage integrity with HMAC

For data the app writes, OWASP describes two options: an HMAC over each key-value pair (for `SharedPreferences`) or over a whole file, and a digital signature over the data. The recommended construction today:

- A key generated **inside** the Android Keystore with `KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")` and `PURPOSE_SIGN` (API 23+). The key material never enters app memory, so it cannot be read from the APK, a backup or a memory dump. `getEncoded()` returns `null`.
- `javax.crypto.Mac.getInstance("HmacSHA256")` initialised with that key, over a canonical encoding of **context and value** (file or preference name, user ID, a version counter, then the value).
- Verification with `MessageDigest.isEqual` (constant-time), after checking the tag length.
- A clear reaction to failure: discard the value, re-fetch from the server, report.

The alternative is `java.security.Signature` with an EC key pair in the Keystore. It gives the same local guarantee as an HMAC, because the private key is in the same place as the HMAC key would be. Signatures earn their place when someone else verifies, for example when the server checks data the device signed, or the device checks data the server signed.

Two limits of the Keystore apply to every Android storage-integrity scheme:

- **Non-exportable is not unusable.** A root attacker cannot extract a hardware-backed key, but can run code inside the app's process (Frida) and ask the Keystore to compute a valid MAC over forged data. The key protects against offline forgery, backup and restore, and copying data to another device. It does not protect against an attacker who instruments the app.
- **Keys do not travel.** Keystore keys are not included in backups or device-to-device transfers. Data restored onto a new device carries tags made with a key that no longer exists. The app must treat that as "unverifiable, re-fetch" rather than "tampered, wipe everything" or "no key, skip the check".

#### How attackers defeat these checks, in general terms

- **Edit data and reference together.** If the reference hash or HMAC key lives in the app, the attacker recomputes it. OWASP's own Android demo shows this with one line of Python against its hardcoded key.
- **Neutralise the comparison.** Hook the app's verify method, or the `MessageDigest.isEqual` / `contentEquals` call it uses, and force the "valid" result. One hook, if the check sits in one place.
- **Neutralise the reaction.** Leave the check alone and patch what happens on failure: the dialog, the `finish()`, the network report.
- **Use the key as an oracle.** With code execution in the app, call the app's own `saveProtected()`-style method with forged data, so the app writes a correctly tagged forgery itself.
- **Redirect file reads.** The legacy OWASP test mentions hooking file system APIs so the check reads the original APK while the modified code runs. Root frameworks that overlay files at mount level have the same effect.

#### Problems in the OWASP sample code

KNOW-0029's samples come from the v1 guide and should not be copied:

- The CRC sample compares `ZipEntry.getCrc()` with a value from `R.string`. Both live in the same APK and both are rewritten by any repackaging, and CRC-32 is not a security primitive.
- The `HMACWrapper` class does not compile. `SecretKey.newKey()` and `key.getKey()` are not JCA methods, and `createHMAC` has no return value on the exception path. It also forces the Bouncy Castle provider (`Mac.getInstance(..., "BC")` and `Security.addProvider(new BouncyCastleProvider())`). Android 9 deprecated requesting algorithms from the platform's `BC` provider where Conscrypt also implements them, and the Android 9 behaviour changes say that apps targeting API 28+ get `NoSuchAlgorithmException` for the affected algorithms. SpongyCastle, which the page also mentions, is no longer maintained. Use the default provider and a Keystore key.
- Its link for "use a bouncy castle implementation or the AndroidKeyStore" points to the Bellare–Namprempre paper on authenticated encryption composition, not to anything about either option.
- Its constant-time comparison loop is correct and worth keeping. In practice `MessageDigest.isEqual` does the same job.
- The page speaks of files "on the SD card or public storage". Since Android 11, other apps cannot read or write an app's `Android/data/<package>/` directory, but files in shared collections (Downloads, Documents, media) can be changed by any app with the right access. Data there is not only a resilience issue: it is reachable by other apps without root, and loading code or configuration from it is a [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/) or [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/) finding in its own right.

### Android: Shared Preferences (MASTG-KNOW-0036)

Source: [MASTG-KNOW-0036](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0036/) (in OWASP's STORAGE category; test 0338 cites it for the storage mechanism). Confidentiality of preference data is covered in the [STORAGE guide](/mobile/masvs-storage-1-secure-storage-guide/). Here we care about integrity.

**Where the data lives.** `getSharedPreferences("app_settings", Context.MODE_PRIVATE)` writes an XML file at `/data/data/<package>/shared_prefs/app_settings.xml` (the same directory is reachable as `/data/user/0/<package>/`; secondary users and work profiles use `/data/user/<userId>/`). `PreferenceManager.getDefaultSharedPreferences()` uses `<package>_preferences.xml`. The format is plain text:

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="user_role">user</string>
    <boolean name="is_premium" value="false" />
    <int name="pin_attempts" value="2" />
</map>
```

Neighbouring stores you will meet: Jetpack DataStore (`files/datastore/<name>.preferences_pb`, a protocol buffer, harder to edit by hand but no more protected), SQLite (`databases/<name>.db` with `-wal` and `-shm` files in WAL mode), Room (SQLite underneath), and arbitrary files under `files/` and `cache/`.

**Who can modify it.** With `MODE_PRIVATE` the file belongs to the app's Linux UID and other apps cannot touch it under the normal sandbox. `MODE_WORLD_READABLE` and `MODE_WORLD_WRITEABLE` were deprecated in API 17 and throw `SecurityException` since Android 7.0 (API 24). The realistic writers are:

- **root** on a rooted device or an emulator image, which can edit the file directly;
- **the app itself under instrumentation**, for example Frida calling the app's editor;
- **backup and restore.** `run-as` works only for debuggable builds. `adb backup` is deprecated, and for apps targeting Android 12 (API 31) or higher it no longer includes app data unless the app is debuggable. Auto Backup to the cloud and device-to-device transfer still restore `shared_prefs/` by default unless excluded. For apps running on and targeting Android 12 (API 31) or higher, the old include/exclude rules no longer apply to device-to-device transfer, `android:dataExtractionRules` controls cloud backup and D2D separately, and Android notes that on some manufacturers' devices `android:allowBackup="false"` does not disable D2D transfer.

**Why "private" does not mean "trustworthy".** `MODE_PRIVATE` protects against other apps, not against the device owner. An app whose threat model includes the user (games, paid content, fraud-sensitive finance) must not treat its own preferences as tamper-proof.

**EncryptedSharedPreferences.** The Jetpack Security wrapper encrypts names with AES-256-SIV and values with AES-256-GCM, both AEAD schemes, so a modified ciphertext fails to decrypt. That gives integrity against editing, but not against **rollback** (restoring an older valid ciphertext) or **deletion** (removing an entry so the app falls back to its default). The whole Jetpack Security Crypto library is deprecated: all APIs were deprecated in 1.1.0, and Android says no further releases are planned. Existing use is not a finding. Do not recommend it for new code. OWASP's page also notes, correctly, that encrypted preference files should be excluded from backup, because the Keystore master key does not move with them.

### iOS: Storage Integrity Checks (MASTG-KNOW-0086)

Source: [MASTG-KNOW-0086](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0086/). The page covers stored data. The package side (code signature, resource seal) is not on any OWASP iOS page for this weakness, so we add it here: you need it for the repackaging test, and the Apple facts are often misquoted.

#### Where iOS apps keep state

| Store | Location (data container is `/var/mobile/Containers/Data/Application/<UUID>/`) | Format |
|---|---|---|
| `UserDefaults` / `NSUserDefaults` | `Library/Preferences/<bundle-id>.plist` | Binary plist, cached by the `cfprefsd` daemon |
| App group defaults and files | `/var/mobile/Containers/Shared/AppGroup/<UUID>/` | Shared with the app's extensions and other apps in the same group |
| Files | `Documents/`, `Library/Application Support/`, `Library/Caches/`, `tmp/` | Anything |
| Core Data, SQLite, Realm | Usually `Library/Application Support/` or `Documents/` | SQLite / Realm files |
| Keychain | System database outside the container, accessed through `SecItem*` | Items protected by data protection classes |

`Documents/` and `Library/` (except `Caches`) are included in iCloud and local backups unless a file is marked with `isExcludedFromBackup`. Keychain items with a `…ThisDeviceOnly` accessibility class are not restored to a different device.

#### HMAC and signatures over stored data

OWASP's page shows `CCHmac` from CommonCrypto with a key from the Keychain: compute an HMAC-SHA256 over the data, append the 32-byte tag, and on read split it off, recompute and compare. It also mentions `SecKeyCreateSignature` / `SecKeyVerifySignature` for asymmetric signing, encrypt-then-MAC when the data is also encrypted, and that a jailbroken attacker can extract the Keychain key or hook the verifier.

What to add:

- **Use CryptoKit where you can** (iOS 13+): `HMAC<SHA256>.authenticationCode(for:using:)` to create and `HMAC<SHA256>.isValidAuthenticationCode(_:authenticating:using:)` to verify. The verify call takes raw bytes read from disk and compares in constant time. OWASP's CommonCrypto sample ends with `[hmac isEqual: digestBuffer]`, which is not constant-time. For a local file this is low-impact, but it is the snippet developers copy into network code (see [MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/)). With CommonCrypto, compare with `timingsafe_bcmp`.
- **The key.** A `SymmetricKey` of 256 bits from `SymmetricKey(size: .bits256)`, stored as a generic password item with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (or `AfterFirstUnlockThisDeviceOnly` if background tasks need it). `ThisDeviceOnly` stops the key from travelling in backups. Data restored to another device then fails verification, and the app must handle that gracefully.
- **Secure Enclave.** The Secure Enclave does not compute HMACs for apps, but it can create and use P-256 signing keys (`SecureEnclave.P256.Signing.PrivateKey` in CryptoKit, or `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`). Signing stored data with such a key means the private key cannot be extracted even on a jailbroken device. As on Android, the attacker can still make the app sign forged data from inside its own process. The gain is against offline forgery and backup tampering, not against instrumentation.
- **What a jailbroken attacker can do.** Read and write every file in the container. Read Keychain items through the app's own access groups (objection's `ios keychain dump` runs inside the app and does exactly that). Hook `isValidAuthenticationCode`, `CCHmac` or the app's wrapper. So OWASP's warning stands: defence in depth.

#### What the platform guarantees for the bundle

- **Code signature.** Every Mach-O in the bundle carries an embedded signature (`LC_CODE_SIGNATURE`) whose CodeDirectory holds a hash per code page plus "special slots" for the `Info.plist`, the entitlements and the **resource seal**. The resource seal is `_CodeSignature/CodeResources`, a plist with a SHA-1 (`files`) and SHA-256 (`files2`, key `hash2`) hash for every non-code file in the bundle. Changing an image, a JSON file or `main.jsbundle` breaks the seal, which breaks the signature of the main executable.
- **When it is enforced.** The kernel checks code pages against the CodeDirectory as they are loaded, so modified executable code does not run on a stock device. The full signature, including the resource seal, is checked when the app is installed. Apple does not document any re-validation of non-code resources each time the app reads them, and in our testing a resource modified in an installed bundle on a jailbroken device is not noticed by iOS.
- **Jailbreaks.** Depending on the jailbreak, code-signing enforcement is relaxed or bypassed for chosen binaries (fake-signing, trust-cache injection), so modified executables can run too. Treat any jailbroken device as one where the platform guarantees above do not hold.
- **FairPlay encryption.** App Store binaries are encrypted (`LC_ENCRYPTION_INFO_64` with `cryptid 1`). To patch code, an attacker first needs a decrypted copy, typically dumped from memory on a jailbroken device. Resources are not encrypted.
- **No self-verification API.** The Code Signing Services functions that verify a running or on-disk signature (`SecCodeCheckValidity`, `SecStaticCodeCheckValidity` and friends) are available on macOS and Mac Catalyst only. Apple's documentation lists no iOS availability. An iOS app cannot ask the system "is my signature still valid and is it mine?".

Because of that last point, iOS repackaging detection is a set of heuristics, each bypassable:

- **`embedded.mobileprovision` present.** Development, ad hoc and enterprise builds contain a provisioning profile in the bundle. In our experience App Store installs do not, so a profile in a supposed App Store build suggests re-signing.
- **Team ID or app ID prefix.** The access group of a Keychain item the app creates starts with the app ID prefix (normally the Team ID). A re-signed app gets the re-signer's prefix. Reading `kSecAttrAccessGroup` back from a test item is a common, public-API way to see it.
- **Bundle identifier.** Free developer accounts force a different bundle ID when re-signing.
- **`cryptid 0` on an App Store build.** The app parses its own Mach-O load commands in memory. A decrypted, re-signed binary reports `cryptid 0`. This overlaps with runtime integrity ([MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/)).
- **Hashes of critical resources.** SHA-256 of `main.jsbundle`, configuration files or HTML templates, with reference values compiled into the executable. This is sound for resources, because the executable is signed separately.

The server-verified alternative is App Attest, which binds a key to the genuine app from the App Store and lets the server verify requests. See [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/).

### Generic: Binary Patching (MASTG-KNOW-0109)

Source: [MASTG-KNOW-0109](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0109/) (summary). Patching means changing the compiled app: bytecode, native code or resources, edited in place with a hex editor or decompiled, changed and rebuilt (in game hacking this is "modding"). Both mobile platforms enforce code signing, so a patched app has to be re-signed (with the attacker's own key on Android, or a development certificate on iOS) or run on a device where signature enforcement is disabled. On your own test device that is routine. That is why integrity checks matter: re-signing is cheap, and a resource-only change (a swapped config file or JavaScript bundle) needs no reverse-engineering skill at all. For this weakness, what matters about patching is that the attacker can change **both** the data and any check that lives next to it. The integrity checks in this note are only worth what it costs to find and remove them. Runtime patching (hooks, memory patches) is covered in [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/).

## Tests

OWASP assigns two current tests to MASWE-0057, one per platform. Both are static searches for integrity APIs (HMAC, signatures, hashes) followed by manual review of whether stored data that feeds a security decision is verified. They replace three legacy v1 tests:

- [MASTG-TEST-0047](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0047/) (Android, "Testing File Integrity Checks", R profile), `covered_by` 0338;
- [MASTG-TEST-0090](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0090/) (iOS, "Testing File Integrity Checks", R profile), `covered_by` 0387;
- [MASTG-TEST-0002](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0002/) (Android, "Testing Local Storage for Input Validation", L1/L2, MASVS-CODE-4), `covered_by` 0338.

The third needs a word of explanation. Test 0002 came from the v1 platform-interaction chapter. It said that any process can overwrite publicly accessible storage (and, on a rooted device, private storage), that data must therefore be validated when it is read back, and that an HMAC over `SharedPreferences` content helps. Test 0338 keeps that core idea, "do not trust security-relevant values read from local storage without verifying them", which is why OWASP maps MASWE-0057 to MASVS-CODE-4 as well. Two parts of 0002 do **not** carry over. Its injection angle (how a stored `String` is interpreted, reflection-based object persistence, a Bouncy Castle key-loading flaw it cites as CVE-2018-1000613) now belongs to [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/). And its claim that `int` and `boolean` preferences "can hardly be used for actual attacks" is wrong for this weakness: `is_premium=true` and `pin_attempts=0` are exactly the values that matter.

The legacy tests 0047 and 0090 were dynamic: patch and re-sign the app, or edit stored files, and see whether the app notices, then judge how hard the defences are to bypass. The v2 tests dropped that part. Static API references cannot tell you whether a check works, or whether the app checks its own package at all. Our two Guler Tech tests restore it in a form that stays within authorised testing on your own device.

Run the static tests first. Their output tells you which storage paths and checks to target in the dynamic tests.

### MASTG-TEST-0338: References to Storage Integrity Check APIs (Android)

*OWASP test: [MASTG-TEST-0338](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0338/). Type: static, code, manual. Front matter: `false_negative_prone: true`, APIs `javax.crypto.Mac`, `java.security.Signature`, `java.security.MessageDigest`, best practice MASTG-BEST-0066.*

#### Overview

The test asks whether the app uses data read from local storage (`SharedPreferences`, files, databases) in a security-relevant decision without first verifying its integrity and authenticity. It finds candidate code by searching decompiled code for integrity primitives (`Mac` for HMAC, `Signature` for asymmetric signatures, `MessageDigest` for hashes) and for storage reads, and then asks you to review each location by hand.

OWASP's attack scenario: an app keeps a trial counter or premium flag in `SharedPreferences`. On a rooted device the attacker finds the data directory (OWASP technique [MASTG-TECH-0008](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0008/), e.g. objection's `env` command), edits the value, and the app loads it as genuine because nothing verifies an HMAC or signature.

The test is *false-negative prone* by design: integrity checks in a third-party SDK, in native code, in a custom implementation, or behind an obfuscated wrapper will not match a search for `javax.crypto.Mac`. "No hits" never means "no check". It is also noisy the other way, because `MessageDigest` and `Mac` are used for request signing, analytics IDs, cache keys and certificate pinning.

#### Prerequisites

- The APK and any split APKs (`adb shell pm path <package>`, then `adb pull` each path).
- [jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/) to decompile ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), Reverse Engineering Android Apps) and [semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) or `grep` to search ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), Static Analysis on Android).
- For native checks: `readelf` / `nm -D` and Ghidra or radare2 on `lib/<abi>/*.so`.
- Knowledge of the app's business logic: which stored values could change a security decision.

#### Steps

1. Decompile everything, including splits:

   ```bash
   jadx -d out/ --deobf base.apk
   ```

2. Find the integrity primitives and package self-checks:

   ```bash
   grep -rnE 'Mac\.getInstance|Signature\.getInstance|MessageDigest\.(getInstance|isEqual)|\.verify\(|KEY_ALGORITHM_HMAC|"HmacSHA(256|384|512)"' out/sources/ > integrity.txt
   grep -rnE 'GET_SIGNING_CERTIFICATES|GET_SIGNATURES|signingInfo|hasSigningCertificate|getSigningCertificateHistory|getApkContentsSigners|getPackageCodePath|sourceDir|ZipFile|getCrc\(' out/sources/ > package-checks.txt
   ```

3. Find the storage reads:

   ```bash
   grep -rnE 'getSharedPreferences|getDefaultSharedPreferences|\.get(String|Boolean|Int|Long|Float|StringSet)\(|DataStore|openFileInput|FileInputStream|rawQuery|\.query\(|RoomDatabase' out/sources/ > storage.txt
   ```

   Or use one semgrep rule file for both lists. OWASP's own rule (`mastg-android-local-storage-input-validation.yml`) only matches inside methods literally named `loadPlain` and `loadProtected`. It is written for the demo and finds nothing in a real app. A generic version:

   ```yaml
   rules:
     - id: gt-android-local-storage-read
       languages: [java]
       severity: INFO
       message: Local storage read. Does the value feed a security decision, and is it verified first?
       pattern-either:
         - pattern: (android.content.SharedPreferences $P).$GET(...)
         - pattern: new java.io.FileInputStream(...)
         - pattern: (android.database.sqlite.SQLiteDatabase $DB).rawQuery(...)
         - pattern: (android.database.sqlite.SQLiteDatabase $DB).query(...)
     - id: gt-android-integrity-primitive
       languages: [java]
       severity: INFO
       message: Integrity primitive. Map it to the storage path or package check it protects.
       pattern-either:
         - pattern: javax.crypto.Mac.getInstance(...)
         - pattern: java.security.Signature.getInstance(...)
         - pattern: java.security.MessageDigest.getInstance(...)
         - pattern: java.security.MessageDigest.isEqual(...)
   ```

   ```bash
   semgrep --config gt-integrity.yml out/sources/ --text
   ```

   Typed metavariables such as `(android.content.SharedPreferences $P)` only match where jadx output gives semgrep the declared type. Keep the `grep` lists as a backstop.

4. For native code, check imports and strings in every library:

   ```bash
   for f in out/resources/lib/*/*.so; do
     echo "== $f"
     nm -D --undefined-only "$f" | grep -iE 'sha256|hmac|EVP_|crc32|AAsset|open$|fopen'
   done
   ```

5. Build a table: for each security-relevant stored value (role, entitlement, counter, flag, URL, pin set), where it is read, where it is used, and whether an integrity check sits between the two. Open each location in jadx ([MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), Reviewing Decompiled Java Code) and follow the value from read to use.

6. For each check you find, answer the three questions OWASP lists: can the value influence a security decision; does the app compute and verify an HMAC or signature over exactly what it reads back, and react when verification fails; and is the verification effective for the attacker model (where does the key come from, what happens when the tag is missing, is the tag bound to the key name).

#### Observation

The list of storage reads and integrity primitives with file and line, and, for each security-relevant value, the read-to-use path you traced, with the integrity check (or its absence) marked. Note the key source for every `Mac.init` call (`SecretKeySpec` with constant bytes, a Keystore key, a derived key) and the comparison used (`MessageDigest.isEqual`, `Arrays.equals`, `contentEquals`, `String.equals` on hex).

#### Evaluation

The test **fails** if a value loaded from `SharedPreferences`, a file or a database is used in a security-relevant decision (authentication state, authorisation, feature or content access, security configuration, trust decisions) without verifying its integrity and authenticity first.

Also record as failing, because the check is not effective for the attacker model:

- the HMAC key is a constant in the app or derived from public values (also a [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) finding);
- a missing tag is accepted;
- the verifier's failure path returns a default that grants access, or only logs.

Note, without failing the test on these alone: tags not bound to the key name or user (value swapping), no rollback protection, non-constant-time comparison (a [MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/) observation, low impact for local data).

The test **passes** for a value if it is verified with a key the attacker cannot read offline before every use, and failure leads to discarding the value. It is **not applicable** when no stored value feeds a security decision. Say so explicitly in the report, with the list of values you reviewed.

Because the test is false-negative prone, a "pass" based only on the absence of hits is not a pass. Confirm with GT-RES-0057-1.

#### Demo

OWASP's [MASTG-DEMO-0101](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0101/MASTG-DEMO-0101/) stores a role twice in `app_settings.xml`: once plain and once with an HMAC-SHA256 tag in a companion `<key>_hmac` entry. Condensed:

```kotlin
private fun loadPlain(key: String, default: String): String =
    prefs().getString(key, default) ?: default                 // trusted as is: FAIL

private fun loadProtected(key: String, default: String): String {
    val value = prefs().getString(key, null) ?: return default
    val stored = prefs().getString("${key}_hmac", null) ?: return default
    return if (stored == calculateHmac(value)) value else default  // verified before use
}

private fun calculateHmac(data: String): String {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(SECRET_KEY.toByteArray(), "HmacSHA256"))  // SECRET_KEY is a constant
    return bytesToHex(mac.doFinal(data.toByteArray()))
}
```

OWASP's semgrep output (abridged) flags the reads and the HMAC code:

```text
❯❱ mastg-android-local-storage-input-validation
      140┆ String string = prefs().getString(key, defaultValue);
      146┆ String value = prefs().getString(key, null);
      147┆ if (value == null || (storedHmac = prefs().getString(key + "_hmac", null)) == null) {
 ❱ mastg-android-hmac-validation-present
      156┆ Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      159┆ SecretKeySpec key = new SecretKeySpec(bytes, HMAC_ALGORITHM);
      160┆ mac.init(key);
      163┆ byte[] bArrDoFinal = mac.doFinal(bytes2);
```

Editing the file as root (`sed -i 's#>user</#>admin</#g'` on `shared_prefs/app_settings.xml`, after `am force-stop`) makes the plain path report "Insecure check bypassed", while the protected path returns `tampering_detected`. The demo then shows why the protected path still fails in practice: the key is the string constant `this-is-a-very-secret-key-for-the-demo`, so `python3 -c 'import hmac,hashlib; print(hmac.new(b"this-is-a-very-secret-key-for-the-demo", b"admin", hashlib.sha256).hexdigest())'` produces a valid tag for `admin`, and the "secure" check accepts the forgery. Three more flaws are worth spotting as practice: the tag covers only the value, so the `(value, tag)` pair of any other protected key can be copied over; `calculateHmac` returns an empty string on error, so an empty stored tag would match if key setup ever failed; and the tags are compared as hex strings with Kotlin `==`. (OWASP's demo text describes a `loadData(..., useHmac)` method, but the sample code uses `loadPlain` and `loadProtected`.)

### MASTG-TEST-0387: References to Storage Integrity Check APIs (iOS)

*OWASP test: [MASTG-TEST-0387](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0387/). Type: static, code, manual. Front matter: `false_negative_prone: true`, APIs `HMAC`, `CCHmac`, `CCHmacFinal`, `CC_SHA256`, `CC_SHA512`, `SecKeyCreateSignature`, best practice MASTG-BEST-0065.*

#### Overview

The iOS twin of 0338: does the app use data from files in the container, `UserDefaults` or a database in a security-relevant decision without verifying an HMAC or signature first? The search targets CryptoKit's `HMAC`, CommonCrypto's `CCHmac` family and hash functions, and `SecKeyCreateSignature`, alongside storage APIs such as `Data(contentsOf:)`, `Data.write(to:)` and `UserDefaults` reads. OWASP's attack scenario mirrors the Android one: a jailbroken attacker finds the data directory ([MASTG-TECH-0059](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0059/), for example objection's `env`), flips a premium flag or resets a counter in `UserDefaults`, and the app accepts it.

Swift makes the static part harder than on Android. CryptoKit's generic `HMAC<SHA256>` calls often appear as long mangled imports, and small functions get inlined. Reading a value in a function that does not call any integrity API proves nothing until you have followed the value to where it is used.

#### Prerequisites

- A decrypted IPA. FairPlay encryption hides code from static tools, so ask the client for a development or ad hoc build of the same version, or use a decrypted copy obtained under the engagement's rules.
- [radare2](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/) (OWASP's choice), plus `otool`, `nm` and Ghidra or Hopper for following call paths.
- OWASP techniques [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/) (Exploring the App Package), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/) (Static Analysis on iOS) and [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/) (Reviewing Disassembled Objective-C and Swift Code).

#### Steps

1. Unpack and list every Mach-O, because checks can live in frameworks:

   ```bash
   unzip -q App.ipa -d ipa/
   APP=ipa/Payload/App.app
   find "$APP" -type f -exec sh -c 'file "$1" | grep -q Mach-O && echo "$1"' _ {} \;
   ```

2. Search imports for storage and integrity APIs (OWASP's radare2 approach):

   ```bash
   r2 -q -e bin.relocs.apply=true -c 'ii~Data.write,Data.contentsOf,UserDefaults' "$APP/App"
   r2 -q -e bin.relocs.apply=true -c 'ii~HMAC,CCHmac,CC_SHA,SecKeyCreateSignature,SecKeyVerifySignature,timingsafe_bcmp' "$APP/App"
   ```

   A quicker first pass with `nm`, demangling Swift symbols:

   ```bash
   nm -u "$APP/App" | xcrun swift-demangle | grep -iE 'HMAC|CCHmac|CC_SHA|SecKey(Create|Verify)Signature|timingsafe_bcmp|UserDefaults|contentsOf'
   ```

3. Look for package self-checks at the same time: strings such as `embedded.mobileprovision`, `_CodeSignature`, `CodeResources`, `cryptid`, and Keychain access-group reads:

   ```bash
   strings -a "$APP/App" | grep -E 'embedded\.mobileprovision|_CodeSignature|CodeResources|kSecAttrAccessGroup|main\.jsbundle'
   ```

4. Find the call sites of each storage API (`axt @ <import address>` in r2) and disassemble each caller. For each security-relevant value, check whether an HMAC or signature computation sits on the write path and a verification on the read path.

5. Answer OWASP's three questions for each path, as for Android: does the value influence a security decision; is it verified before use with a reaction on failure; is the check effective (key from the Keychain with a `ThisDeviceOnly` class, missing tag rejected, tag bound to its context).

#### Observation

The imports for storage and integrity APIs, the callers of each storage API, and for each security-relevant stored value the path from read to use, with the integrity check (or its absence) marked. Note where HMAC keys come from (Keychain query, constant bytes, `SymmetricKey(size:)` regenerated per launch) and how tags are compared.

#### Evaluation

The test **fails** if a value loaded from files, `UserDefaults` or a database is used in a security-relevant decision without verifying its integrity and authenticity first. Treat a hardcoded HMAC key or a check that accepts a missing tag as "no effective check", as on Android. Integrity APIs being present in the binary is not a pass: you have to show that the specific storage path is protected. The test **passes** for a value that is verified before each use with a key that cannot be read offline, with the value discarded on failure. As with 0338, absence of hits is not proof. Confirm with GT-RES-0057-1.

#### Demo

OWASP's [MASTG-DEMO-0150](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0150/MASTG-DEMO-0150/) has two flows in one binary: `user_profile.json` written to `Documents/` and read back with no integrity value (fail), and `user_profile_protected.json` stored with an appended HMAC-SHA256 tag and verified on read (pass). The protected flow, condensed:

```swift
let mac = HMAC<SHA256>.authenticationCode(for: data, using: key)
try (data + Data(mac)).write(to: fileURL)

let stored = try Data(contentsOf: fileURL)
let payload = stored.prefix(stored.count - 32)
let tag = stored.suffix(32)
let valid = HMAC<SHA256>.isValidAuthenticationCode(Data(tag), authenticating: Data(payload), using: key)
```

OWASP's radare2 output (abridged, symbol names shortened) shows the imports and the two callers of `Data.write(to:)`. Only one of them also calls HMAC functions:

```text
=== Storage APIs ===
0x100009724  sym.imp.Foundation.Data.contentsOf.options.URL...
0x100009754  sym.imp.Foundation.Data.write.to.options.URL...
=== Integrity APIs ===
0x1000099f4  sym.imp.CryptoKit.HMAC.authenticationCode.for.using...
0x100009a00  sym.imp.CryptoKit.HMAC.isValidAuthenticationCode.authenticating.using...
=== Flow A (fcn.1000050f8): write + read, no HMAC ===
0x100005394  bl sym.imp.Foundation.Data.write.to...
0x1000054ac  bl sym.imp.Foundation.Data.contentsOf...
=== Flow B (fcn.1000045bc): HMAC, write, read, verify ===
0x100004690  bl sym.imp.CryptoKit.HMAC.authenticationCode...
0x10000499c  bl sym.imp.Foundation.Data.write.to...
0x1000049dc  bl sym.imp.Foundation.Data.contentsOf...
0x100005020  bl sym.imp.CryptoKit.HMAC.isValidAuthenticationCode...
```

Flow A fails the test, so the demo fails as a whole even though the binary references HMAC APIs. Two caveats about the "passing" flow if you reuse it: the key is generated fresh in memory on every call (`SymmetricKey(size: .bits256)`), so in a real app nothing written in one session could be verified in the next. OWASP's comment says a real app would keep the key in the Keychain. And `stored.prefix(stored.count - 32)` traps at runtime if the file is shorter than 32 bytes, so a truncated file crashes the app instead of being reported as tampered. Check the length first.

### GT-RES-0057-1: Tampering with stored data at runtime (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

This is the dynamic half that the legacy tests 0047 and 0090 had and the v2 tests dropped. You change stored values of the app under test on your own rooted or jailbroken test device and observe whether the app notices, how it reacts, and how much effort it takes to make it accept the change. It confirms or refutes what the static tests suggested, and it catches checks that static search missed (native code, SDKs, obfuscated wrappers).

#### Prerequisites

- A rooted Android test device or emulator image, or a jailbroken iOS test device, with the app under test installed and a test account. Our [traffic interception lab note](/mobile/mobile-traffic-interception-lab/) covers the set-up.
- The list of security-relevant stored values from MASTG-TEST-0338 / 0387.
- An intercepting proxy, to see whether a tamper event is reported to the backend.
- Frida and objection, for tracing the app's own checks.

#### Steps

1. **Trace the integrity code while you use the app normally.** This shows which values are read, which are verified and with what key. On Android:

   ```javascript
   // trace-integrity.js - frida -U -f com.example.app -l trace-integrity.js
   Java.perform(() => {
     const Mac = Java.use('javax.crypto.Mac');
     Mac.init.overload('java.security.Key').implementation = function (k) {
       console.log('[Mac.init] ' + this.getAlgorithm() + ' key=' + k.$className);
       return this.init(k);
     };
     const MD = Java.use('java.security.MessageDigest');
     MD.isEqual.implementation = function (a, b) {
       const r = this.isEqual(a, b);   // this = original, avoids recursion
       console.log('[MessageDigest.isEqual] -> ' + r);
       return r;
     };
     const Prefs = Java.use('android.app.SharedPreferencesImpl');
     Prefs.getString.implementation = function (k, d) {
       const v = this.getString(k, d);
       console.log('[prefs.getString] ' + k + ' = ' + v);
       return v;
     };
     Prefs.getBoolean.implementation = function (k, d) {
       const v = this.getBoolean(k, d);
       console.log('[prefs.getBoolean] ' + k + ' = ' + v);
       return v;
     };
   });
   ```

   `key=javax.crypto.spec.SecretKeySpec` means the key bytes are in app memory and came from somewhere you can find. A Keystore class (`android.security.keystore...AndroidKeyStoreSecretKey` or similar) means the key is non-exportable. On iOS, trace CommonCrypto and `UserDefaults`:

   ```bash
   frida-trace -U -f com.example.app -i 'CCHmac*' -i 'SecKeyVerifySignature' -i 'timingsafe_bcmp' \
     -m '-[NSUserDefaults objectForKey:]' -m '-[NSUserDefaults boolForKey:]'
   ```

   CryptoKit HMAC calls are often specialised into the app binary and do not show up as a clean import call. Use the call sites you found in MASTG-TEST-0387 and hook them by address if you need to.

2. **Snapshot the data before you change anything.** You will need it to test rollback and to restore the device afterwards. Android:

   ```bash
   PKG=com.example.app
   adb shell am force-stop $PKG
   adb shell su -c "tar -czf /data/local/tmp/$PKG-before.tgz -C /data/data/$PKG shared_prefs files databases"
   adb pull /data/local/tmp/$PKG-before.tgz
   ```

   iOS (SSH over USB with `iproxy 2222 22`; get the data path from objection's `env`):

   ```bash
   DATA=/var/mobile/Containers/Data/Application/<UUID>
   ssh -p 2222 root@localhost "tar -czf /tmp/before.tgz -C $DATA Library Documents"
   scp -P 2222 root@localhost:/tmp/before.tgz .
   ```

3. **Change a value and only the value.** Android, editing in place so that ownership and SELinux label are kept (writing with `cat >` into the existing file, rather than `cp` or `mv`, keeps the inode):

   ```bash
   adb shell am force-stop $PKG
   adb shell su -c "cat /data/data/$PKG/shared_prefs/app_settings.xml" > app_settings.xml
   sed -i.bak 's#<boolean name="is_premium" value="false" />#<boolean name="is_premium" value="true" />#' app_settings.xml
   adb push app_settings.xml /data/local/tmp/
   adb shell su -c "cat /data/local/tmp/app_settings.xml > /data/data/$PKG/shared_prefs/app_settings.xml"
   adb shell monkey -p $PKG -c android.intent.category.LAUNCHER 1
   ```

   For SQLite, force-stop first and pull the `.db` together with its `-wal` and `-shm` files. Recent writes may still be in the WAL. Edit with `sqlite3` on the host, push everything back, and check ownership with `ls -lZ`. If you created new files, fix them with `chown <app uid>:<app uid>` (from `stat -c %U` on an existing file) and `restorecon`.

   iOS: terminate the app, edit the plist on the host, put it back, and restart `cfprefsd` so it does not serve a cached copy:

   ```bash
   ssh -p 2222 root@localhost 'killall -9 App'          # the executable name
   scp -P 2222 root@localhost:"$DATA/Library/Preferences/com.example.app.plist" .
   plutil -replace isPremium -bool YES com.example.app.plist
   scp -P 2222 com.example.app.plist root@localhost:"$DATA/Library/Preferences/"
   ssh -p 2222 root@localhost "chown mobile:mobile $DATA/Library/Preferences/com.example.app.plist; killall -9 cfprefsd"
   ```

4. **Run the variants that separate a real check from a cosmetic one.** One value at a time, relaunching between each:

   | Variant | What you do | A sound implementation |
   |---|---|---|
   | A. Edit | Change the value, leave the tag | Detects |
   | B. Strip | Delete the tag entry or the appended bytes | Detects (missing tag = tampering) |
   | C. Swap | Copy a valid `(value, tag)` pair from another key, record or test account | Detects if the tag is bound to its context |
   | D. Rollback | Restore the snapshot from step 2 after the value has legitimately changed (trial used up, entitlement removed, PIN attempts used) | Detected by a version counter, or overridden by the server on the next sync |
   | E. Transplant | Install on a second test device, copy the data directory across (or restore a backup), launch | Fails verification because the key did not travel, and recovers by re-fetching from the server rather than crashing or granting |
   | F. Forge | If the key is a constant you found statically, compute a valid tag for your value (as OWASP's demo does) | Not possible with a Keystore or Keychain key |

5. **Watch the reaction.** UI message, wipe, forced logout, crash, silent continuation, and a request to the backend (look for a tamper or integrity field in the proxy). Then check whether the server enforces the same decision anyway: does the premium content still come from the API, or does the API refuse because the server knows the truth? That is the observation that decides the rating.

6. **Measure the cost of bypass**, if the app does detect tampering. Find the app's own verification method (from step 1 and jadx/r2), and on your device change its return value with one Frida hook:

   ```javascript
   Java.perform(() => {
     const S = Java.use('com.example.app.storage.SecurePrefs');   // the app's own class, from jadx
     S.verify.implementation = function (...args) {
       const r = this.verify(...args);
       console.log('[SecurePrefs.verify] ' + r + ' -> true');
       return true;
     };
   });
   ```

   Record how many hooks were needed and how long it took to find the right place. Stop there. The goal is to measure the control, not to build a tool.

7. **Restore the device**: put the snapshot back, or clear the app's data.

#### Observation

For each value and variant: the change made (before/after excerpt of the file), the app's reaction (screenshot or log), any backend report, whether the server-side decision followed the local value, and for detected tampering the bypass effort (number of hooks or patches, time spent, where the check lives: Java, Swift, native).

#### Evaluation

- **Fail** if a security-relevant value can be changed (variant A or B) and the app acts on it. This is the dynamic confirmation of a 0338/0387 failure. Severity depends on whether the server also trusts it (see [Rating findings](#rating-findings)).
- **Fail** if variant F succeeds: the integrity check exists, but its key is public.
- **Weak** (report as an observation with a recommendation) if only C or D succeeds, or if the check detects but the reaction is cosmetic (a toast, a log line).
- **Pass** if A, B, C and F are detected, failure leads to discard or recovery, and E recovers cleanly. Add the bypass effort from step 6 as an informational note. A check that falls to one hook on an R-profile app is worth stating plainly in the report.

#### Demo

An illustrative example (not from an engagement). A lock-out counter kept in `SharedPreferences` without a tag:

```kotlin
val attempts = prefs.getInt("pin_attempts", 0)
if (attempts >= 5) { lockOut(); return }
if (!checkPin(input)) prefs.edit { putInt("pin_attempts", attempts + 1) }
```

Resetting `<int name="pin_attempts" value="5" />` to `0` with step 3, and repeating, removes the lock-out for an attacker with root. The trace from step 1 shows the read with no `Mac` activity around it:

```text
[prefs.getInt] pin_attempts = 0
```

With a Keystore-backed tag bound to the key name, the same edit produces (illustrative):

```text
[Mac.init] HmacSHA256 key=android.security.keystore2.AndroidKeyStoreSecretKey
[MessageDigest.isEqual] -> false
```

and the app falls back to fetching the attempt counter from the server. The second version still yields to a hook on `isEqual`. That is acceptable only because the authoritative counter is on the server.

### GT-RES-0057-2: Repackaging and re-signing detection (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The test checks whether the app notices that it has been repackaged: re-signed with a different key, or with a bundled resource changed. You re-sign the app under test with your own test key, install it on your own test device, and observe. This is verification only. The re-signed build stays on your device and is deleted afterwards, and nothing is distributed. The modification is deliberately minimal (none at all, or one harmless resource), because the question is whether the app detects the different signer or the changed resource, not what an attacker could add.

#### Prerequisites

- **Android**: the APK and all splits; [Apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), `zipalign` and [apksigner](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/) from the build-tools; a test keystore.
- **iOS**: an unencrypted IPA of the version under test (a development or ad hoc build from the client is easiest); a Mac with your own Apple development certificate and a provisioning profile for your test device; [codesign](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0114/). OWASP's [MASTG-TECH-0092](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0092/) (Signing IPA files) describes the same with fastlane. Note that with a free Apple account you must change the bundle identifier.
- Agreement in the rules of engagement that re-signing the app for testing is in scope.

#### Steps

**Android**

1. Record the genuine signer for comparison:

   ```bash
   apksigner verify --print-certs --verbose base.apk | grep -E 'Verified using|certificate SHA-256'
   ```

2. Create a test key once:

   ```bash
   keytool -genkeypair -keystore test.jks -alias test -keyalg RSA -keysize 3072 -validity 365 -dname "CN=Test"
   ```

3. **Variant A, signer change only.** Re-sign without touching the contents. `apksigner` replaces the existing v2/v3 signatures, and for APKs that still carry a v1 signature, remove the old `META-INF` signature files first:

   ```bash
   zip -d base.apk 'META-INF/*.SF' 'META-INF/*.RSA' 'META-INF/*.EC' 'META-INF/*.DSA' 'META-INF/MANIFEST.MF' 2>/dev/null
   zipalign -p -f 4 base.apk base-aligned.apk
   apksigner sign --ks test.jks --ks-key-alias test --out base-resigned.apk base-aligned.apk
   ```

   Re-sign **every** split with the same key in the same way. All APKs of a package must share one signer.

4. **Variant B, resource change.** Change one harmless bundled resource (a string in `res/values/strings.xml`, or one byte of a text asset such as a JavaScript bundle comment), rebuild and sign:

   ```bash
   apktool d -o src base.apk
   # edit one string in src/res/values/strings.xml
   apktool b -o rebuilt.apk src
   zipalign -p -f 4 rebuilt.apk rebuilt-aligned.apk
   apksigner sign --ks test.jks --ks-key-alias test --out rebuilt-signed.apk rebuilt-aligned.apk
   ```

5. Uninstall the genuine app (the signer differs, so it cannot be updated in place) and install the re-signed set:

   ```bash
   adb uninstall com.example.app
   adb install-multiple base-resigned.apk split_config.arm64_v8a-resigned.apk split_config.en-resigned.apk
   ```

6. Use the app through login and one sensitive flow, with the proxy running.

**iOS**

1. Inspect the genuine signature and seal:

   ```bash
   unzip -q App.ipa -d ipa/ && APP=ipa/Payload/App.app
   codesign -dvvv "$APP" 2>&1 | grep -E 'Identifier|TeamIdentifier|CodeDirectory|Hash type|Sealed Resources'
   codesign -d --entitlements :- "$APP"
   plutil -p "$APP/_CodeSignature/CodeResources" | head -20
   otool -l "$APP/App" | grep -A4 LC_ENCRYPTION_INFO
   ```

2. Prepare your profile and entitlements:

   ```bash
   security cms -D -i my_dev.mobileprovision > profile.plist
   /usr/libexec/PlistBuddy -x -c 'Print :Entitlements' profile.plist > ent.plist
   cp my_dev.mobileprovision "$APP/embedded.mobileprovision"
   ```

3. **Variant A, signer change only.** Sign nested code first, then the app:

   ```bash
   ID="Apple Development: Test User (ABCDE12345)"
   find "$APP/Frameworks" "$APP/PlugIns" -maxdepth 1 \( -name '*.framework' -o -name '*.dylib' -o -name '*.appex' \) 2>/dev/null \
     | while read -r f; do codesign -f -s "$ID" "$f"; done
   codesign -f -s "$ID" --entitlements ent.plist "$APP"
   codesign --verify --deep --strict --verbose=2 "$APP"
   ```

   App extensions need their own matching profiles and entitlements. If you do not need them for the test, removing the `PlugIns` folder is simpler.

4. **Variant B, resource change.** Before signing, change one byte in a bundled text resource. Run `codesign --verify` on the unsigned change first to see the seal break (`a sealed resource is missing or invalid`), then sign as in step 3.

5. Package and install on your test device:

   ```bash
   (cd ipa && zip -qr ../App-resigned.ipa Payload)
   ideviceinstaller -i App-resigned.ipa
   ```

6. Use the app through login and one sensitive flow, with the proxy running.

**Both platforms, after the run**

7. If the app detects the change, find the check (MASTG-TEST-0338/0387 output; search for the strings and APIs listed in the Knowledge section) and measure the effort to neutralise it on your device with a Frida hook on the app's own method, as in GT-RES-0057-1 step 6.
8. Uninstall the re-signed build and reinstall the genuine one.

#### Observation

For each variant: does the app start, does it warn or refuse, does it send a tamper signal to the backend (and does the backend then refuse the session), or does it behave normally? Record side effects that are not designed detection: on Android, Google sign-in, Firebase, Maps API keys restricted by certificate digest, and Play Integrity verdicts fail with a foreign signer. On iOS, Keychain items, App Groups, push and App Attest stop working under a different team. Note them, but do not count them as a resilience control unless the app deliberately reacts to them. Record where the check lives and the bypass effort.

#### Evaluation

- **R-profile app, no reaction to either variant and no server-side signal**: fail. No repackaging detection. Rate per [Rating findings](#rating-findings), higher if server-verified app attestation ([MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)) is also absent.
- **Detects variant A but not B**: partial. Signer checks do not cover resources the attacker changes on a rooted device without re-signing. Recommend hashes of critical scripts and configuration.
- **Detects both, but the check is a single Java/Swift boolean defeated by one hook, and nothing reaches the server**: pass with a weakness. Report the bypass effort.
- **Detects both and the server refuses the session (attestation or a reported tamper signal used in risk decisions)**: pass.
- **Not an R-profile app**: record the result as Info.

#### Demo

An illustrative example (not from an engagement). `apksigner` output for the genuine and the re-signed builds. The digest values are placeholders:

```text
$ apksigner verify --print-certs --verbose base.apk | grep -E 'Verified using v3|SHA-256'
Verified using v3 scheme (APK Signature Scheme v3): true
Signer #1 certificate SHA-256 digest: 1f0e...(Play app signing key)...9a2c
$ apksigner verify --print-certs --verbose base-resigned.apk | grep -E 'Verified using v3|SHA-256'
Verified using v3 scheme (APK Signature Scheme v3): true
Signer #1 certificate SHA-256 digest: 7b44...(test.jks)...e01d
```

Both are valid signatures. Only a check that knows the first digest can tell them apart. In the app, the check usually looks like this in jadx, and is found with one `grep` for `GET_SIGNING_CERTIFICATES`:

```java
if (!signerDigests(ctx).contains("1f0e...9a2c")) {
    reportTamper("signer");       // good: the server learns about it
    showFatalDialog();            // a single place to patch
}
```

## Best practices

OWASP has one best-practice page per platform for storage integrity. Both teach the right pattern with sample code that needs correcting. We add two sections of our own for what they leave out: binding, rollback, reaction, and package checks.

### MASTG-BEST-0066: Implementing Storage Integrity Checks on Android

Source: [MASTG-BEST-0066](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0066/).

OWASP's advice: compute an HMAC over stored data before writing and verify it before reading; use a key generated and stored in the Android Keystore so it cannot be taken from the package or a backup; `java.security.Signature` is the asymmetric alternative; if the data is also encrypted, encrypt first and MAC the ciphertext; and treat the whole thing as defence in depth, because a hardcoded or root-recoverable key, or a hooked verifier, defeats it.

The sample code on that page contradicts its own text. It takes the key as a raw `ByteArray` and wraps it in `SecretKeySpec`, so the key is in app memory and most likely hardcoded, and it compares with `contentEquals`, which is not constant-time. The Keystore version is no longer, and binds the tag to the preference name:

```kotlin
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

private const val ALIAS = "prefs_integrity_v1"

private fun macKey(): SecretKey {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
    return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore").run {
        init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN).build())
        generateKey()                                   // never leaves the Keystore
    }
}

// Length-prefixed fields, so ("ab","c") and ("a","bc") never produce the same bytes.
private fun canonical(vararg parts: String): ByteArray {
    val bytes = parts.map { it.toByteArray(Charsets.UTF_8) }
    val buf = ByteBuffer.allocate(bytes.sumOf { 4 + it.size })
    bytes.forEach { buf.putInt(it.size).put(it) }
    return buf.array()
}

fun tag(name: String, userId: String, version: Long, value: String): ByteArray =
    Mac.getInstance("HmacSHA256").run {
        init(macKey())
        doFinal(canonical("prefs", name, userId, version.toString(), value))
    }

fun verify(name: String, userId: String, version: Long, value: String, stored: ByteArray?): Boolean =
    stored != null && stored.size == 32 &&
        MessageDigest.isEqual(tag(name, userId, version, value), stored)   // constant-time
```

Store the tag Base64-encoded next to the value. Treat a missing tag as tampering, and on failure discard the value and ask the server. Our [MASWE-0009 note](/mobile/maswe-0009-improper-use-of-mac/) explains each of these choices in detail, and adds encrypt-then-MAC for when you cannot use AES-GCM. If you encrypt the data anyway, an AEAD (AES-GCM with the context as associated data) gives integrity without a separate MAC.

### MASTG-BEST-0065: Implementing Storage Integrity Checks on iOS

Source: [MASTG-BEST-0065](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0065/).

OWASP's advice: HMAC data before writing it to the Keychain, `UserDefaults`, files or databases, and verify before reading; keep the key in the Keychain with a strict accessibility class such as `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` so it is not carried in backups or to another device; use CryptoKit, or `CCHmac` in Objective-C code; encrypt-then-MAC when both are needed; and accept that a jailbroken attacker can extract the key or hook the verifier. For the app's own executable code, it points to MASTG-BEST-0067 (covered in our [MASWE-0058 note](/mobile/maswe-0058-runtime-code-integrity-not-verified/)).

Its sample verifies with `Data(expected) == mac`, which is not constant-time, although CryptoKit has a verify function that is. Corrected, with context binding and a Keychain-held key:

```swift
import CryptoKit
import Foundation
import Security

func loadOrCreateKey(account: String = "storage-mac-v1") throws -> SymmetricKey {
    let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrAccount as String: account,
                                kSecReturnData as String: true]
    var item: CFTypeRef?
    if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data {
        return SymmetricKey(data: data)
    }
    let key = SymmetricKey(size: .bits256)
    let add: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                              kSecAttrAccount as String: account,
                              kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                              kSecValueData as String: key.withUnsafeBytes { Data($0) }]
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    return key
}

func context(_ name: String, _ userId: String, _ version: UInt64, _ value: Data) -> Data {
    var out = Data()
    for part in [Data(name.utf8), Data(userId.utf8), withUnsafeBytes(of: version.bigEndian) { Data($0) }, value] {
        withUnsafeBytes(of: UInt32(part.count).bigEndian) { out.append(contentsOf: $0) }   // length prefix
        out.append(part)
    }
    return out
}

func tag(_ msg: Data, key: SymmetricKey) -> Data {
    Data(HMAC<SHA256>.authenticationCode(for: msg, using: key))
}

func verify(_ msg: Data, tag stored: Data?, key: SymmetricKey) -> Bool {
    guard let stored, stored.count == 32 else { return false }                 // missing or short = tampered
    return HMAC<SHA256>.isValidAuthenticationCode(stored, authenticating: msg, using: key)  // constant-time
}
```

If the key is missing (first launch on a device restored from backup), verification fails for all existing data. Handle that as "re-fetch from the server", not as "create a new key and re-tag whatever is on disk". The second option launders tampered data into trusted data.

### Beyond the OWASP samples: binding, rollback and response

- **Decide what deserves a tag.** Anything that changes a security or business decision: roles, entitlements, counters and lock-out state, security configuration (pinning flags, server URLs, feature flags that disable checks), cached server-signed tokens. Do not bother tagging UI preferences.
- **Bind the tag to its context**: store name, key name, user or account ID, record ID, and a version, encoded unambiguously. A tag over the value alone can be moved.
- **Reject missing tags.** If you are migrating old data, migrate it once, on the server's word, and from then on treat "no tag" as tampering.
- **Rollback needs something the attacker cannot roll back.** On the device there is no general-purpose, rollback-protected storage available to apps. Put a monotonic version in the authenticated data and keep the latest version on the server. For offline use, keep a server-signed copy with an expiry (`validUntil`), verified with a public key in the app (see [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/)), so a rolled-back copy only works until it expires. Rotating the local MAC key on each write (new alias, old one deleted) also invalidates old copies, at the cost of complexity, and a root attacker who can restore the Keystore's own database may still get round it.
- **React deliberately.** Discard, re-fetch, restrict, report. Never fall back to a default that grants something. Report failures with enough context for the backend to act (which store, which check), and keep the reaction away from the check, so that one patch does not remove both.
- **Remember what the key protects against.** A non-exportable key defeats backup tampering, data transplant and offline forgery. It does not defeat an attacker who runs code inside the app. That residual risk is why the server has to hold the authoritative state.

### Package and resource checks that are worth shipping

For an R-profile app, in order of value:

1. **Server-verified app attestation** (Play Integrity with `appIntegrity`, App Attest) on sensitive API calls. This is the only package-integrity check whose decision the attacker cannot hook. See [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/).
2. **Hashes of critical scripts and configuration** shipped as assets (`index.android.bundle`, `main.jsbundle`, `www/`, Lua, templates, pin sets), with reference values compiled into native code or the main executable, checked before use. On Android, use SHA-256 over the bytes, never ZIP CRCs.
3. **A signer check** on Android (`GET_SIGNING_CERTIFICATES` / `hasSigningCertificate`, against the Play app signing key digest and any rotation lineage), and the re-signing heuristics on iOS (Team ID prefix, unexpected `embedded.mobileprovision`, `cryptid`). Implement in more than one place, preferably native, and send the result to the server rather than only acting locally.
4. **Tie the checks into the rest of the resilience stack**: obfuscation ([MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/)) so the checks are hard to find, runtime integrity ([MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/)) so they are hard to hook, and BEST-0029's guidance on combining RASP signals, summarised in the [series hub](/mobile/masvs-resilience-resilience-testing-guide/).

## Rating findings

The series-wide rules apply. Adapted to this weakness:

- **App without the R profile.** Missing storage integrity checks and missing repackaging detection are **Info** (observations), *unless* a security decision is enforced only by locally stored data. That is not a missing resilience control but a missing server-side control (the MASVS-CODE-4 half of this weakness), and it is rated by what it unlocks regardless of profile.
- **R-profile app.** A missing control is usually **Low–Medium**. It rises to **Medium–High** only when it directly enables a concrete business abuse, such as entitlements or rewards that the server takes from the client, or a lock-out counter that protects a local PIN.
- **A control that exists but is trivially bypassed** (a hardcoded HMAC key, one hook on a boolean verifier, a ZIP CRC) is rated as missing, and then by what the bypass unlocks.
- **Data that other apps can modify without root** (shared storage, world-writable files on very old targets) is not a resilience issue at all. It is a real vulnerability, rated as such.

| Rating | Conditions |
|---|---|
| **High** | A security decision rests only on a locally stored value that can be changed without root (shared storage, backup restore where the platform still allows it) and unlocks something of value: authorisation, paid content at scale, payments. Or a locally stored lock-out counter for a local PIN or passcode that guards access to sensitive data, resettable by editing a file (rate together with [MASWE-0020](/mobile/maswe-0020-local-authentication-bypass/)). Or downloaded code or configuration loaded from a location other apps can write. |
| **Medium** | A security decision rests only on a locally stored value that root or jailbreak access can change (role, premium flag, server URL, pinning switch), and the server does not re-check it. Or an HMAC "protecting" such a value with a hardcoded key (also [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/)). Or, in an R-profile app whose bots or modded clients abuse a business API, no repackaging detection and no app attestation. |
| **Low** | R-profile app: no storage integrity checks for values the server also enforces; no repackaging or signer check, but app attestation is present server-side; a check that detects tampering but reacts cosmetically or falls to one hook; tags not bound to context; no rollback protection for values the server re-syncs. |
| **Info** | Non-R apps without these controls (no local-only decisions); non-constant-time comparison of local tags; reliance on deprecated `EncryptedSharedPreferences`; missing tags on values with no security meaning; side effects of re-signing (Keychain, Firebase, sign-in failing) that the app does not use as a control. |

Lower a level when the server demonstrably ignores the local value (the API returns the real entitlement whatever the app shows). Raise a level when the tampering can be packaged and shared at scale (a single edited file or a re-signed APK that works for everyone), or when the value guards access to other users' data. In the report, give the file path and key name, the before/after excerpt, the app's reaction, what the server did, and for existing checks the bypass effort you recorded (number of hooks, time, where the check lives). State plainly that local checks are defence in depth and that the fix for anything rated Medium or above includes server-side enforcement.

## References

- OWASP MASWE: [MASWE-0057: App Resources Integrity Not Verified](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0057/); related [MASWE-0056](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0056/), [MASWE-0058](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0058/), [MASWE-0049](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0049/), [MASWE-0050](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/), [MASWE-0009](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0009/), [MASWE-0011](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0011/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-RESILIENCE-2](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/), [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0029](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0029/), [MASTG-KNOW-0036](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0036/), [MASTG-KNOW-0086](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0086/), [MASTG-KNOW-0109](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0109/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0338](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0338/), [MASTG-TEST-0387](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0387/); legacy [MASTG-TEST-0047](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0047/), [MASTG-TEST-0090](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0090/), [MASTG-TEST-0002](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0002/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0101](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0101/MASTG-DEMO-0101/), [MASTG-DEMO-0150](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0150/MASTG-DEMO-0150/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0065](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0065/), [MASTG-BEST-0066](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0066/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0008](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0008/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0059](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0059/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0092](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0092/) (CC BY-SA 4.0)
- OWASP MASTG tools: [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [apksigner (MASTG-TOOL-0123)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [radare2 for iOS (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [codesign (MASTG-TOOL-0114)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0114/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [objection (MASTG-TOOL-0038)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/) (CC BY-SA 4.0)
- Android: [`SigningInfo`](https://developer.android.com/reference/android/content/pm/SigningInfo), [`PackageManager`](https://developer.android.com/reference/android/content/pm/PackageManager) (`GET_SIGNING_CERTIFICATES`, `hasSigningCertificate`), [APK signature schemes](https://source.android.com/docs/security/features/apksigning), [Play App Signing](https://support.google.com/googleplay/android-developer/answer/9842756), [Android Keystore system](https://developer.android.com/privacy-and-security/keystore), [Cryptography](https://developer.android.com/privacy-and-security/cryptography) (including the Jetpack Security deprecation), [Cryptography changes in Android P](https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html), [Data storage: shared preferences](https://developer.android.com/training/data-storage/shared-preferences), [Back up user data with Auto Backup](https://developer.android.com/guide/topics/data/autobackup), [Android 12 behaviour changes for apps targeting 12](https://developer.android.com/about/versions/12/behavior-changes-12) ("ADB backup restriction", "Backup and restore")
- Apple: [CryptoKit `HMAC`](https://developer.apple.com/documentation/cryptokit/hmac), [Storing CryptoKit keys in the keychain](https://developer.apple.com/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain), [Restricting keychain item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility), [`SecKeyCreateSignature`](https://developer.apple.com/documentation/security/seckeycreatesignature%28_:_:_:_:%29), [`SecCodeCheckValidity` (macOS and Mac Catalyst only)](https://developer.apple.com/documentation/security/seccodecheckvalidity%28_:_:_:%29), [Apple Platform Security: App code signing process in iOS, iPadOS, tvOS, visionOS and watchOS](https://support.apple.com/en-gb/guide/security/sec7c917bf14/web), [TN3125: Inside Code Signing: Provisioning Profiles](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles), [TN3126: Inside Code Signing: Hashes](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes)
- Background: [Bellare and Namprempre, Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm](https://eprint.iacr.org/2000/025), [RFC 2104: HMAC](https://www.rfc-editor.org/rfc/rfc2104)
- CWE: [CWE-471: Modification of Assumed-Immutable Data (MAID)](https://cwe.mitre.org/data/definitions/471.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
