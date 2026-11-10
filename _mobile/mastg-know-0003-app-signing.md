---
title: "Android App Signing: v1/v2/v3 Schemes and How to Verify Them (MASTG-KNOW-0003)"
date: 2026-09-02
subcategory: resilience
summary: "Signature schemes, debug-key detection, certificate validity requirements, and why a v1-only APK is a repackaging finding."
refs: [MASTG-KNOW-0003, MASVS-RESILIENCE-1, CWE-347]
tags: [android, apk, code-signing, apksigner, repackaging, masvs-resilience]
---

## What it is

Android requires every APK to be digitally signed before it can be installed or run. The signature binds the APK to the developer's private key and is what the platform uses to decide whether an update may replace an installed app: an update signed with a different key is rejected. This is the mechanism that prevents an attacker from pushing a modified version of an app over the legitimate one.

A public-key certificate is attached to the APK at signing time. In debug builds the Android SDK signs with an auto-generated debug key, which is not accepted by Google Play or most other stores. Release builds must be signed with a release key.

### Certificate validity

Before Android 9 (API 28) every update had to be signed with the same certificate, so a validity period of 25 years or more is recommended. Apps published on Google Play must be signed with a key whose validity period ends after 22 October 2033.

### The three schemes

| Scheme | Introduced | Covers | Notes |
|---|---|---|---|
| v1 (JAR signing) | original | individual files listed in `META-INF/MANIFEST.MF` | Does not protect the ZIP structure itself. Vulnerable to Janus (CVE-2017-13156) on Android 5.0–8.0, where a DEX file can be prepended to a valid APK without invalidating the signature. |
| v2 (APK Signature Scheme v2) | Android 7.0 (API 24) | the whole APK file as a blob | Detects any modification to the archive. Faster to verify. |
| v3 (APK Signature Scheme v3) | Android 9 (API 28) | whole file, plus a signing-certificate lineage | Adds key rotation: an app can change its signing key across updates while retaining continuity, since both old and new keys are represented. |

Release builds should be signed with all applicable schemes, not just the newest, so that older platform versions still verify the APK properly. A v3-only APK will not install on Android 7; a v1-only APK on a modern device forgoes whole-file integrity protection.

There is also v4 (Android 11+), used for incremental installs; it is a supplementary signature stored in a `.apk.idsig` file and is not a replacement for v2/v3.

## Why this matters in an assessment

App signing underpins several other controls. If an attacker can repackage and re-sign an app, then any client-side control — root detection, certificate pinning implemented in Java, feature flags, licence checks — can be edited out. The signing scheme in use determines how hard that is and whether platform-level protections apply. Additionally, many apps implement their own runtime signature check (comparing the installed certificate hash against a hardcoded value); the quality of that check is a separate test, and it is only meaningful if it is not trivially patchable.

## How to test

### 1. Enumerate the signature schemes and certificate

```bash
apksigner verify --verbose --print-certs target.apk
```

Expected output includes which schemes verified:

```
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Signer #1 certificate DN: CN=Guler Tech Ltd, O=Guler Tech Ltd, C=GB
Signer #1 certificate SHA-256 digest: 3a7f...
```

Findings to record:

- `v2 scheme: false` on an app targeting API 24+ — no whole-file integrity, Janus exposure on older devices.
- `v1 scheme: false` where `minSdkVersion` is below 24 — the app will not verify on those devices (or, more commonly, indicates a misconfigured build).
- Any scheme failing verification.

### 2. Check for a debug certificate

```bash
apksigner verify --print-certs target.apk | grep -i "CN="
keytool -printcert -jarfile target.apk
```

`keytool -printcert -jarfile` reads only the v1 (JAR) signature. Builds with `minSdkVersion` 24 or higher often carry no v1 signature at all, and then `keytool` prints nothing even though the APK is signed; rely on the `apksigner` output in that case.

The Android debug key is unmistakable:

```
CN=Android Debug, O=Android, C=US
```

A production APK signed with the debug key is a finding in its own right: the private key is the well-known `~/.android/debug.keystore` with password `android`, so anyone can sign a modified build that the platform will accept as an update.

### 3. Verify certificate validity dates

```bash
keytool -printcert -jarfile target.apk | grep -A2 "Valid from"
```

This only works when the APK still has a v1 signature (see above). For v2+-only APKs, take the dates from the certificate in Play Console or from a certificate you export from the signed APK.

Check the expiry against the Play requirement (after 22 October 2033) and against the 25-year recommendation. A certificate expiring within a few years means the app cannot be updated past that date without a key rotation path.

### 4. Confirm the manifest is not debuggable

Signing findings usually cluster with build-configuration findings:

```bash
aapt dump badging target.apk | grep -i debuggable
# or
apktool d target.apk -o out/ && grep -i "android:debuggable" out/AndroidManifest.xml
```

`android:debuggable="true"` in a release build lets any user attach a debugger and `run-as` the app on a non-rooted device.

### 5. Test the repackaging path end to end

This is the practical demonstration of impact. Confirm you can modify, re-sign and install:

```bash
apktool d target.apk -o out/
# modify smali, e.g. force a root-detection method to return false
apktool b out/ -o repacked.apk
zipalign -p -f 4 repacked.apk repacked-aligned.apk
apksigner sign --ks test.keystore --ks-key-alias test repacked-aligned.apk
adb install -r repacked-aligned.apk
```

If the app installs and runs, no runtime integrity verification is present. If it crashes or refuses to start, locate the check and assess whether it is bypassable:

```bash
grep -rn "getPackageInfo\|GET_SIGNATURES\|GET_SIGNING_CERTIFICATES\|signingInfo" out/sources/
```

A runtime check that compares `PackageManager.getPackageInfo(..., GET_SIGNING_CERTIFICATES)` against a hardcoded hash in Java is patchable in one line of smali; the same check implemented in native code with the expected hash obfuscated raises the bar meaningfully. Note which you found.

### 6. Verify key rotation handling (v3)

If the app uses v3 lineage, confirm that any server-side or client-side certificate pinning of the app signature accounts for the lineage rather than a single certificate hash, otherwise a legitimate key rotation will break the check.

## Impact

Weak or absent signing controls do not directly compromise a user; they remove the barrier to distributing a modified build. The realistic attack chain is: attacker repackages the app with pinning and root detection removed (and optionally malicious code added), signs it with their own key, and distributes it through a third-party store or sideload lure. Users who install it get a functioning app that leaks credentials or traffic.

- Debug-key signed release build: **High** — the signing key is public knowledge, so an attacker can produce updates the platform accepts.
- v1-only signature: **Low to Medium** — Janus-style modification (CVE-2017-13156) is possible on unpatched Android 5.0–8.0 devices, and Android 11+ refuses to install a v1-only APK that targets API 30 or higher. Rate it by how many unpatched old devices the app still supports. See [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) for the current signature-scheme tests.
- No runtime integrity check at all: usually **Low to Medium** on its own, but it is the enabling condition that raises the severity of every other client-side control you defeat, and should be reported as such.

## Remediation

- Sign release builds with a release key held in a managed keystore or Play App Signing; never ship a debug-signed build.
- Sign with all schemes applicable to the declared `minSdkVersion` — v1+v2+v3 for broad support.
- Use a certificate with a validity period beyond 22 October 2033.
- Set `android:debuggable="false"` (the default for release build types) and verify it in the built artefact, not just the source manifest.
- Implement a runtime signing-certificate check using `GET_SIGNING_CERTIFICATES`, and place the comparison in native code if repackaging is part of the threat model — while recognising that client-side integrity checks raise cost rather than prevent the attack.

## References

- OWASP MASTG — [MASTG-KNOW-0003: App Signing](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0003/) (CC BY-SA 4.0)
- [Android Developers — Sign your app](https://developer.android.com/studio/publish/app-signing)
- [Android Developers — Signing considerations](https://developer.android.com/studio/publish/app-signing#considerations)
- [apksigner documentation](https://developer.android.com/tools/apksigner)
