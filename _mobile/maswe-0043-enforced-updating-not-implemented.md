---
title: "MASWE-0043: Enforced Updating Not Implemented"
date: 2026-11-10 10:02:00 +0000
subcategory: code
summary: "Testing Android and iOS apps for enforced updates: Play In-App Updates, App Store lookups, fail-open gates and backends that still serve old versions."
refs: [MASWE-0043, MASVS-CODE-2, CWE-602, CWE-693]
tags: [android, ios, masvs-code, app-updates, in-app-updates, api-versioning]
---

This note is part of our [MASVS-CODE guide](/mobile/masvs-code-code-quality-guide/) and covers OWASP [MASWE-0043](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0043/): apps that have no reliable way to retire their own old versions. Every fix you ship only protects the users who install it. A vulnerability you patched in version 5.3 is still live for everyone who stays on 5.2, and on a mobile platform you do not control who updates or when. Forced updating is how the app owner closes that gap. The app learns that its version is no longer acceptable, stops working until it is updated, and the backend refuses to serve the old version. This note covers the platform building blocks (the Google Play In-App Updates API on Android, App Store lookups and server-driven policies on iOS, since iOS has no forced-update API), where they stop working, and why the decision has to sit on the server. It then walks through the four OWASP tests and adds two of our own: one checks whether the backend still accepts outdated clients, the other checks whether the client gate fails open. It ends with secure patterns and how to rate what you find.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Enforced Updating (MASTG-KNOW-0023)](#android-enforced-updating-mastg-know-0023)
  - [iOS: Enforced Updating (MASTG-KNOW-0074)](#ios-enforced-updating-mastg-know-0074)
  - [Backend: why the server has to enforce the minimum version](#backend-why-the-server-has-to-enforce-the-minimum-version)
- [Tests](#tests)
  - [Before you start: test setup](#before-you-start-test-setup)
  - [MASTG-TEST-0392: References to Enforced Updating APIs (Android)](#mastg-test-0392-references-to-enforced-updating-apis-android)
  - [MASTG-TEST-0382: Runtime Use of Enforced Updating APIs (Android)](#mastg-test-0382-runtime-use-of-enforced-updating-apis-android)
  - [MASTG-TEST-0383: References to Enforced Updating APIs (iOS)](#mastg-test-0383-references-to-enforced-updating-apis-ios)
  - [MASTG-TEST-0384: Runtime Use of Enforced Updating APIs (iOS)](#mastg-test-0384-runtime-use-of-enforced-updating-apis-ios)
  - [GT-CODE-0043-1: Backend accepts outdated app versions (Android, iOS)](#gt-code-0043-1-backend-accepts-outdated-app-versions-android-ios)
  - [GT-CODE-0043-2: Update gate fails open or can be skipped (Android, iOS)](#gt-code-0043-2-update-gate-fails-open-or-can-be-skipped-android-ios)
- [Secure implementation](#secure-implementation)
  - [Minimum-version policy on the backend](#minimum-version-policy-on-the-backend)
  - [Android client gate](#android-client-gate)
  - [iOS client gate](#ios-client-gate)
  - [Release process](#release-process)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0043 applies when an app has no way to make users move off a version after a security fix has shipped. The OWASP requirement is *"The app detects if it must be updated and reacts appropriately."* It maps to [MASVS-CODE-2](https://mas.owasp.org/MASVS/controls/MASVS-CODE-2/) ("The app has a mechanism for enforcing app updates") and to two CWEs. [CWE-602](https://cwe.mitre.org/data/definitions/602.html) is Client-Side Enforcement of Server-Side Security, which is what you get when the only gate lives in the app. [CWE-693](https://cwe.mitre.org/data/definitions/693.html) is Protection Mechanism Failure. The weakness carries the **L2** and **EUDIW** profiles. So it is expected in apps that handle high-value data or transactions (banking, health, identity, the EU Digital Identity Wallet), and it is a recommendation, not a requirement, for an L1 app. The `maswe-beta: MASWE-0075` mapping in the OWASP front matter refers to the old beta numbering. The current MASWE-0075 is an unrelated weakness (non-reproducible builds).

OWASP frames the threat as MAS-THREAT-0043, *"Attackers can exploit vulnerabilities that remain reachable in outdated app versions"*, reached through two attacks:

| Attack | Description | Attacker position |
|---|---|---|
| MAS-ATTACK-0053 | Targeting users who stay on an app version with publicly known vulnerabilities | Whatever the old vulnerability needs: a network attacker for a pinning or TLS bug, a malicious app for an IPC bug, a link for a deep-link or WebView bug |
| MAS-ATTACK-0040 | Patching or repackaging the app to remove or alter client-side checks | The attacker controls their own device and their own copy of the app |

The two attacks pull in different directions, and the test design follows from that. MAS-ATTACK-0053 is about **protecting honest users from their own outdated app**. Most of those users have no idea they are exposed. A client-side gate that shows "please update" works well for them, provided it cannot be skipped by accident: by being offline, by tapping "Later", or because their version predates the gate. MAS-ATTACK-0040 is about an **attacker who deliberately keeps an old client**, or patches out the gate, because the old version or the old API contract gives them something the new one does not. No client-side check stops that person. Only a backend that refuses old versions and retires old API behaviour does. A complete control therefore has two halves: a client gate for the installed base, and server-side refusal for everyone, including clients that never had a gate.

Neighbouring notes in this series:

| Question | Where it lives |
|---|---|
| Does the app refuse to run on an OS version that is too old? (`minSdkVersion`, `MinimumOSVersion`) | [MASWE-0041](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/) |
| Does the app target the latest platform behaviour? (`targetSdkVersion`, SDK used to build) | [MASWE-0042](/mobile/maswe-0042-latest-platform-version-not-targeted/) |
| Does the app ship third-party components with known vulnerabilities? | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) |
| Does the app download and run code outside the store update process (OTA bundles, plugins)? | [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/) |
| Can the app retire a pinned key or certificate it ships with? | [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/) |

## Modes of Introduction

**No mechanism at all.** The app has no update check and the backend serves every version it has ever shipped. This is the default state of a new app, and OWASP lists it as the only mode. In practice the following partial implementations are far more common, and they are what you will find in an assessment.

**A soft prompt where a hard gate was intended.** The app shows "A new version is available" with a "Later" button, uses only `AppUpdateType.FLEXIBLE`, or presents an iOS sheet that can be swiped away. That is fine for feature releases. It is a finding when the vendor's policy says the version is no longer supported.

**A gate only at one entry point.** The check runs in the splash or launcher activity, or in `application(_:didFinishLaunchingWithOptions:)`. It does not run when the app is opened from a deep link, a notification, a widget, an app shortcut, or an Android activity restored after process death, and it does not run when the app returns from the background.

**A gate that fails open.** If the policy request times out, returns an error or cannot be parsed, the app carries on. The same happens when the device is offline, or when Firebase Remote Config still holds its in-app default (`min_version = 0`) because no fetch has been activated yet.

**Play-only enforcement.** The app relies on the In-App Updates API alone. That API only works for installs owned by the Play account on a device with the Play Store. Sideloaded copies, other stores and devices without Google Play services fall through.

**Store lookup as the source of truth.** On iOS the app compares itself against `itunes.apple.com/lookup`. That forces *every* update rather than security-relevant ones. Without a `country` parameter the lookup checks the wrong storefront, and it cannot express "5.2 is unsafe, 5.3 is fine".

**Broken version comparison.** Version names are compared as strings (`"5.10.0" < "5.9.0"`) or parsed as floating-point numbers (`5.10` becomes `5.1`), or the app compares `CFBundleVersion` (build number) with an App Store marketing version.

**Server signals but serves.** The backend adds `forceUpdate: true` to a response, or an `X-Update-Required` header, then returns the data anyway. Only some services check the version (the config endpoint does, the payments service does not), or a missing version header is treated as "latest".

**A gate that arrived too late.** The update gate was added in version 4.0. Everything older has no gate, and only the backend can stop it.

## Impact

- **Known vulnerabilities stay exploitable.** Once a fix ships, the release notes, the diff between the two builds and sometimes a public advisory tell an attacker exactly what to target in users who have not updated. MAS-ATTACK-0053 is the cheapest attack there is, because the research has already been done.
- **Old trust material cannot be retired.** Rotated pinning keys, compromised API keys or certificates embedded in old builds, and weak crypto parameters stay in use for as long as old clients keep talking to the backend. See [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/) for pinning.
- **Old API contracts cannot be removed.** The backend has to keep legacy endpoints alive, together with whatever they lack (newer authorisation checks, rate limits, attestation), because old clients still call them. An attacker who keeps an old client, or simply calls the old endpoint directly, gets the weaker contract.
- **Incident response is slower.** Without a gate the vendor cannot answer "when will every user be on the fixed version?", so the exposure window lasts as long as user habit allows.

## Mitigations

- **Define a minimum supported version on the server** for each platform, and expose it through a policy endpoint the app calls at start-up and when it returns to the foreground.
- **Refuse outdated clients on every API**, not only on the config endpoint. Return an explicit, machine-readable "update required" error. Treat a missing or malformed version as unsupported once the versions that predate the header have been retired. Where you can, take the version from an attested source (the Play Integrity `appIntegrity.versionCode`) rather than from a header the client chooses.
- **Block in the app when the policy says so**: a non-dismissible screen that offers only "Update" (and on Android, ideally, the Play immediate flow). Show it at *every* entry point and on every return to the foreground.
- **Use Play In-App Updates where available.** Use `IMMEDIATE` for security-critical releases and `FLEXIBLE` for the rest. Handle cancellation and `DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS`.
- **Cache the last policy and fail closed for known-bad versions.** If the app has once learnt that its version is below the minimum, it must keep blocking when offline.
- **Compare build numbers, not display strings** (`versionCode` on Android, `CFBundleVersion` or a numerically compared `CFBundleShortVersionString` on iOS).
- **Treat update enforcement as part of API lifecycle management.** Updating the app does not fix backend bugs. Version your API and decommission old versions on a published schedule.

## Knowledge

OWASP has one Knowledge page per platform for this weakness. Both sit in OWASP's MASVS-PLATFORM folder for historical reasons: [MASTG-KNOW-0023](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0023/) (Android) and [MASTG-KNOW-0074](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0074/) (iOS). Both pages end with the same warning: the backend has to take part. We give that point a section of its own, because it decides how you rate most findings.

### Android: Enforced Updating (MASTG-KNOW-0023)

Source: [MASTG-KNOW-0023](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0023/).

#### Why apps force updates

The OWASP page lists four reasons. A client-side vulnerability has been fixed. Key material has to be rotated (a pinned public key, for example). An old API has to be decommissioned. A dependency has to be updated to stay compatible with a backend or third party. Only the first is purely about the app. The other three are about the app's relationship with a server, which is why server-side enforcement is the second half of the same control.

#### The Play In-App Updates API

The [Play In-App Updates API](https://developer.android.com/guide/playcore/in-app-updates) is part of the Google Play Core libraries. Google Play's own UI shows an update to the user from inside your app, and Play downloads and installs the new version. Facts that matter for testing:

- **Library.** The current artefacts are `com.google.android.play:app-update` and, for Kotlin extensions, `com.google.android.play:app-update-ktx` (version 2.1.0 at the time of writing). Older apps may still bundle the monolithic `com.google.android.play:core` artefact. Google's Play Core migration guidance asks apps targeting Android 14 (API 34) or higher to move to the split libraries, so the old artefact in a current build is worth a note.
- **Where it works.** Devices running Android 5.0 (API 21) or higher. Phones, tablets and ChromeOS only, so not Wear OS, TV or Automotive. Not compatible with apps that use APK expansion (`.obb`) files.
- **Who it works for.** Updates are offered only to Play accounts that own the app, and only for a build with the same application ID and signing key as the one on Play. Play can only move a user to a higher `versionCode`. During a staged rollout, users outside the rollout percentage are not offered the update.

The flow in code:

1. `AppUpdateManagerFactory.create(context)` returns an `AppUpdateManager`.
2. `appUpdateManager.appUpdateInfo` (Java: `getAppUpdateInfo()`) returns a `Task<AppUpdateInfo>`.
3. `AppUpdateInfo.updateAvailability()` returns one of `UNKNOWN` (0), `UPDATE_NOT_AVAILABLE` (1), `UPDATE_AVAILABLE` (2) or `DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS` (3). `isUpdateTypeAllowed(AppUpdateType.IMMEDIATE)` or `isUpdateTypeAllowed(AppUpdateType.FLEXIBLE)` says whether Play will run that flow now. In `AppUpdateType`, `FLEXIBLE` is 0 and `IMMEDIATE` is 1. `availableVersionCode()` gives the version Play would install.
4. Two signals help the app decide how hard to push:
   - **`updatePriority()`** returns an integer from 0 (the default) to 5. The vendor sets it per release through the `inAppUpdatePriority` field of `edits.tracks` in the **Google Play Developer API**. Google documents no Play Console field for it, it cannot be changed after the release rolls out, and internal app sharing does not support it. The value the app sees is the highest priority of all version codes between the installed one and the latest, across tracks. Google's guidance maps a critical security update to high priority and the immediate flow.
   - **`clientVersionStalenessDays()`** returns the number of days since the Play Store on this device learnt about the update, or `null` if that is unknown. Apps use it to escalate, for example to a flexible prompt after 3 days and an immediate update after 7.
5. `startUpdateFlowForResult(appUpdateInfo, activityResultLauncher, AppUpdateOptions.newBuilder(AppUpdateType.IMMEDIATE).build())` starts the flow. The launcher is registered with `ActivityResultContracts.StartIntentSenderForResult`. `AppUpdateOptions.defaultOptions(type)` is the short form. `setAllowAssetPackDeletion(true)` allows Play to clear asset packs when storage is low. Older code uses the deprecated `startUpdateFlowForResult(info, updateType, activity, requestCode)` and `onActivityResult`. Each `AppUpdateInfo` can start a flow **once**, so a retry needs a fresh `getAppUpdateInfo()`.
6. The result is `RESULT_OK` (accepted; for an immediate update you often never see it, because Play restarts the app), `RESULT_CANCELED` (the user declined or cancelled) or `ActivityResult.RESULT_IN_APP_UPDATE_FAILED` (another error).

The two flows:

| | Immediate (`AppUpdateType.IMMEDIATE`) | Flexible (`AppUpdateType.FLEXIBLE`) |
|---|---|---|
| UI | Full-screen Play UI over the app for the whole download and install | Consent dialog, then the download runs in the background while the user keeps using the app |
| Install | Play installs and restarts the app | The app must listen (`InstallStateUpdatedListener`, `registerListener`) for `InstallStatus.DOWNLOADED` and call `completeUpdate()` |
| Can the user avoid it? | Yes. Cancelling returns `RESULT_CANCELED` and the app is back in control | Yes. They can decline consent, and after the download they can postpone the restart indefinitely |
| Use for | Releases that must not be skipped | Everything else |

The row that matters is "Can the user avoid it?". **Neither flow is enforcement on its own.** The immediate flow is the right UI for a mandatory update, but the app has to treat `RESULT_CANCELED` and `RESULT_IN_APP_UPDATE_FAILED` as "still blocked". It also has to recheck when it returns to the foreground. If the user left the app during an immediate update, `updateAvailability()` reports `DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS` in `onResume()`, and the app should call `startUpdateFlowForResult` again with `IMMEDIATE`. Google's guide says to run this check "at all entry points into the app". For flexible updates, the matching foreground check looks for `installStatus() == InstallStatus.DOWNLOADED` and prompts the user to call `completeUpdate()`.

#### Limits of the Play API

- **It only knows about Play installs.** A sideloaded APK, an install from another store, or a device without the Play Store (many devices sold in China, some enterprise and AOSP builds) gets no `UPDATE_AVAILABLE`, or the task fails. If the app treats "no update info" as "up to date", the gate fails open for exactly the installs that are hardest to update.
- **It only knows about compatible updates.** If you raise `minSdkVersion`, devices below it are never offered the new version, and Play keeps serving them the last compatible one ([MASWE-0041](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/)). The Play API reports no update and the app runs on. Only a server-side minimum can tell these users that their device is no longer supported.
- **It only exists in versions that contain it.** In-app updates protect future versions. Anything shipped before the integration has no gate.
- **It runs on the user's device.** On a rooted device, hooking `updateAvailability()` to return `UPDATE_NOT_AVAILABLE` takes one line of Frida. That is MAS-ATTACK-0040. It does not matter for honest users, and it is why the backend has to decide.

#### Play Console recovery: "prompt users to update"

Google Play also offers a server-side tool, [Prompt users to update to your latest app version](https://support.google.com/googleplay/android-developer/answer/13812041), under Play Console's app recovery features. You pick an app bundle version, optionally narrowed by country or Android version, and the next time affected users open the app, Play shows a full-screen prompt to update to the latest compatible version. The app needs no code for this, so it is the only Google-side mechanism that reaches versions shipped before in-app updates were integrated. Its limits: the app must use Play App Signing and be published as an Android App Bundle. Every track that contains the version must have a newer version. It is not available for apps that use code transparency, Play Automatic Protections or key upgrade, or on Wear OS, Android TV and Android Automotive OS. **Users can dismiss the prompt.** It comes back on the next cold start, but in the meantime the app works. Treat it as a strong nudge for an emergency, not as enforcement.

#### Custom, backend-gated flows

For anything outside Play, or wherever the vendor needs real blocking, the app asks a policy service (a self-hosted endpoint, or a configuration service such as [Firebase Remote Config](https://firebase.google.com/docs/remote-config)) for the minimum supported version and compares it with its own. The app's own version comes from:

- **Compile-time constants**: `BuildConfig.VERSION_CODE` (an `int`) and `BuildConfig.VERSION_NAME`. Since Android Gradle Plugin 8.0, `BuildConfig` generation is off by default and needs `buildFeatures { buildConfig = true }`. These are `static final` constants. The compiler inlines them, so in decompiled code you see the literal number, not a field access, and you cannot hook them at runtime.
- **Runtime lookup**: `packageManager.getPackageInfo(packageName, 0)`, with `PackageInfo.getLongVersionCode()` (API 28 and later) or `PackageInfoCompat.getLongVersionCode()`, and `versionName`.

Compare **version codes**. Android itself uses `versionCode` to order versions, and it is a plain integer. `versionName` is a display string with no defined ordering.

For Remote Config-based gates, know the defaults. The app ships in-app default values (`setDefaultsAsync()`, often from `res/xml/remote_config_defaults.xml`), and those defaults apply until a fetched config is *activated*. The default minimum fetch interval is 12 hours, so a newly raised minimum can take that long to reach clients unless the app lowers the interval or uses real-time config updates. A gate that reads `min_version_code` before `fetchAndActivate()` has completed, against a default of 0, never blocks on first launch.

What a good policy response carries, according to OWASP and our experience: minimum version code, latest version, whether the update is mandatory, a severity or reason, the store target or URL, and a user message. The request should carry the version code and name, platform, application ID, build type and distribution channel, so the server can decide per channel.

### iOS: Enforced Updating (MASTG-KNOW-0074)

Source: [MASTG-KNOW-0074](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0074/).

#### No platform API

iOS has no equivalent of Play In-App Updates. No public API checks for, downloads or installs an update of an App Store app, and nothing can force one. Users who have automatic updates switched on (App Store settings, "App Updates") usually get new versions within days, but many switch it off, devices without the space or the network do not update, and an app can sit on an old version for months. Every forced-update scheme on iOS is therefore built by the app: it finds out that it is too old, blocks itself, and sends the user to the App Store.

#### App Store lookup

The simplest source of "latest version" is the iTunes Search API's lookup endpoint, documented in Apple's archived [iTunes Search API](https://developer.apple.com/library/archive/documentation/AudioVideo/Conceptual/iTuneSearchAPI/index.html) page:

```text
https://itunes.apple.com/lookup?bundleId=com.example.app&country=gb
https://itunes.apple.com/lookup?id=1234567890
```

The response is JSON with `resultCount` and a `results` array. The fields apps use are `results[0].version` (the current App Store marketing version), `results[0].trackViewUrl` (the product page URL), `results[0].trackId` (the numeric App Store ID) and `results[0].minimumOsVersion`. The app compares `version` with its own `CFBundleShortVersionString` (`Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString")`). It must **not** use `CFBundleVersion` here, which is the build number and is never shown in the store.

Pitfalls a tester should know:

- **Storefronts.** Without `country`, the lookup uses the US storefront. An app that is not sold there gets `resultCount: 0`, and an app with region-specific releases gets the wrong version. Empty results must not be read as "up to date", and they should not crash the app either.
- **Propagation.** Lookup results are cached and can lag behind a release by hours. A gate that fires as soon as `version` changes may send users to a store page that does not offer the update yet.
- **Phased releases.** Apple's phased release only affects *automatic* updates. Anyone can update manually from day one, and the lookup returns the new version straight away. A lookup-driven hard gate therefore forces everyone at once and cancels the phased rollout.
- **Device compatibility.** If the new version raises `MinimumOSVersion`, users on older iOS cannot install it. The App Store offers them the last compatible version, so blocking them sends them to a page with no way out. Compare `minimumOsVersion` with `UIDevice.current.systemVersion` and show a "device no longer supported" message, ideally decided by the server.
- **It means "latest", not "minimum".** A lookup cannot say "5.2.0 is unsafe but 5.2.1 is fine". Used as a hard gate it forces every release, and used as a soft prompt it enforces nothing. Lookups are fine for nudging. Security-critical enforcement needs a vendor-controlled minimum version.

Open-source helpers such as [Siren](https://github.com/ArtSabintsev/Siren) (archived on 2 April 2025, so it is itself an unmaintained dependency to flag under [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/)) or react-native-appstore-version-checker wrap the lookup and comparison. Siren's alert types include ones that can be skipped. Check which type the app configures before you credit it with enforcement.

#### Server-driven minimum version

The robust pattern matches Android's backend-gated flow. At launch and on every return to the foreground (`sceneWillEnterForeground(_:)` or `UIApplication.willEnterForegroundNotification`), the app sends its version and build to a policy endpoint over `URLSession`, receives the minimum, and blocks if it is below it. Two details:

- **Comparison.** `CFBundleShortVersionString` is up to three period-separated integers. Compare it numerically: `installed.compare(minimum, options: .numeric) == .orderedAscending` handles `5.10.0` versus `5.9.0` correctly. Or compare `CFBundleVersion` build numbers if the vendor numbers builds monotonically.
- **Default User-Agent.** `URLSession` sends `AppName/<CFBundleVersion> CFNetwork/<version> Darwin/<version>` by default, so the backend already receives the build number on every request unless the app overrides the header. That is useful for server-side enforcement and for your proxy testing.

#### Blocking and redirecting

When an update is required, the app presents something the user cannot get past:

- A `UIAlertController` with a single "Update" action that reopens the App Store and re-presents the alert, with **no** cancel or "Later" action.
- Or, better, a dedicated gating view controller set as the window's `rootViewController`, so no navigation stack sits underneath. A gate shown as a modal sheet on iOS 13 and later can be swiped down unless `isModalInPresentation = true` is set.

To send the user to the store, the app calls `UIApplication.shared.open(_:options:completionHandler:)` with `trackViewUrl` (or an `itms-apps://apps.apple.com/app/id<trackId>` URL), or presents [`SKStoreProductViewController`](https://developer.apple.com/documentation/storekit/skstoreproductviewcontroller) with `loadProduct(withParameters: [SKStoreProductParameterITunesItemIdentifier: trackId])`. That shows the product page inside the app.

#### Distribution and policy notes

Apple's [App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/) contain no rule against forced updates. Many reviewed apps use them, but the app must still be fully functional for review, so a gate must never block the build that is in review. Hot-code-push systems that update a JavaScript bundle without a store release are not a substitute: they cannot change native code, and they bring their own risks under guideline 2.5.2 and [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/). [App Store Connect](https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds/) requires each uploaded build of a version to have a new, higher build number. It does not require build numbers to keep rising across versions. `CFBundleVersion` is therefore only a safe ordering key if the vendor never resets it, so ask before relying on it.

### Backend: why the server has to enforce the minimum version

*Guler Tech addition. Both OWASP Knowledge pages make this point in a closing paragraph. We expand it here because it decides most ratings.*

A client-side gate is code that runs on a device the user controls. It works on an honest user's phone, and it does nothing in four situations that matter:

1. **Versions released before the gate.** If the gate arrived in 4.0, versions 1.0 to 3.x have nothing to obey.
2. **Gates that fail open.** Offline start, an unreachable policy service, an unactivated Remote Config default, a sideloaded install the Play API ignores.
3. **Deliberate bypass.** Someone who wants an old client hooks or patches the gate (MAS-ATTACK-0040), or does not use the app at all and calls the API directly with the old contract.
4. **Old trust material.** Retiring a pinned key or a leaked API key requires the server to stop honouring the old one. No client change can do that.

The server-side half of the control has three parts:

- **A version signal on every request.** A header such as `X-App-Version: 5.3.0` and `X-App-Build: 5300`, the default iOS User-Agent, or a field in the token request. On its own this is *claimed* data. It stops honest old clients, which are the population MAS-ATTACK-0053 targets, but anyone can raise it. That is acceptable for the honest-user problem and it is not a vulnerability by itself.
- **An attested version where the platform offers one.** On Android the [Play Integrity API](https://developer.android.com/google/play/integrity/verdicts) verdict includes `appIntegrity.versionCode`, signed by Google, next to `appRecognitionVerdict` (`PLAY_RECOGNIZED`, `UNRECOGNIZED_VERSION` or `UNEVALUATED`). A server that decrypts the verdict can reject `versionCode` values below the minimum, whatever the header says. On iOS, App Attest (`DCAppAttestService`) proves that the request comes from a genuine instance of your app (team and bundle ID). It does **not** carry the app version. The version stays a claimed value, so you rely on API versioning and server-side retirement of old behaviour.
- **API versioning and retirement.** Old clients call old endpoints (`/v1/...`) or send old request shapes. Removing the endpoint or the legacy code path is the only control that also stops someone who never uses the app. A version check in front of an endpoint that is still deployed is a policy. Removing the endpoint is enforcement.

The response to an outdated client should be an explicit error the app understands and turns into the blocking screen: for example a `403` or `400` with `{"error":"app_version_unsupported","min_build":5300}`, or `426 Upgrade Required`. Note that [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110#name-426-upgrade-required) defines 426 for *protocol* upgrades and requires an `Upgrade` header, so many APIs prefer a 4xx with an application error code. What matters for the test is that the request is **not processed**.

## Tests

OWASP has four tests for this weakness, a static and a dynamic one per platform:

| Test | Platform | Type | Replaces legacy |
|---|---|---|---|
| [MASTG-TEST-0392](#mastg-test-0392-references-to-enforced-updating-apis-android) | Android | static, manual | [MASTG-TEST-0036](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0036/) (with 0382) |
| [MASTG-TEST-0382](#mastg-test-0382-runtime-use-of-enforced-updating-apis-android) | Android | dynamic (network, hooks), manual | [MASTG-TEST-0036](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0036/) (with 0392) |
| [MASTG-TEST-0383](#mastg-test-0383-references-to-enforced-updating-apis-ios) | iOS | static, manual | [MASTG-TEST-0080](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0080/) (with 0384) |
| [MASTG-TEST-0384](#mastg-test-0384-runtime-use-of-enforced-updating-apis-ios) | iOS | dynamic (network, hooks), manual | [MASTG-TEST-0080](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0080/) (with 0383) |

OWASP publishes no demos for these tests yet. The demo snippets below are our own minimal examples, marked as such. The legacy v1 tests ended with *"observe how the backend responds"* when the version is changed in a proxy. The v2 tests mention it only under "further validation". We turn that into its own test, [GT-CODE-0043-1](#gt-code-0043-1-backend-accepts-outdated-app-versions-android-ios), and collect the fail-open checks in [GT-CODE-0043-2](#gt-code-0043-2-update-gate-fails-open-or-can-be-skipped-android-ios).

### Before you start: test setup

**Ask the vendor first.** Ask for the documented minimum-version policy per platform, the policy endpoint, the version header the backend reads, and, if possible, an older build of the app. On Android that means a Play-signed APK set of a previous release. On iOS it means an older TestFlight or ad-hoc build, which is a different build but useful for backend testing. With these, every test below takes minutes. Without them you have to reconstruct the policy from traffic and simulate an old version.

**Simulating "update required" without an old build.** You have three levers, from least to most invasive:

1. **Rewrite the policy response** in your proxy so the minimum is above the installed version (for example `"min_build": 5300` becomes `"min_build": 99999`), or so the iTunes lookup advertises a higher `version`. This tests the client gate.
2. **Lower the version in requests** in your proxy (`X-App-Build: 5300` becomes `X-App-Build: 4000`). This tests the backend.
3. **Lower the version the app reads about itself** with a Frida hook on `PackageManager.getPackageInfo` or on `NSBundle`. This only affects code that reads the version at runtime. `BuildConfig` constants are inlined and cannot be changed this way, and the Play Store's own view of the installed version is unaffected. Use it to exercise a backend-gated flow end to end.

**Keeping an old Android build for later.** Before a client releases a new version, save the current one from your test device: `adb shell pm path com.example.app`, then `adb pull` each `base.apk` and `split_*.apk`. After the new version is live on Play, uninstall it and reinstall the old set with `adb install-multiple base.apk split_*.apk`, signed in with a Play account that owns the app. Google's own `FakeAppUpdateManager` documentation describes exactly this set-up for full-stack testing: the old version sideloaded, the new one on Play. The Play API then reports `UPDATE_AVAILABLE` and you can test the real immediate flow.

**Vendor-side testing with internal app sharing.** If you work with the development team, Google's [testing guide](https://developer.android.com/guide/playcore/in-app-updates/test) describes the following set-up:

1. Install a build that supports in-app updates from an internal app sharing link.
2. Upload a build with a higher `versionCode` to internal app sharing.
3. On the test device, open the link for the new build but **do not** install it from the Play page.
4. Open the installed app. The update is now offered.

`inAppUpdatePriority` is not supported in internal app sharing. For unit tests, developers use `FakeAppUpdateManager` (`com.google.android.play.core.appupdate.testing`). It has `setUpdateAvailable(versionCode)` and `setUpdateAvailable(versionCode, type)`, `setUpdateNotAvailable()`, `setUpdatePriority()`, `setClientVersionStalenessDays()`, `isImmediateFlowVisible()`, `isConfirmationDialogVisible()`, `userAcceptsUpdate()`, `userRejectsUpdate()`, `userCancelsDownload()`, `downloadStarts()`, `downloadCompletes()`, `downloadFails()`, `installCompletes()` and `installFails()`. Its presence in test sources shows that the vendor has tested cancellation and failure paths. It never ships in a release APK.

**Proxy and hooks.** You need an intercepting proxy ([Burp Suite](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/) or [mitmproxy](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/)) with the app's traffic visible, which may mean bypassing pinning on your test build (see the [traffic interception lab](/mobile/mobile-traffic-interception-lab/)). You also need [Frida](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/) on a rooted or jailbroken test device, or a build with Frida Gadget. Use your own test account and the app's own API only.

### MASTG-TEST-0392: References to Enforced Updating APIs (Android)

Source: [MASTG-TEST-0392](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0392/). Platform: Android. Type: static (code) with manual review. Knowledge: MASTG-KNOW-0023. Replaces (with 0382): MASTG-TEST-0036.

#### Overview

This test checks whether the APK contains code that enforces updates, either through Play In-App Updates or through a custom gate that compares the installed version with a backend-supplied minimum. It also checks whether that code is built to *enforce*: an immediate flow or a non-dismissible screen, handling of cancellation, a foreground recheck, and a check that runs before the app reaches protected features. Code that only *suggests* an update does not count.

#### Prerequisites

- The APK (or APK set) of the release build, decompiled with [jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/) ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)). Decode resources with [Apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/) if you need `res/xml` and the manifest as text.
- ripgrep or grep for the search ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)) and jadx-gui for review ([MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)).
- The app's version code, from `aapt2 dump badging`.

#### Steps

1. **Record the installed version.** You will search for this literal, because `BuildConfig.VERSION_CODE` is inlined:

   ```bash
   aapt2 dump badging app.apk | head -1
   # package: name='com.example.app' versionCode='5300' versionName='5.3.0' ...
   jadx -d out app.apk
   apktool d -o apk_out app.apk
   ```

2. **Find Play In-App Updates usage.** Exclude the library's own package so you only see app code:

   ```bash
   rg -n --glob '!com/google/**' \
     'AppUpdateManagerFactory|getAppUpdateInfo|startUpdateFlowForResult|AppUpdateOptions|isUpdateTypeAllowed|updateAvailability\(\)|updatePriority\(\)|clientVersionStalenessDays|InstallStateUpdatedListener|completeUpdate|DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS' \
     out/sources
   ls out/sources/com/google/android/play/core/appupdate 2>/dev/null   # library present?
   ls out/sources/com/google/android/play/core/ | head                 # old monolithic 'core' artefact?
   ```

   The constants are usually inlined. `updateAvailability() == 2` is `UPDATE_AVAILABLE`, `== 3` is `DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS`, `isUpdateTypeAllowed(1)` is `IMMEDIATE` and `isUpdateTypeAllowed(0)` is `FLEXIBLE`. The Play Core library normally ships keep rules for its public API, so these names usually survive R8. If they have been renamed, start from the `com.android.vending` package name, which the library uses to bind to the Play Store.

3. **Find a custom version gate.**

   ```bash
   rg -n -i --glob '!com/google/**' --glob '!androidx/**' --glob '!kotlin/**' \
     'min_?(supported_?)?version|minimum_?version|min_?build|force_?update|update_?required|upgrade_?required|required_?version|app_?version_?unsupported|getPackageInfo|getLongVersionCode|PackageInfoCompat' \
     out/sources
   rg -n --glob '!com/google/**' --glob '!androidx/**' '\b5300\b' out/sources   # inlined BuildConfig.VERSION_CODE
   rg -n -i 'version' apk_out/res/xml/ apk_out/res/values/strings.xml 2>/dev/null   # Remote Config defaults, messages
   rg -n 'FirebaseRemoteConfig|fetchAndActivate|setDefaultsAsync|setMinimumFetchIntervalInSeconds' out/sources --glob '!com/google/**'
   ```

   Cross-platform apps keep the logic elsewhere. Search `assets/index.android.bundle` for React Native, or the strings of `lib/*/libapp.so` for Flutter, for the same keywords.

4. **Review each location in jadx** and answer four questions:
   - **Where does it run?** Find the callers (jadx "Find usage"). The best case is a check in `Application.onCreate` that feeds a gate every activity respects, or a base activity's `onResume()`. A check only in `SplashActivity.onCreate()` misses deep-link, notification and restored activities. List the manifest's other entry points with `rg -n 'android:exported="true"' apk_out/AndroidManifest.xml`.
   - **What happens when an update is required?** Look for `startUpdateFlowForResult` with type 1 or `AppUpdateOptions` built with `IMMEDIATE`, or a full-screen gate activity. A gate dialog should use `setCancelable(false)`, have no negative button, and finish the task or relaunch itself rather than call `dismiss()`.
   - **What happens on cancel or failure?** Check the activity-result callback. `RESULT_CANCELED` and `RESULT_IN_APP_UPDATE_FAILED` must keep the user blocked. A callback that only logs is a fail.
   - **Is there a foreground recheck?** Look for an `onResume()` (or a lifecycle observer) that calls `getAppUpdateInfo()` and restarts the immediate flow on `DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS`. For backend gates, look for a repeat of the policy check.
5. **Check the comparison itself.** Code such as `versionName.compareTo(min) < 0`, `Float.parseFloat(versionName)` or a `split(".")` without numeric parsing is a bug. A `Long` comparison of the version code against the policy minimum is correct.

#### Observation

A list of code locations with class and method: the version source (`getPackageInfo`, an inlined literal), the policy fetch, the comparison, the enforcement action (immediate flow, gate activity, dialog), the result callback and the foreground handler. Note the entry points that do *not* pass through the gate.

#### Evaluation

The test **fails** if there is no update-enforcement code at all.

It also fails when the code exists but cannot enforce:

- Only `FLEXIBLE` is used, or the "update required" UI can be dismissed.
- `RESULT_CANCELED` or a failed flow lets the user continue.
- There is no foreground or entry-point recheck. In particular, the `DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS` handling is missing for immediate updates.
- The gate is reachable only from one launcher activity while other exported entry points skip it.
- The version comparison is broken.

It **passes**, statically, when a reachable gate compares a numeric version against a server-supplied minimum, blocks with an immediate flow or a non-dismissible screen, re-blocks on cancel or failure, and runs at every entry point. Treat a static pass as provisional until MASTG-TEST-0382 and the two GT tests below confirm it. In particular, a Play-only implementation passes this test and still fails open for non-Play installs. Record that as a limitation.

#### Demo

*Guler Tech example. OWASP has no demo for this test.* The app asks Play for an update but uses the flexible flow, and its own "mandatory" dialog can be dismissed:

```kotlin
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val manager = AppUpdateManagerFactory.create(this)
    manager.appUpdateInfo.addOnSuccessListener { info ->
        if (info.updateAvailability() == UpdateAvailability.UPDATE_AVAILABLE &&
            info.isUpdateTypeAllowed(AppUpdateType.FLEXIBLE)) {
            manager.startUpdateFlowForResult(info, launcher,
                AppUpdateOptions.defaultOptions(AppUpdateType.FLEXIBLE))   // user can decline
        }
    }
    if (remoteConfig.getLong("min_version_code") > BuildConfig.VERSION_CODE) {
        AlertDialog.Builder(this)
            .setMessage(R.string.update_required)
            .setPositiveButton(R.string.update) { _, _ -> openPlayStore() }
            .setNegativeButton(R.string.later, null)                      // "mandatory" but skippable
            .show()
    }
}
// no onResume() recheck, launcher callback only logs the result code
```

The search output from the decompiled release build (constants inlined, `5300` is the version code):

```text
out/sources/com/example/app/ui/SplashActivity.java
41:        AppUpdateManager create = AppUpdateManagerFactory.create(this);
42:        create.getAppUpdateInfo().addOnSuccessListener(new SplashActivity$$ExternalSyntheticLambda0(create, this));
58:        if (appUpdateInfo.updateAvailability() == 2 && appUpdateInfo.isUpdateTypeAllowed(0)) {
59:            appUpdateManager.startUpdateFlowForResult(appUpdateInfo, this.launcher, AppUpdateOptions.defaultOptions(0));
66:        if (this.remoteConfig.getLong("min_version_code") > 5300) {
```

Three findings: flexible type `0` where the policy is mandatory, a dismissible dialog, and no recheck outside `SplashActivity`.

### MASTG-TEST-0382: Runtime Use of Enforced Updating APIs (Android)

Source: [MASTG-TEST-0382](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0382/). Platform: Android. Type: dynamic (network, hooks) with manual review. Knowledge: MASTG-KNOW-0023. Replaces (with 0392): MASTG-TEST-0036.

#### Overview

This test confirms at runtime what the static test suggested. It checks whether the app actually runs its update check, whether it happens before protected features or API calls, which version it reports and what the backend answers, and whether the enforcement holds when the user cancels, backgrounds the app or comes back through another entry point.

#### Prerequisites

- A rooted test device or emulator with Google Play (needed for the Play flow) and the app installed ([MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/): `adb install` or `adb install-multiple` for split APKs).
- Traffic capture through a proxy ([MASTG-TECH-0010](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0010/)).
- Frida for method hooking ([MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)).
- For the real immediate flow: an older Play-signed build plus a Play account that owns the app, or the vendor's internal app sharing set-up (see [test setup](#before-you-start-test-setup)).

#### Steps

1. **Trace the update logic.** Save the script below as `update-trace.js`. It logs Play In-App Updates calls and the app's own `PackageInfo` reads with a short backtrace, and it changes nothing:

   ```javascript
   // update-trace.js: log Play In-App Updates calls and version reads (read-only)
   Java.perform(() => {
     const Log = Java.use('android.util.Log');
     const Ex = Java.use('java.lang.Exception');
     const bt = () => Log.getStackTraceString(Ex.$new()).split('\n').slice(2, 7).join('\n');
     let pkg = null;   // resolved lazily: the Application does not exist yet when frida spawns the app
     const self = () => pkg || (pkg = Java.use('android.app.ActivityThread').currentPackageName());

     const Info = Java.use('com.google.android.play.core.appupdate.AppUpdateInfo');
     Info.isUpdateTypeAllowed.overloads.forEach(o => {
       o.implementation = function () {
         const r = o.apply(this, arguments);
         console.log(`[IAU] isUpdateTypeAllowed(${arguments[0]}) -> ${r} | availability=${this.updateAvailability()} ` +
           `priority=${this.updatePriority()} staleness=${this.clientVersionStalenessDays()} ` +
           `available=${this.availableVersionCode()}\n${bt()}`);
         return r;
       };
     });

     const Factory = Java.use('com.google.android.play.core.appupdate.AppUpdateManagerFactory');
     const hooked = {};
     Factory.create.implementation = function (ctx) {
       const mgr = this.create(ctx);
       const cls = mgr.$className;
       if (!hooked[cls]) {
         hooked[cls] = true;
         Java.use(cls).startUpdateFlowForResult.overloads.forEach(o => {
           o.implementation = function () {
             let type = '?';
             for (const a of arguments) {
               if (typeof a === 'number') { type = a; break; }
               try { type = a.appUpdateType(); break; } catch (e) { /* not AppUpdateOptions */ }
             }
             console.log(`[IAU] startUpdateFlowForResult type=${type} (1=IMMEDIATE, 0=FLEXIBLE)\n${bt()}`);
             return o.apply(this, arguments);
           };
         });
       }
       console.log(`[IAU] AppUpdateManagerFactory.create -> ${cls}`);
       return mgr;
     };

     const APM = Java.use('android.app.ApplicationPackageManager');
     APM.getPackageInfo.overloads.forEach(o => {
       o.implementation = function () {
         const pi = o.apply(this, arguments);
         if (String(arguments[0]) === String(self())) {
           console.log(`[ver] getPackageInfo(self) -> ${pi.versionName.value} / ${pi.getLongVersionCode()}\n${bt()}`);
         }
         return pi;
       };
     });
   });
   ```

   ```bash
   frida -U -f com.example.app -l update-trace.js
   ```

   If the app has been obfuscated so that the class names above do not exist, take the renamed names from jadx and adjust them.

2. **Capture the policy traffic.** Cold-start the app through the proxy and identify the policy request and every place a version appears. Typical locations are headers (`X-App-Version`, `X-App-Build`, `X-Client-Version`), a custom `User-Agent` (OkHttp's default `okhttp/4.x` carries no app version), JSON fields, Remote Config fetches (`firebaseremoteconfig.googleapis.com`) and token requests.
3. **Trigger the gate.** Use one of the levers from the [test setup](#before-you-start-test-setup). Rewrite the policy response so the minimum is above the installed version, or install the older Play-signed build so Play reports `UPDATE_AVAILABLE`. Note what appears: the Play immediate UI, Play's flexible dialog, or the app's own screen.
4. **Try to get past it as a user would.**
   - Cancel the Play immediate flow (its close button, or the back key). Watch the result in your trace and see whether the app blocks again.
   - Press back or tap outside the app's own dialog.
   - Start the immediate update, press Home before it finishes, then return. `onResume()` should restart the flow (`DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS`).
   - Background the app and kill its process (`adb shell am kill com.example.app` while it is in the background, or enable "Don't keep activities" in developer options), then return from Recents. Android restores the last activity without passing through the splash screen.
   - Open the app through other entry points: deep links (`adb shell am start -a android.intent.action.VIEW -d 'https://app.example.com/...'`), notifications, app shortcuts and widgets.
5. **Check what the backend does** while the gate is active. If the app still loads data behind a dialog, or the network log shows normal API calls with the outdated version, carry on with [GT-CODE-0043-1](#gt-code-0043-1-backend-accepts-outdated-app-versions-android-ios).

#### Observation

- The network trace: the policy request with the version values, the policy response, and the API calls made before and after the gate appears.
- The Frida log: `getAppUpdateInfo` and `isUpdateTypeAllowed` results, the update type passed to `startUpdateFlowForResult`, version reads with backtraces, and the result of each escape attempt.
- Screenshots or a screen recording of the gate and of anything reachable past it.

#### Evaluation

The test **fails** in any of these cases:

- No update check runs at runtime.
- The check runs only after the app has already reached protected features or sent authenticated API calls.
- The gate can be passed by cancelling, dismissing, backgrounding, restoring after process death or entering through another entry point.
- A rewritten policy response or a lowered version produces no enforcement.

It **passes** when an update-required state reliably blocks every path into the app and survives cancellation and process restoration. Ideally the immediate flow is restarted from `onResume()`. Keep the backend question separate. A perfect client gate with a backend that serves old versions is still a finding under GT-CODE-0043-1.

#### Demo

*Guler Tech example. OWASP has no demo for this test.* Trace from the vulnerable app in the 0392 demo, with an older Play-signed build installed:

```text
[IAU] AppUpdateManagerFactory.create -> com.google.android.play.core.appupdate.zzg
[ver] getPackageInfo(self) -> 5.2.0 / 5200
    at com.example.app.config.VersionHeaderInterceptor.intercept(VersionHeaderInterceptor.java:22)
[IAU] isUpdateTypeAllowed(0) -> true | availability=2 priority=5 staleness=3 available=5300
    at com.example.app.ui.SplashActivity.onUpdateInfo(SplashActivity.java:58)
[IAU] startUpdateFlowForResult type=0 (1=IMMEDIATE, 0=FLEXIBLE)
    at com.example.app.ui.SplashActivity.onUpdateInfo(SplashActivity.java:59)
```

Play marks the release priority 5 (critical) and the app still requests a flexible flow. The user taps "No thanks" in Play's dialog, the app continues, and the proxy shows `GET /v2/accounts` answered `200` with `X-App-Build: 5200`. The implementation class name (`zzg` here) is obfuscated library code and differs between library versions.

### MASTG-TEST-0383: References to Enforced Updating APIs (iOS)

Source: [MASTG-TEST-0383](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0383/). Platform: iOS. Type: static (code) with manual review. Knowledge: MASTG-KNOW-0074. Replaces (with 0384): MASTG-TEST-0080.

#### Overview

Because iOS has no update API, this test looks for the pieces of a home-made gate in the binary. These are a version read (`CFBundleShortVersionString` or `CFBundleVersion`), a source for the required version (iTunes lookup or a policy endpoint), a comparison, a blocking UI and a redirect to the App Store. The test then checks whether the gate runs early enough and is truly blocking.

#### Prerequisites

- The decrypted IPA, unpacked ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)). App Store binaries are FairPlay-encrypted and must be dumped from a jailbroken device first.
- `plutil`, `strings`, `otool`, `nm` and [radare2](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/) or a disassembler for the search ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/)) and the review ([MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)).

#### Steps

1. **Read the version and bundle ID.**

   ```bash
   unzip -q App.ipa -d ipa
   APP=ipa/Payload/App.app; BIN="$APP/App"
   plutil -p "$APP/Info.plist" | grep -E 'CFBundleIdentifier|CFBundleShortVersionString|CFBundleVersion|MinimumOSVersion'
   ```

2. **Search the main binary and the embedded frameworks for lookup and policy strings.**

   ```bash
   for f in "$BIN" "$APP"/Frameworks/*.framework/*; do
     [ -f "$f" ] && strings -a "$f" | grep -iE 'itunes\.apple\.com/lookup|apps\.apple\.com|itms-apps|trackViewUrl|minimumOsVersion|CFBundleShortVersionString|min_?version|minimum_?version|force_?update|update_?required|min_?build' | sed "s|^|$(basename "$f"): |"
   done | sort -u
   ```

   Swift stores strings of up to 15 UTF-8 bytes *inline in the instructions* (small-string optimisation), not in `__cstring`. So `"minVersion"` or `"forceUpdate"` may not show up in `strings` at all, while longer ones (`"CFBundleShortVersionString"`, URLs) do. An empty grep is not proof of absence. Fall back to symbols and cross-references (step 3) and to the dynamic test. For React Native, search `main.jsbundle`. For Flutter, search `Frameworks/App.framework/App`.

3. **Look for StoreKit and the UI pieces.**

   ```bash
   otool -L "$BIN" | grep -i storekit
   nm -u "$BIN" | grep -E 'SKStoreProductViewController|SKStoreProductParameterITunesItemIdentifier'
   nm "$BIN" 2>/dev/null | grep -iE 'update|version' | grep -viE 'protobuf|grpc' | head -50     # unstripped Swift/ObjC symbols, if any
   r2 -A -qc 'izz~itunes' "$BIN"                                                              # address of the lookup URL string
   ```

   Then, in an interactive `r2 -A "$BIN"` session, run `axt @ <address>` on that string to list the functions that use it.

   An undefined `_OBJC_CLASS_$_SKStoreProductViewController` symbol means the class is used. A `Siren` framework or symbols from it point to the library. Check its configured alert type in the call site (it can be skippable).

4. **Review the call sites** ([MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)):
   - **When does the check run?** Look at `application(_:didFinishLaunchingWithOptions:)` and `scene(_:willConnectTo:options:)`. Look for a foreground hook (`sceneWillEnterForeground(_:)`, `applicationWillEnterForeground(_:)`, `willEnterForegroundNotification`). Check whether universal links and URL schemes (`scene(_:continue:)`, `scene(_:openURLContexts:)`) reach content without passing the gate.
   - **What does it compare?** It should compare `CFBundleShortVersionString` against the lookup `version` numerically (`compare(_:options:)` with `.numeric`), or `CFBundleVersion` against a server `min_build`. Comparing `CFBundleVersion` with the lookup's `version`, or comparing strings directly, is a bug.
   - **How does it block?** The alert must have no `.cancel` action (look for a single `UIAlertAction` and re-presentation after `open`), or the gate must be a root view controller. A gate presented as a sheet needs `isModalInPresentation`.
   - **What happens on failure?** Check what happens on empty `results`, network errors and decode failures.

#### Observation

Code locations for the version read, the policy or lookup request, the comparison, the alert or gate controller and the redirect (`UIApplication.open` with `trackViewUrl`, or `SKStoreProductViewController`). Also record the life-cycle methods that call them, and the entry points that do not.

#### Evaluation

The test **fails** if there is no update-enforcement code at all.

It also fails if:

- The only UI is dismissible ("Later" action, swipe-down sheet).
- The check runs only once per process launch, with no foreground recheck, while the app can stay in memory for days.
- The comparison is wrong.
- Failures (empty lookup, network error) are treated as "up to date" for a version the app has already learnt is unsupported.

A lookup-only design that forces *every* release passes the letter of the test, but it is often switched off by product teams within a release or two. Note in the report that it gives no way to say "only versions below X". It **passes** when a server-controlled minimum (or a lookup with sensible handling) drives a non-dismissible gate at launch and on every return to the foreground.

#### Demo

*Guler Tech example. OWASP has no demo for this test.* A lookup-based check with a "Later" button that only runs at launch:

```swift
func checkForUpdate() {
    let url = URL(string: "https://itunes.apple.com/lookup?bundleId=com.example.app")!   // no country
    URLSession.shared.dataTask(with: url) { data, _, _ in
        guard let data,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let result = (json["results"] as? [[String: Any]])?.first,
              let storeVersion = result["version"] as? String,
              let installed = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String
        else { return }                                                    // any failure: carry on
        if storeVersion > installed {                                      // string comparison
            DispatchQueue.main.async {
                let alert = UIAlertController(title: "Update available", message: nil, preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: "Update", style: .default) { _ in
                    if let s = result["trackViewUrl"] as? String, let u = URL(string: s) { UIApplication.shared.open(u) }
                })
                alert.addAction(UIAlertAction(title: "Later", style: .cancel))   // skippable
                self.window?.rootViewController?.present(alert, animated: true)
            }
        }
    }.resume()
}
// called once from application(_:didFinishLaunchingWithOptions:)
```

String search on the binary:

```text
App: https://itunes.apple.com/lookup?bundleId=com.example.app
App: CFBundleShortVersionString
App: trackViewUrl
```

Four findings: no `country` parameter, a string comparison (`"5.10.0" > "5.9.0"` is `false`), a `.cancel` action, and no foreground recheck.

### MASTG-TEST-0384: Runtime Use of Enforced Updating APIs (iOS)

Source: [MASTG-TEST-0384](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0384/). Platform: iOS. Type: dynamic (network, hooks) with manual review. Knowledge: MASTG-KNOW-0074. Replaces (with 0383): MASTG-TEST-0080.

#### Overview

This test confirms at runtime that the app reads its version, asks the lookup or policy service, and enforces the result. The main manipulations are advertising a higher store version, raising the policy minimum and lowering the version the app reports. Each should produce a gate the user cannot get past.

#### Prerequisites

- A test device with the app installed ([MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), for example with `ideviceinstaller` or Sideloadly). Use a jailbroken device for Frida, or a re-signed build with Frida Gadget.
- Traffic capture through a proxy with the proxy CA trusted on the device ([MASTG-TECH-0062](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0062/)).
- Frida for hooking ([MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/)).

#### Steps

1. **Trace version reads, lookups and redirects.** Save as `ios-update-trace.js`:

   ```javascript
   // ios-update-trace.js: log version reads, update-related requests and App Store redirects (read-only)
   const bt = ctx => Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 6)
     .map(DebugSymbol.fromAddress).join('\n    ');

   Interceptor.attach(ObjC.classes.NSBundle['- objectForInfoDictionaryKey:'].implementation, {
     onEnter(args) { this.key = new ObjC.Object(args[2]).toString(); },
     onLeave(ret) {
       if (this.key.startsWith('CFBundle') && this.key.includes('Version')) {
         console.log(`[ver] ${this.key} -> ${new ObjC.Object(ret)}\n    ${bt(this.context)}`);
       }
     }
   });

   ['- dataTaskWithRequest:completionHandler:', '- dataTaskWithURL:completionHandler:'].forEach(sel => {
     Interceptor.attach(ObjC.classes.NSURLSession[sel].implementation, {
       onEnter(args) {
         const o = new ObjC.Object(args[2]);
         const url = (o.$className.includes('URLRequest') ? o.URL() : o).absoluteString().toString();
         if (/lookup|version|config|policy|update/i.test(url)) console.log(`[net] ${url}\n    ${bt(this.context)}`);
       }
     });
   });

   Interceptor.attach(ObjC.classes.UIApplication['- openURL:options:completionHandler:'].implementation, {
     onEnter(args) { console.log(`[store] openURL ${new ObjC.Object(args[2]).absoluteString()}`); }
   });
   if (ObjC.classes.SKStoreProductViewController) {
     Interceptor.attach(ObjC.classes.SKStoreProductViewController['- loadProductWithParameters:completionBlock:'].implementation, {
       onEnter(args) { console.log(`[store] SKStoreProductViewController ${new ObjC.Object(args[2])}`); }
     });
   }
   Interceptor.attach(ObjC.classes.UIAlertController['- addAction:'].implementation, {
     onEnter(args) {
       const a = new ObjC.Object(args[2]);
       console.log(`[ui] alert action "${a.title()}" style=${a.style()} (1 = cancel)`);
     }
   });
   ```

   ```bash
   frida -U -f com.example.app -l ios-update-trace.js
   ```

   Swift code that reads `Bundle.main.infoDictionary?["CFBundleShortVersionString"]` goes through `- infoDictionary` instead of `objectForInfoDictionaryKey:`. Hook that too if the first hook stays silent, and filter the backtrace on the app module, because system frameworks call it constantly. Requests made with Swift `async` APIs (`data(for:)`) may not pass through the two `dataTask` selectors. The proxy log is the reliable record, and the hooks add the backtraces.

2. **Capture the policy traffic** from a cold start. Note the lookup request (with or without `country`), the policy request, the version fields and the default `User-Agent` build number.
3. **Trigger the gate.**
   - *Lookup flow:* in the proxy, rewrite the lookup response so `results[0].version` is higher than the installed version (for example with a Burp "Match and replace" rule on the response body, `"version":"5.3.0"` to `"version":"9.0.0"`).
   - *Policy flow:* rewrite the policy minimum above the installed version.
   - *Backend flow:* lower the version in requests and see whether the backend returns its update-required error and the app turns it into the gate.
4. **Try to get past the gate as a user would.**
   - Swipe the gate down.
   - Tap any secondary action.
   - Send the app to the background and bring it back.
   - Leave the app idle in the background for longer than any cache TTL.
   - Open it from a universal link, a push notification or a home-screen quick action.
   - Kill it and relaunch it in airplane mode.
5. **Check the redirect.** "Update" should open the correct product page (`trackViewUrl` or the right `trackId`), and returning to the app without updating should show the gate again.

#### Observation

The proxy log of the lookup and policy requests and responses (original and rewritten), the Frida log of version reads, requests, alert actions and store redirects with backtraces, and screenshots or recordings of each escape attempt.

#### Evaluation

The test **fails** in any of these cases:

- No update check runs.
- The rewritten lookup, policy or backend response produces no block.
- The block can be dismissed, or is lost on background and foreground or on a different entry point.
- The app reaches authenticated APIs before the check completes.

It **passes** when each manipulation produces a non-dismissible gate at every entry point, with a working redirect to the App Store. As on Android, the client passing this test does not settle the backend question (GT-CODE-0043-1).

#### Demo

*Guler Tech example. OWASP has no demo for this test.* Trace of the 0383 demo app with the lookup response rewritten to `9.0.0`:

```text
[net] https://itunes.apple.com/lookup?bundleId=com.example.app
    0x1000a4c1c App!UpdateChecker.checkForUpdate()
    0x10009f2e0 App!AppDelegate.application(_:didFinishLaunchingWithOptions:)
[ver] CFBundleShortVersionString -> 5.2.0
[ui] alert action "Update" style=0 (1 = cancel)
[ui] alert action "Later" style=1 (1 = cancel)
```

Tapping "Later" dismisses the alert and the app works normally. Sending it to the background and back shows no gate, because the check runs only at launch. Symbol names appear only if the build is not stripped. Otherwise you see module offsets, which you resolve in the disassembler.

### GT-CODE-0043-1: Backend accepts outdated app versions (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

This test checks whether the app's own backend refuses requests from versions below its minimum. This is the half of MASVS-CODE-2 that a client gate cannot provide. It covers app versions released before the gate existed, gates that fail open, and anyone who keeps an old client deliberately. The legacy OWASP tests asked for this ("validating whether the backend will stop calls to vulnerable backends and/or whether the vulnerable app-version itself is blocked by the backend"). The v2 tests mention it only as further validation. Type: dynamic, network (proxy-based), manual.

#### Prerequisites

- An intercepting proxy with the app's traffic visible and a **test account you own**. Only the app's own API endpoints that are in scope.
- The vendor's stated minimum version per platform. If the vendor has none, read it from the policy response, or record "no minimum defined", which is itself the finding.
- Ideally an older build (see [test setup](#before-you-start-test-setup)).
- Agreement on request volume. A few dozen replayed requests are enough, so this is not a load test.

#### Steps

1. **Inventory the version signals.** Run through launch, login, token refresh and the main features with the current build, then list every place the version travels: custom headers, `User-Agent` (on iOS the default contains `CFBundleVersion`), query parameters, JSON fields, GraphQL `extensions`, gRPC metadata, claims inside access tokens (decode them), and attestation tokens. A Play Integrity token is encrypted and opaque to you, but its presence tells you the server *could* check `appIntegrity.versionCode`.
2. **List the services.** Group the requests by host and path prefix: API gateway, identity and token endpoint, GraphQL, payments, messaging, WebSocket upgrade, file upload. Version checks are often implemented in one service and forgotten in the others.
3. **Take a baseline.** Pick one read-only authenticated request per service (for example `GET /v2/me`) and replay it unchanged in Repeater. Expect `200`.
4. **Replay with outdated versions.** For each baseline request, change *only* the version signal and record status and body:
   - the minimum minus one (`X-App-Build: 5299` if the minimum is 5300);
   - a very old version (`1.0.0`, build `1`);
   - the header removed altogether;
   - a malformed value (`abc`, empty, `5.3.0.0.0`);
   - if the server reads several signals, each one changed on its own (header only, `User-Agent` only), so you know which one it uses.

   Do the same for the **token refresh** request. An old client that can still refresh its session keeps working indefinitely even if other endpoints are gated.
5. **Check one benign state-changing request**, such as setting your own display name to its current value, with an outdated version. Some backends check versions only on reads.
6. **Check old API versions.** If the app calls `/v2/...`, request the same resource at `/v1/...` with your own session. A legacy route that still answers is an old contract the version gate never sees.
7. **With an older build, if you have one:** log in with your test account and use it normally. Then use the proxy to *raise* its version header to the current value. If the server accepts it, the server trusts the header alone. That is expected without attestation, but it is a finding if the vendor claims attestation-based enforcement, because the attested `versionCode` from the old build should have been rejected.
8. **Note what the app does** with the server's error, if there is one. It should show the same gate as GT-CODE-0043-2 expects, not a generic "Something went wrong" that the user can retry around.

#### Observation

A table of request, service, version signal sent, status, and whether data was returned or the action was performed. For example:

```text
service        request                  X-App-Build   status  result
gateway        GET  /v2/me              5300          200     profile returned (baseline)
gateway        GET  /v2/me              5299          403     {"error":"app_version_unsupported","min_build":5300}
gateway        GET  /v2/me              (removed)     200     profile returned
identity       POST /oauth/token        1             200     new access + refresh token
payments       GET  /v2/payees          5299          200     payee list returned
legacy         GET  /v1/me              5299          200     profile returned
```

#### Evaluation

The test **fails** if any in-scope service processes a request, returning data or performing the action, that carries:

- a version below the stated minimum;
- no version at all, once the versions that predate the header are supposed to be retired; or
- an outdated version on the token or refresh endpoint.

It also fails when the server marks the response with an update-required flag or header **and still processes it**, and when a retired API version still answers.

It **passes** when every service, or a gateway in front of all of them, consistently refuses outdated or missing versions with an explicit error the app turns into its gate, and the token endpoint refuses to issue or refresh tokens for them.

Accepting a *raised* fake version is not a failure by itself, because headers are client-controlled. Report it as residual risk unless the vendor relies on attestation. If the vendor has no minimum version at all, report the absence of server-side enforcement. Its severity then depends on whether known-vulnerable versions exist in the field (see [Rating findings](#rating-findings)).

#### Demo

*Guler Tech example.* A gateway middleware that signals but serves, and the fixed version (Node.js/Express):

```javascript
// Vulnerable: flags the response, still runs the handler; missing header counts as "latest"
app.use((req, res, next) => {
  const build = parseInt(req.get('X-App-Build') || '999999', 10);
  if (build < MIN_BUILD[req.get('X-Platform')]) res.set('X-Update-Required', 'true');
  next();
});

// Fixed: refuse before any handler runs; missing or malformed version is unsupported
app.use((req, res, next) => {
  const min = MIN_BUILD[req.get('X-Platform')];
  const build = Number.parseInt(req.get('X-App-Build'), 10);
  if (!min || !Number.isInteger(build) || build < min) {
    return res.status(403).json({ error: 'app_version_unsupported', min_build: min ?? null });
  }
  next();
});
```

The replay in step 4 against the vulnerable middleware returns `200` with `X-Update-Required: true` and the full profile body. That is a fail even though the app shows a gate when it sees the header.

### GT-CODE-0043-2: Update gate fails open or can be skipped (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

This test checks whether the client gate keeps blocking when its inputs are missing or unfavourable: no network, an unreachable or broken policy service, unactivated remote-config defaults, a non-Play install. It also checks whether a tester can find the single decision point and confirm that bypassing it is the *only* thing standing between an old client and the backend. The aim is detection, not a bypass recipe. Every step either observes the app's own behaviour or temporarily changes it on your own test device, to see what the rest of the system does. Type: dynamic, network, hooks, manual.

#### Prerequisites

- The gate identified and triggerable (MASTG-TEST-0382 or 0384), the policy endpoint known, and the proxy and Frida set up.
- A test device you control, a test account, and the ability to switch network off (airplane mode) and to make the proxy drop or alter specific requests.

#### Steps

1. **Unreachable policy service.** Cold-start the app with the proxy set to fail the policy request: drop the connection, return `503`, delay it beyond the app's timeout, and return malformed JSON (`{`). With mitmproxy you can use a small addon on the policy path, and in Burp you can intercept the request and drop it. Note whether the app proceeds, retries or blocks.
2. **Offline cold start, no cached policy.** Clear app data (`adb shell pm clear com.example.app`, or delete and reinstall on iOS), enable airplane mode and launch. Proceeding is usually an acceptable availability trade-off if the server enforces. Note the behaviour.
3. **Offline cold start after "update required".** Trigger the gate once while online (rewrite the policy minimum), kill the app, enable airplane mode and relaunch. A well-built gate persists the "unsupported" decision and keeps blocking. If the app forgets it and runs offline features, including access to locally stored data, record that.
4. **Remote Config defaults.** If the gate uses Firebase Remote Config, find the in-app default for the minimum-version key (`res/xml/*.xml` or the `setDefaultsAsync` call) and the configured fetch interval. Block `firebaseremoteconfig.googleapis.com` in the proxy, clear data and launch. If the default is `0` and the gate reads it before activation, the gate never fires on a fresh install.
5. **Non-Play install (Android).** If the gate is Play-only, install the same APK set by `adb install-multiple` on a device or profile where the Play account does not own the app, or on an emulator image without Google Play. Note whether `getAppUpdateInfo()` fails or reports no update, and whether the app then runs. Some apps check `getInstallSourceInfo()` (API 30 and later) or `getInstallerPackageName()`. Note what they do with a non-Play installer.
6. **Find the single decision point.** From the static review and the backtraces of the trace scripts, identify the method that turns "policy plus installed version" into "block or continue" (for example `UpdatePolicy.isUpdateRequired()`, or a Swift `UpdateChecker.mustUpdate(_:)`). Record its class or symbol and its callers.
7. **Verify what remains when that decision is overridden.** On your test device only, temporarily make that method report "not required" with a Frida hook (`Java.use('com.example.app.update.UpdatePolicy').isUpdateRequired.implementation = function () { return false; };` on Android, or an `Interceptor.replace` of the resolved Swift function on iOS), while the proxy keeps sending an outdated version. The client bypass is expected to work, because MAS-ATTACK-0040 cannot be prevented on a device the attacker controls. The **observation that matters is the backend's answer**. If authenticated calls with the outdated version succeed, the whole control rests on client code. Link this result to GT-CODE-0043-1.

#### Observation

For each step, the policy request and response as seen by the proxy, whether the gate appeared, whether authenticated API calls followed, and the method or symbol identified as the decision point. For step 7, record the API responses observed while the decision was overridden.

#### Evaluation

The test **fails** if any of these hold:

- A policy failure (step 1) lets an app that is otherwise gated reach authenticated features while the backend serves outdated versions.
- A once-learnt "update required" state is lost offline (step 3) and gives access to sensitive local data or functions.
- Remote Config defaults or a missing Play Store silently disable the gate (steps 4 and 5) for a whole class of installs.
- Step 7 shows that the only enforcement is the client decision, because the backend accepts the outdated version.

Fail-open behaviour on a cold start with no cached policy (step 2) is a design trade-off. It is a pass **if** the backend enforces (GT-CODE-0043-1 passes), and part of the same finding if it does not. Being able to hook the decision method is never a finding on its own.

#### Demo

*Guler Tech example.* A gate that treats every failure as "no update needed":

```kotlin
suspend fun isUpdateRequired(): Boolean = try {
    val policy = api.fetchUpdatePolicy()                  // GET /config/mobile-policy
    policy.minVersionCode > BuildConfig.VERSION_CODE
} catch (e: Exception) {
    false                                                 // offline, 5xx, bad JSON: let the user in
}
```

With the policy request dropped in the proxy, the app opens to the home screen, and the following `GET /v2/me` with `X-App-Build: 5200` returns `200`. Fixed version: on failure, fall back to the last persisted policy, if one exists and is still within its validity period. If the persisted policy marks this version unsupported, keep blocking. The backend refusal from GT-CODE-0043-1 covers the rest.

## Secure implementation

OWASP has no MASTG best-practice page for enforced updating yet. These are the patterns we expect to see.

### Minimum-version policy on the backend

- One policy per platform and channel. For example:

  ```json
  {
    "platform": "android",
    "min_supported_build": 5300,
    "latest_build": 5310,
    "mandatory": true,
    "reason": "security",
    "store_url": "https://play.google.com/store/apps/details?id=com.example.app",
    "message_key": "update_required_security",
    "valid_until": "2026-12-31T00:00:00Z"
  }
  ```

- **Enforce it in one place every request passes through**: an API gateway or shared middleware, including the identity provider's token and refresh endpoints. Answer outdated clients with a documented error the app turns into its gate. Do not run the handler.
- **Read the version from attestation where possible.** On Android, read `appIntegrity.versionCode` from a server-verified Play Integrity verdict. Use headers as the fallback for honest clients.
- **Retire old API versions** on a schedule, and remove their code paths. A version gate in front of a deployed legacy endpoint is weaker than removing it.
- **Monitor** the version distribution of incoming requests, so the team knows how many users a new minimum will lock out before raising it.

### Android client gate

Combine Play's immediate flow, where it is available, with the server policy, which covers everything else. Run it from a base activity's `onResume()` or a process-wide lifecycle observer, so every entry point and every return to the foreground passes through it:

```kotlin
private val updateLauncher =
    registerForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) { result ->
        if (result.resultCode != RESULT_OK) showUpdateRequiredScreen()   // cancelled or failed: stay blocked
    }

override fun onResume() {
    super.onResume()
    val required = policyRepository.cachedOrFetched().minSupportedBuild > BuildConfig.VERSION_CODE
    appUpdateManager.appUpdateInfo
        .addOnSuccessListener { info ->
            val immediate = AppUpdateOptions.defaultOptions(AppUpdateType.IMMEDIATE)
            when {
                info.updateAvailability() == UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS ->
                    appUpdateManager.startUpdateFlowForResult(info, updateLauncher, immediate)
                required && info.updateAvailability() == UpdateAvailability.UPDATE_AVAILABLE &&
                    info.isUpdateTypeAllowed(AppUpdateType.IMMEDIATE) ->
                    appUpdateManager.startUpdateFlowForResult(info, updateLauncher, immediate)
                required -> showUpdateRequiredScreen()        // non-Play install or no compatible update
            }
        }
        .addOnFailureListener { if (required) showUpdateRequiredScreen() }   // no Play: rely on the policy
}
```

`showUpdateRequiredScreen()` starts a full-screen activity with `FLAG_ACTIVITY_NEW_TASK or FLAG_ACTIVITY_CLEAR_TASK`, overrides back handling (`OnBackPressedCallback`) and offers only "Update" (a Play Store link, or the channel's update URL). `policyRepository` persists the last policy so the gate survives offline restarts. In production, `cachedOrFetched()` should not block the main thread. Load the policy before the first screen renders. Use `FLEXIBLE` for non-mandatory releases, with the `InstallStatus.DOWNLOADED` check and `completeUpdate()` described above.

### iOS client gate

```swift
func isBelowMinimum(_ installed: String, _ minimum: String) -> Bool {
    installed.compare(minimum, options: .numeric) == .orderedAscending
}

func enforceUpdatePolicy(_ policy: UpdatePolicy, in window: UIWindow) {
    let installed = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
    guard isBelowMinimum(installed, policy.minimumVersion) else { return }
    window.rootViewController = UpdateRequiredViewController(storeURL: policy.storeURL)  // nothing underneath
    window.makeKeyAndVisible()
}
```

Call it from `scene(_:willConnectTo:options:)` and `sceneWillEnterForeground(_:)`, and also when any API call returns `app_version_unsupported`. Persist the last policy. `UpdateRequiredViewController` offers one button that opens the store URL (or presents `SKStoreProductViewController`) and nothing else. If you use the iTunes lookup as well, pass `country`, treat empty results as "unknown", not "up to date", and leave the hard decision to the server's minimum.

### Release process

- Raise the minimum only after the new version is available to **everyone** who is supposed to install it. On Play that means after a staged rollout has reached 100%. Users outside the rollout percentage cannot get the update, so a gate would lock them out. On iOS, a phased release does not restrict manual updates, but the build must be live in every storefront you serve.
- If a release raises `minSdkVersion` or `MinimumOSVersion`, decide what users on older devices see. "Update" is impossible for them. Show "This device is no longer supported", and make that a server decision.
- For a security-critical release on Play, set `inAppUpdatePriority` (for example 5) through the Play Developer API when you publish, because it cannot be added later. Consider the Play Console "prompt users to update" recovery action for versions that predate the in-app update code.
- Make sure the gate never blocks the build that is under store review.

## Rating findings

The weakness is profiled L2 and EUDIW. In an L1 assessment, missing enforcement is normally a recommendation. In an L2 assessment it is a finding. Rate on three things:

- **Exposure:** is there a known security issue in a version that users still run, and that the backend still serves?
- **Who is protected:** does the control fail for honest users (MAS-ATTACK-0053), only for deliberate attackers (MAS-ATTACK-0040), or for both?
- **Backend role:** does the server stop it?

The attacker position is whatever the old vulnerability needs. User interaction is "the user did not update", which needs no action at all.

| Rating | Conditions |
|---|---|
| **Critical** | Not for this weakness on its own. Use it for a chain: a known, exploitable Critical issue in a version still in use (for example a trust-all `TrustManager` fixed in the current release, or a leaked key the vendor has rotated) **and** neither the client nor the backend can retire that version. Rate the chain, and cite this weakness as the reason it is still exploitable. |
| **High** | L2 or EUDIW app (banking, payments, health, identity) with no enforcement at all: no client gate and a backend that serves every version. Or the vendor has declared versions unsupported for a security reason, and the backend (including the token and refresh endpoint) still serves them. Or a retired, weaker API version (`/v1`) still answers for authenticated users. |
| **Medium** | A client gate exists but the backend does not enforce (GT-CODE-0043-1 fails) and no known-vulnerable version is identified. A mandatory update can be skipped through "Later", cancelling the immediate flow, background and foreground, process restoration or a deep-link entry point. The gate fails open for a whole class of installs (non-Play, Remote Config defaults) or forgets an "unsupported" state offline. Only `FLEXIBLE` is used for releases marked critical. |
| **Low** | Server and client enforcement exist, with gaps of limited reach: no foreground recheck while the backend still refuses old versions; string or float version comparison that misorders only rare version numbers; lookup without `country`; long policy cache times. Or an L1 app with no mechanism. |
| **Info** | The client gate can be hooked or patched on a rooted or jailbroken device while the backend enforces (expected, MAS-ATTACK-0040). A version header can be raised by the client without attestation. Reliance on the Play Console recovery prompt alone in a low-risk app. Unmaintained helper libraries (Siren), cross-referenced to MASWE-0044. Apps with no backend, where only the client gate is possible: note it as a design limitation. |

Raise one level when you can name a fixed, publicly known vulnerability in a version that still works against production, or when old builds embed secrets or pins the vendor has rotated. Lower one level when the vendor shows that old versions are a negligible share of traffic *and* the backend refuses them. Do not lower a level because "most users have auto-update on". In the report, give the minimum version the vendor states, the version signals the backend reads, the exact replayed request and response that succeeded (with your test account and the version values), the entry points or conditions that skip the client gate, the code location of the decision method, and the fix: server-side refusal first, then the client gate.

## References

- OWASP MASWE: [MASWE-0043: Enforced Updating Not Implemented](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0043/); related [MASWE-0041](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0041/), [MASWE-0044](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0044/), [MASWE-0049](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0049/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-CODE-2](https://mas.owasp.org/MASVS/controls/MASVS-CODE-2/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0023](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0023/), [MASTG-KNOW-0074](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0074/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0392](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0392/), [MASTG-TEST-0382](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0382/), [MASTG-TEST-0383](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0383/), [MASTG-TEST-0384](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0384/); legacy [MASTG-TEST-0036](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0036/), [MASTG-TEST-0080](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0080/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0010](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0010/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0062](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0062/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/) (CC BY-SA 4.0)
- OWASP MASTG tools: [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [aapt2 (MASTG-TOOL-0124)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/), [adb (MASTG-TOOL-0004)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/), [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [Burp Suite (MASTG-TOOL-0077)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/), [mitmproxy (MASTG-TOOL-0097)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/) (CC BY-SA 4.0)
- Android Developers: [In-app updates](https://developer.android.com/guide/playcore/in-app-updates), [Support in-app updates (Kotlin or Java)](https://developer.android.com/guide/playcore/in-app-updates/kotlin-java), [Test in-app updates](https://developer.android.com/guide/playcore/in-app-updates/test), API reference for [`AppUpdateManager`](https://developer.android.com/reference/com/google/android/play/core/appupdate/AppUpdateManager), [`AppUpdateInfo`](https://developer.android.com/reference/com/google/android/play/core/appupdate/AppUpdateInfo), [`AppUpdateOptions`](https://developer.android.com/reference/com/google/android/play/core/appupdate/AppUpdateOptions), [`UpdateAvailability`](https://developer.android.com/reference/com/google/android/play/core/install/model/UpdateAvailability), [`FakeAppUpdateManager`](https://developer.android.com/reference/com/google/android/play/core/appupdate/testing/FakeAppUpdateManager); [Play Integrity API verdicts](https://developer.android.com/google/play/integrity/verdicts); [Version your app](https://developer.android.com/studio/publish/versioning)
- Google Play: [Prompt users to update to your latest app version](https://support.google.com/googleplay/android-developer/answer/13812041), [Share app bundles and APKs internally](https://support.google.com/googleplay/android-developer/answer/9844679); Google Play Developer API [`edits.tracks`](https://developers.google.com/android-publisher/api-ref/rest/v3/edits.tracks) (`inAppUpdatePriority`)
- Firebase: [Remote Config](https://firebase.google.com/docs/remote-config)
- Apple: [iTunes Search API (archived)](https://developer.apple.com/library/archive/documentation/AudioVideo/Conceptual/iTuneSearchAPI/index.html), [`SKStoreProductViewController`](https://developer.apple.com/documentation/storekit/skstoreproductviewcontroller), [`UIApplication.open(_:options:completionHandler:)`](https://developer.apple.com/documentation/uikit/uiapplication/open%28_:options:completionhandler:%29), [`DCAppAttestService`](https://developer.apple.com/documentation/devicecheck/dcappattestservice), [App Store Connect: upload builds](https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds/), [App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/)
- IETF: [RFC 9110, section 15.5.22 (426 Upgrade Required)](https://www.rfc-editor.org/rfc/rfc9110#name-426-upgrade-required)
- CWE: [CWE-602](https://cwe.mitre.org/data/definitions/602.html), [CWE-693](https://cwe.mitre.org/data/definitions/693.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
