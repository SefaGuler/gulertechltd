---
title: "Insecure Intents (MASWE-0032)"
date: 2026-11-09 21:03:00 +0000
subcategory: platform
summary: "Testing Android apps for hijackable implicit intents, leaky broadcasts, intent redirection, mutable PendingIntents and trusted activity results."
refs: [MASWE-0032, MASVS-PLATFORM-1, MASVS-STORAGE-2, CWE-927, CWE-940]
tags: [android, masvs-platform, ipc, intents, pending-intent]
---

This note is part of our [MASVS-PLATFORM guide](/mobile/masvs-platform-platform-interaction-guide/) and covers OWASP [MASWE-0032](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0032/): Android apps that send, receive or forward intents in a way another app on the device can take advantage of. Intents are how Android components talk to each other, inside one app and between apps, and every intent an app sends is a question to the system: "who should get this?". If the app leaves the answer open (an implicit intent, an unrestricted broadcast, a mutable `PendingIntent` with an empty base intent), another app can be the one that answers. If it forwards an intent it received without checking it, it lends its own identity to whoever built that intent. This note is also the series' reference for Android IPC. It covers how Binder carries intents, how intent resolution works, what changed between Android 5 and Android 16, how `PendingIntent` fill-in behaves, how activities, services and receivers handle the intents they get, and how `Parcelable` and `Serializable` extras are unpacked. After that come the three OWASP tests with their demos (including the places where the OWASP material is wrong), our detection and exposure checks for intent redirection, broadcasts and activity results, secure patterns, and how to rate what you find. Whether an exported component checks *who* is calling it is covered in [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/). This note is about what the intents carry and where they end up.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Inter-Process Communication (IPC) Mechanisms (MASTG-KNOW-0020)](#android-inter-process-communication-ipc-mechanisms-mastg-know-0020)
  - [Android: Explicit vs Implicit Intents (MASTG-KNOW-0025)](#android-explicit-vs-implicit-intents-mastg-know-0025)
  - [Android: Pending Intents (MASTG-KNOW-0024)](#android-pending-intents-mastg-know-0024)
  - [Android: Activities (MASTG-KNOW-0132)](#android-activities-mastg-know-0132)
  - [Android: Services (MASTG-KNOW-0133)](#android-services-mastg-know-0133)
  - [Android: Broadcast Receivers (MASTG-KNOW-0134)](#android-broadcast-receivers-mastg-know-0134)
  - [Android: Object Serialization (MASTG-KNOW-0021)](#android-object-serialization-mastg-know-0021)
- [Tests](#tests)
  - [Before you start: static triage of intent traffic](#before-you-start-static-triage-of-intent-traffic)
  - [Runtime tracing of the app's own intents](#runtime-tracing-of-the-apps-own-intents)
  - [MASTG-TEST-0372: Implicit Intents Used for Internal App Communication (Android)](#mastg-test-0372-implicit-intents-used-for-internal-app-communication-android)
  - [MASTG-TEST-0374: References to Implicit Intents Carrying Sensitive Extras (Android)](#mastg-test-0374-references-to-implicit-intents-carrying-sensitive-extras-android)
  - [MASTG-TEST-0381: References to Insecure PendingIntent Creation (Android)](#mastg-test-0381-references-to-insecure-pendingintent-creation-android)
  - [GT-0032-1: Intent redirection through exported components (Android)](#gt-0032-1-intent-redirection-through-exported-components-android)
  - [GT-0032-2: Implicit and sticky broadcasts carrying sensitive extras (Android)](#gt-0032-2-implicit-and-sticky-broadcasts-carrying-sensitive-extras-android)
  - [GT-0032-3: Implicit requests for results and results returned to any caller (Android)](#gt-0032-3-implicit-requests-for-results-and-results-returned-to-any-caller-android)
- [Best practices](#best-practices)
  - [MASTG-BEST-0056: Use Explicit Intents for Internal IPC](#mastg-best-0056-use-explicit-intents-for-internal-ipc)
  - [MASTG-BEST-0063: Use Immutable PendingIntents with Explicit Intents](#mastg-best-0063-use-immutable-pendingintents-with-explicit-intents)
  - [Secure patterns (Guler Tech)](#secure-patterns-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0032 applies when an app creates or handles Android intents insecurely, so that another app can intercept, redirect or manipulate its communication. The OWASP requirement is *"The app securely handles intents."* It maps to MASVS-PLATFORM-1 ("The app uses IPC mechanisms securely") and to MASVS-STORAGE-2 ("The app prevents leakage of sensitive data"), because most real findings end with data in the wrong app. The CWEs are [CWE-927](https://cwe.mitre.org/data/definitions/927.html) (Use of Implicit Intent for Sensitive Communication) and [CWE-940](https://cwe.mitre.org/data/definitions/940.html) (Improper Verification of Source of a Communication Channel). Android's own risk catalogue covers the same ground in five pages: [implicit intent hijacking](https://developer.android.com/privacy-and-security/risks/implicit-intent-hijacking), [intent redirection](https://developer.android.com/privacy-and-security/risks/intent-redirection), [pending intents](https://developer.android.com/privacy-and-security/risks/pending-intent), [sender of pending intents](https://developer.android.com/privacy-and-security/risks/sender-of-pending-intents) and [sticky broadcasts](https://developer.android.com/privacy-and-security/risks/sticky-broadcast). The weakness is tagged for profiles L1, L2 and EUDIW, so it is a baseline expectation, not a hardening extra.

OWASP describes the threat as MAS-THREAT-0032, *"Attackers can intercept or manipulate the app's intents"*, reached through three attacks:

| Attack | Description | Attacker position |
|---|---|---|
| MAS-ATTACK-0047 | Delivering crafted intents (or deep links) to the app's exported components | Another app on the device, or a web page the user opens |
| MAS-ATTACK-0049 | Registering intent filters to intercept the app's implicit intents | Another app on the device; sometimes one user tap in a chooser |
| MAS-ATTACK-0050 | Modifying or replaying mutable `PendingIntent`s obtained from the app | Another app that obtains the `PendingIntent` (an extra, a broadcast, a result, or user-granted notification access) |

In each case the attacker is an ordinary installed app, usually with **no permissions at all**. That is the threat model for the whole note. Assume the user has installed something they should not have, then ask what that app can learn or trigger through this app's intents.

Keep the neighbouring weaknesses apart:

| Question | Where it lives |
|---|---|
| Does an exported component let any caller use it (missing `exported="false"`, missing or weak permission)? | [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/) |
| Does the app address its intents to the right recipient, keep sensitive data out of intents others can read, and avoid forwarding intents it did not build? | This note (MASWE-0032) |
| Does the app validate the *content* of incoming intents and returned results before using it (paths, URLs, SQL, file names)? | [MASWE-0050](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/) (MASVS-CODE), e.g. [MASTG-TEST-0375](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0375/) |
| Do deep links and `intent:` URIs from the browser reach sensitive code? | [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/) |
| Does a notification expose sensitive content or `PendingIntent`s? | [MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/) |

One finding often touches two of these. An exported router activity that forwards a nested intent is the classic case: MASWE-0018 asks whether it should be exported, and MASWE-0032 asks whether it should forward that intent. Report it once, under the weakness that names the root cause, and cross-reference the other.

## Modes of Introduction

**Implicit intents for internal communication.** The app starts its own screen, service or receiver with an action string (`Intent("com.example.app.OPEN_WALLET")`) instead of a class. In development this works because the app's own component is the only match. On a user's device, any other app that declares the same action becomes a candidate as well. For apps targeting Android 14 or higher, a non-exported internal component no longer matches implicit intents at all. So if the developer "fixed" the resulting crash by exporting the component, it is now public and still reached by action.

**Sensitive data in implicit intents and broadcasts.** Tokens, account numbers, OTPs, personal data or internal commands go into the extras of an intent that is resolved by action. Broadcasts have no chooser, so every registered receiver gets a copy.

**Unprotected outgoing broadcasts.** `sendBroadcast(intent)` without `setPackage()`, a component or a receiver permission. `sendOrderedBroadcast()` whose result data the app trusts. Sticky broadcasts, which nothing can protect. Migrations away from the deprecated `LocalBroadcastManager` are a common source: an in-process event becomes a device-wide broadcast when it is moved to plain `sendBroadcast()`.

**Intent redirection.** An exported component takes an `Intent` (or an `intent:` URI string) from its input and passes it to `startActivity()`, `startService()`, `sendBroadcast()` or `setResult()`. The forwarded intent is sent with the app's identity, so it reaches components that are not exported and can carry URI grants for the app's private providers.

**Mutable or implicit `PendingIntent`s.** A `PendingIntent` is created with `FLAG_MUTABLE`, or without `FLAG_IMMUTABLE` by an app targeting Android 11 or lower, over a base intent that leaves fields empty. It is then handed to another party: in a notification, a widget, a slice, a media session, an extra of an implicit intent, or a result.

**Replayable one-off actions.** A `PendingIntent` for something that should happen once (confirm a transfer, accept an invitation) is created without `FLAG_ONE_SHOT`.

**Results returned to anyone.** An exported activity returns tokens, files or URI grants through `setResult()` to whatever app started it, without checking `getCallingPackage()`.

**Trusting results from anyone.** The app calls `startActivityForResult()` or `ActivityResultLauncher.launch()` with an implicit intent, then treats the returned `Intent` (its data URI, extras, clip data) as if a trusted component had produced it.

**Unsafe unpacking of extras.** The app reads extras with the untyped `getParcelableExtra(name)` or `getSerializableExtra(name)` and casts the result, or touches the extras of an incoming intent without handling `BadParcelableException`.

## Impact

- **Disclosure of sensitive data.** The extras of implicit intents and broadcasts go to whichever app answers: session tokens, OTPs, account identifiers, personal data, internal configuration.
- **Actions performed with the app's identity.** Intent redirection and mutable `PendingIntent`s let another app reach components that are not exported, use permissions the app holds (camera, contacts, location), and obtain URI grants to files behind the app's `FileProvider` or other private providers.
- **Forged input to security decisions.** A result or broadcast from the wrong app can supply a file, an account, an "approved" flag or a confirmation that the app believes came from a trusted component.
- **Tampering and denial of service.** A higher-priority receiver can change or drop an ordered broadcast. A sticky broadcast can be overwritten by any app. An extra holding an unknown `Parcelable` class crashes a component that unpacks it without a `try`/`catch`.

## Mitigations

- **Use explicit intents inside the app**: `Intent(context, Foo::class.java)`, `setClassName()` or `setComponent()`, or at least `setPackage(packageName)`. Keep internal components `exported="false"` and remove their intent filters.
- **Keep secrets out of implicit intents.** If data has to go to another app, address that app explicitly and verify its signing certificate when it matters. Share user content only through flows the user drives, such as `ACTION_SEND` through a chooser, and only the content the user selected.
- **Restrict every broadcast.** Use `setPackage()` for your own receivers, `sendBroadcast(intent, permission)` with a `signature` permission for trusted partner apps, and `RECEIVER_NOT_EXPORTED` for runtime receivers. Never use sticky broadcasts. For in-app events use `LiveData`, `Flow` or another in-process mechanism.
- **Do not forward intents you did not build.** If you have to, resolve the target, compare it with an allow-list and strip the `FLAG_GRANT_*` flags (AndroidX `IntentSanitizer` does this). Do not opt out of the Android 16 hardening with `removeLaunchSecurityProtection()`.
- **Create `PendingIntent`s with `FLAG_IMMUTABLE` over explicit base intents.** Use `FLAG_MUTABLE` only where the platform requires it (inline replies, bubbles), and add `FLAG_ONE_SHOT` for single-use actions.
- **Check who receives your results** (`getCallingPackage()` plus a signature check), and **validate results you receive** (scheme, authority, MIME type) before acting on them.
- **Read extras with the typed APIs** (`IntentCompat.getParcelableExtra(intent, name, Class)`, `getSerializableExtra(name, Class)` on API 33+). Avoid `Serializable` in IPC, and catch `BadParcelableException` and `ClassCastException` at component boundaries.
- **Treat all extended data in incoming intents as untrusted input** and validate it before use ([MASWE-0050](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/)).

## Knowledge

OWASP links seven Knowledge pages to this topic. MASTG-KNOW-0020, 0025 and 0024 are about intents themselves. MASTG-KNOW-0132, 0133 and 0134 describe the three component types that intents address. MASTG-KNOW-0021 covers object serialisation, of which only the `Parcelable` and `Serializable` parts matter here. Exported components and the Android permission model (MASTG-KNOW-0017 and the access-control halves of 0132 to 0134) are explained in our [MASWE-0018 note](/mobile/maswe-0018-missing-auth-on-app-components/). Below they get a short summary each, and the focus is on how intents are built, resolved, delivered and unpacked.

### Android: Inter-Process Communication (IPC) Mechanisms (MASTG-KNOW-0020)

Source: [MASTG-KNOW-0020](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0020/).

#### Binder and the calling identity

Each Android app runs as its own Linux user (UID) in its own process. Nothing crosses that boundary except through mechanisms the platform provides, and almost all of them are built on **Binder**: the `/dev/binder` kernel driver, an `ioctl`-based transaction protocol, the `IBinder` interface, and the proxy and stub classes generated from AIDL. When app A calls a method on a proxy, the arguments are flattened into a `Parcel` and sent as a transaction. App B's Binder thread pool unflattens them and calls the real object. Two properties shape everything in this note:

- **The kernel stamps every transaction with the caller's UID and PID.** `Binder.getCallingUid()` cannot be forged. Every permission decision on Android comes down to "does this UID hold that permission?", taken by whoever receives the transaction.
- **Intents are Binder transactions to `system_server`, not to the target app.** `startActivity()`, `startService()`, `bindService()`, `sendBroadcast()` and `PendingIntent.send()` all go to the activity manager. It resolves the target, applies the manifest rules (exported, permissions, intent-filter matching) and delivers the intent. The target receives the intent *from the system*, so by the time `onCreate()` or `onReceive()` runs, the Binder calling identity is the system's, not the original sender's. This gap is what CWE-940 describes. It is why sender identity has to be designed in, through explicit targets, permissions, `getCallingPackage()` for results, `PendingIntent`s, or the Android 14 share-identity options described under [Broadcast Receivers](#android-broadcast-receivers-mastg-know-0134).

`adb shell service list` shows the system services registered with `ServiceManager`. App services do not appear there; you reach them through intents.

#### What an intent carries

An [`Intent`](https://developer.android.com/reference/android/content/Intent) is a small parcelable record. Each field is something a sender may leak or a sender of hostile input may control, so know them all:

| Field | Set with | Role |
|---|---|---|
| Action | `setAction()`, `Intent(String)` | Verb used for resolution (`android.intent.action.VIEW`, `com.example.app.SYNC`) |
| Data URI and MIME type | `setData()`, `setType()`, `setDataAndType()` | Object of the action; matched against `<data>` in filters; subject of URI grants |
| Categories | `addCategory()` | Extra resolution constraints; `CATEGORY_DEFAULT` is implied for `startActivity()` |
| Component | `setComponent()`, `setClass()`, `setClassName()`, `Intent(context, Class)` | Makes the intent explicit: delivered to exactly that class |
| Package | `setPackage()` | Limits resolution to one package; action matching still applies |
| Selector | `setSelector()` | Alternative intent used only for resolution; rarely legitimate in app code |
| Flags | `addFlags()`, `setFlags()` | Task behaviour (`FLAG_ACTIVITY_NEW_TASK`) and URI grants (`FLAG_GRANT_READ_URI_PERMISSION`, `FLAG_GRANT_WRITE_URI_PERMISSION`, `FLAG_GRANT_PERSISTABLE_URI_PERMISSION`, `FLAG_GRANT_PREFIX_URI_PERMISSION`) |
| Extras | `putExtra()`, `putExtras()`, `replaceExtras()` | A `Bundle` of key/value pairs: strings, primitives, arrays, `Parcelable`s (including nested `Intent`s and `PendingIntent`s), `Serializable`s |
| Clip data | `setClipData()` | Additional URIs; grant flags apply to these as well as to the data URI |

Grant flags deserve particular attention. "The recipient of this intent may read this URI" is a capability, and it is backed by the identity of the app that *sends* the intent. This is why forwarding someone else's intent is dangerous, and why a mutable `PendingIntent` can expose files.

#### Component types and other IPC

The manifest declares four component types: activities, services, broadcast receivers and content providers. Intents address the first three. Providers are addressed by `content://` URIs through `ContentResolver`; they and their permissions are covered in [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/). Whether another app can reach a component is decided by `android:exported` and by `android:permission` with its protection level. For runtime receivers it is decided by the `RECEIVER_EXPORTED` or `RECEIVER_NOT_EXPORTED` flag. Components of the same app, apps sharing its UID and privileged system code can always reach a component. Other IPC paths (`Messenger`, AIDL interfaces of bound services, `FileProvider` grants, local sockets) are also covered in the MASWE-0018 note, and the clipboard in [MASWE-0030](/mobile/maswe-0030-improper-use-of-the-clipboard/).

#### Platform changes that affect intents

Results depend on both the device's Android version and the app's `targetSdkVersion`, so record both in every finding.

| Release | Applies to | Change |
|---|---|---|
| Android 5.0 (API 21) | Apps targeting 21+ | `startService()` and `bindService()` with an implicit intent throw `IllegalArgumentException`; sticky broadcasts deprecated |
| Android 6.0 (API 23) | All | `PendingIntent.FLAG_IMMUTABLE` introduced |
| Android 8.0 (API 26) | Apps targeting 26+ | Manifest-declared receivers no longer get most implicit broadcasts ([exceptions](https://developer.android.com/develop/background-work/background-tasks/broadcasts/broadcast-exceptions)); context-registered receivers still do |
| Android 10 (API 29) | All | Background activity launch restrictions: an app in the background generally cannot start activities |
| Android 11 (API 30) | Apps targeting 30+ | Package visibility: `queryIntentActivities()` and similar calls only see packages that match `<queries>`; `startActivity()` with an implicit intent is unaffected |
| Android 12 (API 31) | Apps targeting 31+ | `android:exported` mandatory on components with intent filters; every `PendingIntent` must declare `FLAG_IMMUTABLE` or `FLAG_MUTABLE`, or creation throws `IllegalArgumentException`; `StrictMode.VmPolicy.Builder.detectUnsafeIntentLaunch()` available |
| Android 13 (API 33) | Apps targeting 33+ (receiving side) | Intents sent to an exported component are dropped unless they match one of its filters (exceptions: components without filters, the same app, the system, root); `RECEIVER_EXPORTED` and `RECEIVER_NOT_EXPORTED` introduced; typed `getParcelableExtra(name, Class)` and `getSerializableExtra(name, Class)` added |
| Android 14 (API 34) | Apps targeting 34+ | Implicit intents are only delivered to exported components; creating a `FLAG_MUTABLE` `PendingIntent` whose base intent has neither component nor package throws unless `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT` is set; runtime receivers for non-system broadcasts must pass an export flag; `PendingIntent` senders must opt in before lending their background-launch privilege |
| Android 14 (API 34) | All | Apps targeting below API 23 can no longer be installed |
| Android 15 (API 35) | Apps targeting 35+ | `PendingIntent` creators block background activity launches by default; the minimum installable target rises to API 24 |
| Android 16 (API 36) | All apps on Android 16 | Ordered-broadcast priority is only honoured within one process; default hardening against intent redirection (the system records who created a nested intent and blocks launches that creator could not make itself); `Intent.removeLaunchSecurityProtection()` opts out |

Sources: Android behaviour changes for [12](https://developer.android.com/about/versions/12/behavior-changes-12), [13](https://developer.android.com/about/versions/13/behavior-changes-13), [14](https://developer.android.com/about/versions/14/behavior-changes-14), [15](https://developer.android.com/about/versions/15/behavior-changes-15) and [16 (all apps)](https://developer.android.com/about/versions/16/behavior-changes-all).

This has two practical consequences. First, a newer device can mask an app's mistakes. A redirection bug that Android 16 blocks is still open on the Android 13 to 15 devices many users carry. Test on more than one version and report the code, not the device. Second, a sideloaded app is not bound by Google Play's target-API policy. It can target API 24 on Android 15 and still receive implicit broadcasts in a manifest receiver. Do not dismiss an implicit broadcast on the grounds that "manifest receivers cannot get it any more".

### Android: Explicit vs Implicit Intents (MASTG-KNOW-0025)

Source: [MASTG-KNOW-0025](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0025/) and the Android guide [Intents and intent filters](https://developer.android.com/guide/components/intents-filters).

**Explicit** intents name their recipient, either a component (`Intent(context, PaymentActivity::class.java)`, `setClassName(pkg, cls)`, `setComponent()`) or a package (`setPackage(pkg)`). **Implicit** intents describe what should be done (an action, optionally data and categories) and let the system find a component whose `<intent-filter>` matches.

```kotlin
// Explicit by component: only this class can receive it
startActivity(Intent(this, PaymentActivity::class.java).putExtra("amount", 1999))

// Explicit by package: resolved by action, but only inside com.example.app
startActivity(Intent("com.example.app.OPEN_PAYMENT").setPackage("com.example.app"))

// Implicit: any installed app that declares this action is a candidate
startActivity(Intent("com.example.app.OPEN_PAYMENT").putExtra("token", token))
```

Implicit intents are the right tool when the app *wants* the user or the system to choose a handler: opening a web page (`ACTION_VIEW` with an `https` URI), sharing (`ACTION_SEND`), picking a file (`ACTION_GET_CONTENT`, `ACTION_OPEN_DOCUMENT`), taking a photo (`MediaStore.ACTION_IMAGE_CAPTURE`). They are the wrong tool for anything meant to stay inside the app or go to one known partner.

**Resolution.** For an implicit intent, the package manager compares the intent with every filter on the device ([intent resolution](https://developer.android.com/guide/components/intents-filters#Resolution)):

- **Action**: the filter must list the intent's action.
- **Categories**: every category in the intent must appear in the filter. `startActivity()` adds `CATEGORY_DEFAULT`, so an activity filter without `<category android:name="android.intent.category.DEFAULT"/>` never matches an implicit `startActivity()` call. Receivers and services do not need it.
- **Data**: scheme, host, port, path and MIME type must fit the filter's `<data>` elements. An intent with no data and no type matches only filters that declare neither.

What happens next depends on how many components match and whether the user has set a default:

| Matches | Result | User interaction |
|---|---|---|
| None | `ActivityNotFoundException` for activities; broadcasts go to nobody | n/a |
| Exactly one | Delivered directly | None |
| Several, no default | Disambiguation dialog, or the app's own chooser if it used `Intent.createChooser()` | One choice |
| Several, user chose "Always" earlier | Delivered to that default | None |
| Broadcast | Delivered to **every** matching receiver | None |

`android:priority` does not decide activity resolution for ordinary apps. For activity intent filters the platform caps the requested priority at 0 unless the app is privileged ([`<intent-filter>` reference](https://developer.android.com/guide/topics/manifest/intent-filter-element#priority)). Priority still orders receivers of ordered broadcasts, within one process only from Android 16 onwards. The situation that removes user choice is a *single* match. That happens with custom actions when the app's own handler is non-exported and the app targets Android 14 or higher (the system skips non-exported components for implicit intents), when the intended handler belongs to an app that is not installed, or when the app itself picks the first result of `queryIntentActivities()`.

> **Warning:** MASTG-KNOW-0025 says that for apps targeting Android 14, implicit intents "will never be sent to internal components". The precise rule from the [Android 14 behaviour changes](https://developer.android.com/about/versions/14/behavior-changes-14#safer-intents) is that implicit intents are only delivered to *exported* components. An internal component that is exported still receives them; OWASP's own demo app (MASTG-DEMO-0136) relies on exactly that. The page's code samples also call `startActivityForResult(intent)` without the request-code argument and omit semicolons, so they do not compile as written.

**Package visibility.** Since Android 11, an app targeting API 30+ only sees other packages that match its `<queries>` declarations. The filter applies to `queryIntentActivities()` and `resolveActivity()`, not to `startActivity()` with an implicit intent. An app that declares `<queries><intent><action android:name="X"/></intent></queries>` can see every app that handles `X`, including ones it should not trust.

**Activity results.** An activity started with `startActivityForResult()` or through the [Activity Result APIs](https://developer.android.com/training/basics/intents/result) can return a result code and an `Intent` with `setResult()`. The returned intent can carry a data URI, clip data, extras and grant flags. If the request was implicit, the result comes from whichever app handled it; see [GT-0032-3](#gt-0032-3-implicit-requests-for-results-and-results-returned-to-any-caller-android). Validating the *content* of returned URIs (scheme, provider-supplied display names) is covered by OWASP MASTG-KNOW-0138 and MASTG-TEST-0375.

**Strings that become intents.** `Intent.parseUri(string, Intent.URI_INTENT_SCHEME)` turns an `intent:#Intent;component=…;end` string into a full intent. Any string input that reaches it (a deep-link parameter, a push payload, a URL from the server) is therefore a potential intent redirection source. Browsers parse `intent:` URIs themselves and apply restrictions; an app calling `parseUri` gets none of them. Deep links are covered in [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/).

### Android: Pending Intents (MASTG-KNOW-0024)

Source: [MASTG-KNOW-0024](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0024/), the [`PendingIntent` reference](https://developer.android.com/reference/android/app/PendingIntent), and Android's risk pages on [pending intents](https://developer.android.com/privacy-and-security/risks/pending-intent) and [senders of pending intents](https://developer.android.com/privacy-and-security/risks/sender-of-pending-intents).

**What it is.** A `PendingIntent` is a token for an intent stored in `system_server` (a `PendingIntentRecord`) together with the identity of the app that created it. App A creates one with `PendingIntent.getActivity()`, `getActivities()`, `getService()`, `getForegroundService()` or `getBroadcast()` and hands the token to app B. When B calls `send()`, the system performs the action **as A**: with A's UID, A's permissions and access to A's non-exported components. This lets notifications, widgets, alarms and media sessions call back into an app without the app exporting anything. It is also why a `PendingIntent` that reaches the wrong app matters.

**Where `PendingIntent`s go.** Assessment starts with the question "who can get this token?":

| Channel | Who can obtain it |
|---|---|
| Notification content intent and action buttons | System UI, and any app the user has granted **notification access** (a `NotificationListenerService`), which receives the full `Notification` object |
| App widgets (`RemoteViews.setOnClickPendingIntent`) | The launcher or widget host, which may be a third-party app |
| Slices, media sessions, chooser callbacks (`Intent.createChooser(intent, title, intentSender)`) | The host, controller or chooser app |
| Extras of intents, results and broadcasts sent to other apps | The recipient; for an implicit intent or unprotected broadcast, potentially any app |
| `AlarmManager` and similar system-held uses | The system only (lower exposure, but review mutability anyway) |

> **Warning:** MASTG-KNOW-0024 describes the notification case as "a malicious application with `android.permission.BIND_NOTIFICATION_LISTENER_SERVICE`". That permission protects the listener *service* and is held by the system, which binds to it. The other app only declares the service; the **user** has to enable it under the notification-access settings. Notification-borne `PendingIntent`s are therefore exposed to an app the user has granted a special access, not to any installed app. Rate accordingly.

**Mutability and fill-in.** When B calls `send()` with a fill-in intent, the system merges it into the stored base intent with [`Intent.fillIn()`](https://developer.android.com/reference/android/content/Intent#fillIn(android.content.Intent,%20int)), and only if the `PendingIntent` is mutable. The rules, from the reference and the AOSP implementation:

- Action, data and type, identifier, categories, package and clip data are filled in only where the base intent left them empty.
- The component is copied only if the creator allowed `FILL_IN_COMPONENT`, and the selector only with `FILL_IN_SELECTOR`.
- Extras are merged. Keys already in the base intent win; new keys are added.
- Flags from the fill-in intent are added to the base intent's flags.

The practical reading for a reviewer: an immutable `PendingIntent` cannot be changed at all. A mutable one with a fully **explicit** base intent can still receive extra data and extras aimed at the creator's own component. That matters when the component trusts its extras. A mutable one whose base intent is **implicit or empty** leaves the destination and the grant flags open to whoever holds it, under the creator's identity. That last case is the one Android 14 blocks at creation for apps targeting API 34+, and it is the main reason MASTG-TEST-0381 exists.

**Flags and their values.** jadx shows flags as integers (sometimes replaced by an unrelated constant with the same value; see [MASTG-TEST-0381](#mastg-test-0381-references-to-insecure-pendingintent-creation-android)), so keep this table at hand:

| Flag | Value | Hex | Meaning |
|---|---|---|---|
| `FLAG_ONE_SHOT` | 1073741824 | `0x40000000` | Can be sent once |
| `FLAG_NO_CREATE` | 536870912 | `0x20000000` | Return an existing one or `null` |
| `FLAG_CANCEL_CURRENT` | 268435456 | `0x10000000` | Cancel the existing one first |
| `FLAG_UPDATE_CURRENT` | 134217728 | `0x08000000` | Keep the token, replace the extras |
| `FLAG_IMMUTABLE` | 67108864 | `0x04000000` | Fill-in ignored (API 23+) |
| `FLAG_MUTABLE` | 33554432 | `0x02000000` | Fill-in allowed (explicit from API 31) |
| `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT` | 16777216 | `0x01000000` | Opt out of the API 34 block on mutable implicit `PendingIntent`s |

Mutability rules by target SDK:

| `targetSdkVersion` | No mutability flag | `FLAG_IMMUTABLE` | `FLAG_MUTABLE` |
|---|---|---|---|
| 30 or lower | Mutable | Immutable (devices on API 23+) | Mutable |
| 31 to 33 | `IllegalArgumentException` at creation | Immutable | Mutable |
| 34 and higher | `IllegalArgumentException` at creation | Immutable | Mutable; throws if the base intent has neither component nor package, unless `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT` is set |

Two more pitfalls. **Identity**: two `PendingIntent`s are the same token if their intents are equal under `Intent.filterEquals()` (action, data, type, identifier, class, categories) and the request code matches. Extras are not compared. Code that creates several `PendingIntent`s differing only in extras, with `FLAG_UPDATE_CURRENT`, silently overwrites the earlier ones; that is a correctness bug that occasionally becomes a security one (the wrong account or transaction ID behind a button). **Replay**: without `FLAG_ONE_SHOT`, whoever holds the token can send it again for as long as it exists.

**Do not authenticate the sender with the creator.** `PendingIntent.getCreatorPackage()` and `getCreatorUid()` tell you who *created* a `PendingIntent`, not who *sent* it. An app that receives a `PendingIntent` and treats "created by our trusted partner" as proof of who it is talking to can be misled, because any app holding the token can pass it on. Android's [sender-of-pending-intents](https://developer.android.com/privacy-and-security/risks/sender-of-pending-intents) page recommends Binder-based caller checks instead, or, from Android 14, the share-identity options for broadcasts.

**Background launches.** Since Android 14, an app sending a `PendingIntent` must opt in (`ActivityOptions.setPendingIntentBackgroundActivityStartMode()`) to lend its background-activity-launch privilege. Since Android 15 creators block background launches by default. These rules limit some abuse of activity `PendingIntent`s but do not affect broadcast or service `PendingIntent`s, or anything done while the sender is in the foreground.

OWASP's legacy test cites a real platform example, [A-156959408 (CVE-2020-0389)](https://android.googlesource.com/platform/frameworks/base/+/6ae2bd0e59636254c32896f7f01379d1d704f42d): a screen-recorder notification wrapped an implicit `ACTION_VIEW` intent with a read grant in a `PendingIntent` that was not immutable. The fix made the base intent explicit and the `PendingIntent` immutable.

### Android: Activities (MASTG-KNOW-0132)

Source: [MASTG-KNOW-0132](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0132/).

An activity is one screen. It is declared with `<activity>` in the manifest and started with `startActivity()` or the Activity Result APIs. Exported state, intent filters (`CATEGORY_DEFAULT` for implicit starts), `android:permission` and the API 31 requirement to declare `exported` explicitly are covered in [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/). What matters here is how an activity *handles* intents:

- **Two entry points, not one.** The launching intent is available through `getIntent()` in `onCreate()`. For activities with `launchMode="singleTop"`, `singleTask` or `singleInstance`, or started with `FLAG_ACTIVITY_SINGLE_TOP`, later intents arrive in `onNewIntent(intent)` while the old one stays in `getIntent()` unless the code calls `setIntent()`. Validation applied in `onCreate()` but not in `onNewIntent()` is a recurring gap. Review both.
- **Activity aliases.** An `<activity-alias>` has its own `exported`, permission and filters and points at a target activity. Review it as a separate entry point.
- **Who started me?** `getCallingPackage()` and `getCallingActivity()` are only set when the activity was started *for a result*; otherwise they return `null`. `getReferrer()` is informational and the caller can supply it (`Intent.EXTRA_REFERRER`), so it is not an authentication mechanism. From Android 14, `getLaunchedFromPackage()` and `getLaunchedFromUid()` return the launcher's identity when the launcher opted in with `ActivityOptions.setShareIdentityEnabled(true)`.
- **Returning results.** `setResult(code, intent)` sends data back to whoever started the activity for a result. An exported activity that returns sensitive data, or echoes its incoming intent (with whatever grant flags it carries) as the result, returns it to any caller.
- **Forwarding.** An activity that calls `startActivity()` with an intent taken from its extras is the main intent redirection pattern ([GT-0032-1](#gt-0032-1-intent-redirection-through-exported-components-android)). On Android 12+, `StrictMode.VmPolicy.Builder().detectUnsafeIntentLaunch()` reports such launches during development.

### Android: Services (MASTG-KNOW-0133)

Source: [MASTG-KNOW-0133](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0133/).

A service runs work without a UI. It is *started* (`startService()`, `startForegroundService()`), *bound* (`bindService()`, returning an `IBinder` from `onBind()`), or both. Access control and AIDL/`Messenger` caller checks are covered in [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/). For intent handling:

- **Implicit service intents are mostly gone.** For apps targeting API 21+, `startService()` and `bindService()` with an implicit intent throw. In decompiled code you therefore see service intents made explicit with `setPackage()` or `setComponent()`. A service intent addressed to *another* app by package name only is explicit but trusts the package name: if that app is not installed, another app can claim the name (sideloaded) and receive the intent. Verify the recipient's signing certificate when the intent carries anything sensitive.
- **`onStartCommand(intent, flags, startId)`** receives the full intent with its extras. With `START_REDELIVER_INTENT`, the system redelivers the last intent after the process is killed, so treat it as input every time.
- **`onBind(intent)`** sees the binding intent, but per-call authorisation belongs in the Binder methods (`Binder.getCallingUid()` on the Binder thread), not in `onBind`.
- **`Messenger.replyTo`** gives the service a channel back to the caller. A service that sends sensitive replies to whatever `replyTo` it receives has the same problem as an activity that returns results to anyone.
- **Redirection from services.** A service that calls `startActivity()`, `startService()` or `sendBroadcast()` with an intent from its input is a redirection sink. Background activity-launch limits often block the `startActivity()` variant on Android 10+, but not the service and broadcast variants.

### Android: Broadcast Receivers (MASTG-KNOW-0134)

Source: [MASTG-KNOW-0134](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0134/), and the Android guide [Broadcasts overview](https://developer.android.com/develop/background-work/background-tasks/broadcasts).

The receiving side (manifest versus context-registered receivers, `android:permission`, the `RECEIVER_EXPORTED` (`0x2`) and `RECEIVER_NOT_EXPORTED` (`0x4`) flags, and AndroidX's emulation of the flag with a `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` signature permission on older devices) is explained in [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/). For apps targeting Android 14+, registering a runtime receiver for non-system broadcasts without one of the two flags throws `SecurityException`; receivers only for system broadcasts may omit it. This note is mostly about the **sending** side:

| Method | Recipients | Protection available |
|---|---|---|
| `sendBroadcast(intent)` | Every matching receiver on the device | `intent.setPackage()` or a component; or the overload with `receiverPermission` |
| `sendBroadcast(intent, receiverPermission)` | Receivers whose app holds the permission | Effective only if the permission is `signature` (or system) level and defined by a trusted app |
| `sendOrderedBroadcast(…)` | One receiver at a time, by priority; each can change the result (`setResultData()`, `setResultExtras()`) or `abortBroadcast()` | Same as above; never trust the final result from untrusted receivers |
| `sendStickyBroadcast(…)` and relatives | Every matching receiver now, and any app that registers later | **None.** Deprecated since API 21 |
| `LocalBroadcastManager` | Same process only | In-process by design, but [deprecated](https://developer.android.com/jetpack/androidx/releases/localbroadcastmanager); replace with `LiveData`, `Flow` or similar |

**Implicit versus explicit broadcasts.** A broadcast is implicit when it names no package or component. Any context-registered receiver for the action gets it. Manifest receivers of apps targeting API 26+ do not (outside the exception list), but manifest receivers of apps targeting older APIs do, as noted above. Since Android 14, implicit broadcasts from an app targeting API 34+ do not reach that app's own non-exported receivers, but still reach every exported receiver elsewhere.

**Sticky broadcasts.** Android's [risk page](https://developer.android.com/privacy-and-security/risks/sticky-broadcast) lists the problems. The sticky cache re-delivers the last intent to any app that registers for the action, and `setPackage()` is *not* applied on re-delivery. Any app can send or replace a sticky broadcast, because `BROADCAST_STICKY` is a normal permission granted at install. A receiver cannot restrict sticky senders with a permission, because cached intents are delivered without one. Any sticky broadcast that carries non-public data is a finding; one that the app also *reads* is a tampering risk.

**Ordered broadcasts.** A receiver with higher priority sees an ordered broadcast first and can change or drop it. From Android 16 the priority is only honoured within one process, which weakens but does not remove the ordering risk on older devices. The safe rule is unchanged: do not treat the result of an ordered broadcast as an authorisation decision.

**Sender identity.** A receiver cannot use Binder to learn who sent a broadcast. From Android 14, a sender can opt in with `BroadcastOptions.setShareIdentityEnabled(true)`, and the receiver then reads `getSentFromUid()` and `getSentFromPackage()`. Without that opt-in, use a `signature` permission on the receiver.

### Android: Object Serialization (MASTG-KNOW-0021)

Source: [MASTG-KNOW-0021](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0021/). The page also covers JSON, XML, ORMs and Protocol Buffers as storage formats. Those belong to storage and code-quality testing (legacy MASTG-TEST-0034, now [MASTG-TEST-0337](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0337/)). Here we cover the two mechanisms that travel inside intents.

**`Parcelable`.** A class implements `writeToParcel()` and a `CREATOR` with `createFromParcel()`. `Bundle`s, and therefore intent extras, are flattened with it, and `Intent`, `PendingIntent`, `Uri`, `Bundle` and `ClipData` are all `Parcelable`. When a component reads an extra, the receiving process instantiates the class named in the parcel and runs its `createFromParcel()`. Consequences for review:

- **Nested intents are just another extra.** `getParcelableExtra("next")` can return an `Intent` that someone else built. That is the input to intent redirection.
- **Type confusion.** The untyped `getParcelableExtra(name)` returns whatever `Parcelable` is in the bundle, and Kotlin's `getParcelableExtra<T>(name)` without a class argument only casts afterwards. Code that expects its own `Order` class but receives a different object fails with `ClassCastException`, or worse, takes a branch the developer did not expect.
- **Unpacking happens early.** Reading *any* key can unparcel the bundle. A class the app does not have, or a malformed parcel, throws `BadParcelableException` or `ClassNotFoundException` and crashes the component unless the read is wrapped in `try`/`catch`. Android 13 made `Bundle` deserialise such values lazily, per key. It also added the typed `getParcelableExtra(name, Class)` and `getSerializableExtra(name, Class)`, which check the type before instantiating the object.
- **Typed reads on all versions.** AndroidX `IntentCompat.getParcelableExtra(intent, name, Class)` and `BundleCompat.getParcelable(bundle, key, Class)` give the typed behaviour on API 34+ and check the type after deserialisation on API 33 and lower. That is weaker, but still better than an unchecked cast.
- **Asymmetric `writeToParcel()`/`createFromParcel()`.** A custom `Parcelable` that writes and reads a different number of fields corrupts everything after it in the bundle. Platform bugs of this kind have been used to smuggle values past checks in system components. In app code it is mostly a reliability problem, but flag it.

**`Serializable`.** `putExtra(name, serializable)` stores Java-serialised bytes in the bundle, and `getSerializableExtra(name)` runs `ObjectInputStream` on them in the receiving app. Java deserialisation of untrusted data executes the `readObject()` logic of any serialisable class on the app's class path, which is the root of gadget-chain attacks. Even without a gadget, a large or deeply nested object is a denial of service. For IPC, prefer `Parcelable` or plain values, read with the typed API where `Serializable` cannot be avoided, and never accept `Serializable` extras in exported components.

## Tests

OWASP links three tests to MASWE-0032, all static and all Android: [MASTG-TEST-0372](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0372/) and [MASTG-TEST-0374](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0374/), which sit in OWASP's MASVS-CODE folder (hence the URLs) but are filed under this weakness, and [MASTG-TEST-0381](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0381/). They replace these legacy (MASTG v1) tests:

| Legacy test | Replaced by |
|---|---|
| [MASTG-TEST-0026](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0026/) Testing Implicit Intents | MASTG-TEST-0372 and 0374 (here), and MASTG-TEST-0375 (validation of returned data, filed under MASWE-0050) |
| [MASTG-TEST-0030](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0030/) Testing for Vulnerable Implementation of PendingIntent | MASTG-TEST-0381 |
| [MASTG-TEST-0029](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0029/) Testing for Sensitive Functionality Exposure Through IPC | MASTG-TEST-0364, 0365, 0366, documented in our [MASWE-0018 note](/mobile/maswe-0018-missing-auth-on-app-components/); its broadcast-sniffing part is covered here by [GT-0032-2](#gt-0032-2-implicit-and-sticky-broadcasts-carrying-sensitive-extras-android) |

> **Warning:** Legacy MASTG-TEST-0026 gives its interception example an activity filter with `android:priority="999"`. For activity filters of non-privileged apps the platform caps priority at 0, so that attribute has no effect. What actually decides delivery is how many components match and whether the user chooses (see [MASTG-KNOW-0025](#android-explicit-vs-implicit-intents-mastg-know-0025)).

The OWASP tests find candidates in code. Three questions are left open: is the candidate reached at runtime, who else can receive it, and what does it carry? We answer them with a runtime trace of the app's own intents and three Guler Tech checks. Each check produces evidence from the app under test only: its code, its runtime calls, the system's view of its intents (`dumpsys`), and commands sent to it with `adb`. No custom attacker app is needed to rate these findings.

### Before you start: static triage of intent traffic

One pass over the decompiled app gives you candidates for every test in this note.

```bash
# Pull the installed APK (and any splits) and decompile
adb shell pm path com.example.app
adb pull /data/app/~~XXXX/com.example.app-YYYY/base.apk
jadx -d out base.apk                 # Java sources
apktool d base.apk -o apk_out        # decoded AndroidManifest.xml and resources

# Target and minimum SDK decide which platform rules apply
grep -E 'minSdkVersion|targetSdkVersion' apk_out/apktool.yml

# App code only (drop framework and library packages you trust)
SRC=out/sources/com/example/app

# 1. Intent creation by action (implicit candidates)
grep -rnE 'new Intent\("[^"]+"|\.setAction\(' $SRC > intents-action.txt

# 2. Dispatch sites
grep -rnE '\.(startActivity|startActivityForResult|startActivities|startService|startForegroundService|bindService|sendBroadcast|sendOrderedBroadcast|sendStickyBroadcast|sendStickyOrderedBroadcast)\(|\.launch\(' $SRC > intents-dispatch.txt

# 3. Restrictions applied before dispatch
grep -rnE '\.(setPackage|setComponent|setClassName|setClass)\(|new Intent\([a-zA-Z_.]+, *[A-Za-z_.$]+\.class\)' $SRC > intents-explicit.txt

# 4. Redirection sources and sinks
grep -rnE 'getParcelableExtra\(|getParcelable\(|Intent\.parseUri\(|setResult\(|getSerializableExtra\(' $SRC > intents-input.txt

# 5. PendingIntent creation and runtime receivers
grep -rnE 'PendingIntent\.get(Activity|Activities|Service|ForegroundService|Broadcast)\(' $SRC > pendingintents.txt
grep -rnE 'registerReceiver\(' $SRC > receivers.txt

wc -l intents-*.txt pendingintents.txt receivers.txt
```

Cross-reference the files: a dispatch site with no restriction in the same method is a candidate for MASTG-TEST-0372/0374; a `getParcelableExtra`/`parseUri` in an exported component followed by a dispatch is a candidate for GT-0032-1. Use the manifest to tell exported from internal components (the inventory method is in [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/)):

```bash
grep -nE '<(activity|activity-alias|service|receiver)|android:exported|<action ' apk_out/AndroidManifest.xml
```

Two things survive R8 obfuscation and make this triage work on release builds: platform method names (`startActivity`, `sendBroadcast`, `getParcelableExtra`) and string constants (action names, extra keys). Grep the action strings you find across the whole decompiled tree, including libraries: SDKs send their own broadcasts.

### Runtime tracing of the app's own intents

Static triage misses intents built in libraries, by reflection or from server data. Guler Tech methodology: hook the app's outgoing intent calls with [Frida](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/) ([MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), method hooking) and use the app through every flow. The script only *logs* what the app under test sends, creates and returns. It changes nothing.

```javascript
// intent-trace.js — frida -U -f com.example.app -l intent-trace.js
Java.perform(function () {
  var Intent = Java.use('android.content.Intent');
  var Log = Java.use('android.util.Log');
  var Ex = Java.use('java.lang.Exception');

  function describe(i) {
    var implicit = i.getComponent() === null && i.getPackage() === null;
    var ex = i.getExtras();
    var extras = 'none';
    if (ex !== null) { ex.size(); extras = ex.toString(); }   // size() unparcels for printing
    return (implicit ? 'IMPLICIT ' : 'explicit ') + 'act=' + i.getAction() +
      ' dat=' + i.getData() + ' typ=' + i.getType() + ' pkg=' + i.getPackage() +
      ' cmp=' + i.getComponent() + ' flg=0x' + (i.getFlags() >>> 0).toString(16) +
      ' extras=' + extras;
  }
  function where() {
    return Log.getStackTraceString(Ex.$new()).split('\n').slice(2, 7).join('\n');
  }
  function hookAll(cls, method, tag) {
    Java.use(cls)[method].overloads.forEach(function (ov) {
      ov.implementation = function () {
        for (var k = 0; k < arguments.length; k++) {
          var a = arguments[k];
          if (a !== null && a.$className === 'android.content.Intent') {
            console.log('[' + tag + '] ' + describe(Java.cast(a, Intent)) + '\n' + where());
            break;
          }
        }
        return ov.apply(this, arguments);
      };
    });
  }

  // All activity starts funnel through Instrumentation; all sends through ContextImpl
  hookAll('android.app.Instrumentation', 'execStartActivity', 'startActivity');
  ['sendBroadcast', 'sendOrderedBroadcast', 'sendStickyBroadcast',
   'startService', 'startForegroundService', 'bindService'].forEach(function (m) {
    hookAll('android.app.ContextImpl', m, m);
  });

  // Results this app returns, and to whom
  Java.use('android.app.Activity').setResult.overload('int', 'android.content.Intent')
    .implementation = function (code, data) {
      console.log('[setResult] caller=' + this.getCallingPackage() + ' code=' + code +
                  ' ' + (data !== null ? describe(data) : 'no data'));
      return this.setResult(code, data);
    };

  // PendingIntent creation with decoded flags
  var F = { 1073741824: 'ONE_SHOT', 536870912: 'NO_CREATE', 268435456: 'CANCEL_CURRENT',
            134217728: 'UPDATE_CURRENT', 67108864: 'IMMUTABLE', 33554432: 'MUTABLE',
            16777216: 'ALLOW_UNSAFE_IMPLICIT_INTENT' };
  function decode(f) {
    var out = [];
    Object.keys(F).forEach(function (b) { if ((f & Number(b)) !== 0) out.push(F[b]); });
    return out.length ? out.join('|') : '0';
  }
  var PI = Java.use('android.app.PendingIntent');
  ['getActivity', 'getActivities', 'getService', 'getForegroundService', 'getBroadcast']
    .forEach(function (m) {
      PI[m].overloads.forEach(function (ov) {
        ov.implementation = function () {
          var flags = arguments[3];
          var list = (m === 'getActivities') ? arguments[2] : [arguments[2]];
          for (var j = 0; j < list.length; j++) {
            console.log('[PendingIntent.' + m + '] flags=' + decode(flags) +
              ((flags & 0x06000000) === 0 ? ' (no mutability flag)' : '') +
              ' base=' + describe(list[j]) + '\n' + where());
          }
          return ov.apply(this, arguments);
        };
      });
    });
});
```

```bash
frida -U -f com.example.app -l intent-trace.js -o intent-trace.log
```

Lines tagged `IMPLICIT` are your MASTG-TEST-0372/0374 candidates at runtime, with the stack frame that sent them. `[setResult]` lines with a foreign `caller` show which packages receive results. `[PendingIntent.*]` lines show every token the app creates. Two system views complement the trace:

```bash
# Every start the activity manager performs, with the resolved component and caller UID
adb logcat -s ActivityTaskManager:I | grep 'START u0'

# Live PendingIntents owned by the app (output format varies by Android release)
adb shell dumpsys activity intents | grep -A3 com.example.app
```

An implicit `startActivity()` with several candidates shows up in `logcat` with the system resolver or chooser as the component. One that went straight to a single handler shows that handler's component. That is the quickest way to show *who* got the intent on a given device.

### MASTG-TEST-0372: Implicit Intents Used for Internal App Communication (Android)

Source: [MASTG-TEST-0372](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0372/). Platform: Android. Type: static (code) with manual review. Knowledge: MASTG-KNOW-0025. Best practice: MASTG-BEST-0056.

#### Overview

The test looks for intents the app uses to talk to *itself* (or to one trusted app) that are resolved by action instead of by component or package. Any other app can declare a matching `<intent-filter>` and become a candidate during resolution. If the system shows a chooser, the user may pick the other app. If that app is the only match, or the user set it as the default, the intent goes there without a decision. Legitimate implicit intents, such as opening an `https` link or sharing through a chooser, are not in scope.

#### Prerequisites

- The APK decompiled with jadx ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)) and the decoded manifest.
- semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)) with the OWASP rule, or the grep commands from the triage section ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)).
- jadx-gui for review ([MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)); optionally a device with Frida for confirmation.

#### Steps

1. **Run the OWASP rule** on the decompiled code:

   ```bash
   semgrep -c mastg-android-implicit-intent-internal-communication.yml out/sources/com/example/app/ --text
   ```

   The rule matches `new Intent(...)`, then `setAction(...)`, then `startActivity(...)` on the same variable, without `setPackage`, `setComponent` or an `Intent(context, Class)` constructor in between. It does **not** match `new Intent("ACTION")` (the action passed to the constructor), `sendBroadcast`, `startService`, `bindService`, `startActivityForResult`, `ActivityResultLauncher.launch`, or intents built in one method and sent in another. Use it as a first pass and cover the rest with the triage greps.

2. **Classify each action string.** List the actions the app sends and the actions its own manifest declares:

   ```bash
   grep -ohE 'new Intent\("[^"]+"|setAction\("[^"]+"' -r out/sources/com/example/app/ | grep -oE '"[^"]+"' | sort -u > sent-actions.txt
   grep -oE '<action android:name="[^"]+"' apk_out/AndroidManifest.xml | grep -oE '"[^"]+"' | sort -u > declared-actions.txt
   comm -12 sent-actions.txt declared-actions.txt
   ```

   An action the app both sends and handles itself (`comm -12`) is almost always internal communication. App-specific action names (`com.example.app.*`) sent to no declared handler point to another app of the same vendor, which is "trusted-component communication" and also in scope.

3. **Review each candidate** in jadx: is a component or package set anywhere before dispatch (possibly in a helper)? Is the recipient meant to be the app itself or a specific partner, rather than a user-chosen handler?

4. **See who can resolve it on a test device.** With the app installed, ask the package manager which components currently match the action:

   ```bash
   adb shell cmd package query-activities --components -a com.example.app.INTERNAL_ACTION
   adb shell cmd package query-receivers --components -a com.example.app.INTERNAL_ACTION
   ```

   Today only the app's own component matches. The finding is that *any* app declaring the same action would be added to this list. You do not need to install one to prove it, because the filter syntax is public in the APK.

5. **Confirm at runtime** that the code path is live: run [intent-trace.js](#runtime-tracing-of-the-apps-own-intents) and trigger the flow. An `IMPLICIT act=com.example.app.INTERNAL_ACTION` line with a stack frame in app code is the evidence.

#### Observation

For each candidate: code location, how the intent is created, action, data, categories and extras, dispatch API, the absence of any target-defining call, the manifest component that handles it, and the trace line from the device.

#### Evaluation

The test **fails** if an intent meant for one of the app's own components, or for a specific trusted app, is dispatched without a component or package (or, for broadcasts, without a receiver permission of `signature` level), so that another app can declare a matching filter and receive it.

It **passes** if internal intents name their component (or at least set the package), and every remaining implicit intent is a deliberate hand-off to a user-chosen handler for a generic action (`ACTION_VIEW` for web URLs, `ACTION_SEND` through a chooser, document pickers).

Rate the failure by what the intent carries (MASTG-TEST-0374) and what the internal flow does. An implicit intent with no extras that opens a harmless screen is Low; the same pattern carrying a token is the next test.

#### Demo

[MASTG-DEMO-0136](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0136/MASTG-DEMO-0136/) (fail). The app starts its own `InternalActivity` by action. The activity is exported with a filter for the action. That export is what lets this work at all for an app targeting API 35, and it is itself a finding.

```kotlin
val implicitIntent = Intent().apply {
    action = "org.owasp.mastestapp.INTERNAL_ACTION"      // no component, no package
    putExtra("user_id", "12345")
    putExtra("session_token", "abcde-fghij-12345")
    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
}
context.startActivity(implicitIntent)
```

```xml
<activity android:name="org.owasp.mastestapp.InternalActivity" android:exported="true">
    <intent-filter>
        <action android:name="org.owasp.mastestapp.INTERNAL_ACTION" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

semgrep reports the dispatch in the decompiled code (`268435456` is `FLAG_ACTIVITY_NEW_TASK`):

```text
MastgTest_reversed.java
❯❱ rules.mastg-android-implicit-intent-internal-communication
      [MASVS-CODE-4] The app uses an implicit intent for internal component communication.
       22┆ Intent implicitIntent = new Intent();
       23┆ implicitIntent.setAction("org.owasp.mastestapp.INTERNAL_ACTION");
       24┆ implicitIntent.putExtra("user_id", "12345");
       25┆ implicitIntent.putExtra("session_token", "abcde-fghij-12345");
       26┆ implicitIntent.addFlags(268435456);
       27┆ try {
       28┆     this.context.startActivity(implicitIntent);
```

OWASP pairs this with [MASTG-DEMO-0140](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0140/MASTG-DEMO-0140/), a second app that declares the same action and shows that Android offers it as a handler. With both installed, the system shows a chooser; once the second app is selected, it receives the action and both extras. We do not reproduce that app here. For rating it is enough to show that the action is resolved implicitly (the semgrep hit, the trace line) and that nothing restricts the recipient. The fix is the commented-out branch of the same demo: `Intent(context, InternalActivity::class.java)`, with `InternalActivity` set back to `exported="false"` and its filter removed.

### MASTG-TEST-0374: References to Implicit Intents Carrying Sensitive Extras (Android)

Source: [MASTG-TEST-0374](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0374/). Platform: Android. Type: static (code) with manual review. Knowledge: MASTG-KNOW-0025. Best practice: MASTG-BEST-0056.

#### Overview

This is the data side of MASTG-TEST-0372. It looks for implicit intents (activity, service or broadcast) that carry sensitive or security-relevant extras: credentials, session or refresh tokens, OTPs, account or card identifiers, personal data, internal commands. Whichever app is selected during resolution, or every receiver for a broadcast, gets the whole extras `Bundle`. The test also covers intents that are *meant* for another app (a share or a hand-off) but include more than the user chose to share.

#### Prerequisites

As for MASTG-TEST-0372, plus a list of what counts as sensitive in this app (from its data model, its API traffic and its privacy notice).

#### Steps

1. **Run the OWASP rule:**

   ```bash
   semgrep -c mastg-android-implicit-intent-leaking-extras.yml out/sources/com/example/app/ --text
   ```

   It matches `new Intent(...)`, then `putExtra(...)`, then `startActivity(...)`, excluding intents with `setPackage`, `setComponent` or an `Intent(context, Class)` constructor. Like the 0372 rule it only knows `startActivity`, and it misses `putExtras(bundle)`, `replaceExtras(...)` and extras added in helper methods. Extend your search with the triage greps and with the extra keys themselves:

   ```bash
   grep -rnE 'putExtra\("[^"]*(token|session|auth|otp|code|pin|password|secret|account|iban|card|email|phone)[^"]*"' -i out/sources/com/example/app/
   ```

2. **For each implicit dispatch with extras**, find the values: follow the variables in jadx back to their source (the session store, the user profile, an API response).

3. **Exclude genuine user-driven sharing.** `ACTION_SEND` through `Intent.createChooser()` with `EXTRA_TEXT` or `EXTRA_STREAM` that the user selected is the purpose of the feature. An `ACTION_SEND` that also carries an `auth_token` extra "for our partner app" is not.

4. **Capture the actual extras at runtime** with [intent-trace.js](#runtime-tracing-of-the-apps-own-intents). The trace prints the `Bundle` as the app built it, so you can see values you could not resolve statically. Redact real tokens before putting the log in a report.

#### Observation

For each hit: code location, action, data and categories, the extra keys with their values or their source, the dispatch API, the absence of any target-defining call or receiver permission, and the runtime trace.

#### Evaluation

The test **fails** if an implicit intent carries sensitive or security-relevant extras and another app can declare or register a matching component to receive them. For broadcasts this includes an unprotected `sendBroadcast()` and any sticky broadcast.

It **passes** if sensitive extras only ever travel in explicit intents (component, or package plus a verified signature for a partner app), or in broadcasts restricted by package or by a `signature` permission, and implicit intents carry only content the user chose to share.

#### Demo

[MASTG-DEMO-0138](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0138/MASTG-DEMO-0138/) (fail) reuses the sample from MASTG-DEMO-0136: the same implicit intent carries `user_id` and `session_token`. The semgrep rule reports it:

```text
../MASTG-DEMO-0136/MastgTest_reversed.java
❯❱ rules.mastg-android-implicit-intent-leaking-extras
      [MASVS-CODE-4] The app sends an implicit intent with extras. Any app that registers for this
      action can receive the data. Use explicit intents for internal communication.
       22┆ Intent implicitIntent = new Intent();
       23┆ implicitIntent.setAction("org.owasp.mastestapp.INTERNAL_ACTION");
       24┆ implicitIntent.putExtra("user_id", "12345");
       25┆ implicitIntent.putExtra("session_token", "abcde-fghij-12345");
```

The matching runtime trace line from our script looks like this (values as in the demo):

```text
[startActivity] IMPLICIT act=org.owasp.mastestapp.INTERNAL_ACTION dat=null typ=null pkg=null cmp=null flg=0x10000000 extras=Bundle[{session_token=abcde-fghij-12345, user_id=12345}]
```

A session token in an implicit intent is the core of the finding. Rate it on what the token gives access to and on whether delivery needs a user choice (see [Rating findings](#rating-findings)).

### MASTG-TEST-0381: References to Insecure PendingIntent Creation (Android)

Source: [MASTG-TEST-0381](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0381/). Platform: Android. Type: static. Best practice: MASTG-BEST-0063. Replaces legacy MASTG-TEST-0030.

#### Overview

The test lists every `PendingIntent` the app creates (`getActivity`, `getActivities`, `getService`, `getForegroundService`, `getBroadcast`) and checks two properties: **mutability** (is `FLAG_IMMUTABLE` set, or is `FLAG_MUTABLE` justified?) and **the base intent** (does it name a component, or at least a package?). A mutable `PendingIntent` lets its holder change the parts of the base intent that were left empty, and the result runs with the app's identity. An implicit base intent leaves the destination among those parts. We add a third property that the OWASP test leaves to the reviewer: **exposure**, meaning who can obtain the token at all.

#### Prerequisites

- Decompiled code and the `targetSdkVersion`/`minSdkVersion` from `apktool.yml`.
- semgrep with the OWASP rule, or the triage grep.
- Optionally a device with Frida and `adb` to confirm flags and exposure at runtime.

#### Steps

1. **Find every creation site:**

   ```bash
   semgrep -c mastg-android-pendingintent-mutable.yml out/sources/com/example/app/
   grep -rnE 'PendingIntent\.get(Activity|Activities|Service|ForegroundService|Broadcast)\(' out/sources/
   ```

   The OWASP rule only matches a flags argument that is *exactly* `0`, `134217728` (`FLAG_UPDATE_CURRENT`), `33554432` (`FLAG_MUTABLE`), their hex forms or the named constants. It therefore misses combinations such as `167772160` (`FLAG_MUTABLE | FLAG_UPDATE_CURRENT`) or `1107296256` (`FLAG_MUTABLE | FLAG_ONE_SHOT`), flags held in a variable, and Kotlin/Java code that jadx did not fold into a literal. It does not look at the base intent at all. Take the grep list as the complete set and decode every flag value yourself.

2. **Decode the flags.** jadx usually shows a decimal integer, and sometimes replaces it with an unrelated constant that happens to have the same value. In OWASP's demo, `FLAG_IMMUTABLE` (`67108864`) appears as `AccessibilityEventCompat.TYPE_VIEW_TARGETED_BY_SCROLL`. Use the [flag table](#android-pending-intents-mastg-know-0024) or a one-liner:

   ```bash
   python3 -c 'import sys; f=int(sys.argv[1],0); n={1<<30:"ONE_SHOT",1<<29:"NO_CREATE",1<<28:"CANCEL_CURRENT",1<<27:"UPDATE_CURRENT",1<<26:"IMMUTABLE",1<<25:"MUTABLE",1<<24:"ALLOW_UNSAFE_IMPLICIT_INTENT"}; print([v for k,v in n.items() if f&k] or ["0"])' 167772160
   ```

3. **Classify the base intent**: explicit by component (`Intent(context, X::class.java)`, `setClassName`, `setComponent`), explicit by package only (`setPackage`), or implicit (action or nothing). An empty `Intent()` is the worst case.

4. **Apply the target SDK.** With `targetSdkVersion` 31 or higher, a call with neither mutability flag throws at runtime. A static hit of that kind is dead code or a crash bug, not a mutable `PendingIntent`. With a target of 30 or lower, no flag means mutable on every device. With 34 or higher, `FLAG_MUTABLE` over a base intent with neither component nor package throws unless `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT` is also set, so grep for that flag specifically.

5. **Establish exposure.** Follow each `PendingIntent` in jadx to where it goes: `NotificationCompat.Builder.setContentIntent`/`addAction`, `RemoteViews.setOnClickPendingIntent`, `putExtra(…)` on an intent to another app, `setResult(…)`, `AlarmManager.set*`, `MediaSession.setSessionActivity`. Then confirm on the device:

   ```bash
   frida -U -f com.example.app -l intent-trace.js     # [PendingIntent.*] lines with decoded flags and stack
   adb shell dumpsys activity intents | grep -A3 com.example.app
   adb shell dumpsys notification --noredact | grep -B2 -A8 com.example.app
   ```

   The notification dump shows the app's posted notifications with their content and action `PendingIntent`s, so you can map each token to a channel.

6. **Check single-use actions** for `FLAG_ONE_SHOT`: confirmations, approvals, one-time links.

#### Observation

A table of creation sites with: API, decoded flags, base intent (component/package/implicit), target SDK effect, where the token goes and who can obtain it, and the runtime evidence.

#### Evaluation

The test **fails** if:

- a `PendingIntent` is mutable (`FLAG_MUTABLE`, or no mutability flag with `targetSdkVersion` 30 or lower) without a use case that needs mutability, such as inline replies or bubbles;
- a mutable `PendingIntent` has a base intent with neither component nor package (on API 34+ targets this requires `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT`, which is itself a red flag); or
- any `PendingIntent`, even an immutable one, wraps an implicit base intent and reaches another app, because the destination is then decided by resolution and not by the app.

Note `FLAG_ONE_SHOT` missing on single-use actions as a separate, usually lower-rated, failure.

> **Warning:** OWASP's evaluation ties the missing-`FLAG_IMMUTABLE` case to a `minSdkVersion` below 31. Mutability by default is controlled by the app's **`targetSdkVersion`**, not by `minSdkVersion` or the device version. Apps targeting 30 or lower get mutable `PendingIntent`s when no flag is set; apps targeting 31+ cannot create one without a flag. `minSdkVersion` matters only below 23, where `FLAG_IMMUTABLE` does not exist on the oldest supported devices.

It **passes** if every `PendingIntent` is `FLAG_IMMUTABLE` over an explicit base intent, `FLAG_MUTABLE` appears only where the platform requires it, over an explicit base intent with only the expected fields left open, and single-use actions are `FLAG_ONE_SHOT`.

#### Demo

[MASTG-DEMO-0147](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0147/MASTG-DEMO-0147/) shows three failing creations and one passing one:

```kotlin
// FAIL: implicit base intent, no mutability flag
PendingIntent.getActivity(context, 0, Intent(Intent.ACTION_VIEW), PendingIntent.FLAG_UPDATE_CURRENT)

// FAIL: explicit base intent, but FLAG_MUTABLE without a reason
PendingIntent.getService(context, 1, Intent(context, MastgTest::class.java), PendingIntent.FLAG_MUTABLE)

// FAIL: implicit broadcast, no flags at all
PendingIntent.getBroadcast(context, 2, Intent("com.example.CUSTOM_ACTION"), 0)

// PASS: immutable, explicit class and package
val secure = Intent(context, MastgTest::class.java).apply { setPackage(context.packageName) }
PendingIntent.getActivity(context, 3, secure, PendingIntent.FLAG_IMMUTABLE)
```

The rule reports the first three on the decompiled code:

```text
MastgTest_reversed.java
❯❱ rules.mastg-android-pendingintent-mutable
      [MASVS-PLATFORM-1] PendingIntent created without FLAG_IMMUTABLE or with FLAG_MUTABLE may be
      vulnerable to hijacking.
       25┆ PendingIntent.getActivity(this.context, 0, implicitIntent, 134217728);
       28┆ PendingIntent.getService(this.context, 1, explicitMutableIntent, 33554432);
       31┆ PendingIntent.getBroadcast(this.context, 2, broadcastIntent, 0);
```

In the decompiled source the passing call shows its flag as `AccessibilityEventCompat.TYPE_VIEW_TARGETED_BY_SCROLL`. That is jadx substituting a same-valued constant for `67108864` (`FLAG_IMMUTABLE`), not a bug in the app.

> **Warning:** The demo has three defects. Its code comments label the cases `[MASTG-TEST-0313]` instead of `MASTG-TEST-0381`. Its comment "No flags - mutable by default on API < 31" mixes up the device version with the target SDK. And because the demo app targets a recent SDK, the first `getActivity()` call (only `FLAG_UPDATE_CURRENT`) would throw `IllegalArgumentException` at runtime before the other cases ran. The demo is useful as a static pattern, but do not expect it to run as written.

The demo's "confirm the exposure" section asks the same question as our step 5: none of these tokens is a problem until it reaches another app. In a real app, the finding is a mutable or implicit `PendingIntent` *plus* a channel that hands it out.

### GT-0032-1: Intent redirection through exported components (Android)

Guler Tech methodology. Platform: Android. Type: static (code) and dynamic (Frida trace, `adb`). Related: Android's [intent redirection](https://developer.android.com/privacy-and-security/risks/intent-redirection) risk page. The URI-grant side of this problem, and how it reaches private providers, is covered in [GT-0018-1 in the MASWE-0018 note](/mobile/maswe-0018-missing-auth-on-app-components/). Here we focus on finding the forwarding path and showing that it is reachable.

#### Overview

An exported component reads an `Intent` from its input and dispatches it: a `Parcelable` extra (often named `next`, `target`, `redirect`, `forward`, `extra_intent`), an `intent:` URI string passed to `Intent.parseUri()`, or the component's own incoming intent echoed back with `setResult()`. Because the dispatch happens with the app's identity, the forwarded intent is not subject to the `exported` check of the target, and its grant flags are backed by the app's own providers. This is the most direct route from another app to the app's internal components.

#### Prerequisites

- Decompiled code, the manifest inventory of exported components, Frida on a test device, `adb`.
- Ideally two test devices or emulators: one on Android 16 (with the platform's redirection hardening) and one on Android 13 to 15.

#### Steps

1. **Find sources in exported components.** From `intents-input.txt`, keep the hits whose class is exported (or is called from one):

   ```bash
   grep -rnE 'getParcelableExtra\(|getParcelable\(|Intent\.parseUri\(' out/sources/com/example/app/ | grep -iE 'intent|uri'
   grep -rnE 'removeLaunchSecurityProtection' out/sources/
   ```

   A call to `removeLaunchSecurityProtection()` means the app has opted out of the Android 16 hardening for that intent. Treat it as a deliberate redirection path to review.

2. **Trace source to sink in jadx.** For each source, follow the value to `startActivity`, `startActivityForResult`, `startService`, `bindService`, `sendBroadcast` or `setResult`. Then record what happens in between:
   - Is the target resolved (`resolveActivity(packageManager)`) and compared with an allow-list of package **and** class?
   - Are `FLAG_GRANT_READ_URI_PERMISSION`, `FLAG_GRANT_WRITE_URI_PERMISSION`, `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` and `FLAG_GRANT_PREFIX_URI_PERMISSION` removed? Is a selector cleared?
   - Is AndroidX `IntentSanitizer` used, and with which `allow…` rules?
   - Does the check rely on `getCallingActivity() != null`? Android's risk page lists that as a common mistake: the caller controls it.

3. **Map the reachable internal components.** List the app's non-exported activities, services and receivers, and note what each one does (settings, debug, PIN change, export). These are what a forwarding path would make reachable.

4. **Show the path is live.** Run [intent-trace.js](#runtime-tracing-of-the-apps-own-intents) and use the flows that feed the exported component (notification taps, deep links, widget clicks). The trace shows the forwarded intent, its component and flags, and the stack frame in the router.

5. **Exercise string-based routers with `adb`.** `am start` cannot put a `Parcelable` `Intent` into an extra, but it can pass the `intent:` string that a `parseUri()` router reads. Point it at a harmless non-exported screen of the app under test and watch the activity manager:

   ```bash
   adb logcat -c
   adb shell am start -n com.example.app/.RouterActivity -a com.example.app.ROUTE \
       --es next 'intent:#Intent;component=com.example.app/.internal.AboutDebugActivity;end'
   adb logcat -d -s ActivityTaskManager:I | grep 'START u0'
   ```

   Copy the action (and categories, data) from the router's filter: on API 33+ targets, intents that do not match the filter are dropped and you would wrongly conclude the router is safe. A `START u0 {cmp=com.example.app/.internal.AboutDebugActivity} from uid <app's own UID>` line means the app launched its own non-exported component on your behalf. For `Parcelable` sources you stop at steps 2 and 4: the code path from an exported entry point to an unchecked dispatch, plus the runtime trace, is the evidence. drozer's `app.activity.start` can set string and primitive extras, but not nested intents.

6. **Repeat on Android 16.** If the launch in step 5 is blocked only on Android 16, record that the platform mitigates it there and that the app code remains vulnerable on earlier versions.

#### Observation

Each source-to-sink path with code locations, the checks present or missing, the list of internal components it could reach, the Frida trace, the `adb` and `logcat` output, and the Android versions tested.

#### Evaluation

The check **fails** if an exported component (or code reachable from one, including deep links) dispatches an intent taken from its input without both restricting the target to an allow-list and removing grant flags. It also fails if the app opts out of the Android 16 hardening without such checks. It **passes** if forwarding is absent, or limited to resolved targets on an allow-list with grant flags stripped (for example with `IntentSanitizer`), or replaced by immutable `PendingIntent`s the app created itself.

#### Demo

The vulnerable shape, as we commonly find it in notification and deep-link dispatch code:

```kotlin
class RouterActivity : Activity() {                      // exported, filter com.example.app.ROUTE
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uri = intent.getStringExtra("next")
        if (uri != null) startActivity(Intent.parseUri(uri, Intent.URI_INTENT_SCHEME))  // no checks
        finish()
    }
}
```

With step 5, `logcat` shows the router (the app's own UID) starting `AboutDebugActivity`, which is declared `exported="false"`. The fix is in [Secure patterns](#secure-patterns-guler-tech).

### GT-0032-2: Implicit and sticky broadcasts carrying sensitive extras (Android)

Guler Tech methodology. Platform: Android. Type: static and dynamic (Frida, `adb`, drozer). Based on OWASP's [MASTG-TECH-0164 (Sniffing Implicit Intents and Broadcasts)](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0164/). Runtime-registered receivers that *accept* broadcasts from other apps are covered in [GT-0018-3 in the MASWE-0018 note](/mobile/maswe-0018-missing-auth-on-app-components/); this check covers what the app *sends*.

#### Overview

MASTG-TEST-0374 finds implicit intents with sensitive extras in code. Broadcasts deserve a check of their own because they have no chooser and no user decision: every matching receiver on the device gets a copy, and a sticky broadcast stays readable after delivery. Ordered broadcasts add a second risk: a receiver earlier in the order can change the result the app reads at the end.

#### Prerequisites

- Decompiled code, Frida, `adb`; optionally drozer ([MASTG-TOOL-0015](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0015/)) on a test device.

#### Steps

1. **List every send** with its restriction:

   ```bash
   grep -rnE '\.(sendBroadcast|sendOrderedBroadcast|sendStickyBroadcast|sendStickyOrderedBroadcast|sendBroadcastAsUser)\(' out/sources/com/example/app/
   grep -rnE 'LocalBroadcastManager' out/sources/com/example/app/
   ```

   For each send, note whether the intent has a package or component and whether a receiver permission is passed. If one is, look up its `protectionLevel` in the manifest of the app that defines it: a `normal` permission protects nothing, because any app can request it.

2. **Capture what is actually sent.** Run [intent-trace.js](#runtime-tracing-of-the-apps-own-intents) and use the app through login, refresh, payment and logout flows. Every `[sendBroadcast] IMPLICIT …` line with non-public extras is a candidate. Note `[sendStickyBroadcast]` lines regardless of content.

3. **Check the system's view of the broadcast.** `dumpsys` shows recent broadcasts and the sticky cache (extras are shown only as `(has extras)`):

   ```bash
   adb shell dumpsys activity broadcasts | grep -B2 -A4 com.example.app.SESSION_REFRESHED
   adb shell dumpsys activity broadcasts | sed -n '/Sticky broadcasts/,/^$/p'
   ```

   A sticky intent for one of the app's actions listed under the sticky section stays readable by any app until the app removes it.

4. **Confirm that another app's receiver gets the extras.** OWASP's technique uses drozer, whose agent is a separate app on the device and therefore a fair stand-in for "any other app":

   ```bash
   dz> run app.broadcast.sniff --action com.example.app.SESSION_REFRESHED
   ```

   Trigger the flow in the app under test. drozer prints the action and every extra it received. The drozer agent lags behind current Android releases (runtime receiver flags in particular), so if it receives nothing on a recent device, rely on steps 1 to 3: an unrestricted send of the extras you traced is sufficient evidence.

5. **For ordered broadcasts**, find where the app reads the result (`BroadcastReceiver` passed as `resultReceiver`, `getResultData()`, `getResultExtras()`) and whether it acts on it. A result that any receiver could set is not a trustworthy answer.

6. **Check whether the app reads sticky broadcasts it did not send**, for example `registerReceiver(null, IntentFilter(action))` for a custom action. Any app can replace that value.

#### Observation

The list of sends with restrictions, the traced extras (redacted), the `dumpsys` output, the drozer output if used, and for ordered and sticky broadcasts the code that consumes them.

#### Evaluation

The check **fails** if the app sends sensitive or security-relevant data in a broadcast that is not restricted to a package or component or protected by a `signature`-level permission, if it uses sticky broadcasts for anything other than public state, or if it bases a decision on the result of an ordered broadcast, or on a sticky broadcast, that other apps can influence. It **passes** if all custom broadcasts are restricted, no sticky broadcasts are sent, and in-app events use in-process mechanisms. `LocalBroadcastManager` itself is not a leak (it is in-process), but note it as deprecated.

#### Demo

```kotlin
// Vulnerable: any app with a receiver for this action gets the token
sendBroadcast(Intent("com.example.app.SESSION_REFRESHED").putExtra("access_token", token))
```

```text
[sendBroadcast] IMPLICIT act=com.example.app.SESSION_REFRESHED dat=null typ=null pkg=null cmp=null flg=0x0 extras=Bundle[{access_token=<redacted>}]
```

The fix is `setPackage(packageName)` if only the app listens, or no broadcast at all: an in-process `Flow` or `LiveData` that the token store updates.

### GT-0032-3: Implicit requests for results and results returned to any caller (Android)

Guler Tech methodology. Platform: Android. Type: static and dynamic (Frida, `adb`). Validation of the *content* of returned data is OWASP's [MASTG-TEST-0375](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0375/) (MASWE-0050); this check covers who is on the other end of a result.

#### Overview

Activity results travel in both directions, and both can cross a trust boundary:

- **Outgoing request, incoming result.** The app asks for something with an implicit intent (`startActivityForResult()` or `ActivityResultLauncher.launch()`) and receives the answer from whichever app handled it. The request's extras go to that app, and the answer comes from it. If the action is generic (`ACTION_GET_CONTENT`, `ACTION_IMAGE_CAPTURE`), handling an answer from any app is the design, and the app must validate it. If the action is custom and the app treats the answer as coming from its own component or a partner (an account ID, a "verified" flag, a signed-in state), the trust is misplaced.
- **Incoming request, outgoing result.** An exported activity started for a result returns data with `setResult()` to whichever app started it. Without a check of `getCallingPackage()` (and the caller's signature), it hands tokens, files or URI grants to any caller.

#### Prerequisites

- Decompiled code, Frida, `adb`.

#### Steps

1. **Find requests for results** and classify the intents as in MASTG-TEST-0372:

   ```bash
   grep -rnE 'startActivityForResult\(|registerForActivityResult\(|\.launch\(' out/sources/com/example/app/
   grep -rnE 'onActivityResult\(' out/sources/com/example/app/
   ```

   For each implicit request, read the result handler: what does it do with `getData()`, `getClipData()` and the extras? Does it check the scheme, authority and type, or the identity of the app that answered?

2. **See which apps can answer** each implicit request on the device, and whether the app pre-selects one:

   ```bash
   adb shell cmd package query-activities --components -a com.example.app.PICK_ACCOUNT
   grep -rnE 'queryIntentActivities\(|resolveActivity\(' out/sources/com/example/app/
   grep -A3 '<queries>' apk_out/AndroidManifest.xml
   ```

   Code that takes the first entry of `queryIntentActivities()` and sets it as the component removes the user's choice, so the first app returned gets the request.

3. **Find exported activities that return results:**

   ```bash
   grep -rnE 'setResult\(' out/sources/com/example/app/
   grep -rnE 'getCallingPackage\(|getCallingActivity\(' out/sources/com/example/app/
   ```

   Keep the `setResult` hits in exported activities. For each, note what goes into the result and whether `getCallingPackage()` is checked against an allow-list with a signature check. An activity that returns its own incoming intent (`setResult(RESULT_OK, intent)`) passes back whatever data and grant flags the caller put in.

4. **Observe at runtime.** With [intent-trace.js](#runtime-tracing-of-the-apps-own-intents), implicit requests appear as `[startActivity] IMPLICIT …` lines from `startActivityForResult`, and every result the app returns appears as a `[setResult] caller=<package> …` line. To exercise an exported result-returning activity from outside, start it with `adb` (copy the filter's action):

   ```bash
   adb shell am start -W -n com.example.app/.ExportTokenActivity -a com.example.app.GET_TOKEN
   ```

   `am` cannot read the result, but the Frida `[setResult]` line shows what the activity returned and to whom. A started-not-for-result call shows `caller=null`. Launched for a result by another app, the activity returns the same data to that app, as your static review of step 3 shows.

#### Observation

The list of result requests with their intents and handlers, the apps that can answer each implicit request, the exported activities that return results with their payloads and caller checks, and the runtime trace.

#### Evaluation

The check **fails** if the app sends a custom implicit request for a result and trusts the answer as if it came from a known component, if a result handler acts on returned data without validating it (also report under MASTG-TEST-0375), or if an exported activity returns sensitive data or URI grants without verifying the calling package and its signature. It **passes** if result requests to the app's own or partner components are explicit, generic requests are validated, and exported activities that return results check their caller.

#### Demo

```kotlin
// Vulnerable: custom implicit request, result trusted
val pick = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
    val accountId = r.data?.getStringExtra("account_id") ?: return@registerForActivityResult
    session.switchTo(accountId)                       // whoever answered chose the account
}
pick.launch(Intent("com.example.app.PICK_ACCOUNT"))   // no component, no package

// Vulnerable: exported activity returns a token to any caller
class ExportTokenActivity : Activity() {             // exported, filter com.example.app.GET_TOKEN
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(RESULT_OK, Intent().putExtra("token", tokenStore.current()))   // no caller check
        finish()
    }
}
```

```text
[startActivity] IMPLICIT act=com.example.app.PICK_ACCOUNT dat=null typ=null pkg=null cmp=null flg=0x0 extras=none
[setResult] caller=null code=-1 explicit act=null ... extras=Bundle[{token=<redacted>}]
```

## Best practices

OWASP links two best practices to these tests. We add patterns for the cases they do not cover.

### MASTG-BEST-0056: Use Explicit Intents for Internal IPC

Source: [MASTG-BEST-0056](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0056/).

Address internal intents to a component, which is the most restrictive form, or at least to your own package:

```kotlin
// Most restrictive: one component
startActivity(Intent(context, TargetActivity::class.java).putExtra("key", "value"))

// Package-scoped: still resolved by action, but only inside this app
startActivity(Intent("com.example.app.PROCESS_DATA").setPackage(context.packageName))
```

Never put tokens, credentials or keys in an implicit intent. Keep the internal component `exported="false"` and remove its intent filter (see MASTG-BEST-0052 in the [MASWE-0018 note](/mobile/maswe-0018-missing-auth-on-app-components/)). For broadcasts the same rule means `setPackage(packageName)` or a component, and `RECEIVER_NOT_EXPORTED` on the receiver.

### MASTG-BEST-0063: Use Immutable PendingIntents with Explicit Intents

Source: [MASTG-BEST-0063](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0063/).

```kotlin
val intent = Intent(context, TargetActivity::class.java).setPackage(context.packageName)
val pi = PendingIntent.getActivity(context, requestCode, intent,
    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
```

Use `FLAG_MUTABLE` only where the receiving side must fill something in (inline reply actions, bubbles, some widget collection items). Even then, make the base intent explicit and leave open only the fields you expect to be filled. Add `FLAG_ONE_SHOT` for actions that must not be repeated, and give `PendingIntent`s that should be distinct a distinct request code or `setIdentifier()` (API 29+), because extras do not make them different tokens.

### Secure patterns (Guler Tech)

**Forwarding intents, if you must.** Rebuild the intent rather than forwarding the one you received, or sanitise it against an allow-list:

```kotlin
val nested = IntentCompat.getParcelableExtra(intent, "next", Intent::class.java) ?: return finish()
val safe = IntentSanitizer.Builder()
    .allowComponent(ComponentName(this, OrderDetailsActivity::class.java))
    .allowExtra("order_id", String::class.java)
    .build()
    .sanitizeByFiltering(nested)          // drops anything not allowed, including grant flags
startActivity(safe)
```

`IntentSanitizer` (AndroidX Core) removes grant flags unless you allow them explicitly. A hand-written check must resolve the target (`resolveActivity(packageManager)`) and compare package *and* class, clear `FLAG_GRANT_*` flags and the selector, and must not rely on `getCallingActivity()`. For deep-link routers, map path segments to your own explicit intents instead of calling `Intent.parseUri()` on input.

**Talking to a partner app.** Set the package, then confirm the installed app is the one you expect before sending anything sensitive. On API 28+ use `PackageManager.hasSigningCertificate(packageName, certSha256, PackageManager.CERT_INPUT_SHA256)`; for broadcasts, require a `signature` permission defined by your apps.

**Returning results.** Check the caller before returning anything:

```kotlin
val caller = callingPackage
val trusted = caller != null && packageManager.hasSigningCertificate(
    caller, PARTNER_CERT_SHA256, PackageManager.CERT_INPUT_SHA256)
if (!trusted) { setResult(RESULT_CANCELED); finish(); return }
```

**Requesting results.** Use explicit intents for internal and partner flows. For generic actions, validate what comes back: accept only `content://` URIs from expected authorities, never `file://`, check the MIME type, and do not use provider-supplied file names as paths.

**Broadcasts.** `setPackage(packageName)` plus `ContextCompat.registerReceiver(…, ContextCompat.RECEIVER_NOT_EXPORTED)` for internal events, or replace them with `Flow`/`LiveData`. No sticky broadcasts. From Android 14, use `BroadcastOptions.setShareIdentityEnabled(true)` on the sender and `getSentFromPackage()` on the receiver where the receiver needs the sender's identity.

**Reading extras.** Use `IntentCompat.getParcelableExtra(intent, key, Class)` and `BundleCompat.getParcelable(bundle, key, Class)`, avoid `Serializable` in IPC, and wrap extra reads in exported components in `try`/`catch` for `BadParcelableException`, `ClassCastException` and `RuntimeException`.

**During development.** Enable `StrictMode.VmPolicy.Builder().detectUnsafeIntentLaunch()` in debug builds; it flags launches of intents unparcelled from another app's input.

## Rating findings

Rate on three things: **what the intent carries or enables** (credentials and tokens, personal data, an internal action, a URI grant), **who can obtain it** (any app without permissions; an app the user has granted notification access or another special access; only after a user's choice in a chooser), and **whether the path is reached** in the release app. MAS-ATTACK-0049 and 0050 assume another app is installed. We treat that as a realistic precondition for consumer apps, not as a mitigating factor.

| Rating | Conditions |
|---|---|
| **Critical** | Without user interaction, any installed app without permissions can obtain authentication material (session or refresh tokens, credentials, keys) through an implicit intent, broadcast or sticky broadcast; or can, through intent redirection or an exposed mutable `PendingIntent` with an implicit or empty base intent, obtain URI grants to files holding such material or trigger an account-level action (password, PIN or payee change, payment, device linking). |
| **High** | The same, but the data is other personal, financial or health data; intent redirection or an exposed mutable `PendingIntent` reaches non-exported components with sensitive functions; a forged result or ordered-broadcast result changes a security decision (account selection, verification state, payment confirmation); an exported activity returns tokens to any caller. |
| **Medium** | Delivery needs one user choice in a chooser, or the token is only exposed through notifications (attacker needs user-granted notification access); a mutable `PendingIntent` with an explicit base intent whose target trusts injected extras; sticky broadcasts with non-public but non-credential data; redirection that only reaches components with limited impact; `FLAG_ONE_SHOT` missing on a single-use sensitive action. |
| **Low** | Implicit intents for internal communication without sensitive extras; mutable `PendingIntent`s that never leave the system (alarms); `FLAG_MUTABLE` with an explicit base intent and no reachable consumer of extras; extras read without typed APIs or exception handling (crash only); redirection paths blocked on all supported Android versions by other checks. |
| **Info** | `LocalBroadcastManager` still in use; deliberate user-driven sharing through choosers; `FLAG_MUTABLE` used for inline replies with explicit base intents; findings reproducible only on Android versions below the app's `minSdkVersion`. |

Lower a level when the only path requires the user to pick an obviously unrelated app in a chooser *and* the extras are low value. Do not lower for Android 16's redirection hardening unless the app's `minSdkVersion` is 36. Raise a level when the exposed data or action affects other users (an admin token, a shared account) or when the path runs automatically at start-up or on every refresh. In the report give the code location (class and method from jadx), the manifest entry of the component involved, the `targetSdkVersion` and the Android versions tested, the trace line or `adb`/`dumpsys` output that proves the path, and the fix at the sending or forwarding site.

## References

- OWASP MASWE: [MASWE-0032: Insecure Intents](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0032/); related [MASWE-0018](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0018/), [MASWE-0029](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0029/), [MASWE-0050](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/), [MASVS-STORAGE-2](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0020](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0020/), [MASTG-KNOW-0025](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0025/), [MASTG-KNOW-0024](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0024/), [MASTG-KNOW-0132](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0132/), [MASTG-KNOW-0133](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0133/), [MASTG-KNOW-0134](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0134/), [MASTG-KNOW-0021](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0021/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0372](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0372/), [MASTG-TEST-0374](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0374/), [MASTG-TEST-0381](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0381/), [MASTG-TEST-0375](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0375/); legacy [MASTG-TEST-0026](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0026/), [MASTG-TEST-0029](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0029/), [MASTG-TEST-0030](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0030/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0136](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0136/MASTG-DEMO-0136/), [MASTG-DEMO-0140](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0140/MASTG-DEMO-0140/), [MASTG-DEMO-0138](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0138/MASTG-DEMO-0138/), [MASTG-DEMO-0147](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0147/MASTG-DEMO-0147/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0056](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0056/), [MASTG-BEST-0063](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0063/), [MASTG-BEST-0052](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0052/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0164](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0164/) (CC BY-SA 4.0)
- OWASP MASTG tools: [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [adb (MASTG-TOOL-0004)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/), [drozer (MASTG-TOOL-0015)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0015/) (CC BY-SA 4.0)
- Android Developers, guides: [Intents and intent filters](https://developer.android.com/guide/components/intents-filters), [Broadcasts overview](https://developer.android.com/develop/background-work/background-tasks/broadcasts), [Implicit broadcast exceptions](https://developer.android.com/develop/background-work/background-tasks/broadcasts/broadcast-exceptions), [Getting a result from an activity](https://developer.android.com/training/basics/intents/result), [`<intent-filter>` element](https://developer.android.com/guide/topics/manifest/intent-filter-element)
- Android Developers, risk pages: [Implicit intent hijacking](https://developer.android.com/privacy-and-security/risks/implicit-intent-hijacking), [Intent redirection](https://developer.android.com/privacy-and-security/risks/intent-redirection), [Pending intents](https://developer.android.com/privacy-and-security/risks/pending-intent), [Sender of pending intents](https://developer.android.com/privacy-and-security/risks/sender-of-pending-intents), [Sticky broadcasts](https://developer.android.com/privacy-and-security/risks/sticky-broadcast); Google Play Help [Remediation for Intent Redirection](https://support.google.com/faqs/answer/9267555)
- Android Developers, behaviour changes: [Android 12](https://developer.android.com/about/versions/12/behavior-changes-12), [Android 13](https://developer.android.com/about/versions/13/behavior-changes-13), [Android 14](https://developer.android.com/about/versions/14/behavior-changes-14), [Android 15](https://developer.android.com/about/versions/15/behavior-changes-15), [Android 16 (all apps)](https://developer.android.com/about/versions/16/behavior-changes-all)
- Android API reference: [`Intent`](https://developer.android.com/reference/android/content/Intent) (incl. [`fillIn()`](https://developer.android.com/reference/android/content/Intent#fillIn(android.content.Intent,%20int)) and `removeLaunchSecurityProtection()`), [`PendingIntent`](https://developer.android.com/reference/android/app/PendingIntent), [`IntentSanitizer`](https://developer.android.com/reference/kotlin/androidx/core/content/IntentSanitizer), [`LocalBroadcastManager`](https://developer.android.com/jetpack/androidx/releases/localbroadcastmanager); AOSP sources of [`Intent.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/content/Intent.java) and [`PendingIntent.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/app/PendingIntent.java); [A-156959408](https://android.googlesource.com/platform/frameworks/base/+/6ae2bd0e59636254c32896f7f01379d1d704f42d)
- CWE: [CWE-927](https://cwe.mitre.org/data/definitions/927.html), [CWE-940](https://cwe.mitre.org/data/definitions/940.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
