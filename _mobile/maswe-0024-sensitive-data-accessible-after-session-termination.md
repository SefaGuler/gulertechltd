---
title: "Sensitive Data Accessible After Session Termination (MASWE-0024)"
date: 2026-11-09 08:32:00 +0000
subcategory: auth
summary: "Testing logout, timeouts and token revocation on Android and iOS: replaying old tokens, finding leftover data, back navigation, deep links, reinstall."
refs: [MASWE-0024, MASVS-AUTH-3, CWE-285, CWE-287, CWE-613]
tags: [android, ios, masvs-auth, session-management, logout, oauth]
---

This note is part of our [MASVS-AUTH guide](/mobile/masvs-auth-authentication-guide/) and covers OWASP [MASWE-0024](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0024/): sessions and data that survive the moment they should have ended. "Log out" is a promise with two halves. The server must stop honouring everything it issued for that session, and the device must stop holding and showing what the session gave it. Mobile apps break both halves in characteristic ways: refresh tokens that keep minting access tokens after logout, logout calls that fail silently offline, HTTP caches and WebView storage full of account data, notifications and widgets that keep displaying it, back stacks that still render the last screen, and on iOS, Keychain items that outlive the app itself. Below you will find what counts as session termination, how revocation works on the server (OAuth token revocation, refresh token rotation, OpenID Connect logout), where session state lives on each platform and how to remove it, our tests — token replay, before-and-after filesystem diffs with canaries, back navigation and deep links, reinstall and timeout behaviour — secure Kotlin and Swift, and severity guidance.

> **Note:** At the time of writing, MASWE-0024 has no linked Knowledge pages or Tests on mas.owasp.org; the weakness page says "No Tests Yet". The MASTG does contain related material — the "User Logout" section of its general authentication chapter, WebView cleanup tests, app-switcher screenshot tests, notification tests and storage tests — which we list in [Related OWASP material](#related-owasp-material). The Knowledge and Testing sections below are **Guler Tech methodology**.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Both platforms: what counts as session termination](#both-platforms-what-counts-as-session-termination)
  - [Both platforms: invalidating sessions and tokens on the server](#both-platforms-invalidating-sessions-and-tokens-on-the-server)
  - [Both platforms: the browser session behind the app](#both-platforms-the-browser-session-behind-the-app)
  - [Android: where session state lives and how to remove it (MASTG-KNOW-0041, MASTG-KNOW-0018)](#android-where-session-state-lives-and-how-to-remove-it-mastg-know-0041-mastg-know-0018)
  - [Android: system surfaces that outlive the session (MASTG-KNOW-0053, MASTG-KNOW-0054)](#android-system-surfaces-that-outlive-the-session-mastg-know-0053-mastg-know-0054)
  - [iOS: where session state lives and how to remove it (MASTG-KNOW-0057, MASTG-KNOW-0108, MASTG-KNOW-0125)](#ios-where-session-state-lives-and-how-to-remove-it-mastg-know-0057-mastg-know-0108-mastg-know-0125)
  - [iOS: system surfaces that outlive the session (MASTG-KNOW-0099)](#ios-system-surfaces-that-outlive-the-session-mastg-know-0099)
  - [Both platforms: memory, navigation and deep links](#both-platforms-memory-navigation-and-deep-links)
  - [Both platforms: timeouts and re-authentication](#both-platforms-timeouts-and-re-authentication)
- [Testing](#testing)
  - [Related OWASP material](#related-owasp-material)
  - [GT-0024-1: Logout and timeout implementation in code (Android and iOS)](#gt-0024-1-logout-and-timeout-implementation-in-code-android-and-ios)
  - [GT-0024-2: Replaying tokens after session termination (Android and iOS)](#gt-0024-2-replaying-tokens-after-session-termination-android-and-ios)
  - [GT-0024-3: Data left in the sandbox after logout (Android)](#gt-0024-3-data-left-in-the-sandbox-after-logout-android)
  - [GT-0024-4: Data left in the sandbox and Keychain after logout (iOS)](#gt-0024-4-data-left-in-the-sandbox-and-keychain-after-logout-ios)
  - [GT-0024-5: Memory, navigation, deep links and system surfaces after logout (Android and iOS)](#gt-0024-5-memory-navigation-deep-links-and-system-surfaces-after-logout-android-and-ios)
  - [GT-0024-6: Sessions restored by reinstall or backup (iOS and Android)](#gt-0024-6-sessions-restored-by-reinstall-or-backup-ios-and-android)
  - [GT-0024-7: Idle, absolute and background timeouts (Android and iOS)](#gt-0024-7-idle-absolute-and-background-timeouts-android-and-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0024 applies when sensitive data or an authenticated session remains accessible after the session should have ended. The OWASP requirement is *"The app makes sensitive data inaccessible after session termination."* It maps to MASVS-AUTH-3 and to [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html), [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) and [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html). It is tagged with the [MAS-L2](https://mas.owasp.org/Profiles/MAS-L2/) and [MAS-EUDIW](https://mas.owasp.org/Profiles/MAS-EUDIW/) profiles: apps where an account holds money, health or identity data, and identity wallets whose sessions authorise credential presentation. In an L1-only engagement, treat the client-side residue items as hardening observations; server-side token revocation failures are findings at any level.

OWASP's threat is MAS-THREAT-0024, *"Attackers can access sensitive data or resume a session after it should have ended,"* with three attacks:

- **MAS-ATTACK-0032 — using a victim's device with an active session** (an unlocked or stolen device). The session never timed out, or "logout" only changed the screen.
- **MAS-ATTACK-0033 — reusing stolen session tokens obtained through other attacks.** A token captured from traffic, logs, a backup or a compromised SDK is still accepted after the user logged out, changed their password or used "sign out of all devices".
- **MAS-ATTACK-0005 — accessing device storage on a compromised device.** Cached responses, databases, WebView storage and Keychain items from the "terminated" session are still on disk.

**What a mobile tester can and cannot prove.** MASVS-AUTH is explicit that enforcement belongs on the remote endpoint, and this weakness is half server-side. From the client you can prove the important server-side failure directly: capture a token before termination and show that the API still accepts it afterwards (GT-0024-2). That is not inference; it is the server's own answer. What you cannot see from the client is *why* — whether the backend keeps a session store, checks a denylist, or simply never looks — and you cannot test every token-issuing component the app does not talk to. Where the engagement includes the backend, pair these tests with the [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) session management tests (WSTG-SESS-06 logout, WSTG-SESS-07 session timeout) and the session management chapter (V7) of [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/). The client-side half — what remains on the device and on screen — is fully testable from the app.

## Modes of Introduction

OWASP lists five modes; each comes with recognisable mobile variants.

**Sessions not invalidated server-side.** The app deletes its tokens and shows the login screen, but never tells the server, or tells it in a way that does not revoke anything:

- the logout endpoint invalidates the access token but not the **refresh token**, which keeps minting new access tokens;
- the backend issues self-contained JWT access tokens with long lifetimes and no revocation check;
- the logout call is fire-and-forget and fails offline, with no retry;
- password change, "sign out of all devices", account deletion or an administrator's lock do not touch existing sessions;
- refresh tokens are not rotated, or rotation exists without **reuse detection**, so a stolen refresh token stays useful indefinitely.

**Missing client-side session termination.** No logout option at all, or one buried where users do not find it; no timeout of any kind.

**No re-authentication on state changes.** The app resumes from the background straight into account screens, however long it was away; significant changes (a new device, a password changed elsewhere, a SIM swap signal, a large location jump) do not trigger re-authentication. OWASP gives location and profile changes as examples; which signals matter is the backend's risk decision.

**Cached data not cleared.** Tokens, personal data, in-memory objects or on-screen content remain after the session ends:

- HTTP caches (`Cache.db` on iOS, the OkHttp cache on Android) holding account responses;
- WebView cookies, `localStorage` and IndexedDB, where hybrid screens keep their own session;
- databases, preferences and files that hold the user's data;
- Keychain items, which on iOS survive even uninstalling the app;
- shared containers read by widgets and extensions, delivered notifications, app-switcher snapshots, Spotlight entries;
- the identity provider's browser session in Custom Tabs or `ASWebAuthenticationSession`, which silently signs the next person back in.

**Missing inactivity timeout.** Sessions that never expire, or expire only on an absolute limit measured in months.

## Impact

- **Authentication or authorisation bypass.** Whoever holds the device or a leftover token resumes the session without credentials and acts as the user: moving money, changing contact details (a step towards full account takeover), presenting credentials from a wallet.
- **Remediation that does not remediate.** A user who suspects compromise logs out, changes their password or signs out everywhere. If those actions do not revoke existing tokens, the attacker keeps access precisely when the user believes it has been removed.
- **Compromise of sensitive data.** Personal data from the terminated session remains readable on disk, on screen, in notifications or widgets, to the next user of a shared or resold device, or to anyone with access to a compromised one.
- **Regulatory exposure.** Payment services in the EU must time out online sessions after at most five minutes of inactivity under the PSD2 SCA technical standards; health and identity apps carry similar expectations. A session that never ends is a compliance gap as well as a security one.

## Mitigations

- **Revoke on the server, for every termination trigger.** Logout, timeout, password change, account recovery, "sign out everywhere", account deletion and administrative locks must invalidate the server session or the refresh token family, and short-lived access tokens must either be checked against revocation or expire within minutes ([OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)).
- **Rotate refresh tokens with reuse detection**, or sender-constrain them, as RFC 9700 requires for public clients.
- **Clear everything local when the session ends**, even if the server call fails: tokens and keys, databases, caches, WebView storage, shared containers, notifications, widgets and in-memory state; then reset navigation to a clean login stack.
- **End or isolate the identity provider's browser session**: OpenID Connect RP-initiated logout, or ephemeral browser sessions for sign-in.
- **Enforce idle and absolute timeouts on the server**, mirror them in the app for UX, and require re-authentication when the app returns from the background after the idle limit or after sensitive flows ([MASWE-0023 step-up](/mobile/maswe-0023-step-up-authentication-not-implemented/)).
- **Clean up stale state on first launch** (iOS Keychain) and do not let backups restore live sessions.

## Knowledge

None of the sections below is an OWASP Knowledge page dedicated to MASWE-0024. Where a MASTG Knowledge page covers a storage location or platform surface, we name it in the heading. Storage locations themselves are covered in depth in our [MASWE-0001 note](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/#knowledge); here we focus on what must be removed when a session ends and how.

### Both platforms: what counts as session termination

"Session termination" is any event after which the app's current authenticated state should no longer grant access. The MASTG's general authentication chapter puts it plainly in its [User Logout](https://mas.owasp.org/MASTG/0x04e-Testing-Authentication-and-Session-Management/#user-logout) section: failing to destroy the server-side session is one of the most common logout implementation errors. A complete test covers every trigger the app and backend support:

| Trigger | Initiated by | Server must | Device must |
|---|---|---|---|
| Explicit logout | User, in this app | Revoke this session's refresh token / session ID; reject its access tokens | Clear tokens, data, caches, UI |
| Idle timeout | Server clock (and app timer for UX) | Reject the session after the idle limit | Lock or clear when the app notices |
| Absolute timeout | Server clock | Reject the session after the absolute limit, even if active | Require full sign-in |
| Background / resume | App | — (or shorter server idle limit) | Re-authenticate or lock on return |
| Token revocation | Server, IdP, admin | Revoke token family | Detect `401`/`invalid_grant`, clear local state |
| Password change or reset | User, possibly on another device | Revoke all *other* sessions (and this one, unless re-issued) | Other devices clear state on next call |
| "Sign out of all devices" / remote sign-out | User, on any device | Revoke all sessions | Each device clears on next call or push |
| Account deletion or suspension | User, support, admin | Revoke all sessions and device registrations | Clear everything |
| Significant context change | Server risk engine | Step-up or revoke | Re-authenticate |

For each row, the device side has a weakness of its own: a device that learns about termination only when it next calls the API may show cached data until then. That is why widgets, notifications and offline modes appear in the tests below.

### Both platforms: invalidating sessions and tokens on the server

The MASTG chapter distinguishes **stateful** authentication (the server keeps a session record keyed by a random session ID) from **stateless** authentication (the client carries signed tokens such as JWTs that the server validates without a lookup). Termination works differently in each.

**Stateful sessions** end when the server deletes the record. Logout is a single, reliable operation, and every request after it fails. Mistakes here are the classic web ones: deleting the client cookie but not the record, or keeping the record alive because another device shares it.

**Stateless access tokens** cannot be "deleted": a signed JWT remains valid until its `exp` unless the resource server checks something else. Options, in rising order of strength:

1. **Short lifetimes** (minutes) so that a token outlives logout only briefly. This is the common compromise, and it is acceptable only if the *refresh* token is revoked.
2. **A revocation check** on each request: a denylist of token IDs (`jti`) or, more practically, of session IDs (`sid`) or a per-user "tokens issued before" timestamp checked against `iat`.
3. **Introspection** ([RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)): opaque access tokens validated by asking the authorisation server, which always knows the current state.

**Refresh tokens** are long-lived credentials and the real key to the account. The [OAuth 2.0 Security BCP (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700) requires that refresh tokens issued to public clients — which every mobile app is — be either **sender-constrained** (bound to a key the client holds, for example with DPoP, [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) or **rotated**: each use returns a new refresh token and invalidates the old one, and if an old one is ever presented again the server treats it as theft and revokes the whole token family. Without rotation, a stolen refresh token works until it expires; with rotation but no reuse detection, it works until the legitimate client happens to refresh first.

**Revocation endpoints.** [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) defines a `revocation_endpoint` that accepts `token=…&token_type_hint=refresh_token`. When a refresh token is revoked, the RFC says the server *should* also invalidate access tokens issued from the same grant if it can. The server returns `200` even for unknown tokens, so a `200` from the revocation endpoint proves nothing — only a failed replay does. Authorisation servers advertise the endpoint in their metadata (`/.well-known/openid-configuration` or `/.well-known/oauth-authorization-server`).

**OpenID Connect logout.** Three specifications coordinate logout between an identity provider and relying parties:

- [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html): the app sends the user to the IdP's `end_session_endpoint` with `id_token_hint` (and optionally `post_logout_redirect_uri` and `state`), which ends the IdP's own session.
- [Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html): the IdP POSTs a signed *logout token* (with `sub` and/or `sid` and the `http://schemas.openid.net/event/backchannel-logout` event) to each relying party's `backchannel_logout_uri`. For a mobile app this lands on the app's backend, which must then kill its own sessions and, ideally, push a sign-out to the device.
- Front-Channel Logout, which relies on browser iframes and is of little use to native apps.

**Device registrations.** Push tokens (FCM, APNs), device-binding keys and "trusted device" records are part of the session too. If the server still maps the device's push token to the account after logout, notifications with account data keep arriving on a device that is no longer signed in.

### Both platforms: the browser session behind the app

Apps that sign in through Custom Tabs or `ASWebAuthenticationSession` (as RFC 8252 requires, see our [MASWE-0019 note](/mobile/maswe-0019-no-autofill-support-for-credential-providers/#both-platforms-system-authentication-sessions-for-third-party-login)) leave a session cookie at the identity provider in the **browser**, not in the app. Deleting the app's tokens does not touch it. The next "Sign in" tap opens the IdP, finds a valid cookie, and returns a fresh authorisation code without asking for a password. On a shared or stolen device, that is a full session resumption.

Ways to close the gap:

- **RP-initiated logout** to the IdP's `end_session_endpoint` as part of logout.
- **Ephemeral browser sessions**: on iOS, `ASWebAuthenticationSession.prefersEphemeralWebBrowserSession = true` keeps no cookies after the session; on Android, Custom Tabs share the browser's cookie jar, so rely on RP-initiated logout or on authorisation request parameters.
- **Request parameters**: `prompt=login` forces re-authentication; `max_age` limits how old the IdP's authentication may be.

Federated sign-in through Credential Manager or Sign in with Google adds one more piece of state: auto-select. Android's guidance is to call `clearCredentialState(ClearCredentialStateRequest())` on sign-out so providers stop signing the user back in automatically (the [handle sign-out](https://developer.android.com/identity/sign-in/credential-manager-siwg-implementation#handle-sign-out) section that MASWE-0024 itself references).

### Android: where session state lives and how to remove it (MASTG-KNOW-0041, MASTG-KNOW-0018)

Related: [MASTG-KNOW-0041](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0041/) (Internal Storage), [MASTG-KNOW-0036](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0036/) (Shared Preferences), [MASTG-KNOW-0037](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0037/) (SQLite) and [MASTG-KNOW-0018](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/) (WebViews). The directory layout is in our [MASWE-0001 note](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/#android-internal-storage-mastg-know-0041).

| State | Typical location | How to remove it on logout | Pitfalls |
|---|---|---|---|
| Tokens | `shared_prefs/*.xml`, `files/datastore/*.preferences_pb`, encrypted with a Keystore key | `edit().clear().commit()`; `dataStore.edit { it.clear() }`; delete the Keystore alias (`KeyStore.deleteEntry`) | `apply()` is asynchronous; a crash before it flushes leaves the file. Deleting the key alone makes ciphertext unreadable but leaves it on disk |
| User data | `databases/*.db` plus `-wal`/`-shm` | Close the database and `context.deleteDatabase(name)` | `DELETE`/`clearAllTables()` leaves data in free pages and WAL frames unless `secure_delete` or `VACUUM` |
| HTTP cache | `cache/` (OkHttp `Cache` directory: `journal`, `<key>.0` headers, `<key>.1` body) | `cache.evictAll()`; better, do not cache authenticated responses (`Cache-Control: no-store`) | Image loaders (Coil, Glide) keep their own caches of avatars and document thumbnails |
| WebView | `app_webview/` (cookies, `Local Storage`, `IndexedDB`, HTTP cache) | `CookieManager.removeAllCookies` + `flush()`, `WebStorage.deleteAllData()`, `WebView.clearCache(true)` | As MASTG-KNOW-0018 explains, IndexedDB and OPFS are not covered by `WebStorage`; only clearing the profile removes them |
| Files | `files/`, `no_backup/`, `Android/data/<pkg>/` | `deleteRecursively()` on per-user directories | External app-specific storage is easy to forget ([MASWE-0002 note](/mobile/maswe-0002-sensitive-data-unencrypted-outside-private-storage/)) |
| Accounts | `AccountManager` | `removeAccountExplicitly`, `invalidateAuthToken` | Sync adapters keep running for a removed account until cancelled |
| Background work | WorkManager, alarms, foreground services | `WorkManager.cancelAllWork()` (or tagged work) | A sync job that runs after logout repopulates the cache with the old token |

The bluntest tool is `ActivityManager.clearApplicationUserData()`, which wipes everything the app owns and kills the process — effective for "remove account", heavy-handed for routine logout. Whatever the approach, **local clearing must not depend on the server call succeeding**: revoke if you can, queue the revocation if you are offline, and clear the device regardless.

### Android: system surfaces that outlive the session (MASTG-KNOW-0053, MASTG-KNOW-0054)

Related: [MASTG-KNOW-0053](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0053/) (Screenshots) and [MASTG-KNOW-0054](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0054/) (App Notifications).

- **Recents thumbnails.** The system captures the task's last screen when it leaves the foreground (stored under `/data/system_ce/0/snapshots`, per OWASP's [MASTG-TEST-0289](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0289/)). If an idle timeout fires while the app is in the background, the thumbnail still shows the account until the app is next foregrounded. `FLAG_SECURE` or `setRecentsScreenshotEnabled(false)` ([MASTG-BEST-0015](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0015/)) on sensitive screens prevents this.
- **Notifications.** Delivered notifications stay in the shade after logout unless the app cancels them (`NotificationManagerCompat.cancelAll()`), and new ones keep arriving while the server maps the FCM token to the account. The app should delete its FCM token (`FirebaseMessaging.deleteToken()`) and the backend must drop the registration.
- **App widgets** render from data the app pushed through `AppWidgetManager`; they keep showing balances or messages until updated.
- **Shortcuts and Credential Manager.** Dynamic shortcuts naming accounts or contacts (`ShortcutManager.removeAllDynamicShortcuts()`), and federated auto-select (`clearCredentialState`).
- **Back stack.** Activities below the login screen remain in the task. Starting login with `FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_CLEAR_TASK` (or `finishAffinity()` first) empties it; Navigation component apps should `popUpTo` the graph root inclusively.

### iOS: where session state lives and how to remove it (MASTG-KNOW-0057, MASTG-KNOW-0108, MASTG-KNOW-0125)

Related: [MASTG-KNOW-0057](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/) (Keychain Services), [MASTG-KNOW-0108](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0108/) (App Sandbox Directories) and [MASTG-KNOW-0125](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0125/) (App Groups). Container layout and Data Protection are in our [MASWE-0001 note](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/#ios-app-sandbox-directories-mastg-know-0108).

| State | Typical location | How to remove it on logout | Pitfalls |
|---|---|---|---|
| Tokens | Keychain (`kSecClassGenericPassword`) | `SecItemDelete` with the item's class, service and access group | **Keychain items survive app deletion.** Synchronizable items need `kSecAttrSynchronizable: kSecAttrSynchronizableAny` in the delete query |
| URL cache | `Library/Caches/<bundle-id>/Cache.db` and `fsCachedData/` | `URLCache.shared.removeAllCachedResponses()`; better, `.ephemeral` sessions or `Cache-Control: no-store` | Custom `URLSession`s have their own `URLCache` |
| Cookies | `Library/Cookies/Cookies.binarycookies` | `HTTPCookieStorage.shared.removeCookies(since: .distantPast)` | Session cookies used by the API as well as by web views |
| WebKit | `Library/WebKit/WebsiteData/`, `Library/Caches/<bundle-id>/WebKit/` | `WKWebsiteDataStore.default().removeData(ofTypes: WKWebsiteDataStore.allWebsiteDataTypes(), modifiedSince: .distantPast)` | Use `.nonPersistent()` stores for sensitive web flows instead |
| Preferences | `Library/Preferences/<bundle-id>.plist` | Remove keys; avoid `removePersistentDomain` if it also deletes your first-launch flag | `UserDefaults` is a plist, not secure storage |
| User data | `Documents/`, `Library/Application Support/`, Core Data / SwiftData stores (`.sqlite`, `-wal`, `-shm`) | Destroy the persistent store and delete its files | Deleted rows linger in free pages and WAL |
| Shared data | App Group container `/var/mobile/Containers/Shared/AppGroup/<UUID>/`, `UserDefaults(suiteName:)` | Delete per-user files and keys; reload widgets | Extensions and widgets read it independently of the app's session |

The Keychain deserves its own paragraph. As our MASWE-0001 note explains, Keychain items belong to the device's Keychain, not the app container, so uninstalling the app does not remove them. A reinstalled app with the same access group finds its old refresh token and, if it trusts it, is signed in — on a device that may have changed hands. The standard defence is a first-launch check: keep a flag in `UserDefaults` (which *is* deleted on uninstall) and wipe the app's Keychain items if the flag is missing. Items that are not `…ThisDeviceOnly` also travel to new devices through encrypted backups and device migration; see our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#ios-keychain-accessibility-and-device-binding-mastg-know-0057) for accessibility classes.

### iOS: system surfaces that outlive the session (MASTG-KNOW-0099)

Related: [MASTG-KNOW-0099](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0099/) (Screenshots).

- **App-switcher snapshots.** iOS stores a snapshot of the UI after `applicationDidEnterBackground` (or the scene equivalent) returns, under `Library/SplashBoard/Snapshots/` ([MASTG-TEST-0290](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0290/)). A session that expires while backgrounded leaves the old snapshot visible in the switcher. Cover sensitive screens before the snapshot is taken.
- **Notifications.** `UNUserNotificationCenter.current().removeAllDeliveredNotifications()` and `removeAllPendingNotificationRequests()` remove what is on screen and scheduled; the backend must unbind the APNs device token from the account. (Apple advises calling `unregisterForRemoteNotifications()` only in rare cases, so unbinding server-side is the right control.) Notification Service Extensions that decrypt or enrich payloads using shared Keychain items will keep doing so until those items are deleted.
- **Widgets and Live Activities.** WidgetKit timelines render from App Group data; after clearing it, call `WidgetCenter.shared.reloadAllTimelines()`. End Live Activities that show account data.
- **Spotlight, Siri and Handoff.** Items indexed with Core Spotlight (`CSSearchableIndex.default().deleteAllSearchableItems()`), donated `NSUserActivity` objects (`NSUserActivity.deleteAllSavedUserActivities`) and Siri interactions (`INInteraction.deleteAll`) can expose names, payees and messages after logout.

### Both platforms: memory, navigation and deep links

Logout is also an in-process event. Session objects held by singletons, dependency-injection scopes, view models, repositories and image caches keep the previous user's data until the process dies. If the next screen after logout is the login screen in the same process, those objects are still reachable — and some apps happily render them:

- **Back navigation.** After logout, pressing Back (Android) or swiping back (iOS) returns to an account screen still in the stack, rendered from memory without a network call.
- **Deep links and exported components.** A deep link to `example://account/statements` opens the statements screen, which reads cached data or an in-memory session that was never cleared. On Android, exported activities can be started directly; our [MASWE-0018 note](/mobile/maswe-0018-missing-auth-on-app-components/) covers that weakness. Every entry point must check the session state, not just the login screen.
- **Offline mode.** Apps that show cached data when offline must not show the *previous* user's cache when the session is gone.

Strings in managed memory cannot be reliably wiped (Java/Kotlin `String` and Swift `String` are immutable and copied freely), so the realistic goal is to drop all references at logout and let the process go, not to scrub RAM. Residual strings found by a memory search after logout are a low-severity observation unless app objects still *reference* the data.

### Both platforms: timeouts and re-authentication

Two timeouts, both enforced by the server:

- **Idle (inactivity) timeout**: the session ends after a period without activity.
- **Absolute timeout**: the session ends after a fixed time regardless of activity, forcing a full sign-in.

Reference values to calibrate against, by risk:

| Source | Idle | Absolute |
|---|---|---|
| [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), AAL2 | 1 hour (recommended) | 24 hours |
| NIST SP 800-63B-4, AAL3 | 15 minutes | 12 hours |
| PSD2 RTS on strong customer authentication (Delegated Regulation (EU) 2018/389, Art. 4(3)(d)) | 5 minutes for online access to a payment account | — |
| OWASP Session Management Cheat Sheet | 2–5 minutes for high-value applications, 15–30 minutes for low-risk ones | Set per application risk |

Mobile apps usually separate the **server session** (refresh token lifetime, often days or weeks for convenience) from a **local unlock** (PIN or biometrics after the app has been in the background). That is legitimate if the local unlock is real — crypto-bound to the refresh token, as described in our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#both-platforms-event-bound-versus-crypto-bound-biometrics) — and if the server still enforces an absolute limit. A UI-only lock screen over a live session is not a timeout: hook it away or wait for the token to be used by a background job, and the session is still there. Bypassing local authentication is [MASWE-0020](/mobile/maswe-0020-local-authentication-bypass/).

Client timers should measure elapsed time with a monotonic clock (`SystemClock.elapsedRealtime()` on Android, `ProcessInfo.systemUptime` or `ContinuousClock` on iOS), not wall-clock time, which the user can change. But a client timer is a usability feature; the evidence that matters is whether the server rejects tokens after its idle and absolute limits.

## Testing

The tests below are **Guler Tech methodology**. GT-0024-1 reads the logout code so you know what to expect; GT-0024-2 tests the server half and produces the strongest evidence; GT-0024-3 to GT-0024-6 test the device half; GT-0024-7 tests timeouts. Use **canaries** throughout: before you start, set profile fields, notes, payee names and uploaded file names to unique strings (`GTCANARY-NAME-24`, `GTCANARY-ADDR-24`, `GTCANARY-PAYEE-24`), and record the first 16 characters of every token you capture. Grepping for canaries after logout finds residue that a list of "known locations" would miss.

Run every test once per termination trigger that is in scope — at least explicit logout and timeout, ideally password change, "sign out everywhere" and account deletion as well.

### Related OWASP material

No OWASP test is mapped to MASWE-0024. These existing items cover parts of it; we searched the MASTG knowledge, tests (v1 and beta), techniques, best practices, demos and general chapters, and all IDs below exist.

| ID | Platform | What it covers | Relevance to MASWE-0024 |
|---|---|---|---|
| [MASTG general chapter: User Logout](https://mas.owasp.org/MASTG/0x04e-Testing-Authentication-and-Session-Management/#user-logout) | Generic | Server-side session destruction, token deletion and invalidation on logout | The closest OWASP text to this weakness |
| [MASTG-TEST-0320](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0320/) | Android | WebViews not cleaning up sensitive data (with [MASTG-DEMO-0082](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0082/MASTG-DEMO-0082/), [MASTG-BEST-0028](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0028/)) | WebView residue after logout; walked through in our [MASWE-0001 note](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/#mastg-test-0320-webviews-not-cleaning-up-sensitive-data-android) |
| [MASTG-TEST-0037](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0037/) | Android | Legacy (MASTG v1): Testing WebViews Cleanup | Superseded by TEST-0320 |
| [MASTG-TEST-0207](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/) | Android | Runtime storage of unencrypted data in the sandbox | Same before/after method |
| [MASTG-TEST-0302](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0302/), [MASTG-TEST-0388](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0388/) | iOS | Unencrypted files in private storage; App Group containers | Residue locations |
| [MASTG-TEST-0052](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0052/) | iOS | Legacy (MASTG v1): local data storage, including `Cache.db` and `removeAllCachedResponses` after logout | Cache residue |
| [MASTG-TEST-0289](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0289/), [MASTG-TEST-0292](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0292/), [MASTG-TEST-0290](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0290/) | Android, iOS | Screenshots taken when the app is backgrounded | Snapshots that outlive a timeout |
| [MASTG-TEST-0010](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0010/), [MASTG-TEST-0059](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0059/) | Android, iOS | Legacy (MASTG v1): auto-generated screenshots | Superseded by the tests above |
| [MASTG-TEST-0315](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0315/), [MASTG-BEST-0027](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0027/) | Android | Sensitive data in notifications | Notifications after logout |
| [MASTG-TECH-0061](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0061/) | iOS | Dumping Keychain data | Keychain residue and reinstall test |
| [MASTG-TECH-0002](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/), [MASTG-TECH-0053](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0053/) | Android, iOS | Host-device data transfer | Pulling sandbox snapshots |
| [MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/), [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/), [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/) | Android, iOS | Interception proxy setup and use | Capturing tokens for replay |

### GT-0024-1: Logout and timeout implementation in code (Android and iOS)

Guler Tech methodology. Platforms: Android and iOS. Type: static (code).

#### Overview

Find the code that runs when a session ends — logout handlers, `401`/`invalid_grant` handlers, timeout timers, "delete account" flows — and list what it clears and what it calls on the server. Then compare that list with the inventory of what the app stores. The difference is your target list for the dynamic tests.

#### Prerequisites

- Decompiled sources: jadx for Android ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)); for iOS, a disassembler or decompiler ([MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)) or source code if provided.
- The storage inventory from your MASVS-STORAGE work, if available.

#### Steps

1. **Find the termination entry points.**

   ```bash
   # Android
   grep -rniE 'logout|log_out|signout|sign_out|endsession|end_session|revoke|invalid_grant|deleteAccount' \
     out/sources/ | grep -vE '^out/sources/(androidx|com/google|kotlin|okhttp3)/' | head -50
   # iOS (strings and symbols)
   strings -a "$BIN" | grep -iE 'logout|signout|sign_out|end_session|revoke|invalid_grant' | sort -u
   nm "$BIN" | xcrun swift-demangle | grep -iE 'logout|signOut|terminateSession|clearSession' | sort -u
   ```

2. **List what the logout path clears.** Search the logout class and everything it calls for removal APIs:

   ```bash
   # Android
   grep -rnE 'deleteDatabase|clearAllTables|\.clear\(\)|evictAll|deleteRecursively|removeAllCookies|deleteAllData|clearCache|deleteEntry|cancelAll|cancelAllWork|deleteToken|clearCredentialState|clearApplicationUserData|FLAG_ACTIVITY_CLEAR_TASK|finishAffinity|removeAllDynamicShortcuts' \
     out/sources/com/example/app/
   ```

   ```bash
   # iOS: selectors and imported symbols for the removal APIs
   strings -a "$BIN" | grep -xE 'removeAllCachedResponses|removeCookiesSinceDate:|removeDataOfTypes:modifiedSince:completionHandler:|removeAllDeliveredNotifications|removeAllPendingNotificationRequests|deleteAllSearchableItemsWithCompletionHandler:|reloadAllTimelines'
   nm -u "$BIN" | grep -E '_SecItemDelete|_OBJC_CLASS_\$_WKWebsiteDataStore|WidgetCenter'
   ```

   On iOS, follow `SecItemDelete` call sites and check the query: class, service, access group, and `kSecAttrSynchronizableAny` for synchronizable items.

3. **Check the server call.** Identify the request the logout path sends (logout endpoint, RFC 7009 revocation, `end_session_endpoint`), what it sends (refresh token? access token only?) and how failures are handled (ignored, retried, blocking local cleanup).

4. **Check `401` and refresh-failure handling.** The code path that runs when the API says the session is gone should perform the same cleanup as logout. Often it only navigates to the login screen.

5. **Check timeouts.** Search for timer logic (`postDelayed`, `Handler`, lifecycle observers such as `ProcessLifecycleOwner`; `sceneDidEnterBackground`, `applicationDidEnterBackground`, `Timer`, `DispatchSourceTimer`) and note which clock it uses (`currentTimeMillis`/`Date()` versus `elapsedRealtime`/`systemUptime`).

6. **Check first-launch Keychain cleanup (iOS)**: a `UserDefaults` flag read early in launch followed by `SecItemDelete`.

#### Observation

A table per termination path: server call (endpoint, tokens sent, failure handling), each local store and whether it is cleared, system surfaces handled, navigation reset, and timer implementation.

#### Evaluation

This test produces expectations rather than a verdict on its own. Record a **finding** if the code shows that a termination path makes no server call, sends only the access token, lets a failed call block or skip local cleanup, omits stores that the app is known to use (WebView, HTTP cache, App Group, Keychain), or has no `401`/`invalid_grant` cleanup. Confirm each with GT-0024-2 to GT-0024-5 before rating.

#### Demo

A logout we see often:

```kotlin
fun logout() {
    scope.launch { runCatching { api.logout() } }      // sends only the access token header
    prefs.edit().remove("access_token").apply()         // refresh token, DB, caches untouched
    startActivity(Intent(this, LoginActivity::class.java))
}
```

```text
$ grep -rnE 'deleteDatabase|evictAll|removeAllCookies|deleteAllData|FLAG_ACTIVITY_CLEAR_TASK|refresh_token' \
    out/sources/com/example/app/session/
out/sources/com/example/app/session/TokenStore.java:31:  this.prefs.edit().putString("refresh_token", str).apply();
```

The logout path removes one preference, leaves the refresh token in place, clears no caches, keeps the back stack, and sends no refresh token to the server. Expectations for GT-0024-2: the refresh token will still work. For GT-0024-3: the database, OkHttp cache and WebView storage will still hold account data.

### GT-0024-2: Replaying tokens after session termination (Android and iOS)

Guler Tech methodology. Platforms: Android and iOS. Type: dynamic (network).

#### Overview

Capture every credential the session uses, terminate the session through each supported trigger, and replay the old credentials against the API and the token endpoint. A `200` after termination is direct evidence that the server did not end the session. This is the test the client cannot argue with.

#### Prerequisites

- An interception proxy with the device's traffic routed through it ([MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/), [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/), [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/)); certificate pinning bypassed if necessary, or hooking network APIs instead ([MASTG-TECH-0119](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0119/)).
- Test accounts, ideally two devices (or a device and the website) for remote sign-out and password change.
- `curl` and `jq`. Agree with the client before running long-lived refresh loops or account deletion.

#### Steps

1. **Discover the authorisation server's capabilities.**

   ```bash
   curl -sS https://auth.example.com/.well-known/openid-configuration \
     | jq '{issuer, token_endpoint, revocation_endpoint, introspection_endpoint, end_session_endpoint, backchannel_logout_supported}'
   ```

2. **Capture the session credentials.** Log in and record from the proxy: access token, refresh token, ID token, session cookies, any device-binding or step-up tokens, and `expires_in`. Decode JWT access tokens to see their lifetime and identifiers:

   ```bash
   jwt_payload() {
     local p; p=$(cut -d. -f2 <<<"$1" | tr '_-' '/+')
     while [ $(( ${#p} % 4 )) -ne 0 ]; do p="$p="; done
     base64 -d <<<"$p"
   }
   jwt_payload "$AT" | jq '{iat, exp, lifetime_s: (.exp - .iat), sid, jti}'
   ```

   Opaque (non-JWT) tokens are a good sign: they are usually checked against the server on every request.

3. **Baseline.** Confirm the captured credentials work:

   ```bash
   curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $AT" https://api.example.com/v1/me
   ```

4. **Terminate the session in the app** (explicit logout first). In the proxy, record what the logout sends: endpoint, tokens, status. No request at all means the server was never told.

5. **Replay the access token** against several endpoints, including a sensitive one (account details, transactions, a state-changing call that is safe in the test environment):

   ```bash
   for path in /v1/me /v1/accounts /v1/transactions?limit=1; do
     printf '%s ' "$path"
     curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $AT" "https://api.example.com$path"
   done
   ```

   Record the access token's remaining lifetime at the moment of termination.

6. **Replay the refresh token** at the token endpoint:

   ```bash
   curl -sS https://auth.example.com/oauth/token \
     -d grant_type=refresh_token -d client_id=com.example.app -d refresh_token="$RT" | jq .
   ```

   Expect `"error": "invalid_grant"`. A new token pair means the session is alive.

7. **Replay session cookies** for hybrid screens and web-backed APIs in the same way.

8. **Repeat for other triggers**, each from a fresh login: idle timeout (wait out the documented limit, see GT-0024-7), password change from another device or the website, "sign out of all devices", account deletion or suspension where permitted. For password change and remote sign-out, the *other* device's tokens are the ones to replay.

9. **Test refresh token rotation and reuse detection.** From a fresh login, use `RT1` to obtain `RT2`, then present `RT1` again, then present `RT2`:

   ```bash
   r1=$(curl -sS https://auth.example.com/oauth/token -d grant_type=refresh_token -d client_id=com.example.app -d refresh_token="$RT1")
   RT2=$(jq -r .refresh_token <<<"$r1")
   curl -sS https://auth.example.com/oauth/token -d grant_type=refresh_token -d client_id=com.example.app -d refresh_token="$RT1" | jq .error
   curl -sS https://auth.example.com/oauth/token -d grant_type=refresh_token -d client_id=com.example.app -d refresh_token="$RT2" | jq .error
   ```

   With rotation, the response contains a new `refresh_token` and the second call fails. With reuse detection, the third call also fails because the family was revoked.

10. **Test offline logout.** Put the device in airplane mode, log out, reconnect, wait a few minutes, then replay the refresh token. Check whether the app retried the revocation.

11. **Test the identity provider session.** After logout, start sign-in again. If the IdP returns the user to the app without asking for credentials, the browser session survived (see [the browser session behind the app](#both-platforms-the-browser-session-behind-the-app)).

12. **Test sender binding (optional).** Replay a valid (pre-logout) token from your workstation instead of the device. Success shows the token is a pure bearer token — not a MASWE-0024 failure in itself, but it raises the impact of every replay above because a stolen token works from anywhere (MAS-ATTACK-0033).

#### Observation

For each trigger: the termination request and response, and the HTTP status (or token endpoint response) for each replayed credential, with timestamps and the credential's remaining lifetime; rotation and reuse results; offline-logout result; IdP re-sign-in behaviour; sender-binding result.

#### Evaluation

The test **fails** if, after any in-scope termination trigger:

- the refresh token, session ID or session cookie is still accepted;
- an access token is accepted beyond a short, documented window (we accept up to five minutes of residual validity for stateless access tokens when the refresh token is revoked; up to fifteen minutes is a weaker finding; more is a failure);
- password change, "sign out of all devices", account deletion or suspension leaves other devices' sessions working;
- a rotated refresh token can be reused (L2 and EUDIW apps), or rotation is absent with no sender constraint;
- the IdP silently signs the user back in after logout on an L2 app.

It **passes** when every credential from the terminated session is rejected (`401`/`invalid_grant`), apart from short-lived access tokens within the documented window.

#### Demo

```text
# before logout
$ jwt_payload "$AT" | jq '{lifetime_s: (.exp - .iat), sid}'
{ "lifetime_s": 3600, "sid": "c1a7e0d2" }
$ curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $AT" https://api.example.com/v1/me
200

# app logout sends: POST /v1/logout  (Authorization: Bearer <AT>)  -> 204

$ curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $AT" https://api.example.com/v1/me
200
$ curl -sS https://auth.example.com/oauth/token -d grant_type=refresh_token \
    -d client_id=com.example.app -d refresh_token="$RT" | jq 'keys'
[ "access_token", "expires_in", "refresh_token", "token_type" ]
```

The logout endpoint returns `204`, yet the one-hour access token still works and the refresh token mints a new pair. Anyone holding the refresh token — from a backup, a log, a compromised device — keeps the account after the user "logged out". This is the result that drives a High rating.

### GT-0024-3: Data left in the sandbox after logout (Android)

Guler Tech methodology. Platform: Android. Type: filesystem (dynamic).

#### Overview

Snapshot everything the app owns while logged in, log out, snapshot again, and look for tokens and canaries in the second snapshot. The diff shows what logout changed; the canary search shows what it missed. The WebView portion follows OWASP's [MASTG-TEST-0320](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0320/), which our [MASWE-0001 note](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/#mastg-test-0320-webviews-not-cleaning-up-sensitive-data-android) walks through in detail.

#### Prerequisites

- A rooted device or a rootable emulator image ([MASTG-TECH-0001](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0001/), [MASTG-TECH-0002](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/)). For a debuggable build, `adb shell run-as <pkg>` gives the same access without root.
- Canaries entered across the app, and token prefixes from GT-0024-2.
- `sqlite3` on the workstation; frida-server for step 6.

#### Steps

1. **Exercise the app while logged in**: every screen that shows account data, any WebView content, document downloads, offline features.

2. **Snapshot before logout.**

   ```bash
   PKG=com.example.app
   snap() {
     mkdir -p "$1"
     adb exec-out su -c "tar -cf - /data/data/$PKG /data/user_de/0/$PKG /sdcard/Android/data/$PKG 2>/dev/null" \
       | tar -xf - -C "$1"
   }
   snap before
   ```

3. **Log out through the UI**, wait ten seconds for asynchronous cleanup, and snapshot again with `snap after`. Then force-stop the app (`adb shell am force-stop $PKG`), relaunch it to the login screen, and take a third snapshot (`snap after-relaunch`) — some apps clean up on next start, and some *repopulate* caches on next start.

4. **Diff and search.**

   ```bash
   diff -rq before after | sort
   grep -rlaE 'GTCANARY|<first 16 chars of RT>|<first 16 chars of AT>' after/ after-relaunch/
   ```

5. **Inspect the usual suspects** in `after/data/data/$PKG/`:

   ```bash
   D=after/data/data/$PKG
   grep -lE 'token|session|jwt' "$D"/shared_prefs/*.xml
   for db in "$D"/databases/*.db; do echo "== $db"; sqlite3 "$db" '.tables'; done
   strings -a "$D"/databases/*-wal 2>/dev/null | grep -E 'GTCANARY' | head
   ls -la "$D"/cache/*/ 2>/dev/null | head            # OkHttp: journal, <key>.0 (URL + headers), <key>.1 (body)
   head -c 300 "$D"/cache/*/*.0 2>/dev/null
   sqlite3 "$D"/app_webview/Default/Cookies 'select host_key, name, length(value) from cookies' 2>/dev/null
   grep -rla 'GTCANARY' "$D"/app_webview/ 2>/dev/null
   ```

6. **Check Keystore aliases** that may still decrypt leftover ciphertext:

   ```javascript
   Java.perform(() => {
     const ks = Java.use('java.security.KeyStore').getInstance('AndroidKeyStore');
     ks.load(null);
     const aliases = ks.aliases();
     while (aliases.hasMoreElements()) console.log('alias: ' + aliases.nextElement());
   });
   ```

7. **Relaunch offline.** With the device in airplane mode, open the app after logout and navigate where possible. Any account data shown came from residue.

#### Observation

The diff, the canary and token hits per file, the contents of hits (redacted), Keystore aliases before and after, and screenshots of anything shown offline after logout.

#### Evaluation

The test **fails** if, after logout, any session credential (access, refresh or ID token, session cookie) or any canary-tagged personal data remains in the app's storage — preferences, DataStore, databases (including WAL and journal files), HTTP or image caches, WebView storage, files, or app-specific external storage — or if leftover ciphertext remains together with the Keystore key that decrypts it. Hits only in SQLite free pages after correct `DELETE`s are a weaker finding (recommend `secure_delete` or deleting the database file). It **passes** when only non-sensitive data remains (configuration, feature flags, public content) plus anything the user explicitly chose to keep, such as a remembered username.

#### Demo

```text
$ diff -rq before after | sort
Files before/data/data/com.example.app/shared_prefs/session.xml and after/.../session.xml differ
$ grep -rlaE 'GTCANARY|<first 16 chars of RT>' after/
after/data/data/com.example.app/shared_prefs/session.xml
after/data/data/com.example.app/databases/app.db
after/data/data/com.example.app/cache/http_cache/3f1c9a0e7b2d4c58a6e1f09b2c7d8e41.1
after/data/data/com.example.app/app_webview/Default/Local Storage/leveldb/000003.log
```

Logout changed one preference file. The refresh token (matched by its first 16 characters, recorded in GT-0024-2) is still in `session.xml`; the profile canary is in the database, the cached `/v1/me` response and the WebView's `localStorage`. All four fail.

### GT-0024-4: Data left in the sandbox and Keychain after logout (iOS)

Guler Tech methodology. Platform: iOS. Type: filesystem (dynamic).

#### Overview

The iOS counterpart of GT-0024-3, plus the Keychain, which is outside the app container and is the most common place for iOS session tokens to survive.

#### Prerequisites

- A jailbroken device with SSH ([MASTG-TECH-0052](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0052/), [MASTG-TECH-0053](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0053/)); objection ([MASTG-TOOL-0074](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0074/)) for the Keychain ([MASTG-TECH-0061](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0061/)). On a non-jailbroken device, objection on a Gadget-injected build can list the sandbox and dump the Keychain from inside the app.
- Canaries and token prefixes as before.

#### Steps

1. **Locate the containers.** In objection, `env` prints the app's Data container paths. App Group containers live under `/var/mobile/Containers/Shared/AppGroup/<UUID>/`; find the right one with:

   ```bash
   ssh root@<device> "grep -l group.com.example.app /var/mobile/Containers/Shared/AppGroup/*/.com.apple.mobile_container_manager.metadata.plist"
   ```

2. **Snapshot before logout** (Data container and App Group container), and dump the Keychain:

   ```bash
   DATA=/var/mobile/Containers/Data/Application/<UUID>
   GROUP=/var/mobile/Containers/Shared/AppGroup/<UUID>
   mkdir -p before && ssh root@<device> "tar -cf - '$DATA' '$GROUP'" | tar -xf - -C before
   objection -g "Example" explore
   # in the objection prompt:
   ios keychain dump
   ```

   Save the Keychain dump output as `keychain-before.txt`. Note that objection shows the items the *running app* can access, which is exactly the set that matters here.

3. **Log out**, wait, and repeat both into `after/` and `keychain-after.txt`. Then kill and relaunch the app and repeat once more.

4. **Diff and search.**

   ```bash
   diff -rq before after | sort
   grep -rlaE 'GTCANARY|<token prefix>' after/
   diff keychain-before.txt keychain-after.txt
   ```

5. **Inspect the usual suspects.**

   ```bash
   A=after$DATA
   sqlite3 "$A/Library/Caches/com.example.app/Cache.db" 'select request_key from cfurl_cache_response' | head
   grep -rla 'GTCANARY' "$A/Library/Caches/com.example.app/fsCachedData/" 2>/dev/null
   strings -a "$A/Library/Cookies/Cookies.binarycookies" 2>/dev/null | head
   plutil -p "$A/Library/Preferences/com.example.app.plist" | grep -iE 'token|user|session|GTCANARY'
   grep -rla 'GTCANARY' "$A/Library/WebKit/" "$A/Library/Application Support/" "$A/Documents/" 2>/dev/null
   ls "$A/Library/SplashBoard/Snapshots/"*/ 2>/dev/null
   grep -rla 'GTCANARY' "after$GROUP" 2>/dev/null
   ```

6. **Relaunch offline** and navigate as in GT-0024-3.

#### Observation

Diffs, canary and token hits, Keychain items (service, account, accessibility, and whether the data is a token) before and after, App Group residue, snapshot images, and anything shown offline.

#### Evaluation

The test **fails** if, after logout, Keychain items holding session credentials remain; `Cache.db`/`fsCachedData` holds authenticated responses; cookies, WebKit website data, preferences, Core Data/SwiftData stores, files or the App Group container hold session credentials or canary-tagged personal data. It **passes** under the same conditions as GT-0024-3.

#### Demo

```text
$ diff keychain-before.txt keychain-after.txt
$                                      # no difference: logout did not touch the Keychain
$ grep -E 'refresh|session' keychain-after.txt
Created  Accessible  ACL  Type      Account        Service                    Data
...      AfterFirstUnlock  None  Password  refresh_token  com.example.app.session  <redacted, 512 bytes>
$ sqlite3 after/.../Library/Caches/com.example.app/Cache.db 'select request_key from cfurl_cache_response' | head -3
https://api.example.com/v1/me
https://api.example.com/v1/accounts
https://api.example.com/v1/transactions?limit=50
```

The refresh token remains in the Keychain, readable whenever the device has been unlocked once since boot, and three account responses remain in the URL cache. Both fail; combined with GT-0024-2, the leftover refresh token is also still valid on the server.

### GT-0024-5: Memory, navigation, deep links and system surfaces after logout (Android and iOS)

Guler Tech methodology. Platforms: Android and iOS. Type: dynamic.

#### Overview

Check what the user, or the next person holding the phone, can still see after logout without touching the filesystem: previous screens on the back stack, deep-link targets, app-switcher snapshots, notifications, widgets, search, and objects still alive in memory.

#### Prerequisites

- The app's deep links and exported components (Android manifest, iOS `CFBundleURLTypes` and `applinks:` domains; our [MASWE-0018 note](/mobile/maswe-0018-missing-auth-on-app-components/) shows how to enumerate them).
- frida/objection for the memory step ([MASTG-TOOL-0029](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0029/), [MASTG-TOOL-0074](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0074/)).
- A way to trigger a notification for the account (for example a payment from a second test account).

#### Steps

1. **Back navigation.** Navigate deep into account screens, log out, then press Back repeatedly (`adb shell input keyevent 4`) or swipe back on iOS. On Android, list what is still in the task:

   ```bash
   adb shell dumpsys activity activities | grep -E 'Hist #' | grep "$PKG"
   ```

2. **Deep links and exported components.** For each link that targets account content, open it after logout:

   ```bash
   adb shell am start -W -a android.intent.action.VIEW -d "example://account/statements" "$PKG"
   adb shell am start -W -n "$PKG/.ui.StatementsActivity"     # exported activities only
   ```

   On the iOS Simulator use `xcrun simctl openurl booted "example://account/statements"`; on a device, tap the link from Notes, or call it from Frida:

   ```javascript
   ObjC.schedule(ObjC.mainQueue, () => {
     const url = ObjC.classes.NSURL.URLWithString_('example://account/statements');
     ObjC.classes.UIApplication.sharedApplication()
       .openURL_options_completionHandler_(url, ObjC.classes.NSDictionary.dictionary(), NULL);
   });
   ```

3. **App switcher and Recents.** Immediately after logout, open the switcher: the app's card should not show account data. Then repeat with a timeout: open an account screen, background the app, wait past the idle timeout, open the switcher. Pull the snapshots as in [MASTG-TEST-0289](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0289/) and [MASTG-TEST-0290](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0290/).

4. **Notifications.** Check the shade or Notification Centre right after logout for delivered notifications with account content. Then trigger a new account event and see whether a notification still arrives on the logged-out device.

5. **Widgets, shortcuts, search.** Check home-screen and lock-screen widgets, Live Activities, long-press app shortcuts, and (iOS) Spotlight search for canary names.

6. **Memory.** Without killing the app after logout, search for canaries and token prefixes, and look for live session objects:

   ```text
   # objection, attached to the running app
   memory search "GTCANARY-NAME-24" --string
   android heap search instances com.example.app.session.UserSession
   ```

   On iOS use `memory search` the same way; class names come from GT-0024-1.

#### Observation

Screenshots of any account content reachable after logout, the task's activity list, deep-link results, snapshot images, notifications received after logout, widget and search results, and memory hits with the objects that hold them.

#### Evaluation

The test **fails** if, after logout or timeout, account data is displayed through back navigation, a deep link or an exported component; the app-switcher card or Recents thumbnail shows account data after a timeout; delivered notifications with sensitive content remain or new ones arrive; widgets, Live Activities, shortcuts or Spotlight still expose account data; or app objects (session singletons, view models) still hold the previous session. Isolated strings found in memory with no live owner are an informational observation. It **passes** when all of these show only logged-out content.

#### Demo

```text
$ adb shell am start -W -a android.intent.action.VIEW -d "example://account/statements" com.example.app
Status: ok
Activity: com.example.app/.ui.StatementsActivity
$ adb shell dumpsys activity activities | grep 'Hist #' | grep com.example.app
  * Hist  #2: ActivityRecord{... com.example.app/.ui.StatementsActivity t412}
  * Hist  #1: ActivityRecord{... com.example.app/.ui.LoginActivity t412}
  * Hist  #0: ActivityRecord{... com.example.app/.ui.HomeActivity t412}
```

After logout, the deep link opened the statements screen, which rendered the previous user's statements from the Room cache. `HomeActivity` is still below the login screen, so Back from login also shows the account overview.

### GT-0024-6: Sessions restored by reinstall or backup (iOS and Android)

Guler Tech methodology. Platforms: iOS (primarily) and Android. Type: dynamic.

#### Overview

On iOS, Keychain items survive app deletion. Test whether reinstalling the app restores a signed-in session, or makes old credentials available to the new installation. On Android, Keystore keys are deleted on uninstall, but Auto Backup can restore preferences and files; test whether a restore brings a session back. OWASP tracks backup exposure as [MASWE-0006](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0006/).

#### Prerequisites

- The same build available for reinstall (IPA or TestFlight/App Store; APK).
- For Keychain inspection, objection as in GT-0024-4. For Android backup, a device with a backup transport configured.

#### Steps

1. **iOS, no logout.** Log in, use the app, then delete it from the home screen (no logout). Reinstall the same version and launch it.
   - Does it open signed in, or at a local unlock screen that leads into the account?
   - Dump the Keychain from the new installation: are the old items there?
   - Replay the old refresh token (GT-0024-2): is it still valid?
2. **iOS, after logout.** Repeat with a logout before deletion; combined with GT-0024-4 this shows whether logout cleaned the Keychain.
3. **iOS, device migration (if in scope).** Restore an encrypted backup to a second device and launch the app: Keychain items that are not `…ThisDeviceOnly` migrate.
4. **Android, Auto Backup.** Check the manifest for `android:allowBackup`, `android:fullBackupContent` and `android:dataExtractionRules`. If backup is allowed, log in, then:

   ```bash
   adb shell bmgr backupnow "$PKG"
   adb uninstall "$PKG"
   adb install app.apk          # restore runs on install when backup data exists
   ```

   Launch and check whether the session is restored, or whether the restored files contain tokens (GT-0024-3).

#### Observation

Launch state after reinstall or restore, Keychain items or restored files present, and whether restored credentials are accepted by the server.

#### Evaluation

The test **fails** if a reinstall or restore produces an authenticated session without the user signing in, or if old session credentials that the server still accepts are available to the new installation. It is a **weaker finding** if old Keychain items remain but are ignored by the app and rejected by the server. It **passes** when the reinstalled or restored app starts signed out and holds no previous credentials (a first-launch Keychain wipe on iOS; backup exclusion of session data on Android).

#### Demo

```text
# iOS 18, app deleted while signed in, same build reinstalled from TestFlight
$ objection -g "Example" explore
... # ios keychain dump
Account        Service                    Accessible        Data
refresh_token  com.example.app.session    AfterFirstUnlock  <redacted, 512 bytes>
```

The app launched straight to the account overview: on startup it found the refresh token in the Keychain, refreshed it and continued the previous user's session. Whoever acquires the device after the owner "removed the app" gets the account.

### GT-0024-7: Idle, absolute and background timeouts (Android and iOS)

Guler Tech methodology. Platforms: Android and iOS. Type: dynamic (app and network).

#### Overview

Establish the session lifetimes the server actually enforces and compare them with the app's behaviour and the client's policy: idle timeout, absolute timeout, and re-authentication when the app returns from the background.

#### Prerequisites

- Token capture from GT-0024-2; the client's documented session policy if any; time. Absolute-timeout tests can take a day.

#### Steps

1. **Collect the declared values**: token `expires_in`, JWT `exp - iat`, refresh token lifetime if documented, the app's lock timer from GT-0024-1.
2. **Foreground idle.** Leave the app untouched on an account screen and note when, if ever, it locks or logs out.
3. **Background.** Background the app on an account screen for increasing periods (1, 5, 15, 60 minutes) and return. Note whether it asks for re-authentication, and whether the snapshot shown in the switcher before return contains data (GT-0024-5).
4. **Server idle.** From a fresh login, stop using the app (force-stop it so it cannot refresh in the background) and replay the refresh token after the documented idle limit, then at intervals beyond it.
5. **Server absolute.** Keep a session active by refreshing periodically and see if the server ever forces a new login:

   ```bash
   while true; do
     resp=$(curl -sS https://auth.example.com/oauth/token -d grant_type=refresh_token \
              -d client_id=com.example.app -d refresh_token="$RT")
     RT=$(jq -r '.refresh_token // empty' <<<"$resp")
     if [ -z "$RT" ]; then date -u; echo "$resp"; break; fi
     echo "$(date -u +%FT%TZ) refreshed"; sleep 600
   done
   ```

   If the server does not rotate refresh tokens, `.refresh_token` may be absent from successful responses; adapt the loop to keep the old one.
6. **UI-only lock.** If the app shows a local lock after backgrounding, check whether the underlying session is still live while locked: replay the token from your workstation while the app shows the lock screen, and check whether background jobs keep calling the API. Whether the lock itself can be bypassed is MASWE-0020.
7. **Clock dependence.** If the app's timer uses wall-clock time (GT-0024-1), change the device time back after backgrounding and see whether the lock is skipped.

#### Observation

Measured foreground idle lock time, background re-authentication thresholds, server idle and absolute limits (with timestamps), whether the session remains live behind a local lock, and the clock-change result.

#### Evaluation

The test **fails** for an L2 or EUDIW app if the server enforces no idle limit, or no absolute limit, on refresh tokens; if limits exceed the client's documented policy or the applicable regime (for EU payment account access, more than five minutes of inactivity before re-authentication); or if the app returns from a long background period straight into account screens with no re-authentication. A local lock that is not crypto-bound over a live server session is a weaker finding here and a MASWE-0020 finding. It **passes** when server limits exist, match the risk profile, and the app re-authenticates the user after its idle limit.

#### Demo

```text
2026-10-12T09:00:04Z refreshed
...
2026-10-26T09:10:11Z refreshed
# stopped after 14 days: no absolute limit observed
$ # idle: refresh token unused for 30 days, then:
$ curl -sS https://auth.example.com/oauth/token -d grant_type=refresh_token -d client_id=com.example.app -d refresh_token="$RT" | jq 'keys'
[ "access_token", "expires_in", "refresh_token", "token_type" ]
```

Neither an idle nor an absolute limit is enforced: a refresh token left unused for a month still works, and an actively refreshed session continued for two weeks. Combined with an app that resumes from the background without re-authentication, the device is a permanent key to the account.

## Secure implementation

### Server: what logout and the other triggers must do

- Keep refresh tokens server-side as records (or families) that can be revoked; rotate them on every use; on reuse of an old one, revoke the family and alert.
- On logout: revoke the presented refresh token's family, mark the session ID (`sid`) as ended so access tokens carrying it are rejected, and unbind the device's push token and any device-binding key.
- On password change, recovery, "sign out everywhere", deletion and suspension: revoke every family for the user (or every other one, for password change from a trusted session), and notify devices.
- Keep access tokens short (minutes) or validate them against session state; enforce idle and absolute limits on refresh.
- Expose RFC 7009 revocation and OIDC `end_session_endpoint`; if you federate, implement back-channel logout and act on it.
- Send `Cache-Control: no-store` on every authenticated API response.

### Android: a session terminator

```kotlin
class SessionTerminator(
    private val app: Application,
    private val authApi: AuthApi,
    private val tokenStore: TokenStore,
    private val database: AppDatabase,
    private val httpCache: okhttp3.Cache,
    private val sessionHolder: SessionHolder,
) {
    suspend fun terminate() {
        // 1. Tell the server, but never let failure keep local data alive.
        tokenStore.refreshToken()?.let { rt ->
            runCatching { authApi.revoke(token = rt, hint = "refresh_token") }
                .onFailure { PendingRevocation.enqueue(app, rt) }   // retried by WorkManager when online
        }
        runCatching { FirebaseMessaging.getInstance().deleteToken().await() }

        // 2. Credentials and keys.
        tokenStore.clear()                                        // commit(), not apply()
        KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(TOKEN_KEY_ALIAS) }

        // 3. Data and caches.
        database.close()                                          // then rebuild the DI scope
        app.deleteDatabase(AppDatabase.NAME)                      // removes -wal and -shm too
        httpCache.evictAll()
        File(app.filesDir, "user").deleteRecursively()
        app.getExternalFilesDir(null)?.resolve("user")?.deleteRecursively()
        WorkManager.getInstance(app).cancelAllWorkByTag("user-sync")

        withContext(Dispatchers.Main) {
            // 4. WebView state (IndexedDB/OPFS need a profile wipe; avoid them for session data).
            CookieManager.getInstance().apply { removeAllCookies(null); flush() }
            WebStorage.getInstance().deleteAllData()
            WebView(app).apply { clearCache(true); destroy() }

            // 5. System surfaces.
            NotificationManagerCompat.from(app).cancelAll()
            ShortcutManagerCompat.removeAllDynamicShortcuts(app)
            AccountWidgetProvider.showSignedOut(app)
        }
        CredentialManager.create(app).clearCredentialState(ClearCredentialStateRequest())

        // 6. Memory and navigation.
        sessionHolder.clear()
        app.startActivity(
            Intent(app, LoginActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        )
    }
}
```

Call the same `terminate()` from the logout button, from the `401`/`invalid_grant` handler, from the idle timer and from a push-triggered remote sign-out. Exclude session files from Auto Backup in `dataExtractionRules` (Android 12+) and `fullBackupContent` (older versions).

### iOS: a session terminator and a first-launch wipe

```swift
@MainActor
final class SessionTerminator {
    func terminate() async {
        // 1. Server first; queue on failure, but always continue.
        if let rt = TokenStore.refreshToken {
            do { try await authAPI.revoke(token: rt, hint: "refresh_token") }
            catch { PendingRevocation.enqueue(rt) }
        }
        try? await authAPI.unregisterPushToken()

        // 2. Keychain: the app's own service, including synchronizable items.
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.example.app.session",
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
        ] as CFDictionary)

        // 3. Network and web state.
        URLCache.shared.removeAllCachedResponses()
        HTTPCookieStorage.shared.removeCookies(since: .distantPast)
        await WKWebsiteDataStore.default().removeData(
            ofTypes: WKWebsiteDataStore.allWebsiteDataTypes(), modifiedSince: .distantPast)

        // 4. Files, defaults, shared container.
        try? FileManager.default.removeItem(at: Paths.userData)
        UserDefaults.standard.removeObject(forKey: "lastAccountSnapshot")
        if let group = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.example.app") {
            try? FileManager.default.removeItem(at: group.appendingPathComponent("user"))
        }
        UserDefaults(suiteName: "group.com.example.app")?.removeObject(forKey: "widgetBalance")
        WidgetCenter.shared.reloadAllTimelines()

        // 5. Notifications, search, activities.
        let center = UNUserNotificationCenter.current()
        center.removeAllDeliveredNotifications()
        center.removeAllPendingNotificationRequests()
        try? await CSSearchableIndex.default().deleteAllSearchableItems()
        await NSUserActivity.deleteAllSavedUserActivities()

        // 6. Memory and navigation.
        Session.current = nil
        AppRouter.shared.resetToLogin()          // replaces the window's root view controller
    }
}
```

```swift
// Early in application(_:didFinishLaunchingWithOptions:)
let firstLaunchKey = "com.example.app.hasLaunched"
if !UserDefaults.standard.bool(forKey: firstLaunchKey) {
    for itemClass in [kSecClassGenericPassword, kSecClassInternetPassword, kSecClassKey] {
        SecItemDelete([
            kSecClass as String: itemClass,
            kSecAttrAccessGroup as String: "ABCDE12345.com.example.app",   // only this app's group
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
        ] as CFDictionary)
    }
    UserDefaults.standard.set(true, forKey: firstLaunchKey)
}
```

Restrict the first-launch wipe to the app's own access group so it does not delete items shared with the team's other apps. Store session tokens with a `…ThisDeviceOnly` accessibility class so they do not migrate to other devices.

### Both platforms: browser sessions, entry points and timers

- Include RP-initiated logout in the logout flow (`end_session_endpoint` with `id_token_hint`); on iOS, set `prefersEphemeralWebBrowserSession = true` on `ASWebAuthenticationSession` where SSO across apps is not required.
- Route every deep link and exported entry point through a session check that runs *before* any screen reads data.
- Track inactivity with a monotonic clock, lock on return from the background after the idle limit, and cover sensitive screens before the system snapshot is taken.

## Rating findings

Rate on what survives termination (server credentials versus local residue), how long it survives, who can reach it (anyone with a stolen token, anyone holding the device, only someone with root or jailbreak), and whether user-initiated remediation (password change, sign out everywhere) is defeated.

| Rating | Conditions |
|---|---|
| **Critical** | Password change, account recovery or "sign out of all devices" leaves existing refresh tokens or sessions valid on an L2 or EUDIW app — the user's remediation of a known compromise does not remove the attacker. Also: account deletion or suspension leaves sessions usable for financial or identity operations. |
| **High** | Logout does not revoke the refresh token or server session (GT-0024-2), so any leaked or leftover token keeps the account indefinitely; no server-side idle or absolute limit on refresh tokens for an L2 app; reinstall restores a signed-in session (GT-0024-6); account data shown after logout through back navigation, deep links or exported components without device compromise (GT-0024-5). |
| **Medium** | Refresh token revoked but access tokens remain valid for more than fifteen minutes; session tokens or personal data left in the sandbox or Keychain after logout (requires device compromise or a backup to exploit); WebView or HTTP cache residue with personal data; no re-authentication on resume after long backgrounding; notifications with account content still delivered after logout; widgets or App Group data still showing account data; IdP browser session silently signs the user back in; rotated refresh tokens reusable. |
| **Low** | Access tokens valid for five to fifteen minutes after logout; residue limited to SQLite free pages or non-session metadata; app-switcher snapshot showing data after a background timeout; old Keychain items left after reinstall but ignored and revoked; client timer based on wall-clock time; offline logout never retried, with server-side expiry eventually applying. |
| **Info** | Isolated strings in memory after logout with no live owner; a remembered username the user opted into; absence of OIDC back-channel logout where no federation is used. |

When you report, lead with the server-side evidence if there is any: the termination request, the replay after it, and the response that should have been `401`. For local residue, give the file path, what it contains (redacted), and the termination trigger used. State the profile, because MASWE-0024 is an L2 and EUDIW weakness and the same residue weighs differently in a news app and in a bank.

## References

- OWASP MASWE — [MASWE-0024: Sensitive Data Accessible After Session Termination](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0024/) (CC BY-SA 4.0)
- OWASP MASWE — [MASWE-0006: Sensitive Data Not Excluded From Backup](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0006/) (CC BY-SA 4.0)
- OWASP MAS Profiles — [MAS-L2](https://mas.owasp.org/Profiles/MAS-L2/) and [MAS-EUDIW](https://mas.owasp.org/Profiles/MAS-EUDIW/) (CC BY-SA 4.0)
- OWASP MASTG — [Mobile App Authentication Architectures: User Logout](https://mas.owasp.org/MASTG/0x04e-Testing-Authentication-and-Session-Management/#user-logout) (CC BY-SA 4.0)
- OWASP MASTG — knowledge [MASTG-KNOW-0018](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/), [MASTG-KNOW-0036](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0036/), [MASTG-KNOW-0037](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0037/), [MASTG-KNOW-0041](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0041/), [MASTG-KNOW-0053](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0053/), [MASTG-KNOW-0054](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0054/), [MASTG-KNOW-0057](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/), [MASTG-KNOW-0099](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0099/), [MASTG-KNOW-0108](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0108/), [MASTG-KNOW-0125](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0125/) (CC BY-SA 4.0)
- OWASP MASTG — beta tests [MASTG-TEST-0207](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/), [MASTG-TEST-0289](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0289/), [MASTG-TEST-0292](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0292/), [MASTG-TEST-0315](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0315/), [MASTG-TEST-0320](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0320/), [MASTG-TEST-0290](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0290/), [MASTG-TEST-0302](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0302/), [MASTG-TEST-0388](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0388/) (CC BY-SA 4.0)
- OWASP MASTG — legacy (MASTG v1) tests [MASTG-TEST-0010](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0010/), [MASTG-TEST-0037](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0037/), [MASTG-TEST-0052](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0052/), [MASTG-TEST-0059](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0059/) (CC BY-SA 4.0)
- OWASP MASTG — best practices [MASTG-BEST-0015](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0015/), [MASTG-BEST-0027](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0027/), [MASTG-BEST-0028](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0028/); demo [MASTG-DEMO-0082](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0082/MASTG-DEMO-0082/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0001](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0001/), [MASTG-TECH-0002](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/), [MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0052](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0052/), [MASTG-TECH-0053](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0053/), [MASTG-TECH-0061](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0061/), [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0119](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0119/), [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/); tools [MASTG-TOOL-0029](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0029/), [MASTG-TOOL-0074](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0074/) (CC BY-SA 4.0)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [OWASP WSTG — Session Management Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/README) (WSTG-SESS-06 logout, WSTG-SESS-07 session timeout), [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/) (V7 Session Management)
- [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700), [RFC 7009: OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009), [RFC 7662: OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662), [RFC 9449: DPoP](https://www.rfc-editor.org/rfc/rfc9449), [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252)
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) and [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [NIST SP 800-63B-4: Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html) (reauthentication and session limits)
- [Commission Delegated Regulation (EU) 2018/389](https://eur-lex.europa.eu/eli/reg_del/2018/389/oj) (PSD2 RTS on strong customer authentication, Article 4)
- [Android Developers — Credential Manager: handle sign-out](https://developer.android.com/identity/sign-in/credential-manager-siwg-implementation#handle-sign-out), [`CookieManager`](https://developer.android.com/reference/android/webkit/CookieManager), [`WebStorage`](https://developer.android.com/reference/android/webkit/WebStorage), [Back up user data with Auto Backup](https://developer.android.com/identity/data/autobackup), [Recents screen](https://developer.android.com/guide/components/activities/recents)
- [Apple — `URLCache`](https://developer.apple.com/documentation/foundation/urlcache), [`WKWebsiteDataStore`](https://developer.apple.com/documentation/webkit/wkwebsitedatastore), [`SecItemDelete`](https://developer.apple.com/documentation/security/secitemdelete%28_%3A%29), [`ASWebAuthenticationSession.prefersEphemeralWebBrowserSession`](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession/prefersephemeralwebbrowsersession), [`WidgetCenter`](https://developer.apple.com/documentation/widgetkit/widgetcenter), [Preparing your UI to run in the background](https://developer.apple.com/documentation/uikit/preparing-your-ui-to-run-in-the-background)
- [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html), [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html), [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
