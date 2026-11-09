---
title: "Unnecessary Exposure of Sensitive Data via Notifications (MASWE-0037)"
date: 2026-11-09 21:08:00 +0000
subcategory: platform
summary: "Testing Android and iOS notifications for OTPs and personal data on the lock screen, in notification listeners and in push payloads."
refs: [MASWE-0037, MASVS-PLATFORM-3, MASVS-STORAGE-2, CWE-200, CWE-359]
tags: [android, ios, masvs-platform, notifications, push, lock-screen]
---

This note is part of our [MASVS-PLATFORM guide](/mobile/masvs-platform-platform-interaction-guide/) and covers OWASP [MASWE-0037](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0037/): apps that put one-time codes, message contents, balances, names or health details into system notifications. A notification is the one piece of app UI that the app hands over completely: the system renders it on the lock screen, mirrors it to watches and cars, keeps it in history, and on Android delivers it in full to every app the user has granted notification access. Once posted, its content has left the app's control. Below you will find how each platform decides who sees a notification (Android `setVisibility()`, `setPublicVersion()`, channel and user lock-screen settings, `NotificationListenerService`, the Android 15 OTP redaction for untrusted listeners; iOS Show Previews, `hiddenPreviewsBodyPlaceholder`, Notification Service Extensions), why push payloads matter before the notification is even shown, the one OWASP test with its demo, our Android runtime tests with `dumpsys notification --noredact` and a test listener, our iOS static and lock-screen tests, secure patterns, and how to rate what you find.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: App Notifications (MASTG-KNOW-0054)](#android-app-notifications-mastg-know-0054)
  - [iOS: User notifications, previews and service extensions (supplementary)](#ios-user-notifications-previews-and-service-extensions-supplementary)
  - [Generic: push payloads and the push provider (supplementary)](#generic-push-payloads-and-the-push-provider-supplementary)
- [Tests](#tests)
  - [Before you start: list every notification the app can post](#before-you-start-list-every-notification-the-app-can-post)
  - [MASTG-TEST-0315: Sensitive Data Exposed via Notifications (Android)](#mastg-test-0315-sensitive-data-exposed-via-notifications-android)
  - [GT-0037-1: Runtime notification capture and lock-screen check (Android)](#gt-0037-1-runtime-notification-capture-and-lock-screen-check-android)
  - [GT-0037-2: What a notification listener receives (Android)](#gt-0037-2-what-a-notification-listener-receives-android)
  - [GT-0037-3: References to notification content APIs (iOS)](#gt-0037-3-references-to-notification-content-apis-ios)
  - [GT-0037-4: Runtime capture and lock-screen preview observation (iOS)](#gt-0037-4-runtime-capture-and-lock-screen-preview-observation-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0027: Preventing Sensitive Data Exposure in Notifications](#mastg-best-0027-preventing-sensitive-data-exposure-in-notifications)
  - [Secure patterns for Android (Guler Tech)](#secure-patterns-for-android-guler-tech)
  - [Secure patterns for iOS (Guler Tech)](#secure-patterns-for-ios-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0037 applies when an app includes more sensitive data than necessary in a system notification: one-time codes, message contents, financial details, health information or account details, where a generic "you have a new message" or "new account activity" would do. The OWASP requirement is *"The app does not unnecessarily expose sensitive data through system notifications."* It maps to MASVS-PLATFORM-3 ("The app uses the user interface securely") and MASVS-STORAGE-2 ("The app prevents leakage of sensitive data"), and to [CWE-200](https://cwe.mitre.org/data/definitions/200.html) and [CWE-359](https://cwe.mitre.org/data/definitions/359.html). Like MASWE-0036, it is tagged for the L2 and EUDIW profiles.

OWASP describes the threat as MAS-THREAT-0037, *"Attackers can access sensitive data shown in notifications"*, through two attacks:

| Attack | What it means | Attacker position |
|---|---|---|
| MAS-ATTACK-0044 | Reading notification content shown on the lock screen without unlocking the device | Physical access to the locked device, or a line of sight to it (the phone on a desk, a watch on a wrist) |
| MAS-ATTACK-0045 | Reading notification content from another app holding notification-access permissions | A malicious or over-curious app on the same Android device that the user has granted notification access; Android banking trojans do exactly this to steal OTPs |

There is no iOS equivalent of MAS-ATTACK-0045: iOS has no API for third-party apps to read other apps' notifications. iOS does, however, forward notifications to paired Bluetooth accessories (wearables) and to other Apple devices, and every remote notification on both platforms travels through a push service, which is a data-exposure question of its own (see the [push payloads section](#generic-push-payloads-and-the-push-provider-supplementary)).

**Tests.** OWASP links one test to MASWE-0037, the static Android test MASTG-TEST-0315. There is no OWASP iOS test, and no dynamic test for either platform. We add two Android runtime tests (the notification record as the system stores it, and what a listener receives) and two iOS tests (static and runtime with lock-screen observation), all labelled "Guler Tech methodology".

## Modes of Introduction

**Sensitive content in the notification itself.** The login OTP in the body ("Your code is 482913"), a password-reset or magic login link, the full message text of a secure messaging app, "£2,450.00 paid to J Smith, balance £312.17", appointment details from a health app, the full name and account number in a title. The developer wanted the user to act without opening the app; the cost is that the content is now on the lock screen and in every listener.

**No lock-screen redaction.** On Android, relying on the default `VISIBILITY_PRIVATE` without a redacted public version, or explicitly setting `VISIBILITY_PUBLIC`; putting the sensitive part in the title (which a redacted notification may still show). On iOS, no category with a generic `hiddenPreviewsBodyPlaceholder`, or enabling `hiddenPreviewsShowTitle` / `hiddenPreviewsShowSubtitle` on a category whose title or subtitle carries the sensitive part.

**Server-built notifications.** Push notifications whose text is composed by the backend and displayed by the system (iOS alert payloads, FCM "notification" messages shown by the Firebase SDK while the app is in the background). Nobody reviews them in the app's code, and a static test of the app will not find them.

**Expanded and secondary content.** The collapsed text is generic but the `BigTextStyle`, `InboxStyle` lines or `MessagingStyle` messages carry the details; an action label or a picture contains the data; the summary notification of a group repeats it.

**Payload over-sharing.** A push payload that carries the full message or the OTP in a custom key "for the app to use", even if the displayed text is generic. The push provider, the device's notification stack and anything that logs payloads see it.

## Impact

- **Compromise of sensitive data.** Anyone holding or looking at the device, and on Android any app with notification access, reads personal, financial, health or account information.
- **Authentication or authorisation bypass.** A still-valid OTP, approval code or reset link in a notification is all an attacker needs when they already hold the password or can trigger a reset. This is the standard Android banking-trojan playbook: obtain notification access, trigger the OTP, read it from the notification, submit it.
- **Silent and persistent exposure.** Notification listeners receive every notification in real time and can dismiss them before the user sees them; notification history and Notification Center keep them after the fact.

## Mitigations

- **Say that something happened, not what.** "You have a new message", "New sign-in code available in the app", "New account activity". Fetch details inside the app after authentication.
- **Do not send OTPs through your own notifications** if you can avoid it. Prefer in-app approval (a push that opens an authenticated confirmation screen) or an authenticator flow. If you must, keep it short-lived and single-use.
- **Redact on the lock screen.** Android: `VISIBILITY_PRIVATE` with a generic `setPublicVersion()`, or `VISIBILITY_SECRET` for notifications that should not appear on a secure lock screen at all; keep the title generic either way. iOS: a category with a generic `hiddenPreviewsBodyPlaceholder`, without `hiddenPreviewsShowTitle` / `hiddenPreviewsShowSubtitle` unless those fields are safe.
- **Keep the payload minimal or encrypted.** Send an identifier and fetch the content, or encrypt the payload end to end and decrypt it on the device (Android: a data message handled in `onMessageReceived`; iOS: a Notification Service Extension), then still display generic text.
- **Keep sensitive notifications on the phone.** Android `setLocalOnly(true)` stops bridging to wearables.

## Knowledge

OWASP links one Knowledge page to this weakness, MASTG-KNOW-0054 (Android App Notifications), which is short and covers listeners only. We expand it with the lock-screen visibility model, the listener permission model and the Android 15 change, and add supplementary sections for iOS and for push payloads.

### Android: App Notifications (MASTG-KNOW-0054)

Source: [MASTG-KNOW-0054](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0054/). OWASP's summary is that notifications "should never be considered private". That is correct, with one precision: they are not readable by *any* app, but by any app the user has granted notification access to, and by the system's own surfaces.

#### Where notification content lives

An app builds a notification with [`NotificationCompat.Builder`](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder) (or the platform `Notification.Builder`) and posts it with `NotificationManager(Compat).notify()`. Since Android 13, apps targeting API 33 or higher need the runtime permission `POST_NOTIFICATIONS`; on older versions, or for apps targeting lower API levels, posting needs no permission. The content ends up as `Notification.extras` keys, which is how you will see it in dumps and listeners:

| Builder call | Extras key | Shown where |
|---|---|---|
| `setContentTitle()` | `android.title` | Collapsed and expanded; may be shown on a redacted lock screen |
| `setContentText()` | `android.text` | Collapsed |
| `setSubText()` | `android.subText` | Header |
| `BigTextStyle.bigText()` | `android.bigText` | Expanded |
| `InboxStyle.addLine()` | `android.textLines` | Expanded |
| `MessagingStyle.addMessage()` | `android.messages` | Conversation view |
| `setTicker()` | `tickerText` (a field, not an extra) | Accessibility announcements |
| `setPublicVersion()` | `Notification.publicVersion` | Replaces the notification on a redacting lock screen |

#### Lock-screen visibility: what the app controls and what the user controls

`setVisibility()` sets `Notification.visibility` ([Android Developers: Set lock screen visibility](https://developer.android.com/develop/ui/views/notifications/build-notification#lockscreenNotification)):

| Constant | Value | Meaning on a secure lock screen |
|---|---|---|
| `VISIBILITY_PUBLIC` | 1 | Full content shown |
| `VISIBILITY_PRIVATE` | 0 (the default) | Shown, but replaced by the public version or a generic stub **if the user has chosen to hide sensitive content**; Google documents that basic information such as the icon and content title may still show |
| `VISIBILITY_SECRET` | -1 | Not shown at all |

The second row is the important one. Redaction of a `PRIVATE` notification is conditional on the user's lock-screen setting ("show all notification content" versus "hide sensitive content"; names vary by Android version and manufacturer, and many devices default to showing everything). SystemUI's own logic, in AOSP's `NotificationLockscreenUserManagerImpl.needsRedaction()`, redacts when the user (or a device policy) disallows private notifications on the lock screen *and* the notification is `PRIVATE`, or when the channel's lock-screen visibility has been set to private, or when the notification is flagged as sensitive (the OTP redaction below). So:

- With default user settings, a `PRIVATE` notification without a public version usually shows **everything** on the lock screen. `PRIVATE` is a request to redact *if the user asks for it*, not redaction.
- `VISIBILITY_SECRET` is the only app-side setting that keeps content off a secure lock screen regardless of the user's choice.
- None of this applies to an **insecure** lock screen (swipe or none): with no secure lock, notifications are shown in full. Whether the device is secured is the user's choice (and the subject of [MASWE-0017](/mobile/maswe-0017-device-secure-lock-not-enforced/)).
- Channels (`NotificationChannel`, Android 8+) can carry a lock-screen visibility too, and the user can change it per channel in the app's notification settings. Google's guidance is blunt: the user always has the final say over lock-screen visibility.
- Redaction only concerns the lock screen. Once the device is unlocked, the full notification is in the shade, in heads-up popups, and (if the user enabled it) in **notification history** for the last 24 hours.

#### Notification listeners

A [`NotificationListenerService`](https://developer.android.com/reference/android/service/notification/NotificationListenerService) is a service, protected by `BIND_NOTIFICATION_LISTENER_SERVICE`, that the system binds to once the user enables it under *Settings > Notifications > Device & app notifications* (or *Special app access > Notification access*; names vary). From then on it receives every notification posted by every app, as a `StatusBarNotification` with the full `Notification` object (all extras, the public version, actions and their `PendingIntent`s), can read the currently active notifications at any time, and can cancel them. There is no per-app scoping: the user grants access to everything. Legitimate holders include wearable companion apps, Android Auto, launchers, automation tools and notification-history apps; malicious holders include banking trojans and spyware families documented in public research (OWASP cites Joker and Alien), which use the access to steal OTPs and suppress fraud alerts.

Two platform changes narrow this:

- **Restricted settings (Android 13).** Apps installed from outside an app store by a non-session installer (a browser download opened in the package installer) cannot be granted notification access or accessibility until the user explicitly allows "restricted settings" in the app's info screen. Malware droppers have responded by installing through the session-based API, so treat this as friction, not a barrier.
- **Sensitive notification redaction for untrusted listeners (Android 15).** Android 15 redacts notifications that contain one-time codes before delivering them to untrusted listeners. The detection is done by the device's notification assistant (Android System Intelligence on Pixel devices), which marks the notification as sensitive. In AOSP's `NotificationManagerService`, a listener is trusted if it holds the `RECEIVE_SENSITIVE_NOTIFICATIONS` permission (protection level signature or role), is platform-signed, has the corresponding app-op allowed, or belongs to an app with a Companion Device Manager association (a watch's companion app, for example). Untrusted listeners get a copy whose title is the posting app's name and whose text is "Sensitive notification content hidden", with actions blanked. Google has said Android 16 extends OTP redaction to the lock screen in some conditions; in AOSP this appears as an `isNotifSensitive` term in the same `needsRedaction()` logic quoted above.

None of this is a reason to put an OTP in a notification. It depends on the classifier recognising your text as a code, on the device's Android version and notification assistant, and it exempts exactly the companion apps that forward notifications to other devices. An app that targets older devices, or puts a reset link or a balance rather than a code in the notification, gets no help from it. MASTG-KNOW-0054 does not mention this change; we test against it in GT-0037-2.

#### Other places notifications go

- **Wearables.** Wear OS bridges phone notifications to the watch unless the notification is marked `setLocalOnly(true)`. Third-party watches and fitness bands use a companion app with notification access.
- **Cars.** Android Auto shows and reads out messaging notifications.
- **Screen sharing and recording.** Notifications that arrive during a screen share or recording are captured with it; Android 15 added protection that hides notification content during screen sharing on supported devices. Treat that as best effort.
- **Accessibility services** receive notification events and text (see [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/)).

#### Push messages (FCM)

With Firebase Cloud Messaging, a **notification message** (one with a `notification` block) is displayed by the Firebase SDK itself when the app is in the background, without the app's code building it, so `setVisibility()` in the app never runs. The FCM HTTP v1 `AndroidNotification` object has its own `visibility` field (`PRIVATE`, `PUBLIC`, `SECRET`) that the backend must set. A **data message** is always delivered to `FirebaseMessagingService.onMessageReceived()`, which lets the app decrypt the payload and build a generic local notification. For testing, this means the text of background-delivered notifications lives on the server, not in the APK.

### iOS: User notifications, previews and service extensions (supplementary)

OWASP has no iOS knowledge page for this weakness; the MASWE page links Apple's [User Notifications](https://developer.apple.com/documentation/usernotifications) documentation. This is what you need to test it.

#### Local and remote notifications

A **local** notification is built in the app: a [`UNMutableNotificationContent`](https://developer.apple.com/documentation/usernotifications/unmutablenotificationcontent) with `title`, `subtitle`, `body`, `userInfo`, `categoryIdentifier`, `threadIdentifier` and optional attachments, wrapped in a `UNNotificationRequest` and added with `UNUserNotificationCenter.add(_:)`. A **remote** notification is sent by the app's server through the Apple Push Notification service (APNs) as a JSON payload whose `aps.alert` dictionary carries `title`, `subtitle` and `body` ([Generating a remote notification](https://developer.apple.com/documentation/usernotifications/generating-a-remote-notification)); the system displays it without running the app's code, unless a Notification Service Extension is present. Remote notifications need the `aps-environment` entitlement. The regular payload limit is 4 KB.

#### Show Previews and the hidden-preview placeholder

iOS has no per-notification visibility setting comparable to Android's. Whether the content of a notification is shown on the lock screen is decided by the user under **Settings > Notifications > Show Previews** (Always, When Unlocked, Never), globally and per app. On Face ID devices the default is "When Unlocked": the lock screen shows the app name and a generic text until Face ID recognises the owner, so someone else holding the locked phone does not see the preview. On other devices, and whenever the user chose "Always", the full preview is on the lock screen.

When previews are hidden, the app decides what appears instead, per category:

- [`hiddenPreviewsBodyPlaceholder`](https://developer.apple.com/documentation/usernotifications/unnotificationcategory/hiddenpreviewsbodyplaceholder) (iOS 11+), set when creating the `UNNotificationCategory`. It replaces the body; it can contain a `%u` placeholder for the number of notifications in the group ("%u new messages").
- Category options [`hiddenPreviewsShowTitle`](https://developer.apple.com/documentation/usernotifications/unnotificationcategoryoptions/hiddenpreviewsshowtitle) and [`hiddenPreviewsShowSubtitle`](https://developer.apple.com/documentation/usernotifications/unnotificationcategoryoptions/hiddenpreviewsshowsubtitle) show the title or subtitle even while previews are hidden.

As OWASP's MASWE page puts it, these only customise the preview once it is already hidden; they do not hide anything. An app cannot force previews off. So on iOS the content itself must be safe to show, and the category settings only decide how much leaks for users who *did* hide previews.

#### Notification Service Extensions

A [`UNNotificationServiceExtension`](https://developer.apple.com/documentation/usernotifications/unnotificationserviceextension) is an app extension (in `Payload/App.app/PlugIns/*.appex`, extension point `com.apple.usernotifications.service`) that iOS runs when a remote notification arrives with `"mutable-content": 1` and an alert. Its `didReceive(_:withContentHandler:)` gets the payload and has a limited time (Apple documents no more than 30 seconds) to return modified content; if it runs out, `serviceExtensionTimeWillExpire()` must deliver a fallback. Apps use it to download attachments and, for this weakness, to **decrypt an end-to-end encrypted payload**, so that APNs and anything between the backend and the device only see ciphertext. The extension runs in its own process and gets keys through a shared keychain access group or App Group. Two things to check: decrypting into a detailed body moves the exposure from the push path to the lock screen, so the displayed text should still be generic; and the fallback text in `serviceExtensionTimeWillExpire()` must not be the original (possibly cleartext) payload.

#### Other places notifications go (iOS)

- **Apple Watch** mirrors iPhone notifications when the phone is locked or asleep.
- **Bluetooth accessories** can receive notification titles and messages through the Apple Notification Center Service (ANCS); since iOS 13 the user can turn "Share System Notifications" on or off per paired accessory.
- **Mac, CarPlay and Siri.** iPhone Mirroring shows iPhone notifications on a Mac; CarPlay displays and reads messages; Siri can announce notifications through headphones.
- **Notification Center** keeps delivered notifications until they are cleared, and "Allow Access When Locked" for Notification Center is on by default.

### Generic: push payloads and the push provider (supplementary)

Every remote notification goes from the app's backend to the platform push service (APNs, or FCM, which on Android delivers through Google Play services) and from there to the device. The connections are TLS-protected, but the push service handles the payload in clear, and so do any third-party engagement or marketing SDKs that relay notifications for the app. Push payloads also appear in device logs during development and in crash reports when apps log them. That makes "what is in the payload" a data-minimisation question even when the displayed text is generic:

- Send an opaque identifier ("message 8812 available") and fetch the content over the app's own authenticated, pinned channel, or
- Encrypt sensitive fields end to end with a key provisioned to the app at login, decrypt on the device (iOS Notification Service Extension, Android `onMessageReceived()`), and display generic text anyway.

Testing the transport itself (TLS, pinning, cleartext) belongs to the [MASVS-NETWORK guide](/mobile/masvs-network-secure-communication-guide/); here you only need to record what the payload contains.

## Tests

OWASP links one test to MASWE-0037, the static Android test MASTG-TEST-0315. It replaces these legacy (MASTG v1) tests:

| Legacy test | Replaced by |
|---|---|
| [MASTG-TEST-0005](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0005/) Determining Whether Sensitive Data Is Shared with Third Parties via Notifications (Android) | MASTG-TEST-0315 |
| [MASTG-TEST-0008](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0008/) Checking for Sensitive Data Disclosure Through the User Interface (Android), "App Notifications" part | MASTG-TEST-0315 (OWASP lists only MASTG-TEST-0316 as its replacement, which covers the text-field part; see the [UI note](/mobile/maswe-0036-sensitive-data-exposed-via-ui/)) |

Both legacy tests had a dynamic half (trace `setContentTitle` / `setContentText` while exercising the app) that the new test dropped, and neither had an iOS counterpart. We restore the dynamic half as GT-0037-1 and GT-0037-2 and add GT-0037-3 and GT-0037-4 for iOS.

### Before you start: list every notification the app can post

Notifications are event-driven, and many are triggered by the backend, so you have to provoke them deliberately.

1. List the triggers: login and 2FA, new device sign-in, password or PIN reset, payments in and out, card transactions, payee changes, low balance, messages and chat, appointments and results, document availability, marketing.
2. For each, find how to cause it in the test environment: perform the action yourself, use a second test account (send a message, make a transfer), ask the client for a test push tool, or use the backend's admin console. Note which ones are local (built by the app) and which are remote (built by the server).
3. Grant the permission and enable all channels before you start:

   ```bash
   adb shell pm grant com.example.app android.permission.POST_NOTIFICATIONS
   adb shell cmd notification allow_listener com.guler.nlprobe/com.guler.nlprobe.ProbeListener   # GT-0037-2, if installed
   ```

   On iOS, allow notifications at the prompt, and check *Settings > [App] > Notifications* that banners, lock screen and Notification Center are all on.

4. Record, per notification type: trigger, local or remote, title, body, expanded text, and what the lock screen shows. The tests below fill in the columns.

### MASTG-TEST-0315: Sensitive Data Exposed via Notifications (Android)

Source: [MASTG-TEST-0315](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0315/). Platform: Android. Type: static (code). Prerequisite: identify the sensitive data. Knowledge: MASTG-KNOW-0054. Best practice: MASTG-BEST-0027 (placeholder).

#### Overview

The test finds every place the app builds notification content with `setContentTitle()` and `setContentText()` (on `Notification.Builder` or `NotificationCompat.Builder`), reviews what goes into them, and reads the manifest for `minSdkVersion` and the `POST_NOTIFICATIONS` permission to establish that the app can post notifications on the devices it supports. A notification carrying PII, an OTP, or health or financial details fails.

#### Prerequisites

- The APK decompiled with jadx ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)) and searched with semgrep or grep ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)).
- The decoded `AndroidManifest.xml` ([MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)), analysed for `minSdkVersion` ([MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)) and permissions ([MASTG-TECH-0126](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0126/)).
- Your list of notification types and the sensitive data each could carry.

#### Steps

1. **Manifest.** Get the SDK levels and permissions:

   ```bash
   aapt2 dump badging base.apk | grep -E "^sdkVersion|^targetSdkVersion|POST_NOTIFICATIONS"
   # or, after apktool d base.apk -o apk_out:
   grep -E 'minSdkVersion|targetSdkVersion' apk_out/apktool.yml
   grep -n 'POST_NOTIFICATIONS' apk_out/AndroidManifest.xml
   ```

2. **Run the OWASP rules** against the decompiled code and the manifest:

   ```bash
   semgrep -c mastg-android-sensitive-data-in-notifications.yml out/sources/
   semgrep -c mastg-android-sensitive-data-in-notifications-manifest.yml apk_out/AndroidManifest.xml
   ```

   The code rule matches every `setContentTitle(...)` and `setContentText(...)` call; the manifest rule reports the permission and the `minSdkVersion`.

3. **Widen the search** to the other places content goes, and to the visibility settings:

   ```bash
   grep -rnE 'setContentTitle\(|setContentText\(|setSubText\(|setTicker\(|bigText\(|setBigContentTitle\(|addLine\(|addMessage\(|setPublicVersion\(|setVisibility\(|setLockscreenVisibility\(|setLocalOnly\(' \
       out/sources/ | grep -vE '^out/sources/(androidx|com/google/firebase)/'
   grep -rnE 'extends FirebaseMessagingService|onMessageReceived\(|RemoteMessage' out/sources/ | grep -v '^out/sources/com/google/firebase/'
   ```

   In decompiled code `setVisibility(1)` is `PUBLIC`, `setVisibility(0)` is `PRIVATE` and `setVisibility(-1)` is `SECRET`.

4. **Review each call site** in jadx-gui ([MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)). Trace the argument back to its source: a string resource (resolve it in `apk_out/res/values/strings.xml`), a format string filled with model fields (`getString(R.string.otp_notification, code)`), or a value from the push payload (`remoteMessage.getData().get("body")`). Note the visibility and public version of each notification you identify.

5. **Remote content.** For FCM notification messages and server-built text, the APK does not contain the text. Record "content defined server-side" and cover it with GT-0037-1 and GT-0037-2.

#### Observation

The `minSdkVersion`, whether `POST_NOTIFICATIONS` is declared, and the list of notification-building call sites with what each puts in the title, text and expanded styles, plus its visibility and public version.

#### Evaluation

OWASP's test **fails** if the app exposes sensitive data in any notification and either `minSdkVersion` is 33 or higher and `POST_NOTIFICATIONS` is declared, or `minSdkVersion` is 32 or lower whether or not the permission is declared. Put plainly: the manifest conditions only establish that the app is able to post notifications on at least some supported devices (below Android 13 no permission is needed; from Android 13 the permission is needed for apps targeting 33+). They do not reduce the finding. OWASP chooses `minSdkVersion` rather than `targetSdkVersion` because the oldest supported Android version is the least protected environment the app runs in. An app with `minSdkVersion` 33+ and no `POST_NOTIFICATIONS` declaration cannot post (except for exempt notifications), and passes.

We apply the same rule and add: sensitive data in an expanded style, a subtext or a ticker counts the same as in the text; a `PRIVATE` notification without a generic public version, or a sensitive title, does not count as redacted (see the [visibility model](#lock-screen-visibility-what-the-app-controls-and-what-the-user-controls)). Rate with the table at the end of the note.

#### Demo

[MASTG-DEMO-0078](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0078/MASTG-DEMO-0078/). The sample posts the same personal data through all four builder variants:

```kotlin
val sensitiveTitle = "Hi John Doe"
val sensitiveText = "Hi John Doe <- This is a sensitive string containing PII"

private fun createNotificationCompatOnChannel() =
    NotificationCompat.Builder(context, "TEST_CHANNEL_ID")
        .setContentTitle(sensitiveTitle)
        .setContentText(sensitiveText)
        .setSmallIcon(R.drawable.ic_menu_info_details)
        .build()
// ... plus Notification.Builder(context), Notification.Builder(context, channel)
// and NotificationCompat.Builder(context) with the same content
```

```xml
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
```

The rules report the builder calls and the manifest entries:

```text
MastgTest_reversed.java
❯❱ rules.mastg-android-sensitive-data-in-notifications
     41┆ Notification notificationBuild = new Notification.Builder(this.context).setContentTitle("MASTG Test").setContentText(sensitiveString).build();
     48┆ Notification notificationBuild = new Notification.Builder(this.context, "TEST_CHANNEL_ID").setContentTitle("MASTG Test").setContentText(sensitiveString).build();

AndroidManifest_reversed.xml
 ❱ rules.mastg-android-minsdkversion
     11┆ android:minSdkVersion="29"
❯❱ rules.mastg-android-sensitive-data-in-notifications-manifest
     14┆ <uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
```

The notification text contains a first and last name, and `minSdkVersion` is 29, so the test fails. Note that OWASP's published decompiled file and output are from an older version of the sample: they show two builders with the title "MASTG Test", while the current Kotlin has four builders and puts the name in the title as well. Run the rule on the current build and you should get eight matches.

### GT-0037-1: Runtime notification capture and lock-screen check (Android)

Guler Tech methodology. Platform: Android. Type: dynamic.

#### Overview

The static test cannot see server-built text, values that only exist at runtime, or what the lock screen really shows. The system keeps every active notification as a `NotificationRecord`, and `dumpsys notification` prints them. By default it redacts the text (it prints `[length=N]` for every string extra, so bug reports do not leak content); the `--noredact` flag, parsed by AOSP's `NotificationManagerService` together with its alias `--reveal`, prints the actual strings. Combined with screenshots of the locked device under each lock-screen setting, this gives you the complete picture of what the app posted and what a person holding the phone sees.

#### Prerequisites

- A device or emulator with a **secure** lock screen (PIN), `adb`, and `POST_NOTIFICATIONS` granted.
- Your list of notification triggers.
- Optional: Frida, for tracing the builder calls with stack traces.

#### Steps

1. **Trigger a notification** and dump the records for the app:

   ```bash
   adb shell dumpsys notification --noredact > notif.txt
   grep -n "pkg=com.example.app" notif.txt
   # print the record blocks for the package (abridged view)
   awk '/NotificationRecord\(/{p=/pkg=com\.example\.app/} p' notif.txt \
       | grep -E 'NotificationRecord|vis=|tickerText=|android\.(title|text|bigText|subText|textLines|messages|summaryText)|publicNotification=|mSensitiveContent'
   ```

   Example (abridged):

   ```text
   NotificationRecord(0x0a1b2c3d: pkg=com.example.app user=UserHandle{0} id=3 tag=null importance=4 key=0|com.example.app|3|null|10234: Notification(channel=otp ...))
       tickerText=null
       vis=0
           android.title=String (Your sign-in code)
           android.text=String (Your code is 482913. It expires in 5 minutes.)
     publicNotification=
         None
     mSensitiveContent=true
   ```

   Without `--noredact` the same lines read `android.title=String [length=17]`. Here the record shows a private (`vis=0`) notification with no public version, so on any lock screen that does not redact, the code is shown in full; `mSensitiveContent=true` (on Android versions that print it) means the notification assistant classified it as containing a code.

2. **Use the shell command for single records.** `cmd notification list` prints the keys of active notifications, and `cmd notification get <key>` prints one record, unredacted:

   ```bash
   adb shell cmd notification list | grep com.example.app
   adb shell "cmd notification get '0|com.example.app|3|null|10234'"   # quote twice: the key contains pipes
   ```

3. **Trace who builds what** (optional), which also catches notifications built by the Firebase SDK from a push. Hook every `NotificationManager.notify` overload:

   ```javascript
   // notify-trace.js
   Java.perform(() => {
     const NM = Java.use('android.app.NotificationManager');
     const Notification = Java.use('android.app.Notification');
     const Log = Java.use('android.util.Log');
     const Exception = Java.use('java.lang.Exception');
     NM.notify.overloads.forEach(o => {
       o.implementation = function () {
         const n = Java.cast(arguments[arguments.length - 1], Notification);
         const ex = n.extras.value;
         console.log(`[notify] vis=${n.visibility.value} title=${ex.getCharSequence('android.title')} ` +
                     `text=${ex.getCharSequence('android.text')} big=${ex.getCharSequence('android.bigText')} ` +
                     `public=${n.publicVersion.value !== null}`);
         console.log(Log.getStackTraceString(Exception.$new()));
         return o.apply(this, arguments);
       };
     });
   });
   ```

   ```bash
   frida -U -f com.example.app -l notify-trace.js
   ```

4. **Check the lock screen under both user settings.** Read the current setting, then test with "show all content" and with "hide sensitive content":

   ```bash
   adb shell settings get secure lock_screen_show_notifications            # 1 = notifications on lock screen
   adb shell settings get secure lock_screen_allow_private_notifications   # 1 = show sensitive content
   adb shell settings put secure lock_screen_allow_private_notifications 1
   # trigger the notification, then lock, wake and capture:
   adb shell input keyevent KEYCODE_SLEEP
   adb shell input keyevent KEYCODE_WAKEUP
   adb exec-out screencap -p > lock-showall.png
   adb shell settings put secure lock_screen_allow_private_notifications 0
   # trigger again, lock, wake, capture lock-hidesensitive.png
   ```

   These are hidden `Settings.Secure` keys that SystemUI reads; the same switches are in *Settings > Notifications > Notifications on lock screen* (wording varies by manufacturer). Restore the user's original values afterwards. On some devices `screencap` on the keyguard is blocked; photograph the screen instead.

5. **Check the other surfaces** that matter for the app: enable *Settings > Notifications > Notification history* and confirm what it keeps; if a Wear OS watch is paired, check whether the notification appears there (`setLocalOnly(true)` prevents it).

#### Observation

For each notification type: the unredacted record (title, text, expanded content, visibility, public version), the screenshots of the locked device with both lock-screen settings, and, if traced, the stack trace of the code that built it.

#### Evaluation

The test **fails** for a notification that carries sensitive data (OTP, reset link, credentials, PII, financial or health details) in any text field and is shown in full on a secure lock screen with **default** user settings, which is the case for `VISIBILITY_PUBLIC`, and for `VISIBILITY_PRIVATE` without a generic public version on devices that default to showing all content. It also fails, at lower severity, for sensitive data that is redacted on the lock screen but present in the notification itself, because listeners, wearables and the unlocked shade still receive it (GT-0037-2). It **passes** when notifications carry only generic text, or when sensitive notifications are `VISIBILITY_SECRET` and their content is limited to what an unlocked shoulder-surfer may see.

#### Demo

The record above is a typical failure: an OTP in `android.text`, `vis=0`, `publicNotification=None`. With `lock_screen_allow_private_notifications` set to 1 (the default on many devices) the lock-screen capture shows "Your code is 482913". The fix in the app is a generic text and a public version (see [Secure patterns for Android](#secure-patterns-for-android-guler-tech)); the better fix is not to send the code in a notification.

### GT-0037-2: What a notification listener receives (Android)

Guler Tech methodology. Platform: Android. Type: dynamic, with a test app.

#### Overview

MAS-ATTACK-0045 is a malicious app with notification access. The most convincing evidence for it is your own minimal listener showing, in logcat, the content another app would receive. It also lets you check the Android 15 behaviour: whether the app's OTP notifications are redacted for an untrusted listener, and what a trusted one (a companion app) would still see.

#### Prerequisites

- Android Studio or Gradle, to build a tiny app (package `com.guler.nlprobe` below); a test device.
- Do this only on test devices: the listener logs every notification on the device, including your own.

#### Steps

1. **Create the listener.** Manifest entry:

   ```xml
   <service
       android:name=".ProbeListener"
       android:exported="true"
       android:label="NL probe"
       android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE">
       <intent-filter>
           <action android:name="android.service.notification.NotificationListenerService" />
       </intent-filter>
   </service>
   ```

   Service:

   ```kotlin
   package com.guler.nlprobe

   import android.app.Notification
   import android.service.notification.NotificationListenerService
   import android.service.notification.StatusBarNotification
   import android.util.Log

   class ProbeListener : NotificationListenerService() {
       override fun onNotificationPosted(sbn: StatusBarNotification) {
           if (sbn.packageName != TARGET) return
           val n = sbn.notification
           Log.i(TAG, "key=${sbn.key} vis=${n.visibility} channel=${n.channelId} category=${n.category}")
           for (k in n.extras.keySet()) {
               @Suppress("DEPRECATION")
               Log.i(TAG, "  $k=${n.extras.get(k)}")
           }
           n.publicVersion?.let { pv ->
               Log.i(TAG, "  public.title=${pv.extras.getCharSequence(Notification.EXTRA_TITLE)}")
               Log.i(TAG, "  public.text=${pv.extras.getCharSequence(Notification.EXTRA_TEXT)}")
           }
       }

       companion object {
           const val TAG = "NLProbe"
           const val TARGET = "com.example.app"
       }
   }
   ```

2. **Install and grant access** without going through the settings UI:

   ```bash
   adb install -r nlprobe.apk
   adb shell cmd notification allow_listener com.guler.nlprobe/com.guler.nlprobe.ProbeListener
   adb logcat -s NLProbe
   ```

   (`cmd notification disallow_listener` revokes it.) A real attacker needs the user to grant this in *Settings*, which banking malware achieves with social engineering, often alongside an accessibility service.

3. **Trigger each notification type** and read logcat. Every extra the app set is printed, including expanded text and messages.

4. **Android 15 and later: compare untrusted and trusted.** Trigger an OTP notification. If the device's notification assistant classifies it as sensitive, the untrusted probe logs the app's name as title and "Sensitive notification content hidden" as text. To see what a trusted listener (for example a watch companion app) receives, allow the app-op for the probe on the test device, and trigger again:

   ```bash
   adb shell appops set com.guler.nlprobe RECEIVE_SENSITIVE_NOTIFICATIONS allow
   ```

   Reset it afterwards with `adb shell appops set com.guler.nlprobe RECEIVE_SENSITIVE_NOTIFICATIONS default`.

#### Observation

The logcat output for each notification type, from an untrusted listener and, on Android 15+, from a trusted one.

#### Evaluation

The test **fails** if the listener receives sensitive data for any notification type: on any supported Android version below 15, everything the app posts is delivered in full; on 15 and later, anything the classifier does not flag (reset links, balances, message text, names, codes phrased unusually) and everything delivered to trusted listeners. It **passes** if the listener only ever receives generic content. Do not credit the Android 15 redaction as a mitigation unless `minSdkVersion` is 35 or higher and the data is a code the classifier recognises; even then, trusted companion apps still receive it.

#### Demo

Illustrative logcat output for an OTP notification, Android 14 test device:

```text
I NLProbe : key=0|com.example.app|3|null|10234 vis=0 channel=otp category=null
I NLProbe :   android.title=Your sign-in code
I NLProbe :   android.text=Your code is 482913. It expires in 5 minutes.
```

The same notification on an Android 15 device with the classifier active, untrusted probe:

```text
I NLProbe :   android.title=Example Bank
I NLProbe :   android.text=Sensitive notification content hidden
```

The first result fails outright. The second only shows that the platform, not the app, protected the code on this one device.

### GT-0037-3: References to notification content APIs (iOS)

Guler Tech methodology. Platform: iOS. Type: static (code) with manual review.

#### Overview

Find where the app (and its extensions) builds notification content and categories, check what goes into `title`, `subtitle` and `body`, whether categories define a generic `hiddenPreviewsBodyPlaceholder` and which hidden-preview options they enable, and whether a Notification Service Extension is present and what it does with the payload. `UNMutableNotificationContent` and `UNNotificationCategory` are Objective-C classes, so even Swift apps call their setters through `objc_msgSend` and the selector names are visible in the binary.

#### Prerequisites

- A decrypted IPA, unzipped, including `PlugIns/*.appex` ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)).
- radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)), `plutil`, `codesign` (or `ldid` on device).

#### Steps

1. **Find the binaries and extensions, and check for push.**

   ```bash
   unzip -q App.ipa -d ipa && APP=ipa/Payload/App.app
   codesign -d --entitlements - "$APP" 2>/dev/null | grep -A1 aps-environment     # remote notifications enabled
   for p in "$APP"/PlugIns/*.appex/Info.plist; do
     echo "== $p"; plutil -p "$p" | grep -E 'NSExtensionPointIdentifier|NSExtensionPrincipalClass'
   done
   # com.apple.usernotifications.service           = Notification Service Extension
   # com.apple.usernotifications.content-extension = Notification Content Extension (custom expanded UI)
   ```

2. **Search each binary for the notification APIs:**

   ```bash
   for BIN in "$APP/App" "$APP"/PlugIns/*.appex/*; do
     file "$BIN" | grep -q Mach-O || continue
     echo "== $BIN"
     rabin2 -zz "$BIN" | grep -E 'setTitle:|setSubtitle:|setBody:|setCategoryIdentifier:|requestWithIdentifier:content:trigger:|addNotificationRequest:withCompletionHandler:|hiddenPreviewsBodyPlaceholder|setNotificationCategories:|didReceiveNotificationRequest:withContentHandler:|serviceExtensionTimeWillExpire'
   done
   ```

   `setTitle:` and `setBody:` are common selectors, so treat their presence as a lead and use cross-references to the `UNMutableNotificationContent` class reference to find the right call sites:

   ```bash
   r2 -A "$APP/App"
   # inside r2:
   f~UNMutableNotificationContent,UNNotificationCategory
   axt @ <address of reloc.UNMutableNotificationContent>
   pd 60 @ <function that allocates it>     # follow the setTitle:/setBody: calls and the strings loaded into x2
   ```

3. **Read the text the app uses.** Notification strings are usually localised: inspect `Localizable.strings` (often a binary plist) and `.stringsdict` files, and look for format strings with code, amount or name placeholders:

   ```bash
   plutil -p "$APP"/en.lproj/Localizable.strings | grep -iE 'notif|code|otp|balance|payment|paid|received|message'
   ```

4. **Check the categories.** Find calls to `categoryWithIdentifier:actions:intentIdentifiers:hiddenPreviewsBodyPlaceholder:options:` (or the Swift initialiser that wraps it), the placeholder string passed, and the options value. `UNNotificationCategoryOptions` is a bit field; check the raw value against the SDK header for `hiddenPreviewsShowTitle` and `hiddenPreviewsShowSubtitle` rather than relying on remembered numbers.

5. **Review the service extension**, if any: what payload keys it reads, whether it decrypts, what it writes into `title`/`body`, and what `serviceExtensionTimeWillExpire()` delivers.

6. **Ask for the server templates.** For remote notifications the visible text is in the backend. In a white-box test, request the push templates; in a black-box test, capture them with GT-0037-4.

#### Observation

The notification-building call sites with the strings or variables used for title, subtitle and body; the categories with their placeholders and options; the service extension's behaviour; the push templates if available.

#### Evaluation

The test **fails** if any notification the app or its extension builds carries sensitive data in `title`, `subtitle` or `body` (or in an attachment), or if a remote template does. Missing hidden-preview placeholders, or `hiddenPreviewsShowTitle` / `hiddenPreviewsShowSubtitle` on a category whose title or subtitle is sensitive, make the failure worse for users who hide previews; they do not cause it. It **passes** if notification text is generic. A service extension that decrypts the payload is a positive finding for the push path, but still fails here if it writes the decrypted details into the displayed body.

#### Demo

Illustrative vulnerable code, and what radare2 and the strings show:

```swift
let content = UNMutableNotificationContent()
content.title = "Payment sent"
content.body = String(format: NSLocalizedString("payment.sent.body", comment: ""),
                      payment.amount, payment.payeeName, account.balance)
let request = UNNotificationRequest(identifier: payment.id, content: content, trigger: nil)
UNUserNotificationCenter.current().add(request)
```

```text
$ plutil -p App.app/en.lproj/Localizable.strings | grep payment.sent
  "payment.sent.body" => "%@ paid to %@. Your balance is now %@."
```

The body discloses the amount, the payee and the balance on every lock screen with previews shown. The test fails.

### GT-0037-4: Runtime capture and lock-screen preview observation (iOS)

Guler Tech methodology. Platform: iOS. Type: dynamic, plus manual observation.

#### Overview

Capture the actual content of every notification the app posts or receives, including remote notifications after any service extension has processed them, and observe what the lock screen shows under each Show Previews setting. Two runtime facts make this easy: local notifications pass through `-[UNUserNotificationCenter addNotificationRequest:withCompletionHandler:]`, and the app can list its own delivered notifications (local and remote, with the payload in `userInfo`) through `getDeliveredNotificationsWithCompletionHandler:`.

#### Prerequisites

- The app on a device (jailbroken with frida-server, or a Frida Gadget build) and Frida ([MASTG-TOOL-0039](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/)).
- A way to trigger remote notifications (the real backend in a test environment). For rendering checks, the simulator accepts payload files through `xcrun simctl push`.

#### Steps

1. **Hook local notifications and list delivered ones:**

   ```javascript
   // notif-ios.js
   const str = o => (o === null ? '' : o.toString());
   function show(tag, c) {
     console.log(`[${tag}] title="${str(c.title())}" subtitle="${str(c.subtitle())}" body="${str(c.body())}" ` +
                 `category=${str(c.categoryIdentifier())}\n    userInfo=${str(c.userInfo())}`);
   }
   const UNC = ObjC.classes.UNUserNotificationCenter;
   Interceptor.attach(UNC['- addNotificationRequest:withCompletionHandler:'].implementation, {
     onEnter(args) { show('local', new ObjC.Object(args[2]).content()); }
   });
   globalThis.dumpDelivered = function () {
     const done = new ObjC.Block({
       retType: 'void', argTypes: ['object'],
       implementation(list) {
         const a = new ObjC.Object(list);
         for (let i = 0; i < a.count(); i++) show('delivered', a.objectAtIndex_(i).request().content());
       }
     });
     UNC.currentNotificationCenter().getDeliveredNotificationsWithCompletionHandler_(done);
   };
   ```

   ```bash
   frida -U -f com.example.app -l notif-ios.js
   # trigger notifications (lock the phone first for remote ones, so they are delivered, not presented in-app),
   # then at the Frida prompt:
   dumpDelivered()
   ```

   For a delivered remote notification, `title`/`body` are what was displayed (after any service extension), and `userInfo` holds the payload, including custom keys and the `aps` dictionary, so you see both what the user saw and what travelled through APNs.

2. **Observe the lock screen with previews shown.** Set *Settings > Notifications > Show Previews* to **Always** (and check the app's own Show Previews setting under *Settings > [App] > Notifications*), trigger every notification type, lock the phone, wake it without unlocking, and take a screenshot (side button + volume up). This is the worst case the app has to be safe for: it is the default on devices without Face ID, and any user can choose it.

3. **Observe with previews hidden.** Set Show Previews to **When Unlocked** and repeat, waking the phone while someone else's face or a covered camera prevents Face ID from matching, or with **Never**. Record the placeholder text for each category and whether a title or subtitle still shows.

4. **Check mirrored surfaces** relevant to the user base: a paired Apple Watch, and (if used in testing) Bluetooth accessories with "Share System Notifications" enabled.

5. **Render backend templates on the simulator** (optional) to check category placeholders without the real backend:

   ```json
   {
     "aps": {
       "alert": { "title": "Example Bank", "body": "New account activity" },
       "category": "ACCOUNT_ACTIVITY"
     }
   }
   ```

   ```bash
   xcrun simctl push booted com.example.app payload.json
   ```

#### Observation

The Frida output for each notification type (displayed fields and payload), and lock-screen screenshots under Always and under hidden previews.

#### Evaluation

The test **fails** if a notification displays sensitive data with previews shown, or if the payload carries sensitive data in clear even though the displayed text is generic (a lower-severity, data-minimisation failure; see the push payloads section). With previews hidden, it also fails if the placeholder, title or subtitle shown carries sensitive data. It **passes** if displayed content is generic in all settings and the payload contains only identifiers or ciphertext.

#### Demo

Illustrative output for a remote notification where the backend sends the OTP and the app displays it:

```text
[delivered] title="Example Bank" subtitle="" body="Your login code is 482913" category=OTP
    userInfo={ aps = { alert = { body = "Your login code is 482913"; title = "Example Bank"; }; category = OTP; }; }
```

The lock-screen screenshot with Show Previews set to Always shows the code. The test fails; the fix is a generic body ("Approve your sign-in in the app"), an in-app approval flow, and a category placeholder.

## Best practices

### MASTG-BEST-0027: Preventing Sensitive Data Exposure in Notifications

[MASTG-BEST-0027](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0027/) (Android) is a placeholder in OWASP's repository; its note says it is about "avoiding exposure completely or setting appropriate visibility levels". That is the right order: first keep sensitive data out of notifications, then use visibility as a second layer. The patterns below are ours.

### Secure patterns for Android (Guler Tech)

```kotlin
// Generic public version shown on a redacting lock screen
val publicVersion = NotificationCompat.Builder(context, CHANNEL_ACCOUNT)
    .setSmallIcon(R.drawable.ic_notification)
    .setContentTitle(context.getString(R.string.app_name))
    .setContentText(context.getString(R.string.notif_new_activity))      // "New account activity"
    .build()

val notification = NotificationCompat.Builder(context, CHANNEL_ACCOUNT)
    .setSmallIcon(R.drawable.ic_notification)
    .setContentTitle(context.getString(R.string.app_name))                // never put the data in the title
    .setContentText(context.getString(R.string.notif_new_activity))      // details stay in the app
    .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
    .setPublicVersion(publicVersion)
    .setLocalOnly(true)                                                   // do not bridge to wearables
    .setContentIntent(openAuthenticatedScreen)                            // opens the app; user authenticates
    .setAutoCancel(true)
    .build()
```

- Use `VISIBILITY_SECRET` for notifications that should not appear on a secure lock screen at all (security alerts that include any account detail), and remember the user can still choose to show everything for `PRIVATE`.
- For push, send **data messages** and build the notification locally in `onMessageReceived()`, so the app controls visibility and text; if the backend sends FCM notification messages, set `android.notification.visibility` in the HTTP v1 request and keep `title`/`body` generic.
- If an OTP must be delivered to the device, prefer an in-app approval screen; if a code notification is unavoidable, make it short-lived (`setTimeoutAfter()`), cancel it once the code is used, and keep it `SECRET`.

### Secure patterns for iOS (Guler Tech)

```swift
// Register categories with a generic placeholder and no hidden-preview title/subtitle
let activity = UNNotificationCategory(
    identifier: "ACCOUNT_ACTIVITY",
    actions: [],
    intentIdentifiers: [],
    hiddenPreviewsBodyPlaceholder: NSLocalizedString("notif.placeholder", comment: "e.g. %u new updates"),
    options: [])
UNUserNotificationCenter.current().setNotificationCategories([activity])

// Local notification with generic content
let content = UNMutableNotificationContent()
content.title = "Example Bank"
content.body = NSLocalizedString("notif.new_activity", comment: "New account activity")
content.categoryIdentifier = "ACCOUNT_ACTIVITY"
```

For remote notifications, keep the visible `alert` generic and, if the app needs data, send an identifier or an encrypted blob that a Notification Service Extension handles:

```swift
final class NotificationService: UNNotificationServiceExtension {
    private var handler: ((UNNotificationContent) -> Void)?

    override func didReceive(_ request: UNNotificationRequest,
                             withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        handler = contentHandler
        let content = (request.content.mutableCopy() as? UNMutableNotificationContent) ?? UNMutableNotificationContent()
        // Decrypt request.content.userInfo["enc"] with a key from the shared keychain group,
        // store what the app needs, and keep the displayed text generic.
        content.body = NSLocalizedString("notif.new_message", comment: "You have a new message")
        contentHandler(content)
    }

    override func serviceExtensionTimeWillExpire() {
        let fallback = UNMutableNotificationContent()
        fallback.body = NSLocalizedString("notif.new_message", comment: "You have a new message")
        handler?(fallback)            // never fall back to the original payload text
    }
}
```

The matching payload carries no cleartext:

```json
{
  "aps": {
    "alert": { "title": "Example Bank", "body": "You have a new message" },
    "category": "ACCOUNT_ACTIVITY",
    "mutable-content": 1
  },
  "enc": "BASE64_CIPHERTEXT_PLACEHOLDER"
}
```

## Rating findings

Rate on three things: **what the notification carries** (something that directly grants access or authorises an action, such as an OTP, approval code, reset or magic link; personal, financial or health data; or nothing sensitive), **who can read it** (anyone holding the locked device; an app with notification access; companion devices; the unlocked-device shoulder-surfer; the push provider), and **whether the platform or user settings in their default state expose it**. Notification access is a user-granted special permission, but it is the most common capability Android banking malware obtains, so we do not treat it as an exotic precondition for apps that send codes. Physical access to a locked phone needs no skill and no interaction from the user.

| Rating | Conditions |
|---|---|
| **Critical** | A notification whose content alone gives account access or authorises a sensitive action without any further secret (a magic login link, a password-reset link or token, a full password), shown on a secure lock screen with default settings or delivered in full to notification listeners. |
| **High** | OTPs, transaction-signing or approval codes in notifications for an app protecting money, health, identity or other accounts, delivered in full to notification listeners on supported Android versions (any `minSdkVersion` below 35, or text the classifier will not flag), or shown on the lock screen with default settings (`VISIBILITY_PUBLIC`, `PRIVATE` without public version, iOS preview text on non-Face ID defaults). |
| **Medium** | Personal, financial or health details (names with amounts, balances, message contents, appointment or result details, account numbers) shown on the lock screen with default settings or delivered to listeners; OTPs that are `VISIBILITY_SECRET` but still delivered to listeners and wearables; sensitive titles on otherwise redacted notifications; sensitive data in clear in push payloads where the displayed text is generic. |
| **Low** | Low-sensitivity personal data (first name, a generic "payment received" with amount but no counterparty); sensitive data only visible when the user has explicitly chosen to show everything and the app has done what it can (`SECRET`, generic public version); no iOS hidden-preview placeholder while content is already generic. |
| **Info** | Generic notifications; recommendations such as `setLocalOnly(true)`, end-to-end encrypted payloads, or moving from code notifications to in-app approval. |

Raise a level when the notification is triggered on demand by an attacker who already has partial credentials (a password-reset or login flow they can start), which turns a listener or a glance at a locked phone into account takeover. Lower a level when the exposed code is bound to the device and useless elsewhere, or expires within seconds and is cancelled on use, but not below Medium for a reusable approval code in a finance app. In the report give the notification type and trigger, the exact text (redact real data), the code location or "server-defined", the visibility and public version, the lock-screen screenshots with the setting used, the listener output, and the Android and iOS versions tested.

## References

- OWASP MASWE: [MASWE-0037: Unnecessary Exposure of Sensitive Data via Notifications](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0037/); related [MASWE-0017](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0017/), [MASWE-0036](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0036/), [MASWE-0040](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0040/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PLATFORM-3](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/), [MASVS-STORAGE-2](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0054: App Notifications](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0054/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0315](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0315/); legacy [MASTG-TEST-0005](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0005/), [MASTG-TEST-0008](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0008/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0078](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0078/MASTG-DEMO-0078/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0027](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0027/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0126](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0126/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/) (CC BY-SA 4.0)
- OWASP MASTG tools: [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [adb (MASTG-TOOL-0004)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/), [radare2 for iOS (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/) (CC BY-SA 4.0)
- Android Developers: [Create a notification](https://developer.android.com/develop/ui/views/notifications/build-notification) (incl. [Set lock screen visibility](https://developer.android.com/develop/ui/views/notifications/build-notification#lockscreenNotification)), [Notification runtime permission](https://developer.android.com/develop/ui/compose/notifications/notification-permission), [`NotificationCompat.Builder`](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder), [`NotificationListenerService`](https://developer.android.com/reference/android/service/notification/NotificationListenerService), [`Manifest.permission.POST_NOTIFICATIONS`](https://developer.android.com/reference/android/Manifest.permission#POST_NOTIFICATIONS); Firebase: [Set the message type](https://firebase.google.com/docs/cloud-messaging/customize-messages/set-message-type), [Receive messages in an Android app](https://firebase.google.com/docs/cloud-messaging/android/receive-messages), and the [HTTP v1 `projects.messages` reference](https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages) (`AndroidNotification.visibility`)
- AOSP source (frameworks/base): `NotificationManagerService` (dump filter `--noredact`/`--reveal`, trusted-listener check and `redactStatusBarNotification`), `NotificationRecord.dump()`, `NotificationShellCmd` (`cmd notification`), SystemUI `NotificationLockscreenUserManagerImpl.needsRedaction()`, `Settings.Secure.LOCK_SCREEN_ALLOW_PRIVATE_NOTIFICATIONS`
- Reporting on the Android 15 sensitive-notification change: [Android Authority](https://www.androidauthority.com/android-15-sensitive-notifications-3416414/), and the KDE Connect issue tracker ([bug 495146](https://bugs.kde.org/show_bug.cgi?id=495146)) describing the effect on a companion app
- Apple: [User Notifications](https://developer.apple.com/documentation/usernotifications), [Generating a remote notification](https://developer.apple.com/documentation/usernotifications/generating-a-remote-notification), [`UNMutableNotificationContent`](https://developer.apple.com/documentation/usernotifications/unmutablenotificationcontent), [`hiddenPreviewsBodyPlaceholder`](https://developer.apple.com/documentation/usernotifications/unnotificationcategory/hiddenpreviewsbodyplaceholder), [`hiddenPreviewsShowTitle`](https://developer.apple.com/documentation/usernotifications/unnotificationcategoryoptions/hiddenpreviewsshowtitle), [`hiddenPreviewsShowSubtitle`](https://developer.apple.com/documentation/usernotifications/unnotificationcategoryoptions/hiddenpreviewsshowsubtitle), [`UNNotificationServiceExtension`](https://developer.apple.com/documentation/usernotifications/unnotificationserviceextension), [Apple Notification Center Service (ANCS) Specification](https://developer.apple.com/library/archive/documentation/CoreBluetooth/Reference/AppleNotificationCenterServiceSpecification/Introduction/Introduction.html)
- [Frida JavaScript API](https://frida.re/docs/javascript-api/) (`ObjC.Block`, `Interceptor`, `Java.use`)
- CWE: [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-359](https://cwe.mitre.org/data/definitions/359.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
