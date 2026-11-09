---
title: "Sensitive Data Leaked via Accessibility Services (MASWE-0040)"
date: 2026-11-09 21:11:00 +0000
subcategory: platform
summary: "Testing Android apps for credentials, OTPs and payment controls readable by malicious accessibility services, plus iOS VoiceOver residual risks."
refs: [MASWE-0040, MASVS-PLATFORM-3, MASVS-STORAGE-2, CWE-200, CWE-359]
tags: [android, ios, masvs-platform, accessibility, banking-malware, ui]
---

This note is part of our [MASVS-PLATFORM guide](/mobile/masvs-platform-platform-interaction-guide/) and covers OWASP [MASWE-0040](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0040/): apps that hand their sensitive screen content to accessibility services. On Android, an accessibility service the user has enabled sees every app's UI as a tree of nodes with text, hints and labels, receives an event for every keystroke in every text field, and can click, type and swipe on the user's behalf. That is what makes TalkBack, Switch Access and Voice Access possible, and it is also the core feature set of most modern Android banking malware. Below you will find how a service reads your app (`AccessibilityEvent`, `AccessibilityNodeInfo`, `TYPE_VIEW_TEXT_CHANGED`, password fields, `importantForAccessibility`, Compose semantics), the platform's answer since Android 14 (`accessibilityDataSensitive` and `isAccessibilityTool`), how users get talked into enabling a malicious service and what Android 13+ restricted settings do about it, the two OWASP tests with their demos, our own dynamic test with a minimal logging accessibility service, the iOS residual risks, and how to rate what you find.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: How accessibility services read your app (supplementary)](#android-how-accessibility-services-read-your-app-supplementary)
  - [Android: Accessibility Data Sensitivity (MASTG-KNOW-0143)](#android-accessibility-data-sensitivity-mastg-know-0143)
  - [Android: Accessibility-based banking malware (supplementary)](#android-accessibility-based-banking-malware-supplementary)
  - [iOS: VoiceOver and assistive features (supplementary)](#ios-voiceover-and-assistive-features-supplementary)
- [Tests](#tests)
  - [Before you start: find the sensitive screens](#before-you-start-find-the-sensitive-screens)
  - [MASTG-TEST-0403: References to Accessibility Data Sensitivity APIs (Android)](#mastg-test-0403-references-to-accessibility-data-sensitivity-apis-android)
  - [MASTG-TEST-0404: Runtime Verification of Accessibility Data Sensitivity (Android)](#mastg-test-0404-runtime-verification-of-accessibility-data-sensitivity-android)
  - [MASTG-TEST-0316: App Exposing User Authentication Data in Text Input Fields (Android)](#mastg-test-0316-app-exposing-user-authentication-data-in-text-input-fields-android)
  - [GT-0040-1: Quick look at exposed text with uiautomator dump (Android)](#gt-0040-1-quick-look-at-exposed-text-with-uiautomator-dump-android)
  - [GT-0040-2: Logging what a malicious accessibility service sees (Android)](#gt-0040-2-logging-what-a-malicious-accessibility-service-sees-android)
  - [GT-0040-3: Secrets in accessibility labels (iOS)](#gt-0040-3-secrets-in-accessibility-labels-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0075: Restricting Accessibility Service Access to Sensitive Views](#mastg-best-0075-restricting-accessibility-service-access-to-sensitive-views)
  - [Secure implementation (Guler Tech)](#secure-implementation-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0040 applies when an app exposes sensitive data to accessibility APIs beyond what assistive technology needs, so that a malicious or over-privileged accessibility service can harvest it. The OWASP requirement is *"The app prevents sensitive data from being exposed to, or captured by, accessibility services."* It maps to [MASVS-PLATFORM-3](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/) ("The app uses the user interface securely") and [MASVS-STORAGE-2](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/) (preventing leakage of sensitive data), and to [CWE-200](https://cwe.mitre.org/data/definitions/200.html) (Exposure of Sensitive Information to an Unauthorized Actor) and [CWE-359](https://cwe.mitre.org/data/definitions/359.html) (Exposure of Private Personal Information to an Unauthorized Actor).

OWASP describes the threat as MAS-THREAT-0040, *"Attackers can capture sensitive data displayed or entered in the app"*, reached through MAS-ATTACK-0052: *harvesting on-screen content through a malicious accessibility service the user was tricked into enabling*. Note what the attacker needs: their app on the device **and** the user's explicit consent in Settings to turn its accessibility service on. That is a high bar compared with, say, a missing certificate check. It is also a bar that banking malware campaigns clear every day, with fake browser updates, fake "security" apps and phone calls from "the bank", which is why the weakness exists.

The weakness is tagged for the **L2** and **EUDIW** profiles only. For an L1 app, missing accessibility data sensitivity is a hardening recommendation; for a banking, payments, health or digital-identity wallet app it is an expected control.

Keep it apart from its neighbours:

| Question | Where it lives |
|---|---|
| Can an accessibility service read or operate the app's sensitive views? | This note |
| Can an overlay window trick the user or capture taps? Overlays and accessibility are usually combined by malware | [MASWE-0039: overlay attacks](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/) |
| Is a password or PIN shown in clear in the field itself (shoulder-surfing, screen recording)? | [MASWE-0036: sensitive data in the UI](/mobile/maswe-0036-sensitive-data-exposed-via-ui/) (MASTG-TEST-0316 lives there) |
| Can the screen be captured as pixels (screenshots, recents thumbnail, screen recording)? | [MASWE-0038: screenshots](/mobile/maswe-0038-insufficient-screenshot-protection/) |
| Does an OTP or message body show in a notification? Accessibility services receive notification text too | [MASWE-0037: notifications](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/) |

All OWASP tests for this weakness are Android tests that need Android 14 (API level 34) or later. iOS has no tests because iOS has no third-party accessibility services; we cover the residual iOS risks briefly.

## Modes of Introduction

**Sensitive views not marked as accessibility data sensitive.** The most common case on Android 14+: login, OTP, card-entry and transfer-confirmation screens that never set `accessibilityDataSensitive` (or `filterTouchesWhenObscured`) on the views or their container. Every enabled accessibility service, malicious or not, can read and operate them.

**Protection set, then undone.** A container is marked sensitive but a child explicitly sets `ACCESSIBILITY_DATA_SENSITIVE_NO` (OWASP's demo does this on the *Confirm Payment* button), or code toggles the setting at runtime, or a view is moved out of its protected parent when the screen is rebuilt.

**Secrets in accessibility metadata.** Values placed in `contentDescription`, hint text, Compose `contentDescription`/`stateDescription` semantics, or iOS `accessibilityLabel`/`accessibilityValue` that are more than assistive technology needs. The classic is a "hide balance" or masked-card feature that blanks the visible text but leaves `contentDescription = "Balance £12,345.67"` or the full card number in the label, so the data is hidden from the shoulder-surfer and handed to every accessibility service.

**Secret input not marked as password or secure entry.** A PIN or OTP typed into a plain `EditText`, a Compose `TextField` without password semantics, or an iOS `UITextField` without `isSecureTextEntry`. The node then reports `isPassword=false` and carries the plaintext; each keystroke produces a text-changed event with the full value.

**System keyboards and custom keypads that announce input.** OWASP lists standard system keyboards for PIN entry as a mode of introduction and recommends custom in-app keypads. Be careful with that advice: a custom keypad built from ordinary buttons labelled "1" to "9" produces a `TYPE_VIEW_CLICKED` event with the digit as text for every press, which a logger records just as easily. A custom keypad only helps if the keypad itself is marked accessibility data sensitive.

**High-risk flows fully automatable.** A transfer can be started, filled in (`ACTION_SET_TEXT` on the IBAN and amount fields) and confirmed (`ACTION_CLICK`) entirely through accessibility actions, with no step that a service cannot complete, such as a biometric confirmation bound to a cryptographic key.

**Old platforms and non-View UI.** `minSdkVersion` below 34 means some users run versions where there is no platform protection at all. UI built with Jetpack Compose, Flutter, React Native or a game engine does not use `View` attributes, so the XML and `setAccessibilityDataSensitive` approach either does not apply or must be done through that framework's own semantics.

## Impact

- **Compromise of sensitive data.** Messages, personal data, balances, statements and card details are read straight from the node tree as they are displayed, without screenshots and regardless of `FLAG_SECURE`.
- **Authentication or authorisation bypass.** Usernames, passwords, PINs and one-time codes are captured as they are typed or displayed, which leads to account takeover. OTPs shown in another app (an SMS app, an authenticator) or in a notification are read the same way.
- **Financial loss through on-device fraud.** The service fills in and confirms transactions itself while the user is shown something else or the screen is dimmed. Because the fraud runs on the victim's own device, in the victim's own authenticated session, device-binding and location-based fraud signals see a legitimate customer.
- **Loss of control over the device.** The same service can accept permission prompts, stop the user from uninstalling it, and approve its own requests. That is outside the app's control, but it explains why rating the app's part matters: the app is often the only place the data can still be protected.

## Mitigations

- **Mark sensitive views as accessibility data sensitive** (Android 14+): `android:accessibilityDataSensitive="yes"`, `View.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)`, or the Compose `isSensitiveData` semantics property, on the views or on a container that holds them. `filterTouchesWhenObscured` implies it. Never set `NO` on a view that handles sensitive data.
- **Keep secrets out of accessibility metadata.** Labels and descriptions should say what an element *is* ("Card number, hidden", "Balance hidden"), not carry the secret.
- **Use proper secure input.** `inputType="textPassword"`/`numberPassword`, Compose `SecureTextField` or password semantics, iOS `isSecureTextEntry`/`SecureField`.
- **Mark custom keypads too.** If you build an in-app PIN pad, put it in a container marked accessibility data sensitive; a custom keypad on its own does not stop a logger.
- **Add friction a service cannot complete** for the riskiest actions: a biometric confirmation bound to a Keystore key (`BiometricPrompt` with a `CryptoObject`), see [MASWE-0020](/mobile/maswe-0020-local-authentication-bypass/) and [MASWE-0023](/mobile/maswe-0023-step-up-authentication-not-implemented/), or out-of-band confirmation.
- **Preserve legitimate accessibility.** Protect the sensitive views, not whole screens, and test with TalkBack, Switch Access and Voice Access, which are accessibility tools and keep access. Support Autofill so password managers do not need accessibility.
- **Combine with overlay defences.** `filterTouchesWhenObscured` and `Window.setHideOverlayWindows(true)` (see [MASWE-0039](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/)) cover the overlay half of the typical malware toolkit.

## Knowledge

OWASP links one knowledge item, [MASTG-KNOW-0143](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0143/), which describes the Android 14 control. You cannot judge whether a view needs that control without knowing what an accessibility service actually receives, so we start with that.

### Android: How accessibility services read your app (supplementary)

An accessibility service is an app component that extends [`AccessibilityService`](https://developer.android.com/reference/android/accessibilityservice/AccessibilityService), is protected by the `android.permission.BIND_ACCESSIBILITY_SERVICE` permission (so only the system can bind to it), and declares its capabilities in an XML file referenced from the manifest.

```xml
<!-- AndroidManifest.xml of the service's app -->
<service
    android:name=".MyService"
    android:exported="true"
    android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
    <intent-filter>
        <action android:name="android.accessibilityservice.AccessibilityService" />
    </intent-filter>
    <meta-data
        android:name="android.accessibilityservice"
        android:resource="@xml/my_service_config" />
</service>
```

```xml
<!-- res/xml/my_service_config.xml -->
<accessibility-service xmlns:android="http://schemas.android.com/apk/res/android"
    android:accessibilityEventTypes="typeAllMask"
    android:accessibilityFeedbackType="feedbackGeneric"
    android:accessibilityFlags="flagIncludeNotImportantViews|flagReportViewIds|flagRetrieveInteractiveWindows"
    android:canRetrieveWindowContent="true"
    android:canPerformGestures="true"
    android:isAccessibilityTool="false"
    android:notificationTimeout="100" />
```

The attributes that matter for an attacker (all documented on [`AccessibilityServiceInfo`](https://developer.android.com/reference/android/accessibilityservice/AccessibilityServiceInfo)):

| Attribute | Effect |
|---|---|
| `accessibilityEventTypes="typeAllMask"` | Receive every event type: clicks, focus, text changes, window changes, notifications |
| `android:packageNames` | Comma-separated packages to receive events from. Left out, the service gets events from **all** apps; malware usually leaves it out and filters for its target list in code |
| `canRetrieveWindowContent="true"` | Allows `getRootInActiveWindow()`, `event.getSource()` and `getWindows()`: the full node tree, not just the event |
| `flagIncludeNotImportantViews` | Include views marked not important for accessibility (see below) |
| `flagReportViewIds` | Report resource IDs (`com.example.bank:id/iban`), which makes targeting fields by ID trivial |
| `flagRetrieveInteractiveWindows` | Access every interactive window, not only the active one (including other apps' windows on screen and the IME) |
| `flagRequestFilterKeyEvents` | Receive hardware key events before apps (needs `canRequestFilterKeyEvents`); soft keyboards do not generate these, which is why loggers rely on text-changed events instead |
| `canPerformGestures="true"` | Allows `dispatchGesture()`: synthetic taps and swipes at screen coordinates |
| `isAccessibilityTool` | Declares that the service exists to help people with disabilities (Android 12, API level 31). Defaults to `false`; it is what accessibility data sensitivity keys on (next section) |

Enabling a service takes the user to *Settings > Accessibility > (service) > Use*, followed by a full-screen system warning that the service will be able to view and control the screen. Since Android 12 the framework also posts a reminder notification some time after a service that is not an accessibility tool has been enabled, to remind the user of its access (per the `isAccessibilityTool` attribute documentation). From adb, the same state lives in two secure settings, which is how you enable a test service without the UI:

```bash
adb shell settings get secure enabled_accessibility_services   # colon-separated list of package/class
adb shell settings get secure accessibility_enabled            # 1 when any service is on
```

#### Events: what an `AccessibilityEvent` carries

The system delivers [`AccessibilityEvent`](https://developer.android.com/reference/android/view/accessibility/AccessibilityEvent)s to `onAccessibilityEvent()`. The ones that leak data:

| Event type | When | What it carries |
|---|---|---|
| `TYPE_VIEW_TEXT_CHANGED` (`typeViewTextChanged`) | Every change to an editable text field, i.e. every keystroke | `getText()` (the field's text as displayed), `getBeforeText()`, `getFromIndex()`, `getAddedCount()`, `getRemovedCount()`, `isPassword()` |
| `TYPE_VIEW_CLICKED` | Every click on a view | The view's text or content description: the label of the button pressed, including keypad digits |
| `TYPE_VIEW_FOCUSED`, `TYPE_VIEW_TEXT_SELECTION_CHANGED` | Focus and cursor moves | The text of the focused view |
| `TYPE_WINDOW_STATE_CHANGED` | A new activity, dialog or pane appears | `getPackageName()` and `getClassName()` of the foreground app: this is how malware knows which target app just opened, without any other permission |
| `TYPE_WINDOW_CONTENT_CHANGED` | Any change in a window's content | A trigger to re-read the node tree |
| `TYPE_NOTIFICATION_STATE_CHANGED` | A notification is posted | The notification's text (and the `Notification` as parcelable data): OTPs in notifications leak here |

`TextView` builds the event text from what it *displays*: in AOSP, `getTextForAccessibility()` returns the hint when the field is empty and otherwise the **transformed** text (`mTransformed`), and `TextView.onInitializeAccessibilityEventInternal` sets `event.setPassword(...)` from whether a password transformation is in use. For an ordinary field the transformed text is the plaintext, so a service logging `TYPE_VIEW_TEXT_CHANGED` on a login screen gets the username one character at a time; the last event holds the whole value.

#### The node tree: `AccessibilityNodeInfo`

With `canRetrieveWindowContent`, a service walks the screen as a tree of [`AccessibilityNodeInfo`](https://developer.android.com/reference/android/view/accessibility/AccessibilityNodeInfo) objects from `getRootInActiveWindow()` (or each `AccessibilityWindowInfo.getRoot()` from `getWindows()`). Each node exposes `getText()`, `getHintText()` (API 26), `getContentDescription()`, `getViewIdResourceName()`, `getClassName()`, `isPassword()`, `isEditable()`, `isClickable()` and its bounds. The same nodes accept actions: `performAction(ACTION_CLICK)`, `ACTION_SET_TEXT` with an `ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE` argument (replace a field's content, e.g. the beneficiary's account number), `ACTION_PASTE`, `ACTION_SCROLL_FORWARD`. On top of that, `dispatchGesture()` injects touches at coordinates, and `performGlobalAction()` presses Back, Home or opens notifications.

Things the node tree is **not** affected by:

- `FLAG_SECURE`. It blocks screenshots, screen recording and `AccessibilityService.takeScreenshot()` (which fails with `ERROR_TAKE_SCREENSHOT_SECURE_WINDOW` for secure windows), but the node tree with all its text is still delivered. Apps that rely on `FLAG_SECURE` "against screen-reading malware" are protected against pixel capture only.
- Overlay protections (`setHideOverlayWindows`, untrusted-touch blocking). Accessibility actions are not touches from another window.

Jetpack Compose and WebView content is not made of `View` objects, but both expose virtual node trees through the accessibility framework (Compose through its semantics tree, WebView through the renderer's accessibility tree), so their text reaches services in the same way.

#### Password fields: what is masked and what is not

For a field with a password transformation (`inputType="textPassword"`, `numberPassword`, or `PasswordTransformationMethod`), the node reports `isPassword()=true` and both node text and event text are the transformed text, i.e. bullets (`•`, U+2022). That is much better than plaintext, but not airtight:

- **The last-typed character.** When the system setting *Show passwords* (*Make passwords visible*) is on, which it is by default on many devices, `PasswordTransformationMethod` keeps the most recently typed character visible for a moment by attaching a `Visible` span. `TextView` captures `mBeforeText` from the transformed text in `beforeTextChanged`, so the `getBeforeText()` of a keystroke's event can contain the previous character in clear (`••••a`). A service that logs every event rebuilds the password one character per event. Whether this appears on a given device and Android build is exactly what [GT-0040-2](#gt-0040-2-logging-what-a-malicious-accessibility-service-sees-android) shows you; do not assume either way.
- **Length.** `fromIndex`/`addedCount` and the bullet count reveal the length of the secret.
- **Hints and labels.** The hint is reported when the field is empty, and the field's label or description is always there, so the service knows *which* secret it is looking at.
- **Writing.** `ACTION_SET_TEXT` works on password fields too.
- **Custom keypads.** None of the above applies if the PIN is entered through buttons: each press is a `TYPE_VIEW_CLICKED` with the digit as text.

A secret field that is not marked as a password at all (`isPassword()=false`) leaks every character in plaintext through every channel. That is [MASTG-TEST-0316](#mastg-test-0316-app-exposing-user-authentication-data-in-text-input-fields-android)'s territory.

#### `importantForAccessibility` is not a security control

`android:importantForAccessibility="no"` (or `noHideDescendants`) asks screen readers to skip a view. It is sometimes suggested as a way to "hide" sensitive views from accessibility. It does not work against a malicious service: in AOSP, `View.includeForAccessibility()` includes a view if it is important for accessibility **or** if the querying service set `FLAG_INCLUDE_NOT_IMPORTANT_VIEWS`, which any service can do. Meanwhile it makes the view unusable for TalkBack users. Do not accept it as a mitigation, and flag it as an accessibility defect if it was applied to input fields. The same function is where accessibility data sensitivity is enforced for the node tree: it returns `false` for a sensitive view when the request does not come from an accessibility tool.

#### Jetpack Compose semantics

Compose exposes its UI through semantics. The properties relevant here, from the [`androidx.compose.ui.semantics`](https://developer.android.com/reference/kotlin/androidx/compose/ui/semantics/package-summary) reference:

| Semantics | Effect |
|---|---|
| `password()` | Marks the node as a password field for accessibility services, autofill and tests. It describes the field; it does not mask the text visually (that is the field's visual or codepoint transformation, e.g. `SecureTextField`'s `TextObfuscationMode`) |
| `isSensitiveData = true` | The Compose equivalent of accessibility data sensitivity: the node only allows interactions from services declared as accessibility tools |
| `hideFromAccessibility()` (Compose UI 1.8+; replaces the deprecated `invisibleToUser()`) | Hides the node from accessibility services so screen readers skip it. Like `importantForAccessibility="no"`, it is a usability tool, not a security boundary |
| `contentDescription`, `stateDescription`, `text` | What the node reports. Secrets placed here are exposed |

Because Compose is a single `AndroidComposeView` from the `View` system's point of view, `View`-level checks (the Frida walk in MASTG-TEST-0404, `dumpsys activity top`) cannot see individual composables. Test Compose screens with an accessibility service ([GT-0040-2](#gt-0040-2-logging-what-a-malicious-accessibility-service-sees-android)).

### Android: Accessibility Data Sensitivity (MASTG-KNOW-0143)

Source: [MASTG-KNOW-0143](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0143/). Platform: Android 14 (API level 34) and later. Best practice: MASTG-BEST-0075.

Android 14 added a per-view switch that splits accessibility services into two classes: those declared as accessibility tools (`android:isAccessibilityTool="true"` in the service configuration) and everyone else. A view marked *accessibility data sensitive* is fully available to the first class and invisible and untouchable to the second.

**How to set it.**

| Where | How | Values |
|---|---|---|
| Layout XML | `android:accessibilityDataSensitive` | `auto` (0, default), `yes` (1), `no` (2). The framework declares it as an enum, so use `yes`/`no`, not `true`/`false` |
| Code | `View.setAccessibilityDataSensitive(int)` | `View.ACCESSIBILITY_DATA_SENSITIVE_AUTO`, `_YES`, `_NO`. Guard with `Build.VERSION.SDK_INT >= 34` if `minSdkVersion` is lower |
| Compose | `Modifier.semantics { isSensitiveData = true }` | Boolean |
| Read back | `View.isAccessibilityDataSensitive()` | Effective value, after inheritance |

**Automatic behaviour.** With `AUTO`, AOSP's `View.calculateAccessibilityDataSensitive()` resolves the effective value in this order: an explicit `YES`/`NO` wins; otherwise a view with `filterTouchesWhenObscured` set is sensitive; otherwise a view whose parent is sensitive is sensitive; otherwise not. Two consequences: marking a container protects everything inside it, and a child that explicitly sets `NO` punches a hole in the container's protection (OWASP's demo does exactly that to the payment button). Apps that already set `filterTouchesWhenObscured` against tapjacking get the protection for free on Android 14+.

**What it does for a service that is not an accessibility tool.**

- The view (and its sensitive descendants) is left out of the node tree the service retrieves, so it cannot read its text or get a node to act on.
- Events from the sensitive view are flagged as sensitive and are not dispatched to such services; a sensitive `TextView` also does not add its text to events raised by a non-sensitive view.
- On Android 16 (API level 36) and higher, gestures injected with `dispatchGesture()` that target the sensitive view are blocked as well, closing the "tap at the button's coordinates" workaround ([Android tapjacking guidance](https://developer.android.com/privacy-and-security/risks/tapjacking)).

**Who keeps access.** Services declaring `isAccessibilityTool="true"`. Google Play restricts that declaration to apps whose primary purpose is supporting people with disabilities (screen readers, switch and voice input, braille), rejects other apps that make it, and Google Play Protect blocks them on devices ([Play AccessibilityService policy](https://support.google.com/googleplay/android-developer/answer/10964491), [Android Developers Blog, December 2025](https://android-developers.googleblog.com/2025/12/enhancing-android-security-stop-malware.html)). Password managers, automation apps, launchers and antivirus apps do not qualify and lose access to protected views; password managers should use Autofill instead. The declaration is just a boolean in an XML file: an app sideloaded from outside Play can claim it, and only Play Protect stands in the way. Treat the control as a strong filter, not a guarantee.

**Advanced Protection on Android 17.** OWASP notes that with Android's Advanced Protection mode enabled, Android 17 restricts the accessibility API to verified accessibility tools for all apps, regardless of per-view marking. It is opt-in, so per-view sensitivity remains the control the app owns.

**Version summary.**

| Android | What exists |
|---|---|
| 11 and lower | No per-view protection. Any enabled service reads and operates everything |
| 12 (API 31) | `isAccessibilityTool` attribute; reminder notification for non-tool services |
| 13 (API 33) | Restricted settings for sideloaded apps (see the malware section) |
| 14 (API 34) | `accessibilityDataSensitive`, `filterTouchesWhenObscured` implies it |
| 16 (API 36) | Sensitive views also block injected gestures from non-tool services |
| 17 | Advanced Protection (opt-in) restricts the API to accessibility tools device-wide |

### Android: Accessibility-based banking malware (supplementary)

You will be asked "would anyone really do this?" The short answer is that abusing accessibility is the standard operating model of Android banking trojans, documented continuously by mobile threat-intelligence vendors since around 2017, and that academic work demonstrated the full attack chain the same year: the *Cloak & Dagger* research (IEEE S&P 2017, [cloak-and-dagger.org](https://cloak-and-dagger.org/)) showed overlay plus accessibility giving complete control of the UI. The class of threat, without naming families:

- **Delivery.** Sideloaded apps from smishing links, fake browser or "security" updates, or dropper apps that reach a store and fetch the payload later. A phone call from someone posing as the bank's fraud team walks the victim through enabling the service.
- **Consent.** The malware shows its own screen urging the user to enable "the service" and opens *Settings > Accessibility* for them. Once enabled, it uses its new power to accept its own permission prompts (SMS, notifications, overlay, device admin) and to press Back whenever the user opens its uninstall page.
- **Target detection.** `TYPE_WINDOW_STATE_CHANGED` reports the foreground package; the malware matches it against its list of target apps.
- **Collection.** Keylogging through `TYPE_VIEW_TEXT_CHANGED`, reading the node tree of target screens (balances, card data, messages), reading OTPs from SMS apps, authenticator apps and notifications, and showing overlays at the right moment ([MASWE-0039](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/)).
- **On-device fraud.** Remote control through the node tree and gestures, up to fully automated transfer systems that fill in and confirm payments inside the victim's real session.

**Android 13 restricted settings.** Android 13 greys out the accessibility and notification-listener switches for apps installed by a non-store installer (a browser, file manager or messaging app that does not use the session-based package installer API). The user sees a *Restricted setting* dialog and has to open *App info*, use the overflow menu and choose *Allow restricted settings* before the switch works. Two well-documented weaknesses followed: the restriction did not apply to apps installed through the session-based installer API, which droppers simply used; and the manual override itself became part of the scam script. Android 15 extended the restriction to more permissions and reportedly reworked how installs are classified (Enhanced Confirmation Mode). For testing this means: do not rely on restricted settings as the app's mitigation, and expect the settings UI to block your own test service. Enabling it with `adb shell settings put` bypasses the UI.

The app cannot stop the user from enabling a malicious service. What it controls is what that service gets once enabled, which is what this weakness and its tests are about.

### iOS: VoiceOver and assistive features (supplementary)

iOS has no equivalent of Android's accessibility services. VoiceOver, Switch Control, Voice Control, Speak Screen and Full Keyboard Access are system features; there is no public API through which a third-party app can observe or drive another app's UI, so the MAS-ATTACK-0052 scenario does not exist on a non-jailbroken device. That is why OWASP has no iOS tests.

What remains is the accessibility metadata the app itself publishes through [`UIAccessibility`](https://developer.apple.com/documentation/uikit/uiaccessibility) (`accessibilityLabel`, `accessibilityValue`, `accessibilityHint`, `accessibilityTraits`, `isAccessibilityElement`, `accessibilityElementsHidden`) or SwiftUI modifiers (`.accessibilityLabel(_:)`, `.accessibilityValue(_:)`, `.accessibilityHidden(_:)`):

- **Spoken aloud.** VoiceOver and Speak Screen read labels and values aloud. A label carrying a full card number, a recovery phrase or a balance that is visually hidden is broadcast to anyone in earshot, and a "hide balance" toggle that only blanks the text is not hidden for VoiceOver users at all.
- **Shown on screen.** Voice Control can overlay element names on the screen, which draws accessibility labels as visible text.
- **Read by tooling.** XCUITest, Xcode's Accessibility Inspector, and UI-automation or session-replay SDKs that walk the accessibility hierarchy all pick up what is in the labels.
- **Secure entry.** `UITextField.isSecureTextEntry = true` and SwiftUI `SecureField` mark the field as secure and mask its value for assistive technologies; a secret entered in a plain field is exposed the same way as on Android.

Pixel capture (screen recording, AirPlay mirroring) is a separate problem covered in [MASWE-0038](/mobile/maswe-0038-insufficient-screenshot-protection/). On a jailbroken device, a tweak injected into the app can read anything, accessibility or not, which is out of scope for this weakness.

## Tests

OWASP links two tests to MASWE-0040, both Android and both requiring Android 14 or later: a static search for the sensitivity APIs (MASTG-TEST-0403) and a runtime check of the effective value of each view (MASTG-TEST-0404). OWASP also maps [MASTG-TEST-0316](#mastg-test-0316-app-exposing-user-authentication-data-in-text-input-fields-android) to this weakness; it is documented in full in the MASWE-0036 note. There were no legacy (MASTG v1) accessibility tests, so these do not replace anything.

Both OWASP tests examine the app's configuration. Neither shows what a malicious service actually receives, and OWASP's own UI-hierarchy technique (MASTG-TECH-0177) recommends a custom accessibility service as "the most direct way" to confirm the protection without spelling one out. We add it as [GT-0040-2](#gt-0040-2-logging-what-a-malicious-accessibility-service-sees-android), plus a quick `uiautomator dump` triage ([GT-0040-1](#gt-0040-1-quick-look-at-exposed-text-with-uiautomator-dump-android)) and a short iOS label review ([GT-0040-3](#gt-0040-3-secrets-in-accessibility-labels-ios)).

### Before you start: find the sensitive screens

Every test here starts from OWASP's `identify-sensitive-data` prerequisite: you need a list of the screens and fields that handle sensitive data, because no tool can decide that for you. Walk the app and write down at least: login (username, password, PIN), registration and password reset, OTP and 2FA entry, card and account details, payee and transfer forms with their confirmation and "approve" buttons, recovery phrases or backup codes, personal data screens (ID numbers, addresses, health data), and any in-app display of OTPs or transaction-signing codes. Take a screenshot of each one for the report:

```bash
adb exec-out screencap -p > login.png        # FLAG_SECURE screens come out black, which is fine: note it
adb shell dumpsys activity activities | grep -E 'topResumedActivity|mResumedActivity'   # which activity is this?
```

Then check the version context:

```bash
adb shell getprop ro.build.version.sdk            # 34 or higher needed for the protection to exist
aapt2 dump badging app.apk | grep -E "sdkVersion|targetSdkVersion"   # minSdk: how many users have no protection?
```

### MASTG-TEST-0403: References to Accessibility Data Sensitivity APIs (Android)

Source: [MASTG-TEST-0403](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0403/). Platform: Android (API level 34+). Type: static (code) with manual review. Knowledge: MASTG-KNOW-0143. Best practice: MASTG-BEST-0075.

#### Overview

The test looks for the places where the app configures accessibility data sensitivity, in layouts and in code, and checks that every view handling sensitive data is covered, either on the view or on a parent, and that none of them sets `NO`. It looks for `android:accessibilityDataSensitive` and `android:filterTouchesWhenObscured` in layout files, and for calls to `setAccessibilityDataSensitive` (and the value passed) and `setFilterTouchesWhenObscured`.

Its blind spot is built in: a view for which the app configures nothing does not appear in the output, and those are the views most likely to be unprotected. Use the results to understand the app's intent and confirm with MASTG-TEST-0404 or GT-0040-2.

#### Prerequisites

- The APK, decompiled with jadx ([MASTG-TOOL-0018](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)) and decoded with Apktool ([MASTG-TOOL-0011](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/)), per [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/) and [MASTG-TECH-0007](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0007/).
- semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)) with OWASP's `mastg-android-accessibility-data-sensitive.yaml` rule, or grep ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)).
- Your list of sensitive screens and fields.

#### Steps

1. Pull and decompile the app:

   ```bash
   adb shell pm path com.example.bank            # note every split
   adb pull /data/app/~~XXXX/com.example.bank-YYYY/base.apk
   jadx -d out base.apk
   apktool d base.apk -o apk_out
   ```

2. Find the layout attributes. Apktool decodes the enum back to its name, so expect `yes`, `no` or `auto`:

   ```bash
   grep -rnE 'android:(accessibilityDataSensitive|filterTouchesWhenObscured)=' apk_out/res/layout*/
   ```

3. Find the code calls. In decompiled Java the constants are integers: `0` = `AUTO`, `1` = `YES`, `2` = `NO`. Kotlin property syntax (`view.filterTouchesWhenObscured = true`) compiles to the setter, so one pattern covers both:

   ```bash
   grep -rnE 'setAccessibilityDataSensitive\(|setFilterTouchesWhenObscured\(' out/sources/ \
     | grep -vE '^out/sources/(androidx|com/google/android/material)/'
   ```

   Or run OWASP's rule, which separates "set", "disabled" (`NO`) and "filter touches" findings:

   ```bash
   semgrep -c mastg-android-accessibility-data-sensitive.yaml out/sources/ --text
   ```

4. For Compose, look for the semantics setter. The Kotlin property `isSensitiveData` compiles to a setter called `setSensitiveData`; in a minified release build the Compose library names may be obfuscated, in which case search for the call sites of the `Modifier.semantics` lambdas on your sensitive screens instead:

   ```bash
   grep -rn 'setSensitiveData' out/sources/ | grep -v '^out/sources/androidx/'
   ```

5. Map each hit to a screen. For layout hits, the file name and the view IDs tell you where you are; for code hits, open the class in jadx-gui ([MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)) and find which activity or fragment builds the view. Then go through your list of sensitive fields and, for each one, find its layout or construction code and walk up to its parents to see whether any of them is marked.

#### Observation

All `android:accessibilityDataSensitive` and `android:filterTouchesWhenObscured` attributes with their file and value; all `setAccessibilityDataSensitive` calls with the value passed; all `setFilterTouchesWhenObscured` calls with the value passed; and, from manual review, the list of sensitive fields with how each is (or is not) covered.

#### Evaluation

The test **fails** if any view that handles sensitive data is not accessibility data sensitive, either on the view itself or through a parent (explicit `yes`/`YES`, or `filterTouchesWhenObscured="true"` with the default `auto`), or if the app sets `NO` (`android:accessibilityDataSensitive="no"`, `setAccessibilityDataSensitive(2)`) on such a view.

It **passes** for a view if the view or one of its parents is marked, and the view itself does not override it with `NO`.

False negatives to expect: views with no configuration at all (by design, they do not show up), Compose, Flutter, React Native and game-engine UIs, and values decided at runtime (remote config, reflection). A pass here is provisional until the runtime check agrees.

#### Demo

[MASTG-DEMO-0159](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0159/MASTG-DEMO-0159/). The sample builds a login and payment form in code, each view with a different configuration:

```kotlin
// FAIL: username handles credentials but is not marked
val usernameField = createField("Username", InputType.TYPE_CLASS_TEXT)

// PASS: explicitly marked
val passwordField = createField("Password", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD)
passwordField.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)

// PASS: filterTouchesWhenObscured implies sensitivity
val otpField = createField("One-time code", InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD)
otpField.filterTouchesWhenObscured = true

// PASS: container marked, card field inherits
val paymentContainer = LinearLayout(context)
paymentContainer.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
val cardField = createField("Card number", InputType.TYPE_CLASS_NUMBER)
paymentContainer.addView(cardField)

// FAIL: the confirmation button opts out of the inherited protection
val confirmButton = Button(context).apply { text = "Confirm Payment" }
confirmButton.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_NO)
paymentContainer.addView(confirmButton)
```

semgrep on the decompiled code (trimmed):

```text
MastgTest_reversed.java
 ❱ rules.mastg-android-accessibility-data-sensitive-set
       64┆ passwordField.setAccessibilityDataSensitive(1);
 ❱ rules.mastg-android-accessibility-data-sensitive-filter-touches
       67┆ otpField.setFilterTouchesWhenObscured(true);
 ❱ rules.mastg-android-accessibility-data-sensitive-set
       71┆ paymentContainer.setAccessibilityDataSensitive(1);
❯❱ rules.mastg-android-accessibility-data-sensitive-disabled
       82┆ confirmButton.setAccessibilityDataSensitive(2);
```

The test fails twice. The *Confirm Payment* button is reported by the "disabled" rule (`2` = `NO`), overriding its protected container. The username field is the more instructive failure: it does not appear in the output at all, because nothing configures it; you only find it by reviewing the code against your list of sensitive fields. The card number field also does not appear, but it is protected by inheritance from the container on line 71.

### MASTG-TEST-0404: Runtime Verification of Accessibility Data Sensitivity (Android)

Source: [MASTG-TEST-0404](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0404/). Platform: Android (API level 34+). Type: dynamic (hooks) with manual review. Knowledge: MASTG-KNOW-0143. Best practice: MASTG-BEST-0075.

#### Overview

The dynamic counterpart of MASTG-TEST-0403. Static analysis cannot tell you the *effective* value of a view after inheritance, runtime changes and re-parenting, and it never lists the views nobody configured. This test does two things at runtime: hooks `setAccessibilityDataSensitive` and `setFilterTouchesWhenObscured` to see when and from where the app changes them, and walks the `View` hierarchy of each sensitive screen calling `isAccessibilityDataSensitive()` and `getFilterTouchesWhenObscured()` on every view.

#### Prerequisites

- A device or emulator running Android 14 (API level 34) or later, rooted or with a Frida-gadget build, with frida-server running ([Frida, MASTG-TOOL-0001](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/)).
- The app installed ([MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)): `adb install-multiple base.apk split_*.apk`.
- OWASP's `script.js` from the demo, or the condensed version below ([MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0177](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0177/)).
- Your list of sensitive screens.

#### Steps

1. Spawn the app with the script and log to a file:

   ```bash
   frida -U -f com.example.bank -l a11y_sensitivity.js -o a11y_sensitivity.log
   ```

2. Exercise every flow, entering data wherever you can. The hooks print each setter call with its argument and a backtrace.

3. On each sensitive screen, call `dumpViews()` from the Frida REPL to print the hierarchy of the focused activity with the effective values. The core of OWASP's script:

   ```javascript
   const MODES = { 0: "AUTO", 1: "YES", 2: "NO" };

   function walk(view, depth, out) {
     const ViewGroup = Java.use("android.view.ViewGroup");
     const TextView = Java.use("android.widget.TextView");
     let d = view.getClass().getName();
     if (TextView.class.isInstance(view)) {
       const hint = Java.cast(view, TextView).getHint();
       if (hint !== null) d += ` hint="${hint}"`;          // do not log field contents
     }
     out.push("  ".repeat(depth) + d +
       ` isAccessibilityDataSensitive=${view.isAccessibilityDataSensitive()}` +
       ` filterTouchesWhenObscured=${view.getFilterTouchesWhenObscured()}`);
     if (ViewGroup.class.isInstance(view)) {
       const g = Java.cast(view, ViewGroup);
       for (let i = 0; i < g.getChildCount(); i++) walk(g.getChildAt(i), depth + 1, out);
     }
   }

   globalThis.dumpViews = () => Java.perform(() => Java.scheduleOnMainThread(() => {
     Java.choose("android.app.Activity", {
       onMatch(a) {
         if (a.isFinishing() || !a.hasWindowFocus()) return;
         const out = [];
         walk(a.getWindow().getDecorView(), 0, out);
         console.log(`[*] ${a.getClass().getName()}\n` + out.join("\n"));
       },
       onComplete() {}
     });
   }));

   Java.perform(() => {
     const View = Java.use("android.view.View");
     const trace = () => Java.use("android.util.Log")
       .getStackTraceString(Java.use("java.lang.Exception").$new()).split("\n").slice(1, 6).join("\n");
     View.setAccessibilityDataSensitive.implementation = function (m) {
       console.log(`[setAccessibilityDataSensitive] ${this.getClass().getName()} mode=${MODES[m] ?? m}\n${trace()}`);
       return this.setAccessibilityDataSensitive(m);
     };
     View.setFilterTouchesWhenObscured.implementation = function (e) {
       console.log(`[setFilterTouchesWhenObscured] ${this.getClass().getName()} enabled=${e}\n${trace()}`);
       return this.setFilterTouchesWhenObscured(e);
     };
   });
   ```

   Dialogs and bottom sheets are separate windows with their own decor view; `Java.choose` on `android.app.Dialog` (and walking `getWindow().getDecorView()` the same way) covers them.

4. Take a screenshot of each screen ([MASTG-TECH-0178](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0178/)) so you can match views in the dump to what the user sees: `adb exec-out screencap -p > screen.png`.

5. If a screen shows a single `AndroidComposeView` (or a `FlutterView`, or a WebView) where the sensitive fields are, the walk cannot see inside it. Use GT-0040-2 for that screen.

#### Observation

The setter calls with argument values and backtraces; the hierarchy of every sensitive screen with class, resource ID, hint or button text, `isAccessibilityDataSensitive` and `filterTouchesWhenObscured` per view; a screenshot of each screen.

#### Evaluation

The test **fails** if any view that handles sensitive data returns `false` from `isAccessibilityDataSensitive()` while the screen is displayed. Use the backtraces to find where a `NO` comes from, and the screenshots to decide which views count as sensitive. Do not rely on automated classification of "sensitive" alone; confirm by looking at the screens.

It **passes** for a screen when every view that displays or accepts sensitive data, including the buttons that confirm sensitive actions, returns `true`.

#### Demo

[MASTG-DEMO-0160](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0160/MASTG-DEMO-0160/), on the same sample as DEMO-0159. The hooks fire four times from `MastgTest.mastgTest` (password `YES`, OTP filter-touches `true`, container `YES`, Confirm Payment `NO`), and the hierarchy shows the effective values (trimmed):

```text
android.widget.LinearLayout isAccessibilityDataSensitive=false filterTouchesWhenObscured=false
  android.widget.EditText hint="Username" isAccessibilityDataSensitive=false filterTouchesWhenObscured=false
  android.widget.EditText hint="Password" isAccessibilityDataSensitive=true filterTouchesWhenObscured=false
  android.widget.EditText hint="One-time code" isAccessibilityDataSensitive=true filterTouchesWhenObscured=true
  android.widget.LinearLayout isAccessibilityDataSensitive=true filterTouchesWhenObscured=false
    android.widget.EditText hint="Card number" isAccessibilityDataSensitive=true filterTouchesWhenObscured=false
    android.widget.Button text="Confirm Payment" isAccessibilityDataSensitive=false filterTouchesWhenObscured=false
  android.widget.Button text="Cancel" isAccessibilityDataSensitive=false filterTouchesWhenObscured=false
```

The test fails: *Username* and *Confirm Payment* handle sensitive data and return `false`. Only the walk shows that the card number field is protected by inheritance and that the username field is not protected at all, because neither involves a hooked call. *Cancel* returning `false` is fine: it does not handle sensitive data.

### MASTG-TEST-0316: App Exposing User Authentication Data in Text Input Fields (Android)

OWASP maps [MASTG-TEST-0316](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0316/) to both MASWE-0036 and MASWE-0040. We document it in full in the [MASWE-0036 note on sensitive data in the UI](/mobile/maswe-0036-sensitive-data-exposed-via-ui/), because its primary concern is masking passwords, PINs and OTPs on screen (`inputType="textPassword"`, Compose `SecureTextField` and its `TextObfuscationMode`).

Its relevance here: an unmasked secret field is also an unmasked field for accessibility. The node reports `isPassword()=false` and plaintext text, and every keystroke produces a `TYPE_VIEW_TEXT_CHANGED` event carrying the value. If MASTG-TEST-0316 fails on a field, record the accessibility consequence in this weakness too, and confirm it with GT-0040-2.

### GT-0040-1: Quick look at exposed text with uiautomator dump (Android)

Guler Tech methodology. Platform: Android (any version). Type: dynamic, triage.

#### Overview

`uiautomator dump` serialises the accessibility node tree of the foreground window to XML. It needs no root, no instrumentation, no test app, and it works on release builds and on Compose screens. In two minutes per screen it shows you what text, descriptions and password flags the app publishes to the accessibility layer, which is the raw material for finding secrets in metadata and unmasked secret fields.

Know its limit before you use it for anything else: UI Automator reads through the platform's UI automation connection, which is **not** restricted by accessibility data sensitivity (MASTG-TECH-0177 makes the same point). Protected views still appear in the dump with their text. You cannot use it to verify MASTG-KNOW-0143; that is what GT-0040-2 is for.

#### Prerequisites

- adb ([MASTG-TOOL-0004](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/)) and a device with the app installed and logged in with a test account. Python 3 on the host for the summary.
- Test data you can recognise: a distinctive username, a password such as `Gt-Probe-4711`, a test card from your payment provider's sandbox.

#### Steps

1. Open a sensitive screen, enter the test data, leave the keyboard up.
2. Dump and pull:

   ```bash
   adb shell uiautomator dump /sdcard/ui.xml
   adb pull /sdcard/ui.xml login.xml
   ```

   `ERROR: could not get idle state` means the screen is animating (a spinner, a blinking cursor in some custom views); wait and retry, or stop the animation.

3. Summarise every node that carries text or a description:

   ```bash
   python3 -I - login.xml <<'EOF'
   import sys, xml.etree.ElementTree as ET
   for n in ET.parse(sys.argv[1]).iter('node'):
       t, d = n.get('text', ''), n.get('content-desc', '')
       if t or d:
           print(f"{n.get('class')}\t{n.get('resource-id')}\tpassword={n.get('password')}\ttext={t!r}\tdesc={d!r}")
   EOF
   ```

4. Search for your test values directly, which also finds them in places you did not expect:

   ```bash
   grep -o 'Gt-Probe-4711\|4111 1111\|recovery' login.xml
   ```

5. Repeat on each screen from your list, including screens with masked values ("hide balance" toggled on, masked card numbers, OTP display screens).

#### Observation

The per-screen node summaries: class, resource ID, `password` flag, `text`, `content-desc`.

#### Evaluation

Record a finding when:

- A secret input field reports `password="false"` and its text is your test secret in plaintext (cross-reference MASTG-TEST-0316).
- A `content-desc` or `text` carries a value the screen deliberately hides: the full card number behind a masked display, a balance behind "hide balance", a full OTP, a recovery phrase, a token.
- A label or description contains more than the user needs to understand the element (account numbers in a button description, for example).

A clean dump means only that the app publishes no secrets in metadata on those screens. It says nothing about whether sensitive views are protected from malicious services; a protected password field and an unprotected one look the same here.

#### Demo

Illustrative output for a login form with a masked-balance widget, dumped on Android 14:

```text
android.widget.EditText   com.example.bank:id/username   password=false  text='alice@example.com'  desc=''
android.widget.EditText   com.example.bank:id/password   password=true   text='•••••••••••••'      desc=''
android.widget.TextView   com.example.bank:id/balance    password=false  text='£••••••'            desc='Available balance £12,345.67'
android.widget.Button     com.example.bank:id/login      password=false  text='Log in'             desc=''
```

The password field is correctly masked. The balance is hidden on screen and published in clear in its content description, which TalkBack would read aloud and any accessibility service can collect: a finding (secrets in accessibility metadata), whatever the result of the sensitivity tests.

### GT-0040-2: Logging what a malicious accessibility service sees (Android)

Guler Tech methodology. Platform: Android (Android 14+ to test the protection; any version to demonstrate exposure). Type: dynamic, with a purpose-built test service.

#### Overview

The direct proof. You build a minimal accessibility service that is **not** declared as an accessibility tool, the same as nearly all malware, enable it, use the target app, and read in logcat exactly what it received: the node tree of each sensitive screen and every text-changed and click event. Protected views are simply absent; unprotected ones show their content. Then flip `isAccessibilityTool` to `true` and repeat to show the residual risk. This test also covers what the other tests cannot reach: Compose, Flutter and WebView screens, password-field behaviour on the actual device, and keypad clicks.

Use it only on devices you own and apps you are authorised to test. The probe logs everything it sees from the target package, so use test accounts and test data, and uninstall it when you are done.

#### Prerequisites

- Android Studio or a Gradle setup to build a small app (`minSdk 31` so `isAccessibilityTool` can be read back; compile against SDK 34 or later).
- A test device or emulator on Android 14 or later (ideally also one on Android 16+ to check gestures), adb.
- The target app's package name (`adb shell pm list packages | grep -i bank`).

#### Steps

1. Create the service. One file, no UI:

   ```kotlin
   package uk.co.gulertech.a11yprobe

   import android.accessibilityservice.AccessibilityService
   import android.util.Log
   import android.view.accessibility.AccessibilityEvent
   import android.view.accessibility.AccessibilityNodeInfo

   class LeakProbeService : AccessibilityService() {

       private val tag = "A11yProbe"
       private var lastDump = 0L

       override fun onServiceConnected() {
           Log.i(tag, "connected isAccessibilityTool=${serviceInfo.isAccessibilityTool}")
       }

       override fun onAccessibilityEvent(event: AccessibilityEvent) {
           val type = AccessibilityEvent.eventTypeToString(event.eventType)
           when (event.eventType) {
               AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED ->
                   Log.i(tag, "$type ${event.className} password=${event.isPassword} " +
                       "before=\"${event.beforeText}\" text=${event.text} " +
                       "from=${event.fromIndex} added=${event.addedCount} removed=${event.removedCount}")
               AccessibilityEvent.TYPE_VIEW_CLICKED,
               AccessibilityEvent.TYPE_VIEW_FOCUSED ->
                   Log.i(tag, "$type ${event.className} text=${event.text} desc=${event.contentDescription}")
               AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED,
               AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED -> {
                   val now = System.currentTimeMillis()
                   if (now - lastDump > 1500) {           // content changes are noisy: one dump per 1.5 s
                       lastDump = now
                       Log.i(tag, "---- tree of ${event.packageName} ${event.className}")
                       rootInActiveWindow?.let { dump(it, 0) }
                   }
               }
           }
       }

       private fun dump(node: AccessibilityNodeInfo, depth: Int) {
           Log.i(tag, "  ".repeat(depth) + "${node.className} id=${node.viewIdResourceName} " +
               "text=\"${node.text}\" hint=\"${node.hintText}\" desc=\"${node.contentDescription}\" " +
               "password=${node.isPassword} editable=${node.isEditable} clickable=${node.isClickable}")
           for (i in 0 until node.childCount) node.getChild(i)?.let { dump(it, depth + 1) }
       }

       override fun onInterrupt() {}
   }
   ```

2. Configure it like malware would, restricted to the target package so your logs stay readable (`res/xml/leak_probe_config.xml`):

   ```xml
   <accessibility-service xmlns:android="http://schemas.android.com/apk/res/android"
       android:accessibilityEventTypes="typeAllMask"
       android:accessibilityFeedbackType="feedbackGeneric"
       android:accessibilityFlags="flagIncludeNotImportantViews|flagReportViewIds|flagRetrieveInteractiveWindows"
       android:canRetrieveWindowContent="true"
       android:isAccessibilityTool="false"
       android:notificationTimeout="50"
       android:packageNames="com.example.bank" />
   ```

3. Declare it in the manifest:

   ```xml
   <service
       android:name=".LeakProbeService"
       android:exported="true"
       android:label="GT a11y probe"
       android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
       <intent-filter>
           <action android:name="android.accessibilityservice.AccessibilityService" />
       </intent-filter>
       <meta-data
           android:name="android.accessibilityservice"
           android:resource="@xml/leak_probe_config" />
   </service>
   ```

4. Build, install and enable it. Save the existing value first: `put` replaces the whole list, and you want TalkBack or anything else back afterwards. Enabling through `settings` also sidesteps the Android 13+ restricted-settings dialog:

   ```bash
   ./gradlew :app:assembleDebug
   adb install -r app/build/outputs/apk/debug/app-debug.apk

   OLD=$(adb shell settings get secure enabled_accessibility_services)
   adb shell settings put secure enabled_accessibility_services uk.co.gulertech.a11yprobe/.LeakProbeService
   adb shell settings put secure accessibility_enabled 1

   adb shell dumpsys accessibility | grep -iE 'a11yprobe|Bound services|Enabled services'
   ```

   If the target is already running, the service connects immediately; `connected isAccessibilityTool=false` in logcat confirms it.

5. Watch the log while you use the app:

   ```bash
   adb logcat -c
   adb logcat -s A11yProbe:I | tee probe-tool-false.log
   ```

   Walk every sensitive screen. Type your test username, password, OTP and card number slowly, one character at a time, so the per-keystroke events are clear. Press the confirmation buttons and, if there is a PIN pad, enter a PIN on it.

6. Repeat with `android:isAccessibilityTool="true"` in the config (rebuild, reinstall; the service is re-bound). This shows that an accessibility tool, and anything sideloaded that claims to be one, still sees the protected views.

7. Optional, for transaction screens: prove the automation half. Add a few lines that look up the confirmation button by its text or ID in the node tree (`rootInActiveWindow.findAccessibilityNodeInfosByViewId("com.example.bank:id/confirm")`) and call `performAction(AccessibilityNodeInfo.ACTION_CLICK)` on it, behind a manual trigger so it cannot fire on a real transaction. On an unprotected button the click goes through; on a protected one the lookup returns nothing.

8. Clean up:

   ```bash
   adb shell settings put secure enabled_accessibility_services "$OLD"   # or: settings delete secure enabled_accessibility_services
   adb shell settings put secure accessibility_enabled 0                  # only if nothing else was enabled
   adb uninstall uk.co.gulertech.a11yprobe
   ```

#### Observation

`probe-tool-false.log` and `probe-tool-true.log`: per screen, the node tree the service received, every `TYPE_VIEW_TEXT_CHANGED` with `password`, `before` and `text`, every click and focus event with its text; device model, Android version and security patch level; the state of the *Show passwords* setting (`adb shell settings get system show_password`, where `1` is on).

#### Evaluation

With `isAccessibilityTool="false"` on Android 14 or later, the test **fails** for a sensitive view if any of the following appears in the log:

- the view's node in the tree, with its text, hint or description;
- a `TYPE_VIEW_TEXT_CHANGED` event from it, plaintext or masked (a masked event still leaks length and, with *Show passwords* on, possibly the previous character in `before`);
- a `TYPE_VIEW_CLICKED` event carrying a keypad digit or the label of a confirmation button;
- in step 7, a successful click on a confirmation control.

It **passes** for a view when the view and its events are absent from the non-tool log, and present in the tool log (proving the screen was exercised and the absence is the protection, not a dead logger).

On Android 13 and lower the protection does not exist and every view will show. Run it anyway on the oldest version the app supports: it shows the extent of exposure for those users and catches secrets in metadata and unmasked fields, which fail on every version.

#### Demo

The DEMO-0159 form, rebuilt as a login screen of `com.example.bank`, on Android 14 with *Show passwords* on. Test username `alice`, password `Gt-Probe-4711`. The output below is illustrative and trimmed to the relevant lines. Before the fix (the username field is not marked, and the *Confirm Payment* button sets `NO` inside the protected payment container), non-tool service:

```text
I A11yProbe: connected isAccessibilityTool=false
I A11yProbe: ---- tree of com.example.bank com.example.bank.LoginActivity
I A11yProbe:     android.widget.EditText id=com.example.bank:id/username text="alice" hint="Username" desc="null" password=false editable=true clickable=true
I A11yProbe:     android.widget.Button id=com.example.bank:id/confirm text="Confirm Payment" hint="null" desc="null" password=false editable=false clickable=true
I A11yProbe:     android.widget.Button id=com.example.bank:id/cancel text="Cancel" hint="null" desc="null" password=false editable=false clickable=true
I A11yProbe: TYPE_VIEW_TEXT_CHANGED android.widget.EditText password=false before="alic" text=[alice] from=4 added=1 removed=0
I A11yProbe: TYPE_VIEW_CLICKED android.widget.Button text=[Confirm Payment] desc=null
```

The username is captured keystroke by keystroke and the confirmation button is visible and clickable: the test fails for both. The password, OTP and card fields are missing from the tree and produce no events: they are protected.

The same screen with the password field **not** marked, for comparison: the masked field still shows up, and its events leak length and, on this build, the previous character in `before`:

```text
I A11yProbe:     android.widget.EditText id=com.example.bank:id/password text="•••••••••••••" hint="Password" desc="null" password=true editable=true clickable=true
I A11yProbe: TYPE_VIEW_TEXT_CHANGED android.widget.EditText password=true before="••••••••••••1" text=[•••••••••••••] from=12 added=1 removed=0
```

After the fix (`android:accessibilityDataSensitive="yes"` on the form container, `NO` removed from the button), the non-tool log for the same session contains only the *Cancel* button and the activity's title. With `isAccessibilityTool="true"` all fields reappear, with masked password text: the residual risk that an app falsely claiming to be a tool outside Play still has access.

### GT-0040-3: Secrets in accessibility labels (iOS)

Guler Tech methodology. Platform: iOS. Type: dynamic, manual.

#### Overview

The iOS half of "secrets in accessibility metadata": a label, value or hint that carries something the screen hides or that a bystander should not hear. There is no malicious-service scenario on iOS, so this is a small check, but it is quick and the findings are real for VoiceOver users.

#### Prerequisites

- Xcode's Accessibility Inspector (*Xcode > Open Developer Tool > Accessibility Inspector*), targeting the Simulator or a connected device with the app.
- Optionally, a jailbroken device or a re-signed build with Frida for UIKit apps.

#### Steps

1. In Accessibility Inspector, choose the device and the app, enable the pointer, and hover over each element on the sensitive screens with test data entered and masking toggles switched on. Read the *Label*, *Value*, *Hint* and *Traits* fields.
2. Turn on VoiceOver (or the inspector's audit and speech features) and swipe through the screen; listen for values that are not displayed.
3. For a UIKit app, dump labels and values in one go with Frida:

   ```javascript
   function walk(v, depth) {
     const label = v.accessibilityLabel(), value = v.accessibilityValue();
     if (label !== null || value !== null)
       console.log("  ".repeat(depth) + v.$className + " label=" + label + " value=" + value);
     const subs = v.subviews();
     for (let i = 0; i < subs.count(); i++) walk(subs.objectAtIndex_(i), depth + 1);
   }
   ObjC.schedule(ObjC.mainQueue, () => walk(ObjC.classes.UIApplication.sharedApplication().keyWindow(), 0));
   ```

   SwiftUI elements are not one view each; use the inspector for those.
4. Check secret fields: in the inspector a secure text field reports a secure-text trait and a masked value. A password, PIN or OTP field that does not is a MASWE-0036 finding as well.

#### Observation

Screenshots of the inspector showing the label and value of each sensitive element, and the Frida dump.

#### Evaluation

The test **fails** if a label, value or hint contains a secret or a value the UI deliberately hides (full card number, balance behind a hide toggle, recovery phrase, OTP), or if a secret is entered in a field without secure entry. It **passes** when labels describe elements without carrying their secret content ("Card ending 4242", "Balance hidden").

## Best practices

### MASTG-BEST-0075: Restricting Accessibility Service Access to Sensitive Views

Source: [MASTG-BEST-0075](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0075/). Platform: Android 14 (API level 34) and later.

Mark the views that display or accept sensitive data as accessibility data sensitive, so that services not declared as accessibility tools can neither read them nor act on them (and, from Android 16, cannot inject gestures at them). OWASP's list of where to apply it: login screens (both username and password), permission, settings and in-app confirmation screens such as payment approvals, personal-information forms (national ID, card numbers), 2FA inputs, biometric prompts, and any view showing confidential data.

How, per UI technology:

```xml
<!-- XML: the attribute is an enum (auto | yes | no) -->
<LinearLayout
    android:id="@+id/payment_form"
    android:accessibilityDataSensitive="yes"
    ... >
    <EditText android:id="@+id/card_number" ... />   <!-- inherits -->
    <Button android:id="@+id/confirm" ... />         <!-- inherits; never set "no" here -->
</LinearLayout>
```

```kotlin
// Code, with a guard when minSdk < 34
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
    paymentForm.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
}
```

```kotlin
// Jetpack Compose
OutlinedSecureTextField(
    state = passwordState,
    label = { Text("Password") },
    modifier = Modifier.semantics { isSensitiveData = true }
)
```

OWASP's points on using `filterTouchesWhenObscured`: on Android 14+ it implies sensitivity as long as the view keeps `AUTO`, so apps that already use it against overlays are covered; touch filtering itself only rejects touches flagged as obscured and does not block injected gestures, which is the separate Android 16 policy. Setting `accessibilityDataSensitive` explicitly anyway documents the intent and survives a later change to touch filtering.

Caveats, rephrased from OWASP with our additions:

- **Accessibility.** Services that are not tools lose access to marked views, which can affect users who rely on them. Protect the sensitive views and containers, not entire screens, and test with TalkBack, Switch Access and Voice Access.
- **Password managers and automation apps** lose access too. That is the intended trade-off. Support [Autofill](https://developer.android.com/identity/autofill/autofill-optimize) with `android:autofillHints` (`username`, `password`, `creditCardNumber`, `smsOTPCode`) so password managers keep working without accessibility.
- **Older Android.** On Android 13 and lower the attribute is ignored and there is no platform equivalent. Lean on friction for high-risk actions, overlay protections and server-side fraud controls for those users.
- **Not complete.** Services declaring `isAccessibilityTool="true"` keep full access. Play and Play Protect police that declaration; sideloaded apps may not be checked.

### Secure implementation (Guler Tech)

What we recommend in reports, beyond BEST-0075:

- **Protect the action, not just the data.** Mark the confirmation button (or its container), not only the input fields. A service that cannot read the amount but can press *Confirm* still steals money.
- **PIN pads.** Put any in-app keypad in a sensitive container; check with GT-0040-2 that `TYPE_VIEW_CLICKED` events with digits disappear from the non-tool log. Randomising the key layout does not help against a service that reads the key labels.
- **Labels describe, they do not disclose.** For masked values, set the accessible text to the masked form or to a status ("Balance hidden", "Card ending 4242"). Update `contentDescription` when the user toggles visibility, so the label never shows more than the screen.
- **Bind high-risk actions to something a service cannot do.** A `BiometricPrompt` with `BIOMETRIC_STRONG` and a `CryptoObject` whose key signs the transaction on the server's challenge, so the approval cannot be produced by clicks alone. Server-side, treat "transaction completed seconds after an accessibility-heavy session" as a fraud signal if your telemetry supports it.
- **Optional risk signal.** `AccessibilityManager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)` lists the enabled services; checking `isAccessibilityTool` and the installer of each can feed a risk engine. Do not block users outright on it (legitimate non-tool services exist), and verify on your target SDK that the list is not filtered by package visibility before relying on it.
- **Do not use `importantForAccessibility="no"` or `hideFromAccessibility()` as a security control.** They break screen readers and a malicious service ignores them.
- **`FLAG_SECURE` is complementary, not a substitute.** Keep it for screenshot protection ([MASWE-0038](/mobile/maswe-0038-insufficient-screenshot-protection/)); it does not hide the node tree.

## Rating findings

Rate on three things: **what the exposed view carries or controls** (credentials, OTPs and PINs; transaction confirmation; personal or financial data; low-sensitivity content), **who can get it** (only a malicious accessibility service that is not a tool; any service including tools and TalkBack, as with secrets in labels; any user of an unmasked field), and **the platform window** (Android 14+ where the app could have protected it; Android 13 and lower where it could not).

The attacker position for the main scenario is a malicious app installed on the device **with its accessibility service enabled by the user**. That needs social engineering, several deliberate steps in Settings past a system warning, and on Android 13+ often an extra restricted-settings override. It needs no root and no further interaction once enabled. This is a high bar, and we reflect it by not rating this weakness Critical on its own; it is also a bar that real banking malware campaigns routinely clear, so for L2 apps we do not discount it to Low. MASWE-0040 is an L2 (and EUDIW) control: for an L1 app, report missing accessibility data sensitivity as a Low or Info recommendation unless the app carries L2-class data anyway.

| Rating | Conditions |
|---|---|
| **High** | L2/EUDIW app on Android 14+: credential, PIN or OTP entry, or the confirmation control of a payment, transfer, payee change or identity-wallet presentation, is readable or operable by a non-tool accessibility service (GT-0040-2 or MASTG-TEST-0404 evidence), and the action can be completed with no step a service cannot perform. Also, on any Android version: passwords, PINs or OTPs entered in a field not marked as password (plaintext in every text-changed event), or full card numbers, CVVs, recovery phrases or tokens placed in `contentDescription`, hints or labels. |
| **Medium** | Sensitive personal or financial data (balances, statements, messages, ID numbers) readable by a non-tool service on Android 14+; credential fields unprotected but masked, with leakage limited to length or, where demonstrated, the last-typed character; a sensitive container undermined by a child set to `NO` on a non-critical element; confirmation controls exposed but the action protected by a biometric or out-of-band confirmation a service cannot complete; an in-app PIN pad leaking digits through click events. |
| **Low** | Protection missing on data of limited sensitivity; L1 app with unprotected credential screens; `minSdkVersion` below 34 noted as residual exposure for older devices where the app otherwise protects correctly on 14+; `importantForAccessibility="no"` used as a "security" measure (also report it as an accessibility defect). |
| **Info** | Sensitive views correctly protected; residual access by services declared as accessibility tools; iOS labels that reveal the type of a secret but not its value; recommendations to add Autofill hints or explicit `accessibilityDataSensitive` where only `filterTouchesWhenObscured` provides it. |

Raise a level when the exposure combines with an overlay weakness on the same screen ([MASWE-0039](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/)), when the app displays OTPs or transaction-signing codes on screen for another device, or when the app is a known target class (retail banking, crypto wallets, payment apps). Lower a level when the only proof is static (MASTG-TEST-0403) and you could not reach the screen at runtime, and say so. Never rate on `uiautomator dump` alone: it shows metadata, not what a malicious service can access. In the report give the screen, the view (resource ID or composable), the device, Android version and patch level, the probe log lines, the setting of *Show passwords*, and the fix (which view or container to mark, which label to change).

## References

- OWASP MASWE: [MASWE-0040: Sensitive Data Leaked via Accessibility Services](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0040/); related [MASWE-0036](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0036/), [MASWE-0037](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0037/), [MASWE-0038](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0038/), [MASWE-0039](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0039/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PLATFORM-3](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/), [MASVS-STORAGE-2](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0143: Accessibility Data Sensitivity](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0143/), [MASTG-KNOW-0022: Overlay Attacks](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0022/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0403](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0403/), [MASTG-TEST-0404](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0404/), [MASTG-TEST-0316](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0316/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0159](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0159/MASTG-DEMO-0159/), [MASTG-DEMO-0160](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0160/MASTG-DEMO-0160/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0075](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0075/), [MASTG-BEST-0040](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0040/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0007](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0007/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0177](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0177/), [MASTG-TECH-0178](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0178/) (CC BY-SA 4.0)
- OWASP MASTG tools: [Frida (MASTG-TOOL-0001)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/), [adb (MASTG-TOOL-0004)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [Maestro (MASTG-TOOL-0154)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0154/) (CC BY-SA 4.0)
- Android Developers: [Create your own accessibility service](https://developer.android.com/guide/topics/ui/accessibility/service), [`AccessibilityService`](https://developer.android.com/reference/android/accessibilityservice/AccessibilityService), [`AccessibilityServiceInfo`](https://developer.android.com/reference/android/accessibilityservice/AccessibilityServiceInfo) (incl. [`android:isAccessibilityTool`](https://developer.android.com/reference/android/accessibilityservice/AccessibilityServiceInfo#attr_android:isAccessibilityTool)), [`AccessibilityEvent`](https://developer.android.com/reference/android/view/accessibility/AccessibilityEvent), [`AccessibilityNodeInfo`](https://developer.android.com/reference/android/view/accessibility/AccessibilityNodeInfo), [`View.setAccessibilityDataSensitive`](https://developer.android.com/reference/android/view/View#setAccessibilityDataSensitive%28int%29), [`android:accessibilityDataSensitive`](https://developer.android.com/reference/android/R.attr#accessibilityDataSensitive), [Tapjacking](https://developer.android.com/privacy-and-security/risks/tapjacking), [Compose semantics reference](https://developer.android.com/reference/kotlin/androidx/compose/ui/semantics/package-summary), [Optimise your app for autofill](https://developer.android.com/identity/autofill/autofill-optimize)
- Android Developers Blog: [Enhancing Android security: Stop malware from snooping on your app data](https://android-developers.googleblog.com/2025/12/enhancing-android-security-stop-malware.html) (December 2025)
- Google Play Console Help: [Use of the AccessibilityService API](https://support.google.com/googleplay/android-developer/answer/10964491)
- AOSP source (frameworks/base): `View.java` (`includeForAccessibility`, `calculateAccessibilityDataSensitive`), `TextView.java` (`getTextForAccessibility`, `ChangeWatcher`), `PasswordTransformationMethod.java`, `core/res/res/values/attrs.xml` (`accessibilityDataSensitive` enum), at [android.googlesource.com/platform/frameworks/base](https://android.googlesource.com/platform/frameworks/base/)
- Apple: [`UIAccessibility`](https://developer.apple.com/documentation/uikit/uiaccessibility), [`isSecureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry), [`SecureField`](https://developer.apple.com/documentation/swiftui/securefield), [Accessibility Inspector](https://developer.apple.com/documentation/accessibility/accessibility-inspector)
- Y. Fratantonio, C. Qian, S. Chung, W. Lee: *Cloak and Dagger: From Two Permissions to Complete Control of the UI Feedback Loop*, IEEE S&P 2017, [cloak-and-dagger.org](https://cloak-and-dagger.org/)
- CWE: [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-359](https://cwe.mitre.org/data/definitions/359.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
