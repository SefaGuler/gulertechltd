---
title: "App Vulnerable to Overlay Attacks (MASWE-0039)"
date: 2026-11-09 21:10:00 +0000
subcategory: platform
summary: "Testing Android apps for tapjacking and overlays: touch filtering, obscured-touch flags, setHideOverlayWindows, Android 12 blocking and an attacker app."
refs: [MASWE-0039, MASVS-PLATFORM-3, MASVS-CODE-1, CWE-1021]
tags: [android, ios, masvs-platform, tapjacking, overlay-attacks, ui-redressing]
---

This note is part of our [MASVS-PLATFORM guide](/mobile/masvs-platform-platform-interaction-guide/) and covers OWASP [MASWE-0039](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0039/): apps whose sensitive screens can be covered, fully or partly, by a window that another app controls. The user sees the attacker's content and taps it, and the tap lands on your "Confirm payment" button underneath; or the user types a password into what looks like your login screen and is in fact the attacker's window. It is the mobile form of clickjacking, and on Android it needs nothing more exotic than an app the user has allowed to "display over other apps". Below you will find how overlays work on Android (the `SYSTEM_ALERT_WINDOW` permission and how it is granted, `TYPE_APPLICATION_OVERLAY`, toast overlays, Android 12's untrusted-touch blocking and its 0.8 opacity rule), what each app-side defence does and does not cover (`filterTouchesWhenObscured`, the two obscured-touch flags, `setHideOverlayWindows`, Jetpack Compose), why iOS is largely out of scope, the OWASP static test with its three demos, two Guler Tech dynamic tests built around a small attacker app, secure patterns, and how to rate what you find.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Overlay Attacks (MASTG-KNOW-0022)](#android-overlay-attacks-mastg-know-0022)
    - [Attack variants: tapjacking, input capture and cloak and dagger](#attack-variants-tapjacking-input-capture-and-cloak-and-dagger)
    - [Display over other apps: the overlay permission and how it is granted](#display-over-other-apps-the-overlay-permission-and-how-it-is-granted)
    - [The application overlay window type (Android 8.0)](#the-application-overlay-window-type-android-80)
    - [Toast-based overlays](#toast-based-overlays)
    - [Untrusted-touch blocking (Android 12)](#untrusted-touch-blocking-android-12)
    - [Touch filtering on views](#touch-filtering-on-views)
    - [Obscured versus partially obscured touches](#obscured-versus-partially-obscured-touches)
    - [Hiding overlays for a window (Android 12)](#hiding-overlays-for-a-window-android-12)
    - [Jetpack Compose](#jetpack-compose)
    - [What none of these controls stop](#what-none-of-these-controls-stop)
  - [iOS: why classic overlay attacks do not apply (supplementary)](#ios-why-classic-overlay-attacks-do-not-apply-supplementary)
- [Tests](#tests)
  - [MASTG-TEST-0340: References to Overlay Attack Protections (Android)](#mastg-test-0340-references-to-overlay-attack-protections-android)
  - [GT-0039-1: Proving tapjacking with an attacker overlay app (Android)](#gt-0039-1-proving-tapjacking-with-an-attacker-overlay-app-android)
  - [GT-0039-2: Runtime inventory of overlay protections per screen (Android)](#gt-0039-2-runtime-inventory-of-overlay-protections-per-screen-android)
- [Best practices](#best-practices)
  - [MASTG-BEST-0040: Preventing Overlay Attacks](#mastg-best-0040-preventing-overlay-attacks)
  - [MASTG-BEST-0075: Restricting Accessibility Service Access to Sensitive Views](#mastg-best-0075-restricting-accessibility-service-access-to-sensitive-views)
  - [Secure patterns for Android (Guler Tech)](#secure-patterns-for-android-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0039 applies when an app does not defend its sensitive screens against being obscured by windows from other apps. The OWASP requirement is *"The app protects its sensitive screens against overlay attacks."* It maps to MASVS-PLATFORM-3 ("The app uses the user interface securely"), to MASVS-CODE-1 ("The app requires an up-to-date platform version", because most of the strong protections are platform features that only exist on recent Android versions), to MASVS v1 MSTG-PLATFORM-9, and to [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) (Improper Restriction of Rendered UI Layers or Frames). Android's own risk catalogue lists the problem as [tapjacking](https://developer.android.com/privacy-and-security/risks/tapjacking). The weakness is tagged for profiles **L2 and EUDIW only**: it is a hardening expectation for apps that handle high-value actions (banking, payments, identity wallets, approval of logins), not a baseline for every app.

OWASP describes the threat as MAS-THREAT-0039, *"Attackers can hijack user interactions with the app"*, reached through MAS-ATTACK-0036, *"Displaying overlays or tampering with the UI to alter what the user sees while approving an action"*. The attacker position is always the same: **a malicious app already installed on the victim's device, with the overlay permission granted by the user, and a user who interacts with the screen**. No root, no network position, no physical access; but also no remote, zero-click exploitation. That combination is why this weakness rarely rates above Medium on its own (see [Rating findings](#rating-findings)).

**The MASWE-0039 page has no OWASP tests of its own.** The one test on the topic, [MASTG-TEST-0340](#mastg-test-0340-references-to-overlay-attack-protections-android) (References to Overlay Attack Protections) with demos MASTG-DEMO-0103, 0104 and 0105, is currently filed by OWASP under [MASWE-0036](/mobile/maswe-0036-sensitive-data-exposed-via-ui/) (sensitive data exposed via the UI). We document it in full here, because overlay protection is what it tests. We add two dynamic tests of our own, because a list of API references cannot tell you whether a real overlay can make the user approve something.

It helps to separate the attack variants from the start, because each is stopped by something different:

| Variant | What the attacker's window does | Who receives the touch | What can stop it |
|---|---|---|---|
| Full-occlusion tapjacking | Covers the control the user taps, lets touches pass through (`FLAG_NOT_TOUCHABLE`) | Your app, with `FLAG_WINDOW_IS_OBSCURED` set | Platform blocking above 0.8 opacity (Android 12+), `filterTouchesWhenObscured`, `setHideOverlayWindows` |
| Partial-occlusion tapjacking | Covers or rewrites the *context* (amount, payee, permission text) but leaves the button visible | Your app, with `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` set | Only an app-side check of the partial flag, or `setHideOverlayWindows` |
| Input capture | Draws a fake copy of your screen and keeps the touches (touchable window) | The attacker | Only `setHideOverlayWindows` (and only while your window is visible) |
| Activity or WebView phishing | Launches its own full-screen activity when your app comes to the foreground | The attacker | Nothing in your app; Android's background-activity-start limits and Play Protect |
| Cloak and dagger | Accessibility service plus overlay: reads your screen, draws over it, injects taps | Your app or the attacker | Mostly out of scope here: see [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/) |

## Modes of Introduction

**No touch filtering on sensitive controls.** The confirm, approve, grant and sign buttons accept touches whatever is drawn on top of them. Neither `android:filterTouchesWhenObscured="true"` nor `setFilterTouchesWhenObscured(true)` is set on the control or on any parent, and no `onFilterTouchEventForSecurity` override or obscured-flag check exists.

**Only the full-occlusion case handled.** The app filters touches with `filterTouchesWhenObscured`, which drops only events carrying `FLAG_WINDOW_IS_OBSCURED`. An overlay that covers the transaction details but leaves the button clear produces `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` instead, and the tap goes through.

**External overlays not hidden.** On Android 12 and later the app could call `Window.setHideOverlayWindows(true)` (with the `HIDE_OVERLAY_WINDOWS` permission) and make every third-party overlay disappear while its sensitive screen is visible, but does not.

**Protection on the wrong window or the wrong view.** Common in practice:

- the flag is set on the activity's layout, but the confirmation is shown in a `Dialog`, `BottomSheetDialog`, `PopupWindow`, Compose `Dialog` or `Popup`, each of which is a separate window with its own view tree;
- `setHideOverlayWindows(true)` is called on the main activity, but the step-up or approval screen is a different activity, or a third-party SDK's activity (payment, 3-D Secure, identity verification);
- in Jetpack Compose, the flag is set on `LocalView.current`, which (in the current androidx source) does not filter touches for the composition; see [Jetpack Compose](#jetpack-compose).

**Old platform versions supported without compensation.** A `minSdkVersion` below 31 means some users run versions without `setHideOverlayWindows`; below 29 without the partial-occlusion flag; below 26 without the `TYPE_APPLICATION_OVERLAY` restrictions and with the toast overlay bug. That is what the MASVS-CODE-1 mapping is about: an app that relies on a platform protection should either require the platform version that has it or use a fallback on older ones.

**Sensitive screens with a single-tap commit.** Even with protections, a design in which one tap irreversibly sends money or approves a login is the one overlay attacks target. Critical approvals benefit from a second, out-of-band confirmation (see [MASWE-0025](/mobile/maswe-0025-lack-of-non-repudiation/) for transaction signing and protected confirmation).

## Impact

- **Financial loss.** The user believes they are dismissing a dialog or claiming a reward and in fact confirms a transfer, adds a payee, raises a limit or approves a card payment.
- **Authentication or authorisation bypass.** The user is tricked into approving a login on a new device, a push-MFA prompt, a device-binding step, an OAuth consent, or an in-app permission-like prompt that grants the attacker's account access.
- **Compromise of sensitive data.** An input-capture overlay that mimics the login or PIN screen collects credentials, one-time codes and card numbers directly. This is how most Android banking malware families have operated for a decade (MASTG names BankBot, MysteryBot and MazorBot, among others).
- **Security settings changed.** Disabling app lock, turning off biometric confirmation, approving "trust this device".

## Mitigations

- **Hide external overlays on sensitive screens** (Android 12+): declare `HIDE_OVERLAY_WINDOWS` and call `window.setHideOverlayWindows(true)` on every window that shows sensitive input or approvals.
- **Filter touches on sensitive views** on every Android version: `android:filterTouchesWhenObscured="true"` on the control or its container, or `setFilterTouchesWhenObscured(true)` in code.
- **Handle partial occlusion** on the controls where context matters: reject or re-confirm events carrying `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` (API 29+), through an `onFilterTouchEventForSecurity` override.
- **Cover every window**: dialogs, bottom sheets, popups and Compose dialogs need their own protection; apply hiding to every sensitive activity, including step-up and approval flows.
- **Use trusted confirmation for the most critical actions**, so that an overlay cannot forge consent even if it gets a tap: out-of-band approval on another device, transaction signing with user-authenticated keys, or protected confirmation where available ([MASWE-0025](/mobile/maswe-0025-lack-of-non-repudiation/)).
- **Raise the floor**: a `minSdkVersion` that excludes versions without the protections you rely on, or a documented fallback for them.

## Knowledge

OWASP links one Knowledge page to this topic, MASTG-KNOW-0022 (Overlay Attacks), which is short. We extend it with the platform behaviour you need to predict what a given overlay will do on a given Android version, and add a short supplementary section on iOS. The accessibility side (services that read and act on your screen, `accessibilityDataSensitive`) belongs to [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/); we only mention it where it interacts with overlays.

### Android: Overlay Attacks (MASTG-KNOW-0022)

Source: [MASTG-KNOW-0022](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0022/), extended with the Android Developers documentation, the Android 15 CDD and the AOSP sources (`InputDispatcher`, `WindowManagerService`, `DisplayPolicy`, `WindowState`, `View`) where the documentation is silent.

Android lets an app with the right permission add windows that float above other apps. Those windows are legitimate infrastructure for chat heads, screen dimmers, floating video, call screening and accessibility helpers, and they are what overlay attacks abuse. The question for every attack is the same: when the user's finger touches the glass at a point where the attacker's window and your window overlap, which window receives the event, and what does the receiving window learn about the other one?

#### Attack variants: tapjacking, input capture and cloak and dagger

**Tapjacking** (the term Android uses, after web clickjacking) makes the user tap one thing while the touch lands on another. The attacker's window sets `WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE`, so it is drawn but never receives touches; the system routes the touch to the next window underneath, which is your app. Google distinguishes two forms:

- **Full occlusion**: the attacker's window covers the point being touched (typically your button), showing something harmless in its place.
- **Partial occlusion**: the touched point is clear, but other parts of your screen are covered. The button is genuine; the text that tells the user what the button does (amount, recipient, scope of a permission) is the attacker's.

**Input capture** (overlay phishing) is the opposite approach. The attacker's window is touchable and draws a convincing copy of your login, PIN or card-entry screen. The user types into the attacker's window; your app never sees the touches at all. Touch filtering in your app is irrelevant to this variant, because your views never receive the events it would filter.

**Activity-based overlays** do not use overlay windows at all: the malware detects that your app is in the foreground (historically through accessibility events or usage stats) and launches its own activity or WebView with a pixel-perfect copy of your login screen. To Android this is just another app in front of yours. Your activity is paused and nothing in it can react, which is why we treat it as residual risk, not as an app weakness. A related variant, the *activity sandwich*, starts one of your exported activities and then covers it partially with the attacker's own; not exporting activities that do not need it ([MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/)) removes that option.

**Cloak and dagger** ([Fratantonio et al., IEEE S&P 2017](https://cloak-and-dagger.org/)) combined `SYSTEM_ALERT_WINDOW` with an accessibility service: the overlay hides what is happening while the accessibility service reads the screen, clicks buttons and grants itself further permissions; the paper also showed an invisible keyboard overlay that captured keystrokes. The authors reported that, at the time, apps installed from Google Play received `SYSTEM_ALERT_WINDOW` without the user being asked, which made the combination practical. MASTG says the attacks affected "apps targeting Android 5.0 to 7.1"; more precisely, they worked on devices running those versions, regardless of the victim's `targetSdkVersion`. Today the accessibility half is the dangerous part, and it is covered in [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/). One point matters for this note: accessibility overlays (`TYPE_ACCESSIBILITY_OVERLAY`) are trusted windows, so they bypass every overlay defence described below (see [What none of these controls stop](#what-none-of-these-controls-stop)).

#### Display over other apps: the overlay permission and how it is granted

The [`SYSTEM_ALERT_WINDOW`](https://developer.android.com/reference/android/Manifest.permission#SYSTEM_ALERT_WINDOW) permission "allows an app to create windows using the type `TYPE_APPLICATION_OVERLAY`, shown on top of all other apps". Its protection level is `signature|setup|appop|installer|pre23|development`: for an ordinary third-party app it is an **app-op**, a special access the user switches on, not a runtime permission dialog.

| Platform version | How a third-party app gets it |
|---|---|
| Android 5.1 and lower (API 22 and lower) | Granted at install time, like any normal permission |
| Android 6.0+ (API 23) | The app declares it, then sends the user to the settings screen with `Settings.ACTION_MANAGE_OVERLAY_PERMISSION`; it checks the result with `Settings.canDrawOverlays()`. The screen is usually *Settings > Apps > Special app access > Display over other apps* (names vary by manufacturer) |
| Android 10+ (API 29) | Low-RAM (Android Go) devices do not let apps hold it. Holding it also exempts an app from some of Android 10's background-activity-start restrictions, which matters for activity-based overlays |
| Android 11+ (API 30) | `ACTION_MANAGE_OVERLAY_PERMISSION` always opens the top-level list; the `package:` URI is ignored, so the user must find the app themselves. Apps holding the call-screening role, or capturing the screen with `MediaProjection`, get it automatically on request |
| Android 13+ (API 33) | *Restricted settings*: for apps installed from a local file (sideloaded through a package installer that does not use the session-based install API), the user cannot enable accessibility or notification-listener access until they explicitly *Allow restricted settings* in the app's info screen |
| Android 15+ (API 35) | The [Android 15 CDD](https://source.android.com/docs/compatibility/15/android-15-cdd) (section 9.8, requirement 9.8/H-0-1) extends restricted settings for handheld devices to "Display over other apps (`AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW`)", together with device admin, usage access and the SMS and dialer roles |

So the realistic attacker paths are: an app from Google Play (or another store) that gives the user a plausible reason to enable "display over other apps" (a floating widget, a screen filter, a "call assistant"), or a sideloaded app that walks the user through *Allow restricted settings* first, as current banking malware does with step-by-step instructions. Google Play's specific restrictions concentrate on the AccessibilityService API rather than on overlays; an overlay request is a policy-review and user-persuasion problem for the attacker, not a technical barrier. Either way the user has to take several deliberate steps, which is part of how you rate a finding.

For testing you skip all of that: adb can set the app-op directly.

```bash
adb shell appops set com.example.overlaytest SYSTEM_ALERT_WINDOW allow
adb shell appops get com.example.overlaytest SYSTEM_ALERT_WINDOW
# SYSTEM_ALERT_WINDOW: allow
adb shell appops query-op SYSTEM_ALERT_WINDOW allow        # which packages hold it on this device
adb shell appops set com.example.overlaytest SYSTEM_ALERT_WINDOW default   # revert
```

Note that `pm grant` does not work for this permission: it is an app-op, not a runtime permission.

#### The application overlay window type (Android 8.0)

Before Android 8.0 an overlay app could pick among several system window types (`TYPE_PHONE`, `TYPE_PRIORITY_PHONE`, `TYPE_SYSTEM_ALERT`, `TYPE_SYSTEM_OVERLAY`, `TYPE_SYSTEM_ERROR`), some of which ranked above the status bar or the keyboard. [Android 8.0](https://developer.android.com/about/versions/oreo/android-8.0-changes#all-aw) introduced [`TYPE_APPLICATION_OVERLAY`](https://developer.android.com/reference/android/view/WindowManager.LayoutParams#TYPE_APPLICATION_OVERLAY) (value 2038) and changed the rules:

- Apps that target API 26 or higher **must** use `TYPE_APPLICATION_OVERLAY` for overlays; the old types fail for them.
- On Android 8.0+ devices, windows of the old types from older apps always appear **beneath** `TYPE_APPLICATION_OVERLAY` windows.
- `TYPE_APPLICATION_OVERLAY` windows always appear under critical system windows such as the status bar and the input method. This is what killed the Cloak and Dagger invisible-keyboard trick: an overlay can no longer sit on top of the keyboard.
- The system may move or resize these windows, and the user can block an app's overlays from the notification shade, where Android shows an ongoing "displaying over other apps" notification.

The legacy MASTG test concluded that this "ensures that no overlay attacks may occur" on that version. That is not right: `TYPE_APPLICATION_OVERLAY` still covers every normal app window, which is all tapjacking needs.

#### Toast-based overlays

Toasts are windows the system shows on behalf of an app, and for years they were a permission-free overlay:

- **Toast Overlay (CVE-2017-0752)**: [Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/unit42-android-toast-overlay-attack-cloak-and-dagger-with-no-permissions/) showed that a custom `Toast` with a full-screen view, re-shown in a loop, gave cloak-and-dagger-style overlays without `SYSTEM_ALERT_WINDOW`. It affected Android versions before 8.0 and was fixed in the September 2017 security bulletin.
- **Custom background toasts**: on Android 10 and lower, apps could show custom-view toasts (`Toast.setView()`) from the background. For apps targeting Android 11 (API 30), the system blocks background custom toasts and `setView()` is deprecated.
- **Toast burst**: queuing many toasts while in the foreground so they keep appearing after the app goes to the background. Google's tapjacking page states that background toasts and toast burst are fully mitigated as of Android 12.

Toasts matter today mainly for old devices in your `minSdkVersion` range. On current versions a custom toast can only be shown while its app is in the foreground, and `setHideOverlayWindows` hides toast windows from app processes along with alert windows.

#### Untrusted-touch blocking (Android 12)

Android 12 introduced the first protection that applies to every app without any code change. Per the [Android 12 behaviour changes](https://developer.android.com/about/versions/12/behavior-changes-all#untrusted-touch-events), the system "blocks touches that pass through certain windows". Affected are windows that let touches pass through with `FLAG_NOT_TOUCHABLE`: overlays using `SYSTEM_ALERT_WINDOW`, and activity windows from another app. Pass-through touches are still allowed for:

- interactions within your own app (same UID);
- trusted windows: accessibility windows, input method windows, assistant windows (but **not** `TYPE_APPLICATION_OVERLAY`);
- invisible windows (root view `GONE` or `INVISIBLE`) and completely transparent windows (`LayoutParams.alpha` of 0.0);
- **sufficiently translucent system alert windows**: a set of alert windows whose combined opacity is at most the system's *maximum obscuring opacity for touches*, which is **0.8** by default.

How the input system implements that, from AOSP `InputDispatcher.cpp`:

- For each window above the touched one, at the touch point, from a **different UID**, not trusted, on the same display, the dispatcher looks at its *occlusion mode*. Alert-window types (and windows in an animation) use opacity; everything else blocks outright.
- Opacities are combined per UID as `1 - (1 - a) * (1 - b)`. A touch is dropped if any one UID's combined opacity is **greater than** 0.8. So one window at 0.8 passes; two stacked windows at 0.8 from the same app (0.96) are blocked; windows from two different apps are not combined.
- The opacity is the **window's** `WindowManager.LayoutParams.alpha`, not the colour of what it draws. A window with alpha 1.0 and a 50 % translucent background counts as fully opaque.

A detail the documentation does not mention: since a March 2022 platform change (AOSP commit `a451d5bae2e2`, "Cap alpha to max if SAW + FLAG_NOT_TOUCHABLE", present in releases after Android 12), `WindowManager` **automatically lowers the alpha** of an alert window that has `FLAG_NOT_TOUCHABLE` and an alpha above the maximum, to exactly 0.8, so that touches keep passing through. The attacker does not even have to choose the opacity. The practical consequence: on current Android, a single pass-through overlay at 80 % opacity is always allowed, and it is quite enough to hide or rewrite your screen convincingly. Android 12's blocking stops opaque full-screen tapjacking; it does not make your sensitive screens safe.

When a touch is blocked, logcat shows it. The Android 12 documentation gives the message as `Untrusted touch due to occlusion by PACKAGE_NAME`; current AOSP builds log, from `InputDispatcher`:

```text
Untrusted touch due to occlusion by com.example.overlaytest/10234 (obscuring opacity = 0.96, maximum allowed = 0.80)
Dropping untrusted touch event due to com.example.overlaytest/10234
```

and, when the alpha is capped at window creation:

```text
App com.example.overlaytest has a system alert window (type = 2038) with FLAG_NOT_TOUCHABLE and LayoutParams.alpha = 1.00 > 0.80, setting alpha to 0.80 to let touches pass through (if this is isn't desirable, remove flag FLAG_NOT_TOUCHABLE).
```

The threshold is the hidden global setting `maximum_obscuring_opacity_for_touch` (`adb shell settings get global maximum_obscuring_opacity_for_touch` prints `null` when the default applies). Android 12 also documented `adb shell am compat disable BLOCK_UNTRUSTED_TOUCHES <package>` to turn blocking off for one app while testing; you should not need it, and you should check that a test device has not been left with blocking disabled.

#### Touch filtering on views

Every `View` passes each incoming touch through [`onFilterTouchEventForSecurity(MotionEvent)`](https://developer.android.com/reference/android/view/View#onFilterTouchEventForSecurity%28android.view.MotionEvent%29) before handling it; `ViewGroup.dispatchTouchEvent` does the same before dispatching to children. The default implementation in AOSP is short:

```java
public boolean onFilterTouchEventForSecurity(MotionEvent event) {
    if ((mViewFlags & FILTER_TOUCHES_WHEN_OBSCURED) != 0
            && (event.getFlags() & MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0) {
        return false;   // window is obscured: drop this touch
    }
    return true;
}
```

The flag is set with [`android:filterTouchesWhenObscured="true"`](https://developer.android.com/reference/android/view/View#attr_android:filterTouchesWhenObscured) in a layout (or in a style applied to the view) or [`setFilterTouchesWhenObscured(true)`](https://developer.android.com/reference/android/view/View#setFilterTouchesWhenObscured%28boolean%29) in code (the Kotlin property `filterTouchesWhenObscured = true`). Both exist since API 9. Things to know:

- **Set on a `ViewGroup`, it protects the whole subtree**, because the group drops the event before any child sees it. Setting it on the root of a confirmation layout, or on the activity's content view, protects everything in that window.
- **It only looks at `FLAG_WINDOW_IS_OBSCURED`**, the full-occlusion flag. Partial occlusion passes. To handle that you override `onFilterTouchEventForSecurity` yourself.
- **It is per window.** Dialogs, popups and bottom sheets are other windows.
- **Overrides must call `super`** or reimplement the flag check; an override that only adds logging and returns `true` turns filtering off for that view.
- **Benign overlays trigger it too.** Screen-dimmer and blue-light-filter apps draw full-screen pass-through overlays, so their users find protected buttons "dead". That is the usual reason teams remove the flag; the answer is a clear message to the user (see the [secure patterns](#secure-patterns-for-android-guler-tech)), not removing protection. System features such as Night Light are trusted and do not set the flag.
- Since Android 14, a view with `filterTouchesWhenObscured` and the default `ACCESSIBILITY_DATA_SENSITIVE_AUTO` is also treated as *accessibility data sensitive* (MASTG-KNOW-0143); see [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/).

#### Obscured versus partially obscured touches

The input dispatcher marks each touch it delivers with what lies above the receiving window:

| Flag | Value | Since | Set when |
|---|---|---|---|
| [`MotionEvent.FLAG_WINDOW_IS_OBSCURED`](https://developer.android.com/reference/android/view/MotionEvent#FLAG_WINDOW_IS_OBSCURED) | `0x1` | API 9 | Another visible window covers the receiving window **at the touched location**, and the event passed through it |
| [`MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED`](https://developer.android.com/reference/android/view/MotionEvent#FLAG_WINDOW_IS_PARTIALLY_OBSCURED) | `0x2` | API 29 | Another visible window covers part of the receiving window, but **not** the touched location |

"Another window" excludes windows from the same UID, trusted overlays (system bars, IME, accessibility overlays), windows on other displays, and windows that are both fully transparent and not touchable. The values matter when you read decompiled code: jadx inlines the constants, so `(event.getFlags() & 1) != 0` is the full-occlusion check and `& 2` the partial one. Partial occlusion has no default protection anywhere in the platform; Google's own guidance says you mitigate it "by manually ignoring touch events that have the `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` flag", and warns that this can interfere with benign apps. In practice, apply it only to the few controls where the surrounding text is what the user consents to.

#### Hiding overlays for a window (Android 12)

[`Window.setHideOverlayWindows(true)`](https://developer.android.com/reference/android/view/Window#setHideOverlayWindows%28boolean%29) (API 31) "prevents non-system overlay windows from being drawn on top of this window". It requires the [`HIDE_OVERLAY_WINDOWS`](https://developer.android.com/reference/android/Manifest.permission#HIDE_OVERLAY_WINDOWS) permission, which is declared in the platform manifest with `protectionLevel="normal"`: any app that lists it in its manifest gets it at install, with no prompt. From the AOSP sources:

- The method throws `SecurityException("Permission denial: setHideOverlayWindows: HIDE_OVERLAY_WINDOWS")` if the permission is missing, so in a working app you will see both, or a crash.
- It sets the private window flag `SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS` (shown in `dumpsys window` as `pfl=… HIDE_NON_SYSTEM_OVERLAY_WINDOWS`).
- While **any** window with that flag is visible, `WindowManagerService` hides every window from an app process of an alert-window type (`TYPE_APPLICATION_OVERLAY` and the legacy types) or `TYPE_TOAST`. Windows of system components and privileged system overlays are not hidden.
- Because the hiding is tied to the flagged window being visible, a dialog shown on top of a flagged activity is covered too; a separate activity without the flag is not.
- What depends on the Android version is the **device**: the call exists from API 31. `targetSdkVersion` does not matter beyond compiling against API 31 or higher. On older devices, guard the call with `Build.VERSION.SDK_INT >= Build.VERSION_CODES.S` and rely on touch filtering.

This is the strongest app-side control: the attacker's window is simply not there, so full occlusion, partial occlusion and input capture over your screen all fail. It does not affect accessibility overlays, the keyboard, or an attacker's activity in front of yours.

#### Jetpack Compose

Compose has no `filterTouchesWhenObscured` modifier, and a composable is not a `View`, so there is nothing to set the flag on directly. Two approaches work:

1. **Filter at a host `View`.** Every composition lives inside a `ComposeView` (created for you by `setContent`) inside the activity's content `FrameLayout`. Both are ordinary `ViewGroup`s whose `dispatchTouchEvent` applies `onFilterTouchEventForSecurity`, so setting `filterTouchesWhenObscured = true` on `findViewById<ViewGroup>(android.R.id.content)` or on the `ComposeView` filters every touch for the composition. Be careful with `LocalView.current`: it returns the internal `AndroidComposeView`, whose `dispatchTouchEvent` (in the current androidx source) does not call `onFilterTouchEventForSecurity`. Setting the flag there still makes the view accessibility-data-sensitive on Android 14+, which is what Google's December 2025 blog example is about, but in our reading of the source it does not drop obscured touches. Verify with [GT-0039-1](#gt-0039-1-proving-tapjacking-with-an-attacker-overlay-app-android) whichever way the app does it.
2. **Inspect the `MotionEvent` per composable.** [`Modifier.pointerInteropFilter`](https://developer.android.com/reference/kotlin/androidx/compose/ui/input/pointer/package-summary) hands you the original `MotionEvent` (only offset to local coordinates, so its flags are intact) during the initial pass. Returning `true` for an obscured `ACTION_DOWN` consumes the gesture before the `Button`'s own click handling sees it. It was marked `@ExperimentalComposeUiApi` in older Compose UI releases. This is the only way to handle partial occlusion on one composable without affecting the rest of the screen.

Compose `Dialog`, `Popup`, dropdown menus and modal bottom sheets render in their own windows, with their own `ComposeView`; protection on the activity's content view does not reach them, while `setHideOverlayWindows` on the activity window does.

#### What none of these controls stop

Be explicit about this in reports, so that a client does not believe a flag makes them immune:

- **Accessibility overlays and injected gestures.** `TYPE_ACCESSIBILITY_OVERLAY` is a trusted overlay type in AOSP's `InputMonitor`, so it does not set the obscured flags, is not blocked as untrusted, and is not hidden by `setHideOverlayWindows`. An enabled malicious accessibility service can also click your buttons directly. That is MASWE-0040's territory (`accessibilityDataSensitive`, Android 14 and 16 protections).
- **A malicious input method.** The keyboard is a trusted window above your app; a malicious IME is a keylogger, not an overlay.
- **Activity-based phishing.** The attacker's activity in front of yours; your app is paused.
- **Social engineering without overlays.** A fake "your bank" app, or a phone call talking the user through a transfer.
- **Platform bugs** on unpatched devices (as with Toast Overlay before 8.0).

Some RASP products also flag installed apps holding `SYSTEM_ALERT_WINDOW` or accessibility access (which needs package visibility, restricted by Play's `QUERY_ALL_PACKAGES` policy). That is malware detection ([MASWE-0055](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0055/)), a useful signal but not a substitute for the controls above.

### iOS: why classic overlay attacks do not apply (supplementary)

OWASP lists iOS as a platform for MASWE-0039, but there is no iOS knowledge page or test, and for good reason: **iOS has no equivalent of `SYSTEM_ALERT_WINDOW`.** A third-party app can only draw inside its own windows, and only while it is in the foreground (or in its own extension's sandboxed UI). There is no API to place a window above another app, no pass-through touches between apps, and no way for one app to learn where another is on screen. The system's own UI (alerts, notification banners, the keyboard) is drawn by system processes. Classic tapjacking and input-capture overlays therefore do not exist on iOS, and you should not report "missing overlay protection" for an iOS app.

What remains is in-app UI redress and a couple of edge cases, worth a brief look on L2 apps:

- **Content inside your own app.** A `WKWebView` that loads third-party pages (partners, ads, help centres) can host web clickjacking against whatever the page frames, and a third-party SDK view (ads, chat widgets) can be laid over your own screens. These are web and content-trust problems: see [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/) and make sure your own web origins send `Content-Security-Policy: frame-ancestors` (or `X-Frame-Options`) so they cannot be framed by others.
- **Picture in Picture.** Another app's PiP window ([`AVPictureInPictureController`](https://developer.apple.com/documentation/avkit/avpictureinpicturecontroller); since iOS 15 its content can be app-rendered frames through a sample-buffer content source) floats above your app. It is a system-managed window that the user can move, resize and stash; touches on it go to the PiP controls rather than through to your app, so it can obscure or show misleading content but cannot make your app receive a tap on a hidden control. Treat it as at most an informational observation for screens where a covered amount could mislead.
- **Custom keyboards** run in your text fields, not over them; they are an app-extension and data-leak question ([MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/)), not an overlay one.

## Tests

OWASP has one test on this topic, MASTG-TEST-0340, which replaces the legacy (MASTG v1) test [MASTG-TEST-0035](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0035/) "Testing for Overlay Attacks" (`covered_by: [MASTG-TEST-0340]`). The legacy test had a dynamic half that relied on old proof-of-concept APKs for Android 7.0 and lower; the new one is static only. We restore the dynamic part for current Android versions as [GT-0039-1](#gt-0039-1-proving-tapjacking-with-an-attacker-overlay-app-android), and add [GT-0039-2](#gt-0039-2-runtime-inventory-of-overlay-protections-per-screen-android) to tie static hits to the screens that actually show at runtime. There are no iOS tests (see [above](#ios-why-classic-overlay-attacks-do-not-apply-supplementary)).

Before you start any of them, list the app's **sensitive screens**: login and PIN entry, payment and transfer confirmation, adding a payee, approving a login or MFA push, device binding, consent and authorisation prompts, changes to security settings, and anything that signs or submits on one tap. Everything below is evaluated per screen, not per app.

### MASTG-TEST-0340: References to Overlay Attack Protections (Android)

Source: [MASTG-TEST-0340](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0340/). Platform: Android. Type: static (code and manifest).

OWASP currently files this test under MASWE-0036; we document it here because what it tests is overlay protection, which is MASWE-0039's subject. The [MASWE-0036 note](/mobile/maswe-0036-sensitive-data-exposed-via-ui/) links here.

#### Overview

The test looks for the APIs and attributes an app uses to defend against overlays, and checks whether the sensitive screens are covered by them:

- `setFilterTouchesWhenObscured(...)` calls and `android:filterTouchesWhenObscured="true"` in layouts and styles;
- overrides of `onFilterTouchEventForSecurity`;
- checks of `FLAG_WINDOW_IS_OBSCURED` or `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` in touch handling;
- `Window.setHideOverlayWindows(true)` together with the `HIDE_OVERLAY_WINDOWS` permission;
- the app's `minSdkVersion` and `targetSdkVersion`, which tell you which platform protections its users can be relying on.

#### Prerequisites

- The APK (all splits), [jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [aapt2](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/), [semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) with the OWASP rule `rules/mastg-android-overlay-protection.yml` from the MASTG repository.
- A device with the app installed and a test account, to map screens to classes.
- The list of sensitive screens.

#### Steps

1. **Get and decompile the app** ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/) reverse engineering):

   ```bash
   adb shell pm path com.example.app
   adb pull /data/app/~~XXXX/com.example.app-YYYY/base.apk
   jadx -d out base.apk                  # code in out/sources, manifest and res in out/resources
   apktool d -s -f -o apk_out base.apk   # decoded res/ and manifest; SDK levels go to apktool.yml
   ```

2. **Read the SDK levels and permissions** ([MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/), [MASTG-TECH-0126](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0126/)):

   ```bash
   aapt2 dump badging base.apk | grep -E "^(sdkVersion|targetSdkVersion)"
   # sdkVersion:'26'
   # targetSdkVersion:'35'
   grep -nE 'HIDE_OVERLAY_WINDOWS|SYSTEM_ALERT_WINDOW' out/resources/AndroidManifest.xml
   adb shell dumpsys package com.example.app | grep HIDE_OVERLAY_WINDOWS
   #   android.permission.HIDE_OVERLAY_WINDOWS: granted=true
   ```

   An app that declares `SYSTEM_ALERT_WINDOW` itself is not a finding for this weakness (it is a capability, not a defect), but note it: an app that draws its own overlays may also have relaxed its touch filtering to make them work.

3. **Search code and resources** ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/) static analysis). Grep first, because it catches what the rules miss:

   ```bash
   grep -rnE 'setFilterTouchesWhenObscured|onFilterTouchEventForSecurity|FLAG_WINDOW_IS_(PARTIALLY_)?OBSCURED|setHideOverlayWindows|getFlags\(\) & [123]\)' out/sources/ \
     | grep -vE '^out/sources/(android|androidx|kotlin|kotlinx)/' > overlay-hits.txt
   grep -rn 'filterTouchesWhenObscured' apk_out/res/ >> overlay-hits.txt
   semgrep -c mastg-android-overlay-protection.yml out/sources/ apk_out/res/ out/resources/AndroidManifest.xml --text
   ```

   Two pitfalls. jadx replaces `MotionEvent.FLAG_WINDOW_IS_OBSCURED` with the literal `1` and the partial flag with `2`, so the OWASP rules for the flag constants do not match decompiled code (in the OWASP demo the flag check is found only because the surrounding `onFilterTouchEventForSecurity` override matches); the `getFlags() & …` grep covers that. And check the *argument*: `setFilterTouchesWhenObscured(false)` is also a hit.

4. **Map each hit to a screen.** For every sensitive screen, open it on the device and identify its activity, fragments and view IDs:

   ```bash
   adb shell dumpsys activity activities | grep -E 'topResumedActivity|mResumedActivity'
   adb shell dumpsys activity top | grep -E 'app:id/|Fragment\{' | head -50
   adb shell uiautomator dump /sdcard/ui.xml && adb pull /sdcard/ui.xml
   ```

   `dumpsys activity top` prints the view hierarchy with resource names (for example `app:id/confirm_button`), which you can look up in jadx (*Navigation > Search* for `R.id.confirm_button`, or the layout that declares it). Then answer, per screen: is the confirming control, or a parent of it, covered by touch filtering? Is partial occlusion handled where the screen's text is what the user agrees to? Does the activity (and any dialog or other activity in the flow) call `setHideOverlayWindows(true)`?

5. **Check reachability and version guards.** Follow each `setHideOverlayWindows` call back to where it runs (`onCreate` of which activity, behind which condition). A call wrapped in `if (Build.VERSION.SDK_INT >= 31)` is correct; one behind a remote-config flag or a debug check may not run in production. For Compose screens, see which view receives `filterTouchesWhenObscured` (content view or `ComposeView` versus `LocalView.current`). Where static reading is ambiguous, use [GT-0039-2](#gt-0039-2-runtime-inventory-of-overlay-protections-per-screen-android).

#### Observation

A table per sensitive screen: the activity and window(s) involved, the protection found (touch filtering on which view, custom filter and which flags it checks, overlay hiding), the code or layout location, and the app's `minSdkVersion` and `targetSdkVersion`.

#### Evaluation

The test **fails** for a sensitive screen when the app handles a sensitive interaction there and none of the following applies to the window that receives the user's input or approval:

- `setHideOverlayWindows(true)` is set on that window (or on a window that stays visible underneath it) with `HIDE_OVERLAY_WINDOWS` declared, **and** for the app's supported versions below API 31 there is touch filtering as a fallback;
- touch filtering (`filterTouchesWhenObscured` on the control or an ancestor, or an `onFilterTouchEventForSecurity` override that rejects obscured events) covers the confirming control.

Record as a **partial** failure, rated lower, a screen with touch filtering only, where the user's decision depends on text that a partial overlay could cover (amount, payee, scope), and no `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` handling or overlay hiding exists. OWASP's text lists "targets API level 31 or higher but does not use `setHideOverlayWindows(true)`" as a failure example; we read it as "the app could hide overlays on Android 12+ devices and does not", since availability depends on the device's version, not on `targetSdkVersion`.

The test **passes** for a screen when overlay hiding covers it on API 31+ and touch filtering covers it on older supported versions, or when touch filtering plus partial-occlusion handling covers every control and the text that gives it meaning. Static hits on non-sensitive views, in unused library code, or in code paths that do not run do not count towards a pass; confirm with GT-0039-1.

#### Demo

[MASTG-DEMO-0103](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0103/MASTG-DEMO-0103/) (mixed result). Three buttons on one screen: no protection, the platform flag, and a custom filter:

```kotlin
// FAIL: sensitive action, no overlay protection
val vulnerableButton = Button(context).apply { text = "Vulnerable: Confirm Payment" }

// PASS: drops events flagged FLAG_WINDOW_IS_OBSCURED
val protectedButton = Button(context).apply {
    text = "Protected: Confirm Payment"
    filterTouchesWhenObscured = true
}

// PASS: custom policy
val customProtectedButton = object : Button(context) {
    override fun onFilterTouchEventForSecurity(event: MotionEvent): Boolean {
        if ((event.flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0) return false
        return super.onFilterTouchEventForSecurity(event)
    }
}
```

semgrep on the jadx output reports the two protections; the first button does not appear at all, which is the finding:

```text
❱ rules.mastg-android-overlay-protection-setfiltertoucheswhenobscured
     54┆ $this$mastgTest_u24lambda_u245.setFilterTouchesWhenObscured(true);
❱ rules.mastg-android-overlay-protection-onfiltertoucheventforsecurity
     65┆ public boolean onFilterTouchEventForSecurity(MotionEvent event) {
     67┆     if ((event.getFlags() & 1) != 0) {
```

Note line 67: the flag constant has become `1`. The OWASP demo's code comments refer to the test as MASTG-TEST-0358; the demo's front matter (and the published site) link it to MASTG-TEST-0340. Both custom filters in this demo check only the full-occlusion flag, so a partial overlay that rewrites "Grant Permission" would still work against the third button.

[MASTG-DEMO-0105](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0105/MASTG-DEMO-0105/) (pass). The activity hides all overlays:

```xml
<uses-permission android:name="android.permission.HIDE_OVERLAY_WINDOWS" />
```

```kotlin
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
    activity.window.setHideOverlayWindows(true)
}
```

```text
❱ rules.mastg-android-overlay-protection-hide-overlay-windows-permission
     14┆ <uses-permission android:name="android.permission.HIDE_OVERLAY_WINDOWS"/>
❱ rules.mastg-android-overlay-protection-sethideoverlaywindows
     55┆ activity.getWindow().setHideOverlayWindows(true);
```

The demo app has `minSdkVersion` 29; on Android 10 and 11 its button has no protection at all. In a real assessment that is a note for the fallback criterion above.

[MASTG-DEMO-0104](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0104/MASTG-DEMO-0104/) (attack). The attacker app for exercising DEMO-0103 on a device: it declares `SYSTEM_ALERT_WINDOW`, sends the user to `ACTION_MANAGE_OVERLAY_PERMISSION` if `Settings.canDrawOverlays()` is false, and adds an 800-pixel-high red band:

```kotlin
val params = WindowManager.LayoutParams(
    WindowManager.LayoutParams.MATCH_PARENT, 800,
    WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
        WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE or
        WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
    PixelFormat.TRANSLUCENT
).apply { gravity = Gravity.CENTER }
windowManager.addView(View(context).apply { setBackgroundColor(Color.argb(140, 255, 0, 0)) }, params)
```

OWASP's rule `mastg-android-system-alert-window.yml` simply finds the permission in its manifest; OWASP is right that this is not a vulnerability in the app that declares it. Two observations if you use it: the band's background is translucent, but the window alpha is the default 1.0, which on current Android is capped to 0.8 at creation (look for the `setting alpha to 0.80` line in logcat), so touches pass; and the band is centred, so whether a button gets the full or the partial flag depends on where it sits. Our GT-0039-1 app makes both explicit.

### GT-0039-1: Proving tapjacking with an attacker overlay app (Android)

Guler Tech methodology. Platform: Android. Type: dynamic (UI). This restores and modernises the dynamic part of legacy test MASTG-TEST-0035.

#### Overview

You install a minimal attacker app, grant it the overlay permission through adb, and place overlays over each sensitive screen in four configurations: full occlusion, opaque stacked occlusion, partial occlusion and input capture. For each, you record whether the touch reached the target view, with which flags, and whether the app acted on it. That turns "no reference to `filterTouchesWhenObscured`" into "on Android 15, a user who taps *Claim reward* on this overlay approves a £500 transfer", or into a documented pass.

#### Prerequisites

- A test device or emulator on a current Android version, and if the app's `minSdkVersion` allows it, one below Android 12 (an emulator image is fine), because pre-12 devices lack untrusted-touch blocking and `setHideOverlayWindows`.
- The attacker app below, built with `minSdkVersion` 26 and installed with `adb install`.
- Optional but recommended: [Frida](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/) on the device (rooted device or emulator, or a repackaged debuggable build), to see the flags and the filter decision inside the target app.
- A test account and safe test data (a payee you control, the smallest amount).

The attacker app is one translucent activity, driven entirely by `am start` extras. It adds overlay windows and sends itself to the back, so the target app returns to the front underneath the overlay:

```kotlin
package com.example.overlaytest

class MainActivity : Activity() {
    companion object { private val overlays = mutableListOf<View>(); const val TAG = "OverlayTest" }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val wm = applicationContext.getSystemService(WindowManager::class.java)
        overlays.forEach { wm.removeView(it) }; overlays.clear()
        val mode = intent.getStringExtra("mode") ?: "off"           // pass | capture | off
        if (mode != "off" && Settings.canDrawOverlays(this)) {
            val capture = mode == "capture"
            repeat(intent.getIntExtra("count", 1)) {                // count=2 stacks two windows
                val v = TextView(applicationContext).apply {
                    text = intent.getStringExtra("text") ?: "Tap the button below to claim your reward"
                    textSize = 22f; gravity = Gravity.CENTER
                    setBackgroundColor(Color.WHITE); setTextColor(Color.BLACK)
                    if (capture) setOnTouchListener { _, e ->
                        Log.i(TAG, "captured ${MotionEvent.actionToString(e.action)} at ${e.rawX},${e.rawY}")
                        true
                    }
                }
                var flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN
                if (!capture) flags = flags or WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE
                val lp = WindowManager.LayoutParams(
                    WindowManager.LayoutParams.MATCH_PARENT,
                    intent.getIntExtra("height", WindowManager.LayoutParams.MATCH_PARENT),
                    WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY, flags, PixelFormat.TRANSLUCENT
                ).apply {
                    gravity = Gravity.TOP or Gravity.START
                    y = intent.getIntExtra("top", 0)
                    alpha = intent.getFloatExtra("alpha", 1.0f)
                }
                wm.addView(v, lp); overlays += v
                Log.i(TAG, "overlay mode=$mode alpha=${lp.alpha} top=${lp.y} height=${lp.height}")
            }
        } else if (mode != "off") {
            Log.w(TAG, "no overlay permission: adb shell appops set $packageName SYSTEM_ALERT_WINDOW allow")
        }
        moveTaskToBack(true)
    }
}
```

```xml
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
<application android:label="OverlayTest">
    <activity android:name=".MainActivity" android:exported="true"
        android:theme="@android:style/Theme.Translucent.NoTitleBar">
        <intent-filter>
            <action android:name="android.intent.action.MAIN" />
            <category android:name="android.intent.category.LAUNCHER" />
        </intent-filter>
    </activity>
</application>
```

(Imports omitted; all classes are from `android.app`, `android.graphics`, `android.os`, `android.provider`, `android.util`, `android.view` and `android.widget`.) Because the overlay is pass-through, the attacker app itself cannot see where the user taps: the platform does not report other apps' touch coordinates to it. That is why the evidence of success comes from the target app's reaction and from the Frida hook below, not from the attacker app.

#### Steps

1. **Install and grant.**

   ```bash
   adb install -r overlaytest.apk
   adb shell appops set com.example.overlaytest SYSTEM_ALERT_WINDOW allow
   adb shell appops get com.example.overlaytest SYSTEM_ALERT_WINDOW     # SYSTEM_ALERT_WINDOW: allow
   ```

   adb sets the app-op directly, so you do not go through the Settings flow where Android 15's restricted settings would apply to a sideloaded app. Write down that a real attacker has to get the user through that flow.

2. **Instrument the target (optional).** This hook logs, for every `ACTION_DOWN` that reaches a view, the two occlusion flags and whether the view's filter let it through, and logs which view finally handled a click:

   ```javascript
   // frida -U -n "Example App" -l obscured.js   (or -f com.example.app)
   Java.perform(() => {
     const View = Java.use('android.view.View');
     View.onFilterTouchEventForSecurity.implementation = function (ev) {
       const ok = this.onFilterTouchEventForSecurity(ev);
       if (ev.getActionMasked() === 0) {
         const f = ev.getFlags();
         console.log(`[down] ${this.getClass().getName()} id=0x${(this.getId() >>> 0).toString(16)}` +
                     ` obscured=${(f & 1) !== 0} partial=${(f & 2) !== 0} delivered=${ok}`);
       }
       return ok;
     };
     View.performClick.overload().implementation = function () {
       console.log(`[click] ${this.getClass().getName()} id=0x${(this.getId() >>> 0).toString(16)}`);
       return this.performClick();
     };
   });
   ```

   The `delivered` value is the platform default filter's decision; a view whose own override rejects the event before calling `super` (like the third button in MASTG-DEMO-0103) does not log a line at all, which is itself a sign that the custom filter fired. For Compose screens you will see the call on the content `FrameLayout` and the `ComposeView` but not on `AndroidComposeView` (it does not call the filter), and `performClick` will not fire for composables; use the app's visible reaction instead.

3. **Watch logcat** in a second terminal:

   ```bash
   adb logcat | grep -E 'OverlayTest|Untrusted touch|Dropping untrusted|has a system alert window'
   ```

4. **Find the target control.** Open the sensitive screen and get the bounds of the confirming control from `uiautomator dump` (`bounds="[x1,y1][x2,y2]"`), so you know where to tap and which area the partial overlay must avoid. Tap by hand for the real test; `adb shell input tap X Y` is handy for repeating it, but confirm at least once with a finger.

5. **Baseline.** No overlay, tap the control: the action happens; Frida shows `obscured=false partial=false delivered=true`. Cancel or reverse the action as the test plan allows.

6. **Scenario A: full occlusion at 0.8.**

   ```bash
   adb shell am start -n com.example.overlaytest/.MainActivity --es mode pass --ef alpha 0.8
   ```

   The whole screen shows the decoy text at 80 % opacity, with your screen faintly visible underneath. Tap where the control is. **Vulnerable:** the action happens; Frida shows `obscured=true delivered=true`. **Protected by touch filtering:** nothing happens, `delivered=false`. **Protected by overlay hiding:** the overlay is not visible at all while the screen is shown (confirm with `adb exec-out screencap -p > a.png`).

7. **Scenario B: opaque occlusion.** Repeat with `--ef alpha 1.0`, then with `--ef alpha 1.0 --ei count 2`. On current Android the single window is capped to 0.8 (logcat shows `setting alpha to 0.80 to let touches pass through`) and behaves like scenario A; the stacked pair reaches a combined 0.96 and the platform drops the touch (`Untrusted touch due to occlusion by com.example.overlaytest/…`). That block is the platform's doing, not the app's: do not credit it as an app control. On an Android 11 or older device, the opaque overlay passes touches through, and that is where an unprotected app is fully exposed.

8. **Scenario C: partial occlusion.** Cover the context but not the control: set `top` and `height` so the overlay ends above the control's top edge, and pick text that changes the meaning (`--es text "Tap Confirm to verify your account"` over a transfer summary):

   ```bash
   adb shell am start -n com.example.overlaytest/.MainActivity --es mode pass --ef alpha 0.8 \
       --ei top 0 --ei height 1200 --es text "Tap Confirm to verify your account"
   ```

   Tap the real control. Frida shows `obscured=false partial=true`. An app with only `filterTouchesWhenObscured` accepts it; only a partial-flag check, a re-confirmation, or overlay hiding stops it.

9. **Scenario D: input capture.** A touchable overlay that keeps the touches:

   ```bash
   adb shell am start -n com.example.overlaytest/.MainActivity --es mode capture --es text "Enter your PIN"
   ```

   Tap anywhere: logcat shows `OverlayTest: captured ACTION_DOWN at …` and the target app receives nothing. In a real attack the overlay would be a copy of your PIN pad. Only overlay hiding defeats this while your screen is visible; record whether the overlay disappears when the sensitive screen opens.

10. **Cover the whole flow.** Repeat on every sensitive screen, including dialogs, bottom sheets and any SDK activity in the flow, and on the older device if you have one. Then clean up:

    ```bash
    adb shell am start -n com.example.overlaytest/.MainActivity --es mode off
    adb shell appops set com.example.overlaytest SYSTEM_ALERT_WINDOW default
    adb uninstall com.example.overlaytest
    ```

#### Observation

A matrix per sensitive screen and device (Android version): for baseline and scenarios A to D, whether the action happened, the Frida line (flags and `delivered`), relevant logcat lines, and a screenshot or screen recording (`adb shell screenrecord /sdcard/tapjack.mp4`) showing the overlay and the result. Redact account data in the report.

#### Evaluation

| Result on a sensitive screen | Conclusion |
|---|---|
| Overlay not visible while the screen is shown (A to D) | **Pass**: overlay hiding is effective on this version. Check older supported versions separately |
| A: action happens under a 0.8 full overlay | **Fail**: no full-occlusion protection |
| A blocked (`delivered=false`), C: action happens with partial context rewritten | **Partial fail**: full occlusion handled, partial not. Rate on how much the covered text matters |
| A and C blocked, D: overlay stays visible and captures input | Pass for tapjacking; input capture possible. For PIN, password and card-entry screens record it as a finding unless overlay hiding is present (Android 12+) |
| Only B's stacked case blocked, A succeeds | **Fail**: the block is platform behaviour; the app has no protection |
| Flow continues in a window or activity you could not protect (SDK, Custom Tab) | Note the residual risk, attributed to that component |

#### Demo

Illustrative output from a banking-style app, Android 15 emulator, transfer confirmation screen, protected with `filterTouchesWhenObscured` on the confirm button only:

```text
# Scenario A, alpha 0.8
[down] android.widget.FrameLayout id=0x1020002 obscured=true partial=false delivered=true
[down] com.google.android.material.button.MaterialButton id=0x7f0a00c4 obscured=true partial=false delivered=false
# Scenario C, overlay ends above the button, text "Tap Confirm to verify your account"
[down] com.google.android.material.button.MaterialButton id=0x7f0a00c4 obscured=false partial=true delivered=true
[click] com.google.android.material.button.MaterialButton id=0x7f0a00c4
```

Full occlusion is handled; partial occlusion lets the overlay replace "Send £250.00 to J. Smith" with a harmless instruction while the real button is tapped. Partial fail on that screen; with no second confirmation for new payees, we would rate it Medium (see below).

### GT-0039-2: Runtime inventory of overlay protections per screen (Android)

Guler Tech methodology. Platform: Android. Type: dynamic (runtime inspection).

#### Overview

Static hits do not tell you which view on which screen carries the flag, especially with obfuscation, custom view classes and Compose. This test reads the protections from the live process for the screen currently shown: the window's overlay-hiding flag and every view with touch filtering or a custom security filter. It is quick, and it makes MASTG-TEST-0340's per-screen table reliable.

#### Prerequisites

- Frida on the device (as in GT-0039-1) or, for the window flag alone, just adb.
- The app on the sensitive screen you want to inspect.

#### Steps

1. **Window flag, with adb only.** `dumpsys window` prints each window's layout parameters, including private flags by name:

   ```bash
   adb shell dumpsys window windows | grep -E 'Window #|pfl=' | grep -A1 com.example.app
   #   Window #12 Window{4f1c2e0 u0 com.example.app/com.example.app.TransferConfirmActivity}:
   #     pfl=... HIDE_NON_SYSTEM_OVERLAY_WINDOWS ...
   ```

   The flag on the window of the sensitive screen (and nothing on its dialog, which is fine as long as the activity window stays visible) means overlay hiding is active. While the GT-0039-1 overlay app is running, its window appears with `ty=APPLICATION_OVERLAY` and `alpha=0.8`.

2. **Views with touch filtering or a custom filter, with Frida.** Walk every window's view tree in the process:

   ```javascript
   // frida -U -n "Example App" -l inventory.js
   Java.perform(() => {
     const ViewGroup = Java.use('android.view.ViewGroup');
     const MotionEvent = Java.use('android.view.MotionEvent');
     const sig = Java.array('java.lang.Class', [MotionEvent.class]);
     const HIDE = 1 << 19;   // SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS
     function idName(v) { try { return v.getResources().getResourceEntryName(v.getId()); } catch (e) { return '-'; } }
     function walk(v, depth) {
       const decl = v.getClass().getMethod('onFilterTouchEventForSecurity', sig).getDeclaringClass().getName();
       const filter = v.getFilterTouchesWhenObscured();
       if (filter || decl !== 'android.view.View')
         console.log(`${'  '.repeat(depth)}${v.getClass().getName()} id=${idName(v)} filterTouches=${filter} customFilter=${decl !== 'android.view.View' ? decl : 'no'}`);
       if (ViewGroup.class.isInstance(v)) {
         const g = Java.cast(v, ViewGroup);
         for (let i = 0; i < g.getChildCount(); i++) walk(g.getChildAt(i), depth + 1);
       }
     }
     Java.scheduleOnMainThread(() => {
       Java.choose('android.view.ViewRootImpl', {
         onMatch(r) {
           const attrs = r.mWindowAttributes.value;
           const root = r.getView();
           console.log(`== window "${attrs.getTitle()}" hideOverlays=${(attrs.privateFlags.value & HIDE) !== 0}`);
           if (root) walk(root, 1);
         },
         onComplete() {}
       });
     });
   });
   ```

   Only views with a protection are printed, indented by depth, so a protected container shows its protected subtree implicitly. Run it on each sensitive screen and with each dialog or bottom sheet open.

3. **Compare with the screen.** Match the IDs to what `uiautomator dump` shows for the confirming control and the text around it. Note windows (dialogs, popups) that show sensitive content and have neither `hideOverlays=true` on a visible parent window nor a protected view.

#### Observation

Per screen: each window title with its `hideOverlays` value, and the list of protected views with their IDs and filter type; plus the `dumpsys window` excerpt.

#### Evaluation

This test produces evidence, not a verdict on its own. Use it to fill in MASTG-TEST-0340's table: a sensitive control that is neither inside a protected view nor in a window covered by overlay hiding is unprotected. A `customFilter` class needs reading in jadx to see which flags it checks. Confirm anything you are going to rate above Low with GT-0039-1.

#### Demo

Illustrative, same app as above:

```text
== window "com.example.app/com.example.app.TransferConfirmActivity" hideOverlays=false
        com.google.android.material.button.MaterialButton id=confirm_button filterTouches=true customFilter=no
== window "com.example.app/com.example.app.LoginActivity" hideOverlays=true
```

The login screen hides overlays (so input capture fails there on Android 12+); the transfer confirmation filters full occlusion on the button only, which matches the partial-occlusion result in GT-0039-1.

## Best practices

### MASTG-BEST-0040: Preventing Overlay Attacks

Source: [MASTG-BEST-0040](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0040/). OWASP ranks the defences from most to least robust:

1. **Hide overlays** with `HIDE_OVERLAY_WINDOWS` and `setHideOverlayWindows(true)` (API 31+). Strongest, because the attacker's window is gone rather than its touches filtered. Two corrections to "prevents overlays entirely": it does not hide accessibility overlays or the keyboard, and it cannot help against an attacker's activity in front of yours.
2. **Filter touches** with `android:filterTouchesWhenObscured="true"` or `setFilterTouchesWhenObscured(true)` on sensitive views (all versions). Since Android 14 this also marks the views accessibility data sensitive (see BEST-0075 below).
3. **Override `onFilterTouchEventForSecurity`** for a custom policy, which is where partial-occlusion handling belongs.

As a *detection* mechanism, checking `FLAG_WINDOW_IS_OBSCURED` (API 9+) and `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` (API 29+) in touch handlers lets the app react (warn, require re-confirmation) rather than silently drop the touch.

Apply the protections to security-sensitive elements: login and authentication screens, permission and consent prompts, payment confirmation, sensitive data entry, security settings. OWASP's caveats, which we agree with: touch filtering does not fix system-level bugs on old versions (Toast Overlay before 8.0), so keep `targetSdkVersion` and `minSdkVersion` current; applying filtering too broadly hurts users with legitimate overlays; and social engineering remains possible with every protection in place.

### MASTG-BEST-0075: Restricting Accessibility Service Access to Sensitive Views

Source: [MASTG-BEST-0075](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0075/). Android 14+ lets you mark views `accessibilityDataSensitive` so that only declared accessibility tools can read or act on them; Android 16 also blocks gestures injected at those views. It is the counterpart of this note for the accessibility half of cloak-and-dagger attacks, and views with `filterTouchesWhenObscured` get it automatically. Details and tests are in [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/).

### Secure patterns for Android (Guler Tech)

**Layouts: protect the container, not only the button.** The confirmation summary and its button in one protected group:

```xml
<LinearLayout
    android:id="@+id/confirm_container"
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:orientation="vertical"
    android:filterTouchesWhenObscured="true">
    <TextView android:id="@+id/transfer_summary" ... />
    <com.google.android.material.button.MaterialButton android:id="@+id/confirm_button" ... />
</LinearLayout>
```

**Activity: hide overlays on API 31+, filter everywhere, tell the user.**

```xml
<uses-permission android:name="android.permission.HIDE_OVERLAY_WINDOWS" />
```

```kotlin
class TransferConfirmActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            window.setHideOverlayWindows(true)          // overlays vanish while this window is visible
        }
        setContentView(R.layout.activity_transfer_confirm)
        findViewById<ViewGroup>(android.R.id.content).filterTouchesWhenObscured = true  // fallback below API 31
    }
}
```

**Partial occlusion on the one control that commits.** A button that refuses both kinds of obscured touch and explains why:

```kotlin
class ConfirmButton @JvmOverloads constructor(
    context: Context, attrs: AttributeSet? = null
) : MaterialButton(context, attrs) {
    override fun onFilterTouchEventForSecurity(event: MotionEvent): Boolean {
        var mask = MotionEvent.FLAG_WINDOW_IS_OBSCURED
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) mask = mask or MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED
        if ((event.flags and mask) != 0) {
            if (event.actionMasked == MotionEvent.ACTION_DOWN) {
                Snackbar.make(this, R.string.overlay_detected, Snackbar.LENGTH_LONG).show()
            }
            return false
        }
        return super.onFilterTouchEventForSecurity(event)
    }
}
```

A message such as "Another app is drawing over this screen. Close screen filters or floating apps and try again" turns the screen-dimmer support ticket into a self-service fix. Do not log or send the event coordinates anywhere.

**Compose: filter at the host, partial check per composable.**

```kotlin
class PaymentActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) window.setHideOverlayWindows(true)
        setContent { ConfirmPaymentScreen() }
        // A regular ViewGroup, so its dispatchTouchEvent applies the filter to the whole composition.
        // Do not rely on LocalView.current for this (it is the internal AndroidComposeView).
        findViewById<ViewGroup>(android.R.id.content).filterTouchesWhenObscured = true
    }
}

@OptIn(ExperimentalComposeUiApi::class)   // required by older Compose UI versions
fun Modifier.rejectObscuredTouches(): Modifier = pointerInteropFilter { e ->
    var mask = MotionEvent.FLAG_WINDOW_IS_OBSCURED
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) mask = mask or MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED
    e.actionMasked == MotionEvent.ACTION_DOWN && (e.flags and mask) != 0   // true = consume the gesture here
}

// Button(onClick = onConfirm, modifier = Modifier.rejectObscuredTouches()) { Text("Confirm") }
```

Compose `Dialog` and `ModalBottomSheet` content lives in its own window: rely on the activity's `setHideOverlayWindows` while it is visible, and use the modifier on their confirming controls for older versions.

**For the most critical approvals**, assume an overlay might one day get a tap through and make the approval itself unforgeable: show the transaction details in the confirmation step of a signing flow bound to a user-authenticated key, or approve on a second device ([MASWE-0025](/mobile/maswe-0025-lack-of-non-repudiation/)).

## Rating findings

Rate on three things: **what the unprotected screen lets an attacker achieve** (an irreversible payment or login approval, credential capture, or something minor), **what the attacker needs** (always a malicious app on the device with the overlay permission, which the user must enable through several deliberate steps, plus the user's own tap or typing), and **which Android versions are exposed** (pre-12 devices with no platform blocking, or only partial occlusion on current ones). The weakness is part of the L2 and EUDIW profiles only: for an app assessed against L1, missing overlay protection is informational. We do not rate missing overlay protection as Critical on its own, because exploitation requires a prior compromise step (malware installed and granted special access) and user interaction.

| Rating | Conditions |
|---|---|
| **Critical** | Not used for this weakness alone. Consider it only as part of a chain you have demonstrated end to end, for example an exported activity that any app can start with attacker-chosen parameters ([MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/)) landing on an unprotected one-tap payment approval. |
| **High** | L2 or EUDIW app; a screen where **one tap** commits an irreversible, high-value action (payment, new payee, login or MFA-push approval, device binding, wallet presentation or signing) has no full-occlusion protection, and you have shown with GT-0039-1 that the action completes under a pass-through overlay on a current Android version; no second, out-of-band confirmation. Also: PIN, password or card-entry screens with no overlay hiding where you have demonstrated input capture and the captured data alone gives account access. |
| **Medium** | Same app classes, but the unprotected action needs further steps, is reversible or capped, or is confirmed out of band; or full occlusion is handled but partial occlusion demonstrably rewrites the information the user consents to (amount, payee, scope) on a high-value screen; or protection exists only through `setHideOverlayWindows` while `minSdkVersion` lets a significant share of users run Android 11 or lower without any fallback. |
| **Low** | Sensitive but low-impact screens unprotected (profile changes, notification settings); protection gaps confined to a secondary window (a rarely used dialog) of an otherwise protected flow; Compose screens that set the flag only on `LocalView.current` where you have not been able to show an exploitable screen; touch filtering present but no overlay hiding on API 31+ for screens where input capture would yield only low-value data. |
| **Info** | L1-only apps; iOS apps (classic overlays do not apply); `SYSTEM_ALERT_WINDOW` declared by the app under test; residual risks no app control can remove (activity-based phishing, accessibility overlays, malicious keyboards, third-party Custom Tabs in the flow); results that relied on disabled platform protections. |

Raise a level for apps whose users are actively targeted by overlay malware (banking, crypto wallets, payment and identity apps in markets where that malware circulates), or when the app's `minSdkVersion` reaches back to versions before Android 8.0, where Toast Overlay and keyboard overlays add to the picture. Lower a level when exploitation on current Android versions needs an implausible screen layout (for example, the commit control fills most of the screen so no partial overlay can carry meaningful decoy content). In the report, give the screen and its activity, the protections present (from MASTG-TEST-0340 and GT-0039-2), the GT-0039-1 matrix with the Android versions tested, the attacker prerequisites in plain words ("a malicious app the user has allowed to display over other apps"), and the fix: overlay hiding on the window, touch filtering on the container, partial-occlusion handling on the committing control.

## References

- OWASP MASWE: [MASWE-0039: App Vulnerable to Overlay Attacks](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0039/); related [MASWE-0036](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0036/), [MASWE-0040](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0040/), [MASWE-0025](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0025/), [MASWE-0055](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0055/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PLATFORM-3](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/), [MASVS-CODE-1](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0022: Overlay Attacks](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0022/), [MASTG-KNOW-0143: Accessibility Data Sensitivity](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0143/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0340: References to Overlay Attack Protections](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0340/); legacy [MASTG-TEST-0035: Testing for Overlay Attacks](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0035/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0103](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0103/MASTG-DEMO-0103/), [MASTG-DEMO-0104](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0104/MASTG-DEMO-0104/), [MASTG-DEMO-0105](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0105/MASTG-DEMO-0105/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0040: Preventing Overlay Attacks](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0040/), [MASTG-BEST-0075: Restricting Accessibility Service Access to Sensitive Views](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0075/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0126](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0126/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/) (CC BY-SA 4.0)
- OWASP MASTG tools: [adb (MASTG-TOOL-0004)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [aapt2 (MASTG-TOOL-0124)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) (CC BY-SA 4.0)
- Android Developers: [Tapjacking](https://developer.android.com/privacy-and-security/risks/tapjacking), [Android 12 behaviour changes: untrusted touch events are blocked](https://developer.android.com/about/versions/12/behavior-changes-all#untrusted-touch-events), [Android 11 permission changes: system alert window](https://developer.android.com/about/versions/11/privacy/permissions#system-alert-window), [Android 8.0 behaviour changes: alert windows](https://developer.android.com/about/versions/oreo/android-8.0-changes#all-aw), [`View` security](https://developer.android.com/reference/android/view/View#security), [`View.onFilterTouchEventForSecurity`](https://developer.android.com/reference/android/view/View#onFilterTouchEventForSecurity%28android.view.MotionEvent%29), [`View.setFilterTouchesWhenObscured`](https://developer.android.com/reference/android/view/View#setFilterTouchesWhenObscured%28boolean%29), [`MotionEvent.FLAG_WINDOW_IS_OBSCURED`](https://developer.android.com/reference/android/view/MotionEvent#FLAG_WINDOW_IS_OBSCURED), [`MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED`](https://developer.android.com/reference/android/view/MotionEvent#FLAG_WINDOW_IS_PARTIALLY_OBSCURED), [`Window.setHideOverlayWindows`](https://developer.android.com/reference/android/view/Window#setHideOverlayWindows%28boolean%29), [`Manifest.permission.HIDE_OVERLAY_WINDOWS`](https://developer.android.com/reference/android/Manifest.permission#HIDE_OVERLAY_WINDOWS), [`Manifest.permission.SYSTEM_ALERT_WINDOW`](https://developer.android.com/reference/android/Manifest.permission#SYSTEM_ALERT_WINDOW), [`WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY`](https://developer.android.com/reference/android/view/WindowManager.LayoutParams#TYPE_APPLICATION_OVERLAY), [`Modifier.pointerInteropFilter`](https://developer.android.com/reference/kotlin/androidx/compose/ui/input/pointer/package-summary)
- Android Developers Blog: [Enhancing Android security: Stop malware from snooping on your app data](https://android-developers.googleblog.com/2025/12/enhancing-android-security-stop-malware.html) (December 2025)
- Android Open Source Project: [Android 15 Compatibility Definition](https://source.android.com/docs/compatibility/15/android-15-cdd) (section 9.8, restricted settings); frameworks/native `services/inputflinger/dispatcher/InputDispatcher.cpp` (touch occlusion and logging); frameworks/base `View.java`, `ViewGroup.java`, `Window.java`, `WindowManager.java`, `services/core/java/com/android/server/wm/` (`WindowState`, `WindowManagerService`, `DisplayPolicy`, `InputMonitor`); commit [a451d5bae2e2 "Cap alpha to max if SAW + FLAG_NOT_TOUCHABLE"](https://android.googlesource.com/platform/frameworks/base/+/a451d5bae2e2); androidx `compose/ui` (`AndroidComposeView`, `PointerInteropFilter`)
- Apple: [`AVPictureInPictureController`](https://developer.apple.com/documentation/avkit/avpictureinpicturecontroller)
- Research: Y. Fratantonio, C. Qian, S. Chung, W. Lee, [Cloak and Dagger: From Two Permissions to Complete Control of the UI Feedback Loop](https://cloak-and-dagger.org/) (IEEE S&P 2017); Palo Alto Networks Unit 42, [Android Toast Overlay Attack: "Cloak and Dagger" with No Permissions](https://unit42.paloaltonetworks.com/unit42-android-toast-overlay-attack-cloak-and-dagger-with-no-permissions/) (CVE-2017-0752)
- CWE: [CWE-1021: Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
