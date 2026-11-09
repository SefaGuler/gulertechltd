---
title: "Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings (MASWE-0038)"
date: 2026-11-09 21:09:00 +0000
subcategory: platform
summary: "Testing Android and iOS apps for sensitive data in Recents and app-switcher snapshots, screenshots, screen recordings and screen sharing."
refs: [MASWE-0038, MASVS-PLATFORM-3, MASVS-STORAGE-2, CWE-200, CWE-359]
tags: [android, ios, masvs-platform, screenshots, flag-secure, app-switcher]
---

This note is part of our [MASVS-PLATFORM guide](/mobile/masvs-platform-platform-interaction-guide/) and covers OWASP [MASWE-0038](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0038/): sensitive data that ends up in pixels the app no longer controls. Every time a screen is drawn, there are several ways a copy of it can leave the app: the snapshot the OS takes for the Recents screen or the App Switcher, a screenshot the user takes, a screen recording, a cast to a TV, a screen share in a video call, a `MediaProjection` session started by another app, or an accessibility service asking for a screenshot. Some of those copies are written to disk and stay there; some are synced to a photo cloud; some are streamed live to a person on the other end of a scam call. Below you will find how each platform produces those copies, what Android's `FLAG_SECURE`, `setRecentsScreenshotEnabled`, `SurfaceView.setSecure`, Compose `SecureFlagPolicy` and `setContentSensitivity` actually cover (and the windows they miss), the Android 14 and 15 capture-detection APIs, the iOS snapshot lifecycle and its on-disk location, iOS capture-state detection and why iOS cannot block screenshots, the six OWASP tests (three of them placeholders that we write ourselves), two tests of our own, and how to rate what you find.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Screenshots (MASTG-KNOW-0053)](#android-screenshots-mastg-know-0053)
  - [Android: User-Initiated Screenshots and Screen Recording (MASTG-KNOW-0105)](#android-user-initiated-screenshots-and-screen-recording-mastg-know-0105)
  - [Android: App-Initiated Screenshots and Screen Recording (MASTG-KNOW-0106)](#android-app-initiated-screenshots-and-screen-recording-mastg-know-0106)
  - [Android: Screenshots and Screen Recording Detection (MASTG-KNOW-0107)](#android-screenshots-and-screen-recording-detection-mastg-know-0107)
  - [iOS: Screenshots (MASTG-KNOW-0099)](#ios-screenshots-mastg-know-0099)
  - [iOS: Screen capture detection and the secure-field technique (supplementary)](#ios-screen-capture-detection-and-the-secure-field-technique-supplementary)
- [Tests](#tests)
  - [Before you start: identify the sensitive screens](#before-you-start-identify-the-sensitive-screens)
  - [MASTG-TEST-0289: Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding (Android)](#mastg-test-0289-runtime-verification-of-sensitive-content-exposure-in-screenshots-during-app-backgrounding-android)
  - [MASTG-TEST-0291: References to Screen Capturing Prevention APIs (Android)](#mastg-test-0291-references-to-screen-capturing-prevention-apis-android)
  - [MASTG-TEST-0292: setRecentsScreenshotEnabled Not Used to Prevent Screenshots When Backgrounded (Android)](#mastg-test-0292-setrecentsscreenshotenabled-not-used-to-prevent-screenshots-when-backgrounded-android)
  - [MASTG-TEST-0293: setSecure Not Used to Prevent Screenshots in SurfaceViews (Android)](#mastg-test-0293-setsecure-not-used-to-prevent-screenshots-in-surfaceviews-android)
  - [MASTG-TEST-0294: SecureOn Not Used to Prevent Screenshots in Compose Dialogs (Android)](#mastg-test-0294-secureon-not-used-to-prevent-screenshots-in-compose-dialogs-android)
  - [MASTG-TEST-0290: Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding (iOS)](#mastg-test-0290-runtime-verification-of-sensitive-content-exposure-in-screenshots-during-app-backgrounding-ios)
  - [GT-0038-1: Live capture check with screenshots, recording and casting (Android and iOS)](#gt-0038-1-live-capture-check-with-screenshots-recording-and-casting-android-and-ios)
  - [GT-0038-2: Static review of snapshot and capture handling (iOS)](#gt-0038-2-static-review-of-snapshot-and-capture-handling-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0014: Preventing Screenshots and Screen Recording](#mastg-best-0014-preventing-screenshots-and-screen-recording)
  - [MASTG-BEST-0015, 0016, 0017 and 0018 (placeholders)](#mastg-best-0015-0016-0017-and-0018-placeholders)
  - [Secure patterns for Android (Guler Tech)](#secure-patterns-for-android-guler-tech)
  - [Secure patterns for iOS (Guler Tech)](#secure-patterns-for-ios-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0038 applies when sensitive data shown by an app can be captured in a screenshot, a screen recording or a system snapshot, and the app neither prevents the capture nor hides the data when it should. The OWASP requirement is *"The app removes or masks sensitive data from its views when moved to the background, when being recorded or when a screenshot is taken."* It maps to MASVS-PLATFORM-3 ("The app uses the user interface securely") and MASVS-STORAGE-2 (because some of these images are written to storage), to MASVS v1 MSTG-STORAGE-9, and to [CWE-200](https://cwe.mitre.org/data/definitions/200.html) (Exposure of Sensitive Information to an Unauthorized Actor) and [CWE-359](https://cwe.mitre.org/data/definitions/359.html) (Exposure of Private Personal Information to an Unauthorized Actor). The weakness was MASWE-0055 in the beta numbering, which you may still see in older reports.

The profiles matter for rating: MASWE-0038 is tagged **L2 and EUDIW only**, not L1. OWASP treats it as an expectation for apps that handle high-value data (banking, payments, wallets, health, identity, the EU Digital Identity Wallet), not as a baseline for every app. A recipe app that shows a user's email address in the Recents thumbnail is not the same finding as a wallet that shows a recovery phrase there.

OWASP describes the threat as MAS-THREAT-0038, *"Attackers can access sensitive data displayed on the screen"*, reached through three attacks:

- **MAS-ATTACK-0071**, capturing or recording the screen from another app or an external tool;
- **MAS-ATTACK-0072**, accessing screenshots automatically taken by the system, for example when the app moves to the background;
- **MAS-ATTACK-0010**, accessing shared or external storage from any app holding the corresponding permissions, which is where user screenshots and recordings end up.

The capture channels, who triggers them and what stops them:

| Channel | Triggered by | Where the copy goes | Android control | iOS control |
|---|---|---|---|---|
| Recents / App Switcher snapshot | The OS, every time the app leaves the foreground | System-owned file (Android `/data/system_ce/…`), app container file (iOS `Library/SplashBoard/…`), and the switcher UI | `FLAG_SECURE`, `setRecentsScreenshotEnabled(false)` | Cover or clear the UI before the snapshot |
| User screenshot | The user (hardware buttons, gestures, assistant) | Shared photo library, often cloud-synced | `FLAG_SECURE` blocks it | None: detection only (`userDidTakeScreenshotNotification`) |
| User screen recording | The user (Quick Settings, Control Centre) | Shared media library | `FLAG_SECURE` (window is black) | None built in; detect with capture state, then hide |
| Casting, mirroring, AirPlay, external display | The user | A TV, projector or another device | `FLAG_SECURE` (non-secure displays show black) | Detect with capture state, then hide; FairPlay video is blacked out by the system |
| Screen sharing in another app (video call, "remote support") | Another app via `MediaProjection` / ReplayKit, with user consent | Streamed to a remote party | `FLAG_SECURE`, `setContentSensitivity` (API 35) | Detect with capture state, then hide |
| Accessibility service screenshot | An enabled accessibility service | The service | `FLAG_SECURE` (secure windows are refused or black) | n/a |
| `adb` / developer tools | Someone with USB debugging access | The workstation | `FLAG_SECURE` (black) | n/a (Xcode/QuickTime capture counts as capture) |

Keep this note separate from its neighbours:

- Masking values in the UI (password fields, partial card numbers, shoulder surfing) is [MASWE-0036](/mobile/maswe-0036-sensitive-data-exposed-via-ui/); here we only care about masking as a way to reduce what a capture contains.
- Notification content is [MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/).
- Accessibility services **reading the view tree** are [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/). `FLAG_SECURE` does not stop that: it hides pixels, not the text in `AccessibilityNodeInfo`.
- Overlays and tapjacking are [MASWE-0039](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/).
- Snapshots that outlive a logout or session timeout are discussed in [MASWE-0024](/mobile/maswe-0024-sensitive-data-accessible-after-session-termination/).
- The iOS snapshot files sitting in the app container are data at rest; the general methodology for finding sensitive files in the sandbox and in backups is in the [STORAGE guide](/mobile/masvs-storage-1-secure-storage-guide/) and [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/).

## Modes of Introduction

**No protection on sensitive screens.** The most common case: an activity showing card details, a balance, a recovery phrase or an identity document with no `FLAG_SECURE`, and an iOS view controller with nothing hiding it when the scene resigns active. The Recents thumbnail and every screenshot contain the data.

**Protection applied to the activity but not to the windows on top of it.** On Android, `FLAG_SECURE` is a property of a window. A `Dialog`, `AlertDialog`, `BottomSheetDialog`, `DialogFragment` or Compose `Dialog` is a separate window, and so are some popups. A "Reveal card number" dialog over a protected activity is the classic miss. Compose dialogs default to `SecureFlagPolicy.Inherit`, which only helps if the parent window was already secure when the dialog was created.

**Protection on the window but not on a separate surface.** A `SurfaceView` (camera previews, video players, maps, game engines, Flutter's default renderer) draws into its own surface. On older Android versions that surface did not inherit the window's secure state, so `SurfaceView.setSecure(true)` was needed; it must be called before the view is attached.

**Protection removed at the wrong moment.** `clearFlags(FLAG_SECURE)` in `onResume` "so users can screenshot receipts", a `setFlags(0, FLAG_SECURE)` in a shared base activity, a remote-config flag that turns it off, or a user setting "Allow screenshots" that defaults to on. Each of these is a deliberate choice that needs a reason; when the screen still shows sensitive data, it is a finding.

**Recents-only protection that leaves live capture open, or the opposite.** `setRecentsScreenshotEnabled(false)` hides the Recents thumbnail but does nothing against screenshots, recording or screen sharing. `FLAG_SECURE` set only in `onPause` (a pattern from before API 33) is racy and leaves the screen capturable while in use.

**Detection mistaken for prevention.** An app that registers `Activity.ScreenCaptureCallback` on Android 14 or observes `userDidTakeScreenshotNotification` on iOS and shows a warning. The screenshot has already been taken when the callback runs.

**Ignoring capture state.** On iOS, where screenshots cannot be blocked, the remaining control for live capture is to hide sensitive content while `sceneCaptureState` (or `UIScreen.isCaptured`) says the screen is being recorded, mirrored or shared. Apps that never check it show everything to a screen-sharing scammer. On Android 15 the equivalent signals are the screen recording callback and `setContentSensitivity`.

**Covering the iOS UI too late or incompletely.** Putting the privacy cover in `applicationWillEnterForeground` (too late), in `applicationDidEnterBackground` of an app that uses scenes (that method is not called for scene-based apps; `sceneDidEnterBackground` is), behind a presented view controller, or as a light blur through which large digits stay readable.

**Excessive on-screen disclosure.** Showing a full PAN, IBAN, national ID number or recovery phrase by default when a masked or tap-to-reveal representation would do. Every second the value is on screen is a second it can be captured.

## Impact

- **Compromise of sensitive data.** The captured image or recording outlives the session: it can be viewed later, shared, synced to Google Photos or iCloud Photos, included in a backup, recovered from a lost device, or read by any app with photo-library access.
- **Fraud through screen sharing.** Authorised push payment and "bank safe account" scams routinely ask the victim to install a screen-sharing or remote-support app. Card details, one-time codes and balances shown in the banking app are then read live by the scammer. Android's own fraud-prevention guidance names legitimate screen-sharing apps as a common tool in these scams.
- **Exposure to people with brief physical access.** The Recents screen and the App Switcher show the last screen of every app without opening it, so the app's PIN or biometric lock on resume does not protect what the thumbnail shows. Anyone handed an unlocked phone can see it.
- **Regulatory exposure.** Card data in images is in scope for PCI DSS; personal data in leaked images is personal data under UK GDPR whether or not it is text.

## Mitigations

- **Show less.** Mask by default, reveal on request, re-mask after use, and never show secrets (passwords, full PAN with CVV, recovery phrases, private keys) longer than needed.
- **Android: set `FLAG_SECURE` on every window that shows sensitive data**, including dialogs, bottom sheets and popups; use `SecureFlagPolicy.SecureOn` in Compose `Dialog`, `Popup` and `ModalBottomSheet`; call `SurfaceView.setSecure(true)` before attach for surfaces with sensitive content.
- **Android 13+: use `setRecentsScreenshotEnabled(false)`** on screens where you want users to keep taking screenshots but do not want the content in Recents.
- **Android 15+: mark sensitive views with `setContentSensitivity(View.CONTENT_SENSITIVITY_SENSITIVE)`** so the window is treated as secure while any media projection is active.
- **iOS: hide sensitive content before the snapshot**, from `sceneWillResignActive` (or `applicationWillResignActive`) through `sceneDidEnterBackground`, using an opaque cover over everything, including presented controllers and alerts.
- **iOS: redact while captured**, by observing `sceneCaptureState` (iOS 17+) or `UIScreen.capturedDidChangeNotification` / `isCaptured` (iOS 11+).
- **Use detection only for transparency**: telling the user, or another participant in a conversation, that a capture happened. Never as the control.

## Knowledge

OWASP links five Knowledge pages to this weakness. Two have content (MASTG-KNOW-0053 for Android and MASTG-KNOW-0099 for iOS, both filed under MASVS-STORAGE). The three Android pages filed under MASVS-PLATFORM (MASTG-KNOW-0105, 0106 and 0107) are **placeholders with no content** on mas.owasp.org at the time of writing; the sections below for those three are **Guler Tech methodology**, written from Android's documentation and the AOSP sources. We add one supplementary iOS section because OWASP's iOS page covers only the snapshot.

### Android: Screenshots (MASTG-KNOW-0053)

Source: [MASTG-KNOW-0053](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0053/). OWASP's page is short: when an app goes to the background the system keeps a screenshot of it, the user or a malicious app may also capture the screen, and screenshots on storage can be recovered by a rooted app or a thief. Here is the mechanism in detail.

#### Task snapshots and where they live

When a task leaves the foreground (Home, Recents, switching apps, the screen turning off), `system_server` captures a **task snapshot**: a bitmap of the task's windows used to draw the Recents card and to animate the task back in. The snapshot is kept in memory and persisted to the credential-encrypted system directory of the user, so it survives reboots and app process death. In AOSP the directory is `snapshots` under `Environment.getDataSystemCeDirectory()`, which is:

```text
/data/system_ce/<userId>/snapshots/<taskId>.jpg           high-resolution snapshot
/data/system_ce/<userId>/snapshots/<taskId>_reduced.jpg   low-resolution copy
/data/system_ce/<userId>/snapshots/<taskId>.proto         metadata (orientation, insets, mode)
```

From Android 14, AOSP also has an `activity_snapshots` directory next to it, used for per-activity snapshots in transitions such as predictive back (in Android 14 behind a debug property; enabled by default in current AOSP except on low-RAM devices, and without the `_reduced` copy). Older devices without file-based encryption used `/data/system/…`, and some OEMs use their own folder names (`recent_images` is the common one). The files belong to the `system` user: you need root to read them, which is why OWASP's test is filesystem-based and run on a rooted device or emulator. They are deleted when the task is removed from Recents and overwritten on the next snapshot.

The important property for testers: when the snapshot should not show the content, the system does not skip the file. It writes an **app-theme snapshot** instead, a blank frame in the window's background colour (AOSP's `SNAPSHOT_MODE_APP_THEME`). AOSP chooses it when the activity has disabled Recents screenshots, or when any of its windows is "secure locked", which covers `FLAG_SECURE`, Android 15's sensitive-content protection during projection, and a device policy that disables screen capture. So a passing app still produces files; you judge them by looking at them.

#### FLAG_SECURE

[`WindowManager.LayoutParams.FLAG_SECURE`](https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE) (value `0x2000`, 8192 in decompiled code) is a window flag: *"treat the content of the window as secure, preventing it from appearing in screenshots or from being viewed on non-secure displays."* WindowManager marks the window's surface as secure, and SurfaceFlinger refuses to composite secure layers into any capture or display that is not itself secure. In practice, with the flag set:

- the system screenshot is refused (the user sees a message that the app or the organisation does not allow screenshots; the wording varies by OEM);
- `adb exec-out screencap`, `adb shell screenrecord`, the built-in screen recorder, `MediaProjection` sessions (screen sharing, casting to non-secure displays) and accessibility screenshots show the window as black ([MASTG-TECH-0178](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0178/) confirms this for the `screencap` path);
- the Recents card shows an app-theme snapshot.

Apps set it with `window.addFlags(FLAG_SECURE)` or `window.setFlags(FLAG_SECURE, FLAG_SECURE)`, normally before `setContentView()`. It can be set later and takes effect immediately. It is removed with `clearFlags(FLAG_SECURE)` or `setFlags(0, FLAG_SECURE)`; `addFlags(x)` is literally `setFlags(x, x)` and `clearFlags(x)` is `setFlags(0, x)`, which is useful when hooking. It can also arrive through `window.setAttributes(params)` or a `WindowManager.addView(view, params)` call with the bit set in `params.flags`.

What it does **not** do:

- It does not hide content from accessibility services' view of the UI tree ([MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/)).
- It does not stop overlays, tapjacking or a camera pointed at the screen.
- It does not cover the **input method window**. The keyboard is its own window owned by the IME; Android's fraud-prevention page notes that on Android 11 and lower, keyboard taps can be recorded on some devices even with the flag set.
- It does not apply to **other windows** of the same app unless they set it too (see below).
- It does not stop a debuggable build or a test device from being reconfigured: on debuggable Android builds (emulators without Play Store, `userdebug`), Android 15 and later honour `adb shell settings put secure disable_secure_windows 1`, which makes every window non-secure. That is a lab convenience for collecting evidence, not an attack on production devices.

#### Windows that FLAG_SECURE on the activity does not cover

Each of the following has its own window or surface. Check every one that can show sensitive data:

| Component | Separate window? | How to protect it |
|---|---|---|
| `Dialog`, `AlertDialog`, `DialogFragment`, `BottomSheetDialog` | Yes (`TYPE_APPLICATION`, a sibling of the activity window, not a child) | `dialog.window?.addFlags(FLAG_SECURE)` before `show()` |
| `PopupWindow`, `Spinner` dropdowns, `AutoCompleteTextView` suggestions, `ListPopupWindow`, `PopupMenu` | Yes (a panel sub-window attached to the activity window) | Child surfaces inherit secure state on Android 12+ in AOSP; on older versions or OEM builds, verify dynamically; `PopupWindow` exposes no public flag setter, so avoid putting secrets in popups |
| Compose `Dialog`, `AlertDialog`, `Popup`, `DropdownMenu`, Material 3 `ModalBottomSheet` | Yes | `DialogProperties(securePolicy = SecureFlagPolicy.SecureOn)`, `PopupProperties(securePolicy = …)`, `ModalBottomSheetProperties(securePolicy = …)` |
| `SurfaceView`, `GLSurfaceView`, `VideoView` (a `SurfaceView` subclass), CameraX `PreviewView` in its default performance mode, Media3 `PlayerView` with the default surface type, Flutter's default `FlutterSurfaceView` | Separate surface | `surfaceView.setSecure(true)` before attach; for players, get the surface view from the player view and set it |
| `TextureView` | No: drawn into the window | Covered by the window's flag |
| `Toast` | Text toasts are rendered by System UI, not by the app | Do not put sensitive data in toasts |
| Notifications, widgets, Quick Settings tiles | System UI | Out of scope here; see [MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/) |
| The keyboard (IME) | IME's window | Use password input types so key previews and suggestions are suppressed; see [MASWE-0036](/mobile/maswe-0036-sensitive-data-exposed-via-ui/) |

Why Android 12 matters for child surfaces: in AOSP's SurfaceFlinger up to Android 11, `Layer::isSecure()` returned only the layer's own secure flag. From Android 12 it also returns true if any parent layer is secure, and the newer front end computes `isSecure = parent.isSecure || own flag`. So a `SurfaceView` inside a `FLAG_SECURE` window is protected on current AOSP releases without `setSecure`, but was not on Android 11 and earlier. Apps with a `minSdkVersion` below 31 that rely on inheritance are exposed on older devices. Dialogs are not children of the activity window in either model, which is why they always need their own flag.

#### setRecentsScreenshotEnabled (API 33)

[`Activity.setRecentsScreenshotEnabled(boolean)`](https://developer.android.com/reference/android/app/Activity#setRecentsScreenshotEnabled%28boolean%29), added in Android 13: *"If set to false, this indicates to the system that it should never take a screenshot of the activity to be used as a representation in recents screen. By default, this value is true."* The documentation is explicit about the scope: compared with `FLAG_SECURE`, it *"only affects the behavior when the activity's screenshot would be used as a representation when the activity is not in a started state, i.e. in Overview. The system may still take screenshots of the activity in other contexts; for example, when the user takes a screenshot of the entire screen, or when the active VoiceInteractionService requests a screenshot."* It is the right tool when users must be able to screenshot a screen (a payment receipt) but the screen should not sit in Recents; it is not a substitute for `FLAG_SECURE` on screens that must not be captured at all. It is a per-activity setting, so every sensitive activity needs it (a base class or `ActivityLifecycleCallbacks` is the usual way), and on API 32 and lower it does not exist.

#### setContentSensitivity (API 35)

[`View.setContentSensitivity(int)`](https://developer.android.com/reference/android/view/View#setContentSensitivity%28int%29), added in Android 15, marks a view as displaying sensitive content: *"The window hosting a sensitive view will be marked as secure during an active media projection session. This would be equivalent to applying FLAG_SECURE to the window."* Values are `CONTENT_SENSITIVITY_AUTO` (default; the framework decides, and in current AOSP that heuristic looks at sensitive autofill hints such as passwords), `CONTENT_SENSITIVITY_SENSITIVE` and `CONTENT_SENSITIVITY_NOT_SENSITIVE`. This is aimed squarely at screen-sharing fraud: the screen stays screenshot-able in normal use, but disappears from a projection while the sensitive view is visible. It does not affect user screenshots or the Recents thumbnail.

### Android: User-Initiated Screenshots and Screen Recording (MASTG-KNOW-0105)

Source: [MASTG-KNOW-0105](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0105/). **OWASP placeholder**: the page currently has no content beyond its title. The following is Guler Tech methodology.

The user can capture the screen in several ways, all handled by the system rather than an app, and all honour `FLAG_SECURE`:

- **Screenshots**: Power + Volume Down on AOSP, plus OEM gestures (palm swipe, three-finger swipe, knuckle tap), the screenshot button in the Recents screen, and assistant features that capture the current screen. Screenshots are saved through MediaStore to shared storage, by default `Pictures/Screenshots/` (some OEMs use `DCIM/Screenshots/`).
- **Screen recording**: the built-in recorder in Quick Settings (AOSP from Android 11; many OEMs earlier). Recordings go to shared storage as video files. The recorder uses `MediaProjection` internally.
- **Casting and mirroring**: Cast to a TV, Miracast, or a manufacturer's "link to PC" feature, all of which render to a non-secure virtual display.
- **Developer tools**: with USB debugging enabled, `adb exec-out screencap -p`, `adb shell screenrecord`, Android Studio's screen capture, and mirroring tools built on the shell user. These need someone with the device unlocked and debugging authorised.

Once a screenshot exists, the app has lost control of it. It sits in shared media storage where any app with `READ_MEDIA_IMAGES` (Android 13+) or `READ_EXTERNAL_STORAGE` (older) can read it, or the subset the user picks with partial photo access (`READ_MEDIA_VISUAL_USER_SELECTED`, Android 14). It is commonly backed up to a cloud photo service automatically. This is the route behind MAS-ATTACK-0010.

The user taking a screenshot of their own data is not, by itself, an attack. It becomes one when the user is manipulated into doing it (a scammer asking for a screenshot of the "verification code" screen) or when the screenshot is later reached by someone else. That is why OWASP limits the weakness to L2 apps, and why the right answer for most screens is masking plus `FLAG_SECURE` only where the content is genuinely high-value.

### Android: App-Initiated Screenshots and Screen Recording (MASTG-KNOW-0106)

Source: [MASTG-KNOW-0106](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0106/). **OWASP placeholder**: no content yet. The following is Guler Tech methodology.

An ordinary app cannot read another app's pixels. To capture the screen it needs one of two user-granted capabilities:

**MediaProjection.** The app calls `MediaProjectionManager.createScreenCaptureIntent()` and the system shows a consent dialog. If the user agrees, the app receives a `MediaProjection` and creates a virtual display (usually backed by an `ImageReader` for frames or a `MediaRecorder`/`MediaCodec` for video). Versions matter:

| Android version | Change |
|---|---|
| 10 (API 29) | Apps targeting API 29+ must run the capture in a foreground service with `android:foregroundServiceType="mediaProjection"` |
| 14 (API 34) | For apps targeting API 34+, consent is required for each capture session; the consent intent cannot be reused and `createVirtualDisplay` can be called only once per `MediaProjection`. The foreground service needs `FOREGROUND_SERVICE_MEDIA_PROJECTION` |
| 14 QPR2 and 15 | **App screen sharing**: the user can share a single app window instead of the whole screen |
| 15 QPR1 | A status bar chip shows any ongoing projection and lets the user stop it; projection stops automatically when the device locks |
| 15 (API 35) | Windows hosting views marked with `setContentSensitivity(SENSITIVE)` are treated as secure during projection |

Every `FLAG_SECURE` window is black in the projection. Screen-sharing features of video-call apps and "remote support" apps use exactly this API, which is why the flag is the main control against screen-sharing fraud.

**Accessibility services.** A service that declares `android:canTakeScreenshot="true"` can call `AccessibilityService.takeScreenshot()` (API 30) or `takeScreenshotOfWindow()` (API 34). Secure windows are excluded: the documentation defines `ERROR_TAKE_SCREENSHOT_SECURE_WINDOW` for a window that "contains secure content". Banking malware with an accessibility service does not need screenshots to steal data, though, because it can read the node tree; that is [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/).

**Privileged and root paths.** System components with signature-level permissions, an attacker with root, or `adb` can capture differently. Root also gives direct access to the `/data/system_ce/…/snapshots` files. These are outside what an app can defend against beyond not displaying the data.

### Android: Screenshots and Screen Recording Detection (MASTG-KNOW-0107)

Source: [MASTG-KNOW-0107](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0107/). **OWASP placeholder**: no content yet. The following is Guler Tech methodology, based on the [Android 14 screenshot detection](https://developer.android.com/about/versions/14/features/screenshot-detection) and [Android 15 features](https://developer.android.com/about/versions/15/features#screen-recording-detection) pages.

**Screenshot detection, Android 14 (API 34).** The app declares the install-time (normal) permission `android.permission.DETECT_SCREEN_CAPTURE`, creates an `Activity.ScreenCaptureCallback` (one method, `onScreenCaptured()`), registers it with `registerScreenCaptureCallback(executor, callback)` in `onStart()` and unregisters it with `unregisterScreenCaptureCallback(callback)` in `onStop()`. Properties:

- It fires only while that activity is visible, and the system shows the user a notice that the app detected the screenshot.
- It does not provide the image.
- In Android 14 it detects only screenshots taken with the hardware button combination. It does not fire for `adb` or instrumentation captures, and it is not a screen-recording detector.
- It does not prevent anything. The screenshot has been taken.

**Screen recording detection, Android 15 (API 35).** The app declares `android.permission.DETECT_SCREEN_RECORDING` (normal) and calls `windowManager.addScreenRecordingCallback(executor, consumer)` in `onStart()`, which returns the current state (`SCREEN_RECORDING_STATE_VISIBLE` or `SCREEN_RECORDING_STATE_NOT_VISIBLE`) and invokes the `Consumer<Integer>` whenever the app becomes visible or invisible in a recording. "Visible" means any activity owned by the registering process's UID is being recorded. Remove it with `removeScreenRecordingCallback` in `onStop()`. Use it to warn the user or hide sensitive views while recorded.

**Older heuristics.** Before Android 14, apps detected screenshots by watching MediaStore for new files in a `Screenshots` folder (a `ContentObserver` on `MediaStore.Images.Media.EXTERNAL_CONTENT_URI` or a `FileObserver`). This needs storage or media permission, depends on OEM folder names, and fires after the fact. Treat its presence as a privacy question (why does a banking app read the photo library?) rather than a protection.

For this weakness, detection is at most a transparency feature. An app that relies on it and does not set `FLAG_SECURE` on high-value screens fails the tests below.

### iOS: Screenshots (MASTG-KNOW-0099)

Source: [MASTG-KNOW-0099](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0099/). OWASP describes the snapshot taken when the app enters the background, its location in the app container, and the usual overlay fix. In more detail:

#### When the snapshot is taken

Apple's [Preparing your UI to run in the background](https://developer.apple.com/documentation/uikit/preparing-your-ui-to-run-in-the-background) is the reference: *"After your app enters the background and your delegate method returns, UIKit takes a snapshot of your app's current user interface. The system displays the resulting image in the app switcher. It also displays the image temporarily when bringing your app back to the foreground. Your app's UI must not contain any sensitive user information, such as passwords or credit card numbers."* The delegate method is:

- `sceneDidEnterBackground(_:)` on the `UISceneDelegate` for apps that use scenes (the default since iOS 13, and the only lifecycle for SwiftUI apps); UIKit calls only the scene delegate when one exists;
- [`applicationDidEnterBackground(_:)`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/applicationdidenterbackground%28_:%29) on the app delegate for apps without scenes.

Before that, the app is **deactivated** (`sceneWillResignActive(_:)` / `applicationWillResignActive(_:)`), which also happens without backgrounding: when the user opens the App Switcher or Control Centre, pulls down Notification Centre, when a system alert or a phone call appears, and when a Face ID or Touch ID prompt from `LocalAuthentication` is shown. The App Switcher card is visible while the app is only inactive, so a cover added only in `didEnterBackground` leaves the content visible in the switcher for that moment. Covering on resign-active fixes that, but then the cover also appears during biometric prompts; remove it in `sceneDidBecomeActive(_:)`.

Apple also asks apps to dismiss alerts and temporary interfaces before the snapshot, because they would otherwise appear in it. With state preservation, *"removing sensitive data also prevents that information from being saved in your app's preservation archive."*

Two APIs are often mistaken for protections:

- [`UIApplication.ignoreSnapshotOnNextApplicationLaunch()`](https://developer.apple.com/documentation/uikit/uiapplication/ignoresnapshotonnextapplicationlaunch%28%29) only tells UIKit to show the launch screen instead of the snapshot at the next launch. It does not stop the snapshot being taken or stored.
- SwiftUI's `.privacySensitive()` redacts views when the system sets the `.privacy` redaction reason (for example widgets on a locked device). It does not, on its own, hide the view from the App Switcher snapshot.

#### Where the snapshot is stored

Inside the app's data container, which also means it is readable by anything with access to the container (a jailbreak, a forensic extraction, a sandbox escape):

```text
/var/mobile/Containers/Data/Application/<container UUID>/Library/SplashBoard/Snapshots/sceneID:<bundle id>-default/
```

OWASP writes the last component as `sceneID:$APP_NAME-default`; on the devices we have seen, and in forensic write-ups, it is the **bundle identifier** (for example `sceneID:com.example.app-default`), and apps with several scenes get several folders. The layout has changed across releases: older versions (around iOS 10 to 12) used `Library/Caches/Snapshots/<bundle id>/`, and OWASP notes the path may vary again. The files are **KTX** texture files (Apple-specific, often compressed), commonly with `@2x`/`@3x` in the name, and there can be separate light- and dark-mode versions plus a `downscaled` subfolder. Some macOS versions render them in Quick Look or Preview; otherwise use a KTX-aware forensic converter. Snapshots are replaced each time the app is backgrounded, so what you find is the last screen per scene and appearance. Whether they appear in a device backup depends on the iOS version and backup type; check with the backup method in the [STORAGE guide](/mobile/masvs-storage-1-secure-storage-guide/) rather than assuming.

#### Hiding content before the snapshot

The common implementations, from weakest to strongest:

1. Hide or clear the sensitive fields (`isHidden = true`, replace text with placeholders) on resign-active, restore on become-active.
2. Add a full-screen opaque view (a copy of the launch screen, a logo on a solid background) to the key window on resign-active. Adding it to the window, not to one controller's view, makes it cover navigation and tab bars; it may still sit below a view controller presented afterwards.
3. Show a separate `UIWindow` at a high `windowLevel` (above `.alert`) containing the cover. This covers presented controllers and alerts and is the pattern we recommend (see [Secure patterns for iOS](#secure-patterns-for-ios-guler-tech)).

A blur (`UIVisualEffectView`) is popular but not a reliable cover: large, high-contrast digits such as a balance often stay legible through it. Use an opaque view for high-value screens.

### iOS: Screen capture detection and the secure-field technique (supplementary)

OWASP has no iOS Knowledge page for live capture, so we add one. The key point first: **iOS has no public equivalent of `FLAG_SECURE`.** An app cannot stop the user taking a screenshot or starting a screen recording. What it can do is detect capture and hide content.

**Screenshots: detect only.** [`UIApplication.userDidTakeScreenshotNotification`](https://developer.apple.com/documentation/uikit/uiapplication/userdidtakescreenshotnotification) (iOS 7) *"posts after the screenshot is taken"*, with no `userInfo`. It is useful for telling the user ("This screen contains your card number; delete the screenshot if you did not mean to take it") or for messaging apps that notify the other party. It never prevents anything.

**Recording, mirroring, AirPlay: detect and hide.** [`UIScreen.isCaptured`](https://developer.apple.com/documentation/uikit/uiscreen/iscaptured) (iOS 11) is true when *"the system is actively recording, mirroring, or using AirPlay to stream the contents of the screen"*, and `UIScreen.capturedDidChangeNotification` posts when it changes. Since iOS 17 the per-scene equivalent is the trait [`UITraitCollection.sceneCaptureState`](https://developer.apple.com/documentation/uikit/uitraitcollection/scenecapturestate) (`UISceneCaptureState.active`, `.inactive`, `.unspecified`), observable with `registerForTraitChanges([UITraitSceneCaptureState.self], …)`. Apple's documentation marks `isCaptured` as deprecated in iOS 27 with the note *"Use the sceneCaptureState in UITraitCollection instead"*; it still works, but new code should use the trait with a fallback for older iOS. Note what capture state does not tell you: it says nothing about single screenshots, and a third-party broadcast extension (ReplayKit screen sharing to a video-call app) shows up as capture like any other recording.

**Protected video.** Apple documents that FairPlay Streaming–protected video is blacked out in recordings, mirroring and AirPlay (audio is not). That protects DRM video, not arbitrary UI.

**The secure text field technique (unofficial).** A widely shared trick places sensitive content inside the internal container view of a `UITextField` whose `isSecureTextEntry` is `true`. iOS excludes the contents of secure text entry from screenshots and recordings, and anything rendered inside that container appears to inherit the exclusion. Several open-source "screen shield" libraries are built on it. Treat it as what it is:

- It relies on the undocumented internal view hierarchy of `UITextField`, which Apple has changed between iOS releases; implementations have broken on major updates and needed fixes.
- It is not a documented or supported API, so Apple can change the behaviour at any time without notice.
- It complicates layout, hit-testing and accessibility, and can interfere with VoiceOver.
- Its effect on the App Switcher snapshot is not guaranteed; you still need the snapshot cover.

If an app uses it, test it on every iOS major version in scope (GT-0038-1) and report it as an observation if it is the only control. Do not recommend it as the primary fix.

## Tests

OWASP has six tests for this weakness, all filed under MASWE-0038: five for Android, one for iOS. Three of the Android ones (0292, 0293, 0294) are **placeholders** without content; we write them below as Guler Tech methodology, using OWASP's demo titles where a demo exists. We add two tests of our own: a live-capture check for both platforms (OWASP's dynamic tests only cover backgrounding) and a static review for iOS (OWASP has none).

These tests replace two legacy MASTG v1 tests, both deprecated:

| Legacy test | Platform | Title | Replaced by |
|---|---|---|---|
| [MASTG-TEST-0010](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0010/) | Android | Finding Sensitive Information in Auto-Generated Screenshots | MASTG-TEST-0289, MASTG-TEST-0291 |
| [MASTG-TEST-0059](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0059/) | iOS | Testing Auto-Generated Screenshots for Sensitive Information | MASTG-TEST-0290 |

### Before you start: identify the sensitive screens

OWASP's dynamic tests have a prerequisite, *identify sensitive screens*, that builds on its general *identifying sensitive data* guidance (data at rest, in use and in transit, and a default list of what counts as sensitive when the client has no classification policy). Do it properly, because every evaluation below depends on it. Walk the app and list each screen, dialog, sheet and popup that shows any of:

- credentials, PINs, passcodes, one-time codes, transaction-signing codes, recovery or backup codes;
- full card numbers, CVV, expiry, full account numbers and IBANs, balances and transactions;
- recovery phrases, private keys, QR codes that encode secrets or payment authorisations;
- identity documents, selfies and liveness captures, health data, messages;
- anything the client's data classification marks as confidential.

Record for each: the activity or view controller (from `adb shell dumpsys activity activities | grep -E "mResumedActivity|topResumedActivity"` on Android, from the UI or Frida on iOS), how you reach it, and whether it is a separate window (dialog, bottom sheet, popup) or a `SurfaceView` (camera, video). Agree with the client which screens are in scope as "must not be captured" versus "must not be in Recents only" (receipts the user is expected to screenshot). That table is your evaluation baseline.

### MASTG-TEST-0289: Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding (Android)

Source: [MASTG-TEST-0289](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0289/). Platform: Android. Type: dynamic, filesystem, manual. Knowledge: MASTG-KNOW-0053. Best practice: MASTG-BEST-0014. Replaces part of legacy MASTG-TEST-0010.

#### Overview

The test backgrounds the app on each sensitive screen and collects the task snapshots the system wrote, then inspects them. It answers one question: does the Recents representation of the app ever contain sensitive data? It does not test live screenshots or recording (see GT-0038-1).

#### Prerequisites

- Your list of sensitive screens.
- A rooted device or an emulator image that allows `adb root` (a "Google APIs" image, not "Google Play"), for reading `/data/system_ce`. Without root you can still collect evidence of the Recents screen itself (step 3).
- `adb` ([MASTG-TOOL-0004](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/)) and host-device transfer as in [MASTG-TECH-0002](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/).
- Test on the oldest and newest Android versions in scope: `setRecentsScreenshotEnabled` only exists from API 33, and child-surface behaviour changed at API 31.

#### Steps

1. **Start clean** so old snapshots do not confuse you. Clear the app's task from Recents (swipe it away), then confirm the directory has no file for it later.

   ```bash
   adb root                                   # emulator / userdebug; on a rooted phone use su -c below
   adb shell ls -l /data/system_ce/0/snapshots/ /data/system_ce/0/activity_snapshots/ 2>/dev/null
   ```

2. **For each sensitive screen**, open it, wait until the data is shown, then send the app to the background and open Recents:

   ```bash
   adb shell input keyevent KEYCODE_HOME
   adb shell input keyevent KEYCODE_APP_SWITCH
   ```

   Also try the paths users take: the Recents gesture straight from the sensitive screen, switching directly to another app, and turning the screen off (`adb shell input keyevent KEYCODE_POWER`). Note the time and screen name.

3. **Capture the Recents screen itself.** The launcher's Recents view is not a secure window, so a screenshot of it shows the thumbnails exactly as a person holding the phone would see them. This needs no root and is the best evidence for a report:

   ```bash
   adb exec-out screencap -p > recents_<screen>.png
   ```

4. **Map task IDs to the app**, so you know which snapshot files are yours:

   ```bash
   adb shell dumpsys activity recents | grep -E "Recent #|com.example.app"
   ```

   The number after `#` in the matching `Task{… #<taskId> …}` entry is the task ID used as the file name.

5. **Pull the snapshot files** ([MASTG-TECH-0002](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/)):

   ```bash
   # emulator / adb root
   adb pull /data/system_ce/0/snapshots/ ./snapshots/
   adb pull /data/system_ce/0/activity_snapshots/ ./activity_snapshots/ 2>/dev/null

   # rooted physical device (Magisk): copy out through shared storage
   adb shell su -c 'cp -r /data/system_ce/0/snapshots /sdcard/gt-snapshots && chmod -R a+r /sdcard/gt-snapshots'
   adb pull /sdcard/gt-snapshots ./snapshots/
   adb shell rm -r /sdcard/gt-snapshots
   ```

   If the directory does not exist, search for the OEM's name for it: `adb shell su -c 'find /data/system_ce/0 /data/system -maxdepth 1 \( -iname "*snapshot*" -o -iname "recent*" \)'`. Use user ID 10 (or whichever `adb shell pm list users` shows) for work profiles and secondary users.

6. **Open each `<taskId>.jpg` and `<taskId>_reduced.jpg`** for the app's tasks and compare with the screen you left.

#### Observation

The Recents screenshots from step 3, the snapshot files for the app's task IDs with their timestamps, and a table mapping each sensitive screen to what its snapshot shows: the content, or a blank app-theme frame.

#### Evaluation

The test **fails** if any snapshot, or the Recents screen, shows data from your sensitive-screen list that the agreed baseline says must not be retained: card numbers, codes, balances, recovery phrases, documents, and so on. Partially visible data counts if it is legible.

It **passes** if every sensitive screen produces an app-theme (blank) snapshot or a snapshot showing only non-sensitive content (a logo, a masked value), on every Android version tested.

Common false positives and pitfalls:

- A snapshot taken from a non-sensitive screen you visited before or after the sensitive one. Check the timestamps and go one screen at a time.
- Snapshots from another task of the same app (a separate task for a share target or a document-style activity).
- A blank snapshot on a device where you had set `disable_secure_windows` or a developer option earlier; reset the device state between runs.
- A thumbnail that shows content because the sensitive data is in a dialog over a protected activity: that is a real failure (the dialog's window is not secure), not a test artefact.

#### Demo

OWASP has no demo for this test. A minimal failing case is an activity that shows card details without any protection:

```kotlin
class CardDetailsActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_card_details)    // full PAN, expiry, CVV
        // no FLAG_SECURE, no setRecentsScreenshotEnabled(false)
    }
}
```

After backgrounding it on an emulator (illustrative listing):

```text
$ adb shell ls -l /data/system_ce/0/snapshots/
-rw------- 1 system system  60212 2026-11-09 20:41 87.jpg
-rw------- 1 system system    203 2026-11-09 20:41 87.proto
-rw------- 1 system system  14710 2026-11-09 20:41 87_reduced.jpg
```

`87.jpg` shows the full card number: the test fails. Adding `window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)` before `setContentView` and repeating produces a much smaller `87.jpg` that is a plain frame in the theme's background colour.

### MASTG-TEST-0291: References to Screen Capturing Prevention APIs (Android)

Source: [MASTG-TEST-0291](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0291/). Platform: Android. Type: static (code). Knowledge: MASTG-KNOW-0053. Best practice: MASTG-BEST-0014. Demo: [MASTG-DEMO-0061](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0061/MASTG-DEMO-0061/). Replaces part of legacy MASTG-TEST-0010.

#### Overview

The test looks for where the app sets `FLAG_SECURE`, and just as importantly where it clears it, and checks that every sensitive screen is covered. OWASP lists the failure modes: the flag missing on some sensitive screens, or cleared during transitions with `clearFlags()` or `setFlags()`.

#### Prerequisites

- The APK decompiled with jadx ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/), [jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)):

  ```bash
  jadx -d out/ app-release.apk
  ```

- semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)) and grep ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)).
- Your sensitive-screen list, with class names.
- Optionally Frida ([MASTG-TOOL-0031](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/)) for runtime confirmation.

#### Steps

1. **Run OWASP's rule** (`mastg-android-sensitive-data-in-screenshot.yml`), which flags `addFlags(…)` and `setFlags(x, x)` calls whose argument is `FLAG_SECURE`, `8192` or `0x2000`:

   ```bash
   semgrep -c rules/mastg-android-sensitive-data-in-screenshot.yml out/sources/
   ```

2. **Add the cases the OWASP rule does not cover.** Its regex is anchored, so it misses a qualified constant (`WindowManager.LayoutParams.FLAG_SECURE` in source-level reviews), combined masks (`setFlags(8320, 8320)` for `FLAG_SECURE | FLAG_KEEP_SCREEN_ON`), `setAttributes`, and every call that removes the flag. Our supplementary rules:

   ```yaml
   rules:
     - id: gt-android-flag-secure-cleared
       languages: [java, kotlin]
       severity: WARNING
       message: FLAG_SECURE is removed here. Check which screens are shown afterwards.
       pattern-either:
         - patterns:
             - pattern: $W.clearFlags($F)
             - metavariable-regex:
                 metavariable: $F
                 regex: ^((.*\.)?FLAG_SECURE|8192|0x2000)$
         - patterns:
             - pattern: $W.setFlags(0, $F)
             - metavariable-regex:
                 metavariable: $F
                 regex: ^((.*\.)?FLAG_SECURE|8192|0x2000)$
     - id: gt-android-flag-secure-set-qualified
       languages: [java, kotlin]
       severity: INFO
       message: FLAG_SECURE set via a qualified constant.
       pattern-either:
         - patterns:
             - pattern: $W.addFlags($F)
             - metavariable-regex:
                 metavariable: $F
                 regex: ^(.*\.)?FLAG_SECURE$
         - patterns:
             - pattern: $W.setFlags($F, $M)
             - metavariable-regex:
                 metavariable: $F
                 regex: ^(.*\.)?FLAG_SECURE$
     - id: gt-android-window-attributes
       languages: [java, kotlin]
       severity: INFO
       message: Window attributes set directly. Check params.flags for 0x2000.
       pattern-either:
         - pattern: $W.setAttributes($P)
         - pattern: $WM.addView($V, $P)
   ```

   ```bash
   semgrep -c gt-flag-secure.yml out/sources/
   ```

3. **Catch combined numeric masks.** jadx folds constants into decimals, so list every literal passed to `addFlags`/`setFlags` and keep those with bit `0x2000` set:

   ```bash
   grep -rhoE '(addFlags|setFlags)\(-?[0-9]+' out/sources/ | grep -oE -e '-?[0-9]+$' | sort -u |
     python3 -c 'import sys; [print(v) for v in (l.strip() for l in sys.stdin) if int(v) & 0x2000]'
   ```

   Then grep for each value printed to find the call sites.

4. **Find central mechanisms.** Many apps set the flag once for every activity:

   ```bash
   grep -rnE 'registerActivityLifecycleCallbacks|onActivityCreated|onActivityPreCreated' out/sources/ | grep -v '^out/sources/androidx/'
   grep -rnlE 'extends (AppCompatActivity|FragmentActivity|ComponentActivity|Activity) ' out/sources/ | xargs grep -lE 'addFlags\(8192|setFlags\(8192'
   ```

   A base activity that sets the flag protects only the activities that extend it. List the sensitive activities from your table (and from the manifest) and check each one's superclass chain in jadx.

5. **Look for conditions and switches.** Open each call site and note what gates it: `BuildConfig.DEBUG`, a `SharedPreferences` value ("allow screenshots"), a remote-config flag, an intent extra. A user-facing toggle is acceptable if it defaults to protected on sensitive screens; a remote flag that can turn protection off for everyone deserves a note.

6. **Cover the other windows.** For each sensitive dialog on your list, find where it is created (`AlertDialog.Builder`, `Dialog(`, `DialogFragment.onCreateDialog`, `BottomSheetDialog(`) and check for `getWindow().addFlags(8192)` or equivalent on that dialog. Compose dialogs, `SurfaceView` and Recents-only protection have their own tests below.

7. **Confirm at runtime** that the flag is set on the windows you care about and not cleared later. This Frida script logs every change to the secure bit with a stack trace:

   ```javascript
   // flagsecure-trace.js
   Java.perform(() => {
     const FLAG_SECURE = 0x2000;
     const Window = Java.use('android.view.Window');
     const Log = Java.use('android.util.Log');
     const Exception = Java.use('java.lang.Exception');
     const where = (w) => w.getContext().getClass().getName();

     Window.setFlags.implementation = function (flags, mask) {
       if ((mask & FLAG_SECURE) !== 0) {
         const state = (flags & FLAG_SECURE) !== 0 ? 'SET' : 'CLEARED';
         console.log('[FLAG_SECURE ' + state + '] ' + where(this));
         console.log(Log.getStackTraceString(Exception.$new()));
       }
       return this.setFlags(flags, mask);
     };
     Window.setAttributes.implementation = function (attrs) {
       console.log('[setAttributes] secure=' + ((attrs.flags.value & FLAG_SECURE) !== 0) + ' ' + where(this));
       return this.setAttributes(attrs);
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l flagsecure-trace.js
   ```

   And check the live window state while each sensitive screen or dialog is open. Current versions of `dumpsys window` print each window's flags by name, and `SECURE` appears in the `fl=` line when the flag is set (if an older device prints a hex mask instead, bit `0x2000` is `FLAG_SECURE`):

   ```bash
   adb shell dumpsys window windows | grep -E "Window #|fl="
   ```

#### Observation

A list of call sites that set or clear `FLAG_SECURE`, with class and method, the mechanism (per activity, base class, lifecycle callback), the conditions around them, a mapping from each sensitive screen and dialog to the protection that covers it, and the runtime log or `dumpsys` output confirming it.

#### Evaluation

The test **fails** if any sensitive screen or sensitive dialog is not covered by `FLAG_SECURE` (and is not intentionally covered by a weaker, agreed control such as Recents-only protection for receipts), or if a code path clears the flag while sensitive content is shown without a documented reason.

It **passes** if every sensitive window gets the flag before it shows data, nothing removes it while it is needed, and the runtime check agrees.

A semgrep hit is a locator, not a verdict: OWASP's own demo passes because it finds one `addFlags(8192)`, but one call proves only that one window is protected. Conversely, no hits in app code can still be a pass if a library or a lifecycle callback sets the flag; the runtime check decides.

#### Demo

[MASTG-DEMO-0061](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0061/MASTG-DEMO-0061/) sets the flag on the activity that shows sensitive data:

```kotlin
if (context is Activity) {
    context.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
}
```

In the decompiled code the constant is folded to its value, which is why the rule matches `8192`:

```java
((Activity) this.context).getWindow().addFlags(8192);
```

```text
┌────────────────┐
│ 1 Code Finding │
└────────────────┘

    MastgTest_reversed.java
     ❱ rules.mastg-android-flag-secure-enable-flags
          [MASVS-PLATFORM] Make sure you use this flag for all screens with sensitive data

           32┆ ((Activity) this.context).getWindow().addFlags(8192);
```

OWASP evaluates this as a pass. In a real app, you would now check the remaining sensitive screens and every dialog they open.

### MASTG-TEST-0292: setRecentsScreenshotEnabled Not Used to Prevent Screenshots When Backgrounded (Android)

Source: [MASTG-TEST-0292](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0292/). Platform: Android. Type: static (code). Knowledge: MASTG-KNOW-0053. Best practices: MASTG-BEST-0014, MASTG-BEST-0015. Demo: [MASTG-DEMO-0062](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0062/MASTG-DEMO-0062/) (placeholder, "Enabling Screenshots in Recents via setRecentsScreenshotEnabled with semgrep").

> **Note:** MASTG-TEST-0292 is an OWASP **placeholder**: the page has a title and a one-line note ("verifies whether an app prevents sensitive data from being captured in the Recents screen when backgrounded") but no procedure. The test below is **Guler Tech methodology**.

#### Overview

For screens where screenshots are acceptable but the Recents thumbnail is not, Android 13 gives you `setRecentsScreenshotEnabled(false)`. The test checks that sensitive activities which do not use `FLAG_SECURE` call it, that nothing turns it back on, and that the app has an answer for API 32 and lower. If an activity already has `FLAG_SECURE`, its Recents snapshot is already blank and this test is satisfied for that activity.

#### Prerequisites

- Decompiled sources (jadx), semgrep, grep.
- The output of MASTG-TEST-0291: which sensitive activities lack `FLAG_SECURE`.
- `minSdkVersion` and `targetSdkVersion` from the manifest: `grep -E 'minSdkVersion|targetSdkVersion' out/resources/AndroidManifest.xml`, or `aapt dump badging app.apk | grep -E 'sdkVersion|targetSdkVersion'`.
- A device on Android 13 or later for confirmation, and one on 12 or lower if `minSdkVersion` allows it.

#### Steps

1. **Find all calls.** In decompiled code the call is often unqualified inside the activity class:

   ```yaml
   rules:
     - id: gt-android-recents-screenshot
       languages: [java, kotlin]
       severity: INFO
       message: setRecentsScreenshotEnabled call. false hides the Recents thumbnail; true restores it.
       pattern-either:
         - pattern: setRecentsScreenshotEnabled($V)
         - pattern: $A.setRecentsScreenshotEnabled($V)
   ```

   ```bash
   semgrep -c gt-recents.yml out/sources/
   grep -rn 'setRecentsScreenshotEnabled' out/sources/ | grep -v '^out/sources/androidx/'
   ```

2. **For each sensitive activity without `FLAG_SECURE`**, check that it (or its base class, or a lifecycle callback) calls `setRecentsScreenshotEnabled(false)`, and when: `onCreate` is right; calling it only in `onPause` or `onStop` races the snapshot.

3. **Look for re-enabling.** A `setRecentsScreenshotEnabled(true)` call, a variable argument that comes from settings or remote config, or a call guarded by a condition that is false in production.

4. **Check older Android.** The method only exists on API 33+, so calls are guarded by `Build.VERSION.SDK_INT >= 33` (in jadx, `>= 33`). If `minSdkVersion` is below 33, what protects the Recents thumbnail on older devices? Acceptable answers are `FLAG_SECURE` on those versions or an agreed risk acceptance. Setting `FLAG_SECURE` in `onPause` and clearing it in `onResume` is a common workaround; it is timing-dependent, so confirm it dynamically.

5. **Confirm dynamically** with MASTG-TEST-0289 on an Android 13+ device. Optionally hook the call to see it happen (the method only exists on Android 13 and later, so run this hook there):

   ```javascript
   Java.perform(() => {
     const Activity = Java.use('android.app.Activity');
     Activity.setRecentsScreenshotEnabled.implementation = function (enabled) {
       console.log('[setRecentsScreenshotEnabled] ' + enabled + ' on ' + this.getClass().getName());
       return this.setRecentsScreenshotEnabled(enabled);
     };
   });
   ```

#### Observation

The call sites with their argument and guard, the list of sensitive activities and which control covers their Recents representation on each supported API range, and the MASTG-TEST-0289 snapshots from an API 33+ device.

#### Evaluation

The test **fails** if a sensitive activity without `FLAG_SECURE` does not call `setRecentsScreenshotEnabled(false)` early in its lifecycle, if any path re-enables it while sensitive data is shown, or if the protection exists only for API 33+ while `minSdkVersion` is lower and nothing protects older devices. It **passes** if every sensitive activity has a blank Recents representation on all supported versions, through either API.

Remember the limit when you write it up: passing this test says nothing about screenshots and recording. If the screen must not be captured at all, MASTG-TEST-0291 is the relevant test.

#### Demo

OWASP's demo for this test is a placeholder. Our version of the case its title describes, an activity that turns Recents screenshots back on:

```kotlin
class StatementActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_statement)        // account number, transactions
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            setRecentsScreenshotEnabled(true)              // explicit opt-back-in "so Recents looks nice"
        }
    }
}
```

jadx output and the rule's finding (output illustrative):

```java
if (Build.VERSION.SDK_INT >= 33) {
    setRecentsScreenshotEnabled(true);
}
```

```text
    StatementActivity.java
     ❱ gt-android-recents-screenshot
          setRecentsScreenshotEnabled call. false hides the Recents thumbnail; true restores it.

           24┆ setRecentsScreenshotEnabled(true);
```

The activity shows account data, has no `FLAG_SECURE` and enables Recents screenshots explicitly: the test fails, and MASTG-TEST-0289 confirms it with a readable thumbnail. The fix is `setRecentsScreenshotEnabled(false)` on API 33+ and `FLAG_SECURE` below.

### MASTG-TEST-0293: setSecure Not Used to Prevent Screenshots in SurfaceViews (Android)

Source: [MASTG-TEST-0293](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0293/). Platform: Android. Type: static (code). Knowledge: MASTG-KNOW-0053. Best practices: MASTG-BEST-0014, MASTG-BEST-0017.

> **Note:** MASTG-TEST-0293 is an OWASP **placeholder** with no procedure ("verifies whether an app prevents sensitive data from being captured in screenshots and screen recordings of `SurfaceView` components"). The test below is **Guler Tech methodology**. OWASP's [MASTG-DEMO-0063](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0063/MASTG-DEMO-0063/) declares itself a demo for this test, but its title and note are about Compose dialogs and `SecureFlagPolicy`, which is MASTG-TEST-0294; we treat it as belonging to 0294.

#### Overview

A `SurfaceView` renders into its own surface, separate from the window's. Sensitive content commonly drawn there: a camera preview while scanning a payment card or an identity document, a video of a document, a rendered PDF in some viewers, an entire Flutter UI (Flutter's default Android renderer is a `SurfaceView`), game-engine and map views. `SurfaceView.setSecure(true)` marks that surface secure and, per the documentation, *"must be set before the surface view's containing window is attached to the window manager."* The test finds the surface views that show sensitive content and checks they are protected on every supported Android version.

#### Prerequisites

- Decompiled sources, semgrep, grep, Frida.
- Your sensitive-screen list, noting camera, video and custom-rendered screens.
- Devices on Android 11 or lower (if `minSdkVersion` allows) and 12 or higher: from Android 12, AOSP treats child surfaces of a secure window as secure, so a missing `setSecure` often only shows on older versions.

#### Steps

1. **Find surface views**, including subclasses and library views that use one internally:

   ```bash
   grep -rnE 'extends (SurfaceView|GLSurfaceView|VideoView)|new (SurfaceView|GLSurfaceView|VideoView)\(' out/sources/ | grep -v '^out/sources/android/'
   grep -rnE '<(SurfaceView|android\.view\.SurfaceView|VideoView|androidx\.camera\.view\.PreviewView|androidx\.media3\.ui\.PlayerView)' out/resources/res/layout/
   grep -rlE 'io/flutter/embedding/android/FlutterSurfaceView|io\.flutter\.embedding\.android\.FlutterSurfaceView' out/sources/ | head -1
   ```

   CameraX `PreviewView` uses a `SurfaceView` in its default `PERFORMANCE` implementation mode (a `TextureView` in `COMPATIBLE` mode); Media3 `PlayerView` uses one unless `app:surface_type` says otherwise.

2. **Find `setSecure` calls** and where they happen relative to attachment:

   ```yaml
   rules:
     - id: gt-android-surfaceview-setsecure
       languages: [java, kotlin]
       severity: INFO
       message: SurfaceView.setSecure call. Must run before the view is attached to the window.
       pattern-either:
         - pattern: $S.setSecure($B)
   ```

   ```bash
   semgrep -c gt-surfaceview.yml out/sources/
   ```

   For each hit, check the argument and the timing. The documentation requires the call before the containing window is attached to the window manager. An activity's window is attached after its first `onResume`, so calls in `onCreate` or `onStart` are safe; calls from `surfaceCreated`, after the screen is already visible, or on a surface view added later to a visible window are too late by the documentation. Newer Android versions may still apply a late call, so the capture in step 4 decides.

3. **Map each surface view to its window.** If the window has `FLAG_SECURE` (MASTG-TEST-0291), the surface is protected on Android 12+ in AOSP through inheritance, but not on older versions. If the window does not have the flag (common for camera screens, so users can still screenshot the result), the surface is protected only by `setSecure`.

4. **Confirm at runtime** on each device. Hook `setSecure` and record calls:

   ```javascript
   Java.perform(() => {
     const SurfaceView = Java.use('android.view.SurfaceView');
     SurfaceView.setSecure.implementation = function (secure) {
       console.log('[SurfaceView.setSecure] ' + secure + ' attached=' + this.isAttachedToWindow() + ' ' + this.getClass().getName());
       return this.setSecure(secure);
     };
   });
   ```

   `attached=true` in the output means the call came after attachment, which the documentation says is too late; no output at all means the app never calls it. Then open each surface screen and capture it:

   ```bash
   adb exec-out screencap -p > surface_<screen>.png
   adb shell screenrecord --time-limit 10 /sdcard/surface.mp4 && adb pull /sdcard/surface.mp4
   ```

   A protected surface is black in both. For Recents, follow MASTG-TEST-0289.

#### Observation

The list of surface views (own code, layouts, libraries), the `setSecure` call sites with timing, the window protection for each, and screenshots and recordings from each Android version tested.

#### Evaluation

The test **fails** if a `SurfaceView` that shows sensitive content is visible in a screenshot, recording or Recents snapshot on any supported Android version: no `setSecure(true)` and no effective window protection, `setSecure(true)` called after attachment, or reliance on window inheritance while `minSdkVersion` is below 31 and the content shows on an older device. It **passes** if every sensitive surface is black in captures on all versions tested.

#### Demo

OWASP has no demo for this test. Our minimal case: a card-scanning screen whose window deliberately has no `FLAG_SECURE` (so the user can screenshot the confirmation step), and whose camera preview surface is never marked secure:

```kotlin
class CardScanActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val preview = SurfaceView(this)         // camera frames show the physical card
        setContentView(preview)
        startCamera(preview.holder)
        // missing: preview.setSecure(true) before setContentView(preview)
    }
}
```

semgrep finds no `setSecure` call for this class, the Frida hook prints nothing while the screen is open, and `screencap` and `screenrecord` show the card number in the preview: the test fails. The fix is one line, before the view is attached:

```kotlin
val preview = SurfaceView(this).apply { setSecure(true) }
setContentView(preview)
```

With it, the hook prints `[SurfaceView.setSecure] true attached=false android.view.SurfaceView` and the preview area is black in both captures, while the rest of the (non-secure) window can still be captured.

### MASTG-TEST-0294: SecureOn Not Used to Prevent Screenshots in Compose Dialogs (Android)

Source: [MASTG-TEST-0294](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0294/). Platform: Android. Type: static (code). Knowledge: MASTG-KNOW-0053. Best practices: MASTG-BEST-0014, MASTG-BEST-0018. Related demo: [MASTG-DEMO-0063](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0063/MASTG-DEMO-0063/) (placeholder, "Incorrectly Preventing Screenshots with SecureFlagPolicy in Compose Dialogs with semgrep"; OWASP links it to MASTG-TEST-0293).

> **Note:** MASTG-TEST-0294 is an OWASP **placeholder** with no procedure ("verifies whether an app prevents sensitive data from being captured in screenshots and screen recordings of Jetpack Compose dialogs"). The test below is **Guler Tech methodology**.

#### Overview

Compose `Dialog` (and everything built on it: Material `AlertDialog`, `DatePickerDialog`, `BasicAlertDialog`), `Popup` (and `DropdownMenu`, tooltips) and Material 3 `ModalBottomSheet` create their own Android windows. Each takes a properties object with a [`SecureFlagPolicy`](https://developer.android.com/reference/kotlin/androidx/compose/ui/window/SecureFlagPolicy):

| Value | Effect on the dialog's window |
|---|---|
| `SecureFlagPolicy.Inherit` (default) | *"Inherit FLAG_SECURE from the parent window"*: secure only if the host window had the flag when the dialog was set up |
| `SecureFlagPolicy.SecureOn` | Always sets `FLAG_SECURE` |
| `SecureFlagPolicy.SecureOff` | Never sets it |

The properties classes are `DialogProperties(securePolicy = …)`, `PopupProperties(securePolicy = …)` and `ModalBottomSheetProperties(securePolicy = …)`. The test checks that dialogs, popups and sheets showing sensitive data use `SecureOn`, or `Inherit` over a window that is reliably secure first.

#### Prerequisites

- Decompiled sources, semgrep, grep, Frida.
- Your list of sensitive Compose dialogs, sheets and popups (reveal-card dialogs, OTP sheets, PIN pads, recovery-phrase confirmations).
- Note whether the release build is obfuscated: R8 can rename Compose classes and may unbox enums into integers, which defeats name-based searches. In that case rely on step 4.

#### Steps

1. **Find the policies used:**

   ```yaml
   rules:
     - id: gt-android-compose-secure-policy
       languages: [java, kotlin]
       severity: INFO
       message: Compose window SecureFlagPolicy. SecureOff never protects; Inherit protects only over a secure parent window.
       pattern-either:
         - pattern: SecureFlagPolicy.SecureOff
         - pattern: SecureFlagPolicy.Inherit
         - pattern: SecureFlagPolicy.SecureOn
   ```

   ```bash
   semgrep -c gt-compose-secure.yml out/sources/
   grep -rnE 'SecureFlagPolicy\.(SecureOn|SecureOff|Inherit)|new (DialogProperties|PopupProperties|ModalBottomSheetProperties)\(' out/sources/ | grep -v '^out/sources/androidx/'
   ```

2. **Find dialogs that use the default.** A dialog with no properties argument gets `Inherit` and does not appear in step 1. Kotlin compiles default arguments into a call to a synthetic `…$default` function, so look for call sites of the Compose dialog functions:

   ```bash
   grep -rnE 'AndroidDialog_androidKt\.Dialog|AndroidAlertDialog_androidKt\.|ModalBottomSheet_androidKt\.|AndroidPopup_androidKt\.Popup' out/sources/ | grep -v '^out/sources/androidx/'
   ```

   Exact class names depend on the Compose version; search for `Dialog(` near `DialogProperties` in jadx if these return nothing.

3. **Evaluate `Inherit` cases.** For each dialog left on `Inherit`, check whether the host activity's window has `FLAG_SECURE` from MASTG-TEST-0291 and whether it is set before the dialog is first composed. A flag added to the activity later does not reach a dialog already showing.

4. **Confirm at runtime.** Open each sensitive dialog, sheet and popup and check its window and a capture:

   ```bash
   adb shell dumpsys window windows | grep -E "Window #|fl="
   adb exec-out screencap -p > dialog_<name>.png
   ```

   The dialog is a separate `Window #…` entry; `SECURE` must be in its own `fl=` line. Running `flagsecure-trace.js` from MASTG-TEST-0291 also shows the dialog window's `setFlags` calls.

#### Observation

The `SecureFlagPolicy` values per sensitive dialog, sheet and popup, the host window's protection for `Inherit` cases, and the `dumpsys` output and screenshots with each one open.

#### Evaluation

The test **fails** if a Compose dialog, popup or bottom sheet that shows sensitive data is visible in a screenshot or recording: because it uses `SecureOff`, or uses `Inherit` over a non-secure host window. It **passes** if each such window has `SECURE` in its flags and is black in captures. `SecureOff` on a non-sensitive dialog over a secure screen is not a failure, but it is worth asking why it was chosen.

#### Demo

OWASP's demo is a placeholder. Our version of what its title describes, a dialog that reveals card details with protection switched off:

```kotlin
@Composable
fun RevealCardDialog(card: CardDetails, onDismiss: () -> Unit) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOff)
    ) {
        CardDetailsContent(card)    // PAN, expiry, CVV
    }
}
```

In jadx the default-argument constructor makes the policy easy to spot (exact arguments depend on the Compose version):

```java
new DialogProperties(false, false, SecureFlagPolicy.SecureOff, false, false, 27, (DefaultConstructorMarker) null)
```

The rule flags `SecureFlagPolicy.SecureOff`, `dumpsys window` shows the dialog window without `SECURE`, and `screencap` shows the card number over the black host activity: the test fails. `SecureFlagPolicy.SecureOn` fixes it regardless of the host window.

### MASTG-TEST-0290: Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding (iOS)

Source: [MASTG-TEST-0290](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0290/). Platform: iOS. Type: dynamic, filesystem. Knowledge: MASTG-KNOW-0099. Replaces legacy MASTG-TEST-0059.

#### Overview

iOS takes a snapshot of each scene when it enters the background, shows it in the App Switcher and stores it in the app container. The test backgrounds the app on each sensitive screen, pulls the stored snapshots and inspects them. The visual check in the App Switcher works on any device; the file check needs access to the container.

#### Prerequisites

- Your sensitive-screen list.
- For the file check, one of: a jailbroken device with SSH ([MASTG-TECH-0052](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0052/)); a non-jailbroken device with the app repackaged with Frida Gadget ([MASTG-TECH-0090](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0090/)) and objection ([MASTG-TOOL-0074](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0074/)); or the iOS Simulator if you have a simulator build. Transfer as in [MASTG-TECH-0053](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0053/).
- Test on each iOS major version in scope: the path and the scene behaviour have changed over time.

#### Steps

1. **For each sensitive screen**, open it, then open the App Switcher (swipe up and pause, or double-press Home) and take a screenshot of the switcher with the side and volume-up buttons. That screenshot is your primary evidence: it is exactly what someone holding the phone sees. Then go to the Home Screen so the app enters the background and the snapshot is stored. Repeat from the App Switcher, from Control Centre, and with an incoming notification tapped, because each path deactivates the app differently.

2. **Find the data container.** On a jailbroken device:

   ```bash
   iproxy 2222 22 &                     # libimobiledevice; or use the jailbreak's own SSH over Wi-Fi
   ssh -p 2222 root@localhost
   # on the device: find the container whose metadata names the bundle ID
   grep -l 'com.example.app' /var/mobile/Containers/Data/Application/*/.com.apple.mobile_container_manager.metadata.plist
   ```

   The directory containing the matching plist is the container. With objection, run `env` inside the session to print it.

3. **List and pull the snapshots:**

   ```bash
   # on the device
   APP=/var/mobile/Containers/Data/Application/<UUID>
   find "$APP/Library/SplashBoard" "$APP/Library/Caches/Snapshots" -type f -exec ls -l {} \; 2>/dev/null
   tar czf /tmp/snapshots.tgz -C "$APP/Library" SplashBoard
   exit
   # on the workstation
   scp -P 2222 root@localhost:/tmp/snapshots.tgz . && tar xzf snapshots.tgz
   ```

   With objection on a repackaged app:

   ```bash
   objection -n "Example" start
   # inside objection
   env
   filesystem download <Library path>/SplashBoard ./SplashBoard --folder
   ```

   On the Simulator (no jailbreak needed):

   ```bash
   C=$(xcrun simctl get_app_container booted com.example.app data)
   find "$C/Library/SplashBoard" -type f
   cp -R "$C/Library/SplashBoard" ./SplashBoard-sim
   ```

4. **Open the images.** Some macOS versions render the `.ktx` files in Quick Look or Preview; if yours does not, convert them with a KTX-aware forensic tool (several open-source converters exist for iOS snapshots). Check every scene folder and both light and dark variants.

#### Observation

The App Switcher screenshots per sensitive screen, the list of snapshot files with paths and timestamps, and the rendered images, mapped to the screen you left.

#### Evaluation

The test **fails** if any App Switcher card or stored snapshot shows data from your sensitive-screen list. It **passes** if each shows a cover (logo, blank view) or only non-sensitive content.

Pitfalls: snapshots from an earlier run (check timestamps, or delete the app and reinstall before testing); the switcher card showing content while the stored file is covered (the cover was added on `didEnterBackground` only, which is still a failure for the switcher); a cover that does not reach presented controllers or alerts; Simulator results that differ from devices on timing (confirm a pass on a device).

#### Demo

OWASP has no demo for this test. The failing case is any scene that does nothing on deactivation:

```swift
final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    // no sceneWillResignActive / sceneDidEnterBackground handling:
    // the account screen with IBAN and balance is captured as-is
}
```

On the Simulator:

```text
$ find "$C/Library/SplashBoard" -type f
…/Library/SplashBoard/Snapshots/sceneID:com.example.app-default/2C1A…@3x.ktx
…/Library/SplashBoard/Snapshots/sceneID:com.example.app-default/downscaled/5F7B…@3x.ktx
```

Both images show the IBAN and balance: the test fails. With the cover window from [Secure patterns for iOS](#secure-patterns-for-ios-guler-tech), the App Switcher card and the stored files show only the cover.

### GT-0038-1: Live capture check with screenshots, recording and casting (Android and iOS)

Guler Tech test. Platform: Android and iOS. Type: dynamic, manual. Covers the parts of the weakness that OWASP's tests do not exercise at runtime: user screenshots, screen recording, casting and screen sharing (MAS-ATTACK-0071), and the iOS capture-state redaction mode.

#### Overview

The static Android tests tell you where protections are set; this test shows what a capture actually contains, window by window, including dialogs, the keyboard and surfaces. On iOS, where screenshots cannot be blocked, it checks whether the app hides sensitive content while the screen is captured.

#### Prerequisites

- Your sensitive-screen list, including dialogs, sheets, popups and camera or video screens.
- Android: `adb`; a device with the built-in screen recorder (Android 11+) and, if possible, a cast target or a video-call app with screen sharing. iOS: a device with Screen Recording in Control Centre, and a Mac for QuickTime mirroring or an AirPlay receiver.
- Optionally Frida for the iOS capture-state hooks.

#### Steps

**Android:**

1. On each sensitive screen and with each sensitive dialog open, capture through every path:

   ```bash
   adb exec-out screencap -p > live_<screen>.png
   adb shell screenrecord --time-limit 15 /sdcard/live_<screen>.mp4 && adb pull /sdcard/live_<screen>.mp4
   ```

   Then take a hardware-button screenshot (expect a refusal message when protected), make a recording with the Quick Settings recorder, and share the screen in a video-call app or cast it. The Quick Settings recorder and screen sharing use `MediaProjection`, the path real screen-sharing scams use.

2. While recording, type into the sensitive fields (PIN, password, OTP). Watch the recording for keyboard key-press popups, suggestion strips and custom keypad views.

3. Record the window flags while each sensitive window is open: `adb shell dumpsys window windows | grep -E "Window #|fl="`.

4. On Android 15+, if the app relies on `setContentSensitivity`, verify that its sensitive screens are visible in a normal screenshot but black during a screen share. On Android 14+, if the app uses screenshot detection, note what it does with the callback.

**iOS:**

5. Take a screenshot on each sensitive screen. It will succeed. Note whether the app reacts (a warning, a re-mask, a server-side event), which tells you it observes `userDidTakeScreenshotNotification`.

6. Start Screen Recording from Control Centre, return to the app and walk the sensitive screens. Repeat with AirPlay or QuickTime mirroring (QuickTime Player > New Movie Recording > select the iPhone as the camera), and with a ReplayKit broadcast from a video-call app if one is available. Watch whether sensitive content is hidden while capture is active and comes back afterwards.

7. Confirm what the app checks:

   ```bash
   frida-trace -U -f com.example.app -m "-[UIScreen isCaptured]" -m "-[UITraitCollection sceneCaptureState]"
   ```

   and which notifications it observes:

   ```javascript
   // ios-capture-observers.js
   const nc = ObjC.classes.NSNotificationCenter;
   const show = (p) => (p.isNull() ? '(nil)' : new ObjC.Object(p).toString());
   Interceptor.attach(nc['- addObserver:selector:name:object:'].implementation, {
     onEnter(args) {   // self, _cmd, observer, selector, name, object
       const name = show(args[4]);
       if (/Screenshot|Captured/i.test(name)) console.log('[observer] ' + name + ' -> ' + ObjC.selectorAsString(args[3]));
     }
   });
   Interceptor.attach(nc['- addObserverForName:object:queue:usingBlock:'].implementation, {
     onEnter(args) {   // self, _cmd, name, object, queue, block
       const name = show(args[2]);
       if (/Screenshot|Captured/i.test(name)) console.log('[observer block] ' + name);
     }
   });
   ```

   ```bash
   frida -U -f com.example.app -l ios-capture-observers.js
   ```

   The names to look for are `UIApplicationUserDidTakeScreenshotNotification` and `UIScreenCapturedDidChangeNotification`. Trait-change registrations for `UITraitSceneCaptureState` do not go through Notification Center; the `frida-trace` output covers them.

8. If the app uses the secure-text-field technique, test it on each iOS major version in scope and record where it fails.

#### Observation

Per sensitive window and capture path: the image or video, whether the window was black, refused, hidden or visible, and the window flags (Android); per sensitive screen: whether content was hidden during recording, mirroring and screen sharing, and the hooks showing which APIs the app uses (iOS).

#### Evaluation

**Android** fails if any sensitive window is visible in any capture path that the baseline says must be blocked, or if keystrokes into sensitive fields are readable in a recording (report the latter carefully: it may be an IME behaviour on that device, and the fix is input types and custom keypads, not a window flag). It passes if all sensitive windows are black or refused.

**iOS** cannot fail for allowing a screenshot. It fails the capture-state mode of introduction if high-value content (see [Rating findings](#rating-findings)) stays visible while the screen is recorded, mirrored or shared. It passes if that content is hidden or replaced while captured and the app does not rely on screenshot detection as a control.

#### Demo

An Android dialog over a protected activity is the case this test catches most often:

```kotlin
window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)    // activity is protected
// …
AlertDialog.Builder(this)
    .setTitle("Your one-time code")
    .setMessage(otp)                                       // dialog window has no FLAG_SECURE
    .show()
```

```text
$ adb shell dumpsys window windows | grep -E "Window #|fl="
  Window #7 Window{8c1d2e u0 com.example.app}:
    fl=DIM_BEHIND ALT_FOCUSABLE_IM SPLIT_TOUCH HARDWARE_ACCELERATED
  Window #8 Window{3f9a10 u0 com.example.app/com.example.app.OtpActivity}:
    fl=LAYOUT_IN_SCREEN LAYOUT_INSET_DECOR SPLIT_TOUCH HARDWARE_ACCELERATED SECURE DRAWS_SYSTEM_BAR_BACKGROUNDS
```

(Illustrative and trimmed; window titles, flags and indentation vary by version.) The activity window has `SECURE`; the dialog window does not, and `screencap` shows the code on a black background. The fix is `dialog.window?.addFlags(FLAG_SECURE)` before `show()`.

### GT-0038-2: Static review of snapshot and capture handling (iOS)

Guler Tech test. Platform: iOS. Type: static. OWASP's only iOS test is dynamic; this one tells you, before you start tapping, where the app hides content and what it reacts to, so that you can direct MASTG-TEST-0290 and GT-0038-1 and explain failures in the report.

#### Overview

Look for the lifecycle methods where a cover would be added, the capture-state APIs, the screenshot notification, and any third-party "screen protection" library.

#### Prerequisites

- The decrypted app binary ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)), unzipped: `Payload/Example.app/Example`, plus its frameworks.
- `strings`, radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)) or a disassembler, and the source code if the client provides it.

#### Steps

1. **Find the relevant selectors and symbols:**

   ```bash
   BIN=Payload/Example.app/Example
   strings -a "$BIN" | grep -E 'WillResignActive|DidEnterBackground|DidBecomeActive|WillEnterForeground' | sort -u
   strings -a "$BIN" | grep -E 'isCaptured|sceneCaptureState|UITraitSceneCaptureState|CapturedDidChange|UserDidTakeScreenshot|ignoreSnapshotOnNextApplicationLaunch' | sort -u
   for f in Payload/Example.app/Frameworks/*.framework; do
     n=$(basename "$f" .framework); strings -a "$f/$n" | grep -qE 'isCaptured|sceneCaptureState|UserDidTakeScreenshot' && echo "$n"
   done
   ```

   In radare2, `izz~Captured` and `izz~Screenshot` give the addresses; `axt` on them shows the referencing functions.

2. **Check the scene model.** If `Info.plist` has a `UIApplicationSceneManifest` key (`plutil -p Payload/Example.app/Info.plist | grep -A3 UIApplicationSceneManifest`), the app uses scenes and only the scene-delegate methods (`sceneWillResignActive:`, `sceneDidEnterBackground:`) or SwiftUI `scenePhase` handling matter. An `applicationDidEnterBackground:` cover in a scene-based app is never called.

3. **Read the cover code** at each hit (or in the source). Check that it covers before the snapshot (resign-active or did-enter-background, not will-enter-foreground), that it is opaque, that it sits above presented controllers and alerts, and that it is removed on become-active.

4. **Read the capture-state handling.** Which screens hide content when captured, whether the handler is installed on every high-value screen, and whether the screenshot notification is used only for messaging the user.

5. **Note libraries** that implement the secure-text-field technique and which iOS versions they claim to support.

#### Observation

The list of lifecycle, capture and screenshot APIs used, with locations; the scene model; and a description of each cover and redaction mechanism.

#### Evaluation

This is a supporting test: it does not pass or fail on its own. Use it to predict and explain the results of MASTG-TEST-0290 and GT-0038-1. If static review shows no cover and no capture handling at all on an app with high-value screens, expect both dynamic tests to fail and say so in the report with the code evidence.

#### Demo

A SwiftUI app whose only protection is a screenshot alert:

```swift
.onReceive(NotificationCenter.default.publisher(for: UIApplication.userDidTakeScreenshotNotification)) { _ in
    showScreenshotWarning = true     // detection only: the screenshot already exists
}
```

`strings` finds `UIApplicationUserDidTakeScreenshotNotification` and nothing for `scenePhase` covers, `isCaptured` or `sceneCaptureState`. MASTG-TEST-0290 and GT-0038-1 then confirm that snapshots and recordings show the data.

## Best practices

### MASTG-BEST-0014: Preventing Screenshots and Screen Recording

Source: [MASTG-BEST-0014](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0014/). Platform: Android.

Hide sensitive content (card numbers, passcodes and similar) from screenshots, screen recording, non-secure displays, Recents thumbnails and remote screen sharing, because malware and screen-sharing tools can capture screen output, and screenshots end up where other apps or a local attacker can read them. OWASP also asks you to protect on-screen keyboards and custom keypads, which can leak keystrokes from passcode fields. Set `FLAG_SECURE` on the window, following Android's [Secure sensitive activities](https://developer.android.com/security/fraud-prevention/activities) guidance:

```kotlin
window.setFlags(
    WindowManager.LayoutParams.FLAG_SECURE,
    WindowManager.LayoutParams.FLAG_SECURE
)
```

Android's documentation adds two pieces of context worth passing on to developers: the flag is not a defence against overlay attacks (use `HIDE_OVERLAY_WINDOWS` for that, see [MASWE-0039](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/)), and it suggests considering a user setting to toggle the flag for transparency. If you offer such a toggle, default it to protected on high-value screens.

### MASTG-BEST-0015, 0016, 0017 and 0018 (placeholders)

OWASP lists four more best practices for this weakness, all **placeholders** without content at the time of writing. Their intent, and where we cover it:

| Best practice | Title | Covered in |
|---|---|---|
| [MASTG-BEST-0015](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0015/) | Use `setRecentsScreenshotEnabled` to Prevent Screenshots When Backgrounded | [setRecentsScreenshotEnabled (API 33)](#setrecentsscreenshotenabled-api-33), MASTG-TEST-0292, the patterns below |
| [MASTG-BEST-0016](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0016/) | Use `SECURE_FLAG` to Prevent Screenshots and Screen Recording (the title means `FLAG_SECURE`) | The FLAG_SECURE section of [MASTG-KNOW-0053](#android-screenshots-mastg-know-0053), MASTG-TEST-0291 |
| [MASTG-BEST-0017](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0017/) | Use `setSecure` to Prevent Screenshots in SurfaceViews | MASTG-TEST-0293, the patterns below |
| [MASTG-BEST-0018](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0018/) | Use `SecureFlagPolicy.SecureOn` to Prevent Screenshots in Compose Components | MASTG-TEST-0294, the patterns below |

### Secure patterns for Android (Guler Tech)

**Decide per screen, apply centrally.** Mark the sensitive activities (an annotation, an interface or a list) and apply the right protection in one `ActivityLifecycleCallbacks`, so new screens cannot forget it. `onActivityPreCreated` (API 29+) runs before the activity's own `onCreate`:

```kotlin
interface CaptureSensitive                 // never capturable: FLAG_SECURE
interface RecentsSensitive                 // screenshots allowed, not in Recents

class ScreenProtection : Application.ActivityLifecycleCallbacks {
    override fun onActivityPreCreated(activity: Activity, savedInstanceState: Bundle?) = protect(activity)
    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) protect(activity)
    }

    private fun protect(activity: Activity) {
        when {
            activity is CaptureSensitive ->
                activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            activity is RecentsSensitive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU ->
                activity.setRecentsScreenshotEnabled(false)
            activity is RecentsSensitive ->       // no Recents-only API before 33
                activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
    // remaining callbacks: empty
    override fun onActivityStarted(activity: Activity) {}
    override fun onActivityResumed(activity: Activity) {}
    override fun onActivityPaused(activity: Activity) {}
    override fun onActivityStopped(activity: Activity) {}
    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
    override fun onActivityDestroyed(activity: Activity) {}
}
```

Single-activity apps with Compose or Fragments navigation need per-destination control instead: add the flag when a sensitive destination is shown and clear it when the user leaves it, in one place in the navigation code.

**Protect every window, not just the activity.**

```kotlin
// Views: dialogs and sheets
val dialog = MaterialAlertDialogBuilder(this).setMessage(otp).create()
dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
dialog.show()

// DialogFragment
override fun onStart() {
    super.onStart()
    dialog?.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
}

// Compose
Dialog(onDismissRequest = onDismiss, properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn)) { /* … */ }
Popup(onDismissRequest = onDismiss, properties = PopupProperties(securePolicy = SecureFlagPolicy.SecureOn)) { /* … */ }
ModalBottomSheet(onDismissRequest = onDismiss, properties = ModalBottomSheetProperties(securePolicy = SecureFlagPolicy.SecureOn)) { /* … */ }

// SurfaceView: before it is attached
val preview = SurfaceView(this).apply { setSecure(true) }
setContentView(preview)
```

For `DialogFragment`, the flag set in `onStart` is normally applied before the first frame is drawn; setting it where the dialog is created (`onCreateDialog`) is more robust.

**Android 15: protect against screen sharing without blocking screenshots.** For screens where the user legitimately screenshots but sharing should hide them:

```kotlin
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
    cardNumberView.setContentSensitivity(View.CONTENT_SENSITIVITY_SENSITIVE)
}
```

**Detection, if you want it, is extra.** Register `ScreenCaptureCallback` and the screen recording callback in `onStart` and remove them in `onStop` (code in [MASTG-KNOW-0107](#android-screenshots-and-screen-recording-detection-mastg-know-0107)). Use them to tell the user what happened, never as the reason a screen lacks `FLAG_SECURE`.

**Show less.** Masked by default, tap to reveal with a timeout, and never display secrets that the user does not need to read (a CVV can often be copied to a payment form without being displayed). Use password input types for PINs and codes so the IME treats them as sensitive.

### Secure patterns for iOS (Guler Tech)

**A cover window for every scene.** A separate window above alerts covers presented view controllers and alerts, and appears before the switcher card is drawn:

```swift
final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    private var coverWindow: UIWindow?

    func sceneWillResignActive(_ scene: UIScene) { showCover(on: scene) }
    func sceneDidEnterBackground(_ scene: UIScene) { showCover(on: scene) }
    func sceneDidBecomeActive(_ scene: UIScene) { hideCover() }

    private func showCover(on scene: UIScene) {
        guard coverWindow == nil, let windowScene = scene as? UIWindowScene else { return }
        let cover = UIWindow(windowScene: windowScene)
        cover.rootViewController = PrivacyCoverViewController()   // opaque: logo on a solid background
        cover.windowLevel = .alert + 1
        cover.isHidden = false                                     // visible without becoming key
        coverWindow = cover
    }

    private func hideCover() {
        coverWindow?.isHidden = true
        coverWindow = nil
    }
}
```

If the cover on resign-active gets in the way of Face ID prompts, keep it on resign-active only for high-value screens and always on did-enter-background, and accept the brief switcher exposure for the rest. Then confirm with MASTG-TEST-0290.

**SwiftUI:** react to `scenePhase` in the root view, which applies per scene:

```swift
struct RootView: View {
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        ContentView()
            .overlay {
                if scenePhase != .active {
                    PrivacyCover().ignoresSafeArea()      // opaque view
                }
            }
    }
}
```

Sheets and full-screen covers are presented above this overlay; hide their sensitive content on `scenePhase` changes as well, or use the UIKit cover window from a scene delegate adaptor.

**Hide high-value content while the screen is captured:**

```swift
final class CardViewController: UIViewController {
    @IBOutlet private var cardNumberLabel: UILabel!

    override func viewDidLoad() {
        super.viewDidLoad()
        if #available(iOS 17.0, *) {
            registerForTraitChanges([UITraitSceneCaptureState.self]) { (self: Self, _: UITraitCollection) in
                self.updateCaptureRedaction()
            }
        } else {
            NotificationCenter.default.addObserver(self, selector: #selector(updateCaptureRedaction),
                                                   name: UIScreen.capturedDidChangeNotification, object: nil)
        }
        updateCaptureRedaction()
    }

    @objc private func updateCaptureRedaction() {
        let captured: Bool
        if #available(iOS 17.0, *) {
            captured = traitCollection.sceneCaptureState == .active
        } else {
            captured = view.window?.windowScene?.screen.isCaptured ?? UIScreen.main.isCaptured
        }
        cardNumberLabel.isHidden = captured        // or swap in a masked value and a short explanation
    }
}
```

**Use the screenshot notification only to inform.** For example, a gentle message after a screenshot of a recovery phrase, suggesting the user delete it from Photos. It cannot stop the screenshot.

**Do not rely on the secure-text-field technique as the only control**; if a library uses it, pin the version, test it on every iOS release, and keep the snapshot cover and capture-state redaction in place regardless.

## Rating findings

Rate on three things: **what the capture contains** (a secret that grants access or moves money by itself, or personal data, or little of value), **who can get the copy and what they need** (another app with a permission and user consent, a person holding the unlocked phone, someone with root or a forensic extraction, the user being manipulated), and **whether the app's profile expects this control** (OWASP tags MASWE-0038 L2 and EUDIW only).

Attacker positions, from most to least common in practice:

- **A person with brief access to the unlocked phone** (family, colleague, thief before the phone locks). Opens Recents or the App Switcher; no tools, no interaction with the app, bypasses the app's own lock on resume.
- **A screen-sharing scam.** The victim is talked into sharing the screen through a video-call or remote-support app (MediaProjection or ReplayKit broadcast, with consent obtained by social engineering), then opens the banking app. On Android, `FLAG_SECURE` stops this; on iOS, only capture-state redaction does.
- **Malware with a capture capability.** An app the user installed with `MediaProjection` consent or an enabled accessibility service. Remember that an accessibility service can read text regardless of `FLAG_SECURE` ([MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/)), so this position alone does not make the screenshot finding worse than the accessibility one.
- **Anything that reads the photo library** after the user took a screenshot: an app with media or Photos permission, a cloud photo account, someone who later has the phone. Needs a user action first.
- **Root, jailbreak or forensic extraction** reading Android snapshot files or iOS `SplashBoard` files at rest. Needs a compromised or seized device; the files persist until overwritten. Cross-check the data-at-rest view in the [STORAGE guide](/mobile/masvs-storage-1-secure-storage-guide/).
- **USB debugging access** (`adb screencap`): someone who already has the unlocked device and debugging authorised.

| Rating | Conditions |
|---|---|
| **Critical** | Not used for this weakness on its own. Every capture path needs either physical access, user consent or a user action. Rate Critical only as part of a demonstrated chain, for example a capture path that needs no consent because of a separate flaw, combined with secrets that give irreversible control (wallet recovery phrases, private keys). |
| **High** | Secrets that by themselves allow account takeover, payment or irreversible loss (recovery phrases, private keys, passwords or PINs shown in clear, full card number with CVV, transaction-signing or MFA codes, account recovery codes) shown on an Android screen without effective `FLAG_SECURE` (missing, cleared, or not applied to the dialog or surface showing them), so a screen-sharing session or `MediaProjection` capture gets them; or shown in the Recents/App Switcher snapshot on either platform. Applies to L2 and EUDIW apps. |
| **Medium** | Personal or financial data that is sensitive but not directly usable for takeover (balances, transaction history, full account number or IBAN, identity document images, health records, messages) in the Recents/App Switcher snapshot or capturable live on Android; a sensitive dialog, sheet or `SurfaceView` left unprotected while the rest of the screen is protected; protection that exists only from API 33 (`setRecentsScreenshotEnabled`) or relies on child-surface inheritance while `minSdkVersion` allows older devices where it fails; on iOS, the High-category secrets left visible while the screen is recorded, mirrored or shared (no capture-state redaction). |
| **Low** | Less sensitive personal data (name, email, masked account numbers, partial addresses) in snapshots or captures; a blur cover that leaves content partly legible; a user-facing "allow screenshots" toggle that defaults to allowed on sensitive screens; on iOS, Medium-category data visible during capture. |
| **Info** | Detection-only controls (screen capture callbacks, `userDidTakeScreenshotNotification`) used as a complement; reliance on the unofficial secure-text-field technique as the only iOS live-capture control (recommend capture-state redaction); IME key previews readable in recordings on a specific device; `FLAG_SECURE` intentionally absent on screens the user is expected to screenshot (receipts) where the data is low-value; an L1 app with no high-value data showing personal data in Recents. |

Adjust one level down for L1-profile apps (the control is not expected at that level) and when the data is masked to the point that the capture is useless; one level up for EUDIW and identity apps and for apps whose users are a known target of screen-sharing fraud (banking, payments, crypto). Do not rate an iOS app for "allowing screenshots": the platform does not let it prevent them. Rate what it shows in snapshots and what it hides, or does not hide, during capture.

In the report, give the screen or dialog, the capture path and evidence (Recents or App Switcher screenshot, snapshot file with path, recording), the device and OS version, the attacker position needed, and the fix at the right level: the window flag on the specific window, `SecureFlagPolicy.SecureOn` on the specific composable, `setSecure` before attach, the scene-level cover, or capture-state redaction.

## References

- OWASP MASWE: [MASWE-0038: Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0038/); related [MASWE-0036](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0036/), [MASWE-0040](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0040/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PLATFORM-3](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/), [MASVS-STORAGE-2](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0053: Screenshots (Android)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0053/), [MASTG-KNOW-0105](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0105/), [MASTG-KNOW-0106](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0106/), [MASTG-KNOW-0107](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0107/) (placeholders), [MASTG-KNOW-0099: Screenshots (iOS)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0099/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0289](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0289/), [MASTG-TEST-0291](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0291/), [MASTG-TEST-0292](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0292/), [MASTG-TEST-0293](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0293/), [MASTG-TEST-0294](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0294/), [MASTG-TEST-0290](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0290/); legacy [MASTG-TEST-0010](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0010/), [MASTG-TEST-0059](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0059/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0061](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0061/MASTG-DEMO-0061/), [MASTG-DEMO-0062](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0062/MASTG-DEMO-0062/), [MASTG-DEMO-0063](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0063/MASTG-DEMO-0063/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0014](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0014/), [MASTG-BEST-0015](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0015/), [MASTG-BEST-0016](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0016/), [MASTG-BEST-0017](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0017/), [MASTG-BEST-0018](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0018/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0002](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/), [MASTG-TECH-0178](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0178/), [MASTG-TECH-0052](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0052/), [MASTG-TECH-0053](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0053/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0090](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0090/) (CC BY-SA 4.0)
- OWASP MASTG tools: [adb (MASTG-TOOL-0004)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [objection (MASTG-TOOL-0074)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0074/), [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/) (CC BY-SA 4.0)
- Android Developers: [Secure sensitive activities (FLAG_SECURE, HIDE_OVERLAY_WINDOWS)](https://developer.android.com/security/fraud-prevention/activities), [`WindowManager.LayoutParams.FLAG_SECURE`](https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE), [`Activity.setRecentsScreenshotEnabled`](https://developer.android.com/reference/android/app/Activity#setRecentsScreenshotEnabled%28boolean%29), [`SurfaceView.setSecure`](https://developer.android.com/reference/android/view/SurfaceView#setSecure%28boolean%29), [`View.setContentSensitivity`](https://developer.android.com/reference/android/view/View#setContentSensitivity%28int%29), [Screenshot detection (Android 14)](https://developer.android.com/about/versions/14/features/screenshot-detection), [Android 15 features: screen recording detection, app screen sharing, media projection status bar chip](https://developer.android.com/about/versions/15/features), [`WindowManager.addScreenRecordingCallback`](https://developer.android.com/reference/android/view/WindowManager#addScreenRecordingCallback%28java.util.concurrent.Executor,%20java.util.function.Consumer%3Cjava.lang.Integer%3E%29), [`Manifest.permission` (`DETECT_SCREEN_CAPTURE`, `DETECT_SCREEN_RECORDING`)](https://developer.android.com/reference/android/Manifest.permission), [`AccessibilityService.takeScreenshot`](https://developer.android.com/reference/android/accessibilityservice/AccessibilityService), [Recents screen](https://developer.android.com/guide/components/activities/recents), [Compose `SecureFlagPolicy`](https://developer.android.com/reference/kotlin/androidx/compose/ui/window/SecureFlagPolicy), [`DialogProperties`](https://developer.android.com/reference/kotlin/androidx/compose/ui/window/DialogProperties), [`ModalBottomSheetProperties`](https://developer.android.com/reference/kotlin/androidx/compose/material3/ModalBottomSheetProperties)
- AOSP sources (frameworks/base, frameworks/native): `TaskSnapshotController`, `ActivitySnapshotController`, `BaseAppSnapshotPersister`, `AbsAppSnapshotController`, `ActivityRecord.shouldUseAppThemeSnapshot`, `WindowState.isSecureLocked`, `WindowManager.LayoutParams.toString`, SurfaceFlinger `Layer::isSecure` (android11-release versus android12-release) and `LayerSnapshotBuilder`, `Settings.Secure.DISABLE_SECURE_WINDOWS`
- Apple: [Preparing your UI to run in the background](https://developer.apple.com/documentation/uikit/preparing-your-ui-to-run-in-the-background), [`applicationDidEnterBackground(_:)`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/applicationdidenterbackground%28_:%29), [`ignoreSnapshotOnNextApplicationLaunch()`](https://developer.apple.com/documentation/uikit/uiapplication/ignoresnapshotonnextapplicationlaunch%28%29), [`userDidTakeScreenshotNotification`](https://developer.apple.com/documentation/uikit/uiapplication/userdidtakescreenshotnotification), [`UIScreen.isCaptured`](https://developer.apple.com/documentation/uikit/uiscreen/iscaptured), [`UIScreen.capturedDidChangeNotification`](https://developer.apple.com/documentation/uikit/uiscreen/captureddidchangenotification), [`UITraitCollection.sceneCaptureState`](https://developer.apple.com/documentation/uikit/uitraitcollection/scenecapturestate), [`UISceneCaptureState`](https://developer.apple.com/documentation/uikit/uiscenecapturestate)
- Forensic background on iOS snapshot files (KTX format, `sceneID:<bundle id>-default` folders): [Magnet Forensics, "That One Artifact: Snapshot to justice"](https://www.magnetforensics.com/blog/that-one-artifact-snapshot-to-justice/), [Alexis Brignoni, "iOS snapshots triage parser"](https://abrignoni.blogspot.com/2019/09/ios-snapshots-triage-parser-working.html)
- CWE: [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-359](https://cwe.mitre.org/data/definitions/359.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
