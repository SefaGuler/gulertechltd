---
title: "Improper Use of the Clipboard (MASWE-0030)"
date: 2026-11-09 21:01:00 +0000
subcategory: platform
summary: "Testing Android and iOS apps for secrets put on the clipboard, missing sensitive flags, localOnly and expiry options, and unvalidated pasted input."
refs: [MASWE-0030, MASVS-PLATFORM-1, MASVS-STORAGE-2, CWE-200, CWE-668]
tags: [android, ios, masvs-platform, clipboard, pasteboard, data-leakage]
---

This note is part of our [MASVS-PLATFORM guide](/mobile/masvs-platform-platform-interaction-guide/) and covers OWASP [MASWE-0030](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0030/): apps that put sensitive data on the system clipboard, or take data from it, without accounting for the fact that the clipboard belongs to everyone. Whatever an app copies can be read by the next app the user opens, by the keyboard, by a keyboard's clipboard history, and on Apple devices by the user's other devices through Universal Clipboard. Whatever an app pastes was possibly written by another app. Below you will find how the iOS pasteboard and the Android clipboard work and how their privacy behaviour changed across OS versions (iOS 14 banner, iOS 16 paste prompt, Android 10 background read restriction, Android 12 access toast, Android 13 preview, sensitive flag and auto-clear), the five OWASP iOS pasteboard tests, our own Android tests, a test for untrusted clipboard input on both platforms, secure patterns, and how to rate what you find.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [iOS: Pasteboard (MASTG-KNOW-0083)](#ios-pasteboard-mastg-know-0083)
  - [Android: Clipboard framework and OS-version behaviour (supplementary)](#android-clipboard-framework-and-os-version-behaviour-supplementary)
- [Tests](#tests)
  - [Before you start: static triage of the iOS binaries](#before-you-start-static-triage-of-the-ios-binaries)
  - [MASTG-TEST-0276: Use of the iOS General Pasteboard (iOS)](#mastg-test-0276-use-of-the-ios-general-pasteboard-ios)
  - [MASTG-TEST-0277: Sensitive Data in the iOS General Pasteboard at Runtime (iOS)](#mastg-test-0277-sensitive-data-in-the-ios-general-pasteboard-at-runtime-ios)
  - [MASTG-TEST-0278: Pasteboard Contents Not Cleared After Use (iOS)](#mastg-test-0278-pasteboard-contents-not-cleared-after-use-ios)
  - [MASTG-TEST-0279: Pasteboard Contents Not Expiring (iOS)](#mastg-test-0279-pasteboard-contents-not-expiring-ios)
  - [MASTG-TEST-0280: Pasteboard Contents Not Restricted to Local Device (iOS)](#mastg-test-0280-pasteboard-contents-not-restricted-to-local-device-ios)
  - [GT-0030-1: Clipboard writes of sensitive data without the sensitive flag (Android)](#gt-0030-1-clipboard-writes-of-sensitive-data-without-the-sensitive-flag-android)
  - [GT-0030-2: Sensitive data on the clipboard at runtime (Android)](#gt-0030-2-sensitive-data-on-the-clipboard-at-runtime-android)
  - [GT-0030-3: Untrusted clipboard input (Android and iOS)](#gt-0030-3-untrusted-clipboard-input-android-and-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0045: Limit Sensitive Data Exposure Through iOS IPC Channels (pasteboard part)](#mastg-best-0045-limit-sensitive-data-exposure-through-ios-ipc-channels-pasteboard-part)
  - [Secure patterns (Guler Tech)](#secure-patterns-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0030 applies when an app places sensitive data on the system clipboard, or consumes clipboard content, in a way that exposes the data or the app beyond its control. The OWASP requirement is *"The app uses the clipboard securely and only with user consent."* It maps to MASVS-PLATFORM-1 ("The app uses IPC mechanisms securely": the clipboard is an IPC channel, just one the user drives) and MASVS-STORAGE-2 ("The app prevents leakage of sensitive data"), and to [CWE-200](https://cwe.mitre.org/data/definitions/200.html) (Exposure of Sensitive Information to an Unauthorized Actor) and [CWE-668](https://cwe.mitre.org/data/definitions/668.html) (Exposure of Resource to Wrong Sphere). It is tagged for profiles L1, L2 and EUDIW, so it applies to every app. OWASP's threat is MAS-THREAT-0030, *"Attackers can capture sensitive data placed on the clipboard"*, through MAS-ATTACK-0041, *"Reading sensitive data from the clipboard when users copy it between apps."*

> **Note:** The MASWE-0030 page itself lists no OWASP tests. The five iOS pasteboard tests (MASTG-TEST-0276 to 0280) are filed by OWASP under [MASWE-0036 (sensitive data exposed via the UI)](/mobile/maswe-0036-sensitive-data-exposed-via-ui/); we document them in full here because they test clipboard handling, which is exactly this weakness. OWASP has no Android clipboard test at all, so the Android tests in this note (GT-0030-1 and GT-0030-2) and the cross-platform input test (GT-0030-3) are Guler Tech methodology.

The clipboard is unusual among IPC channels: there is no addressee. An app does not send data *to* another app; it puts data in a shared place and anyone with the right timing can take it. Who that "anyone" is depends on the platform and the OS version:

| Who can get at clipboard content | iOS | Android |
|---|---|---|
| The app the user opens next (foreground) | Yes. Since iOS 14 a banner tells the user; since iOS 16 a programmatic read asks the user first | Yes. Since Android 12 a toast tells the user |
| Any app running in the background | No (foreground-only since iOS 9) | Yes on Android 9 and lower; no on Android 10+ |
| The keyboard (IME) | Not a separate clipboard channel (what custom keyboards see of typed input is [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/)) | The default IME can always read it, and keyboards keep a clipboard history |
| The user's other devices | Yes, via Universal Clipboard, unless the item is `localOnly` | Not by the platform; some keyboards and OEM or companion apps sync clipboard to the cloud or a PC |
| Anyone looking at the screen | Paste banners and previews | The Android 13+ copy preview shows the content unless it is flagged sensitive |

Keep MASWE-0030 apart from its neighbours. Showing a secret on screen is [MASWE-0036](/mobile/maswe-0036-sensitive-data-exposed-via-ui/); secure text entry (which, as a side effect, disables copy) is tested there. Users copying passwords because the app does not support password managers is [MASWE-0019](/mobile/maswe-0019-no-autofill-support-for-credential-providers/), and is usually the root cause worth reporting alongside a clipboard finding. Third-party keyboards seeing what is typed are [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/).

## Modes of Introduction

**Secrets copyable without the user asking.** The app copies a value programmatically as a side effect: it puts the OTP it just received on the clipboard "for convenience", copies a generated password, an API key or a referral link containing a token as soon as the screen opens, or copies a wallet recovery phrase when the user taps "Next". The user never decided to put that value in a shared place.

**Copy features on secret fields.** A "Copy" button next to a card number, IBAN, recovery codes, a TOTP seed or an API key; a `TextView` with `android:textIsSelectable="true"` or a `UITextView` (selectable by default) showing a secret; a PIN or password field built as a plain text field (or a "show password" mode) so the standard Copy and Cut actions work.

**Content not marked sensitive (Android).** A clip without `ClipDescription.EXTRA_IS_SENSITIVE`, so the Android 13+ preview overlay and keyboard clipboard suggestions show it in clear text.

**Universal Clipboard and lifetime not restricted (iOS).** Writing secrets with `UIPasteboard.general.string = …` (or `setItems(_:)` without options), so the item is offered to the user's other Apple devices and stays until something else replaces it.

**Clipboard never cleared.** The secret stays on the clipboard after it has been pasted where it was needed, for hours or days, available to whatever app the user opens next and, on Android, to the keyboard's history.

**Clipboard read without user action.** The app reads the clipboard on launch or resume to look for referral codes, deferred deep links, OTPs or addresses. That is a privacy issue in its own right (and visible to iOS users as a banner or a prompt), and it also feeds the next mode.

**Untrusted clipboard input.** Pasted content is used without validation: a pasted URL is opened or loaded in a WebView, a pasted payment address or IBAN is submitted without being shown, a pasted Android `content://` URI is resolved with the app's own permissions, an `Intent` item from a clip is launched. Any app could have written that content.

## Impact

- **Compromise of sensitive data.** Personal, financial or account data copied in the app is read by another app, a keyboard, a synced device or a shoulder-surfer.
- **Authentication and authorisation bypass.** Copied passwords, OTPs, recovery codes, session tokens or API keys let the attacker take over the account, sometimes long after the copy if the clipboard is never cleared.
- **Manipulated actions.** When the app trusts pasted content, an app that writes to the clipboard can redirect payments (address or IBAN swapping is a long-standing malware technique), feed the app malicious URLs, or make it disclose its own files through a pasted content URI.
- **Privacy exposure.** Reading the clipboard without user action takes data the user copied elsewhere, which is what the iOS and Android notices were introduced to expose.

## Mitigations

- **Keep secrets off the clipboard.** Support password managers and OS autofill (see [MASWE-0019](/mobile/maswe-0019-no-autofill-support-for-credential-providers/)) and SMS/OTP autofill so users never need to copy credentials; disable copy on secret fields (secure text entry on iOS, password input types on Android, or explicitly removing the copy action).
- **Copy only on an explicit user action**, such as a "Copy" button the user taps, never as a side effect.
- **Mark sensitive clips.** On Android set `ClipDescription.EXTRA_IS_SENSITIVE` (or the literal `android.content.extra.IS_SENSITIVE`) on every sensitive clip.
- **Limit reach and lifetime on iOS.** Write sensitive items with `setItems(_:options:)` and both `.localOnly: true` and a short `.expirationDate`.
- **Clear what you copied.** Remove the sensitive item after a short time or when the user leaves the flow, and only if it is still your item.
- **Do not read the clipboard without user intent.** Read it only in response to a paste action, a `UIPasteControl`, or a "Paste" button.
- **Treat pasted data as untrusted input.** Validate format, show it to the user before acting on it, never auto-submit, and refuse URIs that point at your own app's providers.
- **Raise `minSdkVersion` to 29 or higher** if sensitive data can reach the clipboard, so background apps cannot read it.

## Knowledge

OWASP links one Knowledge page to this topic, MASTG-KNOW-0083 for the iOS pasteboard. There is no Android clipboard Knowledge page (the clipboard is only mentioned in passing in [MASTG-KNOW-0020](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0020/)), so we add a supplementary Android section based on the Android developer documentation.

### iOS: Pasteboard (MASTG-KNOW-0083)

Source: [MASTG-KNOW-0083](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0083/), extended from Apple's [`UIPasteboard`](https://developer.apple.com/documentation/uikit/uipasteboard) documentation.

#### General and named pasteboards

[`UIPasteboard`](https://developer.apple.com/documentation/uikit/uipasteboard) gives apps two kinds of pasteboard:

| Pasteboard | How it is obtained | Who can read it | Lifetime |
|---|---|---|---|
| **General** | `UIPasteboard.general` (Objective-C `generalPasteboard`) | Whichever app is in the foreground, plus the user's other devices through Universal Clipboard | Persistent until replaced or cleared, independent of the app that wrote it |
| **Named** | `UIPasteboard(name:create:)` (`pasteboardWithName:create:`), `UIPasteboard.withUniqueName()` (`pasteboardWithUniqueName`) | The creating app and other apps with the same Team ID | Not persistent since iOS 10: removed when the creating app quits or the device restarts; `isPersistent` / `setPersistent:` is deprecated |

The general pasteboard is what the system Copy, Cut and Paste actions use, so anything the user copies from a text field lands there. Named pasteboards are a way for apps of the same developer to exchange data; Apple now recommends an [App Group](https://developer.apple.com/documentation/xcode/configuring-app-groups) for that instead (see the [MASWE-0031 note](/mobile/maswe-0031-allowing-untrusted-app-extensions/)). `UIPasteboard.remove(withName:)` (`removePasteboardWithName:`) invalidates a named pasteboard and has no effect on the general one.

#### Writing items and the options that limit them

A pasteboard holds *items*; each item is a dictionary mapping a type identifier (UTI) to a value, so one item can carry the same content as `public.utf8-plain-text` and `public.url`. The ways to write:

| API (Swift) | Objective-C selector | Options possible? |
|---|---|---|
| `string`, `strings`, `url`, `urls`, `image`, `images`, `color`, `colors` setters | `setString:`, `setStrings:`, `setURL:`, `setURLs:`, `setImage:`, … | No |
| `items` setter | `setItems:` | No |
| [`setItems(_:options:)`](https://developer.apple.com/documentation/uikit/uipasteboard/setitems%28_:options:%29) | `setItems:options:` | **Yes** |
| [`addItems(_:)`](https://developer.apple.com/documentation/uikit/uipasteboard/additems%28_:%29) | `addItems:` | No |
| [`setData(_:forPasteboardType:)`](https://developer.apple.com/documentation/uikit/uipasteboard/setdata%28_:forpasteboardtype:%29), [`setValue(_:forPasteboardType:)`](https://developer.apple.com/documentation/uikit/uipasteboard/setvalue%28_:forpasteboardtype:%29) | `setData:forPasteboardType:`, `setValue:forPasteboardType:` | No |
| `setItemProviders(_:localOnly:expirationDate:)` (iOS 11+) | `setItemProviders:localOnly:expirationDate:` | **Yes** |

Only the options-taking calls can restrict an item, through [`UIPasteboard.OptionsKey`](https://developer.apple.com/documentation/uikit/uipasteboard/optionskey) (iOS 10+):

- [`.localOnly`](https://developer.apple.com/documentation/uikit/uipasteboard/optionskey/localonly) (`UIPasteboardOptionLocalOnly`): `true` keeps the items off Universal Clipboard. It does not hide them from other apps on the same device.
- [`.expirationDate`](https://developer.apple.com/documentation/uikit/uipasteboard/optionskey/expirationdate) (`UIPasteboardOptionExpirationDate`): a `Date` after which the system removes the items.

```swift
import UniformTypeIdentifiers

UIPasteboard.general.setItems(
    [[UTType.utf8PlainText.identifier: otp]],
    options: [.localOnly: true,
              .expirationDate: Date().addingTimeInterval(60)]
)
```

The practical consequence for testing: an app that uses the convenient `string =` setter **cannot** have set either option for that write. That makes MASTG-TEST-0279 and 0280 decidable from the binary in most cases.

#### Reading, changeCount and the privacy notices

Reads are the mirror image: `string`, `strings`, `url`, `image`, `items`, `data(forPasteboardType:)`, `value(forPasteboardType:)`, `itemProviders`. Several properties let an app check what is there without reading the content: `changeCount` (incremented on every change), `numberOfItems`, `hasStrings`, `hasURLs`, `hasImages`, `hasColors` (iOS 10+), `types`, and [`detectPatterns(for:completionHandler:)`](https://developer.apple.com/documentation/uikit/uipasteboard/detectpatterns%28for:completionhandler:%29-23vwn) (iOS 14+), which says whether the content looks like a URL, a web search or a number without returning it. These do not trigger the notices below, which is why well-behaved apps use them to decide whether to enable a Paste button.

How access to the general pasteboard has been restricted:

| iOS version | Change |
|---|---|
| iOS 9 | Only foreground apps can read the general pasteboard. A malicious app still reads whatever is there the next time the user opens it. |
| iOS 10 | Universal Clipboard enabled by default; `localOnly` and `expirationDate` options added; named pasteboards no longer persistent. |
| iOS 14 | A banner (*"‹App› pasted from ‹OtherApp›"*) appears when an app reads content that another app wrote. This exposed many apps and SDKs that read the pasteboard on every launch. |
| iOS 15 | Pastes the user initiates through the system paste UI no longer show the banner. |
| iOS 16 | A programmatic read of content from another app, without a user paste action, shows a confirmation alert (*"‹App› would like to paste from ‹OtherApp›"*, **Allow Paste** / **Don't Allow**). [`UIPasteControl`](https://developer.apple.com/documentation/uikit/uipastecontrol) (and SwiftUI's `PasteButton`) is a system-drawn Paste button whose tap counts as consent, so no alert appears. |
| iOS 16.1 | A per-app **Paste from Other Apps** setting (Ask, Deny, Allow) appears under the app in Settings once the app has asked. |

Two consequences for testers. First, none of this prevents an app from *reading what the user deliberately pasted*, and none of it stops another app from reading a secret your app left behind if the user taps **Allow Paste** or the read follows a paste gesture. The notices make silent harvesting visible; they do not make the pasteboard private. Second, on iOS 16+ the alert is your evidence: if opening the app triggers an "Allow Paste" prompt, the app (or an SDK in it) reads the pasteboard without user intent.

#### Universal Clipboard

With [Universal Clipboard](https://support.apple.com/en-us/102430), content copied on one Apple device can be pasted on another for a short time, when both are signed in to the same Apple Account with Bluetooth, Wi-Fi and Handoff turned on and are near each other. For a secret this means the item reaches a Mac or iPad that may be shared, less well protected, or running other software that watches the clipboard. Only `.localOnly` (or `setItemProviders(_:localOnly:expirationDate:)` with `localOnly: true`) prevents it for a given write.

#### Copy from text fields

The system Copy action is the most common way secrets reach the pasteboard, so the field configuration matters:

- A `UITextField` with [`isSecureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry) `= true` (or SwiftUI `SecureField`) does not offer Copy or Cut. A "show password" toggle that sets it to `false` re-enables them.
- `UITextView` is selectable by default (`isSelectable = true`), so a read-only text view showing a recovery phrase lets the user (and anyone with the device) copy it. `UILabel` is not selectable; SwiftUI `Text` becomes selectable with `.textSelection(.enabled)`.
- Apps can remove Copy from a field by overriding `canPerformAction(_:withSender:)` (returning `false` for `copy(_:)` and `cut(_:)`) or by adjusting the edit menu (`UIEditMenuInteraction` on iOS 16+).
- Custom "Copy" buttons and context-menu actions write to the general pasteboard with whatever API the developer picked, which is where the options above matter.

#### Pitfalls

- `UIPasteboard.general.string = secret` is the most common shape. It cannot carry `localOnly` or an expiry.
- Clearing by assigning `items = []` wipes whatever the user copied from *other* apps since, which users notice and hate; the safe pattern compares `changeCount` with the value saved at copy time.
- `applicationWillTerminate(_:)` is not called when the system kills a suspended app, so clearing "on terminate" rarely runs. Expiry is the reliable control.
- Third-party SDKs (attribution, deferred deep linking, chat widgets) are frequent pasteboard readers on launch. The read is still the app's responsibility.
- Web content in a `WKWebView` can write to the pasteboard through the JavaScript Clipboard API after a user gesture; that write has no options.

### Android: Clipboard framework and OS-version behaviour (supplementary)

Guler Tech supplement, based on the Android developer guides [Copy and paste](https://developer.android.com/develop/ui/views/touch-and-input/copy-paste) and [Secure clipboard handling](https://developer.android.com/privacy-and-security/risks/secure-clipboard-handling), and the [Android 10 privacy changes](https://developer.android.com/about/versions/10/privacy/changes).

#### ClipboardManager, ClipData and ClipDescription

There is one system clipboard per user profile, managed by `ClipboardService` in `system_server` and reached through [`ClipboardManager`](https://developer.android.com/reference/android/content/ClipboardManager) (`context.getSystemService(ClipboardManager::class.java)` or `getSystemService(Context.CLIPBOARD_SERVICE)`). It holds exactly one clip at a time; a new copy by any app replaces it.

- A [`ClipData`](https://developer.android.com/reference/android/content/ClipData) contains one or more `ClipData.Item`s, each holding text (`getText()`), styled HTML text (`getHtmlText()`), a URI (`getUri()`, usually a `content://` URI that the pasting app resolves through a content provider), or an `Intent` (`getIntent()`). Factory methods: `newPlainText(label, text)`, `newHtmlText(label, text, html)`, `newUri(resolver, label, uri)`, `newRawUri(label, uri)`, `newIntent(label, intent)`.
- A [`ClipDescription`](https://developer.android.com/reference/android/content/ClipDescription) carries the label, the MIME types and, since API 24, a `PersistableBundle` of extras (`getExtras()` / `setExtras()`).
- Writes: `setPrimaryClip(ClipData)`; the deprecated `setText(CharSequence)` inherited from `android.text.ClipboardManager` (the framework implementation wraps the text in a `ClipData` and calls `setPrimaryClip`). Reads: `getPrimaryClip()`, `getPrimaryClipDescription()`, `hasPrimaryClip()`, `addPrimaryClipChangedListener()`. Clear: `clearPrimaryClip()` (API 28).

Every copy the framework performs for the app also ends up in `setPrimaryClip` in the app's own process: the Copy action in a `TextView` or `EditText` selection toolbar, a WebView's copy, and Jetpack Compose's clipboard APIs (`LocalClipboardManager.setText`, and `LocalClipboard.setClipEntry` in newer Compose versions). That is why a single Frida hook on `setPrimaryClip` sees every write ([GT-0030-2](#gt-0030-2-sensitive-data-on-the-clipboard-at-runtime-android)).

#### Who can read the clipboard

| Android version | Read access |
|---|---|
| 9 (API 28) and lower | **Any app**, including background services, can call `getPrimaryClip()` or register an `OnPrimaryClipChangedListener` and receive every new clip. Silent sniffing is trivial. |
| 10 (API 29) and higher | Only the app that currently has input focus, or the **default input method (IME)**, can read; other apps get `null` from `getPrimaryClip()` and `getPrimaryClipDescription()`, and change listeners do not fire for them. Writing is not restricted in the same way. |

The restriction depends on the device's Android version, not on the target app's `targetSdkVersion`. What the app controls is `minSdkVersion`: an app that supports Android 9 and lower runs on devices where any installed app can harvest what it copies. Note the IME exception: the user's keyboard can read the clipboard on every version, which is how keyboard clipboard history works.

#### Android 12: access toast

On Android 12 (API 31) and higher the system usually shows a toast, *"‹App› pasted from your clipboard"*, when an app calls `getPrimaryClip()` and receives content another app placed there. It is not shown when the app reads its own clip, after the first read of a given app's clip, or when the app only calls `getPrimaryClipDescription()`. As on iOS, this makes reads visible; it does not prevent them.

#### Android 13: preview, the sensitive flag and auto-clear

On Android 13 (API 33) and higher, the system shows a **visual confirmation** in the corner of the screen whenever content is copied, with a preview of the text or image and an edit button. Apps are told to stop showing their own "Copied" toast on 13+ to avoid duplicates. The preview is the reason for [`ClipDescription.EXTRA_IS_SENSITIVE`](https://developer.android.com/reference/android/content/ClipDescription#EXTRA_IS_SENSITIVE): a boolean extra that makes the preview show dots instead of the content. Google's guidance is that all apps must set it for sensitive clips, regardless of target API level:

```kotlin
val clip = ClipData.newPlainText("otp", code).apply {
    description.extras = PersistableBundle().apply {
        // Compiled against API 33+; with an older compileSdk use the literal
        // "android.content.extra.IS_SENSITIVE" (it is the same string).
        putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
    }
}
clipboardManager.setPrimaryClip(clip)
```

What the flag does and does not do:

- It hides the content in the system preview and, per Google's risk guidance, in keyboard clipboard previews (keyboards decide for themselves whether to honour it). It limits shoulder-surfing and screen-recording exposure.
- It does **not** stop any app or IME that can read the clipboard from reading the value.
- `EXTRA_IS_SENSITIVE` is a compile-time `String` constant, so the compiler inlines it: in the APK you will find the literal `android.content.extra.IS_SENSITIVE`, never a reference to the field. That is what GT-0030-1 searches for.

Android 13 also **clears the clipboard automatically** after a period without new copies (the AOSP default is one hour; device makers can change it). That is a backstop, not a substitute for the app clearing a secret it copied a minute ago.

#### Clearing the clipboard

`clearPrimaryClip()` (API 28) removes the current clip; on older versions apps overwrite it with an empty clip. Clearing unconditionally also destroys whatever the user copied since, so the safe pattern checks the label first with `getPrimaryClipDescription()` (which does not trigger the Android 12 toast). On Android 10+ that check returns `null` while the app does not have focus, so schedule it for when the app is visible.

#### Keyboard clipboard history and sync

Keyboards keep their own copy of what you copied. Gboard's clipboard, when the user enables it, shows recent clips as suggestions and keeps unpinned clips for an hour; other OEM and third-party keyboards have their own retention rules, and some sync clipboard content to a cloud account or a paired PC. None of that is under the app's control, except through the sensitive flag and by not copying secrets in the first place. When you test, look at the keyboard's clipboard panel after copying: it is the most persuasive screenshot in a report.

#### Copy from views

- `EditText` with a password input type (`textPassword`, `numberPassword`, `textWebPassword`, `textVisiblePassword` is *not* one) uses a password transformation, and `TextView` does not offer Copy or Cut while it is applied. A "show password" toggle that swaps in `HideReturnsTransformationMethod` re-enables them.
- A `TextView` with `android:textIsSelectable="true"` (or `setTextIsSelectable(true)`) lets the user long-press and copy. Common on screens showing card numbers, IBANs, recovery codes and API keys.
- Apps remove copy from a field with a custom `ActionMode.Callback` (`setCustomSelectionActionModeCallback` / `setCustomInsertionActionModeCallback`) that removes `android.R.id.copy` and `android.R.id.cut`, or with `setLongClickable(false)` plus `setTextIsSelectable(false)`.
- In Compose, `Text` is selectable only inside `SelectionContainer`; `SecureTextField` / `BasicSecureTextField` do not allow copy or cut.

#### Pasting: what can arrive

When an app pastes, it receives a `ClipData` someone else built. Text can be anything. HTML text may contain script if the app renders it in a WebView. A `content://` URI is resolved by the *pasting* app with the pasting app's own identity and permissions, so a URI pointing at the pasting app's own (non-exported) provider or `FileProvider` makes it read its own private data. An `Intent` item launched by the pasting app is an intent-redirection primitive (see [MASWE-0032](/mobile/maswe-0032-insecure-intents/)). For rich content pasted into editable views, Android recommends `OnReceiveContentListener` (`ViewCompat.setOnReceiveContentListener`), which centralises paste, drag-and-drop and keyboard image input: a good place for validation.

## Tests

> OWASP currently files MASTG-TEST-0276 to 0280 under MASWE-0036; we document them here because they test what an app puts on the iOS pasteboard, which is MASWE-0030's subject. The [MASWE-0036 note](/mobile/maswe-0036-sensitive-data-exposed-via-ui/) links back here.

These five tests replace the legacy v1 test [MASTG-TEST-0073 (Testing UIPasteboard)](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0073/), deprecated with `covered_by: [MASTG-TEST-0276, 0277, 0278, 0279, 0280]`. OWASP has published no demos for them, so the demos below are ours. There is no OWASP Android clipboard test (current or legacy); GT-0030-1 and GT-0030-2 fill that gap, and GT-0030-3 covers the "untrusted clipboard input" mode for both platforms.

All tests share one prerequisite: a list of what counts as sensitive in this app (credentials, OTPs and recovery codes, tokens and keys, card and bank data, personal data, wallet secrets), and of every place in the UI where such data is shown or entered. OWASP calls this `identify-sensitive-data`.

### Before you start: static triage of the iOS binaries

The four static iOS tests all look for the same API family, so do the search once. This follows [MASTG-TECH-0058 (Exploring the App Package)](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/) and [MASTG-TECH-0066 (Static Analysis on iOS)](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/) with [radare2](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/).

1. **Get a decrypted IPA and list every Mach-O.** App Store binaries are FairPlay-encrypted; `otool -l <binary> | grep -A4 LC_ENCRYPTION_INFO` must show `cryptid 0`. Extensions (`PlugIns/*.appex`) and frameworks write to the pasteboard too, so include them.

   ```bash
   unzip -q MyApp.ipa -d ipa_out
   find ipa_out/Payload -type f -print0 | xargs -0 file | grep 'Mach-O' | cut -d: -f1 > macho.txt
   ```

2. **Find pasteboard selectors and UIKit constants in each binary.** Objective-C selectors are stored as strings in `__objc_methname`, also for Swift code calling UIKit, and the option keys are UIKit data symbols the binary imports.

   ```bash
   SEL='^(generalPasteboard|pasteboardWithName:create:|pasteboardWithUniqueName|setPersistent:|setItems:options:|setItems:|addItems:|setString:|setStrings:|setURL:|setURLs:|setImage:|setImages:|setData:forPasteboardType:|setValue:forPasteboardType:|setItemProviders:localOnly:expirationDate:|changeCount)$'
   while read -r b; do
     s=$(strings -a "$b" | grep -E "$SEL" | sort -u | tr '\n' ' ')
     i=$(rabin2 -i "$b" 2>/dev/null | grep -oE 'UIPasteboard(Option|Name)[A-Za-z]+' | sort -u | tr '\n' ' ')
     [ -n "$s$i" ] && printf '%s\n  selectors: %s\n  imports:   %s\n' "$b" "$s" "$i"
   done < macho.txt
   ```

   `setString:`, `setItems:` and `setURL:` are generic names that other classes also use (`NSMutableString` has `setString:`), so treat them as candidates only when `generalPasteboard` or `pasteboardWithName:create:` is present in the same binary. `UIPasteboardOptionLocalOnly` and `UIPasteboardOptionExpirationDate` in the imports mean the options are used *somewhere*; you still need to show they are used on the writes that matter.

3. **Locate the code.** In r2, find the selector string, then follow references: the string is referenced from a selector reference in `__objc_selrefs`, and the code references that.

   ```bash
   r2 -q -c 'aaa; izz~generalPasteboard; izz~setItems:options:' ipa_out/Payload/MyApp.app/MyApp
   r2 -q -c 'aaa; axt @ 0x100012345' ipa_out/Payload/MyApp.app/MyApp   # string address from izz
   # if axt lands in __objc_selrefs, run axt again on that selref address to reach the functions
   ```

   `aaa` is slow on large binaries; on those, analyse only the functions you need (`af @ addr`) after locating them. Then read each calling function with `pdf @ <function>` ([MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)): what value is written, with which selector, and with which options.

4. **Note the lifecycle methods.** For MASTG-TEST-0278 you need to know whether `applicationDidEnterBackground:`, `sceneDidEnterBackground:`, `applicationWillResignActive:` or `applicationWillTerminate:` touch the pasteboard. `rabin2 -c <binary> | grep -E 'DidEnterBackground|WillResignActive|WillTerminate'` lists which delegate methods exist.

Keep the results; each test below evaluates a different aspect of the same call sites.

### MASTG-TEST-0276: Use of the iOS General Pasteboard (iOS)

Source: [MASTG-TEST-0276](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0276/). Platform: iOS. Type: static (code), manual review. OWASP currently files this test under MASWE-0036; we document it here because it is about writing to the clipboard.

#### Overview

Checks whether the app writes sensitive data to the systemwide general pasteboard, the one every foreground app and Universal Clipboard can reach. OWASP lists four write methods (`addItems`, `setItems`, `setData`, `setValue`); in practice the property setters (`string`, `url`, `image`, `items`) are the most common, so we include them.

#### Prerequisites

- Decrypted app binary and extension binaries (see [Before you start](#before-you-start-static-triage-of-the-ios-binaries)).
- The list of sensitive data and the screens that show it.

#### Steps

1. Run the static triage and list every binary that references `generalPasteboard`.
2. For each call site, determine the value written: follow the argument back to its source (a model property, a text field's `text`, a decoded API response). Strings near the call (accessibility labels, toast texts such as "Copied", analytics event names such as `copy_iban`) help map code to UI.
3. Match call sites to UI: walk through the app and tap every Copy button and context-menu Copy action on screens that show sensitive data; note which screens offer one.
4. Check named pasteboards separately: `pasteboardWithName:create:` with a fixed name shared with sibling apps (look at the name string in the disassembly) is reachable by every app of the same team; `setPersistent:` indicates legacy code from before iOS 10.

#### Observation

A list of call sites (binary, function, address) writing to the general pasteboard, with the data each one writes and the user action that triggers it.

#### Evaluation

The test **fails** if sensitive data is written to the general pasteboard. Distinguish two cases in the report, because they rate differently:

- written **without** a user action (on screen load, after an OTP arrives, when a code is generated): fail, rated on the data;
- written **in response to** an explicit Copy action the user chose: still a fail for secrets (passwords, OTPs, recovery codes, keys, full card numbers), with the severity reduced when the write uses `localOnly` and a short `expirationDate` (MASTG-TEST-0279 and 0280 pass). For moderately sensitive data the user legitimately needs elsewhere (an IBAN, a reference number), a user-initiated copy with both options is acceptable.

Writes of non-sensitive data (share links without tokens, order numbers) pass.

#### Demo

A recovery-codes screen with a Copy button:

```swift
@IBAction func copyCodes(_ sender: UIButton) {
    UIPasteboard.general.string = recoveryCodes.joined(separator: "\n")
}
```

Triage output for the main binary:

```text
ipa_out/Payload/MyApp.app/MyApp
  selectors: generalPasteboard setString: setItems:options:
  imports:   UIPasteboardOptionExpirationDate UIPasteboardOptionLocalOnly
```

`setItems:options:` and the option constants are present, which might suggest the app restricts its writes; following the references shows they are used only in the OTP copy flow. The recovery-codes handler (found through `axt` on `setString:` from a function that also references the string "Recovery codes copied") writes with `setString:`. The test fails for that call site: long-lived account recovery secrets on the general pasteboard, Universal Clipboard enabled, no expiry.

### MASTG-TEST-0277: Sensitive Data in the iOS General Pasteboard at Runtime (iOS)

Source: [MASTG-TEST-0277](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0277/). Platform: iOS. Type: dynamic (hooks). OWASP currently files this test under MASWE-0036; we document it here because it is the runtime counterpart of MASTG-TEST-0276.

#### Overview

Observes what the app actually writes to the pasteboard while you use it. It catches writes that static review misses (SDK code, web content in a `WKWebView`, Swift code that is hard to read in disassembly) and gives you the exact values, options and call stacks. OWASP points to [MASTG-TECH-0134 (Monitoring the Pasteboard)](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0134/), which polls the pasteboard; we add write hooks, which are more precise.

#### Prerequisites

- The app installed ([MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/)) on a jailbroken device with [Frida](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), or a re-signed build with Frida Gadget; [objection](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0074/) is optional.
- For a quick look without hooks: the iOS Simulator, if you have a simulator build.
- The list of sensitive flows to exercise.

#### Steps

1. **Quick look with objection.** `ios pasteboard monitor` polls the general pasteboard every five seconds and prints new string content:

   ```bash
   objection -g com.example.myapp explore
   # then, inside objection:
   ios pasteboard monitor
   ```

   On a simulator you can skip instrumentation entirely: perform the copy, then run `xcrun simctl pbpaste booted` on the Mac to print the simulator's pasteboard.

2. **Precise write tracing with Frida.** The general pasteboard is an instance of a private `UIPasteboard` subclass, so hook the methods on the instance's actual class. The script reads the two option keys from UIKit's exported constants rather than hard-coding their values.

   ```javascript
   // gt-pasteboard-trace.js (Frida 17; on Frida 16 use Module.findExportByName(null, name))
   const pb = ObjC.classes.UIPasteboard.generalPasteboard();
   const cls = ObjC.classes[pb.$className];
   const GENERAL = pb.name().toString();
   const key = (n) => new ObjC.Object(Module.getGlobalExportByName(n).readPointer());
   const LOCAL_ONLY = key('UIPasteboardOptionLocalOnly');
   const EXPIRES = key('UIPasteboardOptionExpirationDate');
   const obj = (p) => (p.isNull() ? 'nil' : new ObjC.Object(p).toString());
   const bt = (ctx) => Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 6)
     .map(DebugSymbol.fromAddress).join('\n    ');

   function hook(sel, describe) {
     const m = cls[sel];
     if (m === undefined) { console.log('[-] no ' + sel); return; }
     Interceptor.attach(m.implementation, {
       onEnter(args) {
         const name = new ObjC.Object(args[0]).name().toString();
         const which = name === GENERAL ? 'general' : 'named:' + name;
         console.log('\n[' + which + '] ' + sel + ' ' + describe(args) + '\n    ' + bt(this.context));
       }
     });
   }

   hook('- setItems:options:', (a) => {
     const o = a[3].isNull() ? null : new ObjC.Object(a[3]);
     return 'items=' + obj(a[2]) +
       ' localOnly=' + (o ? obj(o.objectForKey_(LOCAL_ONLY)) : 'nil') +
       ' expirationDate=' + (o ? obj(o.objectForKey_(EXPIRES)) : 'nil');
   });
   hook('- setItems:', (a) => 'items=' + obj(a[2]));
   hook('- addItems:', (a) => 'items=' + obj(a[2]));
   hook('- setString:', (a) => 'string=' + obj(a[2]));
   hook('- setStrings:', (a) => 'strings=' + obj(a[2]));
   hook('- setURL:', (a) => 'url=' + obj(a[2]));
   hook('- setValue:forPasteboardType:', (a) => 'type=' + obj(a[3]) + ' value=' + obj(a[2]));
   hook('- setData:forPasteboardType:', (a) => 'type=' + obj(a[3]) + ' bytes=' +
     (a[2].isNull() ? 0 : new ObjC.Object(a[2]).length()));
   ```

   ```bash
   frida -U -f com.example.myapp -l gt-pasteboard-trace.js
   ```

   A convenience setter may call `setItems:` internally, so one user action can produce two log lines; the first one, with the app frame in the backtrace, is the one to report.

3. **Exercise every sensitive flow**: Copy buttons, long-press Copy on every field and label that shows sensitive data (including in web content), share sheets that offer **Copy** (the `copyToPasteboard` activity), "copy code" actions in OTP and 2FA screens, password generators.
4. **Confirm from the outside.** After each copy, switch to another app (Notes is enough) and paste. On a second Apple device signed in to the same account, paste within a minute to check Universal Clipboard.

#### Observation

The log of writes (pasteboard, selector, value, options, backtrace) per user action, and the paste results from step 4.

#### Evaluation

The test **fails** if sensitive data is written to the **general** pasteboard (named pasteboards are covered by step 4 of MASTG-TEST-0276), with the same distinction between programmatic and user-initiated copies as MASTG-TEST-0276. The options in the log decide MASTG-TEST-0279 and 0280 for each write at the same time.

#### Demo

The OTP screen copies the code automatically when it arrives:

```swift
func didReceive(code: String) {
    codeLabel.text = code
    UIPasteboard.general.string = code   // "so the user can paste it"
}
```

Frida output when the code arrives (no user action):

```text
[general] - setString: string=482913
    0x1024c8f10 MyApp!OTPViewController.didReceive(code:)
    0x1024c7a2c MyApp!OTPService.handle(_:)
    ...
```

The test fails: a one-time code placed on the general pasteboard without user action, with no expiry and Universal Clipboard enabled. Pasting in Notes and on a paired iPad both produce the code.

### MASTG-TEST-0278: Pasteboard Contents Not Cleared After Use (iOS)

Source: [MASTG-TEST-0278](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0278/). Platform: iOS. Type: static (code). OWASP currently files this test under MASWE-0036; we document it here with the other pasteboard tests.

#### Overview

Checks whether an app that writes sensitive data to the general pasteboard removes it when the user leaves the app. OWASP describes the pattern as `UIPasteboard.general.items = []` in `applicationDidEnterBackground(_:)` or `applicationWillTerminate(_:)`; in scene-based apps the equivalent hook is `sceneDidEnterBackground(_:)` or `sceneWillResignActive(_:)`.

#### Prerequisites

- Results of the static triage, including the lifecycle methods (step 4).
- At least one call site from MASTG-TEST-0276 that writes sensitive data. If the app writes nothing sensitive, this test is not applicable.

#### Steps

1. Disassemble each background/terminate lifecycle method (`pdf @ <addr>` in r2) and look for `generalPasteboard` followed by `setItems:` (the `items` setter) with an empty array, `setString:` with an empty string, or `setItems:options:`.
2. Check whether the clearing is conditional on `changeCount`: a load of `changeCount` and a comparison with a stored value before the write is the correct pattern.
3. Verify dynamically with the Frida script from MASTG-TEST-0277: copy the sensitive value, send the app to the background (swipe up to the home screen), and look for the clearing write in the log; then open Notes and paste.
4. Repeat with the app killed from the app switcher, and with the app left in the background for a few minutes: suspended apps that are later killed never run `applicationWillTerminate(_:)`.

#### Observation

Whether and where the app clears the pasteboard, whether it checks `changeCount`, and the paste results after backgrounding.

#### Evaluation

The test **fails** if the app writes sensitive data to the general pasteboard and the data is still pasteable in another app after the user leaves the app, unless the write carried a short `expirationDate` (MASTG-TEST-0279) that has elapsed. OWASP's text asks specifically for `setItems` with an empty array in a lifecycle method; we accept any mechanism that removes the item (including expiry), because the goal is the item's absence, not a particular call. Clearing without a `changeCount` check is a pass for this test but worth a note: it deletes whatever the user copied from other apps in the meantime, which leads users and developers to remove the feature.

#### Demo

```swift
func sceneDidEnterBackground(_ scene: UIScene) {
    // nothing pasteboard-related here
}
```

Static triage shows no pasteboard selector in any lifecycle method. Dynamically: copy the recovery codes, go to the home screen, open Notes, paste: the codes appear, and they are still there an hour later. The test fails.

### MASTG-TEST-0279: Pasteboard Contents Not Expiring (iOS)

Source: [MASTG-TEST-0279](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0279/). Platform: iOS. Type: static (code). OWASP currently files this test under MASWE-0036; we document it here with the other pasteboard tests.

#### Overview

Checks whether sensitive pasteboard writes carry an expiration date, set through `setItems(_:options:)` with `UIPasteboard.OptionsKey.expirationDate` (or `setItemProviders(_:localOnly:expirationDate:)`). Expiry is the one control that works even if the app is killed or the user never returns to it.

#### Prerequisites

- Call sites from MASTG-TEST-0276 that write sensitive data.

#### Steps

1. For each sensitive call site, note the selector. If it is anything other than `setItems:options:` or `setItemProviders:localOnly:expirationDate:`, the write has no expiry; you are done for that call site.
2. For `setItems:options:` call sites, read the options dictionary construction before the call: look for a load of the `UIPasteboardOptionExpirationDate` import and a `Date`/`NSDate` value (for example `dateWithTimeIntervalSinceNow:` or Swift's `Date.addingTimeInterval`). Note the interval if you can recover it.
3. Confirm with the Frida script from MASTG-TEST-0277: the `expirationDate=` field shows the actual date. Then wait past it and paste in Notes to confirm the item is gone.

#### Observation

For each sensitive write: selector, expiry present or not, and the expiry interval.

#### Evaluation

The test **fails** if a sensitive item is written to the general pasteboard without an expiration date. OWASP's text fails any use of the general pasteboard without expiry; we restrict it to sensitive writes, since an expiry on a copied order number protects nothing. An expiry measured in hours for an OTP or password is a weak pass; note it. As a guide, we expect seconds to a couple of minutes for credentials and codes, and a few minutes for other sensitive values.

#### Demo

```swift
UIPasteboard.general.setItems([[UTType.utf8PlainText.identifier: iban]],
                              options: [.localOnly: true])
```

Frida output:

```text
[general] - setItems:options: items=(
        {
        "public.utf8-plain-text" = "GB33BUKB20201555555555";
    }
) localOnly=1 expirationDate=nil
```

`localOnly` is set (MASTG-TEST-0280 passes), but there is no expiry: the IBAN stays on the pasteboard indefinitely. For an IBAN copied on request this is a low-severity fail; for a password it would be higher.

### MASTG-TEST-0280: Pasteboard Contents Not Restricted to Local Device (iOS)

Source: [MASTG-TEST-0280](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0280/). Platform: iOS. Type: static (code). OWASP currently files this test under MASWE-0036; we document it here with the other pasteboard tests.

#### Overview

Checks whether sensitive pasteboard writes are restricted to the device with `UIPasteboard.OptionsKey.localOnly`, so Universal Clipboard does not offer them to the user's other Apple devices.

#### Prerequisites

- Call sites from MASTG-TEST-0276 that write sensitive data.
- For dynamic confirmation: a second Apple device (iPad or Mac) signed in to the same Apple Account, with Bluetooth, Wi-Fi and Handoff enabled on both.

#### Steps

1. As in MASTG-TEST-0279 step 1: any selector other than `setItems:options:` or `setItemProviders:localOnly:expirationDate:` means no `localOnly` for that write.
2. For `setItems:options:`, look for the `UIPasteboardOptionLocalOnly` import being loaded as a dictionary key with a `true` value (in Swift, a `Bool` boxed into an `NSNumber`).
3. Confirm with the Frida script (`localOnly=1`), then copy on the iPhone and try to paste on the second device within a minute.

#### Observation

For each sensitive write: `localOnly` set or not, and whether the second device could paste it.

#### Evaluation

The test **fails** if a sensitive item is written to the general pasteboard without `localOnly: true`. As with MASTG-TEST-0279, we apply this to sensitive writes only, where OWASP's text applies it to every general-pasteboard use.

#### Demo

```swift
UIPasteboard.general.setItems([[UTType.utf8PlainText.identifier: apiKey]],
                              options: [.expirationDate: Date().addingTimeInterval(120)])
```

Frida output shows `localOnly=nil expirationDate=2026-…`. On the paired Mac, **Edit > Paste** in TextEdit within the two minutes produces the API key. The test fails; the expiry limits the window but the key has already reached a second machine.

### GT-0030-1: Clipboard writes of sensitive data without the sensitive flag (Android)

Guler Tech methodology. Platform: Android. Type: static (code and resources).

#### Overview

Finds every place where the app writes to the clipboard, decides which writes can carry sensitive data, and checks whether those writes set `EXTRA_IS_SENSITIVE`, are triggered only by the user, and are cleared. It also finds the views that let users copy sensitive values through the system selection toolbar. This is the Android counterpart of MASTG-TEST-0276 plus the Android-only sensitive flag.

#### Prerequisites

- The APK (or split APKs from `adb shell pm path com.example.app` and `adb pull`), decoded with [Apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/) and decompiled with [jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/); [semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) optional.
- The app's `minSdkVersion` (from `apktool.yml` or `aapt2 dump badging`), because it determines whether background apps can read what is copied.
- The list of sensitive data and screens.

#### Steps

1. **Decode and decompile.**

   ```bash
   apktool d -f app.apk -o apk_out
   jadx -d jadx_out app.apk
   grep -E 'minSdkVersion|targetSdkVersion' apk_out/apktool.yml
   ```

2. **Find clipboard API calls in smali.** Framework classes are never renamed by R8, so this works on obfuscated apps and also catches libraries:

   ```bash
   grep -rnoE 'Landroid/(content|text)/ClipboardManager;->(setPrimaryClip|setText|clearPrimaryClip|getPrimaryClip|getPrimaryClipDescription|addPrimaryClipChangedListener)' apk_out/smali* \
     | awk -F: '{print $1 " -> " $NF}' | sort | uniq -c
   ```

3. **Find the sensitive flag.** `ClipDescription.EXTRA_IS_SENSITIVE` is inlined as a string constant:

   ```bash
   grep -rln 'android.content.extra.IS_SENSITIVE' apk_out/smali* jadx_out/sources
   ```

   No hit at all means no clip in the app is ever flagged.

4. **Review each write in jadx.** Open the class from step 2 and answer: what reaches `ClipData.newPlainText(label, text)` (follow `text` back to its source); is the `PersistableBundle` with the flag set on *this* clip's description before `setPrimaryClip`; what triggers the method (an `OnClickListener` on a Copy button, a lifecycle method, a callback from an SMS retriever or push); is there a scheduled `clearPrimaryClip()` afterwards. A semgrep rule speeds this up on large apps:

   ```yaml
   rules:
     - id: gt-android-clipboard-write
       languages: [java]
       severity: WARNING
       message: Clipboard write. Check what data reaches the clip and whether IS_SENSITIVE is set on it.
       pattern: $CM.setPrimaryClip(...)
     - id: gt-android-clipboard-sensitive-flag
       languages: [java]
       severity: INFO
       message: IS_SENSITIVE set on a clip description.
       pattern: $B.putBoolean("android.content.extra.IS_SENSITIVE", ...)
   ```

   ```bash
   semgrep --config gt-clipboard.yaml jadx_out/sources
   ```

5. **Find copyable sensitive views.** In layouts and code:

   ```bash
   grep -rn 'textIsSelectable="true"' apk_out/res/
   grep -rnE 'inputType="[^"]*[Pp]assword' apk_out/res/layout*/
   grep -rlE 'setTextIsSelectable\(true\)|SelectionContainer|setCustomSelectionActionModeCallback|HideReturnsTransformationMethod' jadx_out/sources
   ```

   Compare with your list of sensitive fields: a PIN, CVV or OTP field without a password input type, a selectable `TextView` showing a card number or recovery phrase, a "show password" toggle. Confirm on the device by long-pressing each one.

#### Observation

A table of clipboard writes (class and method, data, trigger, flag set, cleared) and of copyable sensitive views, plus `minSdkVersion`.

#### Evaluation

The test **fails** if any of the following holds for sensitive data:

- it is written to the clipboard without a user action;
- it is written without `EXTRA_IS_SENSITIVE` (applies to all apps regardless of `targetSdkVersion`; the flag has an effect on devices running Android 13+);
- a secret (password, OTP, recovery code, key, full card number or CVV) is copyable at all, either through a Copy feature or through a selectable view or non-password field, unless there is a documented product need, the copy is user-initiated, flagged and cleared;
- it is written and `minSdkVersion` is below 29, so background apps on older devices can read it (a severity factor rather than a separate failure).

It passes when sensitive data never reaches the clipboard, or reaches it only on user request, flagged, and cleared after a short time.

#### Demo

```kotlin
binding.copyCard.setOnClickListener {
    val cm = getSystemService(ClipboardManager::class.java)
    cm.setPrimaryClip(ClipData.newPlainText("card", card.pan))
    Toast.makeText(this, R.string.copied, Toast.LENGTH_SHORT).show()
}
```

```text
$ # step 2 command
      1 apk_out/smali_classes2/com/example/app/card/CardDetailsActivity$onCreate$2.smali -> Landroid/content/ClipboardManager;->setPrimaryClip
$ # step 3 command: no output
```

The card number goes to the clipboard on tap, without the flag and without clearing; with `minSdkVersion 26`, any background app on Android 8 or 9 devices receives it. The test fails.

### GT-0030-2: Sensitive data on the clipboard at runtime (Android)

Guler Tech methodology. Platform: Android. Type: dynamic (hooks and manual).

#### Overview

Watches every clipboard write the app makes, including those from WebViews, Compose and third-party libraries, and shows what another app and the keyboard actually see. It is the Android counterpart of MASTG-TEST-0277 and the way to prove GT-0030-1 findings.

#### Prerequisites

- A rooted device or emulator with [frida-server](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/), or the app repackaged with Frida Gadget. Ideally two devices: one on Android 13+ (preview, auto-clear) and, if `minSdkVersion` is below 29, one on Android 9 or lower.
- A second "helper" app you control on the same device to act as the reading app (any lab app works, since we inject the reading code with Frida).
- Gboard (or the keyboard your client's users are likely to have) with its clipboard feature enabled.

We do not rely on an adb shell command to read the clipboard, because availability differs across Android versions; reading from a foreground helper app also reproduces the real attacker position.

#### Steps

1. **Trace writes, reads and clears in the target app.**

   ```javascript
   // gt-clip-trace.js
   Java.perform(() => {
     const CM = Java.use('android.content.ClipboardManager');
     const Log = Java.use('android.util.Log');
     const Exception = Java.use('java.lang.Exception');
     const FLAG = 'android.content.extra.IS_SENSITIVE';
     const stack = () => Log.getStackTraceString(Exception.$new()).split('\n').slice(1, 7).join('\n    ');

     CM.setPrimaryClip.overload('android.content.ClipData').implementation = function (clip) {
       const d = clip.getDescription();
       const extras = d.getExtras();
       const sensitive = extras !== null && extras.getBoolean(FLAG, false);
       console.log('\n[setPrimaryClip] label=' + d.getLabel() + ' mime=' + d.getMimeType(0) +
         ' IS_SENSITIVE=' + sensitive);
       for (let i = 0; i < clip.getItemCount(); i++) {
         const it = clip.getItemAt(i);
         console.log('  item[' + i + '] text=' + it.getText() + ' uri=' + it.getUri() + ' intent=' + it.getIntent());
       }
       console.log('    ' + stack());
       return this.setPrimaryClip(clip);
     };

     if (CM.clearPrimaryClip !== undefined) {
       CM.clearPrimaryClip.implementation = function () {
         console.log('\n[clearPrimaryClip]\n    ' + stack());
         return this.clearPrimaryClip();
       };
     }

     CM.getPrimaryClip.implementation = function () {
       const r = this.getPrimaryClip();
       console.log('\n[getPrimaryClip] -> ' + r + '\n    ' + stack());
       return r;
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l gt-clip-trace.js
   ```

2. **Exercise every flow** that shows or handles sensitive data: Copy buttons, long-press Copy on every sensitive field and label (also in WebView screens), share actions offering Copy, OTP and 2FA screens, password or key generators, and app launch and resume (for reads).
3. **Read the clipboard from another app.** Bring your helper app to the foreground and inject a reader into it (`-F` attaches to the frontmost app):

   ```javascript
   // gt-clip-read.js
   Java.perform(() => {
     Java.scheduleOnMainThread(() => {
       const app = Java.use('android.app.ActivityThread').currentApplication();
       const cm = Java.cast(app.getSystemService('clipboard'), Java.use('android.content.ClipboardManager'));
       const clip = cm.getPrimaryClip();
       console.log(clip === null ? '[-] nothing readable' : '[+] ' + clip.getItemAt(0).getText());
     });
   });
   ```

   ```bash
   frida -U -F -l gt-clip-read.js
   ```

   On Android 12+ the target user sees the "pasted from your clipboard" toast at this point; note it. Pasting into any other app's text field shows the same thing without tooling.
4. **On Android 9 or lower** (only relevant if `minSdkVersion` < 29): run the reader with the helper app in the *background* (attach with `frida -U -N <helper package>` while the target app is in front) to show that background reads succeed.
5. **Check the visible surfaces.** On Android 13+, screenshot the copy preview right after copying (masked dots or clear text). Open the keyboard in any text field and open its clipboard panel: is the value there, and is it masked?
6. **Check lifetime.** Wait the clearing interval the app claims (or a few minutes), then read again from the helper app.

#### Observation

Per sensitive flow: the write log (value, flag, stack), whether and when the app clears it, what the helper app reads, the preview and keyboard screenshots, and the OS versions used.

#### Evaluation

The test **fails** under the same conditions as GT-0030-1, now proven: sensitive data written without user action, without `IS_SENSITIVE`, or left on the clipboard after the flow. It also fails if the app reads the clipboard (`getPrimaryClip` in the log) on launch or resume without a user paste action; that is rated as a privacy issue and leads into GT-0030-3. A write that shows `IS_SENSITIVE=true`, is user-initiated and is followed by `clearPrimaryClip` within a short interval passes.

#### Demo

Frida output from the target app when the user taps "Copy OTP" in a 2FA screen:

```text
[setPrimaryClip] label=otp mime=text/plain IS_SENSITIVE=false
  item[0] text=482913 uri=null intent=null
    at android.content.ClipboardManager.setPrimaryClip(Native Method)
    at com.example.app.auth.OtpFragment.copyCode(OtpFragment.kt:88)
    ...
```

The helper app reads `[+] 482913`; the Android 14 copy preview and Gboard's clipboard both show the code in clear; no `clearPrimaryClip` follows. The test fails (user-initiated copy of an OTP, not flagged, not cleared).

### GT-0030-3: Untrusted clipboard input (Android and iOS)

Guler Tech methodology. Platform: Android and iOS. Type: static and dynamic.

#### Overview

Any app can write to the clipboard, so whatever the target app pastes is attacker-controllable input. This test finds where the app reads the clipboard, whether it does so without user action, and whether it validates and confirms pasted data before acting on it. It covers the MASWE-0030 mode "Untrusted Clipboard Input" and the related privacy issue of silent reads.

#### Prerequisites

- The decompiled app (Android) or the triage results (iOS).
- The Frida trace scripts from GT-0030-2 (Android) or a read-hooking variant of `gt-pasteboard-trace.js` (iOS, below).
- A way to plant clipboard content: a helper app with Frida (both platforms), `xcrun simctl pbcopy booted` (iOS Simulator), or simply copying from Notes.

#### Steps

1. **Find the reads.** Android: the smali grep from GT-0030-1 step 2 (`getPrimaryClip`, `addPrimaryClipChangedListener`), plus `coerceToText`, `getUri` and `getIntent` on `ClipData$Item`, and `OnReceiveContentListener` implementations. iOS: the selectors `string`, `strings`, `URL`, `items`, `itemProviders`, `dataForPasteboardType:`, `detectPatternsForPatterns:completionHandler:` near `generalPasteboard`, and whether they sit in `application:didFinishLaunchingWithOptions:`, `applicationDidBecomeActive:` or `sceneDidBecomeActive:` (silent reads).
2. **Trace reads at runtime.** Android: the `getPrimaryClip` hook in `gt-clip-trace.js` logs every read with its stack. iOS: add read hooks to the trace script:

   ```javascript
   ['- string', '- strings', '- URL', '- items', '- itemProviders', '- dataForPasteboardType:']
     .forEach((sel) => hook(sel, () => ''));
   ```

   Launch the app cold, bring it back from the background, and open each screen. Any read without a paste action is a finding; on iOS 16+ it also produces the "Allow Paste" alert, and on Android 12+ the toast.
3. **Plant hostile content** and trigger each paste path (fields with paste, "Paste" buttons, automatic detection of codes, links or addresses). Useful payloads: a very long string; text with HTML and script if pasted text is rendered anywhere; a URL with a `javascript:` scheme, the app's own custom scheme, or a lookalike domain; a different IBAN or wallet address in the same format as a legitimate one; on Android a `content://` URI pointing at the app's own `FileProvider` or provider (authorities from `AndroidManifest.xml`) and an `intent:` item.

   ```javascript
   // gt-clip-write.js, injected into a foreground helper app: frida -U -F -l gt-clip-write.js
   const PAYLOAD = 'content://com.example.app.fileprovider/internal/databases/session.db';
   Java.perform(() => {
     Java.scheduleOnMainThread(() => {
       const app = Java.use('android.app.ActivityThread').currentApplication();
       const cm = Java.cast(app.getSystemService('clipboard'), Java.use('android.content.ClipboardManager'));
       const clip = Java.use('android.content.ClipData').newRawUri('attachment', Java.use('android.net.Uri').parse(PAYLOAD));
       cm.setPrimaryClip(clip);
       console.log('[+] planted ' + clip);
     });
   });
   ```

   On iOS, from a helper app with Frida: `ObjC.classes.UIPasteboard.generalPasteboard().setString_('https://example.org/login')`; on the Simulator: `echo -n 'https://example.org/login' | xcrun simctl pbcopy booted`.
4. **Observe** what the app does with each payload: is it shown to the user before use, validated against the expected format, auto-submitted, opened, loaded in a WebView, resolved (content URIs) and uploaded or displayed?

#### Observation

The list of read sites (silent or user-initiated) and, for each payload, the app's behaviour with screenshots and traces.

#### Evaluation

The test **fails** if:

- the app reads the clipboard without a user paste action (privacy finding; also check which SDK does it from the stack trace);
- pasted data drives a security-relevant action without the user seeing and confirming it (a payment destination, a login or reset link, a deep link to an internal screen);
- pasted data reaches a dangerous sink without validation: a WebView, `openURL`/`startActivity`, a file path, or a content resolver call that returns the app's own private data;
- the app launches an `Intent` taken from a clip.

It passes when the app reads only on user request, validates the format, shows the pasted value in context, and refuses URIs whose authority belongs to the app itself.

#### Demo

An Android chat app lets users paste an attachment:

```kotlin
val item = clipboard.primaryClip?.getItemAt(0) ?: return
item.uri?.let { uri ->
    contentResolver.openInputStream(uri)?.use { upload(it, chatId) }   // resolved with the app's own identity
}
```

With `gt-clip-write.js` planting `content://com.example.app.fileprovider/internal/databases/session.db` (the app's `FileProvider` maps `internal` to `files-path path="."`, so the URI reaches its own data directory) and the user tapping **Paste attachment** in a chat with the attacker, the app uploads its own session database. The test fails; the root cause is shared with the [MASWE-0032](/mobile/maswe-0032-insecure-intents/) and [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/) material on providers, and the fix is to reject URIs with the app's own authorities and to scope the `FileProvider` paths.

## Best practices

### MASTG-BEST-0045: Limit Sensitive Data Exposure Through iOS IPC Channels (pasteboard part)

Source: [MASTG-BEST-0045](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0045/). Platform: iOS. The practice covers all iOS IPC channels; the parts that apply here are:

- **Restrict pasteboard usage.** Do not put sensitive values on `UIPasteboard.general` unless the product genuinely needs it. If it does, write with `setItems(_:options:)` and both `.localOnly` and `.expirationDate`.
- **Validate all IPC input.** Pasteboard contents are untrusted input, even though the user performed the paste: another app wrote them.
- **Prefer App Groups to named pasteboards** for exchanging data between your own apps and extensions (see the [MASWE-0031 note](/mobile/maswe-0031-allowing-untrusted-app-extensions/)).

### Secure patterns (Guler Tech)

**iOS: copy a secret only on request, locally, briefly, and clear only your own item.**

```swift
import UniformTypeIdentifiers

final class SecureCopy {
    private static var ourChangeCount: Int?

    static func copy(_ value: String, lifetime: TimeInterval = 60) {
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: value]],
            options: [.localOnly: true,
                      .expirationDate: Date().addingTimeInterval(lifetime)])
        ourChangeCount = UIPasteboard.general.changeCount
    }

    // Call from sceneDidEnterBackground(_:) / applicationDidEnterBackground(_:)
    static func clearIfStillOurs() {
        if UIPasteboard.general.changeCount == ourChangeCount {
            UIPasteboard.general.items = []
        }
        ourChangeCount = nil
    }
}
```

Reading `changeCount` does not trigger the paste notices. For fields, use `isSecureTextEntry` (or `SecureField`) for secrets, keep secret displays in non-selectable views, and set `textContentType` (`.password`, `.newPassword`, `.oneTimeCode`) so autofill removes the reason to copy. For paste features, use `UIPasteControl` / `PasteButton` rather than reading the pasteboard on launch, and check `hasStrings` or `detectPatterns(for:)` to decide whether to offer the button.

**Android: flag, copy on request, clear your own clip.**

```kotlin
object SecureCopy {
    private const val LABEL = "com.example.app.secure"

    fun copy(context: Context, value: CharSequence) {
        val cm = context.getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText(LABEL, value).apply {
            description.extras = PersistableBundle().apply {
                putBoolean("android.content.extra.IS_SENSITIVE", true)   // = ClipDescription.EXTRA_IS_SENSITIVE
            }
        }
        cm.setPrimaryClip(clip)
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.S_V2) {
            Toast.makeText(context, R.string.copied, Toast.LENGTH_SHORT).show()   // 13+ shows its own UI
        }
    }

    // Call while the app is visible, e.g. from a timer started on copy and from onStop()
    fun clearIfStillOurs(context: Context) {
        val cm = context.getSystemService(ClipboardManager::class.java)
        if (cm.primaryClipDescription?.label == LABEL) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) cm.clearPrimaryClip()
            else cm.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }
}
```

Also: password input types (or Compose `SecureTextField`) for secrets; no `textIsSelectable` on secret displays; autofill hints and the SMS Retriever or SMS User Consent APIs instead of asking users to copy codes; `minSdkVersion` 29 or higher for apps handling sensitive data.

**Both platforms: pasted data is input.** Read only on a user action. Validate against the expected format (an OTP is six digits; an IBAN has a checksum). Show the pasted value in its destination field so the user sees what will be used, and never auto-submit. On Android, reject `content://` URIs whose authority is one of your own, do not launch clip `Intent`s, and render pasted HTML as text.

## Rating findings

Rate on four things: **what reaches the clipboard** (long-lived secrets such as passwords, recovery codes, keys and tokens; short-lived ones such as OTPs; financial and personal data), **how it gets there** (programmatically without user action, or on an explicit Copy), **how far it spreads** (Android `minSdkVersion` below 29 means any background app on older devices; Universal Clipboard; keyboard history; no clearing or expiry), and **who the attacker is**. The realistic attacker positions are: a malicious or over-curious app the user opens later (iOS, Android 10+; the user sees a banner, toast or prompt but rarely understands it); any installed app running in the background (Android 9 and lower, no user interaction); the user's keyboard, which can always read the clipboard on Android; anyone with access to another device on the same Apple Account; and a shoulder-surfer or screen recorder for previews. None of these needs root or special permissions.

| Rating | Conditions |
|---|---|
| **Critical** | Rare. Long-lived master secrets (wallet recovery phrase or private key, password-vault master password, a long-lived bearer or API token that grants account access) placed on the clipboard **programmatically** without user action, on a platform configuration where any app can read them without the user noticing (Android app supporting API 28 and lower), and never cleared. |
| **High** | Long-lived secrets copied on a user action without platform protections (no `IS_SENSITIVE`, no `localOnly`/expiry, no clearing); OTPs or session tokens copied programmatically; pasted data driving a security-relevant action without confirmation (payment destination, login link) or reaching the app's own private data (content URI confused deputy); clip `Intent`s launched. |
| **Medium** | OTPs, CVVs or full card numbers copyable on a user action without flag, expiry or clearing; password or PIN fields that allow copy (non-secure field, "show password" mode); silent clipboard reads on launch or resume by the app or an SDK that process the content; pasted URLs opened or loaded in a WebView without validation. |
| **Low** | Moderately sensitive personal or account data (email, phone, IBAN, account number) copied on request without the Android flag or iOS options; sensitive data cleared but only after a long interval; `minSdkVersion` below 29 as an aggravating note on a lower finding; clearing without a `changeCount` or label check. |
| **Info** | Correctly protected copies (user-initiated, flagged or `localOnly` with short expiry, cleared); named pasteboards between the developer's own apps holding non-sensitive data; `setPersistent:` calls that have no effect on current iOS; reads only through `UIPasteControl` or user paste actions. |

Raise a level when the app's user base makes clipboard harvesting worth an attacker's time (crypto wallets, banking, password managers, 2FA apps), or when the copied secret is not short-lived. Lower a level when the copied value is useless without a second factor the attacker cannot get. In the report, show the code location, the user action (or lack of it), the trace output, what a second app read, and the preview or keyboard-history screenshot: they make the risk obvious to readers who think of the clipboard as private.

## References

- OWASP MASWE: [MASWE-0030: Improper Use of the Clipboard](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0030/); related [MASWE-0036](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0036/), [MASWE-0031](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0031/), [MASWE-0019](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0019/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/), [MASVS-STORAGE-2](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0083: Pasteboard](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0083/), [MASTG-KNOW-0020: Inter-Process Communication (IPC) Mechanisms](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0020/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0276](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0276/), [MASTG-TEST-0277](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0277/), [MASTG-TEST-0278](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0278/), [MASTG-TEST-0279](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0279/), [MASTG-TEST-0280](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0280/); legacy [MASTG-TEST-0073](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0073/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0045](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0045/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0134](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0134/) (CC BY-SA 4.0)
- OWASP MASTG tools: [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [objection (MASTG-TOOL-0074)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0074/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [Frida for Android (MASTG-TOOL-0001)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) (CC BY-SA 4.0)
- Apple: [`UIPasteboard`](https://developer.apple.com/documentation/uikit/uipasteboard), [`UIPasteboard.general`](https://developer.apple.com/documentation/uikit/uipasteboard/general), [`setItems(_:options:)`](https://developer.apple.com/documentation/uikit/uipasteboard/setitems%28_:options:%29), [`UIPasteboard.OptionsKey`](https://developer.apple.com/documentation/uikit/uipasteboard/optionskey), [`localOnly`](https://developer.apple.com/documentation/uikit/uipasteboard/optionskey/localonly), [`expirationDate`](https://developer.apple.com/documentation/uikit/uipasteboard/optionskey/expirationdate), [`detectPatterns(for:completionHandler:)`](https://developer.apple.com/documentation/uikit/uipasteboard/detectpatterns%28for:completionhandler:%29-23vwn), [`UIPasteControl`](https://developer.apple.com/documentation/uikit/uipastecontrol), [`isSecureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry), [Use Universal Clipboard (Apple Support 102430)](https://support.apple.com/en-us/102430), [Configuring App Groups](https://developer.apple.com/documentation/xcode/configuring-app-groups)
- Android Developers: [Copy and paste](https://developer.android.com/develop/ui/views/touch-and-input/copy-paste) (system notification on access, visual confirmation, sensitive content), [Secure clipboard handling](https://developer.android.com/privacy-and-security/risks/secure-clipboard-handling), [Privacy changes in Android 10](https://developer.android.com/about/versions/10/privacy/changes), [`ClipboardManager`](https://developer.android.com/reference/android/content/ClipboardManager), [`ClipData`](https://developer.android.com/reference/android/content/ClipData), [`ClipDescription`](https://developer.android.com/reference/android/content/ClipDescription), [Receive rich content](https://developer.android.com/guide/topics/input/receive-rich-content), [Copy and paste in Compose](https://developer.android.com/develop/ui/compose/touch-input/copy-and-paste)
- Google: [Android 13 announcement](https://blog.google/products/android/android-13/) (clipboard auto-clear)
- [Frida documentation](https://frida.re/docs/home/), [objection](https://github.com/sensepost/objection), [radare2 book](https://book.rada.re/)
- CWE: [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-668](https://cwe.mitre.org/data/definitions/668.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
