---
title: "Allowing Untrusted App Extensions (MASWE-0031)"
date: 2026-11-09 21:02:00 +0000
subcategory: platform
summary: "Testing iOS apps for third-party keyboards on sensitive input, over-shared App Groups and keychain groups, and unsafe share and action extensions."
refs: [MASWE-0031, MASVS-PLATFORM-1, MASVS-STORAGE-2, CWE-829]
tags: [ios, masvs-platform, app-extensions, custom-keyboards, app-groups]
---

This note is part of our [MASVS-PLATFORM guide](/mobile/masvs-platform-platform-interaction-guide/) and covers OWASP [MASWE-0031](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0031/): iOS apps that let app extensions they do not control see the data they handle, and apps whose own extensions widen the attack surface. App extensions are pieces of third-party code that iOS runs next to, and on behalf of, other apps: a custom keyboard sees every keystroke typed while it is active; a share extension receives whatever the host app hands it. In the other direction, your own app's extensions receive input from any app on the device and share storage and keychain items with your app. Below you will find how extensions, custom keyboards, the share sheet, App Groups and keychain access groups work, the OWASP test for the app-wide keyboard restriction, our tests for inventorying an app's extensions, inspecting what they share, and attacking share and action extensions with hostile input, and how to rate what you find.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [iOS: App Extensions (MASTG-KNOW-0082)](#ios-app-extensions-mastg-know-0082)
  - [iOS: Custom Keyboards (MASTG-KNOW-0141)](#ios-custom-keyboards-mastg-know-0141)
  - [iOS: UIActivity Sharing (MASTG-KNOW-0081)](#ios-uiactivity-sharing-mastg-know-0081)
  - [iOS: App Groups (MASTG-KNOW-0125)](#ios-app-groups-mastg-know-0125)
  - [iOS: Keychain Access Groups (MASTG-KNOW-0126)](#ios-keychain-access-groups-mastg-know-0126)
- [Tests](#tests)
  - [MASTG-TEST-0389: References to the App-Wide Restriction of Custom Keyboards (iOS)](#mastg-test-0389-references-to-the-app-wide-restriction-of-custom-keyboards-ios)
  - [GT-0031-1: Inventory of the app's own extensions (iOS)](#gt-0031-1-inventory-of-the-apps-own-extensions-ios)
  - [GT-0031-2: Shared App Group container contents (iOS)](#gt-0031-2-shared-app-group-container-contents-ios)
  - [GT-0031-3: Keychain access-group sharing (iOS)](#gt-0031-3-keychain-access-group-sharing-ios)
  - [GT-0031-4: Share and action extension input handling (iOS)](#gt-0031-4-share-and-action-extension-input-handling-ios)
  - [GT-0031-5: Sensitive data offered through the share sheet (iOS)](#gt-0031-5-sensitive-data-offered-through-the-share-sheet-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0069: Keep Sensitive Input on the System Keyboard](#mastg-best-0069-keep-sensitive-input-on-the-system-keyboard)
  - [MASTG-BEST-0068: Secure Data Sharing Between App Extensions and Containing Apps](#mastg-best-0068-secure-data-sharing-between-app-extensions-and-containing-apps)
  - [MASTG-BEST-0045: Limit Sensitive Data Exposure Through iOS IPC Channels (extension parts)](#mastg-best-0045-limit-sensitive-data-exposure-through-ios-ipc-channels-extension-parts)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0031 applies when an app lets untrusted app extensions, such as custom keyboards or share and action extensions, interact with it and observe the data it handles. The OWASP requirement is *"The app only permits trusted app extensions to interact with it."* It is iOS-only, maps to MASVS-PLATFORM-1 ("The app uses IPC mechanisms securely") and MASVS-STORAGE-2 ("The app prevents leakage of sensitive data"), to MASVS v1 MSTG-PLATFORM-11, and to [CWE-829](https://cwe.mitre.org/data/definitions/829.html) (Inclusion of Functionality from Untrusted Control Sphere). It is tagged for profiles L1, L2 and EUDIW. OWASP's threat is MAS-THREAT-0031, *"Attackers can capture sensitive user input and content"*, through MAS-ATTACK-0048, *"Capturing user input through a malicious custom keyboard or app extension."*

There are two directions to test, and they are easy to confuse:

| Direction | What happens | What the app controls |
|---|---|---|
| **Other developers' extensions acting inside your app** | A third-party custom keyboard processes what the user types in your fields; a third-party share or action extension receives what your app shares | Keyboards: per field (secure entry) or app-wide (`application(_:shouldAllowExtensionPointIdentifier:)`). Share and action extensions: only *what* you hand to the share sheet; you cannot exclude other apps' extensions |
| **Your own extensions acting for other apps** | Your share, action, widget, notification, intents or keyboard extension receives input from any host app and shares an App Group container and keychain items with your app | Everything: which extensions exist, their entitlements, what they store and trust, how they validate input |

The keyboard is the only extension type an app can refuse, and the only one OWASP tests (MASTG-TEST-0389). The rest of this note is our methodology for the second direction, which is where we find most of the real issues: share extensions that act on host-supplied content without confirmation using a token from shared storage, widgets that can read the whole session, and keychain items that ended up in a shared group by accident.

Related notes: field-level secure text entry, which keeps individual fields on the system keyboard, is tested in [MASWE-0036](/mobile/maswe-0036-sensitive-data-exposed-via-ui/) (MASTG-TEST-0346 and 0347). The share sheet's **Copy** destination and pasteboard behaviour are in [MASWE-0030](/mobile/maswe-0030-improper-use-of-the-clipboard/). Extensions and URL handlers that *perform privileged actions* without authentication are in [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/); storage of secrets in App Group containers is a MASVS-STORAGE question covered by OWASP's MASTG-TEST-0388 (see our [MASWE-0001 note](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/)).

> **Note:** Android has no equivalent of this weakness as OWASP defines it. Android keyboards (IMEs) are ordinary apps the user enables, and apps cannot refuse them; the mitigations there are password input types (which tell well-behaved IMEs not to learn or suggest), `EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING`, and in-app PIN pads. Those are covered in the [MASWE-0036 note](/mobile/maswe-0036-sensitive-data-exposed-via-ui/).

## Modes of Introduction

**Every extension point allowed.** The app delegate does not implement `application(_:shouldAllowExtensionPointIdentifier:)`, so a custom keyboard the user installed handles every text field that is not secure. In SwiftUI apps this often happens because there is no `UIApplicationDelegate` at all (no `@UIApplicationDelegateAdaptor`).

**Sensitive input in fields that accept custom keyboards.** PINs typed into a `.numberPad` field without `isSecureTextEntry`, one-time codes in a `.oneTimeCode` field, card numbers, IBANs, security answers, recovery phrases, or a password field whose "show password" toggle turns secure entry off. Keyboard type and content type do not force the system keyboard; only secure entry and the phone-pad keyboard types do.

**Sensitive data handed to extensions.** Sharing more than the user chose: an activity item that serialises a whole object (with account identifiers or tokens) rather than the document, URLs with session tokens in their query, or an action extension that returns more data to the host than it received.

**Own extensions trusting their input.** A share or action extension that uploads, posts or acts on whatever the host app provides without showing it to the user, renders host-supplied HTML in a `WKWebView` with JavaScript enabled, uses `NSItemProvider.suggestedName` or a file name as a path, or follows URLs from the input.

**Over-shared storage.** Tokens and personal data in shared `UserDefaults` or files in an App Group container that every extension can read, often with a weaker file protection class so that a notification service extension can read it while the device is locked. Extensions given App Group or keychain groups they do not need.

**Keychain items in the wrong group.** Items saved without `kSecAttrAccessGroup` land in the *first* group of the entitlement list; when that is the shared group, every secret the app stores is shared with every extension.

## Impact

- **Compromise of sensitive data.** A malicious keyboard logs credentials, OTPs and personal data typed into the app; a shared container exposes the app's data to every extension, including one with a vulnerability.
- **Authentication or authorisation bypass.** Captured credentials or codes give account access; a share extension holding a session token can be driven by any host app to act on the user's account.
- **Data exfiltration through the host app.** Data handed to extensions leaves the app's control, and extensions with network access can transmit it.
- **Integrity issues.** Hostile content passed to your extensions can end up stored in your app's data, rendered as trusted content, or acted upon.

## Mitigations

- **Restrict extension points.** Implement `application(_:shouldAllowExtensionPointIdentifier:)` and return `false` for `.keyboard` in apps that handle sensitive keyboard input throughout (banking, password managers, 2FA). Otherwise use secure text entry on every sensitive field.
- **Keep sensitive input on the system keyboard.** `isSecureTextEntry` (or `SecureField`) for passwords, PINs, OTPs and other secrets.
- **Minimise data shared with extensions.** Hand the share sheet only the item the user chose; use `UIActivityItemSource` to tailor what each destination receives.
- **Give each extension the least it needs.** Separate App Groups and keychain groups per purpose, no secrets in shared `UserDefaults`, `NSFileProtectionComplete` for shared files where the extension type allows, an explicit `kSecAttrAccessGroup` on every keychain write.
- **Treat extension input as untrusted.** Validate type, size and content, confirm with the user before acting, never render it as trusted content.

## Knowledge

OWASP links MASTG-KNOW-0082 (App Extensions) and MASTG-KNOW-0141 (Custom Keyboards) to the test for this weakness. We add MASTG-KNOW-0081 (UIActivity Sharing), because the share sheet is how data reaches other apps' extensions, and MASTG-KNOW-0125 (App Groups) and MASTG-KNOW-0126 (Keychain Access Groups), because they are how extensions share data with their containing app.

### iOS: App Extensions (MASTG-KNOW-0082)

Source: [MASTG-KNOW-0082](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0082/), extended from Apple's [App Extension Programming Guide](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/index.html) and [Apple Platform Security: Supporting extensions](https://support.apple.com/guide/security/supporting-extensions-secabd3504cd/web).

#### Roles and process model

Since iOS 8, an app can ship **app extensions**: small bundles that each implement one task for the system or for other apps. Three parties are involved:

- the **containing app**, which ships the extension inside its bundle;
- the **app extension** itself;
- the **host app**, the app the user is in when the extension runs (any app for a share extension or keyboard; the system for a widget or notification extension).

An extension runs in **its own process** with its own sandbox and container, separate from both the containing app (which is usually not running at the time) and the host. Host and extension talk only through system-mediated IPC (XPC under the hood) using the extension point's API, for example `NSExtensionContext.inputItems` for a share extension. The containing app and the host never talk directly. The extension and its containing app share data only if they opt into an **App Group** container or a **keychain access group**, both gated by entitlements.

#### Packaging and signing

Extensions are `.appex` bundles in the containing app's `PlugIns/` directory (ExtensionKit-based extensions use `Extensions/`; watchOS apps carry their own under `Watch/`). Each has its own `Info.plist`, executable, code signature and entitlements, and is signed by the same team and reviewed with the containing app. It cannot be installed separately. That has a testing consequence: an app's *own* extensions are trusted code from the same developer, so the question for them is not "is this extension malicious?" but "what does it expose, and to whom?".

#### Extension points

Every extension declares exactly one type in its `Info.plist`, under `NSExtension` > `NSExtensionPointIdentifier`. The ones you will meet most often:

| Extension type | `NSExtensionPointIdentifier` | Runs on behalf of | Testing interest |
|---|---|---|---|
| Custom keyboard | `com.apple.keyboard-service` | Every app | Sees typed text; Full Access adds network and shared container |
| Share | `com.apple.share-services` | Any host app | Untrusted input; usually holds a session to post or upload |
| Action (with UI) | `com.apple.ui-services` | Any host app | Untrusted input; may return modified items to the host |
| Action (no UI) | `com.apple.services` | Any host app | As above, without a confirmation screen |
| Widget (WidgetKit) | `com.apple.widgetkit-extension` | The system | Reads shared data, shows it on the Home and Lock Screen |
| Today widget (legacy) | `com.apple.widget-extension` | The system | Removed in iOS 18 in favour of WidgetKit |
| Notification service | `com.apple.usernotifications.service` | The system | Runs on push, including while locked; decrypts and rewrites content |
| Notification content | `com.apple.usernotifications.content-extension` | The system | Custom UI for notifications |
| Intents / Intents UI | `com.apple.intents-service`, `com.apple.intents-ui-service` | Siri and Shortcuts | Actions without opening the app (see `IntentsRestrictedWhileLocked`) |
| File Provider | `com.apple.fileprovider-nonui` | The Files app and document pickers | Exposes the app's files to other apps |
| AutoFill credential provider | `com.apple.authentication-services-credential-provider-ui` | Any app with login fields | Password managers; holds the vault |
| Safari web extension, content blocker | `com.apple.Safari.web-extension`, `com.apple.Safari.content-blocker` | Safari | Web content |
| Broadcast upload | `com.apple.broadcast-services-upload` | ReplayKit | Receives screen recording frames |
| iMessage app | `com.apple.message-payload-provider` | Messages | Message payloads |

Apple's [`NSExtensionPointIdentifier`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsextension/nsextensionpointidentifier) reference has the full list. The other keys under `NSExtension` are `NSExtensionPrincipalClass` or `NSExtensionMainStoryboard` (the entry point) and `NSExtensionAttributes`, whose contents depend on the type: `NSExtensionActivationRule` for share and action extensions, `RequestsOpenAccess`, `IsASCIICapable` and `PrimaryLanguage` for keyboards, `IntentsSupported` and `IntentsRestrictedWhileLocked` for intents.

#### Declaring supported data types

Share and action extensions say what they accept through `NSExtensionActivationRule`, either as a dictionary of counts or as a predicate string over the offered UTIs:

```xml
<key>NSExtensionAttributes</key>
<dict>
    <key>NSExtensionActivationRule</key>
    <dict>
        <key>NSExtensionActivationSupportsImageWithMaxCount</key>
        <integer>10</integer>
        <key>NSExtensionActivationSupportsWebURLWithMaxCount</key>
        <integer>1</integer>
    </dict>
</dict>
```

The rule only decides whether the extension is *offered* in the share sheet for a given set of items. It is not validation: a host app chooses what it puts in its items, and the extension still receives whatever `NSItemProvider` objects the host built. The Xcode template ships the rule as the string `TRUEPREDICATE` (offer for anything), which Apple says to replace before release; finding it in a production build tells you the extension was never scoped.

#### What extensions cannot do

Apple restricts extensions: some APIs are marked unavailable to them (for example `UIApplication.shared`), they cannot run long background tasks (but can start `URLSession` background transfers, which need a shared container), and they cannot receive AirDrop. A legacy Today widget was the only type allowed to ask the system to open its containing app with `NSExtensionContext.open(_:completionHandler:)`; WidgetKit widgets open the app through `Link` or `widgetURL(_:)` deep links, which are untrusted input to the app like any URL (see the [MASWE-0029 note](/mobile/maswe-0029-insecure-deep-links/)).

### iOS: Custom Keyboards (MASTG-KNOW-0141)

Source: [MASTG-KNOW-0141](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0141/), extended from Apple's [Creating a custom keyboard](https://developer.apple.com/documentation/uikit/creating-a-custom-keyboard) and [Configuring open access for a custom keyboard](https://developer.apple.com/documentation/uikit/configuring-open-access-for-a-custom-keyboard).

#### Installation and Full Access

A custom keyboard is an extension (`com.apple.keyboard-service`) whose principal class subclasses `UIInputViewController`. The user installs the containing app and then enables the keyboard in **Settings > General > Keyboard > Keyboards > Add New Keyboard**. Once enabled, it replaces the system keyboard in every app, whenever the user switches to it with the globe key, and iOS remembers the last keyboard used.

By default a keyboard runs **without Full Access**: no network, no shared container with its containing app, so what it sees cannot easily leave the device. If its `Info.plist` sets `RequestsOpenAccess` to `true`, the user can turn on **Allow Full Access** for it, and iOS warns that the keyboard's developer could then transmit anything typed. The keyboard checks the grant through `UIInputViewController.hasFullAccess`. Many legitimate keyboards (swipe typing, translation, GIF search, cloud-synced dictionaries) ask for it, and users grant it routinely.

#### What a keyboard sees

A keyboard does not receive a copy of the text field; it talks to it through `textDocumentProxy` (`UITextDocumentProxy`). Through that proxy it can:

- see every character it inserts (it is the one inserting them);
- read the text around the cursor with `documentContextBeforeInput` and `documentContextAfterInput`, and the current `selectedText` (iOS 11+), so it can read pre-filled content in the field, not only what the user types;
- read the field's traits, including `keyboardType`, `returnKeyType` and `textContentType`, so it knows when it is in a `.oneTimeCode`, `.creditCardNumber` or `.username` field.

That last point matters: a field marked `.oneTimeCode` or `.creditCardNumber` (for autofill) tells a malicious keyboard exactly which keystrokes are worth sending.

#### When the system keyboard is forced

iOS swaps back to the system keyboard for:

- text fields and views with [`isSecureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry) set to `true`, and SwiftUI `SecureField`;
- the phone-pad keyboard types, `UIKeyboardType.phonePad` and `.namePhonePad`;
- every field in an app that rejects the keyboard extension point.

It does **not** do so for `.numberPad`, `.decimalPad`, `.asciiCapableNumberPad`, `.oneTimeCode` or `.password` content types without secure entry, or for text in `WKWebView` forms unless the input is `type="password"`. A PIN field built as a `.numberPad` text field with dots drawn by the app is the classic gap.

#### App-wide rejection

An app can refuse custom keyboards entirely by implementing [`application(_:shouldAllowExtensionPointIdentifier:)`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/application%28_:shouldallowextensionpointidentifier:%29) in its `UIApplicationDelegate` and returning `false` for [`UIApplication.ExtensionPointIdentifier.keyboard`](https://developer.apple.com/documentation/uikit/uiapplication/extensionpointidentifier/keyboard) (Objective-C `UIApplicationKeyboardExtensionPointIdentifier`, raw value `com.apple.keyboard-service`). Keyboards are the only extension point this method governs. Points to remember:

- The method lives on the **app** delegate, also in scene-based apps; a SwiftUI app needs `@UIApplicationDelegateAdaptor` to have one.
- Returning `false` affects every field, including chat and search, and removes accessibility and language keyboards the user relies on. Apple and OWASP both recommend per-field secure entry first and the app-wide switch for apps where no field should ever see a third-party keyboard.
- It governs keyboards for the app's own text input, including forms in its `WKWebView`s. Verify it on the device for any web-based login flow the app hands to another process, such as `ASWebAuthenticationSession` or `SFSafariViewController`, rather than assuming it applies there.

### iOS: UIActivity Sharing (MASTG-KNOW-0081)

Source: [MASTG-KNOW-0081](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0081/), with Apple's [`UIActivityViewController`](https://developer.apple.com/documentation/uikit/uiactivityviewcontroller) documentation.

#### Sending

The share sheet is a [`UIActivityViewController`](https://developer.apple.com/documentation/uikit/uiactivityviewcontroller) created with [`init(activityItems:applicationActivities:)`](https://developer.apple.com/documentation/uikit/uiactivityviewcontroller/init%28activityitems:applicationactivities:%29): the items to share (strings, URLs, images, file URLs, or objects conforming to [`UIActivityItemSource`](https://developer.apple.com/documentation/uikit/uiactivityitemsource)) and optional custom `UIActivity` subclasses. The destinations offered are the system activity types ([`UIActivity.ActivityType`](https://developer.apple.com/documentation/uikit/uiactivity/activitytype): `.airDrop`, `.copyToPasteboard`, `.mail`, `.message`, `.saveToCameraRoll`, `.print`, `.assignToContact`, `.addToReadingList`, `.markupAsPDF`, and others), the app's custom activities, and **every installed share and action extension** whose activation rule matches the items.

`UIActivityItemSource` is the useful hook for minimisation: `activityViewController(_:itemForActivityType:)` is asked for the item per destination, so an app can hand a redacted summary to Messages and the full PDF to Files, or return `nil` for a destination it does not want to serve.

#### Excluding activity types, and its limits

[`excludedActivityTypes`](https://developer.apple.com/documentation/uikit/uiactivityviewcontroller/excludedactivitytypes) hides system activity types. It is **not a security boundary**:

- it cannot exclude other apps' share and action extensions, which are where most sharing goes on modern iOS (Apple has confirmed this on its developer forums);
- new system types appear in new iOS versions and are not excluded automatically;
- the legacy social types (`.postToFacebook`, `.postToTwitter` and so on) belong to the Social framework integration removed in iOS 11, and excluding them achieves nothing on current iOS.

OWASP therefore deprecated its legacy share-sheet test (MASTG-TEST-0071) without a successor: once the user chooses a destination, the data goes where the user sent it. Exclusion remains useful for removing destinations that would put a secret somewhere *persistent or synced without the user realising*, notably `.copyToPasteboard` (general pasteboard, Universal Clipboard; see [MASWE-0030](/mobile/maswe-0030-improper-use-of-the-clipboard/)) and `.saveToCameraRoll` (the photo library, often synced to iCloud Photos), and `.assignToContact` for images.

#### Receiving

An app becomes a share-sheet or "Open in" destination by declaring document types (`CFBundleDocumentTypes`, with UTIs, plus `UTExportedTypeDeclarations` / `UTImportedTypeDeclarations` for custom types). Incoming files arrive through `application(_:open:options:)` or `scene(_:openURLContexts:)`, usually copied into `Documents/Inbox/`, which the app should validate and clean up. That path is covered as URL handling in the [MASWE-0029 note](/mobile/maswe-0029-insecure-deep-links/); a *share extension* is the other way to receive, covered here in GT-0031-4.

#### Custom activities

A custom `UIActivity` receives the items in `prepare(withActivityItems:)` and acts in `perform()`. It is app code with the app's privileges; whatever it does with the items (upload, log, store) falls under the app's normal storage, logging and network requirements.

### iOS: App Groups (MASTG-KNOW-0125)

Source: [MASTG-KNOW-0125](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0125/), with Apple's [Configuring App Groups](https://developer.apple.com/documentation/xcode/configuring-app-groups) and the [`com.apple.security.application-groups`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.application-groups) entitlement reference.

An **App Group** is a container shared between apps and extensions of the same team. Each member declares the group identifier (`group.<reverse-DNS>`) in its `com.apple.security.application-groups` entitlement, and the provisioning profile must allow it; a different team cannot join the group.

| Access path | API | On-disk location |
|---|---|---|
| Shared file container | [`FileManager.containerURL(forSecurityApplicationGroupIdentifier:)`](https://developer.apple.com/documentation/foundation/filemanager/containerurl%28forsecurityapplicationgroupidentifier:%29) | `/private/var/mobile/Containers/Shared/AppGroup/<UUID>/` |
| Shared defaults | [`UserDefaults(suiteName:)`](https://developer.apple.com/documentation/foundation/userdefaults/init%28suitename:%29) with the group ID | `<container>/Library/Preferences/<group-id>.plist` |
| Shared Core Data / SQLite | A store URL inside the container | Anywhere under `<container>/` |

The UUID directory is identified by a hidden `.com.apple.mobile_container_manager.metadata.plist` whose `MCMMetadataIdentifier` is the group ID, which is how you find the right one on a jailbroken device.

Properties that drive the tests:

- **Equal access.** Every member can read and write everything in the container. There is no per-extension access control.
- **No extra encryption.** Files are protected by Data Protection according to their class, as in a private container. The default is `NSFileProtectionCompleteUntilFirstUserAuthentication` (readable whenever the device has been unlocked once since boot). Shared `UserDefaults` files get the default class; you cannot raise it per key.
- **Locked-device extensions.** A notification service extension or a widget timeline refresh may run while the device is locked; developers then lower protection on shared files so those extensions can read them, which weakens protection for the main app too.
- **App Groups are also keychain access groups** (see the next section), so the group entitlement shares keychain items as well as files if the app writes items with the group ID.

### iOS: Keychain Access Groups (MASTG-KNOW-0126)

Source: [MASTG-KNOW-0126](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0126/), with Apple's [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps) and the [`keychain-access-groups`](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups) entitlement reference.

Each keychain item belongs to exactly one **access group** (attribute `kSecAttrAccessGroup`, raw key `agrp`). A process can read and write items in every group it is entitled to. Its list of groups is built, in this order, from:

1. the `keychain-access-groups` entitlement entries (each prefixed with the App ID prefix, usually the Team ID: `ABCDE12345.com.example.shared`);
2. the `application-identifier` entitlement (`ABCDE12345.com.example.myapp`), the app's private default group;
3. the `com.apple.security.application-groups` entries (`group.com.example.myapp`).

**When a write does not set `kSecAttrAccessGroup`, the item goes into the first group of that list.** If an app declares a shared group in `keychain-access-groups` to give an extension one token, and that group comes first, then every item the app writes without an explicit group is shared with that extension and with every other member. This is the most common keychain-sharing finding we report, and it is invisible in code review unless you know to look at the entitlement order.

Queries without `kSecAttrAccessGroup` search all of the process's groups. Items keep their own accessibility (`kSecAttrAccessible`, raw key `pdmn`: `ak` WhenUnlocked, `ck` AfterFirstUnlock, `aku` / `cku` the ThisDeviceOnly variants, `akpu` WhenPasscodeSetThisDeviceOnly) and access control, independent of the group. Sharing therefore does not weaken an item's protection class, but it does widen the set of processes, and therefore the set of bugs, that can read it.

## Tests

MASWE-0031 has one OWASP test, MASTG-TEST-0389. It and its siblings replace the legacy v1 test [MASTG-TEST-0072 (Testing App Extensions)](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0072/), deprecated with `covered_by: [MASTG-TEST-0388, MASTG-TEST-0389, MASTG-TEST-0299, MASTG-TEST-0346, MASTG-TEST-0347]`:

- [MASTG-TEST-0389](#mastg-test-0389-references-to-the-app-wide-restriction-of-custom-keyboards-ios) is below.
- MASTG-TEST-0346 and 0347 (secure text entry per field) are filed under MASWE-0036 and documented in our [MASWE-0036 note](/mobile/maswe-0036-sensitive-data-exposed-via-ui/).
- [MASTG-TEST-0388](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0388/) (secrets in shared App Group containers) and [MASTG-TEST-0299](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0299/) (data protection classes) are MASVS-STORAGE tests filed under MASWE-0001; GT-0031-2 below is their runtime companion for extension data.

The legacy share-sheet test [MASTG-TEST-0071 (Testing UIActivity Sharing)](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0071/) was deprecated without a successor (its techniques survive as [MASTG-TECH-0167](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0167/) and [MASTG-TECH-0168](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0168/)); GT-0031-5 keeps a narrow version of it for the cases where sharing settings still matter. GT-0031-1 to GT-0031-4 cover the app's own extensions, which the legacy test inspected and no current OWASP test does. OWASP has published no demo for MASTG-TEST-0389; the demos below are ours.

Common prerequisites: a decrypted IPA unpacked into `ipa_out/` ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/); `otool -l <binary> | grep -A4 LC_ENCRYPTION_INFO` must show `cryptid 0`), a jailbroken test device or a re-signed build with Frida Gadget, [Frida](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [radare2](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), and the list of sensitive data and the fields where it is entered.

### MASTG-TEST-0389: References to the App-Wide Restriction of Custom Keyboards (iOS)

Source: [MASTG-TEST-0389](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0389/). Platform: iOS. Type: static (code), manual review.

#### Overview

Checks whether an app that takes sensitive input through the keyboard refuses custom keyboards app-wide, by implementing `application(_:shouldAllowExtensionPointIdentifier:)` and returning `false` for the keyboard extension point. It complements the field-level checks in MASTG-TEST-0346 and 0347: an app passes the *intent* of this weakness either by restricting keyboards app-wide or by keeping every sensitive field secure.

#### Prerequisites

- The decrypted main binary.
- The list of fields where sensitive data is typed (credentials, PINs, OTPs, card data, security answers, recovery phrases), and the results of MASTG-TEST-0346/0347 if you have them.
- For dynamic confirmation: a third-party keyboard installed and enabled on the test device (any App Store keyboard, or a test keyboard you build; see the demo).

#### Steps

1. **Look for the delegate method and the constant** ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/)):

   ```bash
   BIN=ipa_out/Payload/MyApp.app/MyApp
   strings -a "$BIN" | grep -x 'application:shouldAllowExtensionPointIdentifier:'
   rabin2 -i "$BIN" | grep UIApplicationKeyboardExtensionPointIdentifier
   rabin2 -c "$BIN" | grep -B3 'shouldAllowExtensionPointIdentifier'
   ```

   The selector string alone appears whenever the method exists (Swift `@objc` delegate methods are registered under their Objective-C selector); the class listing tells you which class implements it and at what address. No selector: the app does not restrict keyboards.

2. **Read the implementation** ([MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)):

   ```bash
   r2 -q -c 'aaa; afl~shouldAllowExtension' "$BIN"
   r2 -q -c 'aaa; pdf @ <address from above>' "$BIN"
   ```

   You are looking for a load of `UIApplicationKeyboardExtensionPointIdentifier` (an imported data symbol), a string comparison with the argument (`isEqualToString:` in Objective-C; Swift's `String ==` on the raw values), and the value returned on the matching path (`mov w0, 0` for `false`). Watch for implementations that return `true` unconditionally or only under a debug or remote flag.

3. **Check that the delegate is the one in use.** In SwiftUI apps, confirm a `@UIApplicationDelegateAdaptor` (the delegate class appears in the binary and is instantiated at launch); a delegate class that is never installed has no effect.

4. **Confirm at runtime.** Attach while the app is in front and focus a text field:

   ```javascript
   // gt-keyboard-policy.js — attach with: frida -U -F -l gt-keyboard-policy.js
   ObjC.schedule(ObjC.mainQueue, () => {
     const del = ObjC.classes.UIApplication.sharedApplication().delegate();
     const name = del.$className;
     const m = ObjC.classes[name]['- application:shouldAllowExtensionPointIdentifier:'];
     if (m === undefined) {
       console.log('[!] ' + name + ' does not implement application:shouldAllowExtensionPointIdentifier:');
       return;
     }
     Interceptor.attach(m.implementation, {
       onEnter(args) { this.ep = new ObjC.Object(args[3]).toString(); },
       onLeave(ret) { console.log('[shouldAllow] ' + this.ep + ' -> ' + ((ret.toInt32() & 1) ? 'YES' : 'NO')); }
     });
     console.log('[+] hooked ' + name);
   });
   ```

   If UIKit consulted the delegate before you attached, no line appears; relaunch the app and attach before focusing the first field.

5. **Confirm on the device.** With the third-party keyboard enabled, focus each sensitive field and long-press the globe key: if the app rejects custom keyboards, only system keyboards are listed. For fields that are secure, the system keyboard appears regardless.

#### Observation

Whether the method exists, which class implements it, its return value for `com.apple.keyboard-service`, and per sensitive field whether the third-party keyboard could be used.

#### Evaluation

The test **fails** if the app handles sensitive data entered through the keyboard in at least one field that a custom keyboard can serve (not secure, not a phone-pad type), and it does not reject the keyboard extension point app-wide (method missing, or returns `true` for `com.apple.keyboard-service`).

OWASP's evaluation text fails any app with sensitive keyboard input that lacks the app-wide restriction, while its "further validation" accepts per-field secure entry instead. We apply the combined reading above: an app whose every sensitive field is secure passes this weakness without the app-wide switch, and we report the missing switch as Info (or Low for high-assurance apps, where we recommend it). An app with the switch passes regardless of individual fields.

#### Demo

A banking app collects a six-digit transaction PIN in a `.numberPad` field and draws its own dots:

```swift
pinField.keyboardType = .numberPad
pinField.textContentType = .oneTimeCode
// isSecureTextEntry not set; no shouldAllowExtensionPointIdentifier in AppDelegate
```

```text
$ strings -a MyApp | grep -x 'application:shouldAllowExtensionPointIdentifier:'
$ rabin2 -i MyApp | grep UIApplicationKeyboardExtensionPointIdentifier
$
```

On the device, a lab keyboard built from Xcode's Custom Keyboard Extension template, with this added to its `UIInputViewController` subclass, is offered in the PIN field and logs what it sees:

```swift
override func textDidChange(_ textInput: UITextInput?) {
    let p = textDocumentProxy
    NSLog("GTKB before=%@ type=%ld content=%@",
          p.documentContextBeforeInput ?? "", p.keyboardType?.rawValue ?? -1,
          p.textContentType?.rawValue ?? "nil")
}
```

```text
$ idevicesyslog | grep GTKB
... GTKB before=4829 type=4 content=one-time-code
```

The test fails: the PIN is readable by any custom keyboard the user has enabled, and the field's content type tells the keyboard what it is. The fix is `isSecureTextEntry = true` on the field (and, for a banking app, returning `false` for `.keyboard` app-wide).

### GT-0031-1: Inventory of the app's own extensions (iOS)

Guler Tech methodology. Platform: iOS. Type: static.

#### Overview

Lists every extension the app ships, what type it is, what it accepts, and what it is entitled to share with the containing app. Every other test in this note starts from this inventory; it also catches over-provisioned extensions on its own.

#### Prerequisites

- The decrypted, unpacked IPA. `codesign` and `plutil` on macOS, or `ldid` and `plistutil` on Linux.

#### Steps

1. **Find the extensions** (including nested ones in a Watch app):

   ```bash
   APP=$(ls -d ipa_out/Payload/*.app)
   find "$APP" -name '*.appex' -type d
   ```

2. **Dump each extension's `NSExtension` dictionary and entitlements**, and the main app's for comparison:

   ```bash
   dump() {
     b="$1"; exe=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$b/Info.plist")
     echo "=== ${b#$APP/}  $(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$b/Info.plist")"
     plutil -extract NSExtension xml1 -o - "$b/Info.plist" 2>/dev/null
     codesign -d --entitlements :- "$b/$exe" 2>/dev/null     # Linux: ldid -e "$b/$exe"
   }
   dump "$APP"
   find "$APP" -name '*.appex' -type d | while read -r ex; do dump "$ex"; done > extensions.txt
   ```

   If a bundle contains `embedded.mobileprovision` (development, ad hoc and enterprise builds), `security cms -D -i <bundle>/embedded.mobileprovision` shows what the profile allows.

3. **Build the table**: per extension, the extension point, entry class, activation rule (or `TRUEPREDICATE`), `RequestsOpenAccess` for keyboards, `IntentsRestrictedWhileLocked` for intents, and the entitlements `com.apple.security.application-groups`, `keychain-access-groups`, `com.apple.developer.associated-domains` and any network-extension or credential-provider entitlements.
4. **Map data needs**: from the extension's purpose and a quick look at its binary (`strings -a` for `suiteName`, `containerURLForSecurityApplicationGroupIdentifier:`, `kSecAttrAccessGroup` usage, URL hosts), decide what each extension actually needs to read.

#### Observation

The extension inventory table and, for each extension, the shared groups it holds versus what it needs.

#### Evaluation

This is an inventory step, but it **fails** on its own if:

- an extension holds App Group or keychain groups it does not need (a keyboard, sticker pack or content blocker in the same group as the session store; a widget entitled to the group holding refresh tokens when it only needs a balance summary);
- a share or action extension in a release build uses `TRUEPREDICATE`, so it is offered for, and receives, any content;
- the app ships a custom keyboard with `RequestsOpenAccess` that has no feature requiring it.

Everything else feeds GT-0031-2 to GT-0031-4.

#### Demo

```text
=== MyApp.app  com.example.myapp
    com.apple.security.application-groups: group.com.example.myapp
    keychain-access-groups: ABCDE12345.com.example.shared, ABCDE12345.com.example.myapp
=== PlugIns/Share.appex  com.example.myapp.share
    NSExtensionPointIdentifier: com.apple.share-services
    NSExtensionActivationRule: TRUEPREDICATE
    com.apple.security.application-groups: group.com.example.myapp
    keychain-access-groups: ABCDE12345.com.example.shared
=== PlugIns/Widget.appex  com.example.myapp.widget
    NSExtensionPointIdentifier: com.apple.widgetkit-extension
    com.apple.security.application-groups: group.com.example.myapp
    keychain-access-groups: ABCDE12345.com.example.shared
```

Three leads: the share extension accepts anything (`TRUEPREDICATE`); the widget shares the keychain group the share extension uses for its token, which a widget showing a balance does not need; and the main app lists the shared group *first*, so its own unlabelled keychain writes land in it (GT-0031-3).

### GT-0031-2: Shared App Group container contents (iOS)

Guler Tech methodology. Platform: iOS. Type: dynamic (filesystem and hooks).

#### Overview

Shows what is actually stored in each App Group container after realistic use, with which file protection class, and which extension can read it. It is the runtime companion of OWASP's static MASTG-TEST-0388 and of MASTG-TEST-0299.

#### Prerequisites

- The group identifiers from GT-0031-1.
- A jailbroken device (to pull files) or the Simulator (`xcrun simctl`), plus Frida for in-process listing. [objection](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0074/) is handy for downloads.

#### Steps

1. **Use the app and every extension**: log in, use the widget, receive a push notification, share something through the share extension, so the containers are populated.
2. **List the container from inside the app** (the process is entitled, so this works without a jailbreak on a Gadget build):

   ```javascript
   // gt-appgroup-ls.js
   const GROUP = 'group.com.example.myapp';
   const fm = ObjC.classes.NSFileManager.defaultManager();
   const url = fm.containerURLForSecurityApplicationGroupIdentifier_(GROUP);
   if (url === null) {
     console.log('[-] not entitled to ' + GROUP);
   } else {
     const root = url.path().toString();
     console.log('[+] ' + root);
     const en = fm.enumeratorAtPath_(root);
     let rel;
     while ((rel = en.nextObject()) !== null) {
       const attrs = fm.attributesOfItemAtPath_error_(root + '/' + rel, NULL);
       if (attrs === null || attrs.objectForKey_('NSFileType').toString() !== 'NSFileTypeRegular') continue;
       console.log(attrs.objectForKey_('NSFileProtectionKey') + '\t' + attrs.objectForKey_('NSFileSize') + '\t' + rel);
     }
   }
   ```

   ```bash
   frida -U -n MyApp -l gt-appgroup-ls.js
   ```

3. **Pull the files.** On a jailbroken device, copy the directory printed above with `scp -r`, or use objection's `file download <path>`. On the Simulator:

   ```bash
   cd "$(xcrun simctl get_app_container booted com.example.myapp group.com.example.myapp)"
   ```

4. **Inspect them** for secrets and personal data:

   ```bash
   plutil -p Library/Preferences/group.com.example.myapp.plist
   find . -name '*.sqlite' -o -name '*.db' | while read -r db; do echo "== $db"; sqlite3 "$db" .tables; done
   grep -rIlE 'eyJ[A-Za-z0-9_-]+\.|[Bb]earer |refresh_?token|password|secret' .
   ```

5. **Check locked-device behaviour**: with the device locked (after first unlock), trigger a widget refresh or a push that the notification service extension handles; if it works, the files it reads cannot be `NSFileProtectionComplete`. Compare with the classes printed in step 2.

#### Observation

The container listing with protection classes, the sensitive values found, and which members (from GT-0031-1) can read each.

#### Evaluation

The test **fails** if the shared container holds credentials, session or refresh tokens, keys or API secrets (these belong in a keychain group, MASTG-BEST-0068), or holds personal data that some members do not need, or holds sensitive files with a protection class weaker than the extension types require (anything other than `NSFileProtectionComplete` for data no locked-device extension reads). Stale staging files left behind by a share extension (uploaded documents, drafts) are a finding of the same kind. The container is expected to hold what the extensions legitimately need, with appropriate protection; that passes.

#### Demo

```text
[+] /private/var/mobile/Containers/Shared/AppGroup/6B1C…/
NSFileProtectionCompleteUntilFirstUserAuthentication  2481   Library/Preferences/group.com.example.myapp.plist
NSFileProtectionNone                                  90112  Shared/cache.sqlite
NSFileProtectionCompleteUntilFirstUserAuthentication  418204 ShareStaging/upload-1730.pdf
```

```text
$ plutil -p Library/Preferences/group.com.example.myapp.plist
{
  "accessToken" => "eyJhbGciOi…"
  "userEmail" => "user@example.com"
  "widgetBalance" => "1,204.17"
}
```

The access token sits in shared defaults (readable by every member, protected only until first unlock), the cache database has no protection at all, and a document shared days ago is still in the staging folder. The test fails on all three counts.

### GT-0031-3: Keychain access-group sharing (iOS)

Guler Tech methodology. Platform: iOS. Type: static (entitlements) and dynamic (hooks).

#### Overview

Determines which keychain items each extension can read, and whether items are shared deliberately or by the default-group rule.

#### Prerequisites

- Entitlements from GT-0031-1 (main app and every extension).
- Frida on the device; the ability to make each extension run (open the share sheet, show the widget, send a push).

#### Steps

1. **Work out each process's group list** from its entitlements, in order: `keychain-access-groups`, then `application-identifier`, then App Groups. Note which group comes first in the main app.
2. **Log keychain writes in the main app**, to see where items land:

   ```javascript
   // gt-secitemadd.js (Frida 17; on Frida 16 use Module.findExportByName(null, name))
   Interceptor.attach(Module.getGlobalExportByName('SecItemAdd'), {
     onEnter(args) {
       const q = new ObjC.Object(args[0]);
       console.log('[SecItemAdd] class=' + q.objectForKey_('class') + ' agrp=' + q.objectForKey_('agrp') +
         ' pdmn=' + q.objectForKey_('pdmn') + ' svce=' + q.objectForKey_('svce') + ' acct=' + q.objectForKey_('acct'));
     }
   });
   ```

   `agrp=null` means the item goes into the first group from step 1.
3. **List what each extension can see.** Run this in the extension's process; it requests attributes only, never secret data:

   ```javascript
   // gt-keychain-visible.js
   const SecItemCopyMatching = new NativeFunction(Module.getGlobalExportByName('SecItemCopyMatching'),
     'int', ['pointer', 'pointer']);
   const yes = ObjC.classes.NSNumber.numberWithBool_(true);
   ['genp', 'inet', 'keys', 'cert'].forEach((cls) => {
     const q = ObjC.classes.NSMutableDictionary.alloc().init();
     q.setObject_forKey_(cls, 'class');
     q.setObject_forKey_(yes, 'r_Attributes');
     q.setObject_forKey_('m_LimitAll', 'm_Limit');
     const out = Memory.alloc(Process.pointerSize);
     const status = SecItemCopyMatching(q.handle, out);
     if (status !== 0) { console.log(cls + ': status ' + status); return; }   // -25300 = none
     const items = new ObjC.Object(out.readPointer());
     for (let i = 0; i < items.count(); i++) {
       const a = items.objectAtIndex_(i);
       console.log(cls + '\tagrp=' + a.objectForKey_('agrp') + '\tpdmn=' + a.objectForKey_('pdmn') +
         '\tsvce=' + a.objectForKey_('svce') + '\tacct=' + a.objectForKey_('acct') + '\tlabl=' + a.objectForKey_('labl'));
     }
   });
   ```

   Extension processes are short-lived: open the extension first, then find and attach to it.

   ```bash
   frida-ps -U | grep -iE 'share|widget|notification|intent|keyboard'
   frida -U -p <pid> -l gt-keychain-visible.js
   ```

4. **Compare** each extension's visible items with what it needs (from GT-0031-1 step 4).

#### Observation

Per process: its group list, the items it can see (class, group, accessibility, service and account), and for the main app where each new item was written.

#### Evaluation

The test **fails** if an extension can read keychain items it does not need (typically the main app's credentials or refresh token visible from a widget, keyboard or share extension), if items are shared because of the default-group rule rather than an explicit `kSecAttrAccessGroup`, or if shared items use a weaker accessibility than the extensions require (`ck` or the deprecated always-accessible classes where `ak`/`aku` would do). It passes when each shared group holds only the items its members need, written with an explicit group.

#### Demo

Main app log after login:

```text
[SecItemAdd] class=genp agrp=null pdmn=ck svce=auth acct=refresh_token
[SecItemAdd] class=genp agrp=null pdmn=ak svce=auth acct=password
[SecItemAdd] class=genp agrp=ABCDE12345.com.example.shared pdmn=ak svce=share acct=upload_token
```

From the widget process:

```text
genp  agrp=ABCDE12345.com.example.shared  pdmn=ck  svce=auth   acct=refresh_token  labl=null
genp  agrp=ABCDE12345.com.example.shared  pdmn=ak  svce=auth   acct=password       labl=null
genp  agrp=ABCDE12345.com.example.shared  pdmn=ak  svce=share  acct=upload_token   labl=null
```

Only the upload token was meant to be shared. Because the shared group is first in the main app's `keychain-access-groups`, the refresh token and the user's password went there too and are readable by the widget and the share extension. The test fails; the fix is to put the app's private group first (or always set `kSecAttrAccessGroup`) and migrate the existing items.

### GT-0031-4: Share and action extension input handling (iOS)

Guler Tech methodology. Platform: iOS. Type: dynamic (manual and hooks), with static support.

#### Overview

A share or action extension receives content from whichever app the user is in. This test feeds the app's own share and action extensions hostile content from a host app you control and checks whether they validate it, confirm with the user before acting, and keep it out of trusted contexts.

#### Prerequisites

- The share (`com.apple.share-services`) and action (`com.apple.ui-services`, `com.apple.services`) extensions from GT-0031-1, with their activation rules.
- A small test host app you can build and run on the device (a single view controller presenting a `UIActivityViewController` is enough), plus built-in hosts such as Safari, Files, Notes and Photos.
- Frida on the device.

#### Steps

1. **Read the extension's code paths** statically: in the extension binary, look for `inputItems`, `attachments`, `loadItemForTypeIdentifier:options:completionHandler:`, `loadFileRepresentationForTypeIdentifier:completionHandler:`, `loadDataRepresentationForTypeIdentifier:completionHandler:`, `loadObjectOfClass:completionHandler:`, `suggestedName`, `loadHTMLString:baseURL:`, `openURL`, and `completeRequestReturningItems:completionHandler:`, and for the network hosts it talks to. Note what it does with each item type.
2. **Trace a normal share.** Share a document from Files into the extension; while its UI is up, attach and trace:

   ```bash
   frida-ps -U | grep -i share
   frida-trace -U -p <pid> -m '-[NSItemProvider load*]' -m '-[NSExtensionContext completeRequestReturningItems:completionHandler:]'
   ```

   Then complete the share. Note whether anything leaves the device before the user confirms, and with which credentials (link to GT-0031-2 and 0031-3: where does the token come from?).
3. **Share hostile content from your host app.** For example:

   ```swift
   let dir = FileManager.default.temporaryDirectory
   let html = dir.appendingPathComponent("statement.pdf")          // HTML content, PDF name
   try Data("<html><body><script>document.write(document.cookie)</script></body></html>".utf8).write(to: html)
   let empty = dir.appendingPathComponent("..hidden.txt")
   try Data().write(to: empty)
   let items: [Any] = [html, empty,
                       "javascript:alert(1)",
                       URL(string: "myapp://settings?biometrics=off")!,
                       String(repeating: "A", count: 5_000_000)]
   present(UIActivityViewController(activityItems: items, applicationActivities: nil), animated: true)
   ```

   Vary one item at a time if the activation rule filters combinations. Also try a very large file, a file whose UTI does not match its content, and a URL to a lookalike domain.
4. **Observe**: does the extension show the content and ask before posting or uploading; does it render shared HTML (and with JavaScript) in a `WKWebView`; does it open URLs, including the app's own scheme (a route into the app's URL handler from any host app); does it write files under host-supplied names; what does it leave in the shared container; what does an action extension return to the host; does it crash on large or malformed input.

#### Observation

The trace of loads and completions, screenshots of what the user is shown, network evidence (from your proxy), and the shared-container state afterwards.

#### Evaluation

The test **fails** if the extension:

- performs an action on the user's account (post, upload, send, transfer) with host-supplied content without showing it and getting confirmation in the extension's UI;
- renders host-supplied content as trusted (HTML with JavaScript in a `WKWebView`, especially one with native bridges; see [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/));
- opens host-supplied URLs, in particular the app's own URL scheme or universal links, without validation;
- uses host-supplied names as file paths, or leaves shared content behind in the App Group container;
- returns more data to the host than the action requires.

Crashes on oversized or malformed input are a robustness finding (Low) unless they corrupt shared data. It passes when the extension validates types and sizes, shows the content and asks before acting, and keeps the input inert.

#### Demo

The share extension's principal class:

```swift
override func didSelectPost() {
    let token = UserDefaults(suiteName: "group.com.example.myapp")?.string(forKey: "accessToken")
    for item in extensionContext?.inputItems as? [NSExtensionItem] ?? [] {
        for provider in item.attachments ?? [] {
            provider.loadItem(forTypeIdentifier: UTType.url.identifier) { url, _ in
                if let url = url as? URL { Uploader.upload(url, token: token) }   // no preview, no type check
            }
        }
    }
    extensionContext?.completeRequest(returningItems: nil)
}
```

With `TRUEPREDICATE` (GT-0031-1), the extension is offered for every item; sharing a file URL from the test host uploads it to the user's account with the token from shared defaults, and a `myapp://` URL is uploaded as a "document" that the main app later opens. The test fails; combined with GT-0031-2 the report links storage, trust and input handling into one finding.

### GT-0031-5: Sensitive data offered through the share sheet (iOS)

Guler Tech methodology. Platform: iOS. Type: static and dynamic.

#### Overview

OWASP deprecated its share-sheet test because `excludedActivityTypes` cannot restrict third-party extensions and the user chooses the destination. We keep a narrow check for what the app *puts* into the share sheet and for the system destinations that silently persist or sync secrets.

#### Prerequisites

- The list of share actions in the app (statements, receipts, recovery codes, QR codes, invite links, exported keys or backups).
- Frida on the device.

#### Steps

1. **Find share sheets statically**: `initWithActivityItems:applicationActivities:`, `setExcludedActivityTypes:`, `UIActivityItemSource` conformances (`activityViewController:itemForActivityType:`), custom `UIActivity` subclasses (`prepareWithActivityItems:`, `performActivity`), and imported constants such as `UIActivityTypeCopyToPasteboard` and `UIActivityTypeSaveToCameraRoll` (`rabin2 -i <binary> | grep UIActivityType`).
2. **Trace each share at runtime** ([MASTG-TECH-0167](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0167/)):

   ```javascript
   // gt-share-sheet.js
   const AVC = ObjC.classes.UIActivityViewController;
   Interceptor.attach(AVC['- initWithActivityItems:applicationActivities:'].implementation, {
     onEnter(args) {
       console.log('\n[share] items=' + new ObjC.Object(args[2]) +
         '\n        activities=' + (args[3].isNull() ? 'nil' : new ObjC.Object(args[3])));
     }
   });
   Interceptor.attach(AVC['- setExcludedActivityTypes:'].implementation, {
     onEnter(args) { console.log('[share] excluded=' + (args[2].isNull() ? 'nil' : new ObjC.Object(args[2]))); }
   });
   ```

   For items that are `UIActivityItemSource` objects, also trace `activityViewController:itemForActivityType:` on their class to see what each destination receives.
3. **Inspect the items**: open the shared file (AirDrop it to a Mac, or save to Files) and check its contents and metadata; decode URLs for tokens; check what custom activities do in `performActivity`.

#### Observation

Per share action: the items handed over (and their contents), the excluded types, custom activities and their behaviour.

#### Evaluation

The test **fails** if:

- the shared item contains more than the user chose to share: tokens or session identifiers in URLs, internal identifiers or other users' data in exported files, debug metadata;
- secrets that are not meant to leave the app at all (TOTP seeds, private keys, recovery codes, unencrypted backups) are offered through a share sheet without a deliberate export flow and warning;
- such secrets are offered without excluding `.copyToPasteboard` and `.saveToCameraRoll` (pasteboard and photo library persistence, often synced);
- a custom activity handles the items insecurely (logs them, uploads them over an insecure channel).

The absence of `excludedActivityTypes` for ordinary content, and the presence of third-party extensions in the sheet, are not findings.

#### Demo

```text
[share] excluded=nil
[share] items=(
    "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
    "<UIImage: 0x28123c0f0> size {512, 512}"
)
        activities=nil
```

The 2FA settings screen offers the TOTP seed URI and its QR image through the share sheet, with Copy and Save Image available. The seed ends up on the general pasteboard and in the photo library. The test fails; the fix is to remove sharing for the seed (users add it to an authenticator through the QR shown on screen or an `otpauth` link opened directly).

## Best practices

### MASTG-BEST-0069: Keep Sensitive Input on the System Keyboard

Source: [MASTG-BEST-0069](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0069/). Platform: iOS.

Mark every field that takes a secret as secure; it keeps the input on the system keyboard, masks it and stops keyboard caching, without affecting the user's keyboard choice elsewhere:

```swift
pinField.isSecureTextEntry = true          // SwiftUI: SecureField("PIN", text: $pin)
```

For apps where no field should ever reach a third-party keyboard, reject the keyboard extension point in the app delegate (in SwiftUI, through `@UIApplicationDelegateAdaptor`):

```swift
func application(_ application: UIApplication,
                 shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier) -> Bool {
    extensionPointIdentifier != .keyboard
}
```

Use the app-wide switch deliberately: it also removes accessibility and language keyboards. We recommend it for banking, payment, password-manager and authenticator apps, and per-field secure entry for everyone else. Do not rely on `.numberPad` or `.oneTimeCode` to keep a PIN or code private.

### MASTG-BEST-0068: Secure Data Sharing Between App Extensions and Containing Apps

Source: [MASTG-BEST-0068](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0068/). Platform: iOS.

- **Secrets in a shared keychain group, not in the container.** Tokens and keys an extension needs go into a dedicated keychain access group, with an explicit `kSecAttrAccessGroup` and an accessibility such as `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (or `AfterFirstUnlockThisDeviceOnly` only for extensions that must run while locked).
- **Protect shared files.** Write sensitive files with `NSFileProtectionComplete`: `try data.write(to: url, options: .completeFileProtection)`. If a locked-device extension needs some data, give it a separate, minimal file rather than lowering protection on everything.
- **Share the minimum.** Give each extension only the groups it needs, and only the subset of data it uses (a widget needs a summary, not the account database). Delete staging files after use.

A keychain write that is explicit about its group:

```swift
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "share",
    kSecAttrAccount as String: "upload_token",
    kSecAttrAccessGroup as String: "ABCDE12345.com.example.shared",
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecValueData as String: Data(uploadToken.utf8)
]
let status = SecItemAdd(query as CFDictionary, nil)
```

And keep the app's private group first in `keychain-access-groups` (or list only shared groups there and rely on the `application-identifier` default for private items, writing shared items with an explicit group).

### MASTG-BEST-0045: Limit Sensitive Data Exposure Through iOS IPC Channels (extension parts)

Source: [MASTG-BEST-0045](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0045/). Platform: iOS. The parts that apply to extensions:

- **Constrain shared container data** and remove shared artefacts once consumed.
- **Limit shared keychain access** to dedicated groups for specific purposes, and review every app and extension that declares a group: each one is part of the trust boundary.
- **Validate all IPC input**, including files read from App Group containers (another member may have written them) and items received by share and action extensions.
- **Protect document exchange flows**: validate type, size, structure and content of received files, and do not trust the declared UTI.
- **Require confirmation** for sensitive, financial or irreversible actions triggered from extensions, intents or widgets, with the same authorisation checks as the in-app flow (see [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/)).

## Rating findings

Rate on **what is exposed** (credentials, PINs, OTPs and tokens; financial and personal data), **to whom** (any third-party keyboard the user enables; every extension in a group; any host app on the device), and **what the attacker needs**. The attacker positions are: a malicious or compromised custom keyboard the user installed and enabled (and, to exfiltrate, granted Full Access; users do this routinely, but it is still user interaction); any app on the device acting as a host for your share or action extension (no permissions; the user has to pick your extension in the share sheet, which a malicious app can encourage); and a bug or compromise in one of your own extensions, which inherits everything shared with it.

| Rating | Conditions |
|---|---|
| **Critical** | Your extension performs account actions or exfiltration-equivalent operations on host-supplied content with no user confirmation, using credentials from shared storage, so that any app can trigger it once the user selects the extension (e.g. silent upload of arbitrary content to the user's account, actions with financial effect). |
| **High** | Credentials, transaction PINs or OTPs entered in fields a custom keyboard can serve, in an app without the app-wide restriction; session or refresh tokens and passwords readable by extensions that do not need them (shared container or default-group keychain sharing); share extensions rendering host content with JavaScript and native bridges. |
| **Medium** | Card numbers, security answers or other sensitive personal data entered in keyboard-accessible fields; sensitive data in the shared container with weak protection classes; `TRUEPREDICATE` combined with an extension that acts on its input after confirmation; secrets offered via the share sheet with Copy or Save Image available; tokens in shared URLs. |
| **Low** | Over-provisioned entitlements with no sensitive data currently exposed; stale staging files with low-sensitivity content; crashes on malformed extension input; `TRUEPREDICATE` on an extension that only displays content; high-assurance app (banking, password manager, authenticator) without the app-wide keyboard restriction even though all sensitive fields are secure. |
| **Info** | All sensitive fields secure and no app-wide restriction in an ordinary app; extensions that share only what they need with appropriate protection; absence of `excludedActivityTypes` for ordinary content. |

Raise a level for banking, payment, health and authenticator apps, where MASVS L2 expectations apply and attackers target keyboards and share flows. Lower a level when a keyboard-accessible field carries a value that is useless on its own (a username without the password, a card's last four digits). In the report, show the entitlements and `Info.plist` snippets, the trace or keyboard log, what the extension or host could read or do, and the specific fix (secure field, explicit access group, confirmation screen).

## References

- OWASP MASWE: [MASWE-0031: Allowing Untrusted App Extensions](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0031/); related [MASWE-0030](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0030/), [MASWE-0036](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0036/), [MASWE-0001](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/), [MASWE-0018](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0018/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/), [MASVS-STORAGE-2](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0082: App Extensions](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0082/), [MASTG-KNOW-0141: Custom Keyboards](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0141/), [MASTG-KNOW-0081: UIActivity Sharing](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0081/), [MASTG-KNOW-0125: App Groups](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0125/), [MASTG-KNOW-0126: Keychain Access Groups](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0126/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0389](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0389/), [MASTG-TEST-0388](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0388/), [MASTG-TEST-0299](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0299/), [MASTG-TEST-0346](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0346/), [MASTG-TEST-0347](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0347/); legacy [MASTG-TEST-0071](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0071/), [MASTG-TEST-0072](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0072/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0069](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0069/), [MASTG-BEST-0068](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0068/), [MASTG-BEST-0045](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0045/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0167](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0167/), [MASTG-TECH-0168](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0168/) (CC BY-SA 4.0)
- OWASP MASTG tools: [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [objection (MASTG-TOOL-0074)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0074/), [ldid (MASTG-TOOL-0111)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0111/), [libimobiledevice (MASTG-TOOL-0126)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0126/) (CC BY-SA 4.0)
- Apple: [App Extension Programming Guide](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/index.html), [Apple Platform Security: Supporting extensions](https://support.apple.com/guide/security/supporting-extensions-secabd3504cd/web), [`NSExtensionPointIdentifier`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsextension/nsextensionpointidentifier), [`application(_:shouldAllowExtensionPointIdentifier:)`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/application%28_:shouldallowextensionpointidentifier:%29), [`ExtensionPointIdentifier.keyboard`](https://developer.apple.com/documentation/uikit/uiapplication/extensionpointidentifier/keyboard), [Creating a custom keyboard](https://developer.apple.com/documentation/uikit/creating-a-custom-keyboard), [Configuring open access for a custom keyboard](https://developer.apple.com/documentation/uikit/configuring-open-access-for-a-custom-keyboard), [`isSecureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry), [`UIActivityViewController`](https://developer.apple.com/documentation/uikit/uiactivityviewcontroller), [`excludedActivityTypes`](https://developer.apple.com/documentation/uikit/uiactivityviewcontroller/excludedactivitytypes), [`UIActivityItemSource`](https://developer.apple.com/documentation/uikit/uiactivityitemsource), [Configuring App Groups](https://developer.apple.com/documentation/xcode/configuring-app-groups), [`com.apple.security.application-groups`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.application-groups), [`keychain-access-groups`](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups), [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps), [`containerURL(forSecurityApplicationGroupIdentifier:)`](https://developer.apple.com/documentation/foundation/filemanager/containerurl%28forsecurityapplicationgroupidentifier:%29), [`UserDefaults(suiteName:)`](https://developer.apple.com/documentation/foundation/userdefaults/init%28suitename:%29), Apple Developer Forums [thread 689062](https://developer.apple.com/forums/thread/689062) (excluding extension activities)
- [Frida documentation](https://frida.re/docs/home/), [frida-trace](https://frida.re/docs/frida-trace/), [radare2 book](https://book.rada.re/)
- CWE: [CWE-829](https://cwe.mitre.org/data/definitions/829.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
