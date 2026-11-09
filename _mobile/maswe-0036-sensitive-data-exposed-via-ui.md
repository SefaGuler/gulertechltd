---
title: "Unnecessary Exposure of Sensitive Data via the User Interface (MASWE-0036)"
date: 2026-11-09 21:07:00 +0000
subcategory: platform
summary: "Testing Android and iOS apps for unmasked passwords, PINs and OTPs, keyboard-cached input, and sensitive values shown in full on screen."
refs: [MASWE-0036, MASVS-PLATFORM-3, MASVS-STORAGE-2, CWE-200, CWE-359]
tags: [android, ios, masvs-platform, keyboard-cache, input-masking, shoulder-surfing]
---

This note is part of our [MASVS-PLATFORM guide](/mobile/masvs-platform-platform-interaction-guide/) and covers OWASP [MASWE-0036](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0036/): apps that show more of a secret than the user's task needs, or show it without the protection the platform already offers. The two classic cases are a password, PIN or one-time code typed into a field that is not marked as secret, and a full card number, account number or national ID printed on a screen where the last four characters would do. A third case sits with them because the same field attributes control it: input that the system keyboard learns and later offers back as a suggestion, in any app. Below you will find how each platform decides whether a field is masked and whether the keyboard may learn from it (Android `inputType`, `imeOptions`, `TransformationMethod` and the Compose text fields; iOS `UITextInputTraits` and SwiftUI `SecureField`), the six OWASP tests with their demos, our own runtime and manual UI checks (including `dumpsys input_method`, `uiautomator dump` and the Accessibility Inspector), secure patterns, and how to rate what you find.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Keyboard Cache (MASTG-KNOW-0055)](#android-keyboard-cache-mastg-know-0055)
  - [Android: Masking text input and displayed values (supplementary)](#android-masking-text-input-and-displayed-values-supplementary)
  - [iOS: Keyboard Cache (MASTG-KNOW-0100)](#ios-keyboard-cache-mastg-know-0100)
  - [iOS: Text Input Field Masking in iOS (MASTG-KNOW-0121)](#ios-text-input-field-masking-in-ios-mastg-know-0121)
  - [iOS: Custom Keyboards (MASTG-KNOW-0141)](#ios-custom-keyboards-mastg-know-0141)
  - [Generic: Unmasked sensitive values on screen (Guler Tech)](#generic-unmasked-sensitive-values-on-screen-guler-tech)
- [Tests](#tests)
  - [Before you start: inventory the sensitive inputs and outputs](#before-you-start-inventory-the-sensitive-inputs-and-outputs)
  - [MASTG-TEST-0258: References to Keyboard Caching Attributes in UI Elements (Android)](#mastg-test-0258-references-to-keyboard-caching-attributes-in-ui-elements-android)
  - [MASTG-TEST-0316: App Exposing User Authentication Data in Text Input Fields (Android)](#mastg-test-0316-app-exposing-user-authentication-data-in-text-input-fields-android)
  - [MASTG-TEST-0313: References to APIs for Preventing Keyboard Caching of Text Fields (iOS)](#mastg-test-0313-references-to-apis-for-preventing-keyboard-caching-of-text-fields-ios)
  - [MASTG-TEST-0314: Runtime Monitoring of Text Fields Eligible for Keyboard Caching (iOS)](#mastg-test-0314-runtime-monitoring-of-text-fields-eligible-for-keyboard-caching-ios)
  - [MASTG-TEST-0346: References to APIs Hiding Sensitive Data in Text Input Fields (iOS)](#mastg-test-0346-references-to-apis-hiding-sensitive-data-in-text-input-fields-ios)
  - [MASTG-TEST-0347: Runtime Use of APIs Hiding Sensitive Data in Text Input Fields (iOS)](#mastg-test-0347-runtime-use-of-apis-hiding-sensitive-data-in-text-input-fields-ios)
  - [GT-0036-1: Runtime input-type and keyboard-learning check (Android)](#gt-0036-1-runtime-input-type-and-keyboard-learning-check-android)
  - [GT-0036-2: Manual UI review for unmasked sensitive values (Android and iOS)](#gt-0036-2-manual-ui-review-for-unmasked-sensitive-values-android-and-ios)
  - [Pointer: pasteboard tests MASTG-TEST-0276 to 0280 (iOS)](#pointer-pasteboard-tests-mastg-test-0276-to-0280-ios)
  - [Pointer: MASTG-TEST-0340 References to Overlay Attack Protections (Android)](#pointer-mastg-test-0340-references-to-overlay-attack-protections-android)
- [Best practices](#best-practices)
  - [MASTG-BEST-0044: Mask Sensitive Data in Text Input Fields](#mastg-best-0044-mask-sensitive-data-in-text-input-fields)
  - [MASTG-BEST-0019 and MASTG-BEST-0026: Prevent keyboard caching of sensitive input](#mastg-best-0019-and-mastg-best-0026-prevent-keyboard-caching-of-sensitive-input)
  - [MASTG-BEST-0069: Keep Sensitive Input on the System Keyboard](#mastg-best-0069-keep-sensitive-input-on-the-system-keyboard)
  - [Secure patterns for displayed values (Guler Tech)](#secure-patterns-for-displayed-values-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0036 applies when an app exposes sensitive data through its user interface beyond what the user's current task requires, or shows data the task does require without protection proportionate to its sensitivity. The OWASP requirement is *"The app does not unnecessarily expose sensitive data through its user interface."* It maps to MASVS-PLATFORM-3 ("The app uses the user interface securely"), to MASVS-STORAGE-2 ("The app prevents leakage of sensitive data") because of the keyboard cache, to MASVS v1 MSTG-STORAGE-7, and to two CWEs: [CWE-200](https://cwe.mitre.org/data/definitions/200.html) (Exposure of Sensitive Information to an Unauthorized Actor) and [CWE-359](https://cwe.mitre.org/data/definitions/359.html) (Exposure of Private Personal Information to an Unauthorized Actor). The weakness is tagged for the L2 and EUDIW (EU Digital Identity Wallet) profiles, not L1: OWASP treats it as a requirement for apps that handle sensitive data, not for every app.

OWASP describes the threat as MAS-THREAT-0036, *"Attackers can capture sensitive data displayed or entered in the user interface"*, and lists three attacks:

| Attack | What it means here | Attacker position |
|---|---|---|
| MAS-ATTACK-0043 | Observing the screen while sensitive data is displayed or entered (shoulder surfing) | Physical proximity, a camera, or anything that records the screen (screen sharing, a support session, a screen recording the user starts) |
| MAS-ATTACK-0005 | Accessing device storage on a compromised device | Root or jailbreak, or forensic access: this is how keyboard cache files are read |
| MAS-ATTACK-0041 | Reading clipboard data when users copy it between apps | Another app on the device; covered in the [clipboard note](/mobile/maswe-0030-improper-use-of-the-clipboard/) |

Several neighbouring weaknesses share the same screens. Keep them apart, because they are tested and rated separately:

| Question | Where it lives |
|---|---|
| Is a secret masked while it is typed or shown? Is a sensitive value shown in full when part of it would do? Can the keyboard learn it? | This note (MASWE-0036) |
| Can other apps read it from the clipboard? | [MASWE-0030](/mobile/maswe-0030-improper-use-of-the-clipboard/) |
| Can a third-party keyboard or other app extension receive it? | [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/) |
| Is it in a notification? | [MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/) |
| Is it captured in screenshots, screen recordings or the app switcher snapshot? | [MASWE-0038](/mobile/maswe-0038-insufficient-screenshot-protection/) |
| Can another app draw over the screen and capture taps or input? | [MASWE-0039](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/) |
| Can an accessibility service read it? | [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/) |

**Test placement.** OWASP files twelve tests under MASWE-0036. We document six of them here: the masking and keyboard-cache tests for both platforms (Android MASTG-TEST-0258 and 0316, iOS MASTG-TEST-0313, 0314, 0346 and 0347; 0313 and 0314 live in OWASP's MASVS-STORAGE folder, and 0316 is also mapped to MASWE-0040). The five iOS pasteboard tests (MASTG-TEST-0276 to 0280) are documented in the [clipboard note](/mobile/maswe-0030-improper-use-of-the-clipboard/), and the Android overlay test MASTG-TEST-0340 in the [overlay note](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/), because that is where the mechanisms they test are explained. You will find short pointers to them at the end of the [Tests](#tests) section.

## Modes of Introduction

**Secret fields built as plain text fields.** A password, PIN, passcode, OTP, CVV or recovery code entered into an Android `EditText` without a password `inputType`, a Compose `TextField` instead of `SecureTextField`, a `UITextField` without `isSecureTextEntry`, or a SwiftUI `TextField` instead of `SecureField`. The typed value is readable on screen, and on both platforms the keyboard treats it as ordinary text it may learn from.

**Masking switched off in code.** A "show password" toggle that is left in the revealed state, a field configured in XML as `textPassword` and later overwritten with `setInputType(InputType.TYPE_CLASS_TEXT)` (exactly what OWASP's Android demo shows), a Compose `SecureTextField` with `TextObfuscationMode.Visible`, or `isSecureTextEntry = false` set after a storyboard enabled it.

**Masking done only visually.** A custom PIN pad that draws dots but feeds an ordinary text field, an Android `EditText` given a `PasswordTransformationMethod` but no password input type (the screen shows dots, the keyboard still learns the value), or a Compose `TextField` with `PasswordVisualTransformation()` but default `KeyboardOptions`. Visual masking without the platform's secure-entry attribute leaves the keyboard, autofill and accessibility layers treating the field as normal text.

**Sensitive non-secret fields left eligible for keyboard learning.** Card numbers, IBANs, national insurance or passport numbers, security answers, email addresses and usernames typed into fields with default traits. These need not be masked, but the keyboard should not learn them.

**Values shown in full.** Full card numbers (PAN), account numbers, sort codes plus account numbers, identity document numbers, dates of birth, recovery phrases or API keys printed on a dashboard, a profile page or a confirmation screen where a partial value would do, or revealed without an explicit user action and left revealed indefinitely.

**Cross-platform and custom UI.** Flutter (`obscureText`, `enableSuggestions`, `autocorrect`, `enableIMEPersonalizedLearning` on `TextField`), React Native (`secureTextEntry`, `autoCorrect`, `spellCheck` on `TextInput`), game engines and custom canvas-drawn inputs. Each has its own switches, and a field that forgets them behaves like an unprotected native field. In WebViews, an HTML `<input type="password">` is masked by the engine, but `type="text"` used for a PIN is not, and the page's JavaScript can read either (see MASTG-BEST-0060 in the [WebView native bridges note](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/)).

## Impact

- **Compromise of sensitive data.** Anyone who can see the screen (in person, through a camera, through screen sharing or a recording) reads what is typed or displayed. Anyone with access to the keyboard's learned data (on a rooted or jailbroken device, or simply by typing a prefix into another app on an unlocked phone and watching the suggestion strip) can recover values the keyboard learnt.
- **Authentication or authorisation bypass.** A captured password, PIN, OTP or recovery code gives access to the account, or authorises a transaction, with no further attack needed.
- **Wider exposure through the platform.** An unmasked field is also not protected by the platform features that key off "secure" fields: on iOS, third-party keyboards are not kept away from it; on both platforms, autofill and accessibility treat it as ordinary text.
- **Regulatory exposure.** Displaying a full card number where it is not needed conflicts with PCI DSS display-masking expectations; displaying identity data more widely than necessary conflicts with UK GDPR data-minimisation principles.

## Mitigations

- **Use the platform's secure entry for secrets.** Android Views: a password `inputType` (`textPassword`, `numberPassword`, `textWebPassword`). Compose: `SecureTextField` / `OutlinedSecureTextField` / `BasicSecureTextField` with `KeyboardType.Password` or `KeyboardType.NumberPassword`. iOS: `isSecureTextEntry = true` or SwiftUI `SecureField`. Do not rely on custom drawing alone.
- **Keep sensitive non-secret input out of the keyboard's learning.** Android: `textNoSuggestions` plus `imeOptions="flagNoPersonalizedLearning"`; Compose: `autoCorrectEnabled = false` and a fitting `KeyboardType`. iOS: `autocorrectionType = .no` and `spellCheckingType = .no` (plus `inlinePredictionType = .no` on iOS 17 and later).
- **Show only what the task needs.** Mask by default (`•••• 1234`), reveal the full value only after an explicit action and, where the value is high-value, after step-up authentication ([MASWE-0023](/mobile/maswe-0023-step-up-authentication-not-implemented/)); re-mask after a timeout and when the app goes to the background.
- **Minimise at the source.** If the screen only ever shows the last four digits, have the backend return only the last four digits.
- **Keep reveal toggles honest.** A "show password" button should be momentary or reset when the screen is left, and should not change the field's keyboard behaviour to a learning one.

## Knowledge

OWASP links four Knowledge pages to the tests in this note: MASTG-KNOW-0055 (Android keyboard cache), MASTG-KNOW-0100 (iOS keyboard cache), MASTG-KNOW-0121 (iOS text input masking) and MASTG-KNOW-0141 (iOS custom keyboards). OWASP has no Android knowledge page on masking, so we add a supplementary Android section, and a Guler Tech section on displayed values, which the OWASP tests do not cover at all.

### Android: Keyboard Cache (MASTG-KNOW-0055)

Source: [MASTG-KNOW-0055](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0055/).

**Who learns what.** On Android the keyboard is an app: an input method editor (IME) such as Gboard, SwiftKey or Samsung Keyboard, chosen by the user and running in its own process. When a text field gains focus, the app's view describes the field to the IME in an [`EditorInfo`](https://developer.android.com/reference/android/view/inputmethod/EditorInfo) object; the IME uses it to choose a layout and to decide whether to offer suggestions and whether to add what is typed to its personal dictionary and language model. Your app never sees the IME's learned data and cannot delete it. All it can do is describe the field correctly, and the IME is trusted to honour that description. You can see which IME is active with:

```bash
adb shell settings get secure default_input_method
# com.google.android.inputmethod.latin/com.android.inputmethod.latin.LatinIME
```

**`inputType`: class, variation, flags.** The most important field of `EditorInfo` is `inputType`, an integer built from three parts ([`InputType`](https://developer.android.com/reference/android/text/InputType)):

| Part | Mask | Values that matter here |
|---|---|---|
| Class | `TYPE_MASK_CLASS` = `0x0000000f` | `TYPE_CLASS_TEXT` = 1, `TYPE_CLASS_NUMBER` = 2, `TYPE_CLASS_PHONE` = 3, `TYPE_CLASS_DATETIME` = 4 |
| Variation | `TYPE_MASK_VARIATION` = `0x00000ff0` | Text: `PASSWORD` = `0x80`, `VISIBLE_PASSWORD` = `0x90`, `WEB_PASSWORD` = `0xe0`, `EMAIL_ADDRESS` = `0x20`, `PERSON_NAME` = `0x60`. Number: `TYPE_NUMBER_VARIATION_PASSWORD` = `0x10` |
| Flags | `TYPE_MASK_FLAGS` = `0x00fff000` | Text: `TYPE_TEXT_FLAG_AUTO_CORRECT` = `0x8000`, `TYPE_TEXT_FLAG_MULTI_LINE` = `0x20000`, `TYPE_TEXT_FLAG_NO_SUGGESTIONS` = `0x80000` |

The XML attribute `android:inputType` takes names (`textPassword` is `TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_PASSWORD` = 129 = `0x81`); code passes the integer to `setInputType()`. In decompiled code you only see the integer, so you need to decode it: 129 is a text password, 18 (`0x12`) is a numeric password, 1 is plain text, 2 is a plain number.

The values OWASP lists as non-caching, with the API level each appeared in:

| XML `android:inputType` | Constant | Masks the text? | API |
|---|---|---|---|
| `textPassword` | `TYPE_TEXT_VARIATION_PASSWORD` | Yes | 3 |
| `numberPassword` | `TYPE_NUMBER_VARIATION_PASSWORD` | Yes | 11 |
| `textWebPassword` | `TYPE_TEXT_VARIATION_WEB_PASSWORD` | Yes | 11 |
| `textVisiblePassword` | `TYPE_TEXT_VARIATION_VISIBLE_PASSWORD` | **No** | 3 |
| `textNoSuggestions` | `TYPE_TEXT_FLAG_NO_SUGGESTIONS` | **No** | 3 |

Two points the table hides. First, the variation is what tells the IME "this is a password"; masking on screen is a separate mechanism (the `TransformationMethod`, below). `textVisiblePassword` tells the IME not to learn but shows the characters, so it is right for a field like a voucher code and wrong for a PIN. Second, every one of these is a request. The IME decides, and IMEs differ; Gboard follows them, but you are testing the app, and the app's job is to make the request.

**`imeOptions` and personalised learning.** Since API 26, [`EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING`](https://developer.android.com/reference/android/view/inputmethod/EditorInfo#IME_FLAG_NO_PERSONALIZED_LEARNING) (`0x1000000`; XML `android:imeOptions="flagNoPersonalizedLearning"`; code `setImeOptions()`) asks the IME not to update typing history or its personalised language model from this field. It is the direct way to say "do not learn this" for a field that is not a password and still needs suggestions off (card number, IBAN, ID number), and it is what Chrome uses for incognito tabs. The Android documentation itself says the flag is not a guarantee and that some IMEs may not respect it; the same is true of the input types above. OWASP's knowledge page does not mention it; we treat its absence on sensitive non-password fields as an observation, not a failure.

**Jetpack Compose.** Compose does not use `EditText`. Its text fields build the `EditorInfo` from `KeyboardOptions`:

- [`KeyboardOptions`](https://developer.android.com/reference/kotlin/androidx/compose/foundation/text/KeyboardOptions)`(keyboardType = ..., autoCorrectEnabled = ...)`. `KeyboardType.Password` maps to `TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_PASSWORD`, `KeyboardType.NumberPassword` to the numeric password type, `KeyboardType.PasswordVisible` to the visible-password variation. The older `autoCorrect` parameter, which OWASP's examples still use, has been deprecated since Compose Foundation 1.7 in favour of `autoCorrectEnabled`; a `null` value means "use the keyboard's default".
- There is no `KeyboardOptions` parameter for `IME_FLAG_NO_PERSONALIZED_LEARNING`; `platformImeOptions` only carries the free-form `privateImeOptions` string. If a Compose app needs the flag, it has to host an `EditText` through `AndroidView` or provide its own input connection.

**Finding learned data.** On a rooted test device you can look for a value you typed into the IME's private storage. OWASP's example uses Gboard:

```bash
# Type a unique canary (e.g. GTCANARY7319) into the field a few times, submit, then:
adb shell su -c 'ls -R /data/data/com.google.android.inputmethod.latin/databases/'
adb shell su -c 'grep -rl GTCANARY7319 /data/data/com.google.android.inputmethod.latin/'
```

OWASP found its canary in `databases/trainingcachev3.db`. File names change between Gboard versions, other IMEs keep data elsewhere (`com.touchtype.swiftkey`, `com.samsung.android.honeyboard`), and learning is not always written to disk immediately, so search the whole data directory rather than one file, and do not treat "not found" as proof. The cheaper behavioural check works on any device: after submitting the canary, open an ordinary text field in another app, type the first few characters, and watch the suggestion strip.

### Android: Masking text input and displayed values (supplementary)

OWASP's Android test for masking (MASTG-TEST-0316) relies on knowledge that is not on a single OWASP page. This is what you need.

**Views.** `TextView` (and therefore `EditText`) draws its text through a [`TransformationMethod`](https://developer.android.com/reference/android/text/method/TransformationMethod). Setting a password `inputType` installs a [`PasswordTransformationMethod`](https://developer.android.com/reference/android/text/method/PasswordTransformationMethod), which replaces each character with a dot and briefly shows the last typed character if the system "Show passwords" setting is on (`adb shell settings get system show_password`; 1 means on). A "show password" toggle usually swaps it for `HideReturnsTransformationMethod`. The consequences for testing:

- `inputType="textPassword"` gives you masking **and** the IME hint. This is the configuration to expect.
- `setTransformationMethod(PasswordTransformationMethod.getInstance())` on a field whose `inputType` is plain text gives you masking **without** the IME hint: dots on screen, learnable by the keyboard. Look for it explicitly.
- `android:password="true"` is a deprecated attribute that still masks; treat it like the previous case and check the input type separately.
- Material Components' `TextInputLayout` with `app:endIconMode="password_toggle"` only works on a password-type `EditText`; it is a reveal toggle, and its default state is masked.

**Compose.** The current API is `SecureTextField` / `OutlinedSecureTextField` (Material 3) and `BasicSecureTextField` (Foundation), all driven by a `TextFieldState` and a [`TextObfuscationMode`](https://developer.android.com/reference/kotlin/androidx/compose/foundation/text/input/TextObfuscationMode): `RevealLastTyped` (briefly show the last character, the mobile convention), `Hidden` (always dots), `System` (follow the platform "Show passwords" setting; added in later Foundation releases) and `Visible` (no masking at all). Secure text fields also block cut and copy. The older pattern is a `TextField` with `visualTransformation = PasswordVisualTransformation()` and `keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password)`; it masks visually, and it is only complete if the keyboard type is set too. Any of these can be flipped to visible at runtime, which is legitimate for a reveal button and a finding when it is the default.

**Displayed values.** A `TextView` or Compose `Text` showing an account number has no masking mechanism at all: whatever string the app passes is what appears. Masking displayed values is entirely the app's job (see the [Guler Tech section](#generic-unmasked-sensitive-values-on-screen-guler-tech) below). Screenshots, the recents thumbnail and `FLAG_SECURE` are covered in [MASWE-0038](/mobile/maswe-0038-insufficient-screenshot-protection/).

### iOS: Keyboard Cache (MASTG-KNOW-0100)

Source: [MASTG-KNOW-0100](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0100/).

**What the keyboard keeps.** The iOS system keyboard learns words the user types, to drive autocorrection, QuickType predictions and (on iOS 17 and later) inline predictions. The learned data is stored outside the app's sandbox under `/private/var/mobile/Library/Keyboard/` and its subdirectories, in `.dat` files (historically `dynamic-text.dat`; newer iOS versions use per-language directories such as `en-dynamic.lm/`). An app cannot read or clear it. The user can, through **Settings > General > Transfer or Reset iPhone > Reset > Reset Keyboard Dictionary**, and on a jailbroken device a tester can read it over SSH.

**What controls eligibility.** `UITextField`, `UITextView` and `UISearchBar` adopt [`UITextInputTraits`](https://developer.apple.com/documentation/uikit/uitextinputtraits). The traits that matter:

| Trait | Default | Effect for this weakness |
|---|---|---|
| [`isSecureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry) | `false` | `true` masks the text, disables copy and cut, excludes the field from keyboard learning, and forces the system keyboard |
| [`autocorrectionType`](https://developer.apple.com/documentation/uikit/uitextinputtraits/autocorrectiontype) | `.default` | `.default` (enabled for most keyboards) and `.yes` let the keyboard learn and correct; `.no` turns autocorrection off |
| [`spellCheckingType`](https://developer.apple.com/documentation/uikit/uitextinputtraits/spellcheckingtype) | `.default` | Follows autocorrection by default; set `.no` explicitly |
| `inlinePredictionType` (iOS 17+) | `.default` | `.no` stops inline completions being offered in the field |
| [`textContentType`](https://developer.apple.com/documentation/uikit/uitextinputtraits/textcontenttype) | `nil` | `.password`, `.newPassword`, `.oneTimeCode` drive AutoFill and suggest the field's purpose; they do not mask anything (see [MASWE-0019](/mobile/maswe-0019-no-autofill-support-for-credential-providers/)) |
| `keyboardType` | `.default` | `.phonePad` and `.namePhonePad` force the system keyboard (custom keyboards cannot type into them) |

The enum raw values you will see in disassembly are `UITextAutocorrectionType`: `default` = 0, `no` = 1, `yes` = 2, and the same layout for `UITextSpellCheckingType`. A `setAutocorrectionType:` call with `x2 = 0` is therefore an *explicit* choice of the default, and no call at all means the same thing.

**SwiftUI.** `TextField` has no trait properties; you use modifiers: `.autocorrectionDisabled()` (and the older `.disableAutocorrection(true)`), `.textInputAutocapitalization(.never)`, `.keyboardType(_:)`, `.textContentType(_:)`. There is no SwiftUI modifier for spell checking, which is one more reason to use `SecureField` for anything secret.

**Interface Builder.** Traits are often set in storyboards and XIBs (the "Secure Text Entry", "Correction" and "Spell Checking" options in the Attributes Inspector). In source form they appear in the XML as a `<textInputTraits key="textInputTraits" .../>` element with attributes such as `secureTextEntry="YES"` and `autocorrectionType="no"`. In a shipped app the storyboards are compiled into binary `.storyboardc`/`.nib` archives, so a static search of the binary will not see them. This is why MASTG-TEST-0314 (runtime) matters more than 0313 (static) on iOS.

### iOS: Text Input Field Masking in iOS (MASTG-KNOW-0121)

Source: [MASTG-KNOW-0121](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0121/). Related legacy page: MASTG-KNOW-0098 (User Interface Components).

**UIKit.** Setting `isSecureTextEntry = true` on a `UITextField` replaces typed characters with bullets (the last character is shown briefly as you type), disables copy and cut from the field, keeps the text out of keyboard learning and suggestions, and makes iOS use the system keyboard for that field. The default is `false`. The property can be toggled at runtime (`textField.isSecureTextEntry.toggle()`) to build a show/hide button; when it is toggled back on, UIKit clears the field if the user starts editing again, which is expected behaviour, not a bug. The rendered content of a secure field is also excluded from screen capture, which some apps exploit as a screenshot-hiding trick; that belongs to [MASWE-0038](/mobile/maswe-0038-insufficient-screenshot-protection/).

**SwiftUI.** [`SecureField`](https://developer.apple.com/documentation/swiftui/securefield) is always masked; there is no property to turn masking off. A show/hide button is built by swapping a `SecureField` for a `TextField` bound to the same state. A plain [`TextField`](https://developer.apple.com/documentation/swiftui/textfield) is never masked. At runtime SwiftUI's `SecureField` is backed by a `UITextField` with `isSecureTextEntry` set, which is why the Frida scripts below see it, though without the SwiftUI `accessibilityIdentifier`.

**Other controls.** `UITextView` also adopts `UITextInputTraits`, but masking a multi-line view is rarely meaningful. Controls that bypass UIKit text input (game engines, some cross-platform frameworks, custom-drawn PIN pads) inherit none of this and have to implement masking themselves, and usually get keyboard learning wrong.

### iOS: Custom Keyboards (MASTG-KNOW-0141)

Source: [MASTG-KNOW-0141](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0141/). The full treatment of keyboard extensions, "Full Access" and the app-wide opt-out is in the [app extensions note](/mobile/maswe-0031-allowing-untrusted-app-extensions/); here is the part that ties into masking.

A custom keyboard is an app extension that replaces the system keyboard in every app once the user enables it under **Settings > General > Keyboard > Keyboards**. With "Full Access" granted it can talk to the network. iOS keeps third-party keyboards away from two kinds of field: secure text fields (`isSecureTextEntry = true` or a SwiftUI `SecureField`), and phone-pad fields (`.phonePad`, `.namePhonePad`). When the user taps one, the system keyboard is swapped in temporarily ([Apple: Custom Keyboard](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/CustomKeyboard.html)). An app can also reject custom keyboards app-wide by returning `false` for the keyboard extension point from [`application(_:shouldAllowExtensionPointIdentifier:)`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/application%28_:shouldallowextensionpointidentifier:%29).

The practical consequence: on iOS, an unmasked password or PIN field is not only readable over the user's shoulder, it is also typed through whatever keyboard the user installed. That raises the severity of a missing `isSecureTextEntry`, and it is why OWASP's iOS masking tests reference this knowledge page. Android has no equivalent: an Android IME receives every field, password or not, which is why the [extensions note](/mobile/maswe-0031-allowing-untrusted-app-extensions/) treats the IME itself as the trust decision.

### Generic: Unmasked sensitive values on screen (Guler Tech)

The OWASP tests for this weakness only look at text *input*. The second mode of introduction in MASWE-0036, "Unmasked Sensitive Values", is about *output*, and you have to test it by looking at the app. These are the values we check and what "proportionate" looks like for each:

| Value | Usually enough on screen | When the full value is legitimately needed |
|---|---|---|
| Card number (PAN) | Last four digits (PCI DSS v4.0 requirement 3.4.1 allows at most the first six/eight (BIN) and last four when displayed) | A card issuer's "show card details" for online shopping: on explicit action, ideally after step-up, auto-hidden |
| CVV / CVC | Never shown by merchants; PCI DSS forbids storing it after authorisation | Issuer apps showing virtual card details on demand, same conditions as above |
| Bank account number, IBAN | Last four digits; sort code may be shown | The user's own details for receiving payments, on demand ("copy details" is a clipboard question, [MASWE-0030](/mobile/maswe-0030-improper-use-of-the-clipboard/)) |
| National insurance number, passport, driving licence, other ID numbers | Last few characters or nothing | Identity wallets presenting a credential, deliberately, to a verifier |
| Date of birth, full address, phone, email | Partial (`j***@example.com`, `07*** ***123`) on recovery and confirmation screens | Profile editing screens, after authentication |
| Recovery codes, seed phrases, backup keys | Hidden by default | At creation and on explicit request after re-authentication |
| Passwords, PINs, OTPs after entry | Never echoed back ("Your PIN is 1234" on a confirmation screen is a finding) | Not needed |
| API keys, access tokens, debug values | Not at all in production UI | Developer menus that must not ship |

Three implementation points decide whether masking is real:

- **Where the masking happens.** If the server sends the full PAN and the app formats it as `•••• 1234`, the full value is still in memory, in the network response, possibly in logs and caches, and very often in the accessibility tree (a `contentDescription` or `accessibilityLabel` built from the raw value). Masking at the source is the robust fix; masking at render time is a display fix only. The accessibility side is tested in [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/).
- **How reveal works.** Reveal on an explicit action, re-mask after a short timeout and on `onPause` / `sceneDidEnterBackground`, and require step-up authentication for the highest-value items ([MASWE-0023](/mobile/maswe-0023-step-up-authentication-not-implemented/)).
- **Where else the value appears.** Error messages ("Card 4111 1111 1111 1111 declined"), push notification text ([MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/)), share sheets, and screens pre-filled from previous sessions.

## Tests

OWASP files twelve tests under MASWE-0036; six are documented here, two Android and four iOS. Four are static, two (both iOS) use Frida at runtime. They replace these legacy (MASTG v1) tests:

| Legacy test | Replaced by |
|---|---|
| [MASTG-TEST-0006](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0006/) Determining Whether the Keyboard Cache Is Disabled for Text Input Fields (Android) | MASTG-TEST-0258 |
| [MASTG-TEST-0008](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0008/) Checking for Sensitive Data Disclosure Through the User Interface (Android) | MASTG-TEST-0316 (its notification half is now MASTG-TEST-0315, in the [notifications note](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/)) |
| [MASTG-TEST-0055](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0055/) Finding Sensitive Data in the Keyboard Cache (iOS) | MASTG-TEST-0313, 0314 |
| [MASTG-TEST-0057](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0057/) Checking for Sensitive Data Disclosed Through the User Interface (iOS) | MASTG-TEST-0346, 0347 |
| [MASTG-TEST-0072](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0072/) Testing App Extensions (iOS) | Partly 0346 and 0347 (the custom keyboard angle); the rest is in the [app extensions note](/mobile/maswe-0031-allowing-untrusted-app-extensions/) |

The Android tests are static only, and none of the OWASP tests look at displayed values. We add [GT-0036-1](#gt-0036-1-runtime-input-type-and-keyboard-learning-check-android) (what the IME is actually told, field by field, for any UI toolkit) and [GT-0036-2](#gt-0036-2-manual-ui-review-for-unmasked-sensitive-values-android-and-ios) (the manual screen review).

### Before you start: inventory the sensitive inputs and outputs

Every test in this note ends with the same question: *does this field or label handle sensitive data?* Answer it once, up front, by walking the app and listing what you see.

1. Use the app as a real user with a fully populated test account: registration, login, PIN setup and change, 2FA enrolment and challenge, password reset, card management, payments and payees, profile and identity screens, settings, support chat.
2. For each screen, record every input and every displayed value that is sensitive: secrets (password, PIN, OTP, CVV, recovery code), sensitive identifiers (PAN, IBAN, account number, ID numbers, DOB), and personal data. Note how it should behave (masked / no keyboard learning / partial display).
3. Capture the UI hierarchy at each screen so you can match fields to code later:

   ```bash
   # Android: one dump per screen, named after the screen
   adb shell uiautomator dump /sdcard/ui.xml && adb pull /sdcard/ui.xml ui-login.xml
   # iOS: objection's view hierarchy dump (or Accessibility Inspector, see GT-0036-2)
   objection -g com.example.app explore
   # then at the objection prompt:
   ios ui dump
   ```

4. Keep the inventory as a table (screen, element, resource ID or accessibility identifier, data type, expected protection). The static tests produce code locations; this table is what turns them into findings.

### MASTG-TEST-0258: References to Keyboard Caching Attributes in UI Elements (Android)

Source: [MASTG-TEST-0258](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0258/). Platform: Android. Type: static (code). Knowledge: MASTG-KNOW-0055. Best practice: MASTG-BEST-0019 (placeholder).

#### Overview

The test finds every place where the app sets a text field's input type, in layouts (`android:inputType`) and in code (`setInputType()`, Compose `KeyboardOptions`), and checks that fields handling sensitive data use a non-caching type. A field without one is eligible for keyboard learning: what the user typed can come back as a suggestion in any app and, on a rooted device, be read from the IME's storage.

#### Prerequisites

- The APK (all splits), decoded with apktool for layouts and decompiled with jadx for code ([MASTG-TECH-0007](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0007/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)).
- semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)) with the OWASP rule, or grep ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)).
- Your field inventory from [Before you start](#before-you-start-inventory-the-sensitive-inputs-and-outputs).

#### Steps

1. **Decode and decompile.**

   ```bash
   adb shell pm path com.example.app          # pull every split it lists
   adb pull /data/app/~~XXXX/com.example.app-YYYY/base.apk
   apktool d base.apk -o apk_out              # res/layout*/ as readable XML
   jadx -d out base.apk                       # Java sources in out/sources/
   ```

2. **Layouts.** apktool decodes `inputType` back to names, so you can read them directly. List every editable view with its ID, hint and input attributes:

   ```bash
   grep -rnE '<(EditText|AutoCompleteTextView|com\.google\.android\.material\.textfield\.TextInputEditText|androidx\.appcompat\.widget\.AppCompatEditText)' \
       -A12 apk_out/res/layout*/ | grep -E 'android:id=|android:hint=|android:inputType=|android:imeOptions=|android:password='
   ```

   An editable view with **no** `android:inputType` is a plain text field and eligible for learning. Resolve `@string/...` hints in `apk_out/res/values/strings.xml` to see which field is which.

3. **Code.** Find every programmatic input type, IME option and transformation method, outside library packages:

   ```bash
   grep -rnE '\.setInputType\(|\.setRawInputType\(|\.setImeOptions\(|\.setTransformationMethod\(' out/sources/ \
       | grep -vE '^out/sources/(androidx|android/support|com/google/android/material)/'
   semgrep -c mastg-android-keyboard-cache-input-types.yml out/sources/
   ```

   The OWASP rule simply matches `$OBJ.setInputType($ARG)`; like most rules in this series it is a locator, not a verdict.

4. **Compose.** Look for `KeyboardOptions` and the keyboard types. Compose's inline value classes produce mangled names in decompiled code, so match on the stable part:

   ```bash
   grep -rnE 'KeyboardOptions|KeyboardType\.Companion\.m[0-9]+get(Password|NumberPassword|PasswordVisible|Text|Number|Email)|PasswordVisualTransformation' \
       out/sources/ | grep -vE '^out/sources/androidx/'
   ```

5. **Decode every integer.** For each `setInputType(N)`, decode `N`:

   ```python
   # inputtype.py - run as: python3 -I inputtype.py 129
   import sys
   v = int(sys.argv[1], 0)
   cls, var, flags = v & 0xF, v & 0xFF0, v & 0xFFF000
   classes = {1: "TEXT", 2: "NUMBER", 3: "PHONE", 4: "DATETIME"}
   text_var = {0x00: "NORMAL", 0x10: "URI", 0x20: "EMAIL_ADDRESS", 0x60: "PERSON_NAME",
               0x80: "PASSWORD", 0x90: "VISIBLE_PASSWORD", 0xA0: "WEB_EDIT_TEXT",
               0xD0: "WEB_EMAIL_ADDRESS", 0xE0: "WEB_PASSWORD"}
   text_flags = {0x8000: "AUTO_CORRECT", 0x10000: "AUTO_COMPLETE", 0x20000: "MULTI_LINE",
                 0x80000: "NO_SUGGESTIONS"}
   name = classes.get(cls, hex(cls))
   if cls == 1:
       name += "|" + text_var.get(var, hex(var))
       name += "".join("|" + n for f, n in text_flags.items() if flags & f)
   elif cls == 2:
       name += "|PASSWORD" if var == 0x10 else ""
   non_caching = (cls == 1 and (var in (0x80, 0x90, 0xE0) or flags & 0x80000)) or (cls == 2 and var == 0x10)
   print(f"{v} = {name} -> {'non-caching' if non_caching else 'ELIGIBLE for keyboard learning'}")
   ```

6. **Follow the order of calls.** The last call wins. A field set to `numberPassword` in XML and then to `InputType.TYPE_CLASS_NUMBER` in `onCreate()` is a plain number field; that is exactly what OWASP's demo shows. In jadx-gui, use *Find Usage* on the view's ID to see every place it is configured.

7. **Map to the inventory.** For each sensitive field from your inventory, record the effective input type and IME options. Confirm any doubtful case with [GT-0036-1](#gt-0036-1-runtime-input-type-and-keyboard-learning-check-android).

#### Observation

A list of every `android:inputType` / `android:imeOptions` attribute in layouts and every `setInputType()` / `setImeOptions()` / `KeyboardOptions` use in code, with the decoded value and the field it belongs to.

#### Evaluation

The test **fails** if any field that handles sensitive data (from your inventory) ends up with an input type that is not one of: a password variation (`textPassword`, `numberPassword`, `textWebPassword`, `textVisiblePassword`) or a text class with `TYPE_TEXT_FLAG_NO_SUGGESTIONS`. Secrets (passwords, PINs, OTPs, CVVs) need a *masking* password variation; `textVisiblePassword` and `textNoSuggestions` are only acceptable for sensitive values that may legitimately be visible (a card number being typed, an IBAN).

It **passes** if every sensitive field uses a non-caching type and no later call overrides it. Record as an observation (not a failure) a sensitive non-password field that uses `textNoSuggestions` without `flagNoPersonalizedLearning`, and a `minSdkVersion` below 11 if the app uses `numberPassword` or `textWebPassword` (OWASP's knowledge page flags that older platforms do not know those constants).

#### Demo

[MASTG-DEMO-0064](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0064/MASTG-DEMO-0064/). A sign-up dialog with three fields:

```kotlin
val input1 = EditText(context).apply {
    hint = "Enter password (not cached)"
    inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD   // 129
}
val input2 = EditText(context).apply {
    hint = "Enter password (cached)"
    inputType = InputType.TYPE_CLASS_TEXT                                            // 1
}
val input3 = EditText(context).apply {
    hint = "Enter PIN (cached)"
    inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD // 18
}
input3.inputType = InputType.TYPE_CLASS_NUMBER                                         // 2, overrides 18
```

The semgrep rule finds four calls in the decompiled code:

```text
MastgTest_reversed.java
 35┆ $this$showPopup_u24lambda_u241.setInputType(129);
 38┆ $this$showPopup_u24lambda_u242.setInputType(1);
 41┆ input3.setInputType(18);
 42┆ input3.setInputType(2);
```

129 decodes to `TEXT|PASSWORD` (pass). 1 is plain text, so the second password field is learnable (fail). 18 would be a numeric password, but the following call sets 2, a plain number, so the PIN field is learnable too (fail). The test fails.

### MASTG-TEST-0316: App Exposing User Authentication Data in Text Input Fields (Android)

Source: [MASTG-TEST-0316](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0316/). Platform: Android. Type: static (code) with manual review. OWASP maps it to MASWE-0036 and also to [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/); we document it here because it tests on-screen masking, and the accessibility note links back to it.

#### Overview

The test checks that fields for access codes (passwords, PINs) and verification codes (OTPs) mask what is typed. For Views that means a password `inputType`; for Compose it means `SecureTextField` (or `OutlinedSecureTextField` / `BasicSecureTextField`) with a masking `TextObfuscationMode`, or a `TextField` with `PasswordVisualTransformation()`. OWASP's version focuses on Compose: it flags uses of `TextField` and any `SecureTextField` configured with `TextObfuscationMode.Visible`.

#### Prerequisites

- The APK decompiled with jadx ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)), and apktool output for layouts.
- semgrep with the OWASP rule `mastg-android-input-field-usage.yml`, or grep ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)).
- jadx-gui for reviewing each hit ([MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)), and a device to look at the screens.

#### Steps

1. **Run the OWASP rule** against the decompiled sources. It matches references to `androidx.compose.material3.TextFieldKt` and calls to `SecureTextFieldKt.m…SecureTextField…(…)` that pass `TextObfuscationMode.Companion.m…getVisible…()`:

   ```bash
   semgrep -c mastg-android-input-field-usage.yml out/sources/
   ```

2. **Widen the search**, because the rule misses common variants: `OutlinedTextField`, Foundation's `BasicTextField`, `OutlinedSecureTextField`, `BasicSecureTextField`, the legacy `PasswordVisualTransformation` pattern, and visibility chosen by a variable rather than a constant:

   ```bash
   grep -rnE '(Outlined)?(Secure)?TextFieldKt\.|Basic(Secure)?TextFieldKt\.|TextObfuscationMode\.Companion|PasswordVisualTransformation|VisualTransformation\.Companion\.getNone' \
       out/sources/ | grep -vE '^out/sources/androidx/'
   ```

3. **Views.** From the layouts and code you collected in MASTG-TEST-0258, list password, PIN and OTP fields whose effective `inputType` is not a masking password variation, and fields that rely on `setTransformationMethod(PasswordTransformationMethod…)` with a plain input type.

4. **Review each hit** in jadx-gui. Identify what the field is for by tracing its label lambda back to the text it renders (Compose) or its `hint` / ID (Views), and check how the obfuscation mode or transformation is chosen: constant `Visible` is a failure, a state variable driven by a reveal button is normal, a state variable that *defaults* to visible is a failure.

5. **Look at the screen.** Type into each authentication field on a device. Dots (with an optional brief reveal of the last character) mean masked.

#### Observation

The list of text input fields used for access or verification codes, with file and line, the masking configuration of each (input type, transformation method, Compose component and obfuscation mode), and a screenshot of each field with text typed into it.

#### Evaluation

The test **fails** if any field used for a password, PIN, passcode, OTP or similar code shows the typed characters in clear by default, for example because:

- a Compose `TextField` / `OutlinedTextField` / `BasicTextField` is used for it without `PasswordVisualTransformation()`;
- a `SecureTextField` is configured with `TextObfuscationMode.Visible`, or with a mode that starts as visible;
- a View field's effective `inputType` is not `textPassword`, `numberPassword` or `textWebPassword`, and no password transformation method is applied.

It **passes** if every such field is masked by default. A reveal toggle the user must press is fine. Unmasked username and email fields are not failures. Visual-only masking (password transformation with a plain input type, or `PasswordVisualTransformation` without `KeyboardType.Password`) passes this test and fails MASTG-TEST-0258.

OWASP notes the false negatives: custom input controls (game engines, custom UI frameworks) that do not use these classes will not be found. Cover them with [GT-0036-1](#gt-0036-1-runtime-input-type-and-keyboard-learning-check-android) and by looking at the screen.

#### Demo

[MASTG-DEMO-0079](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0079/MASTG-DEMO-0079/). A Compose login screen:

```kotlin
TextField(
    state = rememberTextFieldState(),
    label = { Text("Username") },
)
SecureTextField(
    state = rememberTextFieldState(),
    textObfuscationMode = TextObfuscationMode.Visible,   // masking switched off
    label = { Text("Visible Password Field") },
)
```

semgrep finds both components in the decompiled `ComposableSingletons$MainActivityKt` class:

```text
142┆ TextFieldKt.TextField(TextFieldStateKt.m1440rememberTextFieldStateLepunE(...), ...,
       ComposableSingletons$MainActivityKt.INSTANCE.m10512getLambda2$app_debug(), ...);
143┆ SecureTextFieldKt.m3241SecureTextFieldXvU6IwQ(TextFieldStateKt.m1440rememberTextFieldStateLepunE(...), ...,
       TextObfuscationMode.Companion.m1459getVisiblevTwcZD0(), ...);
```

Line 143 is the failure: a secure field explicitly set to `Visible`. Line 142 is a false positive: following its label lambda (`m10512getLambda2$app_debug()`) leads to `TextKt.m3574TextNvy7gAk("Username", ...)`, so it is the username field. The test fails because of the password field.

### MASTG-TEST-0313: References to APIs for Preventing Keyboard Caching of Text Fields (iOS)

Source: [MASTG-TEST-0313](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0313/). Platform: iOS. Type: static (code) with manual review. Knowledge: MASTG-KNOW-0100. Best practice: MASTG-BEST-0026 (placeholder). OWASP keeps the file in its MASVS-STORAGE folder but maps it to MASWE-0036.

#### Overview

The test searches the app binary for text input classes (`UITextField`, `UITextView`, `UISearchBar`) and for the trait setters that keep input out of the keyboard cache (`setSecureTextEntry:`, `setAutocorrectionType:`, `setSpellCheckingType:`), then reads the arguments passed to each. Because the default is "eligible", and because traits are often set in compiled storyboards, absence of a call proves little: OWASP itself says this test may miss many true positives and recommends MASTG-TEST-0314 for coverage.

#### Prerequisites

- A decrypted IPA, unzipped, with the main binary and any frameworks you are responsible for ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)).
- radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)) for static analysis ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/)) and disassembly review ([MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)).

#### Steps

1. **Extract and confirm the binary is decrypted.**

   ```bash
   unzip -q App.ipa -d ipa
   BIN=ipa/Payload/App.app/App
   otool -l "$BIN" | grep -A4 LC_ENCRYPTION_INFO     # cryptid 0 = decrypted
   ```

2. **Check which selectors and classes the binary references.** The selector strings are in `__objc_methname` whether the code is Objective-C or Swift calling UIKit:

   ```bash
   rabin2 -zz "$BIN" | grep -E 'setSecureTextEntry:|setAutocorrectionType:|setSpellCheckingType:|setInlinePredictionType:'
   rabin2 -i "$BIN"  | grep -E 'UITextField|UITextView|UISearchBar'
   ```

3. **Find the call sites.** In radare2, list the selector references and their cross-references (addresses differ per binary; take them from the `f~` output):

   ```bash
   r2 -A "$BIN"
   # inside r2:
   f~UITextField,UITextView,UISearchBar
   f~setAutocorrectionType,setSecureTextEntry,setSpellCheckingType
   axt @ <address of reloc.fixup.setAutocorrectionType:>
   axt @ <address of reloc.fixup.setSpellCheckingType:>
   axt @ <address of reloc.fixup.setSecureTextEntry:>
   ```

4. **Read the argument at each call site.** Print the instructions around each `ldr x1, <selector>`: `x0` holds the receiver, `x1` the selector, `x2`/`w2` the argument. Map raw values with the enums (`0` = default, `1` = no, `2` = yes; for `setSecureTextEntry:` `1` = true). Look backwards for the field's placeholder or `accessibilityIdentifier` string to tell which field it is:

   ```bash
   # inside r2
   pd--10 @ <call-site address>
   ```

5. **Check storyboards in source if you have them** (white-box): grep the `.storyboard` and `.xib` XML for `textInputTraits`. In a binary-only test, go straight to MASTG-TEST-0314.

#### Observation

For each sensitive field: the call sites that configure it, the decoded value of each trait, and the evidence that links the call site to the field (placeholder, identifier, surrounding code).

#### Evaluation

The test **fails** if a field that may handle sensitive values (usernames, passwords, email addresses, card numbers, recovery codes) is eligible for keyboard caching. OWASP lists three conditions joined by "or" (`isSecureTextEntry` not enabled, `autocorrectionType` default or yes, `spellCheckingType` default or yes); read literally, that would fail a field with autocorrection and spell checking both off simply because it is not secure. The logic OWASP's own Frida script uses, and the one we apply, is:

*A field is excluded from caching if `isSecureTextEntry` is true, **or** if both `autocorrectionType` and `spellCheckingType` are `.no`. Otherwise it is eligible.*

Secrets additionally need `isSecureTextEntry` (that is MASTG-TEST-0346). A field you cannot find any configuration for is eligible by default; mark it "further validation required" and confirm with MASTG-TEST-0314. OWASP's advice is to disable all three for any field that may carry sensitive information, which we agree with.

#### Demo

[MASTG-DEMO-0076](https://mas.owasp.org/MASTG/demos/ios/MASVS-STORAGE/MASTG-DEMO-0076/MASTG-DEMO-0076/). An alert with three fields:

```swift
alert.addTextField { tf in
    tf.placeholder = "Name"
    tf.autocorrectionType = .default        // eligible
    tf.spellCheckingType = .no
}
alert.addTextField { tf in
    tf.placeholder = "E-Mail"
    tf.autocorrectionType = .no             // spell checking left at default: eligible
}
alert.addTextField { tf in
    tf.placeholder = "Password"
    tf.isSecureTextEntry = true             // excluded
}
```

radare2 finds one `setSecureTextEntry:` reference, two `setAutocorrectionType:` and one `setSpellCheckingType:`, and the disassembly shows the arguments:

```text
0x100004550  ldr x1, [x8, 0x120]   ; reloc.fixup.setAutocorrectionType:   (Name)
0x100004558  mov x2, 0             ; UITextAutocorrectionTypeDefault
0x100004564  ldr x1, [x8, 0x128]   ; reloc.fixup.setSpellCheckingType:    (Name)
0x10000456c  mov w2, 1             ; UITextSpellCheckingTypeNo
0x100004604  ldr x1, ...           ; reloc.fixup.setAutocorrectionType:   (E-Mail)
0x10000460c  mov w2, 1             ; UITextAutocorrectionTypeNo
0x1000046b0  ldr x1, ...           ; reloc.fixup.setSecureTextEntry:      (Password)
0x1000046b8  mov w2, 1             ; true
```

The name field explicitly keeps autocorrection at default, and the email field has no spell-checking call, so both are eligible. The test fails; the password field passes.

### MASTG-TEST-0314: Runtime Monitoring of Text Fields Eligible for Keyboard Caching (iOS)

Source: [MASTG-TEST-0314](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0314/). Platform: iOS. Type: dynamic (hooks). Prerequisite: identify the sensitive data (your inventory). Knowledge: MASTG-KNOW-0100. OWASP keeps the file in its MASVS-STORAGE folder.

#### Overview

The runtime counterpart of MASTG-TEST-0313. Instead of reading code, it hooks the text input classes and, every time a field loses focus, reports its class, accessibility identifier, placeholder, the caching-relevant traits and the text that was entered. That catches fields configured in storyboards, in SwiftUI and in code paths that static analysis cannot resolve.

#### Prerequisites

- The app installed on a device ([MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/)) with frida-server running (jailbroken), or a Frida Gadget build; Frida ([MASTG-TOOL-0039](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/)) on your machine.
- Method hooking ([MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/)).
- Your inventory of sensitive fields, and realistic test values for each.

#### Steps

1. Save the script below as `kbcache.js`. It is OWASP's script, condensed: it hooks `-resignFirstResponder` on `UITextField`, `UITextView` and `UISearchBar` and classifies each field with the logic from MASTG-TEST-0313.

   ```javascript
   // kbcache.js - log keyboard-cache eligibility of every text input when it loses focus
   const T = { 0: '.default', 1: '.no', 2: '.yes' };
   ['UITextField', 'UITextView', 'UISearchBar'].forEach(name => {
     const cls = ObjC.classes[name];
     if (!cls || !cls['- resignFirstResponder']) return;
     Interceptor.attach(cls['- resignFirstResponder'].implementation, {
       onEnter(args) {
         const f = new ObjC.Object(args[0]);
         const ac = T[f.autocorrectionType()];
         let sc = null; try { sc = T[f.spellCheckingType()]; } catch (e) {}
         const secure = f.isSecureTextEntry ? f.isSecureTextEntry() : false;
         const aid = f.respondsToSelector_(ObjC.selector('accessibilityIdentifier')) ? f.accessibilityIdentifier() : null;
         const ph = f.respondsToSelector_(ObjC.selector('placeholder')) ? f.placeholder() : null;
         const excluded = secure || (ac === '.no' && sc === '.no');
         console.log(`${excluded ? 'Excluded from caching' : 'Eligible for caching'} ` +
           `[autocorrectionType=${ac}, spellCheckingType=${sc}, isSecureTextEntry=${secure}, ` +
           `class=${f.$className}, aid=${aid}, placeholder=${ph}]: "${f.text()}"`);
       }
     });
   });
   ```

2. Spawn the app with the script and save the output:

   ```bash
   frida -U -f com.example.app -l kbcache.js -o kbcache.txt
   ```

3. Exercise every flow in your inventory, typing realistic values into every field (a test card number, a test IBAN, the test account's email, the password, OTPs), and move focus out of each field (next field, keyboard dismiss, submit).

4. Optionally confirm the effect. On a non-jailbroken device: reset the keyboard dictionary, type a unique canary into the field, submit, then type its first letters in Notes and see whether QuickType offers it. On a jailbroken device: `grep -rl GTCANARY7319 /private/var/mobile/Library/Keyboard/` over SSH.

#### Observation

One line per field interaction with class, identifier, placeholder, traits and entered value, which lets you associate each sensitive value with its field and protection status.

#### Evaluation

The test **fails** if a field that received a sensitive value is reported as eligible for caching (`isSecureTextEntry` false and not both `autocorrectionType` and `spellCheckingType` set to `.no`). It **passes** if every field that received sensitive data is excluded. If the app's text entry does not go through UIKit text inputs (Flutter, game engines, custom keyboards drawn by the app), the hooks will not fire: note it as a false-negative risk and fall back to the canary check.

#### Demo

[MASTG-DEMO-0077](https://mas.owasp.org/MASTG/demos/ios/MASVS-STORAGE/MASTG-DEMO-0077/MASTG-DEMO-0077/), using the same sample as DEMO-0076:

```text
Eligible for caching [autocorrectionType=.default, spellCheckingType=.no, isSecureTextEntry=false, class=_UIAlertControllerTextField, aid=name_field, placeholder=Name]: "OWASP MAS"
Eligible for caching [autocorrectionType=.no, spellCheckingType=.default, isSecureTextEntry=false, class=_UIAlertControllerTextField, aid=email_field, placeholder=E-Mail]: "mas@owasp.org"
Excluded from caching [autocorrectionType=.no, spellCheckingType=.no, isSecureTextEntry=true, class=_UIAlertControllerTextField, aid=password_field, placeholder=Password]: "my$ecr3tP4sS!"
```

The name and email fields received personal data and are eligible, so the test fails. Note that UIKit reports the secure field's other traits as `.no`, although the code only set `isSecureTextEntry`.

### MASTG-TEST-0346: References to APIs Hiding Sensitive Data in Text Input Fields (iOS)

Source: [MASTG-TEST-0346](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0346/). Platform: iOS. Type: static (code) with manual review. Knowledge: MASTG-KNOW-0121, MASTG-KNOW-0141. Best practice: MASTG-BEST-0044.

#### Overview

The test looks for text input fields in the binary and checks that those used for passwords, PINs and OTPs are masked: `isSecureTextEntry = true` on a `UITextField`, or a SwiftUI `SecureField` instead of `TextField`. An unmasked secret field is visible to anyone who can see the screen, and on iOS it is also open to whatever third-party keyboard the user has installed, because only secure fields force the system keyboard.

#### Prerequisites

- A decrypted IPA ([MASTG-TECH-0065](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0065/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)).
- radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)), for searching ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/)) and reading the disassembly ([MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)).

#### Steps

1. **List the relevant symbols.** In a Swift binary, UIKit text fields appear as `UITextField` class references and closures, SwiftUI fields as mangled `SwiftUI.SecureField` and `SwiftUI.TextField` symbols:

   ```bash
   r2 -A "$BIN"     # $BIN as extracted in MASTG-TEST-0313, step 1
   # inside r2:
   f~UITextField,setSecureTextEntry,SecureField,SwiftUI.TextField
   ```

2. **Cross-reference the setter and the SwiftUI initialisers.**

   ```bash
   # inside r2, with addresses from step 1
   axt @ <address of reloc.fixup.setSecureTextEntry:>
   axt @ <address of the SwiftUI.SecureField initializer>
   axt @ <address of the SwiftUI.TextField initializer>
   ```

3. **Read each `setSecureTextEntry:` argument.** As in MASTG-TEST-0313, `w2`/`x2` holds the boolean; unoptimised Swift often loads it from a stack slot (`ldr w8, [var_1ch]` then `and w2, w8, 1`), so follow it back to the `mov w8, 0` or `mov w8, 1` that stored it.

4. **Identify each field's purpose.** Look for the placeholder, label or accessibility identifier string loaded near the call (`"password_field"`, `"OTP"`), and confirm on the device by typing into it.

#### Observation

The list of text input fields (UIKit and SwiftUI) with their location, whether they are masked, and what each is used for.

#### Evaluation

The test **fails** if a field used for a password, PIN or OTP is a `UITextField` without `isSecureTextEntry = true` (explicitly `false`, or never set), or a SwiftUI `TextField` rather than `SecureField`. Unmasked non-sensitive fields such as username or email are not failures (though they are still keyboard-cache candidates for MASTG-TEST-0313). Custom input controls that do not use these classes cause false negatives.

#### Demo

[MASTG-DEMO-0112](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0112/MASTG-DEMO-0112/). A login alert and a SwiftUI OTP screen:

```swift
alert.addTextField { tf in
    tf.placeholder = "Password"
    tf.isSecureTextEntry = false            // FAIL: password shown in clear
    tf.accessibilityIdentifier = "password_field"
}
alert.addTextField { tf in
    tf.placeholder = "OTP 1"
    tf.isSecureTextEntry = true             // PASS
    tf.keyboardType = .numberPad
}
// SwiftUI
SecureField("OTP 2", text: $otp2)          // PASS: always masked
```

radare2 shows two `setSecureTextEntry:` call sites and one `SecureField` initialiser call:

```text
Cross-references to the "setSecureTextEntry:" selector:
...UITextField...U0_ 0x1a24 [DATA:r--] ldr x1, reloc.fixup.setSecureTextEntry:
...UITextField._     0x1b38 [DATA:r--] ldr x1, reloc.fixup.setSecureTextEntry:

0x00001a24  ldr x1, [x8, 0x1c0]   ; str.setSecureTextEntry:
0x00001a28  mov w8, 0
0x00001a2c  and w2, w8, 1         ; w2 = 0 (false) -> password field
0x00001a4c  add x0, x0, 0xf26     ; "password_field"

Cross-references to the "SecureField" initializer:
...OTPView.body... 0x3c60 [CALL:--x] bl sym.SwiftUI.SecureField...
```

The password field's argument is `false`, so the test fails. The OTP 1 call reloads a stored `1` (true) and the SwiftUI `SecureField` masks by design; both pass.

### MASTG-TEST-0347: Runtime Use of APIs Hiding Sensitive Data in Text Input Fields (iOS)

Source: [MASTG-TEST-0347](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0347/). Platform: iOS. Type: dynamic (hooks). Knowledge: MASTG-KNOW-0121, MASTG-KNOW-0141. Best practice: MASTG-BEST-0044.

#### Overview

The runtime counterpart of MASTG-TEST-0346: hook the text input classes, enter realistic sensitive values into every field, and record for each whether it was masked. It catches storyboard configuration, SwiftUI and fields whose masking is decided at runtime.

#### Prerequisites

Same as MASTG-TEST-0314: the app on a device ([MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/)), Frida ([MASTG-TOOL-0039](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/)) and method hooking ([MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/)).

#### Steps

1. Use the `kbcache.js` script from MASTG-TEST-0314: its `isSecureTextEntry` column is exactly what this test needs, so one run covers both tests. OWASP's own script for this test logs `Masked` or `Exposed` instead of the caching verdict.

   ```bash
   frida -U -f com.example.app -l kbcache.js -o fields.txt
   ```

2. Fill in every authentication-related form with realistic values (password, PIN, OTP, recovery code), moving focus out of each field.

3. Watch the screen while you type: masked fields show bullets, unmasked fields show the characters. Take a screenshot of each.

#### Observation

Per field: class, identifier, placeholder, `isSecureTextEntry`, and the value entered, plus the screenshots.

#### Evaluation

The test **fails** if a field that received a password, PIN or OTP reports `isSecureTextEntry=false`, or if the app uses an input control that cannot mask (a SwiftUI `TextField`, a custom control) for such a value. Unmasked username or email fields are not failures.

#### Demo

[MASTG-DEMO-0113](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0113/MASTG-DEMO-0113/), same sample as DEMO-0112:

```text
Exposed [isSecureTextEntry=false, class=_UIAlertControllerTextField, aid=username_field, placeholder=Username]: "username"
Exposed [isSecureTextEntry=false, class=_UIAlertControllerTextField, aid=password_field, placeholder=Password]: "password"
Masked [isSecureTextEntry=true, class=_UIAlertControllerTextField, aid=otp_1_field, placeholder=OTP 1]: "1234"
Masked [isSecureTextEntry=true, class=UITextField, aid=null, placeholder=OTP 2]: "5678"
```

The password field is exposed: the test fails. The username field is exposed but not sensitive. The SwiftUI `SecureField` (OTP 2) shows up as a plain `UITextField` with `aid=null`, because SwiftUI does not pass its `accessibilityIdentifier` to the backing view; the placeholder identifies it.

### GT-0036-1: Runtime input-type and keyboard-learning check (Android)

Guler Tech methodology. Platform: Android. Type: dynamic.

#### Overview

The OWASP Android tests read code, which works for Views and Compose and fails for everything else: Flutter, React Native, WebView forms, game engines, and obfuscated code where the field cannot be tied to a screen. Whatever the toolkit, the field ends up describing itself to the IME in an `EditorInfo`, and Android's own debug dump shows that `EditorInfo` for the field that is focused and for the recent history of focused fields. That is the ground truth for "what did the app ask the keyboard to do". The canary check then shows what the keyboard actually did.

#### Prerequisites

- A test device or emulator with `adb`; Gboard as the active IME (it is the most common one and follows the hints), with suggestions enabled.
- The `inputtype.py` helper from MASTG-TEST-0258 (it accepts hex such as `0x81`).
- Optional: root, to search the IME's data directory.

#### Steps

1. **Focus each sensitive field** from your inventory (tap into it so the keyboard opens) and dump the input method state:

   ```bash
   adb shell dumpsys input_method > ime-login-password.txt
   grep -E 'inputType=0x|hintText=|packageName=' ime-login-password.txt
   ```

   The IME service section prints the focused field's `EditorInfo` (`mInputEditorInfo:`), and the start-input history prints one line per recently focused field, so a single dump after walking a form covers the whole form. The exact layout of the dump differs between Android versions; the `EditorInfo` lines look like this:

   ```text
     mInputEditorInfo:
       inputType=0x81 imeOptions=0x2000006 privateImeOptions=null
       hintText=Password label=null
       packageName=com.example.app autofillId=1073741824 fieldId=2131230987 fieldName=null
   ```

2. **Decode** each `inputType` with `inputtype.py` and check `imeOptions` for `0x1000000` (`IME_FLAG_NO_PERSONALIZED_LEARNING`):

   ```bash
   python3 -I inputtype.py 0x81
   python3 -c 'import sys; v=int(sys.argv[1],0); print("noPersonalizedLearning" if v & 0x1000000 else "learning allowed")' 0x2000006
   ```

3. **Tie fields to screens.** `fieldId` is the view's resource ID for View-based fields; find its name in `apk_out/res/values/public.xml` (convert to hex first: `printf '0x%x\n' 2131230987`). For Compose, Flutter and WebView fields the ID is not a resource; use `hintText`, the screen you are on and the order of the history entries.

4. **Canary check.** In each sensitive field, type a unique value such as `GTCANARY7319` three times across separate submissions. Then open a plain text field in another app (a notes app, the browser address bar), type `GTCAN` and watch the suggestion strip. A suggestion of the canary means the keyboard learnt it from the app.

5. **On a rooted device**, search the active IME's storage for the canary (see [MASTG-KNOW-0055](#android-keyboard-cache-mastg-know-0055)):

   ```bash
   IME_PKG=$(adb shell settings get secure default_input_method | cut -d/ -f1)
   adb shell su -c "grep -rl GTCANARY7319 /data/data/$IME_PKG/"
   ```

6. **Check the reveal state** of any "show password" control: reveal, send the app to the background (`adb shell input keyevent KEYCODE_HOME`), return, and see whether the field is masked again.

#### Observation

Per sensitive field: the `inputType` and `imeOptions` the IME received (decoded), whether the canary was suggested elsewhere or found in the IME's storage, and whether reveal state persists across backgrounding.

#### Evaluation

The field **fails** if it carries a secret and the IME received a non-password `inputType`, or if it carries any sensitive value and the IME received an input type that is eligible for learning (no password variation, no `NO_SUGGESTIONS` flag) without `IME_FLAG_NO_PERSONALIZED_LEARNING`. A canary that comes back as a suggestion or is found in the IME's storage is direct proof and should be in the report. It **passes** if every sensitive field is described correctly. If the description is correct and the canary still leaks, the IME is ignoring the hints: report it as an observation about the platform, not a finding against the app.

#### Demo

An illustrative pair from a payment form. The card-number field is plain text and the IME may learn from it; the CVV field is a numeric password with personalised learning disabled:

```text
inputType=0x1 imeOptions=0x6 ...             hintText=Card number
inputType=0x12 imeOptions=0x1000006 ...      hintText=CVV
```

`0x1` decodes to `TEXT|NORMAL` (eligible), `0x12` to `NUMBER|PASSWORD` (masked, non-caching), and `0x1000006` contains the no-learning flag. The card-number field fails; the fix is `inputType="number"` (or `textNoSuggestions` for an alphanumeric value) plus `imeOptions="flagNoPersonalizedLearning"`.

### GT-0036-2: Manual UI review for unmasked sensitive values (Android and iOS)

Guler Tech methodology. Platform: Android and iOS. Type: manual / UI, with tooling.

#### Overview

None of the OWASP tests look at what the app *displays*. This review finds sensitive values shown in full where a partial value would do, values revealed without an explicit user action or left revealed, and masked values whose full form is still present in the UI tree (where screen readers, accessibility services and UI automation can read it). It uses the platform's own UI inspection: `uiautomator dump` on Android, the Accessibility Inspector and a Frida view scan on iOS.

#### Prerequisites

- A test account with realistic data: a card on file, a bank account, identity details, recovery codes.
- Android: `adb`, Python 3. iOS: Xcode's Accessibility Inspector (simulator or a connected device), and optionally Frida or objection on a jailbroken device.
- The value catalogue from [Unmasked sensitive values on screen](#generic-unmasked-sensitive-values-on-screen-guler-tech).

#### Steps

1. **Walk every screen in the inventory** and, for each, write down what is shown and whether it is the full value, a partial value or masked. Screenshot each screen (`adb exec-out screencap -p > screen.png` on Android; side button + volume up on iOS). If the screenshot comes out black, the app uses `FLAG_SECURE` or an iOS capture-hiding technique; that is good for [MASWE-0038](/mobile/maswe-0038-insufficient-screenshot-protection/) and does not change this review, so photograph the screen with a second device.

2. **Android: dump and scan the UI tree** on each screen, including the masked state and, separately, the revealed state:

   ```bash
   adb shell uiautomator dump /sdcard/ui.xml && adb pull /sdcard/ui.xml ui-cards.xml
   ```

   ```python
   # uiscan.py - run as: python3 -I uiscan.py ui-*.xml
   import re, sys, xml.etree.ElementTree as ET
   PATTERNS = {
       "PAN-like": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
       "IBAN-like": re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b"),
       "NINO-like": re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b"),
   }
   for path in sys.argv[1:]:
       for n in ET.parse(path).iter("node"):
           cls, rid = n.get("class", ""), n.get("resource-id", "")
           text, desc, pw = n.get("text", ""), n.get("content-desc", ""), n.get("password", "")
           if "EditText" in cls or pw == "true":
               print(f"{path}: [input] {cls} id={rid} password={pw} text={text!r}")
           for label, rx in PATTERNS.items():
               for where, val in (("text", text), ("content-desc", desc)):
                   if rx.search(val):
                       print(f"{path}: [{label} in {where}] {cls} id={rid} value={val!r}")
   ```

   Every editable node is listed with its `password` attribute (Compose text fields also appear as `android.widget.EditText`), so you can spot a PIN field reporting `password="false"`. Any full-length card number, IBAN or NI-number pattern in `text` or `content-desc` is flagged, which catches the common case of a label showing `•••• 1234` while its `content-desc` carries the whole number.

3. **iOS: inspect with the Accessibility Inspector.** In Xcode, *Xcode > Open Developer Tool > Accessibility Inspector*, choose the simulator or the connected device as target, enable the pointer, and hover over every sensitive label and field. Check the *Label* and *Value* in the Basic section: a masked display should not have the full value as its label or value, and a secure text field should not expose its contents.

4. **iOS: scan live views with Frida** (UIKit only; SwiftUI `Text` is not a `UILabel`, so use step 3 or objection's `ios ui dump` for SwiftUI screens). Attach to the app while it shows the screen of interest:

   ```javascript
   // uiscan-ios.js - list text fields and any label showing a PAN-like number
   const panLike = /\b(?:\d[ -]?){13,19}\b/;
   const str = o => (o === null ? '' : o.toString());
   ObjC.schedule(ObjC.mainQueue, () => {
     ObjC.choose(ObjC.classes.UITextField, {
       onMatch(f) {
         console.log(`[field] ${f.$className} aid=${str(f.accessibilityIdentifier())} ` +
           `placeholder=${str(f.placeholder())} secure=${f.isSecureTextEntry()} text="${str(f.text())}"`);
       },
       onComplete() {}
     });
     ObjC.choose(ObjC.classes.UILabel, {
       onMatch(l) {
         const t = str(l.text()), a = str(l.accessibilityLabel());
         if (panLike.test(t) || panLike.test(a)) console.log(`[label] ${l.$className} text="${t}" accessibilityLabel="${a}"`);
       },
       onComplete() {}
     });
   });
   ```

   ```bash
   frida -U -F -l uiscan-ios.js        # -F attaches to the frontmost app
   ```

   `ObjC.choose` also finds views that are not currently on screen (cached cells, previous screens still in memory), which is useful: a full PAN sitting in an off-screen label is still in the UI tree.

5. **Test the reveal flow** for every value that can be revealed: what action reveals it, is step-up authentication required, does it re-mask after a timeout, does it re-mask when the app goes to the background and comes back, and does the app switcher snapshot show it (the last point is [MASWE-0038](/mobile/maswe-0038-insufficient-screenshot-protection/)).

6. **Look for echoes**: confirmation screens, error messages, receipts and share sheets that repeat a value in full.

#### Observation

Per screen: screenshots in masked and revealed states, the UI tree scan output, and for each sensitive value whether it is shown in full or partially, how reveal works, and whether the full value is present in the UI tree while the display is masked.

#### Evaluation

The review **fails** for a value if it is shown in full where a partial representation would serve the user's task (by the catalogue above), if it is revealed without an explicit user action, if a revealed high-value item (full PAN with CVV, recovery codes, full identity numbers) stays revealed after backgrounding or indefinitely, or if a secret is echoed back at all. A masked display whose full value is in `content-desc` / `accessibilityLabel` fails here and should also be reported under [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/). It **passes** if every sensitive value is minimised by default and revealed only deliberately and temporarily.

#### Demo

An illustrative Android finding. The cards screen shows `•••• 4242`, but the scan reports:

```text
ui-cards.xml: [PAN-like in content-desc] android.widget.TextView id=com.example.app:id/card_number value='Card number 4000 0000 0000 4242'
```

The layout builds the visible text from the last four digits and the content description from the full number:

```kotlin
binding.cardNumber.text = "•••• ${card.pan.takeLast(4)}"
binding.cardNumber.contentDescription = "Card number ${card.pan}"   // full PAN in the UI tree
```

Fix: have the API return only the last four digits for this screen, and build both strings from them.

### Pointer: pasteboard tests MASTG-TEST-0276 to 0280 (iOS)

OWASP files five iOS pasteboard tests under MASWE-0036: [MASTG-TEST-0276](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0276/) (Use of the iOS General Pasteboard), [MASTG-TEST-0277](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0277/) (Sensitive Data in the iOS General Pasteboard at Runtime), [MASTG-TEST-0278](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0278/) (Pasteboard Contents Not Cleared After Use), [MASTG-TEST-0279](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0279/) (Pasteboard Contents Not Expiring) and [MASTG-TEST-0280](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0280/) (Pasteboard Contents Not Restricted to Local Device). They are documented in full, with our Android clipboard tests, in the [clipboard note (MASWE-0030)](/mobile/maswe-0030-improper-use-of-the-clipboard/), where the pasteboard mechanism is explained. The link to this note is the secure text field: `isSecureTextEntry` disables copy and cut, so a masked field cannot be the source of a pasteboard leak, while an unmasked password field can.

### Pointer: MASTG-TEST-0340 References to Overlay Attack Protections (Android)

OWASP also files [MASTG-TEST-0340](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0340/) under MASWE-0036. It checks whether the app uses Android's overlay protections (touch filtering, `setHideOverlayWindows`) on sensitive screens, and is documented in full in the [overlay attacks note (MASWE-0039)](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/), together with the platform's untrusted-touch rules.

## Best practices

### MASTG-BEST-0044: Mask Sensitive Data in Text Input Fields

Source: [MASTG-BEST-0044](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0044/) (iOS). For any field that takes a password, PIN or OTP, use the platform's secure entry: `isSecureTextEntry = true` on `UITextField`, or `SecureField` in SwiftUI. Do not use a plain `TextField` styled to look masked; it does not get the platform's protections (no copy, no keyboard learning, system keyboard only). The same principle on Android: a password `inputType` or a Compose secure text field, not a custom-drawn mask.

```swift
let pinField = UITextField()
pinField.isSecureTextEntry = true
pinField.keyboardType = .numberPad
pinField.textContentType = .oneTimeCode    // for OTP fields: enables code AutoFill, does not mask

// SwiftUI
SecureField("PIN", text: $pin)
    .keyboardType(.numberPad)
```

```xml
<!-- Android Views -->
<EditText
    android:id="@+id/pin"
    android:inputType="numberPassword"
    android:imeOptions="flagNoPersonalizedLearning|actionDone" />
<EditText
    android:id="@+id/password"
    android:inputType="textPassword"
    android:imeOptions="flagNoPersonalizedLearning" />
```

```kotlin
// Jetpack Compose
OutlinedSecureTextField(
    state = pinState,
    label = { Text("PIN") },
    textObfuscationMode = TextObfuscationMode.Hidden,
    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
)
```

### MASTG-BEST-0019 and MASTG-BEST-0026: Prevent keyboard caching of sensitive input

[MASTG-BEST-0019](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0019/) (Android, "Use Non-Caching Input Types for Sensitive Fields") and [MASTG-BEST-0026](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0026/) (iOS, "Preventing Keyboard Caching for Sensitive Text Inputs") are placeholders in OWASP's repository. This is what we recommend in their place.

For sensitive values that do not need masking (card numbers while typed, IBANs, ID numbers, security answers):

```xml
<!-- Android: alphanumeric value, no suggestions, no learning -->
<EditText
    android:id="@+id/iban"
    android:inputType="textNoSuggestions|textCapCharacters"
    android:imeOptions="flagNoPersonalizedLearning" />
<!-- Android: numeric value -->
<EditText
    android:id="@+id/card_number"
    android:inputType="number"
    android:imeOptions="flagNoPersonalizedLearning" />
```

```kotlin
// Compose: no personalised-learning flag is available, so at least disable autocorrect
OutlinedTextField(
    state = ibanState,
    label = { Text("IBAN") },
    keyboardOptions = KeyboardOptions(
        keyboardType = KeyboardType.Ascii,
        capitalization = KeyboardCapitalization.Characters,
        autoCorrectEnabled = false,
    ),
)
```

```swift
// UIKit
ibanField.autocorrectionType = .no
ibanField.spellCheckingType = .no
ibanField.autocapitalizationType = .allCharacters
if #available(iOS 17.0, *) { ibanField.inlinePredictionType = .no }

// SwiftUI
TextField("IBAN", text: $iban)
    .autocorrectionDisabled()
    .textInputAutocapitalization(.characters)
```

Two cautions. The OWASP placeholder note for BEST-0019 says non-caching input types protect data "from being exposed in system-generated snapshots and recordings"; they do not, they only affect the keyboard. And none of these settings are guarantees: they are requests the keyboard is expected to honour, which is why secrets should always use secure entry, the one mode both platforms treat as non-negotiable for their own keyboards.

### MASTG-BEST-0069: Keep Sensitive Input on the System Keyboard

Source: [MASTG-BEST-0069](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0069/) (iOS). Mark secret fields as secure, which keeps third-party keyboards away from them field by field; reserve the app-wide rejection of keyboard extensions (`application(_:shouldAllowExtensionPointIdentifier:)` returning `false` for `.keyboard`) for apps that genuinely need it, because it also takes away accessibility and language keyboards. Details, and the Android side, are in the [app extensions note](/mobile/maswe-0031-allowing-untrusted-app-extensions/).

### Secure patterns for displayed values (Guler Tech)

- **Return less.** Give the screen an API field such as `panLast4`, not the PAN. Then nothing else (logs, caches, accessibility) can leak the rest.
- **Mask by default, reveal deliberately, re-mask automatically.** In Compose:

  ```kotlin
  var revealed by rememberSaveable { mutableStateOf(false) }
  LaunchedEffect(revealed) {
      if (revealed) { delay(30_000); revealed = false }          // re-mask after 30 s
  }
  LifecycleEventEffect(Lifecycle.Event.ON_STOP) { revealed = false }  // re-mask when backgrounded
  Text(if (revealed) details.formattedNumber else "•••• ${details.last4}")
  ```

  On iOS, reset the revealed state in `sceneDidEnterBackground(_:)` (or on `UIApplication.didEnterBackgroundNotification`), and gate the reveal of high-value items behind `LAContext` or a server-side step-up ([MASWE-0023](/mobile/maswe-0023-step-up-authentication-not-implemented/)).
- **Build accessibility text from the masked value**, not the raw one: "Card ending 4242".
- **Never echo secrets.** Confirmation screens say "PIN changed", not the PIN.

## Rating findings

Rate on three things: **what is exposed** (an authentication secret, a high-value identifier, or other personal data), **who can get it and how** (a shoulder-surfer or camera in the same room; someone who picks up the unlocked phone and reads keyboard suggestions; a screen recording or screen share; an attacker with root/jailbreak or forensic access to keyboard files; on iOS, a third-party keyboard with Full Access for unmasked fields), and **whether the exposure needs the user to do anything** beyond normal use. Every path needs either proximity, the device, or a component the user installed and trusted, so MASWE-0036 findings are rarely Critical on their own.

| Rating | Conditions |
|---|---|
| **Critical** | Not used for this weakness alone. Reserve for a chain where the UI exposure feeds a remote attack, for example a full PAN with CVV shown persistently and also captured by a component reachable remotely (rate the chain, cite this note for the UI part). |
| **High** | A password, PIN, passcode, OTP, transaction-signing code or recovery secret entered into an **unmasked** field by default, in an app protecting money, health records, identity or access to other accounts (on iOS this also routes the secret through any third-party keyboard). A secret **echoed back** on screen. A full PAN with CVV, or a complete recovery phrase, shown without explicit user action. |
| **Medium** | Secrets shown unmasked in a lower-value app; secret fields that are masked but eligible for keyboard learning (visual-only masking, so the keyboard can resurface the value); full card numbers, IBANs or national ID numbers shown where a partial value would do, or kept revealed across backgrounding; high-value non-secret fields (card number, IBAN, ID numbers, security answers) eligible for keyboard learning. |
| **Low** | Personal data (email, phone, name, address) eligible for keyboard learning; a reveal toggle that does not re-mask on backgrounding for medium-value data; a masked display whose full value is only in the accessibility tree (rate the accessibility side under [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/), which may be higher); `minSdkVersion` below 11 with `numberPassword` or `textWebPassword`. |
| **Info** | Defence-in-depth gaps: `textNoSuggestions` without `flagNoPersonalizedLearning`; no `inlinePredictionType = .no` on iOS 17+ for sensitive non-secret fields; no app-wide keyboard-extension rejection in a high-assurance iOS app; masking correct but `RevealLastTyped` chosen where `Hidden` was the stated policy. |

Raise a level when the app is typically used in public or shared settings (point-of-sale, kiosks, field workers, shared family devices), when screen sharing or remote support is a feature of the app, or when the exposed secret is long-lived (a password rather than a 30-second OTP). Lower a level when the exposed value is short-lived and single-use and already expired by the time it could be reused, but not below Low for an unmasked secret field. In the report give the screen, the field's resource ID or accessibility identifier, the code location where the configuration is set (from jadx or r2), the decoded `inputType`/`imeOptions` or the trait values, the screenshot, and any canary or keyboard-cache evidence.

## References

- OWASP MASWE: [MASWE-0036: Unnecessary Exposure of Sensitive Data via the User Interface](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0036/); related [MASWE-0023](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0023/), [MASWE-0030](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0030/), [MASWE-0031](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0031/), [MASWE-0038](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0038/), [MASWE-0039](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0039/), [MASWE-0040](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0040/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PLATFORM-3](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/), [MASVS-STORAGE-2](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0055: Keyboard Cache (Android)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0055/), [MASTG-KNOW-0100: Keyboard Cache (iOS)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0100/), [MASTG-KNOW-0121: Text Input Field Masking in iOS](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0121/), [MASTG-KNOW-0141: Custom Keyboards](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0141/), [MASTG-KNOW-0098: User Interface Components](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0098/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0258](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0258/), [MASTG-TEST-0316](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0316/), [MASTG-TEST-0313](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0313/), [MASTG-TEST-0314](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0314/), [MASTG-TEST-0346](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0346/), [MASTG-TEST-0347](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0347/), [MASTG-TEST-0276](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0276/) to [MASTG-TEST-0280](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0280/), [MASTG-TEST-0340](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0340/); legacy [MASTG-TEST-0006](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0006/), [MASTG-TEST-0008](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0008/), [MASTG-TEST-0055](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0055/), [MASTG-TEST-0057](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0057/), [MASTG-TEST-0072](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0072/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0064](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0064/MASTG-DEMO-0064/), [MASTG-DEMO-0079](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0079/MASTG-DEMO-0079/), [MASTG-DEMO-0076](https://mas.owasp.org/MASTG/demos/ios/MASVS-STORAGE/MASTG-DEMO-0076/MASTG-DEMO-0076/), [MASTG-DEMO-0077](https://mas.owasp.org/MASTG/demos/ios/MASVS-STORAGE/MASTG-DEMO-0077/MASTG-DEMO-0077/), [MASTG-DEMO-0112](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0112/MASTG-DEMO-0112/), [MASTG-DEMO-0113](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0113/MASTG-DEMO-0113/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0044](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0044/), [MASTG-BEST-0019](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0019/), [MASTG-BEST-0026](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0026/), [MASTG-BEST-0069](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0069/), [MASTG-BEST-0060](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0060/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0007](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0007/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0065](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0065/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/) (CC BY-SA 4.0)
- OWASP MASTG tools: [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [radare2 for iOS (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [adb (MASTG-TOOL-0004)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/), [Xcode (MASTG-TOOL-0070)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0070/) (CC BY-SA 4.0)
- Android Developers: [Specify the input method type](https://developer.android.com/develop/ui/views/touch-and-input/keyboard-input/style), [`InputType`](https://developer.android.com/reference/android/text/InputType), [`EditorInfo`](https://developer.android.com/reference/android/view/inputmethod/EditorInfo) (incl. `IME_FLAG_NO_PERSONALIZED_LEARNING`), [`TextView` `android:inputType`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType), [`PasswordTransformationMethod`](https://developer.android.com/reference/android/text/method/PasswordTransformationMethod), [Compose: Configure text fields](https://developer.android.com/develop/ui/compose/text/user-input), [`KeyboardOptions`](https://developer.android.com/reference/kotlin/androidx/compose/foundation/text/KeyboardOptions), [`TextObfuscationMode`](https://developer.android.com/reference/kotlin/androidx/compose/foundation/text/input/TextObfuscationMode); AOSP source of `EditorInfo.dump()` and the input method service dump (frameworks/base)
- Apple: [`UITextInputTraits`](https://developer.apple.com/documentation/uikit/uitextinputtraits), [`isSecureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry), [`autocorrectionType`](https://developer.apple.com/documentation/uikit/uitextinputtraits/autocorrectiontype), [`spellCheckingType`](https://developer.apple.com/documentation/uikit/uitextinputtraits/spellcheckingtype), [`textContentType`](https://developer.apple.com/documentation/uikit/uitextinputtraits/textcontenttype), [`SecureField`](https://developer.apple.com/documentation/swiftui/securefield), [`TextField`](https://developer.apple.com/documentation/swiftui/textfield), [App Extension Programming Guide: Custom Keyboard](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/CustomKeyboard.html), [`application(_:shouldAllowExtensionPointIdentifier:)`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/application%28_:shouldallowextensionpointidentifier:%29), [Accessibility Inspector](https://developer.apple.com/documentation/accessibility/accessibility-inspector)
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library/) requirements 3.3 (sensitive authentication data not stored after authorisation) and 3.4.1 (PAN masked when displayed)
- [Frida JavaScript API](https://frida.re/docs/javascript-api/) (`ObjC.choose`, `Interceptor`), [objection](https://github.com/sensepost/objection), [radare2](https://book.rada.re/)
- CWE: [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-359](https://cwe.mitre.org/data/definitions/359.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
