---
title: "MASWE-0070: Inadequate Awareness for Privacy Relevant Actions"
date: 2026-11-10 22:04:00 +0000
subcategory: privacy
summary: "Testing whether an app tells users what a share, sync, upload or visibility change will disclose, to whom, before it happens, and whether traffic matches."
refs: [MASWE-0070, MASVS-PRIVACY-2, CWE-359]
tags: [android, ios, masvs-privacy, transparency, dark-patterns, ux-review]
---

This note is part of our [MASVS-PRIVACY guide](/mobile/masvs-privacy-privacy-testing-guide/) and covers OWASP [MASWE-0070](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0070/): an app that performs a privacy-relevant action without making clear, at the moment it happens, what will be disclosed, to whom, for how long and whether it can be undone. Typical cases are a "find friends" button that uploads the whole address book, a toggle that makes a profile public and indexable, live location sharing with no visible sign that it is still running, an "ask the assistant" feature that sends the open document to a third-party AI model, or a photo post that carries the GPS position of the user's home in its EXIF data. The operating system shows indicators for camera, microphone and location access, but it knows nothing about what the app does with the data afterwards. Explaining that is the app's job. Part of this test is a UX review, but each part ends in something you can check objectively: an inventory of every disclosing action, a review of the notice shown at each one against fixed criteria, and a capture of the app's own traffic to confirm that it sends what the notice says and nothing more. Below you will find the background (what counts as a privacy-relevant action, just-in-time notices, platform indicators, requests from another party, deceptive design patterns, the legal and store rules), our three tests, secure patterns and how to rate the findings.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Android and iOS: What counts as a privacy-relevant action](#android-and-ios-what-counts-as-a-privacy-relevant-action)
  - [Android and iOS: Just-in-time notices versus buried settings](#android-and-ios-just-in-time-notices-versus-buried-settings)
  - [Android and iOS: What the platform shows, and what it cannot](#android-and-ios-what-the-platform-shows-and-what-it-cannot)
  - [Android and iOS: Requests from another party](#android-and-ios-requests-from-another-party)
  - [Android and iOS: Deceptive design patterns](#android-and-ios-deceptive-design-patterns)
  - [Android and iOS: Legal and store requirements](#android-and-ios-legal-and-store-requirements)
- [Tests](#tests)
  - [GT-PRIV-0070-1: Privacy-relevant action inventory (Android and iOS)](#gt-priv-0070-1-privacy-relevant-action-inventory-android-and-ios)
  - [GT-PRIV-0070-2: Just-in-time notice review per action (Android and iOS)](#gt-priv-0070-2-just-in-time-notice-review-per-action-android-and-ios)
  - [GT-PRIV-0070-3: Disclosure matches the notice in traffic (Android and iOS)](#gt-priv-0070-3-disclosure-matches-the-notice-in-traffic-android-and-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app informs the user about the privacy implications before performing an action."* OWASP defines privacy-relevant actions broadly: sharing, exporting, publishing, synchronising, backing up, changing visibility, responding to a request from another party, or moving data out of the app's private storage to a place other apps, users or third parties can reach. The weakness is present when the scope of such an action (which records, which fields, which metadata, which recipient or audience, how persistent) or its material consequences are not reasonably apparent, or when the user cannot review, limit or confirm a consequential disclosure.

Two points in OWASP's text deserve emphasis:

- **It is not about consent.** The weakness applies even when the processing rests on another lawful basis (contract, legitimate interests). The question is whether the interface lets the user understand and control the privacy state that results. Consent quality is [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/).
- **It includes responding to other parties.** Honouring someone else's request for the user's data (a contact asking for location, a relying party asking a wallet for attributes, a partner app asking through a share or account-link flow) without showing what goes to whom is in scope.

MASWE-0070 carries OWASP's **P** and **EUDIW** profiles, applies to Android and iOS, and maps to [CWE-359](https://cwe.mitre.org/data/definitions/359.html) (Exposure of Private Personal Information to an Unauthorized Actor). Its front matter maps it to **MASVS-PRIVACY-2** ("The app prevents identification of the user"). In practice the test sits closer to MASVS-PRIVACY-3 (transparency) and MASVS-PRIVACY-4 (user control); we keep OWASP's mapping in the front matter and mention this so nobody is confused when they map findings.

**OWASP has no tests and no Knowledge items for this weakness**, and there are no legacy v1 PRIVACY tests to replace. The background below is ours, and the three tests are Guler Tech methodology, numbered GT-PRIV-0070-1 to -3.

Keep the neighbours apart:

| Question | Where it lives |
|---|---|
| Is the user told, at the moment of a disclosing action, what goes where, and can they control it? | This note |
| Is the disclosing option preselected or switched on before the user decides? | [MASWE-0071](/mobile/maswe-0071-inadequate-privacy-defaults/) |
| Is consent, where consent is the basis, freely given, specific, informed and prior? | [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/) |
| Does the app explain *why* it asks for a runtime permission? | [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/) |
| Is a less exposing platform API (picker, share sheet) available but not used? | [MASWE-0069](/mobile/maswe-0069-non-privacy-preserving-functionality/) |
| Can the user later see and change who sees their data, or delete and export it? | [MASWE-0077](/mobile/maswe-0077-inadequate-data-visibility-controls/), [MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/) |
| Does the privacy policy or store declaration describe the flow? | [MASWE-0072](/mobile/maswe-0072-inadequate-privacy-policy/), [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) |
| Is sensitive data shown on the lock screen or in a notification? | [MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/) |

## Modes of Introduction

**Labels that hide the destination.** "Continue", "Sync", "Find friends", "Improve suggestions" or "Share" without saying that the address book goes to the provider's server, that a post becomes public, or that a third party receives the content. OWASP calls this *unclear disclosure context*: the label does not identify the records, fields, metadata, destination, audience or resulting state.

**Notice in the wrong place.** The only explanation lives in the privacy policy, a settings sub-page or a one-time onboarding carousel, while the action itself happens weeks later behind a single tap.

**No review step for high-impact disclosures.** Bulk actions (upload all contacts, sync the whole photo library, export a full history) run without a preview of what is selected; a public post goes out without showing its audience; there is no confirmation for actions that are hard to reverse.

**Invisible metadata.** Photos with EXIF GPS and device model, documents with author names, voice notes with location, share links that embed the user ID, contact cards with every field instead of the selected one.

**No feedback after the action.** Live location, background sync or a "visible to nearby users" mode keeps running with no persistent indication and no obvious way to stop it. OWASP calls this *insufficient disclosure review and feedback*.

**Silent responses to other parties.** A friend's location request, an account-link or OAuth flow, a wallet presentation request or an incoming deep link that returns data without showing the requester and the data.

**Feature creep.** A new feature (an AI summary, a "people you may know" list, a cross-app sync) reuses data the user disclosed for another purpose, with no notice at the point where the new disclosure starts.

## Impact

- **Disclosure beyond what the user intended.** Data reaches a wider audience, a different recipient or a more persistent copy than the user meant: a public profile instead of friends, a third-party AI provider instead of on-device processing, a cloud backup instead of local storage. That is the OWASP *violation of user privacy* impact, and it often affects people who never used the app (contacts in an uploaded address book, people tagged in a photo).
- **Physical-world risk.** Location (live sharing, photo GPS, check-ins) and contact data enable stalking, domestic abuse and targeted fraud. These are the cases where a missing notice does real harm.
- **Loss of trust.** Users who discover an unannounced disclosure, often through someone else's notification ("X joined, you have them in your contacts"), lose confidence in the app.
- **Regulatory and store exposure.** Transparency failures sit under GDPR / UK GDPR Articles 5(1)(a), 12 and 13; undisclosed sharing with third parties breaches Google Play's User Data policy and Apple guideline 5.1.2 (see [legal and store requirements](#android-and-ios-legal-and-store-requirements)). Your severity score does not measure that regulatory risk; the client's legal team does.

## Mitigations

- **Explain at the point of action.** Show the data affected (including metadata), the recipient or audience, the persistence and the consequences, in the screen or sheet where the user triggers the action, not only in the policy.
- **Let the user review and limit.** Preview selected items, let the user remove items, strip metadata, choose the audience, and decline. Use platform pickers so the app receives only what is selected ([MASWE-0069](/mobile/maswe-0069-non-privacy-preserving-functionality/)).
- **Identify the requester.** Before answering another party's request, name who asks, what they ask for and where the data will go, and offer approve, limit and decline.
- **Confirm high-impact, hard-to-reverse actions.** Public visibility, bulk uploads, sharing with third parties, irreversible exports.
- **Make the resulting state visible and reversible.** A persistent indicator for ongoing sharing, an entry in settings that lists active shares and connected services, undo where practical, and expiry for live sharing.
- **Keep the notice true.** Test in CI or release QA that the traffic of each action matches its notice (GT-PRIV-0070-3), and update the notice and the store declarations when the feature changes.

## Background

There is no OWASP Knowledge item for this weakness. This section explains what to look for and why.

### Android and iOS: What counts as a privacy-relevant action

A privacy-relevant action is any step after which personal data sits somewhere new, with someone new, or in a new state of visibility. In mobile apps the usual ones are:

| Action | What is disclosed | Typical hidden scope |
|---|---|---|
| **Sharing location with contacts** (live location, check-in, "find my family") | Precise position, often continuously | Duration, update frequency, whether history is kept server-side, whether recipients see the address |
| **Making a profile or post public** | Profile fields, content, follower lists | Search-engine indexing, discoverability by phone number or email, visibility of old posts |
| **Uploading contacts for friend-finding** | The whole address book: names, numbers, emails, sometimes notes and birthdays | Data about people who never used the app, retention after the match, use for invitations or "people you may know" |
| **Enabling cloud backup or sync** | Messages, media, documents, health data | Who holds the keys (end-to-end or provider-readable), retention, region, third-party storage |
| **Sending data to an AI or LLM feature** | Prompt plus context: open document, chat history, images, voice | Third-party model provider, retention, use for training, human review |
| **Connecting a third-party account** (OAuth, account link, data import) | Data pulled from or pushed to the other service | Scopes requested, ongoing versus one-off access, what the partner receives about the user |
| **Granting a runtime permission** | Access to a sensor or data store | What the app then does with it; covered with the rationale requirement in [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/) |
| **Exporting or moving data out of private storage** | Files to shared storage, the share sheet, the clipboard | Readable by other apps; see [MASWE-0030](/mobile/maswe-0030-improper-use-of-the-clipboard/) and the [STORAGE hub](/mobile/masvs-storage-1-secure-storage-guide/) |
| **Answering another party's request** | Whatever the requester asked for | Who the requester is, whether a subset can be sent |

Two dimensions make an action more consequential and raise the bar for the notice: **audience** (one named person, a group, all users, the public internet, a company) and **reversibility** (a live share that can be stopped, a post that can be deleted, a contact upload that cannot be recalled from someone else's server, a training data set that cannot be untrained).

### Android and iOS: Just-in-time notices versus buried settings

Data protection guidance distinguishes between information that is always available (the privacy policy, a "privacy" settings page) and information pushed to the user at the moment it matters. The Article 29 Working Party's *Guidelines on transparency* (WP260 rev.01, endorsed by the EDPB) recommend a layered approach and specifically name **just-in-time notices** for apps: short, contextual information shown when data is about to be collected or used. GDPR Article 12 asks for information in a concise, transparent, intelligible and easily accessible form, in clear and plain language; a sentence in paragraph 14 of a policy does not tell a user what the "Find friends" button does.

A good just-in-time notice answers five questions in a few lines:

1. **What**: which data, including metadata ("your contacts' names, phone numbers and email addresses").
2. **Who**: the audience or recipient ("our servers, to find people you know"; "anyone on the internet"; "a third-party AI provider", named in the real app).
3. **How long and how widely**: retention, indexing, forwarding.
4. **Choices**: select a subset, change the audience, decline and still use the rest of the app.
5. **Undo**: how to stop or reverse it, and where the state is shown later.

A notice is **not** adequate when it is shown only once at onboarding for an action performed much later, sits behind a "learn more" link with the button already primed, is worded to minimise ("Improve your experience"), or appears after the data has already left the device. The last one is common and is what GT-PRIV-0070-3 checks: the contacts are uploaded when the screen opens, and the dialog only asks whether to send invitations.

### Android and iOS: What the platform shows, and what it cannot

Both platforms add system-level awareness for sensor and data access. Know what each covers, so you neither credit the app for platform behaviour nor report the platform's limits as app findings.

**Android**

- **Microphone and camera indicators** (Android 12): a green indicator in the status bar while an app uses the camera or microphone, with the app's name in Quick Settings, and system-wide toggles to block camera and microphone access.
- **Privacy dashboard** (Android 12, *Settings > Security & privacy > Privacy > Privacy dashboard*; the path varies by version and manufacturer): a 24-hour timeline of which apps used location, camera and microphone. Android 12 also lets apps attribute access to a feature with `AttributionSource` / `createAttributionContext()` so the dashboard can say why; the per-permission detail screen can show an app-provided rationale page if the app declares an activity for the `android.intent.action.VIEW_PERMISSION_USAGE_FOR_PERIOD` intent.
- **Location in the background**: an app that uses location while not visible needs a foreground service of type `location` on recent versions, which means a persistent notification. That notification is the user's only cue; its text should say that sharing is active and with whom.
- **Clipboard access toast** (Android 12): a message when an app reads clipboard content another app wrote.
- **Data sharing updates** (Android 14): the system can tell users when an app's Data safety declaration for location sharing changes. It reflects the declaration, not what the app actually sends.

**iOS**

- **Recording indicators** (iOS 14): an orange dot for microphone use and a green dot for camera use, with the app named in Control Center.
- **App Privacy Report** (iOS 15.2, *Settings > Privacy & Security > App Privacy Report*, once switched on): seven days of data and sensor access per app (location, photos, camera, microphone, contacts) and the domains each app contacted. You can export it as an `.ndjson` file, which is useful evidence in GT-PRIV-0070-3.
- **Background location indicator**: `CLLocationManager.showsBackgroundLocationIndicator` shows the blue status-bar pill while an app with "Always" authorisation uses location in the background. For a live-sharing feature, turning it on is a cheap feedback mechanism.
- **Paste notifications** (iOS 14) and the paste permission prompt (iOS 16).
- **Share sheet options**: when sharing photos through the system share sheet, *Options* lets the user leave out location data. That control exists only in the system sheet; an in-app uploader that reads assets directly must strip metadata itself.

What none of these do: say where data went after the app read it, whether it was uploaded, to whom, or who can see it now. The platform knows that an app read the contacts; only the app can say that it uploaded them, kept them for 30 days and used them to suggest the user to strangers. That gap is this weakness.

### Android and iOS: Requests from another party

OWASP explicitly includes "responding to a request from another party". On mobile this shows up as:

- **Person-to-person requests**: "Alex wants to see your location", "Sam asked for your contact card". The prompt should name the requester, the data, the duration, and offer once / for a period / decline.
- **Account linking and data import** (OAuth or proprietary): the consent screen of the other service shows what the app gets; the app itself must show what the other service gets back, if anything, and whether the link is ongoing.
- **Wallet presentations** (the EUDIW profile): a relying party asks a digital identity wallet for attributes. The wallet should identify the relying party, list each requested attribute, support selective disclosure (send the "over 18" attribute, not the date of birth), and keep a log of presentations. Check the current EUDI Wallet Architecture and Reference Framework for the exact requirements your client is held to.
- **App-to-app requests**: content providers, intents, URL schemes and app extensions that return the user's data to a calling app. Access control is a PLATFORM topic ([MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/), [MASWE-0032](/mobile/maswe-0032-insecure-intents/)); this note asks whether the user saw and approved it when the data is personal.

### Android and iOS: Deceptive design patterns

A notice can be technically present and still fail, because the design steers the user away from understanding or from the less exposing choice. Two references are useful as checklists, because both name and illustrate patterns:

- **EDPB Guidelines 03/2022 on deceptive design patterns in social media platform interfaces** (version 2.0, adopted in February 2023) group them into six categories: *Overloading* (too many requests, options or information), *Skipping* (designs that make users forget or not think about data protection), *Stirring* (emotional or visual steering), *Obstructing* (making the privacy-protective path hard or impossible), *Fickle* (inconsistent, unclear interfaces) and *Left in the dark* (hidden or contradictory information). The guidelines target social media but the patterns apply to any app.
- **US FTC staff report *Bringing Dark Patterns to Light*** (September 2022) catalogues common patterns and concentrates on four tactics: misleading consumers and disguising ads, making it hard to cancel, burying key terms and fees, and tricking consumers into sharing data, including interfaces that obscure or subvert privacy choices.

Patterns we see most in this weakness: a bright "Continue" and a grey "Not now" link where "Continue" uploads contacts (*Stirring*); a share flow where the audience selector is two screens deep (*Left in the dark*); a "Make my profile discoverable" switch explained as "Help friends find you" with no mention of phone-number lookup (*Skipping*); and repeated prompts after the user declined (*Overloading*). Record the pattern by name in the finding; it helps the client's designers more than "the dialog is unclear".

### Android and iOS: Legal and store requirements

*This is technical testing guidance, not legal advice. Hand the evidence to the client's DPO or legal team for the legal assessment.*

- **GDPR / UK GDPR.** Article 5(1)(a) (lawfulness, fairness and transparency), Article 12 (concise, intelligible, easily accessible information in clear and plain language) and Article 13 (information at the time personal data is obtained: purposes, recipients or categories of recipients, retention, transfers). Data about third parties, such as uploaded contacts, also triggers Article 14 obligations towards those people. The ICO's guidance on the right to be informed applies the same in the UK.
- **Google Play.** The User Data policy requires a **prominent in-app disclosure** when an app collects or shares personal and sensitive data in ways users might not reasonably expect: shown during normal use, not only in the privacy policy or terms; describing the data and how it is used and shared; followed by a request for affirmative consent. Contacts, location and other sensitive data shared beyond the core feature are the typical triggers.
- **Apple App Store Review Guidelines 5.1.2.** 5.1.2(i) requires apps to *"clearly disclose where personal data will be shared with third parties, including with third-party AI, and obtain explicit permission before doing so"*. 5.1.2(iv) prohibits building a contact database from Contacts or Photos data; 5.1.2(v) prohibits contacting people from a user's Contacts or Photos except at the user's explicit, individual initiative, and requires *"a clear description of how the message will appear to the recipient before sending it"*. All three map directly onto the actions in this note.
- **EU Digital Services Act**, Article 25, prohibits online platforms from designing interfaces that deceive or manipulate users; it applies to services that qualify as online platforms.
- **CCPA / CPRA.** The California definition of consent excludes agreement obtained through dark patterns, and the CPPA regulations set requirements for symmetry in choice and easy-to-understand language.

## Tests

The three tests build on each other: GT-PRIV-0070-1 produces the list of actions, GT-PRIV-0070-2 reviews the notice at each one, GT-PRIV-0070-3 checks that the traffic matches. Run them on both platforms: Android and iOS versions of the same app often have different flows, and a notice present on one platform and missing on the other is a common finding.

### GT-PRIV-0070-1: Privacy-relevant action inventory (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Build a complete list of the actions in the app that disclose personal data to a new recipient, audience or location, with their scope. Without the inventory, the review covers only the flows the client thought about.

#### Prerequisites

- The release build on an Android and an iOS test device you control, signed in with a test account. A **second test account**, not connected to the first, to see what other users see, and a logged-out browser for public visibility.
- Synthetic test data on the device: a handful of contacts (names with `example.com` emails and UK drama numbers such as `+44 7700 900123`), photos you took with location tagging on, a calendar entry. Never use real people's data.
- The decompiled app (jadx output for Android; class dump or `strings` output for iOS) and the proxy set-up from our [traffic interception lab](/mobile/mobile-traffic-interception-lab/).

#### Steps

1. **Walk every feature.** Use each screen and menu on both platforms, including settings, onboarding, invite flows, sharing, export, backup, integrations, AI features and anything behind a paid tier the client enabled for you. Screen-record the walk:

   ```bash
   adb shell screenrecord /sdcard/walk-01.mp4      # stop with Ctrl+C, max 3 min per file
   adb pull /sdcard/walk-01.mp4
   ```

   On iOS, use the Control Center screen recording or QuickTime Player with the device connected.
2. **Search the code for disclosing APIs** to catch flows the UI hides. On Android (jadx output):

   ```bash
   grep -rnE 'ACTION_SEND(_MULTIPLE)?|createChooser|ContactsContract|MediaStore\.(Images|Video|Files)|ACTION_CREATE_DOCUMENT|ClipboardManager|setPrimaryClip|BackupAgent|requestLocationUpdates|FusedLocationProviderClient|AccountManager' out/sources/ | grep -v '/androidx/\|/kotlin/' | cut -c1-200
   ```

   On iOS, list the frameworks and symbols in the main binary:

   ```bash
   otool -L Payload/App.app/App | grep -E 'Contacts|Photos|CoreLocation|CloudKit|LinkPresentation|AuthenticationServices'
   rabin2 -zz Payload/App.app/App | grep -E 'CNContactStore|UIActivityViewController|PHAsset|NSUbiquitous|CKContainer|UIPasteboard|ASWebAuthenticationSession' | head -50
   ```

3. **List server-side features from traffic.** Exercise the app through the proxy and note endpoints whose names suggest disclosure (`share`, `visibility`, `public`, `invite`, `contacts`, `sync`, `backup`, `export`, `link`, `connect`, `assistant`, `summarize`). Each is a candidate action.
4. **Check requests from another party.** From the second account, request everything the app lets one user request from another (location, contact card, documents, follow/friend requests that reveal data). Note what the first account sees.
5. **Record each action** in a table with these columns: trigger (user tap, implicit, another party), data elements, metadata, destination (own server, third party, other users, public), audience, persistence, reversibility, platform(s). Add the sensitivity of the data (location, contacts, health, children's data, financial).
6. **Cross-check with declarations.** Compare the list with the privacy policy, the Data safety section and the App Privacy details. An action missing from the declarations is a lead for [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) and [MASWE-0072](/mobile/maswe-0072-inadequate-privacy-policy/).

#### Observation

The action inventory, with evidence for each row (screen recording timestamp, code location or endpoint), and the list of actions found only in code or traffic but not in the UI walk.

#### Evaluation

This test produces the scope for GT-PRIV-0070-2 and -3; on its own it **fails** only when it finds a disclosure that has **no user-facing trigger at all**: data leaves the device or changes visibility as a side effect (contacts uploaded at login, location shared because a group was joined, a draft sent to an AI service when the screen opens). Report those directly. Everything else passes to the next test.

#### Demo

Illustrative excerpt from an inventory:

```text
No Action                       Trigger        Data / metadata                       Destination / audience        Persist  Reversible
1  Find friends                 tap            all contacts: name, phones, emails    own API, then other users     server   no (others' data)
2  Share live location          tap            precise location every 30 s           selected contacts             1 h      yes (stop)
3  Post photo                   tap            image + EXIF GPS, device model        followers (default: public)   server   delete post
4  Summarise chat (AI)          tap            last 200 messages, names              third-party model provider    unknown  no
5  Contact requests location    other party    precise location                      requester                     once     n/a
6  Login                        implicit       contacts hash list                    own API                       server   no   <- no UI trigger
```

Row 6 is a direct finding; rows 1 to 5 go to GT-PRIV-0070-2.

### GT-PRIV-0070-2: Just-in-time notice review per action (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

For each action from the inventory, check what the user is told and offered at the point of action, against fixed criteria, so that the result is reproducible and not a matter of taste.

#### Prerequisites

- The inventory from GT-PRIV-0070-1.
- Fresh state for first-use flows: reinstall or clear data (`adb shell pm clear com.example.app`; on iOS delete and reinstall) so you see the notices a new user sees, not the "don't show again" state.

#### Steps

1. **Trigger each action** on both platforms and capture every screen from the first tap to the completed action, including any dialog, sheet, tooltip and the confirmation after.
2. **Score the notice** against these criteria. Each is yes, partial or no:

   | # | Criterion | What "yes" looks like |
   |---|---|---|
   | C1 | Data stated | Names the data elements, including metadata ("photo and its location") |
   | C2 | Recipient / audience stated | Names who receives it: the company, a named third party, specific contacts, the public |
   | C3 | Consequences stated | Persistence, indexing, forwarding, use for other purposes (AI training, suggestions to others) |
   | C4 | Shown before the data leaves | The notice and the choice come before the disclosure, not after |
   | C5 | Review and limit | Preview of selected items, deselect, strip metadata, choose audience |
   | C6 | Real choice | Decline is as easy as accept; the rest of the app works after declining |
   | C7 | Confirmation proportionate to impact | Explicit confirmation for public, bulk, third-party or irreversible actions |
   | C8 | Resulting state visible | Indicator for ongoing sharing; settings entry listing active shares and connected services |
   | C9 | Reversible where practical | Stop, undo, delete, disconnect; expiry for live sharing |
   | C10 | No deceptive pattern | None of the EDPB categories (Overloading, Skipping, Stirring, Obstructing, Fickle, Left in the dark) |

3. **Check the reversal path.** Stop the share, make the profile private, disconnect the account, delete the upload; note how many steps it takes compared with turning it on, and whether the reversal really takes effect (see GT-PRIV-0070-3).
4. **Compare platforms.** Note any criterion met on one platform and not on the other.
5. **Check the notice text against the policy and declarations.** A notice that says "we never share your contacts" while the policy lists a "people you may know" use is a contradiction to report.

#### Observation

A score table per action and platform, with screenshots for every "partial" or "no".

#### Evaluation

The test **fails** for an action when C1, C2 or C4 is "no" (the user cannot know what goes to whom before it goes), when C7 is "no" for a public, bulk, third-party or irreversible disclosure, when C8 is "no" for an ongoing disclosure such as live location, or when C10 finds a pattern that steers the user to the more exposing choice. "Partial" scores on the other criteria are lower-severity findings or recommendations. It **passes** when every high-impact action meets C1 to C9 and no deceptive pattern is present. Platform system prompts (permission dialogs, ATT) do not satisfy C1 to C3 on their own: they say what the app may access, not what it will do with it.

#### Demo

Non-compliant: the friend-finding screen. The illustrative code below uploads the address book in `onCreate`, before the user does anything, and the only dialog asks about invitations:

```kotlin
class FindFriendsActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Data leaves before any notice (fails C1, C2, C4)
        lifecycleScope.launch { api.uploadContacts(contactsRepo.readAll()) }
        AlertDialog.Builder(this)
            .setMessage("Invite your friends to join!")
            .setPositiveButton("Continue") { _, _ -> api.sendInvites() }
            .show()
    }
}
```

Compliant pattern: explain first, let the user choose, upload only the selection, and say where it goes:

```kotlin
private val pickContact = registerForActivityResult(ActivityResultContracts.PickContact()) { uri ->
    uri?.let { viewModel.matchSingleContact(it) }   // only the chosen contact, no READ_CONTACTS needed
}

private fun showFindFriendsNotice() {
    MaterialAlertDialogBuilder(this)
        .setTitle("Find friends from your contacts")
        .setMessage(
            "We send the phone numbers and email addresses of the contacts you select to our " +
            "servers to check who uses the app. We delete them after matching and never send " +
            "messages without asking you. You can choose contacts one by one."
        )
        .setPositiveButton("Choose contacts") { _, _ -> pickContact.launch(null) }
        .setNegativeButton("Not now", null)
        .show()
}
```

Illustrative score line for the non-compliant build: `Find friends | Android | C1 no | C2 no | C4 no | C5 no | C6 partial | C7 no | ... | FAIL`.

### GT-PRIV-0070-3: Disclosure matches the notice in traffic (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

A notice is only as good as its accuracy. This test captures the app's own traffic for each action and checks four things: the data sent is what the notice says, nothing is sent before the user confirms, nothing is sent after the user declines or cancels, and stopping or reversing really stops the disclosure. It also checks metadata in uploaded files.

#### Prerequisites

- Proxy interception of the app's own traffic on both platforms (see the [traffic interception lab](/mobile/mobile-traffic-interception-lab/); if the app pins certificates, use a test build without pinning from the client or the bypass described in the [NETWORK hub](/mobile/masvs-network-secure-communication-guide/)).
- Your test accounts and synthetic data only. Do not capture or keep data about real users that may appear in responses; note its presence and discard it.
- Optional: a rooted Android or jailbroken iOS test device with Frida for API traces; iOS App Privacy Report switched on.

#### Steps

1. **Log field names and list sizes per request.** A small mitmproxy addon prints, for each JSON request, the field paths and the length of each array, so you can see "347 contacts sent" at a glance without reading every value:

   ```python
   # fields_per_request.py  -  usage: mitmdump -q -s fields_per_request.py
   import json
   from mitmproxy import http

   def walk(obj, path, out):
       if isinstance(obj, dict):
           for key, value in obj.items():
               walk(value, f"{path}.{key}" if path else key, out)
       elif isinstance(obj, list):
           out[path + "[]"] = f"list of {len(obj)}"
           if obj:
               walk(obj[0], path + "[]", out)
       else:
           out.setdefault(path, type(obj).__name__)

   def request(flow: http.HTTPFlow) -> None:
       if "json" not in flow.request.headers.get("content-type", ""):
           return
       try:
           body = json.loads(flow.request.get_text() or "null")
       except ValueError:
           return
       out = {}
       walk(body, "", out)
       print(f"{flow.request.method} {flow.request.pretty_url}")
       for path, kind in sorted(out.items()):
           print(f"    {path}: {kind}")
   ```

2. **Before confirmation.** Open each action's screen and stop at the notice. Any request carrying the action's data at this point fails C4 regardless of what the notice says. Also check when the app read the data:

   ```bash
   adb shell cmd appops get com.example.app READ_CONTACTS     # shows time of last access
   adb shell cmd appops get com.example.app FINE_LOCATION
   ```

   On iOS, the App Privacy Report shows when the app last accessed Contacts, Photos or Location; export it with the share button at the bottom of the report and look for access timestamps before your confirmation tap.
3. **After confirmation.** Compare the captured fields with the notice. Typical mismatches: all contacts instead of the selected ones; every field of a contact card (notes, birthdays, addresses) when the notice says "phone numbers"; device identifiers or location attached to an AI request; the precise location sent when the notice says "your city".
4. **After decline or cancel.** Repeat with "Not now" and with the back button; there should be no disclosure.
5. **Metadata in files.** Post a photo you took with location tagging on, then download it as the second test account (or from the public link) and inspect it:

   ```bash
   exiftool -a -G1 -GPS:all -Make -Model -DateTimeOriginal shared.jpg
   ```

   Also inspect the upload request body itself (save it from Burp or mitmproxy): some apps strip metadata on the server, so the provider still receives the location even though other users do not. The notice should match whichever is true.
6. **Third parties.** Note any request to a host that is not the app's own backend during the action (AI providers, analytics with event parameters that contain the content, attribution SDKs). The [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) note covers how to attribute SDK traffic.
7. **Reversal.** Stop live sharing, switch the profile to private or disconnect the integration, then check that location updates stop (traffic and `cmd appops`), that the second account and the logged-out browser no longer see the data, and that a connected service's token is revoked.
8. **Optional API trace** on rooted or jailbroken test devices, to tie reads to UI events:

   ```bash
   frida-trace -U -f com.example.app -j 'android.content.ContentResolver!query'
   frida-trace -U -f com.example.app -m '-[CNContactStore enumerateContactsWithFetchRequest:error:usingBlock:]'
   ```

#### Observation

For each action: the requests before confirmation, after confirmation, after decline and after reversal; the field paths and list sizes; EXIF results; third-party hosts contacted; appops or App Privacy Report timestamps.

#### Evaluation

The test **fails** when data is sent before the user confirms or after the user declines, when the content sent is broader than the notice (more records, more fields, metadata not mentioned, more recipients), when an undeclared third party receives it, or when reversal does not stop the disclosure. It **passes** when every captured disclosure is covered by the notice shown before it and stops when the user reverses it.

Common false positives: a request that sends only a count or a feature flag when the screen opens; contact matching that uses hashes *and* the notice says so (hashed phone numbers are still personal data and easy to reverse, see [MASWE-0067](/mobile/maswe-0067-lack-of-anonymization-or-pseudonymisation/), but the transparency question is whether the notice is accurate); EXIF on the original kept only in the user's own private storage.

#### Demo

Illustrative output from the addon for the non-compliant friend-finding screen, captured before any tap:

```text
POST https://api.example.com/v2/contacts/upload
    contacts[]: list of 12
    contacts[].emails[]: list of 1
    contacts[].emails[]: str
    contacts[].name: str
    contacts[].note: str
    contacts[].phones[]: list of 2
    contacts[].phones[]: str
    device.locale: str
```

The upload happens before the notice, carries all 12 synthetic contacts, and includes the `note` field. That is three findings: C4 failed, scope broader than any selection, and a field the user would not expect. For the compliant build, the same capture shows nothing until the user picks a contact, then `contacts[]: list of 1` with phone and email only.

## Secure implementation

No OWASP best practice exists for this weakness; ours:

- **Pattern for every disclosing action:** notice (what, who, how long) → choice (select, limit, decline) → confirmation proportionate to impact → action → visible state → reversal. Put the notice text under change control next to the code that performs the action, so a change to one prompts a review of the other.
- **Use platform pickers and share sheets** where they fit: Android `ActivityResultContracts.PickContact`, the photo picker (`PickVisualMedia`), the Storage Access Framework; iOS `CNContactPickerViewController`, `PHPickerViewController`, `UIActivityViewController`. The app receives only what the user selects, and the system UI already shows the user what is being shared. On iOS 18 and later, design for limited contacts access.
- **Strip metadata before upload** unless the feature needs it and the notice says so. On Android, re-encode images or remove EXIF tags with `androidx.exifinterface.media.ExifInterface`; reading the original location also requires `ACCESS_MEDIA_LOCATION` since Android 10, so do not request it without need. On iOS, re-encode with ImageIO and drop the GPS dictionary (`kCGImagePropertyGPSDictionary`).
- **Live sharing:** default expiry, a persistent in-app banner, an ongoing notification (required anyway for a location foreground service on Android), `showsBackgroundLocationIndicator = true` on iOS, and a one-tap stop from the notification.
- **AI features:** state the provider, what context is sent (the message, the chat, the document), retention and training use, before the first request; let users exclude conversations; get explicit permission before sharing personal data with a third-party AI provider, as Apple 5.1.2(i) now requires.
- **Requests from other parties:** a sheet naming the requester, the data and the duration, with approve, limit and decline; a log of what was shared with whom.
- **Contacts:** no "select all", no preselected contacts (Apple 5.1.2(v)); show the invitation text and sender before sending.
- **Regression test:** keep the GT-PRIV-0070-3 capture as an automated check in release QA (UI test plus proxy), failing when a disclosing request occurs before the confirmation tap.

## Rating findings

Apply the series-wide rule: rate by what personal data is disclosed beyond what the user was told, how sensitive it is, scale and reversibility, and whether the behaviour contradicts the app's own declarations or store policy. Regulatory risk is for the client's legal team; your severity describes the technical and privacy impact.

| Rating | Conditions |
|---|---|
| **High** | Sensitive data (precise location, contacts, health, children's data, financial, private messages) disclosed to a third party or the public with no notice before it leaves the device, or contrary to the notice; whole address book uploaded silently or before the notice; content sent to a third-party AI provider without disclosure and permission; live location sharing with no visible indication that it is active; a disclosure that continues after the user stops it. |
| **Medium** | Notice present but missing the recipient, audience or material consequence for a sensitive action (for example "Share" that makes a post public and indexed without saying so); EXIF location published to other users without notice; bulk action without review or selection; another party's request answered without showing what is sent; a deceptive pattern that steers users to the more exposing option. |
| **Low** | Notice present but only partly specific for low-sensitivity data; reversal possible but hard to find; platform parity gaps where the weaker platform still states recipient and data. |
| **Info** | Wording improvements, missing confirmation for low-impact reversible actions, recommendations to add indicators or logs where the state is already visible elsewhere. |

Raise a level for apps aimed at children or vulnerable users, and when the disclosure contradicts the Data safety section, App Privacy details or Apple 5.1.2 (store removal risk). Lower a level when the disclosure goes only to the user's own other devices or to a recipient the user named individually and the data is not sensitive.

In the report give the action, the platform and version, the screens shown (or not shown) before the disclosure, the score from GT-PRIV-0070-2, the captured request with field paths and list sizes (values redacted), the recipients, how to reverse it, and the fix pattern from [Secure implementation](#secure-implementation). Point to [MASWE-0071](/mobile/maswe-0071-inadequate-privacy-defaults/) when the root cause is a preselected option rather than a missing notice.

## References

- OWASP MASWE: [MASWE-0070: Inadequate Awareness for Privacy Relevant Actions](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0070/); related [MASWE-0071](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0071/), [MASWE-0078](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0078/), [MASWE-0077](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0077/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PRIVACY-2](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-2/), [MASVS-PRIVACY-3](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/), [MASVS-PRIVACY-4](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-4/) (CC BY-SA 4.0)
- Series: [MASVS-PRIVACY hub](/mobile/masvs-privacy-privacy-testing-guide/), [MASWE-0071 privacy defaults](/mobile/maswe-0071-inadequate-privacy-defaults/), [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/), [MASWE-0067](/mobile/maswe-0067-lack-of-anonymization-or-pseudonymisation/), [MASWE-0069](/mobile/maswe-0069-non-privacy-preserving-functionality/), [MASWE-0072](/mobile/maswe-0072-inadequate-privacy-policy/), [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/), [MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/), [MASWE-0077](/mobile/maswe-0077-inadequate-data-visibility-controls/), [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/); other notes: [MASWE-0030](/mobile/maswe-0030-improper-use-of-the-clipboard/), [MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/), [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/), [MASWE-0032](/mobile/maswe-0032-insecure-intents/), [traffic interception lab](/mobile/mobile-traffic-interception-lab/), [STORAGE hub](/mobile/masvs-storage-1-secure-storage-guide/), [NETWORK hub](/mobile/masvs-network-secure-communication-guide/)
- Law and regulators: [GDPR (Regulation (EU) 2016/679), EUR-Lex](https://eur-lex.europa.eu/eli/reg/2016/679/oj), [UK GDPR Article 13, legislation.gov.uk](https://www.legislation.gov.uk/eur/2016/679/article/13), [ICO: The right to be informed](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/the-right-to-be-informed/), [Article 29 WP Guidelines on transparency (WP260 rev.01)](https://ec.europa.eu/newsroom/article29/items/622227), [EDPB Guidelines 03/2022 on deceptive design patterns in social media platform interfaces](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-032022-deceptive-design-patterns-social-media_en), [FTC: Bringing Dark Patterns to Light (2022)](https://www.ftc.gov/reports/bringing-dark-patterns-light), [Digital Services Act (Regulation (EU) 2022/2065)](https://eur-lex.europa.eu/eli/reg/2022/2065/oj)
- Stores: [Google Play User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311), [Google Play Data safety section](https://support.google.com/googleplay/android-developer/answer/10787469), [Apple App Store Review Guidelines (5.1.1, 5.1.2)](https://developer.apple.com/app-store/review/guidelines/)
- Android: [Android 12 features (privacy dashboard, indicators)](https://developer.android.com/about/versions/12/features), [Android 12 behaviour changes](https://developer.android.com/about/versions/12/behavior-changes-all), [Data access auditing](https://developer.android.com/guide/topics/data/audit-access), [Photo picker](https://developer.android.com/training/data-storage/shared/photo-picker), [Location permissions](https://developer.android.com/develop/sensors-and-location/location/permissions)
- Apple: [Inspecting app activity data (App Privacy Report)](https://developer.apple.com/documentation/network/inspecting-app-activity-data), [`showsBackgroundLocationIndicator`](https://developer.apple.com/documentation/corelocation/cllocationmanager/showsbackgroundlocationindicator), [`CNContactPickerViewController`](https://developer.apple.com/documentation/contactsui/cncontactpickerviewcontroller), [`PHPickerViewController`](https://developer.apple.com/documentation/photokit/phpickerviewcontroller)
- Tools: [mitmproxy addons](https://docs.mitmproxy.org/stable/addons/overview/), [ExifTool](https://exiftool.org/), [frida-trace](https://frida.re/docs/frida-trace/)
- CWE: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
