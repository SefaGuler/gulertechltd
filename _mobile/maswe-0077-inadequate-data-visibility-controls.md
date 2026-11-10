---
title: "MASWE-0077: Inadequate Data Visibility Controls"
date: 2026-11-10 22:11:00 +0000
subcategory: privacy
summary: "Testing who else can see a user's data: visibility settings, server-side enforcement, contact discovery and location metadata in shared photos."
refs: [MASWE-0077, MASVS-PRIVACY-4, CWE-359]
tags: [android, ios, masvs-privacy, data-visibility, authorisation, metadata]
---

This note is part of our [MASVS-PRIVACY guide](/mobile/masvs-privacy-privacy-testing-guide/) and covers OWASP [MASWE-0077](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0077/): an app that does not give users enough control over what *other people* can see about them. The audience here is not the app's developer or its SDKs (that is the rest of this series) but other users, contacts, anyone with a shared link, and the environment the phone sits in: the lock screen, the share sheet, the photo you just posted with your home's coordinates in it. Typical examples are an email address or date of birth shown on a public profile with no way to hide it, "last seen" and read receipts that cannot be turned off, discoverability by phone number that cannot be disabled, and live location shared more precisely or for longer than the user meant. There is also a security half to this weakness that privacy reviews often miss: a visibility setting that only hides a field in the app's UI, while the API still returns it to everyone, is not a control at all. OWASP has no tests or Knowledge items for MASWE-0077, so below are the background, four Guler Tech tests (an inventory of the controls, server-side enforcement with two test accounts, contact discovery and enumeration, and metadata in shared content), the implementation we recommend and how we rate findings.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Both platforms: what visibility covers](#both-platforms-what-visibility-covers)
  - [Both platforms: audiences and defaults](#both-platforms-audiences-and-defaults)
  - [Both platforms: the server enforces visibility, not the app](#both-platforms-the-server-enforces-visibility-not-the-app)
  - [Both platforms: location sharing granularity and duration](#both-platforms-location-sharing-granularity-and-duration)
  - [Both platforms: contact discovery and enumeration](#both-platforms-contact-discovery-and-enumeration)
  - [Both platforms: presence, read receipts, activity and link previews](#both-platforms-presence-read-receipts-activity-and-link-previews)
  - [Android and iOS: metadata in shared photos and files](#android-and-ios-metadata-in-shared-photos-and-files)
  - [Android and iOS: share sheets, public links and system surfaces](#android-and-ios-share-sheets-public-links-and-system-surfaces)
- [Tests](#tests)
  - [GT-PRIV-0077-1: Visibility controls inventory (Android and iOS)](#gt-priv-0077-1-visibility-controls-inventory-android-and-ios)
  - [GT-PRIV-0077-2: Server-side enforcement of visibility with two test accounts (Android and iOS)](#gt-priv-0077-2-server-side-enforcement-of-visibility-with-two-test-accounts-android-and-ios)
  - [GT-PRIV-0077-3: Contact discovery and enumeration resistance (Android and iOS)](#gt-priv-0077-3-contact-discovery-and-enumeration-resistance-android-and-ios)
  - [GT-PRIV-0077-4: Metadata in shared content (Android and iOS)](#gt-priv-0077-4-metadata-in-shared-content-android-and-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app provides adequate controls over the visibility of user data."* MASWE-0077 maps to **MASVS-PRIVACY-4** ("The app offers user control over their data") and to [CWE-359](https://cwe.mitre.org/data/definitions/359.html) (Exposure of Private Personal Information to an Unauthorized Actor). It carries OWASP's **P** and **EUDIW** profiles. In the MASWE threat model it is MAS-THREAT-0077 ("apps and their users' counterparts can expose personal information beyond the user's intent"), realised by two attacks: MAS-ATTACK-0084 (profile details, activity status or discoverability visible to other users or third parties by default) and MAS-ATTACK-0087 (exporting or sharing data through flows whose privacy consequences are not evident to the user). In the earlier beta numbering it was MASWE-0114.

**OWASP has no MASTG tests, no Knowledge items and no best practices for MASWE-0077**, and there are no legacy MASVS v1 tests for it. The four tests below are ours. OWASP's references for the weakness are Firebase's guidance on [storing privacy settings](https://firebase.google.com/support/privacy/storing-privacy-settings) and the research paper [Demystifying Hidden Privacy Settings in Mobile Apps](https://www.researchgate.net/publication/335863205_Demystifying_Hidden_Privacy_Settings_in_Mobile_Apps), which found that many apps' privacy settings are hard to find; both inform the tests below.

The legal hook is GDPR Art. 25(2), data protection by default: measures must ensure that *"by default personal data are not made accessible without the individual's intervention to an indefinite number of natural persons."* This is technical testing guidance, not legal advice; whether a visibility gap breaches that provision is for the client's legal team.

What is covered, and by which test:

| Question | Test |
|---|---|
| What can other people see, which controls exist, what are the defaults, can users find them? | [GT-PRIV-0077-1](#gt-priv-0077-1-visibility-controls-inventory-android-and-ios) |
| Does the backend actually withhold what the user hid? | [GT-PRIV-0077-2](#gt-priv-0077-2-server-side-enforcement-of-visibility-with-two-test-accounts-android-and-ios) |
| Can someone find out who uses the app, or link a phone number to a profile, at scale? | [GT-PRIV-0077-3](#gt-priv-0077-3-contact-discovery-and-enumeration-resistance-android-and-ios) |
| Do photos, videos and files that users share carry location or device metadata to others? | [GT-PRIV-0077-4](#gt-priv-0077-4-metadata-in-shared-content-android-and-ios) |

Keep the neighbours apart:

| Question | Where it lives |
|---|---|
| Can the user delete, export, correct their data or opt out of processing? | [MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/) |
| Are visibility settings private by default? | [MASWE-0071](/mobile/maswe-0071-inadequate-privacy-defaults/) (the defaults rule); recorded here in the inventory |
| Is the user told, at the moment of sharing, what will be shared? | [MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/) |
| Does the app read precise location, contacts or photos at all, and is that justified? | [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/) |
| Sensitive data on screen, in notifications, screenshots, the clipboard or to accessibility services | PLATFORM: [MASWE-0036](/mobile/maswe-0036-sensitive-data-exposed-via-ui/), [MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/), [MASWE-0038](/mobile/maswe-0038-insufficient-screenshot-protection/), [MASWE-0030](/mobile/maswe-0030-improper-use-of-the-clipboard/), [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/) |

## Modes of Introduction

**No setting, or a setting that is too coarse.** One "private account" switch that hides posts but not the follower list, the profile photo, the real name or the phone number; no way to hide "last seen" without losing the ability to message.

**Public by default.** New profiles, posts, location check-ins or activity are visible to everyone until the user finds the setting.

**Hiding in the client.** The visibility flag is sent to the app, and the app decides whether to render the field; the API returns the full object regardless. The same happens in search results, follower lists, comment author objects, GraphQL types and real-time events that a different team built later.

**Discoverability that cannot be turned off.** "Find friends" by phone number or email with no opt-out, lookups that confirm whether a number is registered, and no rate limiting, so anyone can map phone numbers to profiles.

**Location shared too precisely or for too long.** Exact coordinates where a city would do, a live location share with no end time, or "distance from you" values precise enough to work out a user's position from several vantage points.

**Metadata left in shared content.** Uploaded photos served with their original EXIF, including GPS coordinates, device model and capture time; the same for videos and documents.

**Sharing flows with hidden consequences.** "Share" generates a public link with no expiry and no way to revoke it; an invite link embeds the user's phone number or email; a link preview fetched from the recipient's device reveals their IP address to the linked site.

## Impact

- **Physical safety.** Precise or live location, home coordinates in photo EXIF, and routine visible through activity status are the raw material of stalking and harassment. This is why we rate location visibility highly.
- **Contact data exposure and enumeration.** A phone number or email visible to everyone, or confirmable through discovery, feeds spam, phishing, SIM-swap targeting and doxxing; at scale it becomes a dataset that links phone numbers to names and photos.
- **Inference.** Group memberships, follows, likes and check-ins reveal sensitive characteristics (health, religion, sexuality, politics) that the user never stated.
- **Loss of trust and regulatory exposure** for the app owner, for the client to assess.
- **Security.** Where the API ignores visibility, every hidden field of every user is one request away: an excessive data exposure / broken object property level authorisation flaw ([OWASP API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)).

## Mitigations

- **Per-field and per-feature audiences** (only me, contacts or followers, everyone) for profile fields, content, location, presence, discoverability and social graph.
- **Private by default** for anything beyond what the service needs to function, as Art. 25(2) requires.
- **Enforce on the server**: build responses from the viewer's permissions, never send hidden fields to the client.
- **Make discovery opt-in or opt-out per identifier**, rate-limit lookups, and make "not found" and "found but not discoverable" look the same.
- **Coarsen location** on the server for anyone but the user, and give live sharing an end time.
- **Strip metadata** from uploaded media on the server, for every rendition, unless the user explicitly chose to share it.
- **Make sharing consequences evident**: say when a link is public, let users revoke links, keep personal data out of URLs.
- **Make the settings findable**: one privacy screen that lists every visibility control, with a preview of how the profile looks to others.

## Background

OWASP has no Knowledge items for this weakness. This section describes the visibility surfaces a mobile app usually has, the platform features that affect them, and the server-side rule that makes or breaks every one of them.

### Both platforms: what visibility covers

Use this list to build the inventory in GT-PRIV-0077-1:

| Surface | Examples | Controls users expect |
|---|---|---|
| Profile fields | Real name, username, photo, bio, email, phone, date of birth or age, gender, workplace, school, city | Per-field audience, or at least hide contact details and date of birth |
| Content | Posts, photos, reviews, playlists, workouts, routes | Per-item audience; default audience for new items |
| Social graph | Followers, following, friends, group and community memberships | Hide lists; hide membership of sensitive groups |
| Discoverability | Find me by phone number, by email, by username; appear in "people you may know"; appear in search engines | Separate switches per identifier |
| Presence and activity | Online, last seen, typing indicators, read receipts, "active now", activity feeds ("X liked Y"), viewing history ("X viewed your profile") | Per-feature switches, often reciprocal |
| Location | Check-ins, live location, location on posts, nearby users, "distance from you" | Precision, audience and duration |
| Shared content metadata | EXIF/GPS in photos, location atoms in videos, author fields in documents | Strip by default, or explicit choice |
| Outbound sharing | Public links, invite links, link previews, share sheet payloads | Clear labelling, revocation, no personal data in URLs |
| The device environment | Notifications on the lock screen, app switcher snapshots, screen sharing, clipboard | See the PLATFORM notes linked above |

### Both platforms: audiences and defaults

An audience selector is only as good as its weakest path. Things to look for in design and in testing:

- **Granularity.** "Private account" as one switch is a start, but users reasonably want their phone number usable for login and discovery by friends without it being on their public profile. Separate the identifier's *uses* (login, discovery, display) from its *visibility*.
- **Defaults.** Under Art. 25(2) and the ICO's [Age appropriate design code](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/childrens-information/childrens-code-guidance-and-resources/age-appropriate-design-a-code-of-practice-for-online-services/) for services likely to be accessed by children, the starting point is the most private option that still lets the feature work. Default settings are covered in [MASWE-0071](/mobile/maswe-0071-inadequate-privacy-defaults/); here you record them as part of the inventory.
- **Changes apply backwards.** Switching from "everyone" to "followers" should apply to existing content, or the app should say clearly that it does not.
- **Findability.** The settings research OWASP cites found privacy settings buried several levels deep and labelled inconsistently. A setting that users cannot find does not give them control. Record the path to each one.
- **Reciprocity is a design choice, not an excuse.** Many apps make read receipts and last seen reciprocal (if you hide yours, you cannot see others'). That is fine as long as the user can hide their own.
- **Blocking.** A blocked user should lose access to everything not public, and ideally to the profile altogether; check that blocking applies to search, discovery and real-time presence too.

### Both platforms: the server enforces visibility, not the app

A mobile client is under the user's control: anyone can read its traffic with a proxy, call its API directly, or modify it. Any data the server sends to the app should therefore be treated as visible to the person holding the phone. That makes client-side hiding (the API returns `"email": "..."` and the app chooses not to show it) equivalent to publishing the field.

The server must decide, per request, *who is asking* and *what they are allowed to see*, and build the response from that. In the [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) this is **API3: Broken Object Property Level Authorization** (which absorbed the 2019 "excessive data exposure" category); where whole objects leak (another user's private post by ID), it is **API1: Broken Object Level Authorization**. Visibility leaks tend to hide in places other than the main profile endpoint:

- **Embedded objects.** The comment author, the message sender, the follower list entry, the "people you may know" card: each is a user object, often serialised by the same full serialiser.
- **Search and suggestions** endpoints written for speed, returning index documents directly.
- **GraphQL.** Field-level authorisation must be on the field resolvers; a client that never asks for `phoneNumber` does not stop someone else asking.
- **Real-time channels.** WebSocket or MQTT presence events, typing indicators and read receipts delivered to the client regardless of the user's settings.
- **Push payloads** that include the full object for the notification extension to render.
- **Caches and CDNs** that store a response built for one viewer and serve it to another, and old values that persist after a setting changed.

Testing this needs two accounts you control, which is the core of [GT-PRIV-0077-2](#gt-priv-0077-2-server-side-enforcement-of-visibility-with-two-test-accounts-android-and-ios).

### Both platforms: location sharing granularity and duration

The operating systems already offer the user a precision choice for what the *app* gets:

- **Android**: `ACCESS_COARSE_LOCATION` (approximate) and `ACCESS_FINE_LOCATION` (precise). From Android 12, when an app targeting API 31 or higher asks for fine location the user can choose approximate instead; background access (`ACCESS_BACKGROUND_LOCATION`, Android 10+) is a separate grant. See [location permissions](https://developer.android.com/training/location/permissions).
- **iOS**: from iOS 14 the user can switch off *Precise Location* per app (`CLLocationManager.accuracyAuthorization` returns `.reducedAccuracy`); apps can declare `NSLocationDefaultAccuracyReduced` to ask for approximate location by default, and request temporary full accuracy with a purpose string.

Those controls govern the app. Visibility to **other users** is the app's own responsibility, and the questions are:

- **Precision for others.** Does the profile or post show a city or neighbourhood, or the raw coordinates? Rounding in the client is not enough; the server should store or at least serve only the coarse value to other users.
- **Distance features.** "2.3 km away" shown to anyone, updated live and computed from exact coordinates lets an observer narrow down a user's position by checking from several places. Coarse distance bands and server-side snapping of the user's position to a grid before computing distances are the usual mitigations.
- **Duration.** Live location sharing should have an end time chosen at the start (for example 15 minutes, 1 hour, 8 hours), an obvious "stop sharing" control, and an indicator while it runs. The server must stop serving positions when the share ends, not only the app stop sending them.
- **Audience.** Per-share recipients, not "all contacts", and no location in public posts unless the user adds it.
- **History.** Who can see past check-ins and routes, and whether start and end points of recorded activities (often a home address) are hidden by default; privacy zones around a chosen address are a good pattern for activity-tracking apps.

### Both platforms: contact discovery and enumeration

Contact discovery lets users find people they know by uploading their address book or searching by phone number or email. It is useful and it is also a lookup service that answers "is this phone number a user, and who are they?". The weaknesses are well known:

- **No opt-out.** Users cannot choose not to be findable by phone number or email.
- **Oracle responses.** The API answers differently for "registered", "registered but not discoverable" and "not registered", and the difference itself reveals the registration. Sign-up ("this number is already registered") and password reset flows are often a second oracle.
- **Too much in the answer.** A match returns the full profile, including fields the user hid, rather than the minimum needed to show a "connect" card.
- **No rate limiting.** Contact upload endpoints accept thousands of entries per request and unlimited requests per account, which makes mass enumeration cheap ([OWASP API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) and [API6:2023](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)).
- **Hashing as a false comfort.** Uploading SHA-256 hashes of phone numbers instead of the numbers does not protect them: the space of valid phone numbers is small enough to hash exhaustively. It reduces casual exposure in logs, nothing more.

On the device side, iOS 18 added **limited contacts access**: the user can share only selected contacts with the app, and apps can offer the `ContactAccessButton` and contact access picker to add more over time. Android has no equivalent partial grant for contacts, so an Android app that syncs the address book usually gets all of it. Whether contacts access is justified at all belongs to [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/); what is uploaded and to whom belongs to [MASWE-0069](/mobile/maswe-0069-non-privacy-preserving-functionality/). Here the concern is what the discovery service reveals about the people being looked up.

### Both platforms: presence, read receipts, activity and link previews

- **Presence and last seen.** Precise "last seen" timestamps reveal sleep patterns and routines, and comparing two users' timestamps suggests who talks to whom. Offer "nobody / contacts / everyone", and consider coarsening ("recently", "within a week").
- **Read receipts and typing indicators.** Let users switch them off; check that the server stops sending them, not only the app stops displaying them.
- **Activity feeds.** "X liked Y", "X started following Z", "X viewed your profile" broadcast behaviour the user may not expect to be public. Each needs a setting or a clear statement at the moment of the action ([MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/)).
- **Link previews.** Someone has to fetch a URL to build its preview. If the **recipient's** app fetches it, the linked site learns the recipient's IP address and that the message was received, without them tapping anything. If the **sender's** app fetches it, the sender's IP is exposed, which is what they chose. If the **server** fetches it, the server learns every shared URL, which matters for end-to-end encrypted messaging. Recipient-side fetching is the problematic design; test for it by sending a link to a server you control from account A to account B and watching which IP fetches it.

### Android and iOS: metadata in shared photos and files

Photos taken on phones usually carry EXIF metadata: GPS latitude, longitude and altitude, capture time, device make and model, sometimes the camera serial number and editing software. Videos store location in the container (QuickTime/MP4 metadata). Office documents and PDFs carry author names. When a user shares a photo through an app, whether that metadata reaches other users depends on three layers:

**Android.** Since Android 10, apps reading photos through `MediaStore` get location metadata **redacted** unless they hold the `ACCESS_MEDIA_LOCATION` runtime permission **and** ask for the original bytes with [`MediaStore.setRequireOriginal(uri)`](https://developer.android.com/training/data-storage/shared/media#location-info-photos) (without the permission that call throws). The system [photo picker](https://developer.android.com/training/data-storage/shared/photopicker) also hands apps media without location metadata; developer reports since its introduction show it redacting location even for apps holding `ACCESS_MEDIA_LOCATION`, and reports from August 2026 describe a Mainline update that adds a user-facing toggle in the picker to include location for apps that adopt a new API. We have not been able to confirm the API in official documentation at the time of writing; check the current behaviour on your test device. Images that reach the app another way (a share intent from the gallery, the Storage Access Framework, a file from another app, or the app's own camera capture) may still carry GPS data, so do not assume redaction.

**iOS.** The share sheet has had an **Options** control since iOS 13 that lets the user turn off *Location* (and *All Photos Data*) before sharing photos; from iOS 17 the system photo picker (`PHPickerViewController` and SwiftUI `PhotosPicker`) has a similar **Options** menu. By default the picker passes metadata, including location, through to the app, and an app that reads the file representation gets the original EXIF. An app with full photo library access reading `PHAsset` gets `location` directly. Camera capture inside the app only adds GPS data if the app writes it.

**The server.** Because the client side has so many paths, the only control that reliably protects other users from seeing the metadata is the server: strip or rewrite metadata on upload (or re-encode the image), for every rendition it serves, including "download original" options, unless the user explicitly chose to include the location and was told it would be visible. Keep orientation, colour profile and other non-identifying tags that are needed to display the image correctly.

### Android and iOS: share sheets, public links and system surfaces

- **Share sheets.** On Android, `Intent.ACTION_SEND` with `Intent.createChooser` (and `FLAG_GRANT_READ_URI_PERMISSION` on a `FileProvider` URI) hands content to another app; on iOS, `UIActivityViewController` does the same. The content and any extra text the app adds (a profile URL, a referral code, the user's name) go to whatever app the user picks. Check what the app puts in the shared payload beyond what the user selected.
- **Public links.** "Share" or "invite" features often create a URL that anyone can open. Check whether the user is told the link is public, whether it is an unguessable token rather than a sequential ID, whether it expires, whether it can be revoked, and whether it contains personal data (email, phone number, name) in the path or query string, where it ends up in logs, analytics and referrer headers.
- **System surfaces.** Data visible on the lock screen, in the app switcher, in screen recordings, on the clipboard (including Universal Clipboard on Apple devices) and to accessibility services is part of the environment's view of the user. These are tested in the PLATFORM notes: [notifications](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/), [screenshots and recents](/mobile/maswe-0038-insufficient-screenshot-protection/), [the UI](/mobile/maswe-0036-sensitive-data-exposed-via-ui/), [the clipboard](/mobile/maswe-0030-improper-use-of-the-clipboard/) and [accessibility](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/). In this note, record which of them the app offers settings for (for example "hide message content in notifications").

## Tests

None of these are OWASP tests. Use only test accounts and devices you control; where a test involves another person's view, that "other person" is your second test account. Set up traffic interception as in our [traffic interception lab](/mobile/mobile-traffic-interception-lab/) ([MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/), [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/), [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/)).

### GT-PRIV-0077-1: Visibility controls inventory (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Builds the list of everything about a user that other users or the environment can see, the control (if any) for each item, its default, and how to find it. The inventory is a finding in itself where controls are missing or defaults are public, and it is the input for GT-PRIV-0077-2.

#### Prerequisites

- The production app on Android and iOS, a freshly created test account A (to see real defaults) and a second test account B that is not connected to A.
- The privacy policy and the store declarations, which sometimes describe visibility.

#### Steps

1. **Fill in a fresh profile** for A with every field the app accepts, using test data (an example.com email, a reserved fictional phone number such as the UK's 07700 900xxx range [set aside by Ofcom for drama](https://www.ofcom.org.uk/phones-and-broadband/phone-numbers/numbers-for-drama)).
2. **Record the defaults** before touching any setting: open A's profile from B (not connected), from B after following or connecting, and logged out (web profile URL, if any). Note every field, content item, list and status visible to each.
3. **Walk every settings screen** and record each visibility control: its label, options, default, the path to reach it, and whether the app explains its effect. Include presence, read receipts, typing, activity feed, discoverability per identifier, search engine indexing, location precision and history, social graph, blocking and notification content settings.
4. **Exercise the sharing features**: post with and without location, start and stop live location sharing (note the duration options and the indicator), create a public or invite link, share a profile to another app and read the payload (on Android, share to a note app; on iOS, share to Notes or copy).
5. **Check what changes apply to.** Switch a setting to the most private option and check existing content and the profile from B again.
6. **Test a link preview.** From A, send B a link to a host you control (a request bin on your own server) and record which IP address fetches it and when: before B opens the conversation (server-side), from B's device (recipient-side), or from A's device (sender-side).

#### Observation

A table per visibility surface: item, visible to (strangers, connections, logged out), control yes/no, options, default, path depth, explained yes/no; plus the sharing and link preview observations.

#### Evaluation

The test **fails** for any item of personal contact data (email, phone), date of birth, precise location, presence or sensitive group membership that is visible to others with no control to hide it; for public-by-default settings on those items; for live location sharing with no end time or indicator; for settings that do not apply to existing content without saying so; and for recipient-side link preview fetching in a messaging app. Hard-to-find settings (several levels deep, inconsistently labelled) are a lower-rated finding. It **passes** when each surface has a control with options appropriate to its sensitivity, defaults are private for sensitive items, and the controls are grouped and explained.

#### Demo

Illustrative extract from an inventory:

```text
Surface            Item              Strangers  Control                    Default      Path
Profile            Phone number      visible    none                       -            -
Profile            Date of birth     visible    "Show birthday" on/off     on           Profile > Edit > Birthday (3)
Presence           Last seen         visible    nobody/contacts/everyone   everyone     Settings > Privacy > Last seen (3)
Discoverability    Find by phone     yes        none                       -            -
Location           Live share        -          15 min / 1 h / until off   until off    Chat > Share > Location (3)
Link preview       Fetch origin      recipient device (IP 198.51.100.23, before message opened)
```

### GT-PRIV-0077-2: Server-side enforcement of visibility with two test accounts (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Checks that the backend withholds the fields and objects that the visibility settings hide, on every endpoint and channel that returns user data, using two test accounts you control. This is an authorisation test as much as a privacy one, and a failure is rated as a security vulnerability.

#### Prerequisites

- Test accounts A (the "owner") and B (the "viewer"), signed in on two devices or two app instances, and B's session token captured in the proxy.
- The inventory from GT-PRIV-0077-1, with A set to the **most private** option for every setting.
- A proxy and `curl` and `jq` on your workstation.

#### Steps

1. **Map the endpoints** that return user data, from the traffic of a long session as B: profile, search, suggestions, followers and following, comments and reactions, messages and conversation members, notifications, feeds, location, presence and any GraphQL operations. Note real-time channels (WebSocket frames are visible in Burp and mitmproxy) and push payloads.
2. **Set A's settings to private** and confirm in the app that B no longer *sees* the fields.
3. **Request A's data as B** directly, and list every field path in each response:

   ```bash
   B="Authorization: Bearer $TOKEN_B"
   curl -s -H "$B" https://api.example.com/v1/users/1001 | jq -S . > b-view-profile.json
   curl -s -H "$B" "https://api.example.com/v1/search?q=tester-a" | jq -S . > b-view-search.json
   # every field path present in what B received, to compare with what A allowed
   jq -r '[paths(scalars) | map(tostring) | join(".")] | .[]' b-view-*.json | sort -u
   # direct search for A's hidden values in all of B's captured traffic
   grep -l -e 'tester-a@example.com' -e '7700900123' -e '1990-04-02' b-view-*.json
   ```

   Search the saved proxy session too (all hosts, including real-time frames) for A's hidden values.
4. **Ask for hidden fields explicitly.** For GraphQL, request the fields the UI never asks for:

   ```bash
   curl -s -H "$B" -H 'Content-Type: application/json' https://api.example.com/graphql \
     -d '{"query":"query { user(id: \"1001\") { username email phoneNumber birthDate lastSeenAt location { lat lng } } }"}' | jq .
   ```

   For REST, try documented or observed field selectors (`?fields=email,phone`, `?expand=contact`).
5. **Check objects, not only fields.** As B, request A's private posts, photos or location shares by ID (IDs taken from A's own session). They must return 403 or 404.
6. **Check presence and receipts.** With A's last seen, online status and read receipts off, keep B's real-time connection open while A uses the app and reads B's messages. Inspect the frames B receives: there should be no presence or read events for A.
7. **Check changes and blocking.** Switch a field from public to private and request it again immediately and after a few minutes (cache behaviour). Block B from A and repeat steps 3 to 6.

#### Observation

For each endpoint and channel: the fields and objects B received, compared with what A's settings allow; the GraphQL and selector results; the real-time frames; and the behaviour after a change and after blocking.

#### Evaluation

The test **fails** if any response or event delivered to B contains a field or object that A's settings hide from B, whether or not the app displays it, or if hidden data is still served after the setting changed beyond a short, stated cache period. It **passes** when hidden fields are absent from responses (not empty strings that still reveal their existence where that matters, not masked only in the UI), private objects are refused, and real-time and push channels respect the same settings.

#### Demo

Illustrative response to B for A's profile, with A's email, phone and birthday set to "only me". The app shows only the name and avatar:

```json
{
  "id": "1001",
  "username": "tester-a",
  "displayName": "Tester A",
  "avatarUrl": "https://cdn.example.com/a/1001.jpg",
  "email": "tester-a@example.com",
  "phone": "+447700900123",
  "birthDate": "1990-04-02",
  "privacy": { "showEmail": false, "showPhone": false, "showBirthday": false },
  "lastSeenAt": "2026-11-10T21:58:12Z"
}
```

The `privacy` object is the giveaway: the client is being trusted to apply it. A compliant response omits the hidden fields entirely.

### GT-PRIV-0077-3: Contact discovery and enumeration resistance (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Checks that discovery by phone number, email or username respects the user's choice, does not leak registration status or hidden fields, and resists bulk lookups. Run it only with identifiers you own (your test accounts) and reserved fictional ones (Ofcom 07700 900xxx numbers, example.com addresses), at a volume agreed with the client in the rules of engagement. Do not look up real people's numbers or upload a real address book.

#### Prerequisites

- Test accounts A and B, with A's phone number and email known to you; a test device whose address book contains only test entries.
- A proxy; the discovery endpoints identified from the traffic (contact sync or upload, "find friends", search by phone or email, invite flows).
- Written agreement on the request volume for the rate-limit check, preferably against a staging environment that mirrors production limits.

#### Steps

1. **Inventory the discovery paths**: contact upload, search by identifier, QR or link lookups, sign-up ("already registered") and password reset responses.
2. **Compare three cases** on each path, as B:
   - A, discoverable by phone (default or switched on);
   - A, with discoverability by phone switched off;
   - a reserved number that is not registered (for example `+447700900999`).

   Record status codes, response bodies, sizes and timings. The second and third cases should be indistinguishable.
3. **Check what a match returns.** A match should return the minimum needed for a "connect" card (and nothing A hid; see GT-PRIV-0077-2).
4. **Check the upload format and size limits.** Note whether identifiers are sent in clear or hashed (hashing is not a protection; say so in the report if the client relies on it), and how many entries one request accepts.
5. **Check rate limiting** within the agreed volume, repeating lookups for your own identifiers only:

   ```bash
   # 60 lookups of your own test identifiers, one per second; record status codes
   for i in $(seq 1 60); do
     curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN_B" \
       -H 'Content-Type: application/json' \
       -d '{"phones":["+447700900123","+447700900999"]}' \
       https://api.example.com/v1/contacts/match
     sleep 1
   done | sort | uniq -c
   ```

   Look for 429 responses, CAPTCHA or step-up challenges, or silent throttling (results suddenly empty). Record the threshold you reached, not just "no limit observed".
6. **Check the opt-out's reach.** With A's discoverability off, check that A no longer appears in "people you may know" or similar suggestion features for B, even though B has A's number in the address book.

#### Observation

The response comparison table for the three cases per path, the content of a match, the upload format and limits, the rate-limit result and threshold, and the suggestions behaviour.

#### Evaluation

The test **fails** if users cannot opt out of discovery by phone number or email; if responses distinguish "not discoverable" from "not registered" or reveal registration in sign-up or reset flows without compensating controls; if a match returns hidden fields or more profile data than the connect card needs; or if no meaningful rate limit applies to lookups or contact upload size. It **passes** when discovery respects per-identifier opt-outs, all non-matches look the same, matches are minimal, and lookups are limited per account, device and time window with monitoring for abuse.

Some disclosure is inherent: a messaging app that lets you message a phone number will reveal that the number is registered to anyone who has it. Rate it by what an attacker gains at scale, and credit compensating controls (strict rate limits, abuse detection, minimal match data).

#### Demo

Illustrative responses showing an oracle between "opted out" and "not registered":

```text
POST /v1/contacts/match  {"phones":["+447700900123"]}   (A, discoverable)
200 {"matches":[{"phone":"+447700900123","userId":"1001","displayName":"Tester A"}]}

POST /v1/contacts/match  {"phones":["+447700900123"]}   (A, discoverability off)
200 {"matches":[{"phone":"+447700900123","discoverable":false}]}

POST /v1/contacts/match  {"phones":["+447700900999"]}   (not registered)
200 {"matches":[]}

rate check: 60 x 200, no throttling observed at 1 request/s
```

### GT-PRIV-0077-4: Metadata in shared content (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Checks whether photos, videos and documents a user shares reach other users with location, device or author metadata. It covers every upload path in the app on both platforms, and the files as **another user** receives them.

#### Prerequisites

- Test accounts A (uploader) and B (viewer), the production app on both platforms, a proxy, and [ExifTool](https://exiftool.org/) on your workstation.
- Test media with known metadata at a location that is not yours (a public landmark):

  ```bash
  cp sample.jpg gps-test.jpg
  exiftool -overwrite_original -GPSLatitude=51.5007 -GPSLatitudeRef=N \
    -GPSLongitude=0.1246 -GPSLongitudeRef=W -Make=TestMake -Model=TestModel \
    -DateTimeOriginal="2026:11:10 12:00:00" gps-test.jpg
  exiftool -gps:all -Make -Model gps-test.jpg      # confirm the tags are there
  ```

  Push it to the test devices (`adb push gps-test.jpg /sdcard/Pictures/`, then a media scan or reboot; on iOS, AirDrop or save it to Photos from Files). Also take a photo and a short video with the test device's camera with location services on for the Camera app, to get native HEIC/JPEG and MOV/MP4 files with real container metadata.

#### Steps

1. **Static check of what the app asks for.** On Android, check whether the app declares `ACCESS_MEDIA_LOCATION` and calls `setRequireOriginal`:

   ```bash
   aapt2 dump permissions app-release.apk | grep -i media_location
   jadx -d out app-release.apk && grep -rn "setRequireOriginal\|ExifInterface" out/sources | head
   ```

   On iOS, look in the decrypted binary's strings and imports for `PHPickerViewController`, `PhotosPicker`, `PHAsset`, `kCGImagePropertyGPSDictionary` and `CGImageSourceCopyPropertiesAtIndex` to see whether the app reads or writes location metadata. An app that deliberately requests original location must have a feature that needs it.
2. **Upload through every path** as A: the in-app camera, the photo picker, the gallery or Photos share sheet into the app ("Share to..."), the document or file picker, chat attachments, avatar and cover photo, and any "attach original" or "send as file" option. On iOS, do one upload with the picker's or share sheet's **Options > Location** on and one with it off, and record which you used.
3. **Capture what leaves the device.** Save the upload request bodies from the proxy. Multipart bodies need carving before ExifTool can read them:

   ```python
   # carve_multipart.py - extract file parts from a saved multipart/form-data request body
   # usage: python3 -I carve_multipart.py body.bin 'multipart/form-data; boundary=...'
   import os, sys, email.parser, email.policy
   body = open(sys.argv[1], 'rb').read()
   msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(
       b'Content-Type: ' + sys.argv[2].encode() + b'\r\n\r\n' + body)
   for i, part in enumerate(msg.iter_parts()):
       name = part.get_filename()
       if name:
           out = f'part{i}_' + os.path.basename(name)
           open(out, 'wb').write(part.get_payload(decode=True))
           print('wrote', out)
   ```

4. **Download as B** what other users receive: the image in the feed or chat, the thumbnail, the full-size view, any "download" or "save original" option, and the media URL opened directly in a browser. Do the same for the video and any shared document.
5. **Read the metadata** of each file from steps 3 and 4:

   ```bash
   exiftool -a -G1 -s -gps:all -Keys:GPSCoordinates -UserData:GPSCoordinates \
     -Make -Model -SerialNumber -DateTimeOriginal -Software -Author -Creator part*_* b-*
   ```

6. **Check the app's own location features**: if the app offers "add location" on posts, check that what B receives matches the precision the UI promised (place name versus coordinates in the API response).

#### Observation

A table per upload path and platform: metadata present on the device copy, in the uploaded bytes, and in each rendition B received; the static findings; the effect of the iOS Options setting.

#### Evaluation

The test **fails** if any file served to B (any rendition, including originals offered for download) contains GPS coordinates, or device serial numbers, that A did not explicitly choose to share with a clear indication that they would be visible. It is also a finding, at a lower level, if uploads carry location to the server when no feature needs it (data minimisation, [MASWE-0069](/mobile/maswe-0069-non-privacy-preserving-functionality/)), even if the server strips it before serving. It **passes** when the server strips or rewrites identifying metadata for every rendition, or when location is shared only through an explicit, labelled choice. Device make and model and capture time are lower-sensitivity on their own; report them, but rate primarily on location.

A common false positive: ExifTool on a re-encoded thumbnail shows only `ImageWidth`, `ImageHeight` and colour profile tags. That is a stripped file. Another: the photo B sees has no GPS tags, but the "download original" path does; test every rendition before concluding.

#### Demo

Illustrative ExifTool output for the file B downloaded through "save original", uploaded by A through the share sheet:

```text
[GPS]           GPSLatitudeRef                  : North
[GPS]           GPSLatitude                     : 51 deg 30' 2.52"
[GPS]           GPSLongitudeRef                 : West
[GPS]           GPSLongitude                    : 0 deg 7' 28.56"
[IFD0]          Make                            : TestMake
[IFD0]          Model                           : TestModel
[ExifIFD]       DateTimeOriginal                : 2026:11:10 12:00:00
```

and for the feed image of the same upload, after server-side re-encoding:

```text
[File]          ImageWidth                      : 1080
[File]          ImageHeight                     : 1440
[ICC-header]    ProfileDescription              : sRGB IEC61966-2.1
```

## Secure implementation

OWASP has no best practices for this weakness. What we recommend:

- **One visibility model on the server.** Store per-field and per-feature audiences with the user (Firebase's guidance on [storing privacy settings](https://firebase.google.com/support/privacy/storing-privacy-settings) shows the pattern: settings under the user's ID, writable only by that user, validated, with an audit log of changes). Every serialiser of a user object takes the viewer as input and emits only what that viewer may see; use explicit allow-lists of fields per audience, not a full object with fields removed afterwards.

  ```kotlin
  // Server-side (Kotlin, illustrative): build the view per viewer; never ship the privacy flags for the client to apply.
  fun profileFor(owner: User, viewer: User?): Map<String, Any?> {
      val rel = relationship(owner, viewer)            // SELF, CONNECTION, STRANGER, BLOCKED
      if (rel == Relationship.BLOCKED) throw NotFound()
      return buildMap {
          put("id", owner.id); put("displayName", owner.displayName); put("avatarUrl", owner.avatarUrl)
          if (owner.privacy.email.allows(rel)) put("email", owner.email)
          if (owner.privacy.phone.allows(rel)) put("phone", owner.phone)
          if (owner.privacy.birthday.allows(rel)) put("birthDate", owner.birthDate)
          if (owner.privacy.lastSeen.allows(rel)) put("lastSeen", coarsen(owner.lastSeenAt))
      }
  }
  ```

- **Apply the same model to every channel**: search, suggestions, embedded author objects, GraphQL field resolvers, real-time events and push payloads. Add automated tests that request each endpoint as a stranger and assert that hidden fields are absent.
- **Private defaults** for contact details, date of birth, presence, location and discoverability, with a "preview my profile as" view so users see the effect.
- **Discovery**: separate opt-outs per identifier, identical responses for non-matches and opted-out users, minimal match data, per-account and per-device rate limits, upload size limits and abuse monitoring.
- **Location**: coarsen on the server for other users; live sharing with a chosen end time, visible indicator and server-side expiry; privacy zones for recorded routes.
- **Media**: strip GPS and device identifiers on the server for every rendition (re-encoding or an explicit metadata allow-list), and do not request original location on the client unless a feature needs it. On Android, prefer the photo picker and do not declare `ACCESS_MEDIA_LOCATION` without a reason; on iOS, prefer `PHPickerViewController` or `PhotosPicker` over full library access.
- **Sharing**: label public links as public, use unguessable tokens with expiry and revocation, and keep personal data out of URLs. Generate link previews on the sender's device or not at all.

## Rating findings

We follow the series-wide rule from the [PRIVACY hub](/mobile/masvs-privacy-privacy-testing-guide/): rate by what personal data is exposed beyond what the user intended, its sensitivity, scale and reversibility, and whether the behaviour contradicts the app's own declarations or settings. Severity is not a statement about regulatory liability; that assessment belongs to the client's legal team.

| Rating | Conditions |
|---|---|
| **High** | Hidden fields or private objects returned by the API to other users (a server-side authorisation failure; may be Critical at scale or for special-category data); precise or live location visible to strangers, or live sharing with no end; GPS coordinates served to other users in shared photos without an explicit choice; unrestricted contact discovery that maps phone numbers to profiles at scale; any of these in an app for children or for sensitive communities. |
| **Medium** | Contact details, date of birth or presence visible to strangers with no control; public-by-default sensitive settings; an oracle that reveals opted-out users; real-time presence or read events delivered despite being switched off; recipient-side link preview fetching in a messaging app; public share links that never expire or cannot be revoked. |
| **Low** | Settings that exist but are hard to find or poorly explained; changes that do not apply to existing content without warning; device make and model in shared media; location uploaded to the server but stripped before serving; personal data in share URLs with limited exposure. |
| **Info** | Inherent disclosures with compensating controls (registered status revealed to someone who already has the number, with strict rate limits); reciprocal read receipt designs; observations for the client's design team. |

Raise a level where the exposed data is special-category or concerns children, where the exposure contradicts a setting the user switched on (the app said "hidden" and it was not), and where it is reachable without an account. Lower a level where the exposure needs an existing connection the user accepted.

In the report give: the setting and its state, the account relationship (stranger, connection, blocked), the request and the response or frame with the hidden values highlighted (other test account data only; redact tokens), the inventory table, and the server-side change that fixes it.

## References

- OWASP MASWE: [MASWE-0077: Inadequate Data Visibility Controls](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0077/); related [MASWE-0076](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0076/), [MASWE-0071](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0071/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PRIVACY-4](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-4/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/), [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/), [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/) (CC BY-SA 4.0)
- OWASP MASTG tools: [Burp Suite (MASTG-TOOL-0077)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/), [mitmproxy (MASTG-TOOL-0097)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/) (CC BY-SA 4.0)
- OWASP MASWE references: [Firebase: storing privacy settings](https://firebase.google.com/support/privacy/storing-privacy-settings), [Demystifying Hidden Privacy Settings in Mobile Apps](https://www.researchgate.net/publication/335863205_Demystifying_Hidden_Privacy_Settings_in_Mobile_Apps)
- OWASP API Security Top 10 2023: [API1 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [API3 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/), [API4 Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/), [API6 Unrestricted Access to Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)
- Law and guidance: [GDPR (EUR-Lex)](https://eur-lex.europa.eu/eli/reg/2016/679/oj) Art. 5, 25; [UK GDPR (legislation.gov.uk)](https://www.legislation.gov.uk/eur/2016/679/contents); ICO: [Age appropriate design code](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/childrens-information/childrens-code-guidance-and-resources/age-appropriate-design-a-code-of-practice-for-online-services/); Ofcom: [numbers for drama](https://www.ofcom.org.uk/phones-and-broadband/phone-numbers/numbers-for-drama)
- Android: [Access media files from shared storage (location information in photos)](https://developer.android.com/training/data-storage/shared/media#location-info-photos), [Photo picker](https://developer.android.com/training/data-storage/shared/photopicker), [`Manifest.permission`](https://developer.android.com/reference/android/Manifest.permission), [Location permissions](https://developer.android.com/training/location/permissions)
- Apple: [`PHPickerConfiguration`](https://developer.apple.com/documentation/photokit/phpickerconfiguration), [`ContactAccessButton`](https://developer.apple.com/documentation/contactsui/contactaccessbutton)
- Tools: [ExifTool](https://exiftool.org/)
- CWE: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)
- Sibling notes: [PRIVACY hub](/mobile/masvs-privacy-privacy-testing-guide/), [MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/), [MASWE-0071](/mobile/maswe-0071-inadequate-privacy-defaults/), [MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/), [MASWE-0069](/mobile/maswe-0069-non-privacy-preserving-functionality/), [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/); PLATFORM: [MASWE-0030](/mobile/maswe-0030-improper-use-of-the-clipboard/), [MASWE-0036](/mobile/maswe-0036-sensitive-data-exposed-via-ui/), [MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/), [MASWE-0038](/mobile/maswe-0038-insufficient-screenshot-protection/), [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/), [PLATFORM hub](/mobile/masvs-platform-platform-interaction-guide/); [traffic interception lab](/mobile/mobile-traffic-interception-lab/)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
