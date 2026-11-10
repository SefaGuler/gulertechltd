---
title: "MASWE-0076: Lack of Proper Data Management Controls"
date: 2026-11-10 22:10:00 +0000
subcategory: privacy
summary: "Testing account deletion, data export, rectification and opt-out controls in Android and iOS apps: store rules, what delete must cover, and proof."
refs: [MASWE-0076, MASVS-PRIVACY-4, CWE-359]
tags: [android, ios, masvs-privacy, account-deletion, data-subject-rights, gdpr]
---

This note is part of our [MASVS-PRIVACY guide](/mobile/masvs-privacy-privacy-testing-guide/) and covers OWASP [MASWE-0076](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0076/): an app that gives its users no proper way to manage the personal data it holds about them. In practice that means four controls: **delete** (the account and the data behind it), **access and export** (see and take away a copy), **rectify** (correct what is wrong) and **opt out** (stop optional processing such as analytics, personalised ads or marketing). All four are legal duties in most markets, and account deletion is also a hard store requirement on both Google Play and the App Store. What makes this a testing topic rather than a checklist is that a button is not a control: a "Delete account" screen that deactivates the account, leaves a refresh token valid, keeps sending analytics under the old user ID or leaves the session in the iOS Keychain is a finding even though the screen exists. OWASP has no tests or Knowledge items for this weakness yet, so everything below is Guler Tech methodology: the platform and store background, four tests that you can run with your own test accounts, the implementation we recommend and how we rate what we find.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Both platforms: data subject rights and what they mean for an app](#both-platforms-data-subject-rights-and-what-they-mean-for-an-app)
  - [Both platforms: store rules for account deletion](#both-platforms-store-rules-for-account-deletion)
  - [Both platforms: what delete has to cover](#both-platforms-what-delete-has-to-cover)
  - [Android: data the app leaves on the device](#android-data-the-app-leaves-on-the-device)
  - [iOS: data the app leaves on the device](#ios-data-the-app-leaves-on-the-device)
  - [Both platforms: access, export and rectification](#both-platforms-access-export-and-rectification)
  - [Both platforms: opt-out controls that actually stop processing](#both-platforms-opt-out-controls-that-actually-stop-processing)
- [Tests](#tests)
  - [GT-PRIV-0076-1: Account deletion flow (Android and iOS)](#gt-priv-0076-1-account-deletion-flow-android-and-ios)
  - [GT-PRIV-0076-2: Deletion effectiveness (Android and iOS)](#gt-priv-0076-2-deletion-effectiveness-android-and-ios)
  - [GT-PRIV-0076-3: Data access and export (Android and iOS)](#gt-priv-0076-3-data-access-and-export-android-and-ios)
  - [GT-PRIV-0076-4: Rectification and opt-out controls (Android and iOS)](#gt-priv-0076-4-rectification-and-opt-out-controls-android-and-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app provides adequate controls to manage user data."* MASWE-0076 maps to **MASVS-PRIVACY-4** ("The app offers user control over their data") and to [CWE-359](https://cwe.mitre.org/data/definitions/359.html) (Exposure of Private Personal Information to an Unauthorized Actor). It carries OWASP's **P** and **EUDIW** profiles. In the MASWE threat model it is MAS-THREAT-0076 ("apps and their backend services can retain and process personal data beyond the user's control"), realised by MAS-ATTACK-0083: providing no way to delete, export, modify or opt out of the collection of data. In the earlier beta numbering it was MASWE-0113.

**OWASP has no MASTG tests, no Knowledge items and no best practices for MASWE-0076**, and MASVS v1 had no privacy category, so no legacy tests are replaced. The four tests in this note are ours and are labelled as such.

This is technical testing guidance, not legal advice. We point to GDPR / UK GDPR articles and store policies because they define what "adequate" means in practice, but whether a given gap breaches a law is for the client's DPO or legal team to decide. Our job is to show what the app and its backend actually do, with evidence they can use.

What is covered, and by which test:

| Control | What we check | Test |
|---|---|---|
| Account deletion, in the app and on the web | Reachable, honest, real deletion rather than deactivation, works for every sign-in method | [GT-PRIV-0076-1](#gt-priv-0076-1-account-deletion-flow-android-and-ios) |
| Deletion effectiveness | Tokens revoked, server data gone, third parties told, nothing left on the device | [GT-PRIV-0076-2](#gt-priv-0076-2-deletion-effectiveness-android-and-ios) |
| Access and export | Complete, machine-readable, delivered safely, only to the right person | [GT-PRIV-0076-3](#gt-priv-0076-3-data-access-and-export-android-and-ios) |
| Rectification and opt-outs | Edits propagate; opt-outs stop the traffic and persist | [GT-PRIV-0076-4](#gt-priv-0076-4-rectification-and-opt-out-controls-android-and-ios) |

Keep the neighbours apart:

| Question | Where it lives |
|---|---|
| Can the user control what *other users* see about them (profile fields, presence, discoverability)? | [MASWE-0077](/mobile/maswe-0077-inadequate-data-visibility-controls/) |
| Is consent asked for properly, and can it be withdrawn? | [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/) |
| Are the optional processing switches on or off by default? | [MASWE-0071](/mobile/maswe-0071-inadequate-privacy-defaults/) |
| Does the privacy policy explain retention and how to exercise rights? | [MASWE-0072](/mobile/maswe-0072-inadequate-privacy-policy/) |
| Does the Data safety form's "data deletion" answer match reality? | [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) |
| Does logout (not deletion) clear the session and local data? | [MASWE-0024](/mobile/maswe-0024-sensitive-data-accessible-after-session-termination/) |

## Modes of Introduction

**No deletion path at all.** Common in apps built before the store rules, in B2B apps that assume "the customer's admin handles it", and in apps where account creation happens on a website and the team believes the app is therefore out of scope (Google Play says otherwise; see [store rules](#both-platforms-store-rules-for-account-deletion)).

**Deletion by support ticket.** "Email privacy@ to close your account", a chat flow, a phone call or a web form that asks for the same details the app already has. Apple accepts extra customer-service steps only for highly regulated industries.

**Deactivation dressed up as deletion.** The button sets `status = disabled`, hides the profile and keeps everything. Signing in again "reactivates" the account. Both stores say that this is not deletion.

**Deletion that forgets half the data.** The user row goes, but uploads in object storage, search indexes, analytics and CRM profiles, data warehouse copies, push tokens, the third-party SDK profiles and the device's local storage do not.

**Sessions outlive the account.** Access and refresh tokens stay valid until expiry, the Sign in with Apple grant is never revoked, and on iOS the old refresh token survives in the Keychain.

**Export and edit as an afterthought.** No export, an export that only includes the profile row, a PDF where a machine-readable format is needed, or an export link that is public and never expires. Some fields (date of birth, phone number, real name) cannot be edited at all, or edits do not reach the copies other systems hold.

**Opt-outs that only change the UI.** An "analytics" switch that is stored but never read by the SDK initialisation code, a switch that is reset by an app update, or a server-side "marketing" preference that the email platform never receives.

## Impact

- **Users cannot exercise their rights.** Without working controls a user cannot stop processing they no longer want, correct data that affects decisions about them, or leave the service and take their data with them.
- **Data that should not exist is still there.** Every deleted-but-not-really account remains in the blast radius of the next breach and in the next data-sharing arrangement. Retaining it without a disclosed reason is itself the problem the GDPR storage limitation principle (Art. 5(1)(e)) addresses.
- **Tracking continues after the user said no.** An opt-out that does not stop traffic means third parties keep receiving identifiers and events the user has refused.
- **Store enforcement.** Missing or broken account deletion is a documented rejection reason on the App Store and a policy violation on Google Play that can lead to update rejection or removal.
- **Regulatory and contractual exposure, and loss of trust.** These are for the client to assess, but your evidence is what they will rely on.
- **Security side effects.** Deletion and export endpoints are high-value targets in their own right: an authorisation flaw in either lets an attacker delete or download another user's account. We test for that too (with two of your own accounts).

## Mitigations

- **Offer all four controls in the app**: delete account, download your data, edit profile, and privacy settings with the opt-outs, plus a web route for deletion that does not require the app.
- **Delete, do not deactivate.** If you offer a grace period, say how long it is, allow immediate deletion where the store requires it, and actually delete when it ends.
- **Make deletion complete**: a deletion job that reaches every store and processor listed in the record of processing, revokes every token and grant, and is logged so it can be evidenced. Disclose what is retained, why and for how long.
- **Clean the device**: on deletion (and logout), remove local files, databases, preferences, caches, web storage, Keychain items and Keystore keys, and unbind push tokens.
- **Make opt-outs real**: wire each switch to the SDK's collection controls and to the server-side processing it governs, persist it server-side, and verify with traffic captures in CI or QA.
- **Protect the endpoints**: deletion and export require a fresh authentication, act only on the caller's own account, and deliver exports through authenticated, expiring links.

## Background

OWASP has no Knowledge items for this weakness. This section covers what a tester needs: the rights behind the controls, the store rules, what "delete" has to reach on the server and on each platform, and how access, export and opt-outs are usually built.

### Both platforms: data subject rights and what they mean for an app

The GDPR (and the UK GDPR, which keeps the same article numbers) gives individuals a set of rights in Articles 15–22. The ones that turn into app features:

| Right | Article | What it looks like in an app |
|---|---|---|
| Access | 15 | "Download your data" or "Request a copy"; also a view of what is held, the purposes and the recipients |
| Rectification | 16 | Editable profile fields; a route to correct data the user cannot edit directly |
| Erasure ("right to be forgotten") | 17 | "Delete account", plus deletion of specific content (posts, messages, location history, uploads) |
| Restriction | 18 | Pausing processing while a dispute is resolved: an account freeze or "hold" state that keeps data but stops using it |
| Notification to recipients | 19 | Back-end duty to pass rectification, erasure and restriction on to those the data was disclosed to (including processors and partners) |
| Portability | 20 | Export in a "structured, commonly used and machine-readable format" (JSON or CSV in practice) for data the user provided, where processing is based on consent or contract and is automated |
| Objection | 21 | Opt-outs for processing based on legitimate interests (for example product analytics), and an absolute right to stop direct marketing (Art. 21(2)–(3)) |
| Automated decisions | 22 | A route to human review where the app makes significant decisions automatically (credit, eligibility) |

Three more provisions shape how the controls must work:

- **Art. 12** says the controller must *facilitate* the exercise of these rights and answer without undue delay and within one month (extendable by two further months for complex or numerous requests). An in-app control that works immediately is the easiest way to meet that; a support mailbox is the slowest.
- **Art. 7(3)** says withdrawing consent must be as easy as giving it. If consent was a single tap in the app, withdrawal cannot require an email. Consent mechanics are covered in [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/).
- **Art. 17(3)** lists the exceptions that allow retention (legal obligations, legal claims, and others). This is why "we keep invoices for six years" can be fine while "we keep everything" is not, as long as the retention is disclosed and limited.

In the UK, the Data (Use and Access) Act 2025 amends parts of this regime (for example, it confirms that searches for access requests need only be reasonable and proportionate); check with the client's legal team which provisions are in force. The [ICO's individual rights guidance](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/) and [EDPB Guidelines 01/2022 on the right of access](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-012022-data-subject-rights-right-access_en) explain the expectations in detail. In California, the CCPA as amended by the CPRA gives rights to know, delete and correct, to opt out of the sale or sharing of personal information and to limit use of sensitive personal information, with a 45-day response period ([California AG summary](https://oag.ca.gov/privacy/ccpa)).

None of these laws prescribes a UI. What they do is set a bar that an in-app control either meets (immediate, complete, verifiable) or forces the user to go round.

### Both platforms: store rules for account deletion

Both stores turned account deletion from good practice into a release gate. Their rules are worth knowing word for word, because they settle most arguments about whether a flow is "enough".

#### Google Play

The Play [User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311) and the [account deletion requirements](https://support.google.com/googleplay/android-developer/answer/13327111) apply to **any app that lets users create an account from within the app**, including apps that send the user to an external sign-up flow. Fully offline accounts are out of scope, and the help page exempts permanently private apps and enterprise device-management apps. The requirement has three parts:

- **An in-app path.** A "readily discoverable" option to start account deletion from inside the app, typically in account settings. (Wear OS, TV and other non-phone form factors do not need the in-app path.)
- **A web link.** A web resource where users can request deletion of the account and associated data **without reinstalling the app**. The link goes in the Data safety form, is shown on the store listing, must work, must name the app or developer, and must list any extra steps (for example cancelling a subscription first).
- **Real deletion.** Deleting the account must also delete the associated user data, and all data declared as collected in the Data safety section is in scope. The policy states that *temporary account deactivation, disabling, or "freezing" the app account does not qualify as account deletion.* Data kept for legitimate reasons such as security, fraud prevention or regulatory compliance must be disclosed, for example in the privacy policy. Data shared with service providers should be deleted from your systems and the providers asked to do the same.

The Data safety form has data deletion questions (whether users can request deletion, and the account deletion URL); Google set 7 December 2023 as the completion deadline, with extensions to 31 May 2024, after which non-compliant apps face enforcement. Partial deletion (data without closing the account) is optional but, if offered, is shown on the listing. Whether the form's deletion answer matches what the app does is our [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) territory; here we test the deletion itself.

#### App Store

[App Review Guideline 5.1.1(v)](https://developer.apple.com/app-store/review/guidelines/#data-collection-and-storage) says: *"If your app supports account creation, you must also offer account deletion within the app."* Apple has enforced this for submissions since 30 June 2022. Its [account deletion guidance](https://developer.apple.com/support/offering-account-deletion-in-your-app/) adds the practical rules:

- The option must be **easy to find**, typically in account settings, and the user must be able to **initiate** deletion in the app. A link straight to the web page where deletion is completed is acceptable; a link to the home page is not.
- Offer to delete **the entire account record and associated personal data**. *Only offering to temporarily deactivate or disable an account is insufficient.*
- Apps outside highly regulated industries (see 5.1.1(ix)) **should not require a phone call, email, chat or other support flow**.
- Confirming intent is fine, and so is verification such as a code sent to the email or phone number already on the account; making deletion *"unnecessarily difficult"* fails review.
- A manual process that takes time is acceptable, but the app must tell the user how long it will take and **confirm when deletion is complete**.
- With an **auto-renewable subscription**, tell the user that billing continues through Apple until they cancel; scheduling deletion for the end of the subscription is fine as long as immediate deletion is also offered.
- **Guest accounts** (generated automatically) must be deletable too, everyone must be able to delete regardless of country, and user-generated content is expected to go with the account.

Separately, **5.1.1(i)** requires the privacy policy to explain retention and deletion and *how a user can revoke consent and/or request deletion*, and App Store Connect has an optional **Privacy Choices** URL on the product page ([App Privacy details](https://developer.apple.com/app-store/app-privacy-details/)) for a web page where users can access, delete or change their data.

#### Sign in with Apple token revocation

Apple's deletion guidance says apps that support Sign in with Apple **should use the Sign in with Apple REST API to revoke user tokens** when the account is deleted. The call is server-to-server: [`POST https://appleid.apple.com/auth/revoke`](https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens) with the app's `client_id`, a `client_secret` (a JWT the server signs with its Sign in with Apple key), the refresh or access token, and `token_type_hint`. To have a token to revoke, the backend must have exchanged the authorisation code and kept the refresh token at sign-in; teams that only verify the identity token never have one, and cannot comply without changing the sign-in flow. Apple also sends [server-to-server notifications](https://developer.apple.com/documentation/signinwithapple/processing-changes-for-sign-in-with-apple-accounts) when a user stops using Sign in with Apple for the app or deletes their Apple Account; the backend should act on those as well.

You cannot see the revoke call from the device, but you can see its effect: after a correct deletion, the app disappears from the list of apps using Sign in with Apple in the device's Apple Account settings (Sign-In & Security, Sign in with Apple; the exact path varies between iOS versions), and the next sign-in with the same Apple Account shows the first-time consent sheet again. Other identity providers (Google, Facebook and similar) have their own grant revocation; the principle is the same.

### Both platforms: what delete has to cover

"Delete account" is a promise about every copy. Map them before testing, from the privacy policy, the Data safety and App Privacy declarations, the SDK inventory ([MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/), [third-party libraries](/mobile/mastg-know-0004-third-party-libraries/)) and the traffic you capture:

| Where the data lives | What deletion means | How you can test it |
|---|---|---|
| Primary database (account, profile, content) | Rows deleted or irreversibly anonymised | Access request after deletion; public URLs return 404; sign-in fails |
| Object storage and CDN (photos, files) | Objects deleted and CDN caches purged | Re-request the media URLs you recorded before deletion |
| Search indexes, recommendation and social graph | Entries removed | Search for the test account's handle and content from a second account |
| Sessions and tokens | Access and refresh tokens revoked; identity-provider grants revoked | Replay the recorded tokens; check the Sign in with Apple list |
| Push tokens | FCM/APNs device tokens unbound from the account | Trigger an event that used to notify the account; nothing should arrive |
| Analytics, attribution, crash reporting, ads SDKs | User-level data deleted through the vendor's deletion API or console, or kept only pseudonymous under a disclosed retention | Observe the app resetting SDK identifiers; ask for the deletion job and the processor terms |
| CRM, email, support desk, data warehouse | Records deleted by the deletion job | Ask for the job log; check that marketing email stops |
| Backups | Deleted when the backup ages out, and not restored into live systems (or re-deleted after a restore) | Ask for the backup retention period and the restore procedure |
| The device | App storage cleaned (next sections) | Local storage diff before and after |

Two points come up in almost every assessment:

- **Backups are not a reason to keep data indefinitely, nor a reason deletion is impossible.** Regulators generally accept that data in backups is put "beyond use" and expires with the backup cycle, provided it is not used or restored without re-applying deletions. Ask how long backups live and whether a restore re-runs the deletion log.
- **Third parties do not delete on their own.** Most analytics, attribution and crash-reporting platforms offer a user deletion API or console request (for example the [Google Analytics User Deletion API](https://developers.google.com/analytics/devguides/config/userdeletion/v3)); the backend has to call it with the identifiers the SDK used. You cannot verify vendor-side deletion from outside, so the evidence is (a) the app stops sending the old identifiers and (b) the client can show the deletion job and its calls.

### Android: data the app leaves on the device

Uninstalling an Android app removes its internal storage (`/data/user/<n>/<package>`, which is `/data/data/<package>` for the primary user), its app-specific external directories (`Android/data/<package>`, `Android/media/<package>`) and its Android Keystore keys. Deleting the *account* while the app stays installed removes nothing on its own; the app has to clean up. The places to check:

| Location | Clean-up |
|---|---|
| `shared_prefs/*.xml`, including `EncryptedSharedPreferences` files | `Context.deleteSharedPreferences(name)` (API 24+) or `edit().clear().commit()` |
| `databases/` (SQLite, Room, Realm) | `Context.deleteDatabase(name)` or the library's own delete |
| `files/`, `no_backup/`, `cache/`, `code_cache/`, DataStore files | Delete recursively |
| WebView cookies and storage (`app_webview/`) | `CookieManager.getInstance().removeAllCookies(null)`, `WebStorage.getInstance().deleteAllData()` |
| Android Keystore keys | `KeyStore.getInstance("AndroidKeyStore")` then `deleteEntry(alias)` for each alias |
| Accounts added through `AccountManager` | `removeAccountExplicitly(account)` |
| Push registration | Delete the messaging token and unbind it on the server |
| Scheduled work and notifications | Cancel `WorkManager` jobs and alarms; `NotificationManager.cancelAll()` |
| Files written to shared storage (`MediaStore`: Pictures, Downloads, Documents) | Delete what the app created, or tell the user they remain. These files **survive uninstall** |
| Credentials saved to Block Store (designed to survive reinstall) | Delete them on account deletion |
| Auto Backup copies in the user's cloud backup | Only replaced at the next backup; exclude account data from backup in the first place (`dataExtractionRules`; see [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/)) |

The simplest complete answer for "delete my account on this device" is [`ActivityManager.clearApplicationUserData()`](https://developer.android.com/reference/android/app/ActivityManager#clearApplicationUserData%28%29) (API 19+). It is equivalent to the user tapping *Clear storage* in Settings: it erases the app's private data and its private area on external storage, revokes its runtime permissions, clears its notifications and URI grants, and kills the process. It does not touch `MediaStore` files or anything held by the server or by other apps, and because it kills the process the server-side deletion must have completed (or be queued durably on the server) before you call it.

### iOS: data the app leaves on the device

Deleting an iOS app removes its data container (`Documents/`, `Library/` including `Preferences/` and `Caches/`, `tmp/`). It does **not** remove:

- **Keychain items.** They belong to the device's Keychain, not the container, and survive app deletion. A reinstall with the same access group reads the old refresh token. Our [MASWE-0024 note](/mobile/maswe-0024-sensitive-data-accessible-after-session-termination/) and [MASWE-0001 note](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/) cover this in depth, including the first-launch clean-up pattern; on account deletion the app must call `SecItemDelete` for every class it uses (`kSecClassGenericPassword`, `kSecClassInternetPassword`, `kSecClassKey`, `kSecClassCertificate`, `kSecClassIdentity`), with `kSecAttrSynchronizable: kSecAttrSynchronizableAny` so iCloud Keychain copies go too.
- **App group containers** shared with extensions or sibling apps (`FileManager.containerURL(forSecurityApplicationGroupIdentifier:)`, `UserDefaults(suiteName:)`). They are removed only when the last app in the group is deleted.
- **iCloud data**: CloudKit private database records, iCloud Drive documents, `NSUbiquitousKeyValueStore` values. These follow the Apple Account to every device and survive app deletion; the app must delete them explicitly.
- **Data written to system stores**: HealthKit samples the app saved, Contacts or Calendar entries it created, photos it saved to the library, Spotlight items (`CSSearchableIndex`) and donated Siri/Shortcuts interactions (`INInteraction`).

While the app stays installed, account deletion should also clear `UserDefaults` (`removePersistentDomain(forName:)` for the bundle identifier and any suites), files and databases (Core Data / SwiftData stores, SQLite, Realm), `URLCache` and `HTTPCookieStorage`, `WKWebsiteDataStore` website data, delivered and pending notifications, and the APNs token binding on the server. *Offload App* in Settings keeps documents and data by design; that is the user's choice, not a finding.

### Both platforms: access, export and rectification

**Access and export** are usually implemented in one of three ways: an in-app viewer ("Your data"), an asynchronous export job that emails a download link, or a web privacy centre. Whichever it is, check:

- **Completeness.** The export should cover the categories the privacy policy and store declarations say are collected, including derived and observed data (inferred interests, location history, device and login history) and not only the profile row. Under Art. 15 the user is also entitled to the purposes, recipients, retention and source, which usually live in the privacy policy rather than the file.
- **Format.** For portability (Art. 20), structured and machine-readable: JSON or CSV in a ZIP, with media files alongside. A PDF or a screenshot-style HTML page satisfies "access" at best.
- **Delivery.** The export contains everything sensitive about the user in one file, so treat it like a credential: generated only after re-authentication, delivered to the verified address or inside the authenticated session, through a link that is unguessable, short-lived and bound to the account. On the device, an app that saves the export into shared storage (`Downloads` via `MediaStore`, or the iOS Files app's public folders) leaves it readable by other apps and behind after uninstall ([MASWE-0002](/mobile/maswe-0002-sensitive-data-unencrypted-outside-private-storage/)).
- **Other people's data.** Messages and shared content naturally include others' data; hidden fields of other users (their phone number or email) should not appear just because they are in the same table.

**Rectification** means the user can correct their data: editable profile fields, a route (with proportionate verification) for fields the user cannot change directly such as legal name or date of birth, and propagation of the corrected value to copies the backend shared (Art. 19). Changing the email address or phone number is also an account-takeover path, so it must be verified on the new address and notified to the old one; that is an AUTH question we touch on in [GT-PRIV-0076-4](#gt-priv-0076-4-rectification-and-opt-out-controls-android-and-ios).

### Both platforms: opt-out controls that actually stop processing

Opt-outs typically cover product analytics, personalised advertising, "sale or sharing" of data (CCPA/CPRA), marketing communications, personalisation and recommendations, location history, and the use of content for model training. Each switch is only real if it reaches the code that does the processing:

- **SDK collection controls.** Most analytics and crash-reporting SDKs expose a collection switch (for example `setAnalyticsCollectionEnabled(false)`, a crash-reporting `setCrashlyticsCollectionEnabled(false)`, consent-mode or "consent status" APIs in ads SDKs) and a manifest or `Info.plist` key to start disabled. If the switch is applied after the SDK has already initialised and sent its first batch, the opt-out leaks every cold start.
- **Platform signals.** On Android, the user can delete the advertising ID, after which apps receive a string of zeros instead of an ID; on iOS, denying App Tracking Transparency also gives the app an all-zero IDFA. An in-app opt-out should be honoured in addition to these, not replaced by them. Identifier use is [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/).
- **Server-side processing.** Many opt-outs only matter on the server (marketing lists, data sharing with partners, model training). The app should store the choice server-side, not only in local preferences, so it applies on every device and to processing that never touches the app.
- **Persistence.** The choice must survive app restarts, updates, reinstall (once the user signs in again) and sign-in on a second device.

Where the processing relied on consent, the opt-out is consent withdrawal ([MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/)); where it relied on legitimate interests, it is an objection under Art. 21. Either way the technical test is the same: turn it off and watch the traffic.

## Tests

None of these are OWASP tests. They need test accounts you control on a test device; nothing here should be run against real users' accounts. For traffic capture, set up a proxy as in our [traffic interception lab](/mobile/mobile-traffic-interception-lab/) (OWASP techniques [MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/), [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/) and [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/)), with certificate pinning bypassed on your own build or device if needed.

### GT-PRIV-0076-1: Account deletion flow (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Checks that the user can find and complete account deletion from inside the app and through the web link, that the flow is honest about scope, timing and retention, that it does not obstruct the user, and that it deletes rather than deactivates. It also checks the deletion endpoint's authorisation.

#### Prerequisites

- The production build from the store on an Android and an iOS test device, and the store listing (Play: *Data safety* section; App Store: product page and App Privacy).
- At least two test accounts per sign-in method the app supports (email and password, phone, Sign in with Apple, Google or other social sign-in, guest accounts). Keep account B for the authorisation check.
- A proxy capturing the app's traffic, and the privacy policy.

#### Steps

1. **Find the path.** From the home screen, look for deletion where users would look: profile, account settings, privacy settings. Record the path and the number of steps. Search the help pages only after trying the app, as a user would.
2. **Check the web route.** On Google Play, open the listing's *Data safety* section and follow the account deletion link; on the App Store, check the Privacy Choices link if there is one. The page must work without the app, name the app, and let you request deletion of the account and data.
3. **Walk the flow for each sign-in method** and record every screen:
   - Does it say what will be deleted, what is retained (and why and for how long), and when deletion completes?
   - Does it require re-authentication that fits the sign-in method? An account created with Sign in with Apple has no password to type; a flow that demands one blocks that user.
   - Does it push the user to a phone call, email or chat (acceptable on iOS only for highly regulated industries)?
   - Look for obstruction: guilt-tripping copy, repeated "are you sure" loops, a pre-selected "deactivate instead", a mandatory survey, or requiring the user to cancel a subscription without explaining how. [EDPB Guidelines 03/2022 on deceptive design patterns](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-032022-deceptive-design-patterns-social-media_en) describe these patterns and are a useful vocabulary for the report.
   - With an active subscription (sandbox or test track purchase): is the user told billing continues through the store?
4. **Check it is deletion.** After completing the flow, try to sign in with the same credentials. If the account comes back ("Welcome back! Your account has been reactivated") outside a disclosed grace period, it was deactivation. If there is a grace period, check that immediate deletion is also available where the store requires it and note the period.
5. **Check the confirmation.** The app or an email should confirm the request and, for asynchronous deletion, its completion.
6. **Capture the API call** and check its authorisation. With account A's session, look at how the target account is identified (`DELETE /v1/me` is safest; `DELETE /v1/users/1001` needs a check). Replay A's request with **your own** account B's identifier: it must fail with 403 or 404 and B must be intact. Also check whether the endpoint needs a fresh authentication proof (a re-auth token or a step-up challenge) or accepts any valid session token.

#### Observation

The path and step count, screenshots of each screen, the web route's behaviour, the request and response of the deletion call, the result of the sign-in attempt afterwards and of the cross-account replay.

#### Evaluation

The test **fails** if:

- the app supports account creation and has no in-app deletion path (both stores), or no working web route (Google Play);
- deletion only deactivates or freezes the account, or signing in again restores it outside a disclosed grace period;
- deletion requires email, phone or chat in an app outside a highly regulated industry, or the flow obstructs the user beyond a reasonable confirmation;
- a sign-in method or a guest account cannot be deleted;
- the endpoint deletes another account when given its identifier (rate this as a security vulnerability, see [Rating findings](#rating-findings)).

It **passes** if every account type can be deleted from the app in a few clear steps, the flow states scope, retention and timing, the web route works, and the endpoint acts only on the caller's own account after re-authentication.

#### Demo

Illustrative capture of a deletion flow that only deactivates:

```text
POST /v2/account/close HTTP/2
Host: api.example.com
Authorization: Bearer <session token of test account A>

HTTP/2 200
{"status":"closed","reactivatable_until":null,"message":"Your account has been closed."}

(ten minutes later, signing in again with the same credentials)
POST /v2/auth/login  ->  200 {"user_id":"1001","notice":"Welcome back! Your account is active again."}
```

and of a compliant one:

```text
DELETE /v2/me HTTP/2
Authorization: Bearer <session token of test account A>
X-Reauth-Token: <proof from the re-authentication step>

HTTP/2 202
{"deletion_id":"d-7f3a","scheduled_completion":"2026-11-24","retained":["invoices (6 years, legal obligation)"]}

POST /v2/auth/login  ->  401 {"error":"invalid_credentials"}
```

### GT-PRIV-0076-2: Deletion effectiveness (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

GT-PRIV-0076-1 shows that the flow exists. This test checks what deletion actually achieved: tokens revoked, server data gone (as far as can be observed from outside and from the client's evidence), third-party identifiers reset, and the device cleaned. Run it on a fresh test account that you populate yourself.

#### Prerequisites

- A test account populated with realistic data: profile fields, an avatar and uploaded files, content visible to other users, location history if the app has it, contacts if the app syncs them.
- A second test account (B) that can see A's public content.
- An Android device you can inspect: rooted, or a debuggable build of the app so `run-as` works. An iOS device you can inspect: jailbroken, or a re-signed build with Frida and [objection](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/) (re-signing changes the Keychain access group, so treat Keychain results on a re-signed build as indicative).
- A proxy capture of the whole session, from sign-up to deletion.

#### Steps

1. **Record what exists before deletion.** From the proxy capture, note account A's user ID, the access and refresh tokens, the URLs of A's media, the push token the app registered, and every third-party SDK request that carries a user-level identifier (user ID, hashed email, install or app-instance ID). Submit an access/export request (GT-PRIV-0076-3) so you have a baseline of what the server holds.
2. **Snapshot local storage.**

   ```bash
   # Android (rooted test device)
   adb shell su -c 'cd /data/data/com.example.app && find . -type f | sort' > before-android.txt
   adb shell su -c 'grep -rl "tester-a@example.com" /data/data/com.example.app /sdcard/Android/data/com.example.app'
   # Android (debuggable build instead of root)
   adb shell run-as com.example.app find . -type f | sort > before-android.txt
   ```

   ```bash
   # iOS (objection session attached to the app)
   objection -g "Example App" explore
   ios keychain dump --json keychain-before.json
   env                                   # prints the container paths
   # iOS (jailbroken): list the data container and app group containers
   ssh root@<device> 'find /var/mobile/Containers/Data/Application/<UUID> -type f' | sort > before-ios.txt
   ```

3. **Delete the account** through the in-app flow and keep the capture running.
4. **Replay the tokens.** Send an authenticated request with the old access token, and a refresh request with the old refresh token. Both must fail (401 or `invalid_grant`). A token that keeps working until its natural expiry is a finding; how bad depends on the lifetime.
5. **Check identity-provider grants.** For a Sign in with Apple account, check that the app is gone from the device's Sign in with Apple list and that signing in again shows the first-time consent sheet. For other providers, check the provider's connected apps page for the test identity.
6. **Check server-side data from outside.** As account B: open A's profile and content, search for A's handle, request A's media URLs recorded in step 1 (allow time for CDN purges and note the delay). As A: request password reset and sign-in with the old credentials. After the stated completion date, ask the client to run an access request lookup for the test account's email, or ask for the deletion job's log entry.
7. **Check third parties.** In the capture after deletion, the app should stop sending A's identifiers. Look for SDK reset calls (an analytics `reset`/logout call, a new app-instance or anonymous ID) and confirm that the next SDK requests do not carry the old user ID or hashed email. Trace the SDK calls with Frida if traffic is encrypted at the payload level:

   ```bash
   # Android: which SDK identity calls run on deletion (pattern is illustrative; adjust to the SDKs present)
   frida-trace -U -f com.example.app -j '*!*setUserId*' -j '*!*resetAnalyticsData*' -j '*!*logout*'
   # iOS (Objective-C SDKs)
   frida-trace -U -f com.example.app -m '*[* setUserID*]' -m '*[* reset*]'
   ```

   Ask the client for evidence of the deletion calls their backend makes to processors (the vendor deletion API requests or tickets).
8. **Diff local storage** with the same commands as step 2, without uninstalling the app. Then, on iOS, delete and reinstall the app and dump the Keychain again: the old refresh token or user identifiers must not be there.
9. **Check push.** Trigger something that used to notify A (a message from B). Nothing should arrive on the device.

#### Observation

Token replay results, the Sign in with Apple state, what B can still see, the server's answer to the access request, SDK requests after deletion, the before/after file and Keychain diffs, and the push result.

#### Evaluation

The test **fails** if any of the following holds after the deletion has reportedly completed: old tokens are still accepted; the Sign in with Apple grant is still listed; A's profile, content or media is still reachable by B (beyond a disclosed, short CDN or grace delay); the access request shows retained data that the deletion screen or privacy policy did not disclose; SDK traffic continues to carry A's identifiers; account data, tokens or personal content remain in app storage or the Keychain; or push notifications for A still arrive. It **passes** when tokens are dead immediately, server data is gone or limited to disclosed retention, SDK identifiers are reset, the device holds nothing linked to A, and the client can evidence the processor deletion calls.

Common false positives: content that B legitimately keeps (a message A sent to B may remain in B's conversation, ideally attributed to "Deleted user"); disclosed retention under a legal obligation; cached images in **B's** app; and files A explicitly saved to the photo library or Downloads, which belong to the user, not the app.

#### Demo

Illustrative token replay and local diff after a deletion that did not clean up:

```text
$ curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $OLD_ACCESS_TOKEN" https://api.example.com/v2/me/messages
200
$ curl -s -X POST https://api.example.com/oauth/token -d grant_type=refresh_token -d refresh_token=$OLD_REFRESH_TOKEN | jq .error
null

$ diff before-android.txt after-android.txt
(no differences)
$ adb shell su -c 'grep -rl "tester-a@example.com" /data/data/com.example.app'
/data/data/com.example.app/shared_prefs/session.xml
/data/data/com.example.app/databases/messages.db
```

Illustrative iOS result after reinstalling the app:

```text
... ios keychain dump
Service              Account          Data
com.example.app.auth refresh_token    rt_0f2c...   (truncated)
```

### GT-PRIV-0076-3: Data access and export (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Checks that the user can see and obtain a copy of their data, that the copy is complete and machine-readable, and that the export is delivered only to the account holder through a channel that does not leak it.

#### Prerequisites

- The populated test account A from GT-PRIV-0076-2 (before deletion) and test account B.
- The privacy policy, the Data safety and App Privacy declarations, and your own record of what you entered and did in the app.
- A proxy capture.

#### Steps

1. **Find the control** in the app (privacy settings, "Download your data") and on the web privacy centre. Note whether the app offers it at all, or only "email us".
2. **Request the export** and record the flow: re-authentication, where the result is delivered (in-app, email, web), how long it takes. Art. 12 sets one month as the outer limit for responses; an automated export should take minutes or hours.
3. **Examine the delivery link** in the capture or the email. Check whether it requires the session, whether it is a long random token or a sequential ID, whether it expires, and whether it can be used repeatedly. Using your own two accounts: can B download A's export by swapping the export ID (`GET /v2/exports/5521` vs `5522`)? Can the link be opened in a browser that has no session?
4. **Check where the app stores it.** On Android, see whether the file lands in `Downloads` or another shared collection (`adb shell ls /sdcard/Download/`) or in app-private storage; on iOS, whether it is written to a folder exposed in the Files app (`UIFileSharingEnabled`, `LSSupportsOpeningDocumentsInPlace` in `Info.plist`). Shared locations are readable by other apps with storage access and survive uninstall.
5. **Assess completeness.** Compare the export with the declared data categories and with what you know the account contains: profile, content, uploads, messages, contacts, location history, device and login history, consents given, inferred interests or segments, linked third-party accounts. Missing categories are the finding; list them.
6. **Assess the format.** JSON or CSV with documented fields is machine-readable; a PDF or HTML-only rendering is not, for portability purposes.
7. **Check for other users' hidden data.** Search the export for B's email and phone number (which B set as hidden). They should not appear unless B shared them with A.

#### Observation

The flow and timing, the delivery mechanism and link properties, the cross-account result, the storage location on the device, a completeness table (declared category, present in export yes/no), and the file format.

#### Evaluation

The test **fails** if there is no way to access the data other than an unstructured support request, if the export omits declared categories of personal data without explanation, if it is not machine-readable where portability applies, if the delivery link works without authentication and does not expire, if another account's export can be retrieved, or if the app writes the export unencrypted to shared storage. It **passes** with an in-app or web self-service export that is complete, machine-readable, delivered after re-authentication through an expiring, account-bound link, and stored privately on the device.

#### Demo

Illustrative export delivery with a weak link, followed by the cross-account check using test account B's session:

```text
GET /v2/exports/5521/download HTTP/2       (no Authorization header)
HTTP/2 302 Location: https://files.example.com/exports/5521.zip

GET /v2/exports/5522/download HTTP/2
Authorization: Bearer <session token of test account B>
HTTP/2 200 (export of test account A)
```

### GT-PRIV-0076-4: Rectification and opt-out controls (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Checks that the user can correct their personal data and that each privacy opt-out the app offers does what it says: it stops the related traffic and processing, persists, and applies across devices. This is where "the switch exists" most often differs from "the switch works".

#### Prerequisites

- Test accounts and devices as above; a proxy; Frida on a rooted/jailbroken test device or a patched build.
- The list of the app's privacy switches and the SDKs present (from the SDK inventory and the traffic).

#### Steps

1. **Rectification.** Edit every profile field. For each, check the API response and a second view (account B, the web app, the export) to confirm the new value is used everywhere and the old one does not linger in other endpoints. For fields that cannot be edited in the app (legal name, date of birth), check that a route exists. Change the email address and the phone number: the new value should be verified before it takes effect and the old one notified, otherwise this is an account-takeover path ([AUTH hub](/mobile/masvs-auth-authentication-guide/)).
2. **Baseline the traffic.** With all optional processing allowed, use the app for a few minutes and save the capture. List the third-party hosts (analytics, attribution, crash reporting, ads) and the first-party event endpoints.
3. **Turn each opt-out off one at a time** (analytics, personalised ads, "do not sell or share", marketing, personalisation, location history). For each:
   - Use the same features again and capture. The related hosts or event endpoints should stop receiving events, or switch to a documented non-identifying mode.
   - Force-stop and relaunch the app and capture the **cold start**: early SDK initialisation is where opt-outs leak.
   - Update or reinstall the app and sign in again: the choice should be restored from the server.
   - Sign in on the second device: the same choice should apply.
4. **Trace the SDK switches** to confirm the app passes the choice to the SDK, and when:

   ```bash
   # Android: collection switches called by the app (adjust the patterns to the SDKs in the app)
   frida-trace -U -f com.example.app -j '*!set*CollectionEnabled*' -j '*!setConsent*'
   # iOS
   frida-trace -U -f com.example.app -m '*[* set*CollectionEnabled*]' -m '*[* setConsent*]'
   ```

   Compare the timestamp of the first SDK network request with the first switch call.
5. **Check platform signals.** On Android, delete the advertising ID (the *Ads* entry under the Privacy or Google settings, depending on the version) and on iOS deny tracking; confirm that ad requests no longer carry a non-zero advertising identifier and that the app does not substitute another persistent identifier ([MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/)).
6. **Check server-side opt-outs** that you can observe: a marketing opt-out should stop marketing email to the test address within the stated time.

Filter captures by host to compare before and after, for example with mitmproxy's dump tool:

```bash
mitmdump -nr optout-coldstart.flows "~d analytics.example.net | ~d ads.example.org"
```

#### Observation

For each field and switch: what changed in the UI, in the API and in the traffic; the cold-start capture; persistence after update, reinstall and on the second device; the Frida trace showing switch calls and their timing.

#### Evaluation

The test **fails** if a field of personal data cannot be corrected and there is no alternative route; if a corrected value persists in other endpoints or copies; if email or phone changes take effect without verification; if, with an opt-out off, identifying events still reach the related third party or endpoint (including only at cold start); if the choice is lost on restart, update, reinstall or on another device; or if a platform signal is ignored. It **passes** when edits propagate, sensitive identity changes are verified, and every opt-out stops the related traffic from the first request onwards and is stored server-side.

Not every request after an opt-out is a failure. SDK configuration fetches, strictly necessary crash reporting the user was told about, and consent-mode pings that carry no identifiers and are documented may be acceptable; describe them precisely and let the client's privacy team judge the basis. A request that still carries the user ID, an advertising ID or a persistent install ID to an analytics or ads host is not in that category.

#### Demo

Illustrative cold-start leak: the opt-out is read from preferences after the analytics SDK has already started.

```kotlin
class App : Application() {
    override fun onCreate() {
        super.onCreate()
        Analytics.init(this)                           // starts collecting and sends app_open
        val optedOut = getSharedPreferences("privacy", MODE_PRIVATE)
            .getBoolean("analytics_opt_out", false)
        Analytics.setCollectionEnabled(!optedOut)      // too late for the first batch
    }
}
```

```text
(cold start, analytics opt-out ON; illustrative)
12:00:01.120  POST https://analytics.example.net/v1/batch   {"events":["app_open"],"user_id":"1001","install_id":"9c1e..."}
12:00:01.410  Frida: setCollectionEnabled(false)
```

The fix is to start the SDK disabled (its manifest or `Info.plist` "collection disabled by default" key) and enable it only after reading the stored choice.

## Secure implementation

OWASP has no best practices for this weakness. What we recommend:

- **One deletion pipeline.** A server-side job, triggered by the app, the web route and support alike, that walks a registry of every system holding personal data (databases, object storage, search, analytics, CRM, processors' deletion APIs), records each step, and reports completion to the user. New data stores must be added to the registry before they go live.
- **Revoke before you delete.** Invalidate all sessions and refresh tokens, revoke identity-provider grants (Sign in with Apple `/auth/revoke`), and unbind push tokens as the first step, so nothing can act on the account while the rest of the job runs.
- **Clean the device as part of the flow**, after the server has accepted the request:

  ```kotlin
  // Android: full local wipe once the server has confirmed the deletion request.
  suspend fun onAccountDeleted(context: Context) {
      messaging.deleteToken()                      // push token (SDK-specific call)
      analytics.resetUser()                        // new anonymous IDs (SDK-specific call)
      val am = context.getSystemService(ActivityManager::class.java)
      am.clearApplicationUserData()                // wipes private storage, revokes permissions, kills the app
  }
  ```

  ```swift
  // iOS: remove what survives in the Keychain and outside the container.
  func wipeLocalAccountData() {
      for itemClass in [kSecClassGenericPassword, kSecClassInternetPassword,
                        kSecClassKey, kSecClassCertificate, kSecClassIdentity] {
          let query: [String: Any] = [kSecClass as String: itemClass,
                                      kSecAttrSynchronizable as String: kSecAttrSynchronizableAny]
          SecItemDelete(query as CFDictionary)
      }
      if let id = Bundle.main.bundleIdentifier {
          UserDefaults.standard.removePersistentDomain(forName: id)
      }
      URLCache.shared.removeAllCachedResponses()
      HTTPCookieStorage.shared.removeCookies(since: .distantPast)
      WKWebsiteDataStore.default().removeData(ofTypes: WKWebsiteDataStore.allWebsiteDataTypes(),
                                              modifiedSince: .distantPast) { }
      CSSearchableIndex.default().deleteAllSearchableItems { _ in }
      UNUserNotificationCenter.current().removeAllDeliveredNotifications()
      UNUserNotificationCenter.current().removeAllPendingNotificationRequests()
      // Also: app group containers, Core Data / SwiftData stores, CloudKit and iCloud key-value data.
  }
  ```

  On iOS, keep the first-launch Keychain clean-up from our [MASWE-0024 note](/mobile/maswe-0024-sensitive-data-accessible-after-session-termination/) as well, for users who delete the app instead of the account.
- **Self-service export** generated asynchronously as JSON/CSV plus media, available inside the authenticated session or through a single-use, expiring link bound to the account, with re-authentication before it is generated.
- **Privacy settings stored server-side** and applied to SDK initialisation: start every optional SDK disabled, read the choice, then enable. Add an automated check in QA that captures cold-start traffic with each opt-out set.
- **Honest UI.** A deletion screen that says what goes, what stays and why, and when it is done; no obstruction patterns; the same visual weight for "Delete" and "Cancel".
- **Keep the declarations in step**: the Data safety deletion answers and URL, the App Privacy Choices URL and the privacy policy's retention section must describe the same process ([MASWE-0072](/mobile/maswe-0072-inadequate-privacy-policy/), [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/)).

## Rating findings

We follow the series-wide rule from the [PRIVACY hub](/mobile/masvs-privacy-privacy-testing-guide/): rate by the personal data affected beyond what is necessary, declared or consented; its sensitivity; scale and reversibility; and whether the behaviour contradicts the app's own declarations or store policy. Severity is not a statement about regulatory liability; that assessment belongs to the client's legal team.

| Rating | Conditions |
|---|---|
| **High** | No way to delete an account that holds sensitive data (health, precise location history, financial, children's data, private messages); deletion reported as complete while the server keeps processing the data undisclosed; analytics or ads opt-outs that are ignored so identifying data keeps flowing to third parties; old tokens accepted indefinitely after deletion. |
| **Medium** | No in-app deletion or no working web route (store non-compliance) for an app with ordinary personal data; deactivation presented as deletion; deletion by email or support only; tokens valid until natural expiry after deletion; account data or tokens left on the device (including the iOS Keychain after reinstall); export missing major categories or delivered through an unauthenticated, non-expiring link; opt-out leaking only at cold start; email change without verification. |
| **Low** | Deletion path hard to find but working; missing completion confirmation or timeline; export not machine-readable; a field that cannot be edited but has a support route; an opt-out not synced across devices. |
| **Info** | Disclosed retention under a legal obligation; content legitimately kept by other users, attributed to a deleted user; observations about vendor-side deletion that only the client can evidence. |

**Security findings in these flows are rated on the normal vulnerability scale, not this one.** If the deletion or export endpoint acts on another account's identifier, that is broken object-level authorisation ([OWASP API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)) with account destruction or full data disclosure as impact: High to Critical. Raise privacy findings a level for apps aimed at children or processing special-category data, and when the gap contradicts a store declaration (for example a Data safety answer that says users can request deletion).

In the report give: the account types and builds tested, the path and screenshots, the requests and responses (tokens redacted), before/after evidence (diffs, Keychain dump extracts, captures), what the client needs to confirm on their side (processor deletion calls, backup retention), and the store rule or article the gap relates to for the legal team to assess.

## References

- OWASP MASWE: [MASWE-0076: Lack of Proper Data Management Controls](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0076/); related [MASWE-0077](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0077/), [MASWE-0078](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0078/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PRIVACY-4](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-4/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/), [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/), [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/) (CC BY-SA 4.0)
- OWASP MASTG tools: [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [objection (MASTG-TOOL-0038)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/), [Burp Suite (MASTG-TOOL-0077)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/), [mitmproxy (MASTG-TOOL-0097)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/) (CC BY-SA 4.0)
- Law and guidance: [GDPR (EUR-Lex)](https://eur-lex.europa.eu/eli/reg/2016/679/oj) Art. 5, 7, 12–22; [UK GDPR (legislation.gov.uk)](https://www.legislation.gov.uk/eur/2016/679/contents); ICO: [individual rights](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/), [right of access](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-of-access/), [right to erasure](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-erasure/), [right to data portability](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-data-portability/); EDPB: [Guidelines 01/2022 on the right of access](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-012022-data-subject-rights-right-access_en), [Guidelines 03/2022 on deceptive design patterns](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-032022-deceptive-design-patterns-social-media_en); [CCPA (California AG)](https://oag.ca.gov/privacy/ccpa)
- Google Play: [Understanding Google Play's app account deletion requirements](https://support.google.com/googleplay/android-developer/answer/13327111), [User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311), [Data safety section](https://support.google.com/googleplay/android-developer/answer/10787469)
- Apple: [App Review Guidelines 5.1.1](https://developer.apple.com/app-store/review/guidelines/#data-collection-and-storage), [Offering account deletion in your app](https://developer.apple.com/support/offering-account-deletion-in-your-app/), [App Privacy details (privacy links)](https://developer.apple.com/app-store/app-privacy-details/), [Revoke tokens (Sign in with Apple REST API)](https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens), [Processing changes for Sign in with Apple accounts](https://developer.apple.com/documentation/signinwithapple/processing-changes-for-sign-in-with-apple-accounts), [`WKWebsiteDataStore`](https://developer.apple.com/documentation/webkit/wkwebsitedatastore), [`NSUbiquitousKeyValueStore`](https://developer.apple.com/documentation/foundation/nsubiquitouskeyvaluestore)
- Android: [`ActivityManager.clearApplicationUserData`](https://developer.android.com/reference/android/app/ActivityManager#clearApplicationUserData%28%29), [Auto Backup](https://developer.android.com/guide/topics/data/autobackup)
- Third-party deletion example: [Google Analytics User Deletion API](https://developers.google.com/analytics/devguides/config/userdeletion/v3)
- OWASP API Security Top 10 2023: [API1 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- CWE: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)
- Sibling notes: [PRIVACY hub](/mobile/masvs-privacy-privacy-testing-guide/), [MASWE-0077](/mobile/maswe-0077-inadequate-data-visibility-controls/), [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/), [MASWE-0071](/mobile/maswe-0071-inadequate-privacy-defaults/), [MASWE-0072](/mobile/maswe-0072-inadequate-privacy-policy/), [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/), [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/); STORAGE: [STORAGE hub](/mobile/masvs-storage-1-secure-storage-guide/), [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/), [MASWE-0002](/mobile/maswe-0002-sensitive-data-unencrypted-outside-private-storage/); AUTH: [MASWE-0024](/mobile/maswe-0024-sensitive-data-accessible-after-session-termination/), [AUTH hub](/mobile/masvs-auth-authentication-guide/)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
