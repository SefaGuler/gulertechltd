---
title: "MASWE-0067: Lack of Anonymization or Pseudonymisation Measures"
date: 2026-11-10 22:01:00 +0000
subcategory: privacy
summary: "Testing what personal data an app's analytics, crash and attribution traffic carries, and whether its hashing or pseudonymisation actually de-identifies."
refs: [MASWE-0067, MASVS-PRIVACY-2, CWE-359]
tags: [android, ios, masvs-privacy, pseudonymisation, analytics, gdpr]
---

This note is part of our [MASVS-PRIVACY guide](/mobile/masvs-privacy-privacy-testing-guide/) and covers OWASP [MASWE-0067](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0067/): an app that sends personal data off the device in a form that still identifies the person, when a de-identified form would do the job. In mobile apps this rarely means the app's own core API: a banking app has to send the account number to the bank. It means everything else that leaves the device. That covers analytics events with the email address in a parameter, crash reports that carry a support-chat message, attribution SDKs that receive a "hashed" phone number, location reported to five decimal places when a city would do, photos uploaded with GPS in the EXIF, and free text forwarded to an AI service unredacted. OWASP has no tests and no Knowledge items for this weakness, so everything below the overview is ours: the legal definitions a tester needs to get right (and the one most teams get wrong: a SHA-256 of an email address is not anonymous), the de-identification techniques that work at the app and SDK boundary, three tests that find the problem in traffic, code and hashing constructions, and how to rate it.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Android and iOS: personal, pseudonymous and anonymous data](#android-and-ios-personal-pseudonymous-and-anonymous-data)
  - [Android and iOS: why a hashed email or phone number is still personal data](#android-and-ios-why-a-hashed-email-or-phone-number-is-still-personal-data)
  - [Android and iOS: de-identification techniques at the app and SDK boundary](#android-and-ios-de-identification-techniques-at-the-app-and-sdk-boundary)
  - [Android and iOS: what analytics, crash and attribution SDKs carry](#android-and-ios-what-analytics-crash-and-attribution-sdks-carry)
  - [Android: platform behaviour that affects de-identification](#android-platform-behaviour-that-affects-de-identification)
  - [iOS: platform behaviour that affects de-identification](#ios-platform-behaviour-that-affects-de-identification)
  - [Android and iOS: store declarations that depend on de-identification](#android-and-ios-store-declarations-that-depend-on-de-identification)
- [Tests](#tests)
  - [GT-PRIV-0067-1: Personal data in analytics, crash and attribution payloads (Android and iOS)](#gt-priv-0067-1-personal-data-in-analytics-crash-and-attribution-payloads-android-and-ios)
  - [GT-PRIV-0067-2: SDK initialisation and event-logging calls that pass personal data (Android and iOS)](#gt-priv-0067-2-sdk-initialisation-and-event-logging-calls-that-pass-personal-data-android-and-ios)
  - [GT-PRIV-0067-3: Hashing and pseudonymisation construction review (Android and iOS)](#gt-priv-0067-3-hashing-and-pseudonymisation-construction-review-android-and-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app uses anonymization or pseudonymisation measures."* MASWE-0067 maps to **MASVS-PRIVACY-2** ("The app prevents identification of the user") and to [CWE-359](https://cwe.mitre.org/data/definitions/359.html) (Exposure of Private Personal Information to an Unauthorized Actor). In OWASP's beta numbering it was part of MASWE-0109. It carries the **P** profile (privacy assessments for apps that process personal data) and the **EUDIW** profile (EU Digital Identity Wallet).

The control text of PRIVACY-2 is worth reading closely, because it sets the bar this note tests against: use "unlinkability techniques like data abstraction, anonymization and pseudonymization", and build "technical barriers" so that a signal collected for one purpose (the example given is a fraud-detection fingerprint) is not reused for another (audience measurement in an analytics SDK).

**OWASP has no tests and no Knowledge items for MASWE-0067**, and there are no legacy v1 tests to replace: privacy only arrived in MASVS v2. The `## Background` section and the three `GT-PRIV-0067-x` tests below are Guler Tech methodology.

This is technical testing guidance, not legal advice. Where GDPR, UK GDPR, the ePrivacy Directive or PECR come up, the point is to tell you what to look for and what evidence to give the client's DPO or legal team. Whether a particular flow is lawful is their call.

What is covered, and by which test:

| Question | Test |
|---|---|
| Which personal data (direct identifiers, contact details, precise location, free text, metadata) actually leaves the device to analytics, crash, attribution, support and AI endpoints, and in what form? | [GT-PRIV-0067-1](#gt-priv-0067-1-personal-data-in-analytics-crash-and-attribution-payloads-android-and-ios) |
| Where in the code does the app hand personal data to an SDK (user IDs, user properties, event parameters, breadcrumbs, custom keys, logs)? | [GT-PRIV-0067-2](#gt-priv-0067-2-sdk-initialisation-and-event-logging-calls-that-pass-personal-data-android-and-ios) |
| When the app does "anonymise" or "hash" something, does the construction de-identify anything? | [GT-PRIV-0067-3](#gt-priv-0067-3-hashing-and-pseudonymisation-construction-review-android-and-ios) |

Keep the neighbours apart:

| Question | Where it lives |
|---|---|
| Which device and advertising identifiers the app reads, and whether it uses them to track people across apps or bridge resets | [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/) |
| Whether a feature could work with less data at all (on-device processing, approximate location, picker instead of permission) | [MASWE-0069](/mobile/maswe-0069-non-privacy-preserving-functionality/), [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/) |
| Whether the Data safety section and App Privacy labels match what the app collects and shares | [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) |
| Whether tracking domains are declared in the privacy manifest | [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/) |
| Whether the app asks for consent before analytics or ads SDKs start | [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/), [MASWE-0071](/mobile/maswe-0071-inadequate-privacy-defaults/) |
| Personal data written to logs, files and backups on the device | [STORAGE hub](/mobile/masvs-storage-1-secure-storage-guide/) |
| The hash and MAC primitives themselves (weak algorithms, wrong use of a MAC) | [MASWE-0008](/mobile/maswe-0008-improper-hashing/), [MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/) |
| An SDK harvesting data the app never handed it | [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) |

## Modes of Introduction

OWASP lists four modes. In assessments we see each of them in a specific, recurring shape:

**Identifiers not removed before collection.** The app sets the account email, username or phone number as the analytics "user ID" or as a user property. Event parameters carry `email`, `name` or `postcode`. Event or screen *names* embed identifiers (`checkout_user_84211`, `Profile/jane.doe@example.com`), which is worse, because the analytics backend indexes event names everywhere and nobody thinks to scrub them. Deep-link URLs with tokens or emails in the query string are recorded as screen views or network breadcrumbs.

**Pseudonymisation implemented insecurely.** The app "hashes" an email or phone number with plain SHA-256 or MD5 and sends it to an advertising or attribution SDK, then the privacy policy describes the data as anonymised. Variants: a salt or HMAC key hard-coded in the app (so every copy of the app holds it), the same pseudonym sent to every third party (so they can join their datasets on it), pseudonyms that never rotate, and a mapping table kept next to the pseudonymised data.

**Sensitive metadata not removed.** Photos and videos uploaded with GPS coordinates, camera serial numbers and timestamps in EXIF or XMP. Documents with the author's name in their properties. Audio files with location in their metadata. The user-assigned device name ("Jane's phone") sent as a device label.

**Sensitive data not redacted before sending to AI services.** Chat transcripts, support tickets, documents or images forwarded to a third-party model API for summarisation, classification or OCR with names, account numbers and health details intact, where redacting them first would not change the result the app needs.

To those we add four that come up again and again in mobile apps:

**Free text collected by default.** Search queries, form contents, support messages and in-app feedback captured by analytics auto-collection, by session-replay SDKs that record text fields, or by crash-reporting "breadcrumbs" that log every user action.

**Crash and diagnostic reports carrying personal data.** Exception messages that include the offending value (`Invalid email: jane.doe@example.com`), custom keys set to the account email for "easier support", logs attached to crash reports, screenshots or view hierarchies captured at crash time.

**Precision beyond need.** Latitude and longitude with five or more decimal places (about a metre) for a feature that needs a city; millisecond timestamps on rare events; exact date of birth when an age band would do. Precise values make records unique even when no name is attached.

**IP addresses as an afterthought.** Every request reveals the device's public IP to the receiving server. Many analytics backends can truncate or discard it, but only if configured to, and the configuration lives on the server side where the app team rarely checks it.

## Impact

- **Identification and profiling by third parties.** An analytics, advertising or attribution provider that receives a stable identifier (an email, a phone number, or a deterministic hash of either) can join the app's data with everything else it holds under the same key. The user's behaviour in this app becomes part of a profile they never agreed to.
- **Re-identification of "anonymous" datasets.** Precise location traces, rare events with exact timestamps and combinations of quasi-identifiers (postcode, date of birth, gender) single people out even with names removed. Datasets that the client shares, sells or publishes as "anonymised" may not be.
- **Secondary use and retention the user cannot see.** Data in third-party analytics, crash and AI systems is retained under their policies, may be used to train models, and is outside the client's deletion workflow. A user who deletes their account ([MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/)) still exists in those systems under their real email.
- **Larger blast radius in a breach.** De-identified data that leaks is a much smaller problem than identified data that leaks. Pseudonymisation is one of the measures GDPR names in Art. 32 for exactly that reason.
- **Legal, contractual and store exposure.** Claims in the privacy policy ("we only share anonymised data") or the store labels ("data not linked to you") that the traffic contradicts. The client's legal team assesses the regulatory side; the store side can mean rejection or removal.
- **Loss of trust.** Users and journalists who inspect app traffic find names and emails in analytics calls easily, and the story writes itself.

## Mitigations

- **Do not send it.** The cheapest de-identification is minimisation: an allowlisted event schema with no free text and no direct identifiers, enforced in one analytics wrapper that every call goes through.
- **Use a random, app-scoped pseudonymous ID for analytics and crash reporting**, not the account email, phone number or username. If the backend needs to link analytics to accounts, keep that link on the client's own server.
- **When an identifier must be matched with a third party, use keyed pseudonymisation on the server**: HMAC with a secret key that never ships in the app, a separate key per recipient and purpose, and rotation where linkage over time is not needed. Treat the result as personal data, because it is.
- **Coarsen before collection**: round coordinates, bucket timestamps and ages, truncate or drop IP addresses at the collection endpoint, aggregate counts on the device where possible.
- **Strip metadata** (EXIF/XMP GPS, device serials, author fields) before upload unless the feature needs it and the user knows.
- **Scrub crash reports and logs**: no custom keys or breadcrumbs with personal data, sanitised exception messages, masking in session replay, before-send hooks that remove what slipped through.
- **Redact before AI services**: remove or mask names, contact details, account numbers and health data before a prompt or document leaves for a third-party model, and use the provider's no-retention and no-training options where they exist.
- **Keep the declarations honest**: only describe data as anonymised or "not linked" if the construction supports it (see [Background](#android-and-ios-store-declarations-that-depend-on-de-identification)).

## Background

OWASP has no Knowledge item for this weakness. The sections below cover what you need to judge a finding: the legal vocabulary, why hashing is not anonymisation, the techniques that work at the app/SDK boundary, what SDKs carry by default, platform behaviour on each OS, and the store rules that hinge on de-identification.

### Android and iOS: personal, pseudonymous and anonymous data

You do not need to be a lawyer to test this weakness, but you do need to use three words correctly, because clients, SDK vendors and privacy policies routinely do not.

**Personal data** ([GDPR Art. 4(1)](https://eur-lex.europa.eu/eli/reg/2016/679/oj)) is any information relating to an identified or *identifiable* natural person, directly or indirectly, including by reference to "an identification number, location data, an online identifier". [Recital 30](https://eur-lex.europa.eu/eli/reg/2016/679/oj) spells out that device identifiers, IP addresses and cookie identifiers can make a person identifiable when combined with other information. The UK GDPR carries the same definitions ([legislation.gov.uk](https://www.legislation.gov.uk/eur/2016/679/contents)).

**Pseudonymisation** (Art. 4(5)) is processing personal data so that it "can no longer be attributed to a specific data subject without the use of additional information, provided that such additional information is kept separately and is subject to technical and organisational measures". Two points matter for testing:

- Pseudonymised data **is still personal data** (Recital 26). Pseudonymisation is a security and risk-reduction measure (Recital 28, Art. 25 data protection by design, Art. 32(1)(a) security of processing), not a way out of the GDPR.
- The definition only works if the "additional information" (the key, the salt, the mapping table) is **kept separately**. A key compiled into every copy of the app is not kept separately from anyone.

**Anonymous information** (Recital 26) is data that does not relate to an identifiable person, taking into account "all the means reasonably likely to be used" to identify someone, by the controller or by anyone else. Anonymous data is outside the GDPR. The bar is high: the Article 29 Working Party's [Opinion 05/2014 on anonymisation techniques (WP216)](https://ec.europa.eu/justice/article-29/documentation/opinion-recommendation/files/2014/wp216_en.pdf) asks whether a dataset still allows **singling out** (isolating one person's records), **linkability** (connecting records about the same person across datasets) or **inference** (deducing a value about a person). If any of the three is reasonably possible, it is not anonymous.

Current guidance you can point the client at:

- **ICO, [Anonymisation](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-sharing/anonymisation/) and [Pseudonymisation](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-sharing/anonymisation/pseudonymisation/)** (final guidance published in March 2025). It treats identifiability as a spectrum, uses the "motivated intruder" test (could a reasonably competent person with access to public resources identify someone?), and says plainly that pseudonymised data remains personal data.
- **EDPB, [Guidelines 01/2025 on Pseudonymisation](https://www.edpb.europa.eu/our-work-tools/documents/public-consultations/2025/guidelines-012025-pseudonymisation_en)**, adopted for public consultation in January 2025 (the consultation closed in March 2025). They describe pseudonymisation in terms of a *pseudonymisation domain* (who must be unable to re-attribute the data) and *pseudonymisation secrets* (keys, tables) that must be protected from that domain, and they discuss keyed cryptographic functions and per-recipient pseudonyms. At the time of writing we have only verified the consultation version (v1); check the EDPB site for a final version.
- **CJEU, [EDPS v SRB (C-413/23 P)](https://curia.europa.eu/juris/liste.jsf?num=C-413/23)**, judgment of 4 September 2025. The Court held that pseudonymised data is not automatically personal data *for every recipient*: for a recipient that has no means reasonably likely to re-identify the people, it may not be. It remains personal data for the controller that holds the key. Do not let this be read as "hashing is fine": an advertising or attribution platform that receives a hashed email and holds the same emails (hashed the same way) for its own users plainly has the means to re-identify. That is the whole point of sending it.

Two adjacent regimes come up in the same conversations:

- **Reading or storing identifiers on the device** falls under Art. 5(3) of the [ePrivacy Directive](https://eur-lex.europa.eu/eli/dir/2002/58/oj) and, in the UK, [PECR regulation 6](https://www.legislation.gov.uk/uksi/2003/2426/regulation/6): consent unless strictly necessary for the service the user asked for. The EDPB's [Guidelines 2/2023 on the technical scope of Art. 5(3)](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-22023-technical-scope-art-53-eprivacy-directive_en) read that broadly enough to include SDKs and identifiers in apps. Identifier collection is covered in [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/); the UK has since changed some PECR exemptions (for example for some analytics) through the Data (Use and Access) Act 2025, which the client's legal team should check for commencement and scope.
- **CCPA/CPRA** (California) defines *deidentified* and *pseudonymize* in Cal. Civ. Code § 1798.140 in terms close to the GDPR's, and requires public commitments and contractual controls for data to count as deidentified. A hashed email disclosed for cross-context behavioural advertising is generally treated as "sharing" personal information; the client's counsel decides.

### Android and iOS: why a hashed email or phone number is still personal data

This is the misunderstanding you will meet most often, usually in the form "we don't send emails to the attribution partner, only SHA-256 hashes". The US FTC wrote a blog post with the title [No, hashing still doesn't make your data anonymous](https://www.ftc.gov/policy/advocacy-research/tech-at-ftc/2024/07/no-hashing-still-doesnt-make-your-data-anonymous) (July 2024), and the European position is the same. An unsalted SHA-256 of a normalised email address fails every one of the WP216 tests:

1. **It is a stable unique identifier.** The same email always produces the same hash, in every app, on every device, for every company that normalises the same way (trim, lowercase, sometimes strip dots and `+tags`). Singling out and linkability are not side effects; they are what the hash is used for. Advertising "customer match" and attribution products work by joining hashed emails from different sources.
2. **The recipient can re-identify it by design.** A platform that holds email addresses for its own users hashes them the same way and gets a lookup table. For that recipient, the hash is just the email in a different encoding.
3. **The input space is small enough to enumerate.** Phone numbers are the obvious case: a national numbering plan has at most a few billion valid numbers, and hashing all of them with SHA-256 takes a commodity GPU minutes. Emails are not enumerable in the abstract, but breach compilations and marketing lists contain billions of real addresses, and a dictionary of candidates is all an attacker needs to reverse the ones that matter.
4. **A global salt changes nothing.** A salt that is the same for every user and shipped in the app is just part of the hash function. Anyone with the APK or IPA can repeat the computation. It also does not stop the recipient from linking records, because the salted hash is still stable.

What does help, in increasing order of strength:

| Construction | Who can re-identify | Linkable across recipients? | Verdict |
|---|---|---|---|
| Plain or globally salted hash (`SHA-256(email)`), computed in the app | Anyone with candidate emails or numbers; any recipient holding the same data | Yes | Pseudonymous at best. Personal data for every realistic recipient. |
| HMAC with a key compiled into the app | Anyone who extracts the key from the app | Yes, if all recipients get the same value | No better than a salted hash. |
| HMAC (or other keyed PRF) computed on the **server**, key held only there, **separate key per recipient and purpose** | Only the key holder | No: each recipient gets a different pseudonym for the same person | Proper pseudonymisation. Still personal data for the controller; may reduce the recipient's ability to identify. |
| Random token per user (or per user and recipient) with the mapping held server-side | Only the holder of the mapping table | No, if tokens differ per recipient | Proper pseudonymisation, same caveats. |
| Rotating keys or tokens (per day, per study) | Only the key holder, and only within a period | No, and not over time either | Stronger unlinkability; useful for analytics that do not need long-term cohorts. |
| Aggregates with minimum counts, noise, or no per-user rows at all | Nobody, if done well | Not applicable | Can be anonymous. Needs proper analysis (see below). |

Two further points to check in practice:

- **Keyed hashing for matching with a partner who has the same data** (a "clean room" or customer-match upload) is still sharing personal data with that partner. The key protects the data in transit and at rest; it does not make the flow anonymous. It needs a lawful basis, and on iOS it is **tracking** in Apple's terms if the purpose is advertising: Apple's [User Privacy and Data Use](https://developer.apple.com/app-store/user-privacy-and-data-use/) FAQ answers "can I use a hashed email address or hashed phone number to track that user without ATT permission?" with "No". That angle belongs to [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/).
- **Truncating a hash** (sending the first 8 hex characters) reduces uniqueness only if the truncated value really collides across many people. With 32 bits and a user base of a few million, most values are still unique. Do not accept truncation as anonymisation without numbers.

### Android and iOS: de-identification techniques at the app and SDK boundary

These are the techniques that can be implemented, and therefore tested, in the app or at its first server hop. They are listed roughly from simplest to most specialised.

**Minimisation and allowlisting.** Decide which events and parameters analytics needs, and route every call through one wrapper that drops anything not on the list. This beats any downstream scrubbing, because it fails closed. Things that should almost never be on the list: free text, email, phone, names, full addresses, exact date of birth, government IDs, payment data, health data, contact lists, precise location.

**Pseudonymous app-scoped identifiers.** For analytics and crash reporting, a random UUID generated at install (or the SDK's own installation ID) is enough to count users and group events. It does not need to be the account ID, and it should not be the email. Identifier choice and scope are covered in depth in [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/).

**Server-side keyed pseudonymisation.** Where a stable pseudonym tied to the account is needed (cross-device analytics, a research dataset), compute it on the client's server as `HMAC-SHA256(key_purpose, account_id)` ([RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104)) with a key per purpose or recipient, held in a KMS and never sent to the app. The app can receive the pseudonym from its own backend and pass it to the SDK.

**Generalisation (coarsening).** Reduce precision until records stop being unique:

| Data | Typical precise form | Coarsened form | Rough effect |
|---|---|---|---|
| Latitude/longitude | 5–6 decimal places | 2 decimal places, or a geohash/grid cell, or city/region | 2 decimals is about 1.1 km of latitude; 1 decimal about 11 km |
| Timestamps | Milliseconds | Hour or day; or relative ("day 3 of trial") | Rare events stop being joinable on time |
| Age / date of birth | Full date | Year or age band (18–24, 25–34...) | Removes a classic quasi-identifier |
| Postcode | Full postcode | Outward code or district | Full UK postcodes often cover a handful of addresses |
| Device model + OS build + locale + timezone | Exact strings | Model family, major OS version | Reduces fingerprint entropy (see [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/)) |

**IP address handling.** The receiving server sees the client IP on every request, whatever the app does. What matters is whether the collection endpoint truncates (zeroes the last octet of IPv4, the last 80 bits of IPv6 is a common choice) or discards it before storage, and whether it is forwarded to further parties. This is a server-side configuration: you verify it from the SDK's or backend's documented settings and the client's configuration, not from the app traffic. A first-party proxy endpoint that strips the IP and forwards events is a common pattern.

**Aggregation and thresholds.** Send counts, not rows ("12 users opened feature X today"), and suppress small cells (no group smaller than k). On-device aggregation means the server never sees per-user events at all.

**On-device processing.** Run classification, recommendation, OCR or speech recognition on the device and send only the result, or nothing. Both platforms provide on-device ML frameworks; [MASWE-0069](/mobile/maswe-0069-non-privacy-preserving-functionality/) covers when a feature should be redesigned this way.

**Differential privacy (high level).** Adds calibrated random noise so that the presence or absence of one person changes the output only within a bound set by a privacy parameter (epsilon). In *local* differential privacy the noise is added on the device before anything is sent; in *central* differential privacy a trusted server adds noise to aggregates. It gives a mathematical guarantee that the techniques above do not, but it only fits aggregate statistics, and the guarantee depends entirely on the parameters. If a client claims differential privacy, ask for the mechanism, epsilon, and what is sent per user per day, and record that as evidence for their DPO rather than assessing the maths yourself.

**Redaction before AI services.** Detect and replace names, emails, phone numbers, account and card numbers, addresses and health terms with placeholders before sending text to a third-party model, ideally on the client's server rather than in the app (so the redaction rules and the AI provider's API key are not in the app). Pattern-based detection catches structured identifiers; names and free-form health details need a classifier and will always leak some. Combine redaction with the provider's retention and training opt-outs.

**Metadata stripping.** Remove EXIF/XMP GPS and device data from images and videos, author and revision data from documents, before upload, unless the feature needs them and the user can see that.

### Android and iOS: what analytics, crash and attribution SDKs carry

You will meet these SDK categories in almost every app. What they send *by default* is mostly device data plus their own identifiers; the personal data usually comes from the app.

| SDK category | Sends by default (typical) | Personal data usually added by the app | Usual hiding places |
|---|---|---|---|
| Product analytics | Install/instance ID, device model, OS, locale, app version, screen names, session timing, coarse location derived from IP (server-side) | User ID, user properties, event parameters | Event names, screen names, URL parameters, "auto-collected" form interactions |
| Crash and performance reporting | Stack trace, device state, breadcrumbs, network request URLs and timings | Custom keys, user ID or email "for support", log lines | Exception messages, attached logs, view hierarchies, screenshots |
| Attribution / mobile measurement | Advertising ID (when available), install referrer data, IP, user agent | Hashed email or phone for "advanced matching", purchase values, customer IDs | Event payloads named after the partner's matching feature |
| Session replay / heatmaps | Screen recordings or view trees, gestures | Everything visible on screen unless masked | Text fields, web views, images of documents |
| Support chat / feedback | Conversation, device info | Name, email, account ID, attachments | Uploaded screenshots and logs |
| AI features | Prompt and context | Whatever the user typed or the app attached | Conversation history, documents, images |

Most SDKs expose switches for the worst of this: a global "collection enabled" flag (useful for consent gating), flags to stop collecting device identifiers, masking APIs for session replay, and "before send" callbacks to scrub crash reports. Their names differ per SDK; GT-PRIV-0067-2 shows how to find the ones the app sets. On iOS, for example, one widely used analytics SDK reads `FIREBASE_ANALYTICS_COLLECTION_ENABLED` and `GOOGLE_ANALYTICS_IDFV_COLLECTION_ENABLED` from `Info.plist` ([documentation](https://firebase.google.com/docs/analytics/configure-data-collection)). The [third-party libraries note](/mobile/mastg-know-0004-third-party-libraries/) and [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) cover building the SDK inventory itself.

### Android: platform behaviour that affects de-identification

- **Location precision.** Since Android 12, users can grant approximate location only (`ACCESS_COARSE_LOCATION`), for which the platform returns a location estimate accurate to within about 3 square kilometres. An app that only holds coarse location cannot leak precise coordinates, so check the permission state first ([MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/)).
- **Location in media.** Since Android 10, apps reading media from shared storage get the location metadata redacted unless they hold `ACCESS_MEDIA_LOCATION` and request the original with `MediaStore.setRequireOriginal()` ([documentation](https://developer.android.com/training/data-storage/shared/media)). Images the app captures itself, receives through a share intent from another app, or reads from its own storage keep whatever EXIF they have. Use `androidx.exifinterface.media.ExifInterface` to remove GPS tags before upload.
- **Device and Bluetooth names** often contain the owner's first name. Third-party apps cannot read the device MAC addresses, but the user-visible device name may be reachable through Bluetooth APIs (with the Bluetooth permissions) or settings, and is personal data when it contains a name.
- **Logs.** Since Android 4.1 apps cannot read other apps' logcat output, but crash SDKs attach the app's own log buffer to reports. Anything the app logs can end up in a crash report.

### iOS: platform behaviour that affects de-identification

- **Location precision.** Since iOS 14, users can turn off *Precise Location* for an app, which then receives approximate location only. Check `CLLocationManager.accuracyAuthorization` during testing.
- **Device name.** [`UIDevice.name`](https://developer.apple.com/documentation/uikit/uidevice/name) returns a generic name ("iPhone") on iOS 16 and later; the user-assigned name ("Jane's iPhone") requires the `com.apple.developer.device-information.user-assigned-device-name` [entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.device-information.user-assigned-device-name), which Apple grants only for specific use cases. An app that has it and sends the name to analytics is sending the user's first name. Check entitlements with `codesign -d --entitlements :- Payload/App.app`.
- **Location in media.** Whether an image obtained through the photo picker or the camera carries GPS metadata depends on the API used, the user's choices in the share/picker options and the iOS version, so test with a real image rather than assume. To strip GPS when re-encoding with Image I/O, set [`kCGImageMetadataShouldExcludeGPS`](https://developer.apple.com/documentation/imageio/kcgimagemetadatashouldexcludegps) to true. Apple notes it does not remove location stored in a manufacturer MakerNote or custom XMP properties, so re-encoding without the metadata dictionary at all is safer.
- **App Privacy Report** (Settings > Privacy & Security > App Privacy Report) lists the domains an app contacted and when. It is a quick way to see which third-party hosts receive traffic, but it does not show payloads.

### Android and iOS: store declarations that depend on de-identification

Both stores give developers less to declare if data is properly de-identified. That makes the de-identification claim something you can test, and a false claim a store-policy finding:

- **Google Play Data safety** ([guidance](https://support.google.com/googleplay/android-developer/answer/10787469)): transferring data that is "fully anonymized so that it can no longer be associated with an individual user" is not "sharing". There is no comparable exemption for *collection*. Data processed only on the device or end-to-end encrypted is out of scope for collection, and "ephemeral" processing changes how it is shown, not whether it must be declared. Hashed emails and pseudonymous IDs are not "fully anonymized".
- **Apple App Privacy details** ([guidance](https://developer.apple.com/app-store/app-privacy-details/)): data counts as *linked to the user* unless it is de-identified *before collection* (Apple's examples: stripping direct identifiers such as user ID or name, and manipulating data to break and prevent re-linkage) and the developer does not link it back afterwards or combine it with datasets that would. An app that labels analytics "Data Not Linked to You" while sending the account ID with every event has a wrong label.

Declaration testing itself lives in [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/). This note supplies the evidence: what is actually in the payloads.

## Tests

All three tests are Guler Tech methodology. Run them on test devices you control, with test accounts created for the assessment, and capture only your own traffic. Never use real customer data as canaries.

### GT-PRIV-0067-1: Personal data in analytics, crash and attribution payloads (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The traffic is the ground truth. This test seeds test accounts with distinctive canary values, exercises the app, and searches all outgoing traffic, first party and third party, for those values in clear and in the common encoded and hashed forms. The result is a matrix of *which personal data, in which form, to which destination*, which is the evidence both for this weakness and for the declaration checks in [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/).

#### Prerequisites

- An Android test device or emulator and an iOS test device, with the app installed from the production channel (or a client build with the same SDK configuration).
- An interception proxy (mitmproxy or Burp Suite) trusted by the device, with certificate pinning handled for your test build if needed. Our [traffic interception lab](/mobile/mobile-traffic-interception-lab/) covers set-up on both platforms; OWASP's techniques are [MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/) (Android) and [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/) (iOS).
- At least one test account seeded with canaries that cannot occur by chance. Use reserved ranges: an email at a domain you control or `example.com` (`canary.pt7k2@example.com`), a UK drama number (Ofcom reserves `07700 900000` to `07700 900999`, so `+447700900417`), an unusual first and last name (`Quillon Testerby`), a street address that does not exist (`17 Canaryfield Lane`), a date of birth you will recognise.
- A fixed test location: set the emulator location (`adb emu geo fix <longitude> <latitude>`) or use Xcode's location simulation on a development build, so you know the exact coordinates to look for.
- The consent state recorded: run once with all optional consents refused and once with all accepted, because many SDKs change behaviour on consent ([MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/)).

#### Steps

1. **Prepare the search terms.** For each canary, compute the forms an app or SDK typically sends: as typed, normalised (trimmed, lowercased; phone in E.164 and digits-only), URL-encoded, Base64, and the hex digests MD5, SHA-1 and SHA-256 of the normalised form (SDKs that "hash for privacy" almost always use one of these). The addon below does this for you.
2. **Start the proxy with a canary search addon.** It records every request whose URL, headers or body (after content decoding) contain a canary in any form, with the destination host:

   ```python
   # canary_search.py - mitmproxy addon. Searches YOUR test account's canary
   # values in the app's own traffic. Usage:
   #   mitmdump -s canary_search.py --set canaries=canaries.txt
   import base64, hashlib, json, urllib.parse
   from mitmproxy import ctx, http

   def variants(value):
       v = value.strip()
       norm = v.lower()
       out = {"raw": v, "norm": norm,
              "url": urllib.parse.quote(v, safe=""),
              "b64": base64.b64encode(v.encode()).decode()}
       if norm.startswith("+"):
           out["digits"] = norm.lstrip("+")
       for alg in ("md5", "sha1", "sha256"):
           for label, s in (("norm", norm), ("digits", out.get("digits"))):
               if s:
                   out[alg + "_" + label] = hashlib.new(alg, s.encode()).hexdigest()
       return out

   class CanarySearch:
       def load(self, loader):
           loader.add_option("canaries", str, "canaries.txt", "one label=value per line")

       def running(self):
           self.terms = []
           with open(ctx.options.canaries) as fh:
               for line in fh:
                   if "=" in line:
                       label, value = line.rstrip("\n").split("=", 1)
                       for form, needle in variants(value).items():
                           self.terms.append((label, form, needle))

       def request(self, flow: http.HTTPFlow):
           req = flow.request
           parts = [("url", req.pretty_url),
                    ("headers", "\n".join(k + ": " + v for k, v in req.headers.items())),
                    ("body", req.get_text(strict=False) or "")]
           for where, text in parts:
               low = text.lower()
               for label, form, needle in self.terms:
                   if needle.lower() in low:
                       ctx.log.warn(json.dumps({"host": req.pretty_host, "path": req.path.split("?")[0],
                                                "canary": label, "form": form, "in": where}))

   addons = [CanarySearch()]
   ```

   With `canaries.txt` containing, for example:

   ```text
   email=canary.pt7k2@example.com
   phone=+447700900417
   name=Quillon Testerby
   address=17 Canaryfield Lane
   lat=51.50135
   lon=-0.14189
   ```

   Run `mitmdump -s canary_search.py --set canaries=canaries.txt -w capture.flows` so you keep the full capture for review. (Coordinates are matched as text; also search for truncated forms of them, step 5.) OWASP's [MASTG-TECH-0100](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0100/) shows the same idea with plain string matching; the hashed and encoded variants are what it misses.
3. **Exercise the app as a user would.** Sign up or sign in with the canary account, complete the profile, search for something distinctive, use location features, open support chat and send a message containing a canary, upload a test photo (step 6), make a test purchase if available. Background the app and bring it back: many SDKs batch events and only flush on backgrounding or after a timer, so wait a few minutes before concluding nothing was sent.
4. **Get a crash report out, without breaking anything.** If the client build has a test-crash or "send diagnostics" option, use it. Otherwise, ask the client for a build with one, or review crash payloads already in the capture (non-fatal error reports are sent routinely by many SDKs). Inspect the report on the next launch: exception message, custom keys, attached logs, breadcrumbs.
5. **Check precision and quasi-identifiers.** In the capture, look at every location field (decimal places), timestamps (resolution), date of birth or age fields, postcode fields, IP-related fields, device name fields. Note binary bodies: protobuf payloads can be decoded without the schema with `protoc --decode_raw < body.bin`; mitmproxy's protobuf view also helps.
6. **Check media metadata.** Before the test, create a photo with known GPS coordinates on the test device (camera with location tagging on, at the test location), confirm with `exiftool -gps:all test.jpg` on a copy, then upload it through the app. Find the upload in the capture, export the body (in mitmproxy: select the flow and export the request body to a file), and run `exiftool -a -G1 upload.bin`. If the server lets the account download its own upload, check the stored copy the same way.
7. **Check AI and support endpoints.** For any feature that sends user text or documents to a summariser, assistant or OCR service, send a message containing canaries and check whether they reach a third-party host verbatim.
8. **Record destinations.** For each hit, classify the host as first party (the client's own API), a first-party proxy, or a third party, and note the SDK it belongs to (from the host and the call stack in GT-PRIV-0067-2).

#### Observation

A table of canary × form × destination × consent state, the precision of location and time fields per destination, the EXIF result for uploads, and any free text seen in analytics, crash, support or AI traffic. Keep the flows (`capture.flows`) as evidence, with tokens redacted before sharing.

#### Evaluation

The test **fails** when any of the following is observed and the client cannot show it is necessary for the feature and disclosed:

- A direct identifier (email, phone, name, full address, government or customer ID) or a deterministic hash of one is sent to an analytics, crash, attribution, advertising, session-replay or AI provider.
- Free text, search queries or support messages are sent to analytics or crash reporting.
- Precise location (four or more decimal places) is sent to a third party for a feature that does not need it, or any location is sent before the relevant consent.
- Uploaded media keeps GPS metadata on the server or in transit to a third party, without the feature needing it and the user knowing.
- The app's own declarations say the data is anonymised or "not linked" while the payload contains an identifier that links it.

It **passes** when third-party payloads contain only pseudonymous app-scoped IDs and allowlisted event data, location is coarsened to what the feature needs, media metadata is stripped, and identifiers reach only the client's own backend for features that need them. Note as **observations** (not failures) identifiers sent to the client's own API for core functions (logging in sends the email), and IP addresses reaching third-party endpoints; the latter needs server-side configuration evidence from the client.

#### Demo

An app's Kotlin code that produces a typical failure:

```kotlin
// Vulnerable: account email as analytics user ID, full profile as properties,
// and the search text as an event parameter.
analytics.setUserId(account.email)
analytics.setUserProperty("address", account.addressLine1)
analytics.logEvent("search", mapOf("query" to searchBox.text.toString(),
                                   "lat" to location.latitude, "lon" to location.longitude))
attribution.trackEvent("purchase", mapOf("em" to sha256(account.email.trim().lowercase())))
```

Illustrative addon output from such an app (not from a real engagement):

```text
[12:41:07.112] {"host": "analytics.example.net", "path": "/v1/batch", "canary": "email", "form": "norm", "in": "body"}
[12:41:07.113] {"host": "analytics.example.net", "path": "/v1/batch", "canary": "address", "form": "raw", "in": "body"}
[12:41:07.113] {"host": "analytics.example.net", "path": "/v1/batch", "canary": "lat", "form": "raw", "in": "body"}
[12:41:09.540] {"host": "attribution.example.org", "path": "/events", "canary": "email", "form": "sha256_norm", "in": "body"}
```

The `sha256_norm` hit is the one teams contest. The explanation in [the hashing section](#android-and-ios-why-a-hashed-email-or-phone-number-is-still-personal-data) is what you give them.

### GT-PRIV-0067-2: SDK initialisation and event-logging calls that pass personal data (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Traffic shows what was sent during your session. Code shows what *can* be sent, including on paths you did not exercise (error handling, rare flows, other locales). This test finds where the app hands data to analytics, crash, attribution and AI SDKs, what it passes, and how the SDKs are configured, then confirms the important call sites at runtime with a trace of the app's own calls.

#### Prerequisites

- The APK (decompiled with jadx, see [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/)) and the decrypted IPA (see [MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/)); source code if the client provides it.
- semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)), rabin2 ([MASTG-TOOL-0129](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/)), `plutil`, and Frida ([MASTG-TOOL-0031](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/)) on a rooted or jailbroken test device, or a test build with Frida Gadget.
- The SDK inventory (which analytics, crash, attribution, replay and AI SDKs are present); see [third-party libraries](/mobile/mastg-know-0004-third-party-libraries/).

#### Steps

1. **Read the SDK configuration.**

   Android: decode the manifest and look at `<meta-data>` entries and providers that SDKs use for configuration and auto-initialisation:

   ```bash
   apktool d -s app.apk -o app_src
   grep -n "<meta-data" app_src/AndroidManifest.xml
   grep -n "InitProvider\|InitializationProvider\|startup" app_src/AndroidManifest.xml
   grep -rn "collection_enabled\|_enabled\"\|deactivated" app_src/res/values/strings.xml app_src/AndroidManifest.xml
   ```

   iOS: dump `Info.plist` and any SDK configuration plists in the bundle:

   ```bash
   plutil -p Payload/App.app/Info.plist | grep -iE "collection|enabled|deactivat|tracking|analytics"
   find Payload/App.app -name "*.plist" -maxdepth 2 | xargs -I{} sh -c 'echo "== {}"; plutil -p "{}" | grep -iE "collection|enabled|analytics|crash" '
   ```

   Record whether collection starts automatically at launch (before any consent screen) or is enabled explicitly later, and which identifier-collection switches are on.

2. **Find the call sites (Android).** Analytics APIs vary, but they share a vocabulary: `setUserId`, `setUserProperty`, `logEvent`, `track`, `identify`, `setCustomKey`, `log`, `addBreadcrumb`, `setUser`, `setAttribute`. Run a semgrep rule over the jadx output that flags those calls when the argument looks like personal data:

   ```yaml
   # pii-to-sdk.yaml - run: semgrep --config pii-to-sdk.yaml jadx_out/sources
   rules:
     - id: pii-passed-to-analytics-or-crash-sdk
       languages: [java]
       severity: WARNING
       message: Possible personal data passed to an analytics, crash or attribution call ($METHOD)
       patterns:
         - pattern: $SDK.$METHOD(..., $ARG, ...)
         - metavariable-regex:
             metavariable: $METHOD
             regex: ^(setUserId|setUserID|setUserProperty|setUserProperties|logEvent|track|trackEvent|identify|setCustomKey|setCustomValue|log|addBreadcrumb|leaveBreadcrumb|setUser|setAttribute|setEmail|setPhone)$
         - metavariable-regex:
             metavariable: $ARG
             regex: (?i).*(mail|phone|msisdn|name|address|postcode|zip|birth|dob|latitude|longitude|getText|query|message|ssn|iban|card).*
   ```

   Then read the hits. The rule depends on readable names, so it under-reports in obfuscated code: follow the SDK's public API instead (SDK classes are usually kept unobfuscated) and look at what flows into it. Also search for event *names* built by concatenation (`"purchase_" + userId`) and for URLs with query strings passed as screen names.

3. **Find the call sites (iOS).** In the main binary and the app's own frameworks, list references to analytics methods and look for the app's wrapper:

   ```bash
   rabin2 -zz Payload/App.app/App | grep -iE "setUserID|setUserProperty|logEvent|identify|setCustomValue|setCustomKey|breadcrumb|setUser"
   rabin2 -i Payload/App.app/App | grep -iE "analytics|crash|attribution"
   ```

   Follow the selector references to call sites in Ghidra or r2 and look at what is loaded into the argument registers. Swift-only SDK APIs do not appear as Objective-C selectors; look for their mangled symbol names instead (`rabin2 -s` and `swift-demangle`).

4. **Trace the app's own analytics calls at runtime.** Start broad with `frida-trace` on the SDK's public methods to see which fire and from where:

   ```bash
   # Android: Java methods (class!method globs; /i case-insensitive)
   frida-trace -U -f com.example.app -j '*!setUserId*/i' -j '*!logEvent*/i' -j '*!setCustomKey*/i'
   # iOS: Objective-C methods
   frida-trace -U -f com.example.app -m '*[* setUserID:]' -m '*[* logEventWithName:*]' -m '*[* setCustomValue:*]'
   ```

   Then narrow to the app's analytics wrapper (found in step 2 or 3), and print the event name and parameters without changing anything:

   ```javascript
   // trace-analytics.js - observe the app's own analytics wrapper (Android).
   // Replace the class and method with the wrapper you found.
   Java.perform(() => {
     const Tracker = Java.use('com.example.app.analytics.Tracker');
     Tracker.track.overload('java.lang.String', 'java.util.Map').implementation = function (name, params) {
       const out = [];
       if (params !== null) {
         const it = params.entrySet().iterator();
         while (it.hasNext()) {
           const e = Java.cast(it.next(), Java.use('java.util.Map$Entry'));
           out.push(e.getKey() + '=' + e.getValue());
         }
       }
       console.log('[analytics] ' + name + ' {' + out.join(', ') + '}');
       return this.track(name, params);
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l trace-analytics.js
   ```

   Exercise the same flows as GT-PRIV-0067-1 and compare: every personal value in the trace should either be absent from the traffic (dropped by an allowlist) or explain a hit in the traffic.
5. **Check crash-report hygiene.** Look for custom keys and user fields set on the crash SDK, for logging calls whose output goes to crash breadcrumbs, and for a "before send" or scrubbing callback. If one exists, read what it removes.
6. **Check session replay and AI calls.** For replay SDKs, find the masking configuration (which views are masked; whether text inputs and web views are masked by default). For AI features, find where the prompt is built and whether any redaction step runs before the request.

#### Observation

The SDK configuration (auto-start, collection switches), a list of call sites passing personal data with file and line (or address), the runtime trace of event names and parameters, the crash-report scrubbing behaviour, the replay masking settings, and the redaction logic for AI calls.

#### Evaluation

The test **fails** if the app passes direct identifiers, free text or precise location to an analytics, crash, attribution, replay or AI SDK; builds event or screen names from identifiers; sets the account email or phone as a user ID or custom key; or records text inputs in session replay without masking. It also fails if collection starts before the consent it requires (cross-reference [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/)). It **passes** if all SDK calls go through a wrapper that enforces an allowlist, the IDs passed are pseudonymous and app-scoped, crash reports are scrubbed, replay masks inputs, and AI prompts are redacted or built server-side.

#### Demo

Decompiled call site (illustrative):

```java
// jadx output
public final void onLoginSuccess(Account account) {
    this.crashReporter.setUserId(account.getEmail());
    this.crashReporter.setCustomKey("phone", account.getPhoneNumber());
    this.analytics.logEvent("login_" + account.getId(), null);
}
```

semgrep output (illustrative):

```text
jadx_out/sources/com/example/app/auth/LoginViewModel.java
  pii-passed-to-analytics-or-crash-sdk
     Possible personal data passed to an analytics, crash or attribution call (setUserId)
     41┆ this.crashReporter.setUserId(account.getEmail());
     Possible personal data passed to an analytics, crash or attribution call (setCustomKey)
     42┆ this.crashReporter.setCustomKey("phone", account.getPhoneNumber());
```

The third line is not caught by the rule (the identifier is in the event name, built by concatenation) and is exactly why the manual read in step 2 matters.

### GT-PRIV-0067-3: Hashing and pseudonymisation construction review (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

When the app or its documentation says data is "hashed", "anonymised" or "pseudonymised" before it leaves the device, this test establishes what the construction actually is: algorithm, input normalisation, salt or key and where it comes from, whether the output differs per recipient, and whether it rotates. It does not attempt to reverse anyone's data. You confirm the construction by recomputing the value for your own canary account and matching it against the traffic.

#### Prerequisites

- The results of GT-PRIV-0067-1 (which hashed or encoded values leave the device, and where to).
- Decompiled code (jadx; Ghidra or r2 for iOS), and Frida on a rooted or jailbroken test device.
- The client's description of the scheme, if any (privacy policy, data map, DPIA extract).

#### Steps

1. **Find the hashing and keyed-hash calls.**

   ```bash
   # Android (jadx output)
   grep -rnE 'MessageDigest\.getInstance|Mac\.getInstance|Hashing\.(sha256|md5|hmacSha256)|DigestUtils' jadx_out/sources \
     | grep -v '/androidx/\|/kotlin/'
   # iOS
   rabin2 -i Payload/App.app/App | grep -E 'CC_SHA(1|256)|CC_MD5|CCHmac'
   rabin2 -zz Payload/App.app/App | grep -iE 'sha256|hmac|salt|pepper|pseudonym|anonymi'
   ```

   CryptoKit's `SHA256.hash(data:)` and `HMAC` are Swift APIs; look for `CryptoKit` in the imported libraries (`rabin2 -l`) and follow references in the disassembler.
2. **Trace inputs and outputs for your own canaries.** Log what the app hashes, filtered to your canary values so that you do not capture anything else:

   ```javascript
   // trace-digest.js - Android, observe only. Logs digests whose input contains a canary.
   const CANARIES = ['canary.pt7k2@example.com', '447700900417'];
   Java.perform(() => {
     const MD = Java.use('java.security.MessageDigest');
     const JString = Java.use('java.lang.String');
     MD.digest.overload('[B').implementation = function (input) {
       const s = JString.$new(input, 'UTF-8').toString();
       const out = this.digest(input);
       if (CANARIES.some(c => s.toLowerCase().includes(c))) {
         const hex = Array.from(out, b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
         console.log('[digest] ' + this.getAlgorithm() + '(' + JSON.stringify(s) + ') = ' + hex + '\n' +
           Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
       }
       return out;
     };
   });
   ```

   Hash APIs have several entry points (`update` then `digest()`, `Mac.doFinal`); add hooks for the ones step 1 found. On iOS, CommonCrypto is a C API:

   ```javascript
   // trace-ccsha256.js - iOS, observe only.
   const m = Process.getModuleByName('libcommonCrypto.dylib');
   Interceptor.attach(m.findExportByName('CC_SHA256'), {
     onEnter(args) {
       const len = args[1].toInt32();
       const s = args[0].readUtf8String(Math.min(len, 256));
       if (s && s.toLowerCase().includes('canary.pt7k2@example.com')) {
         console.log('[CC_SHA256] ' + JSON.stringify(s) + '\n' +
           Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
       }
     }
   });
   ```

   (`readUtf8String` throws on invalid UTF-8; wrap it in `try` if the app hashes binary data too.)
3. **Recompute and match.** Confirm the construction by hashing your own canary the same way and comparing it with the traffic:

   ```bash
   printf '%s' 'canary.pt7k2@example.com' | shasum -a 256
   printf '%s' '447700900417' | shasum -a 256
   ```

   A match means a deterministic, unkeyed hash. If the value only matches with a constant salt or key that you found in the app (`printf '%s' "<salt>canary.pt7k2@example.com" | shasum -a 256`, or `openssl dgst -sha256 -hmac "<key>"`), the "secret" ships with the app.
4. **Check per-recipient and per-period behaviour.** From the GT-PRIV-0067-1 capture: do two different third parties receive the same pseudonym for your account? Does the value change after a day, a reinstall, or a logout and login? Do two test accounts with the same email domain get unrelated values (they should)?
5. **Check where the mapping lives.** If the app receives a pseudonym from the backend, ask the client how it is derived and where the key or table is stored (KMS, separate service, access controls). Record the answer as evidence; you cannot verify the server side from the app.
6. **Compare with the claims.** Read what the privacy policy, the Data safety form and the App Privacy label say about this data ("anonymised", "not linked to you", "hashed for your privacy").

#### Observation

The algorithm and input normalisation, where any salt or key comes from (hard-coded, fetched, server-only), whether outputs are the same across recipients and over time, whether your recomputation matched the traffic, and the client's stated scheme and claims.

#### Evaluation

The test **fails** if:

- An identifier is hashed on the device with an unkeyed or globally salted hash, or with a key embedded in the app, and the result is shared with a third party while the app or its declarations treat it as anonymous or not linked; or
- The same pseudonym is given to several unrelated recipients, enabling them to link their data on it, where the purpose does not require it; or
- The mapping table or key is stored with the pseudonymised data (for example sent alongside it, or kept in the same analytics project).

It **passes** if identifiers that leave the device for third parties are random app-scoped IDs or server-derived keyed pseudonyms with per-recipient keys held only server-side, and the declarations describe them as personal data that is pseudonymised rather than anonymous. A deterministic hash sent to a partner for a disclosed and consented matching purpose is not a construction failure, but it **is** personal data sharing; record it for [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/) and [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/).

#### Demo

Vulnerable and better Kotlin:

```kotlin
// Vulnerable: deterministic hash on device, "salt" shipped in the APK,
// same value to every partner, described as anonymised.
private const val SALT = "s3cr3t-salt"
fun anonymousId(email: String): String =
    MessageDigest.getInstance("SHA-256")
        .digest((SALT + email.trim().lowercase()).toByteArray())
        .joinToString("") { "%02x".format(it) }

// Better: the app never derives pseudonyms from identifiers. Analytics gets a random
// install-scoped ID; where an account-linked pseudonym is needed, the backend returns
// HMAC-SHA256(key_for_this_recipient, accountId), with keys held in the server's KMS.
val analyticsId: String = prefs.getString("analytics_id", null)
    ?: UUID.randomUUID().toString().also { prefs.edit().putString("analytics_id", it).apply() }
```

Illustrative Frida output for the vulnerable version, and the matching recomputation:

```text
[digest] SHA-256("s3cr3t-saltcanary.pt7k2@example.com") = 5d0c...e91a
    at com.example.app.privacy.Ids.anonymousId(Ids.kt:12)
    at com.example.app.ads.Attribution.onSignup(Attribution.kt:40)
```

```bash
$ printf '%s' 's3cr3t-saltcanary.pt7k2@example.com' | shasum -a 256
5d0c...e91a  -
```

The same value appeared in requests to two different third-party hosts in GT-PRIV-0067-1, so both can link the user on it, and anyone with the APK can compute it for any email.

## Secure implementation

No OWASP best practice exists for this weakness. What we recommend, and what a retest should find:

- **One analytics gateway in the app.** Every analytics, crash and attribution call goes through one wrapper with an allowlisted schema (event names from an enum, parameters from a typed set, no free-text strings). Anything else is dropped and, in debug builds, fails loudly.

  ```kotlin
  enum class Event { APP_OPEN, SEARCH_PERFORMED, CHECKOUT_STARTED, CHECKOUT_COMPLETED }
  enum class Param { RESULT_COUNT, BASKET_SIZE_BAND, REGION }

  object Telemetry {
      fun log(event: Event, params: Map<Param, Any> = emptyMap()) {
          if (!Consent.analyticsAllowed()) return
          analytics.logEvent(event.name.lowercase(),
              params.mapKeys { it.key.name.lowercase() })   // no free text possible
      }
  }
  ```

- **Random, app-scoped analytics IDs.** Generate a UUID at first launch (or use the SDK's installation ID) and use it as the analytics and crash user ID. Do not set the email, phone or username. If support needs to find a user's crash, give support a lookup from account to analytics ID on the client's own backend.
- **Keyed pseudonyms from the backend, per recipient.** Where a partner needs an account-linked ID, derive it server-side with HMAC and a separate key per partner and purpose, stored in a KMS, rotated where long-term linkage is not needed. Never compute it in the app, never ship the key, never send the same value to two partners. Document it as pseudonymised personal data.
- **Coarsen at the source.** Round coordinates to what the feature needs before they leave the device (`Math.round(lat * 100) / 100.0` gives two decimals); bucket timestamps and ages; send region rather than postcode.

  ```swift
  func coarse(_ c: CLLocationCoordinate2D, decimals: Double = 2) -> (Double, Double) {
      let f = pow(10.0, decimals)
      return ((c.latitude * f).rounded() / f, (c.longitude * f).rounded() / f)
  }
  ```

- **IP handling at the collection endpoint.** Configure analytics backends to truncate or drop IPs, or put a first-party collection proxy in front that strips them, and say so in the data map.
- **Strip media metadata before upload.**

  ```kotlin
  // Android: remove GPS and device tags from a JPEG the app is about to upload
  val exif = androidx.exifinterface.media.ExifInterface(file)
  listOf(ExifInterface.TAG_GPS_LATITUDE, ExifInterface.TAG_GPS_LONGITUDE, ExifInterface.TAG_GPS_LATITUDE_REF,
         ExifInterface.TAG_GPS_LONGITUDE_REF, ExifInterface.TAG_GPS_ALTITUDE, ExifInterface.TAG_GPS_TIMESTAMP,
         ExifInterface.TAG_GPS_DATESTAMP, ExifInterface.TAG_BODY_SERIAL_NUMBER, ExifInterface.TAG_CAMERA_OWNER_NAME)
      .forEach { exif.setAttribute(it, null) }
  exif.saveAttributes()
  ```

  On iOS, re-encode with Image I/O and pass `kCGImageMetadataShouldExcludeGPS: true`, or write the image without copying the source metadata dictionary at all.
- **Crash-report scrubbing.** No custom keys or user fields with personal data; sanitise exception messages that include input values; do not attach raw logs; use the SDK's before-send hook to remove emails, phone numbers and tokens with patterns as a last line of defence, not the first.
- **Session replay masking on by default** for all text inputs, web views and any screen that shows personal data; review it whenever screens change.
- **Redaction for AI features, on the server.** Route prompts through the client's backend, redact identifiers there, keep the provider key there, and use the provider's no-retention options.
- **Keep the data map and declarations in sync** with what the gateway allows, and describe pseudonymised data as personal data.

## Rating findings

Apply the series-wide rule: rate by (a) what personal data is exposed or processed beyond what is necessary, declared or consented, (b) how sensitive it is (special-category data, precise location, children's data, financial data, contacts, health), (c) scale and reversibility, and (d) whether it contradicts the app's own declarations or store policy. Regulatory risk is assessed by the client's legal team, not by these ratings.

| Rating | Typical conditions |
|---|---|
| **High** | Direct identifiers or deterministic hashes of them shared with advertising, attribution or data-broker-type recipients without consent where consent is required, or contrary to the app's declarations. Special-category or health data, children's data, precise location traces, or financial identifiers sent to analytics, crash, replay or AI providers. Free text from support or health features forwarded unredacted to a third-party AI service. |
| **Medium** | Account email, phone or name used as the analytics or crash user ID, or in event names, with a processor-type SDK and no sensitive content. Precise location sent to analytics where coarse would do. Media uploads keeping GPS metadata in a feature where users would not expect location to be shared. Hash-based "anonymisation" claims in the privacy policy or labels that the construction does not support, with limited data. |
| **Low** | Quasi-identifiers at more precision than needed (millisecond timestamps, full date of birth) in first-party analytics; an app-embedded salt or key for pseudonyms that reach only first-party systems; crash reports that occasionally include identifiers through exception messages. |
| **Info** | Identifiers sent to the client's own backend for core functions; IP addresses reaching SDK endpoints, with server-side truncation unverified (request evidence); a missing data map or undocumented scheme with no observed data impact. |

Raise a level when the data concerns children, health or other special categories, when the recipient is an advertising or data-broker-type party, or when the app explicitly promises anonymity. Lower a level when the recipient is contractually a processor with retention limits, the client can show it, and nothing sensitive is involved.

In the report give: the canary values and their forms, the destination hosts and the SDK each belongs to, the request excerpts (tokens redacted), the code call sites, the hashing construction and your recomputation, the consent state during the capture, the relevant declarations, and the fix. Hand the destination matrix to the client's DPO as-is; it is the most useful artefact of the test.

## References

- OWASP MASWE: [MASWE-0067: Lack of Anonymization or Pseudonymisation Measures](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0067/); related [MASWE-0068](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0068/), [MASWE-0073](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0073/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PRIVACY-2](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-2/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/), [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/), [MASTG-TECH-0100](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0100/), [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/), [MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/), [MASTG-TECH-0033](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0033/), [MASTG-TECH-0086](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0086/) (CC BY-SA 4.0)
- OWASP MASTG tools: [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/), [mitmproxy (MASTG-TOOL-0097)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/), [Burp Suite (MASTG-TOOL-0077)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/) (CC BY-SA 4.0)
- Sibling notes: [PRIVACY hub](/mobile/masvs-privacy-privacy-testing-guide/), [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/), [MASWE-0069](/mobile/maswe-0069-non-privacy-preserving-functionality/), [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/), [MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/), [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/); [traffic interception lab](/mobile/mobile-traffic-interception-lab/), [MASWE-0008](/mobile/maswe-0008-improper-hashing/), [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/), [third-party libraries](/mobile/mastg-know-0004-third-party-libraries/)
- Law and guidance (EU/UK): [GDPR (Regulation (EU) 2016/679)](https://eur-lex.europa.eu/eli/reg/2016/679/oj), Art. 4(1), 4(5), 25, 32 and Recitals 26, 28, 30; [UK GDPR](https://www.legislation.gov.uk/eur/2016/679/contents); [ePrivacy Directive 2002/58/EC](https://eur-lex.europa.eu/eli/dir/2002/58/oj); [PECR regulation 6](https://www.legislation.gov.uk/uksi/2003/2426/regulation/6); [ICO: Anonymisation](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-sharing/anonymisation/) and [Pseudonymisation](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-sharing/anonymisation/pseudonymisation/); [EDPB Guidelines 01/2025 on Pseudonymisation](https://www.edpb.europa.eu/our-work-tools/documents/public-consultations/2025/guidelines-012025-pseudonymisation_en); [EDPB Guidelines 2/2023 on the technical scope of Art. 5(3) ePrivacy](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-22023-technical-scope-art-53-eprivacy-directive_en); [Article 29 WP Opinion 05/2014 on Anonymisation Techniques (WP216)](https://ec.europa.eu/justice/article-29/documentation/opinion-recommendation/files/2014/wp216_en.pdf); [CJEU C-413/23 P, EDPS v SRB](https://curia.europa.eu/juris/liste.jsf?num=C-413/23)
- Law and guidance (US): [FTC: No, hashing still doesn't make your data anonymous](https://www.ftc.gov/policy/advocacy-research/tech-at-ftc/2024/07/no-hashing-still-doesnt-make-your-data-anonymous); CCPA/CPRA, Cal. Civ. Code § 1798.140
- Stores: [Google Play Data safety guidance](https://support.google.com/googleplay/android-developer/answer/10787469); [Apple App Privacy details](https://developer.apple.com/app-store/app-privacy-details/); [Apple User Privacy and Data Use](https://developer.apple.com/app-store/user-privacy-and-data-use/)
- Platform: [Android: Access media files from shared storage](https://developer.android.com/training/data-storage/shared/media), [`ExifInterface`](https://developer.android.com/reference/androidx/exifinterface/media/ExifInterface); [Apple: `UIDevice.name`](https://developer.apple.com/documentation/uikit/uidevice/name), [user-assigned device name entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.device-information.user-assigned-device-name), [`kCGImageMetadataShouldExcludeGPS`](https://developer.apple.com/documentation/imageio/kcgimagemetadatashouldexcludegps); [Firebase: configure Analytics data collection (iOS)](https://firebase.google.com/docs/analytics/configure-data-collection)
- Standards: [RFC 2104 (HMAC)](https://datatracker.ietf.org/doc/html/rfc2104); [CWE-359](https://cwe.mitre.org/data/definitions/359.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
