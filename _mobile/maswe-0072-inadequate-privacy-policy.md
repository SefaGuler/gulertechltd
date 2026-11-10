---
title: "MASWE-0072: Inadequate Privacy Policy"
date: 2026-11-10 22:06:00 +0000
subcategory: privacy
summary: "Testing a mobile app's privacy policy: can users reach it, does it say what GDPR and the stores require, and does it match what the app really does?"
refs: [MASWE-0072, MASVS-PRIVACY-3, CWE-359]
tags: [android, ios, masvs-privacy, privacy-policy, transparency, gdpr]
---

This note is part of our [MASVS-PRIVACY guide](/mobile/masvs-privacy-privacy-testing-guide/) and covers OWASP [MASWE-0072](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0072/): an app whose privacy policy is missing, hard to reach, incomplete, generic, or contradicted by what the app actually does. It can look like a paperwork issue for the legal team. It is not only that. The privacy policy is the document both app stores require for every app, the document regulators read first, and the yardstick against which every other privacy finding in this series is measured. If the app sends contact lists to an analytics endpoint, whether that is an "undeclared sharing" finding or an expected, documented behaviour depends on what the policy says. OWASP has no tests and no Knowledge item for this weakness. Below you get the background a tester needs (what GDPR, UK GDPR, CCPA and the two stores require of a policy, layered notices, children), three Guler Tech tests (availability, completeness, policy against behaviour), and how to rate what you find.

> **Note:** This is technical testing guidance, not legal advice. You collect evidence about what the policy says and what the app does; the client's DPO or legal team decides what the law requires of them.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Generic: what a privacy policy must contain](#generic-what-a-privacy-policy-must-contain)
  - [Generic: layered notices, timing and children](#generic-layered-notices-timing-and-children)
  - [Android: Google Play privacy policy and prominent disclosure rules](#android-google-play-privacy-policy-and-prominent-disclosure-rules)
  - [iOS: App Store privacy policy rules](#ios-app-store-privacy-policy-rules)
  - [Generic: how mobile privacy policies go wrong](#generic-how-mobile-privacy-policies-go-wrong)
- [Tests](#tests)
  - [GT-PRIV-0072-1: Privacy policy availability (Android and iOS)](#gt-priv-0072-1-privacy-policy-availability-android-and-ios)
  - [GT-PRIV-0072-2: Privacy policy completeness (Android and iOS)](#gt-priv-0072-2-privacy-policy-completeness-android-and-ios)
  - [GT-PRIV-0072-3: Privacy policy against observed behaviour (Android and iOS)](#gt-priv-0072-3-privacy-policy-against-observed-behaviour-android-and-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0003: Comply with Privacy Regulations and Best Practices (Android)](#mastg-best-0003-comply-with-privacy-regulations-and-best-practices-android)
  - [Writing a policy that stays accurate (Guler Tech)](#writing-a-policy-that-stays-accurate-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app provides an adequate privacy policy."* MASWE-0072 maps to **MASVS-PRIVACY-3** ("The app is transparent about data collection and usage") and to [CWE-359](https://cwe.mitre.org/data/definitions/359.html) (Exposure of Private Personal Information to an Unauthorized Actor). Its MASVS v1 ancestor is MSTG-STORAGE-12, the old "the app educates the user about the types of personally identifiable information processed" requirement, and it replaces the beta weakness MASWE-0111. It carries OWASP's **P** and **EUDIW** profiles: it applies to any app that processes personal data, which in practice is nearly every app with an account, analytics or ads.

**OWASP has no tests for this weakness**, current or legacy, and no Knowledge item. MASVS added the PRIVACY group in v2, and OWASP has not yet written policy tests. The only related OWASP content is the generic best practice [MASTG-BEST-0003](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0003/). Everything testable below is Guler Tech methodology.

What is covered, and by which test:

| Question | Test |
|---|---|
| Can a user, and a prospective user, actually reach the policy from the store listing and from inside the app? | [GT-PRIV-0072-1](#gt-priv-0072-1-privacy-policy-availability-android-and-ios) |
| Does the policy contain what GDPR Art. 13/14 and the store rules require, specifically for this app? | [GT-PRIV-0072-2](#gt-priv-0072-2-privacy-policy-completeness-android-and-ios) |
| Does what the app collects, shares and keeps match what the policy says? | [GT-PRIV-0072-3](#gt-priv-0072-3-privacy-policy-against-observed-behaviour-android-and-ios) |

Keep the neighbours apart. The privacy policy is one of several transparency artefacts, and each has its own note:

| Question | Where it lives |
|---|---|
| Do the Data safety section, App Privacy label and privacy manifest match the app's behaviour? | [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) (its declaration-vs-behaviour matrix is the evidence base for GT-PRIV-0072-3) |
| Are tracking domains declared in `NSPrivacyTrackingDomains`? | [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/) |
| Does the app tell the user *at the moment* something privacy-relevant happens (just-in-time notices, permission rationale)? | [MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/) |
| Is consent valid where consent is the lawful basis? | [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/) |
| Can the user access, export and delete their data as the policy promises? | [MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/) |
| Are the defaults privacy-protective? | [MASWE-0071](/mobile/maswe-0071-inadequate-privacy-defaults/) |

## Modes of Introduction

OWASP names two modes: an unclear or absent policy, and a mismatch between policy and behaviour. In practice they break down further.

**No policy, or no link to it.** The URL in Play Console or App Store Connect points at a page that no longer exists after a website redesign or domain change, or at the company's home page. Inside the app there is no link at all, or only on the sign-up screen, so a signed-in user cannot find it again.

**A website policy that does not cover the app.** The company's web cookie policy is reused for the app. It talks about cookies and browser settings and says nothing about device identifiers, permissions, push tokens, location, contacts, crash reporting or the SDKs bundled in the app.

**A group-wide policy that covers everything and nothing.** One document for ten brands and five products, written in "we may collect" language. A user cannot tell which data *this* app collects, for what, or who receives it.

**The policy is out of date.** Policies are written at launch; SDKs, features and data flows change with every release. A new attribution SDK, a chat feature that uploads photos, or a move of the backend to another region quietly makes the policy wrong.

**Unreachable in practice.** The policy loads in a WebView that requires an account, is a PDF, is geofenced, only exists in English while the app is localised into six languages, or sits five levels deep in a settings menu.

**Behaviour that contradicts the policy.** "We never share your data with third parties" in an app that ships three advertising SDKs; "we keep your data for 30 days" while the backend never deletes; "you can delete your account at any time" without a working deletion path.

## Impact

- **Users cannot make informed choices.** Transparency is what makes every other choice meaningful: a user cannot object to profiling, withdraw consent or exercise rights they do not know about. This is OWASP's "violation of user privacy" impact, and it is real even when no single data flow is unlawful.
- **The policy becomes evidence against the controller.** A specific, false statement in a policy ("we do not share location with anyone") turns a debatable processing practice into a clear transparency failure under GDPR Art. 5(1)(a) and Art. 12–14, and, in the US, into a potential unfair or deceptive practice claim. Regulators routinely start enforcement from the published policy.
- **Store rejection or removal.** Both stores make a privacy policy mandatory for every app and check the link. Google Play treats a missing or invalid policy as a User Data policy violation; Apple rejects under guideline 5.1.1(i).
- **Loss of trust.** Users, journalists and researchers compare policies with traffic captures and store labels. A contradiction is easy to publish and hard to explain.

## Mitigations

- **Publish an app-specific policy** that names the app, lists the data types it collects and why, the recipients (including SDK providers by category or name), retention, international transfers and the user's rights, in clear and plain language (GDPR Art. 12).
- **Make it reachable**: an active, public, non-geofenced, non-PDF URL in Play Console and App Store Connect, and a link inside the app that works before sign-in and after it, typically in Settings or About.
- **Layer it**: a short summary first, details behind it, and just-in-time notices at the point of collection ([MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/)).
- **Keep it consistent with the other declarations**: the Data safety section, the App Privacy label and the privacy manifests describe the same app and must not contradict the policy ([MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/)).
- **Tie policy review to releases**: any change in SDKs, permissions, data types or backend regions triggers a policy review before the release ships.

## Background

OWASP has no Knowledge item for this weakness. The sections below are ours. They summarise what the law and the stores ask of a privacy policy closely enough that you can test against it, and they deliberately stay brief on law: the client's legal team owns the interpretation.

### Generic: what a privacy policy must contain

#### GDPR and UK GDPR Articles 12 to 14

The EU [GDPR](https://eur-lex.europa.eu/eli/reg/2016/679/oj) and the [UK GDPR](https://www.legislation.gov.uk/eur/2016/679/contents) (the retained version, same article numbering) set the content and the form of privacy information. Article 12(1) sets the form: information must be **concise, transparent, intelligible and easily accessible**, in **clear and plain language**, in particular when addressed to a child. Article 13 lists what to tell people when you collect data from them (the app collecting it from the user), Article 14 what to tell them when you obtained it elsewhere (a data broker, a partner, an SDK provider's enrichment, another user's contact list).

The Article 13 list, with what it means for a mobile app:

| Art. | Item | Mobile-specific examples of what to look for |
|---|---|---|
| 13(1)(a) | Identity and contact details of the controller (and EU/UK representative where required) | The legal entity behind the app, not just the brand; matches the developer name on the store listing |
| 13(1)(b) | Contact details of the DPO, where one is appointed | An address or form, not a generic support inbox only |
| 13(1)(c) | Purposes **and** lawful basis for each processing activity | "Crash reporting: legitimate interests"; "personalised ads: consent". One basis for everything is a warning sign |
| 13(1)(d) | The legitimate interests pursued, where Art. 6(1)(f) is relied on | What the interest is, for analytics, fraud prevention, security logging |
| 13(1)(e) | Recipients or categories of recipients | Analytics, crash reporting, attribution, advertising, push, cloud hosting, payment providers |
| 13(1)(f) | Transfers to third countries and the safeguard used | Where the backend and SDK providers process data; adequacy decision or standard contractual clauses |
| 13(2)(a) | Retention period, or the criteria used to set it | Per category: account data, chat content, location history, logs, analytics events |
| 13(2)(b) | Rights: access, rectification, erasure, restriction, objection, portability | And how to exercise them from the app ([MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/)) |
| 13(2)(c) | Right to withdraw consent at any time, where processing is based on consent | Where in the app to withdraw (a privacy settings screen, not an email address only) |
| 13(2)(d) | Right to lodge a complaint with a supervisory authority | The ICO for UK users, the relevant EU authority |
| 13(2)(e) | Whether providing the data is a statutory or contractual requirement, and the consequences of not providing it | Which fields and permissions are optional; what stops working if the user refuses |
| 13(2)(f) | Automated decision-making, including profiling, with meaningful information about the logic | Credit, fraud scoring, risk-based account blocking |

Article 14 adds two items: the **categories** of personal data concerned (Art. 14(1)(d)) and the **source** of the data (Art. 14(2)(f)). It also sets the timing: within a reasonable period and at the latest within one month, or at first communication with the person, or before the data is disclosed to another recipient (Art. 14(3)). Article 13(3) requires new information before data is used for a new purpose.

The UK regulator's guidance is [the right to be informed](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/the-right-to-be-informed/), including [what privacy information to provide](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/the-right-to-be-informed/what-privacy-information-should-we-provide/) and [how to draft it](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/the-right-to-be-informed/how-should-we-draft-our-privacy-information/). The EU reference is the Article 29 Working Party [Guidelines on transparency (WP260 rev.01)](https://ec.europa.eu/newsroom/article29/items/622227), endorsed by the EDPB. Both say the same things a tester can use: avoid vague qualifiers ("may", "might", "some", "often", "possible"), state purposes specifically, and match the medium; for apps that means layered, short, readable on a phone. The UK GDPR has been amended by the Data (Use and Access) Act 2025, with provisions commencing in stages; check the ICO's current guidance rather than relying on older summaries.

Where the app stores or reads information on the device that is not strictly necessary (advertising identifiers, SDK-generated device IDs, local analytics storage), [PECR](https://www.legislation.gov.uk/uksi/2003/2426/regulation/6) regulation 6 in the UK and Art. 5(3) of the ePrivacy Directive in the EU separately require "clear and comprehensive information" about it. In app terms, the privacy policy (or a linked cookie and SDK notice) is where that information usually lives.

#### CCPA and CPRA

If the client has Californian users and falls within the [CCPA](https://oag.ca.gov/privacy/ccpa) thresholds, two artefacts matter. The **privacy policy** must cover, among other things, the categories of personal information collected, their sources, the business purposes, the categories of third parties it is disclosed to, whether it is sold or shared (for cross-context behavioural advertising), the consumer's rights and how to exercise them, and it must be updated at least every 12 months. The **notice at collection** must list the categories collected, the purposes, whether they are sold or shared, and the retention period for each category, at or before collection. The regulations (Cal. Code Regs. tit. 11, [§ 7011](https://www.law.cornell.edu/regulations/california/11-CCR-7011) and [§ 7012](https://www.law.cornell.edu/regulations/california/11-CCR-7012)) allow mobile apps to link these from the app's download page and from within the app, for example in its settings menu. For testing, that means the same two places the stores require.

### Generic: layered notices, timing and children

**Layered notices.** Nobody reads a 9,000-word policy on a phone. Regulators accept, and recommend, layering: a first layer with the essentials (who you are, the main purposes, the main recipients, where the rest is, how to exercise rights), with detailed sections behind it. Layering is not permission to hide things in the second layer: anything with a significant effect on the user (sharing with advertisers, profiling, sensitive data, transfers) belongs in the first layer. The privacy policy is the complete layer. The just-in-time notices at the moment of collection (before a permission prompt, before enabling contact sync) are the other end of the same design and are tested in [MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/).

**Timing.** For data the app collects directly, the information is due at collection. For an app, the earliest collection point is often first launch: SDKs initialise in `Application.onCreate()` or `application(_:didFinishLaunchingWithOptions:)` and send identifiers and device data before any screen is shown. A policy the user can only reach after creating an account is too late for everything that happened before. GT-PRIV-0072-1 checks this.

**Children.** If the app is directed at children or likely to be used by them, the bar rises:

- **UK:** the ICO's [Age appropriate design code](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/childrens-information/childrens-code-guidance-and-resources/age-appropriate-design-a-code-of-practice-for-online-services/) (the Children's code) applies to online services likely to be accessed by under-18s in the UK. Its [standard 4, transparency](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/childrens-information/childrens-code-guidance-and-resources/age-appropriate-design-a-code-of-practice-for-online-services/4-transparency/), asks for privacy information that is concise, prominent and in language suited to the child's age, plus "bite-sized" explanations at the point where a use of data is activated.
- **US:** the FTC's [COPPA Rule (16 CFR Part 312)](https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-312) requires an online notice of information practices and direct notice to parents before collecting personal information from children under 13. The FTC amended the rule in 2025, with a compliance date in 2026; among other things the amendments require a written data retention policy to be published in the online notice. Check the current text if COPPA is in scope.
- **Stores:** Apple's guidelines require apps in the Kids Category, and apps that collect personal information from minors, to include a privacy policy and comply with children's privacy law (guidelines 1.3 and 5.1.4). Google Play's Families policies add requirements for apps whose target audience includes children, including restrictions on which ads SDKs they may use.

### Android: Google Play privacy policy and prominent disclosure rules

Google Play requires a privacy policy for **every** app, including apps that collect no personal data. The requirements are in the [User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311) and the Play Console help on [the privacy policy field](https://support.google.com/googleplay/android-developer/answer/9859455).

**Where it must be:** a link in the Privacy policy field of Play Console (App content page), which Play shows on the store listing, **and** a link or the text itself inside the app.

**What the URL must be:** an active, publicly accessible URL with a valid TLS certificate; accessible worldwide without geofencing or login; a standard, non-editable web page, not a PDF or a downloadable file; and specific to the app.

**What it must contain**, in Google's list: developer information and a privacy point of contact or a way to submit inquiries; the types of personal and sensitive user data the app accesses, collects, uses and shares, and the types of parties it is shared with; secure data handling procedures; the developer's data retention and deletion policy; clear labelling as a privacy policy; and the entity named in the store listing or the app name.

**Prominent disclosure.** The User Data policy also requires an **in-app** disclosure when the app collects personal and sensitive data in ways a user might not expect (and for several specific permission categories). The disclosure must be inside the app in normal use, describe the data and how it is used or shared, and must not live only in the privacy policy or terms of service. If consent is needed, it must follow the disclosure, be an affirmative action, and come before collection. That is a [MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/) and [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/) test, but it matters here for one reason: a policy is never a substitute for the prominent disclosure, and a policy finding often comes with a disclosure finding.

**Data safety.** The [Data safety section](https://support.google.com/googleplay/android-developer/answer/10787469) is a separate declaration, but Google expects it to be consistent with the policy, and it counts data collected and shared by SDKs in the app. Contradictions between the two are tested in [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/).

### iOS: App Store privacy policy rules

Apple's [App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/#5.1.1), guideline **5.1.1(i) Privacy Policies**, require that all apps include a link to their privacy policy in the App Store Connect metadata field **and** within the app in an easily accessible manner. The policy must clearly and explicitly:

- identify what data, if any, the app or service collects, how it collects that data, and all uses of that data;
- confirm that any third party the app shares user data with (analytics tools, advertising networks, third-party SDKs, and parent, subsidiary or related entities) will provide the same or equal protection of user data as stated in the policy and required by the guidelines;
- explain the data retention and deletion policies and describe how a user can revoke consent and request deletion of their data.

In App Store Connect the policy URL is set with the app's [App Privacy details](https://developer.apple.com/app-store/app-privacy-details/) and is required; an optional **Privacy Choices** URL can point at a page where users manage their data. On the App Store product page, the App Privacy section links to "the developer's privacy policy". The App Privacy label itself (the "nutrition label") and the privacy manifests are separate declarations, tested in [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) and [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/). The third bullet links this note to account deletion: an app that supports account creation must also offer deletion in the app (5.1.1(v)), and the policy should describe it.

Apple's list is shorter than GDPR's and phrased differently (it has the "equal protection" confirmation, which GDPR does not), so GT-PRIV-0072-2 checks the two separately.

### Generic: how mobile privacy policies go wrong

What we see most often, in rough order of frequency:

| Pattern | Why it is a problem |
|---|---|
| Web policy reused for the app: cookies explained, SDKs and device identifiers not | The policy is not specific to the app; Art. 13 recipients and purposes are missing for the app's actual data flows |
| "We may share your data with trusted partners" | No recipients or categories; vague qualifiers the transparency guidelines name as poor practice |
| Third-party SDKs not mentioned | The commonest policy-vs-behaviour gap: analytics, crash, attribution and ads SDKs send data from first launch |
| One retention statement ("as long as necessary") | Art. 13(2)(a) asks for periods or criteria; Google and Apple ask for a retention and deletion policy |
| In-app link only on the sign-up or onboarding screen | A signed-in user cannot find it again; Apple wants it "easily accessible" |
| Policy loads inside an authenticated WebView or needs an account | Not reachable by prospective users; Google forbids login requirements for the URL |
| Store URL redirects to the home page or a 404 after a site move | Both stores treat a broken link as a missing policy |
| Policy only in English in a localised app | Not intelligible to the audience the app targets (Art. 12) |
| Different versions on the store URL, in the app, and on the website | Users cannot know which applies; often the in-app copy is a bundled HTML file that never updates |
| Policy names data the app does not collect, "just in case" | Over-disclosure is less harmful than under-disclosure, but it destroys the policy's usefulness and often contradicts the App Privacy label |

## Tests

OWASP has no tests for MASWE-0072, current or legacy. The three tests below are Guler Tech methodology. They are mostly manual review, supported by commands for the parts that can be checked mechanically. GT-PRIV-0072-3 reuses the evidence you collect for [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/); if you test both, collect once.

### GT-PRIV-0072-1: Privacy policy availability (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Platform: Android and iOS. Type: static and dynamic, partly manual.

This test checks that the policy exists and that a user can actually reach it: from the Google Play and App Store listings, inside the app before and after sign-in, over a URL that meets the store rules, in the languages the app is offered in, and that the store link and in-app link lead to the same current document.

#### Prerequisites

- The package name and App Store ID of the app, and the store listings for the markets in scope.
- The release APK/AAB (or the installed APK pulled from a test device) and the release IPA (decrypted if you want to search the binary; the bundle's resource files are readable without decryption).
- A test device for each platform with the app freshly installed and no account signed in, plus a test account.
- `curl`, `aapt2` (Android SDK build tools), `jadx` or `apktool`, `plutil` and `rabin2` (radare2) or `strings`.

#### Steps

1. **Store listings.** Open the Google Play listing in a browser (`https://play.google.com/store/apps/details?id=com.example.app&hl=en_GB`) and find the *Privacy policy* link in the *App support* section. Open the App Store page (`https://apps.apple.com/gb/app/id<app-id>`) and find the developer's privacy policy link in the *App Privacy* section. Record both URLs. Check the Data safety section and the App Privacy label at the same time; you will need them in GT-PRIV-0072-3.

2. **Check each URL mechanically**, without cookies, from a clean client:

   ```bash
   for u in "https://www.example.com/privacy" "https://www.example.com/app/privacy"; do
     echo "== $u"
     curl -sS -L -o /dev/null --max-time 20 \
       -w 'final=%{url_effective} code=%{http_code} type=%{content_type} redirects=%{num_redirects}\n' "$u"
     curl -sS -L --max-time 20 -D - -o /dev/null "$u" | grep -iE '^(content-language|location|www-authenticate|set-cookie):'
   done
   ```

   You want a final `200`, `text/html`, no redirect to a login page or the home page, and no `www-authenticate`. A `application/pdf` content type fails the Google rule. If the client's markets include other regions, repeat from a second region (a VPN exit you control) to detect geofencing.

3. **Find the in-app link statically.**

   Android:

   ```bash
   jadx -d app_src app-release.apk
   grep -rniE 'privacy|datenschutz|confidentialit|privacidad' app_src/resources/res/values*/strings.xml | head -40
   grep -rnoE 'https?://[A-Za-z0-9./_-]*privacy[A-Za-z0-9./_?=&-]*' app_src | sort -u
   aapt2 dump badging app-release.apk | grep -E '^locales:'
   ```

   iOS:

   ```bash
   unzip -q App.ipa -d ipa && cd ipa/Payload/*.app
   ls -d *.lproj
   for f in */Localizable.strings; do plutil -convert json -o - "$f" 2>/dev/null | grep -io '"[^"]*privacy[^"]*"'; done
   rabin2 -zz "$(plutil -extract CFBundleExecutable raw Info.plist)" | grep -iE 'https?://[^ ]*privacy' | sort -u
   ```

   The URLs you find should match the store URL (or redirect to it). A bundled HTML file (`assets/privacy.html`, a `privacy.html` in the iOS bundle) is a copy that ages: note its date or version and compare it with the online version. Server-driven apps may fetch the URL from a config endpoint; then you find it in traffic in step 4 instead.

4. **Find it dynamically, as a new user.** On a freshly installed app with no account: can you reach the policy from the first screens (onboarding, sign-in, sign-up) without creating an account? Then sign in and find it again from the signed-in UI: Settings, Account, About, Legal, Help. Count the taps from the main screen. Note whether it opens in an in-app browser, an external browser or a WebView, and whether that view requires a session.

5. **Check timing against first-launch traffic.** With your proxy set up as in our [traffic interception lab](/mobile/mobile-traffic-interception-lab/), start the app for the first time and do nothing. Note which hosts are contacted before the user could possibly have seen the policy or a notice. You will evaluate this in GT-PRIV-0072-3 and in [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/); here, record it.

6. **Language.** Compare the app's localisations (`locales:` line, `*.lproj` directories) with the languages the policy is available in. Switch the device language to each in-scope market language and open the in-app link.

7. **Version consistency.** Compare the "last updated" date or version on the store-linked policy, the in-app policy and any bundled copy.

#### Observation

The store URLs and the in-app URLs with their HTTP results, the path and tap count to the policy before and after sign-in, the view it opens in, the language matrix, the "last updated" dates, and the list of hosts contacted at first launch.

#### Evaluation

The test **fails** if any of these holds:

- there is no policy URL on either store listing, or the URL does not resolve to the policy (404, redirect to the home page, login required, PDF, geofenced from a market in scope);
- there is no way to reach the policy from inside the app, or only from a screen the user cannot return to (onboarding, sign-up);
- the in-app link requires an account, so a user who has not signed up cannot read it, while the app already processes their data;
- the store, in-app and bundled versions differ in substance;
- the policy is not available in a language the app is offered in for a market in scope (record this one as a finding with the language, not as a hard failure, if the client has a documented reason).

It **passes** if the policy is reachable from both store listings and from the signed-out and signed-in app in a few taps, over a public HTML URL, in the app's languages, and every route leads to the same current version.

#### Demo

Illustrative output for a failing store URL after a site migration:

```text
== https://www.example.com/legal/app-privacy
final=https://www.example.com/ code=200 type=text/html; charset=utf-8 redirects=1
location: https://www.example.com/
```

and for a passing one:

```text
== https://www.example.com/privacy/app
final=https://www.example.com/privacy/app code=200 type=text/html; charset=utf-8 redirects=0
content-language: en-GB
```

Illustrative in-app result table for the report:

| Route | Signed out | Signed in | Opens in | Version |
|---|---|---|---|---|
| Onboarding, "Privacy" link | Yes | n/a | In-app browser | 2026-03 |
| Settings > About > Privacy policy | Not reachable (Settings needs sign-in) | Yes, 3 taps | WebView, needs session | 2025-07 (bundled copy) |

That second row is a fail twice: the signed-in route shows an older bundled version, and a prospective user can only see the policy during onboarding.

### GT-PRIV-0072-2: Privacy policy completeness (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Platform: Android and iOS (the policy is usually shared, the store requirements differ). Type: manual document review.

This test checks the content of the policy against a checklist drawn from GDPR Art. 13 and 14, the Google Play and Apple requirements, and, where in scope, CCPA and children's rules. It checks presence and specificity: an item that is present but vague ("we may share with partners") is recorded as vague, not as present.

#### Prerequisites

- The policy version reached in GT-PRIV-0072-1 (save a copy: `curl -sL <url> -o policy-$(date +%F).html`, and a PDF print for the report).
- The scope agreed with the client: which laws and markets apply (EU/UK GDPR, CCPA, COPPA, Children's code). You do not decide applicability; you record it as an assumption.
- A first idea of what the app does: its permissions, SDK categories and main features. A quick pass of GT-PRIV-0072-3 step 1 is enough.

#### Steps

1. **Is it about this app?** Search the policy for the app's name and for app-specific terms: "app", "device", "advertising ID", "IDFA", "push notifications", "location", "contacts", "camera", "crash", "SDK". A policy with none of these is a web policy. Record it.

2. **Walk the checklist.** For each row, record *present and specific*, *present but vague*, *missing*, or *not applicable*, with the quoted sentence:

   | # | Item | Source |
   |---|---|---|
   | 1 | Controller identity and contact; EU/UK representative if needed | GDPR 13(1)(a); Google "developer information" |
   | 2 | DPO contact, if appointed | GDPR 13(1)(b) |
   | 3 | Privacy contact or inquiry mechanism | Google |
   | 4 | Data types collected, including by SDKs and from device (identifiers, location, contacts, media, diagnostics) | GDPR 14(1)(d) by analogy; Google; Apple "what data" |
   | 5 | How it is collected (from the user, from the device, from third parties) and sources | Apple "how it collects"; GDPR 14(2)(f) |
   | 6 | Purposes per data type, and lawful basis per purpose | GDPR 13(1)(c); Apple "all uses" |
   | 7 | Legitimate interests stated, where relied on | GDPR 13(1)(d) |
   | 8 | Recipients or categories, including SDK providers, group companies, processors | GDPR 13(1)(e); Google "types of parties"; Apple third parties |
   | 9 | Confirmation that third parties give equal protection | Apple 5.1.1(i) |
   | 10 | International transfers and safeguards | GDPR 13(1)(f) |
   | 11 | Retention periods or criteria, per category | GDPR 13(2)(a); Google; Apple |
   | 12 | Deletion: how to delete the account and data, from the app and from the web | Google; Apple 5.1.1(i) and (v); [MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/) |
   | 13 | Data subject rights and how to exercise them | GDPR 13(2)(b) |
   | 14 | Withdrawing consent, and where in the app | GDPR 13(2)(c); Apple "revoke consent" |
   | 15 | Right to complain to a supervisory authority | GDPR 13(2)(d) |
   | 16 | Which data is optional, and the consequences of not providing it | GDPR 13(2)(e) |
   | 17 | Automated decision-making and profiling, with meaningful logic | GDPR 13(2)(f) |
   | 18 | Secure data handling | Google |
   | 19 | Clearly labelled as a privacy policy; names the app or listing entity | Google |
   | 20 | Device storage and access (identifiers, SDK storage) explained | PECR reg. 6 / ePrivacy 5(3) |
   | 21 | CCPA items: categories, sources, purposes, sold/shared, rights, "last updated" within 12 months | CCPA, if in scope |
   | 22 | Children: age-appropriate summary, parental notice, retention policy | Children's code std 4, COPPA, if in scope |
   | 23 | Last-updated date and a change log or notice of changes | Good practice; supports Art. 13(3) |

3. **Check readability on a phone.** Open the policy on the test device. Is there a first layer or summary? Can you find the SDK list and retention section without scrolling through the whole document? Count vague qualifiers:

   ```bash
   python3 - policy.html <<'EOF'
   import re, sys, html
   text = html.unescape(re.sub(r"<[^>]+>", " ", open(sys.argv[1], encoding="utf-8").read()))
   words = len(text.split())
   hits = re.findall(r"\b(may|might|some|certain|often|possibly|including but not limited to|such as)\b", text, re.I)
   print(f"words={words} vague_qualifiers={len(hits)}")
   EOF
   ```

   The count is a conversation starter, not a score; the transparency guidelines name these words because they hide the actual practice.

4. **Note contradictions inside the policy**, for example "we do not sell personal data" next to a section describing ad-targeting partners.

#### Observation

A filled checklist with quotes, the readability notes, and any internal contradictions.

#### Evaluation

The test **fails** if:

- the policy is not specific to the app (step 1);
- any store-mandated item is missing: for Google, rows 3, 4, 8, 11, 12, 18, 19; for Apple, rows 4, 5, 6, 8, 9, 11, 12, 14;
- any Art. 13 item applicable to the app's processing is missing (rows 1, 2, 6, 8, 10, 11, 13, 14, 15 are the ones we find missing most often);
- the policy contradicts itself.

Rows marked *present but vague* are findings in their own right when the vagueness hides something material (recipients, sharing for advertising, sensitive data). Rows 21 and 22 apply only when the client confirms the law is in scope. The test **passes** if every applicable row is present and specific.

#### Demo

Illustrative extract from a completed checklist:

| # | Item | Result | Quote / note |
|---|---|---|---|
| 4 | Data types | Present but vague | "We collect information you provide and information about your use of our services." No mention of device identifiers or location, which the app requests |
| 8 | Recipients | Vague | "trusted partners". The app bundles analytics, crash reporting and attribution SDKs |
| 9 | Equal protection | Missing | No statement; Apple 5.1.1(i) |
| 11 | Retention | Vague | "as long as necessary" for all data |
| 12 | Deletion | Present | "Settings > Account > Delete account", matches the app |
| 15 | Complaint | Present | ICO named with link |

### GT-PRIV-0072-3: Privacy policy against observed behaviour (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Platform: Android and iOS. Type: static and dynamic.

This is OWASP's second mode of introduction, "discrepancies in policy vs behavior", turned into a test. You build an inventory of what the app collects, from where, sends to whom, and keeps for how long, and compare it line by line with the policy (and, through [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/), with the Data safety section and App Privacy label). The inventory is the same one MASWE-0073 uses: build it once and use it for both notes.

#### Prerequisites

- The completed checklist from GT-PRIV-0072-2.
- Rooted Android and jailbroken iOS test devices are helpful but not required; a proxy setup as in our [traffic interception lab](/mobile/mobile-traffic-interception-lab/) is required, and you may need to bypass certificate pinning on the test build ([NETWORK hub](/mobile/masvs-network-secure-communication-guide/)).
- Test accounts you control. Capture only your own sessions.
- For iOS, *App Privacy Report* turned on on the test device (Settings > Privacy & Security > App Privacy Report).

#### Steps

1. **Static inventory.** Collect what the app *can* do:

   ```bash
   # Android: permissions, SDK packages, SDK init metadata
   aapt2 dump permissions app-release.apk
   apkanalyzer dex packages --defined-only app-release.apk | awk '$1=="P" {print $NF}' | cut -d. -f1-3 | sort -u > packages.txt
   aapt2 dump xmltree app-release.apk --file AndroidManifest.xml | grep -A1 'meta-data' | grep -E 'name|value' | head -60
   ```

   ```bash
   # iOS: usage strings, embedded frameworks, privacy manifests
   plutil -p Payload/App.app/Info.plist | grep -E 'UsageDescription|NSUserTracking'
   ls Payload/App.app/Frameworks
   find Payload -name PrivacyInfo.xcprivacy -exec sh -c 'echo "== $1"; plutil -p "$1" | grep -E "NSPrivacyCollectedDataType\"|NSPrivacyTracking"' _ {} \;
   ```

   Map packages and frameworks to SDK categories (analytics, crash reporting, attribution, advertising, push, chat, payments, maps). Our [third-party libraries note](/mobile/mastg-know-0004-third-party-libraries/) and [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) describe the inventory in depth.

2. **Dynamic inventory.** Run a fixed script on a fresh install with the proxy recording: first launch with no interaction, onboarding, decline every optional consent and permission, sign up, use the main features, then repeat on a second fresh install accepting everything. Log every request's host, path and **field names** (not values) with a small mitmproxy addon:

   ```python
   # data-inventory.py - host, method, path and field names of the app's own requests (no values)
   import json
   from mitmproxy import http

   def _keys(obj, prefix=""):
       if isinstance(obj, dict):
           for k, v in obj.items():
               path = prefix + "." + str(k) if prefix else str(k)
               yield path
               yield from _keys(v, path)
       elif isinstance(obj, list) and obj:
           yield from _keys(obj[0], prefix + "[]")

   def request(flow: http.HTTPFlow) -> None:
       r = flow.request
       fields = set(r.query.keys())
       if r.urlencoded_form:
           fields |= set(r.urlencoded_form.keys())
       try:
           fields |= set(_keys(json.loads(r.get_text(strict=False) or "null")))
       except (ValueError, TypeError):
           pass
       print("\t".join([r.pretty_host, r.method, r.path.split("?")[0], ",".join(sorted(fields))]))
   ```

   ```bash
   mitmdump -q -s data-inventory.py -w declined.flows | tee declined.tsv
   # later, offline:
   mitmdump -q -n -r accepted.flows -s data-inventory.py > accepted.tsv
   cut -f1 declined.tsv | sort | uniq -c | sort -rn
   ```

   Field names such as `adid`, `idfa`, `idfv`, `android_id`, `lat`, `lng`, `contacts`, `email_sha256`, `device_model`, `carrier` tell you which data types leave the device and to which host, without copying the values into your notes. For identifiers, see [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/).

   On iOS, export the App Privacy Report (Share button on the report screen) and list the app's domains and resource accesses:

   ```bash
   jq -r 'select(.type=="networkActivity" and .bundleID=="com.example.app") | [.domain, .domainType, .hits] | @tsv' App_Privacy_Report.ndjson | sort -u
   jq -r 'select(.type=="access" and .accessor.identifier=="com.example.app" and .kind=="intervalBegin") | .category' App_Privacy_Report.ndjson | sort | uniq -c
   ```

   On Android, the Privacy dashboard (Settings > Security & privacy > Privacy > Privacy dashboard, Android 12+) shows location, camera and microphone access in the last 24 hours (some newer releases add a 7-day view); `adb shell dumpsys appops --package com.example.app` shows the last access time per operation.

3. **Retention and deletion.** Compare what the policy says about retention and deletion with what you can observe: delete the test account through the advertised path and check that it can no longer sign in, that a data export request (if offered) after deletion returns nothing, and that local data is removed ([MASWE-0024](/mobile/maswe-0024-sensitive-data-accessible-after-session-termination/), [MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/)). Server-side retention is usually not observable; record the policy statement as an assumption and ask the client for the retention schedule.

4. **Transfers.** For each first-party and SDK host, note the IP geolocation and the provider (CDN, cloud region). This is weak evidence (CDNs terminate close to the user) and only indicates where to ask questions; record it as such.

5. **Build the matrix.** One row per data flow. MASWE-0073 holds the same matrix with Data safety and App Privacy label columns; here, the columns are the policy's:

   | Data type | Source (static / dynamic evidence) | Recipient host / SDK category | When (pre-consent, after consent, feature use) | Policy says | Match? |
   |---|---|---|---|---|---|

#### Observation

The static and dynamic inventories, the App Privacy Report extract, the deletion results, and the completed matrix.

#### Evaluation

The test **fails** if the app's observed behaviour contradicts or exceeds the policy:

- a data type leaves the device that the policy does not mention (typical: device identifiers, precise location, contact data, installed apps, photos metadata);
- data reaches a recipient or category of recipient the policy does not mention, or the policy says "we do not share" while data goes to advertising or attribution hosts;
- data is collected before the point the policy says it is (for example "only with your consent" while the SDK sends identifiers at first launch with consent declined);
- data is used for a purpose not in the policy (an analytics field set in the ads request, for instance);
- the promised controls (deletion, consent withdrawal, opt-out) do not work as described.

It **passes** if every row in the matrix is described by the policy with the correct purpose and recipient category. A policy that describes *more* than the app does is not a fail here; record it as an observation, because it usually also means the store labels are inflated, and check consistency in MASWE-0073.

#### Demo

Illustrative excerpt of `declined.tsv` (consent declined, first launch, no interaction):

```text
api.example.com            GET   /v2/config        app_version,locale,platform
events.analytics.example   POST  /batch            events[].name,events[].ts,device.model,device.os,device.idfv,user.id
attribution.example.net    POST  /v1/install       idfv,ip_hint,install_ts,app_id,att_status
```

with the matching matrix rows:

| Data type | Evidence | Recipient | When | Policy says | Match? |
|---|---|---|---|---|---|
| Device ID (IDFV), device model | `declined.tsv` line 2 | Analytics SDK | First launch, consent declined | "Analytics data is collected only if you agree" | No |
| Device ID, install time | `declined.tsv` line 3 | Attribution SDK | First launch, consent declined | Not mentioned | No |
| App config request | line 1 | First party | First launch | "Technical data needed to run the app" | Yes |

Both "No" rows fail. The second is also a MASWE-0073 finding if the Data safety section or App Privacy label does not declare it, and a [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/) finding if consent is the basis.

## Best practices

### MASTG-BEST-0003: Comply with Privacy Regulations and Best Practices (Android)

OWASP page: [MASTG-BEST-0003](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0003/).

This best practice is reproduced from CWE-359's mitigations: identify the privacy regulations that apply (it names GDPR, CCPA, HIPAA, GLBA and the Safe Harbor framework), and weigh security logging against privacy, because logging everything "for security" creates new stores of personal data. It is tagged Android only but is platform-neutral, and it is primarily attached to the declaration tests in [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/); we only point to it here. Two points from it matter for policies: knowing which regulations apply is the prerequisite for GT-PRIV-0072-2's checklist, and security logs and crash reports are data flows that must appear in the policy like any other.

Two details of the OWASP text are dated. The EU-US Safe Harbor framework it cites was invalidated by the CJEU in 2015 (Schrems I); EU-US transfers now rely on the EU-US Data Privacy Framework or other Art. 46 safeguards. Its GDPR reference points to Wikipedia; use the [official text](https://eur-lex.europa.eu/eli/reg/2016/679/oj).

### Writing a policy that stays accurate (Guler Tech)

No OWASP best practice covers policy content; ours:

- **Generate the policy's data sections from the data inventory**, the same inventory that feeds the Data safety form, the App Privacy label and the privacy manifests. One source, four outputs, no contradictions.
- **Make policy review part of the release checklist.** A new SDK, a new permission, a new data type, a new backend region or a new purpose blocks the release until the policy, the store declarations and the in-app notices are updated.
- **Layer it.** A first screen with who you are, what you collect, why, who receives it, how long you keep it and how to exercise your rights; details behind expandable sections; a dated change log at the end.
- **Name SDK providers or at least their categories and purposes**, and say what each receives (identifiers, events, crash data) and whether it is used for advertising.
- **Host it once.** Link the same URL from Play Console, App Store Connect and the app. If you bundle an offline copy for first launch, fetch the online version when the network is available and show the date.
- **Put the link where users look**: the sign-in and sign-up screens, and Settings > Privacy (or About) when signed in. Do not put the Settings screen behind sign-in.
- **Localise it** for every market where the app is localised.
- **Test the URLs in CI**: a scheduled job that requests the policy URL from the store listing and the in-app constant, and fails on anything but `200 text/html`.

## Rating findings

The series-wide rule applies: rate by what personal data is processed beyond what is declared, how sensitive it is, scale, and whether it contradicts the app's own declarations or store policy. Regulatory exposure is assessed by the client's legal team, not by our severity.

| Rating | Conditions |
|---|---|
| **High** | The policy states something specific that observed behaviour contradicts, for sensitive data or sharing: "we do not share location" while precise location goes to an ads SDK; "no data before consent" while identifiers go to attribution and ad hosts at first launch; undisclosed sharing of special-category, children's, contact or financial data |
| **Medium** | No policy reachable at all (store link broken and no in-app link) for an app that processes personal data; undisclosed SDK recipients or data types of ordinary sensitivity (device IDs, analytics events, coarse location); missing retention, rights or deletion information when the advertised control also does not work; a web-only policy that ignores the app's data flows |
| **Low** | The policy is reachable and broadly accurate but incomplete (missing DPO contact, complaint right, transfer safeguards, Apple's equal-protection statement); in-app link only on onboarding; not localised; store and in-app versions out of step without a material difference |
| **Info** | Readability and layering improvements; over-disclosure ("we may collect" data the app does not collect) with no contradiction elsewhere; a PDF or bundled copy where the online version is fine |

Raise a level for apps aimed at children or handling health, financial or other special-category data, and when the contradiction would breach a store rule that leads to removal (Google's privacy policy and prominent disclosure requirements, Apple 5.1.1(i)). Lower a level when the gap is pure documentation and you found no data flow it hides.

In the report give: the policy URL and the version you reviewed (with a saved copy), the checklist with quotes, each contradiction with the matrix row and the request that proves it (host, path, field names, timing), and the change needed: in the policy, in the app, or both. Leave the legal assessment to the client's DPO or counsel.

## References

- OWASP MASWE: [MASWE-0072: Inadequate Privacy Policy](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0072/); related [MASWE-0073](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0073/), [MASWE-0074](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0074/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PRIVACY-3](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0003](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0003/) (CC BY-SA 4.0)
- Sibling notes: [PRIVACY hub](/mobile/masvs-privacy-privacy-testing-guide/), [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/), [MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/), [MASWE-0071](/mobile/maswe-0071-inadequate-privacy-defaults/), [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/), [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/), [MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/), [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/); also [MASWE-0024](/mobile/maswe-0024-sensitive-data-accessible-after-session-termination/), [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/), [third-party libraries](/mobile/mastg-know-0004-third-party-libraries/), [traffic interception lab](/mobile/mobile-traffic-interception-lab/), [NETWORK hub](/mobile/masvs-network-secure-communication-guide/)
- Law and regulators: [GDPR (Regulation (EU) 2016/679)](https://eur-lex.europa.eu/eli/reg/2016/679/oj), [UK GDPR](https://www.legislation.gov.uk/eur/2016/679/contents), [PECR regulation 6](https://www.legislation.gov.uk/uksi/2003/2426/regulation/6); ICO: [The right to be informed](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/the-right-to-be-informed/), [Age appropriate design code](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/childrens-information/childrens-code-guidance-and-resources/age-appropriate-design-a-code-of-practice-for-online-services/); Article 29 Working Party / EDPB: [Guidelines on transparency (WP260 rev.01)](https://ec.europa.eu/newsroom/article29/items/622227); California: [CCPA](https://oag.ca.gov/privacy/ccpa), [11 CCR § 7011](https://www.law.cornell.edu/regulations/california/11-CCR-7011), [11 CCR § 7012](https://www.law.cornell.edu/regulations/california/11-CCR-7012); FTC: [COPPA Rule, 16 CFR Part 312](https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-312)
- Google Play: [User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311), [Privacy policy field and requirements](https://support.google.com/googleplay/android-developer/answer/9859455), [Data safety section](https://support.google.com/googleplay/android-developer/answer/10787469)
- Apple: [App Review Guidelines 5.1.1](https://developer.apple.com/app-store/review/guidelines/#5.1.1), [App Privacy details (privacy links)](https://developer.apple.com/app-store/app-privacy-details/#privacy-links), [Inspecting app activity data (App Privacy Report)](https://developer.apple.com/documentation/network/inspecting-app-activity-data)
- CWE: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
