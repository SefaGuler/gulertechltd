---
title: "Client-Side Testing Guide"
date: 2026-11-15 22:20:00 +0000
subcategory: client-side
summary: "Hub for the Client-Side notes: origins and browser trust, safe marker proofs, a test plan, all 100 tests, ASVS V3 coverage and rating rules."
refs: [WSTG-CLNT, WSTG-INJT-01, WSTG-INJT-02, v5.0.0-V3, v5.0.0-1.2.1, v5.0.0-1.3.1, "A05:2025", "A01:2025", "A02:2025", "A06:2025", "A08:2025", CWE-79, CWE-942, CWE-1021, CWE-1022, CWE-346, CWE-601, CWE-922, CWE-829]
tags: [web, client-side, xss, browser-security, methodology, asvs]
---

A client-side bug is one that lands in the browser. The flaw may sit in server code (a template that does not encode, a CORS policy that trusts the wrong origin, a missing header) or in JavaScript the server sent (a sink fed from the URL, a message listener with no origin check). Either way, the harm happens in the victim's browser: attacker code runs with the application's origin, a page on another origin reads what it should not, the application's window is framed, opened or messaged by a stranger, or the user is sent somewhere they did not choose. That is why these findings need a second party, the victim, and why their impact depends on what the victim's session can do. Cross-site scripting is the largest part of the subcategory. The [OWASP Top 10:2025](https://top10.owasp.org/2025/A05_2025-Injection/) files it under `A05:2025` Injection, and the rest of the subcategory is spread across `A01:2025` Broken Access Control (CORS, redirects, browser storage), `A02:2025` Security Misconfiguration (headers), `A06:2025` Insecure Design (clickjacking, tabnabbing), `A07:2025` Authentication Failures (origin validation) and `A08:2025` Software or Data Integrity Failures (third-party scripts). This page is the hub of the Client-Side subcategory of our [Web Application Security testing guide](/web/web-application-security-testing-guide/). It covers reflected, stored, blind and DOM-based XSS, client-side template injection, Content Security Policy and the other browser security headers, CORS and cross-site script inclusion, clickjacking and reverse tabnabbing, postMessage, DOM clobbering and other scriptless injection, open redirects, and what the browser keeps for an origin: storage, service workers, secrets in bundles and third-party scripts. Related topics live elsewhere. Cookies, CSRF and JWTs belong to Session Management, WebSockets and cache poisoning to HTTP & Infrastructure, and OAuth `redirect_uri` validation to Authentication. Those three are not written yet. Header and response-splitting injection is in the Injection subcategory, in [CRLF, header, log and CSV injection](/web/web-crlf-header-log-csv-injection/), and server-side prototype pollution in [its own note](/web/web-server-side-prototype-pollution/). The hub sets out the model, the safe-proof rules that every note follows, the order we test in, a table of all 100 tests with their WSTG and ASVS 5.0 mapping, ASVS V3 coverage, the rating conventions and a practice path. Rules of engagement, Burp set-up and the severity scale are in the series hub and are not repeated here. Everything assumes an authorised engagement, a bug bounty programme whose rules allow client-side testing, or a lab. Outputs shown on this page are illustrative.

## Contents

- [How client-side bugs work](#how-client-side-bugs-work)
  - [Origins and the same-origin policy](#origins-and-the-same-origin-policy)
  - [The browser's trust decisions](#the-browsers-trust-decisions)
  - [Browser boundaries and the notes that test them](#browser-boundaries-and-the-notes-that-test-them)
  - [Why it keeps happening](#why-it-keeps-happening)
- [Safe proofs](#safe-proofs)
  - [Marker payloads](#marker-payloads)
  - [Stored payloads and clean-up](#stored-payloads-and-clean-up)
  - [Blind XSS](#blind-xss)
  - [Local proof-of-concept pages](#local-proof-of-concept-pages)
  - [The proof per note](#the-proof-per-note)
  - [What we never do](#what-we-never-do)
- [Test plan](#test-plan)
  - [Order of work](#order-of-work)
  - [Tooling](#tooling)
  - [Where scanners help and where they mislead](#where-scanners-help-and-where-they-mislead)
  - [Prioritisation](#prioritisation)
- [Notes in this subcategory](#notes-in-this-subcategory)
  - [Reflected and stored XSS](#reflected-and-stored-xss)
  - [DOM XSS and client-side injection](#dom-xss-and-client-side-injection)
  - [CSP and browser security headers](#csp-and-browser-security-headers)
  - [CORS and cross-site script inclusion](#cors-and-cross-site-script-inclusion)
  - [Clickjacking and reverse tabnabbing](#clickjacking-and-reverse-tabnabbing)
  - [postMessage and web messaging](#postmessage-and-web-messaging)
  - [DOM clobbering, CSS injection and scriptless attacks](#dom-clobbering-css-injection-and-scriptless-attacks)
  - [Open redirects](#open-redirects)
  - [Browser storage, client-side secrets and third-party scripts](#browser-storage-client-side-secrets-and-third-party-scripts)
- [All tests at a glance](#all-tests-at-a-glance)
- [ASVS 5.0 V3 coverage](#asvs-50-v3-coverage)
- [Rating client-side findings](#rating-client-side-findings)
  - [Conventions](#conventions)
  - [Typical ratings](#typical-ratings)
- [Prevention patterns](#prevention-patterns)
  - [The patterns](#the-patterns)
  - [Regression tests](#regression-tests)
- [Practice path](#practice-path)
- [References](#references)

## How client-side bugs work

### Origins and the same-origin policy

An **origin** is the triple of scheme, host and port: `https://app.example.com` and `https://api.example.com` are different origins, and so are `http://app.example.com` and `https://app.example.com`. A **site** is coarser: the scheme plus the registrable domain, so every `https://*.example.com` host is the same site. The distinction matters throughout this subcategory. The [same-origin policy](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Same-origin_policy) is enforced per origin, while cookies are scoped by host and their `SameSite` attribute is judged per site.

The policy is narrower than people expect. A page may *send* requests almost anywhere: forms post cross-site, images, scripts and stylesheets load from any host, and the browser attaches the cookies it holds for the destination. What the policy blocks is *reading*: script on one origin cannot read another origin's responses, DOM or storage. Three relaxations account for most of what follows:

- **Embedding executes or renders in the embedder's context.** A cross-origin script runs with the including page's authority, and a cross-origin page can be framed unless it refuses. That is the root of cross-site script inclusion, JSONP and clickjacking.
- **CORS lets a server opt in to cross-origin reads**, including credentialed ones. A wrong opt-in turns every visitor's browser into a reader for the attacker.
- **Windows can talk.** A page holding a reference to another window (a frame it embeds, a popup it opened, the page that opened it) can navigate it and send it messages, whatever its origin.

Script that runs *inside* an origin has all of that origin's authority. It can read the DOM, call the API with the user's cookies, read `localStorage`, register a service worker and change what the user sees. Getting code into the origin is the most serious outcome in this subcategory; reading across the boundary and hijacking the user's interaction or navigation are the other two families.

### The browser's trust decisions

For every page it renders, the browser answers four questions. Each finding in this subcategory is a case where the application lets the browser answer one of them wrongly.

1. **What executes in this origin?** Script the server templated into the page, script the page's own JavaScript built from the URL, from storage or from a message, markup that changes how existing script behaves, and every third-party script the page includes. CSP and Trusted Types narrow the answer, and SRI pins what a third-party file may contain.
2. **What may be read across origins?** API responses opened up by CORS, data that parses as script, messages posted to `*`, page content carried out by dangling markup or CSS, and URLs that travel in the `Referer` header to third parties.
3. **What may frame, open or message this window?** The answer comes from `frame-ancestors` and `X-Frame-Options`, Cross-Origin-Opener-Policy, `rel="noopener"` and the origin checks in every `message` listener.
4. **Where may the page send the user?** Server redirects, client-side navigation sinks, `javascript:` URLs, meta refresh, the base URL and form targets.

A test answers one question for one page and one path in. Record the answer together with what the victim must do (open a link, view a page, click) and what their session can do. Those two facts drive every rating in this subcategory.

### Browser boundaries and the notes that test them

| Boundary | The browser's decision | Typical failure | Note | WSTG | ASVS 5.0 | Default CWE | Top 10:2025 |
|---|---|---|---|---|---|---|---|
| Server-rendered output | Is this text or markup and script? | Missing or wrong-context encoding, escape hatches, unsafe sanitiser settings, uploads served as HTML | [Reflected and stored XSS](/web/web-reflected-stored-xss/) | WSTG-INJT-01, WSTG-INJT-02, WSTG-CLNT-03 | `1.2.1`–`1.2.3` L1, `1.3.1` L1, `1.3.4` L2, `1.3.5` L2, `3.2.1` L1 | CWE-79 | A05 |
| Client code | Does a value from the URL, storage, the server or a message reach an HTML, script or URL sink? | `innerHTML`, `eval`, `javascript:` navigation, script URLs from the page address, AngularJS expressions, pollution gadgets | [DOM XSS](/web/web-dom-xss-client-side-injection/) | WSTG-CLNT-01, WSTG-CLNT-02, WSTG-CLNT-06, WSTG-CLNT-15 | `3.2.2` L1, `1.3.2` L1, `1.3.7` L2 | CWE-79, CWE-95, CWE-1336 | A05 |
| Policy headers | What may load and run, over what transport, with what referrer? | `'unsafe-inline'`, allow-listed gadget hosts, reused nonces, short HSTS, no `nosniff`, inconsistent coverage | [CSP and headers](/web/web-content-security-policy-headers/) | WSTG-CONF-12, WSTG-CONF-14, WSTG-CONF-07 | `3.4.1`–`3.4.8`, `3.7.4` | The CWE of the weakness mitigated; CWE-693 only as a last resort | A02 |
| Cross-origin reads | May this origin read the response, with credentials? | Reflected or `null` origins, broken suffix checks, trusted subdomains, JSONP, data in script files | [CORS and XSSI](/web/web-cors-xssi/) | WSTG-CLNT-07, WSTG-CLNT-13 | `3.4.2` L1, `3.5.1` L1, `3.5.2` L1, `3.5.6`–`3.5.8` L3 | CWE-942, CWE-346 | A01, A02 |
| Framing and window references | May another site frame or keep a handle on this window? | No `frame-ancestors`, partial coverage, frame busting only, links that keep `window.opener` | [Clickjacking and tabnabbing](/web/web-clickjacking-tabnabbing/) | WSTG-CLNT-09, WSTG-CLNT-14 | `3.4.6` L2, `3.4.8` L3 | CWE-1021, CWE-1022 | A06 |
| Cross-window messages | Does this listener trust the sender, and does this sender trust the receiver? | No or bypassable origin check, message data in sinks, tokens posted to `*` | [postMessage](/web/web-postmessage-web-messaging/) | WSTG-CLNT-11 | `3.5.5` L2 | CWE-346, CWE-940, CWE-201 | A07, A05, A01 |
| Markup without script | What do allowed tags and attributes change? | Named elements shadowing globals, injected CSS, dangling markup, `base`, meta refresh and form hijacking | [Clobbering and CSS](/web/web-dom-clobbering-css-injection/) | WSTG-CLNT-16, WSTG-CLNT-05, WSTG-CLNT-03 | `3.2.3` L3, `1.3.5` L2, `3.4.3` L2 | CWE-79 | A05 |
| Navigation | Where may the application send the user? | No allow-list, prefix and substring matching, parser differentials, dangerous schemes | [Open redirect](/web/web-open-redirect/) | WSTG-CLNT-04 | `3.7.2` L2, `3.7.3` L3, `1.2.2` L1 | CWE-601 | A01 |
| What the origin keeps and whom it trusts | What survives logout, what ships in the bundle, which third parties run as the origin? | Tokens in storage, cached personal data, live secrets and source maps, scripts without SRI or from dead domains | [Storage and scripts](/web/web-browser-storage-third-party-scripts/) | WSTG-CLNT-12, WSTG-INFO-05 | `14.3.1`–`14.3.3`, `3.6.1` L3, `13.3.1` L2 | CWE-922, CWE-540, CWE-829 | A01, A08, A03 |

Two WSTG client-side pages are not covered here. WSTG-CLNT-08 (Cross Site Flashing) describes a dead plugin; the supported-technology check of ASVS `v5.0.0-3.7.1` is part of DOM-1 and STOR-11. WSTG-CLNT-10 (WebSockets) belongs to HTTP & Infrastructure. At the time of writing the online [WSTG client-side chapter](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/) also lists a newer DNS rebinding page, which this subcategory does not cover. The OWASP API Security Top 10 2023 has no client-side category; the notes cite `API8:2023` Security Misconfiguration only for CORS policies and headers on API responses.

### Why it keeps happening

Most applications we test use a framework that escapes output by default, and many send a CSP. Client-side bugs survive in the gaps:

- **Escape hatches.** `dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrustHtml`, `|safe`, `th:utext`, raw Blade output and `innerHTML` exist for rich content, and each one hands encoding back to the developer.
- **Rendering moved to the browser.** In a single-page application the server returns JSON and the client builds the page, so a server-side scanner that looks for its payload in the response never sees the sink.
- **Contexts the framework does not know.** URLs (`javascript:`), inline script and JSON blocks, CSS values and attribute names are outside what HTML auto-escaping protects.
- **Configuration in many layers.** Headers and CORS rules are set by the framework, the web server, the CDN and sometimes the load balancer, and they drift between routes, status codes and static files.
- **Code nobody on the team wrote.** Widgets, payment frames, chat and analytics scripts, tag managers and SSO popups talk to the page through `postMessage` and run with its authority.
- **Old libraries.** jQuery, AngularJS 1.x and old DOMPurify releases ship known sinks and bypasses long after the application stopped being actively developed.

## Safe proofs

A client-side test is finished when you have shown that the browser made the wrong decision: a marker ran in the origin, a local page read your own data across origins, your own window was framed or messaged, or the browser went to `https://example.org/`. Impact beyond that point (session riding, token theft, account takeover) is real, but it happens in someone else's browser, and demonstrating it on a client system would mean attacking a person. The report describes it in prose and links public research; the notes give the wording. These rules are stricter than the injection proof ladder because the payload's victim is a human being, not an interpreter.

### Marker payloads

Every payload proves execution and nothing else:

- `alert(document.domain)` shows *which origin* the script runs in, which matters for sandbox and user-content domains.
- `print()` works where dialogs are suppressed (Chrome blocks `alert()` from cross-origin frames).
- `console.log('GT-XSS-014')` or a visible text marker such as `GT-XSS-014` when you want no dialog at all, and HTML-only markers (a bold `GT-` string) for stored probes that need no script.

Give every payload a unique ID that names the note and a sequence number, and put the ID in the payload itself, so that a dialog seen weeks later can be traced to one request, one field and one tester. A payload never reads or sends cookies, tokens, storage, DOM contents or keystrokes, never loads a remote framework, never propagates itself and never acts as the victim. For payload variety, link the [PortSwigger XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) in the report rather than building a list; a sanitiser or filter that fails against a handful of variants is a finding about that filter, and we stop there.

### Stored payloads and clean-up

Stored probes are writes that other people's browsers may render. The rules:

- **Where.** Only in objects that only your own test accounts can see, or in a staging environment. Anything real users or staff would render (public comments, shared workspaces, support tickets, admin views) needs written approval per location.
- **Register.** Record every stored probe the moment you place it, including plain-text canaries: ID, account, object and field, where it renders, payload, time placed, time removed. The XSS note has the template.
- **Clean-up.** At the end of testing, and at the end of each day for anything in a shared area, restore every field in the register or delete the object. Re-check that it no longer renders, including search indexes, caches and email digests. List anything you could not remove in the report and ask the client to purge it.
- **Stop rule.** If a payload fires somewhere you did not expect (a public page, another customer's view, a staff tool without approval), remove it at once and tell the client the same day.

### Blind XSS

Blind XSS is a payload that fires in a back-office tool you cannot see. It is never a default test. It needs written approval naming the channels and tools, a collaborator only you can see (Burp Collaborator or a self-hosted interactsh), one unique subdomain per placement, and a callback that reports only that it fired and `location.origin` plus `location.pathname`. No query string or fragment, which may carry tokens, and no referrer. Hosted blind-XSS services collect much more by default (cookies, the full DOM, screenshots), so do not use them against a client unless self-hosted and stripped down to that minimal callback. First ask for an account on the back-office tool: with one, the test becomes an ordinary stored test with an HTML-only marker, which is safer and gives better evidence. The interaction records the staff member's IP address and browser; treat them as personal data and redact them in the report. Test XSS-9 has the full procedure.

### Local proof-of-concept pages

CORS, clickjacking, postMessage and tabnabbing are proven with HTML pages you write. They are local files served from loopback (`python3 -m http.server 8000 --bind 127.0.0.1` gives a real foreign origin; a `file:` page has the origin `null`, which is useful only for one check). They are opened in your own browser profile, logged into your own test account. They **display the result on the page and send nothing anywhere**: no `fetch` to a logging endpoint, no image beacons, no collaborator. Show field names and masked values, not records. Where a test needs a look-alike origin, map a name you control to `127.0.0.1` in your hosts file or let Playwright fulfil it locally; never use a domain that belongs to someone else. No deceptive pages, nothing hosted where a real user could open it, and any token you receive in your own PoC is masked in screenshots and revoked afterwards.

Three more channels follow the same idea. **Open redirects** go to `https://example.org/` only. **CSS injection and dangling markup** are proven with a single request to your own collaborator, triggered by the injected style or tag and carrying no page data; character-by-character exfiltration is described in prose. **Clickjacking** PoCs show the frame at partial opacity, and no decoy is ever shown to anyone else.

### The proof per note

| Note | Enough to prove it | Ceiling | Never |
|---|---|---|---|
| [Reflected and stored XSS](/web/web-reflected-stored-xss/) | Unencoded special characters in the raw response, then a marker firing from a link in a real browser | `alert(document.domain)` in your own session; stored markers in your own objects | Cookie or DOM reads, hooks, stored payloads in real users' views without approval |
| [DOM XSS](/web/web-dom-xss-client-side-injection/) | Canary traced from source to sink in the debugger, then a marker firing | Marker firing, with the stack trace as evidence | Sandbox escapes or gadget chains developed on client systems |
| [CSP and headers](/web/web-content-security-policy-headers/) | Header values verbatim per response type; CSP Evaluator output; the violation in the console | A marker blocked or allowed, on a page where an injection already exists | Policy bypass research against production |
| [CORS and XSSI](/web/web-cors-xssi/) | curl with an `Origin` header showing the reflected `Access-Control-*` headers | A local page reading your own data with credentials, and failing after logout | A second request carrying the data anywhere |
| [Clickjacking and tabnabbing](/web/web-clickjacking-tabnabbing/) | Missing `frame-ancestors` on the response that matters, the framed page loaded authenticated | Your own click in the local PoC changing your own account; opener check showing `window.opener` | A lure or decoy shown to anyone else |
| [postMessage](/web/web-postmessage-web-messaging/) | The listener's code and its check, a marker message accepted from a foreign origin | A marker or `print()` fired by your local page; your own token received and masked | Messages that perform real transactions; fuzzing third-party frames |
| [Clobbering and CSS](/web/web-dom-clobbering-css-injection/) | The markup that survived sanitising and the reference it shadows | A clobbered value reaching a sink with a marker; one collaborator request from CSS | Reading page data through CSS or dangling markup |
| [Open redirect](/web/web-open-redirect/) | The `Location` value or sink assignment | A browser landing on `https://example.org/` | Phishing pages, redirect chains carrying real tokens |
| [Storage and scripts](/web/web-browser-storage-third-party-scripts/) | The storage key or bundle offset, classified, with values redacted | The client confirming what a secret can do | Using any secret found; registering a dead script domain |

### What we never do

- **No session riding or account takeover**, even against our own accounts, on client systems. Prove the primitive and describe the chain.
- **No data leaving the browser.** Payloads and PoC pages send nothing to any host except the single, data-free callback that blind XSS, CSS injection and dangling markup proofs allow.
- **No payload lists or evasion catalogues.** A few variants against a filter, then a finding about the filter. Known sanitiser bypass CVEs are handled as version checks.
- **No lures.** No phishing pages, no decoys for real users, no links sent to client staff.
- **No use of secrets.** A key found in a bundle is classified and reported, never tried. A dead domain that serves a script is reported, never registered.
- **No real third parties.** Payment, identity, chat and analytics frames are observed in your own browser, not fuzzed, unless they are explicitly in scope.

If any test shows data that is not yours (another customer's record next to your canary, a message carrying someone else's details, a secret in a staff page), stop that line, keep only the minimum redacted evidence and report it at once, as the series hub's stop-on-real-data rule requires.

## Test plan

### Order of work

1. **Inventory in one pass.** Walk the application in Burp's browser with two test accounts and run the mapping tests together: XSS-1 (canaries in every reflected and stored field), DOM-1 (frameworks, libraries and versions), CSP-1 (headers per response type), CORS-1 (CORS behaviour and how the API authenticates), CLICK-1 (pages with one-click actions), MSG-1 (listeners and senders), CLOB-1 (what survives the sanitiser), REDIR-1 (redirect parameters and sinks), STOR-1, STOR-6 and STOR-10 (storage, bundles and source maps, third-party scripts). Record the session cookie's attributes at the same time; they decide whether CORS and framing findings are exploitable.
2. **Configuration and header review.** These are cheap and touch nothing: CSP-2 to CSP-12, CLICK-2, the header-only CORS probes (CORS-2 to CORS-9 with curl), CLICK-8 (links and `window.open` calls), STOR-7 and STOR-8 (secrets in bundles) and STOR-11 (SRI and dead origins). A live secret goes to the client the same day.
3. **Reflected and DOM injection.** XSS-2 to XSS-7 per context, DOM-2 to DOM-11, and the redirect tests REDIR-2 to REDIR-8. Confirm every reflected finding from a link in a real browser.
4. **Stored and second-order paths.** XSS-8, XSS-10 and XSS-11, CLOB-1 to CLOB-9, with the register open. XSS-9 (blind) only with approval, and only after asking for a back-office account instead.
5. **Cross-window behaviour.** MSG-2 to MSG-10, CLICK-3 to CLICK-7, CLICK-9 and CLICK-10. These need the local PoC pages and your own session.
6. **Browser confirmation of the reads.** CORS-10 (credentialed read with a local page), CORS-11 and CORS-12 (JSONP and XSSI), STOR-2 to STOR-5 (tokens, logout, service workers) and STOR-12 (data sent to third parties).
7. **Source review** where you have code or source maps: XSS-12, DOM-12, CLOB-3, the static half of MSG-3, and STOR-9. Run these first if source is available on day one; they turn the black-box search into a list of sinks to confirm.
8. **Clean-up.** Remove every stored probe, revoke tokens you captured in your own PoCs, unregister service workers you changed, and record what you could not remove.

### Tooling

- **Burp Suite.** Repeater with the raw response view; Logger; Burp's search across history to find canaries in responses to *other* requests (stored reflections); Param Miner for unlinked reflected parameters; a Proxy match-and-replace rule that adds a probe `Origin` header to every request (CORS-1); Collaborator for the approved callbacks.
- **DOM Invader** in Burp's browser. Canary injection with source and sink tracing for DOM XSS, the web-message views for postMessage, and the prototype pollution and DOM clobbering scans. Its message-generation and origin-spoofing settings send real messages to the page, so use them only in your own session.
- **Browser DevTools.** The Sources panel with DOM and event-listener breakpoints for tracing sinks, `getEventListeners(window)` typed into the Console, the Application panel for storage, Cache Storage and service workers, the Network panel for what actually loads, and the Console for CSP violation messages.
- **Playwright.** A repeatable harness: it serves look-alike origins locally with route fulfilment, records dialogs and console markers, and becomes the client's regression test. The DOM, postMessage, open-redirect and clickjacking notes give the scripts.
- **Smaller tools from the notes.** [CSP Evaluator](https://csp-evaluator.withgoogle.com/) and the header-matrix script in the CSP note; Retire.js for library versions; gitleaks and trufflehog over downloaded bundles and source maps; CodeQL and Semgrep rules for sinks, listeners and redirects in source.

### Where scanners help and where they mislead

Burp Scanner and ZAP find reflected XSS in server responses well, and Burp's browser-powered scanning finds some DOM XSS. They also list every missing header, which is where the trouble starts. Our triage rules:

- **Every reported XSS is re-proven in a real browser from a link,** with a marker and `document.domain`. A scanner payload in Repeater may not survive the browser's URL encoding, and a reflection in a JSON response with `nosniff` is not XSS.
- **Scanners store payloads.** An active scan submits forms and can leave hundreds of stored probes in places other people see. Agree scope and rate, scope it to chosen requests, and add anything it stored to the register.
- **Header findings are not findings until rated.** "Missing CSP" or "missing X-Frame-Options" on every response is one hardening item, or a real finding only on the pages where it matters (CSP and clickjacking notes).
- **CORS reflection needs context.** A scanner that sees an echoed `Origin` does not know whether the API uses cookies or bearer tokens, what the `SameSite` value is, or whether the data is sensitive. CORS-1 and CORS-10 decide.
- **What scanners miss.** Second-order rendering in staff tools, sinks behind clicks and routes in single-page applications, message listeners, clobbering gadgets, sanitiser configuration, opener relationships, cached data after logout and secrets in source maps. A clean scan narrows the search; it does not close a test.

### Prioritisation

You will not run every test on every page. Rank by what a victim's browser would lose if the decision went wrong:

| Priority | What the victim's browser would lose | Where to look first | Tests |
|---|---|---|---|
| 1 | A staff or admin session to attacker script | Customer input rendered in help desks, admin lists, moderation queues; rich text and uploads | XSS-8 to XSS-11, DOM-4, CLOB-4 |
| 1 | Tokens or authorisation codes leaving the origin | SSO popups, OAuth callbacks, login and logout redirects, `postMessage` senders, `Referer` to third parties | MSG-8, MSG-9, REDIR-9, STOR-2, STOR-12 |
| 1 | Server-side secrets shipped to every visitor | Bundles, source maps, environment variables compiled into the front end | STOR-6 to STOR-8 |
| 2 | Authenticated API data read by any site | CORS on cookie-authenticated APIs, JSONP, user data in JavaScript files | CORS-2 to CORS-12 |
| 2 | The user's session to script delivered by a link | Search, error and 404 pages, URL-driven routes, message listeners | XSS-2 to XSS-7, DOM-2 to DOM-11, MSG-4 to MSG-6 |
| 2 | Security-sensitive clicks | Account security settings, consent, payment and admin actions in a frame | CLICK-1 to CLICK-7 |
| 3 | The user's trust in where they are | Redirect parameters, link wrappers, tabnabbing, meta refresh | REDIR-2 to REDIR-10, CLICK-8 to CLICK-10, CLOB-8 |
| 3 | Defence in depth that multiplies other bugs | CSP strength, headers, storage after logout, service workers, SRI | CSP-2 to CSP-12, STOR-3 to STOR-5, STOR-11 |

Within each band, pages behind login beat public pages, and administrative users beat ordinary ones. A finding on an origin that also hosts the login form or the account settings outranks the same finding on a marketing subdomain.

## Notes in this subcategory

The nine notes, in the order they were written. Each one has its own *Before you start*, tests, secure implementation for Node.js, Django, Spring and Laravel where they apply, practice labs, real-world cases, rating table and mapping.

### Reflected and stored XSS

[Reflected and Stored XSS: Contexts, Encoding and Sanitisation](/web/web-reflected-stored-xss/) covers input that a server renders into a page as markup or script. It works context by context (HTML body, quoted and unquoted attributes, URLs, JavaScript strings and JSON-in-script, CSS and SVG) and explains why the encoding has to match the context. It then follows stored input through every place it renders, including back-office tools, and covers rich text and Markdown sanitisers, uploaded files and `nosniff`, framework escape hatches, and blind XSS under written approval with a minimal callback. The fixes cover Express templates, React, Angular, Vue, Django, Jinja2, Thymeleaf, Blade and Rails.

- GT-WEB-XSS-1: Map reflection and storage points with a unique canary
- GT-WEB-XSS-2: Probe special characters and identify the context
- GT-WEB-XSS-3: HTML body context, HTML injection and error pages
- GT-WEB-XSS-4: Quoted and unquoted attribute contexts
- GT-WEB-XSS-5: URL contexts and dangerous schemes
- GT-WEB-XSS-6: JavaScript string, template literal and JSON-in-script contexts
- GT-WEB-XSS-7: CSS, SVG and XML contexts
- GT-WEB-XSS-8: Stored XSS across write and render paths
- GT-WEB-XSS-9: Blind XSS in back-office tools
- GT-WEB-XSS-10: Rich text, Markdown and sanitiser review
- GT-WEB-XSS-11: Uploaded files, Content-Type and nosniff
- GT-WEB-XSS-12: Framework escape-hatch and template review

### DOM XSS and client-side injection

[DOM XSS and Client-Side Injection](/web/web-dom-xss-client-side-injection/) covers bugs that live entirely in the page's own JavaScript: a source the attacker controls (the URL, `window.name`, storage, API data) reaching an HTML, script or navigation sink. It traces canaries with DOM Invader and the debugger, and covers `javascript:` URLs, client-side resource manipulation, jQuery sinks, React, Angular and Vue escape hatches, AngularJS template injection and client-side prototype pollution as a source. The fixes centre on text APIs, DOMPurify and the Sanitizer API, and Trusted Types.

- GT-WEB-DOM-1: Inventory client-side code, frameworks and library versions
- GT-WEB-DOM-2: Trace URL sources into HTML sinks with a canary
- GT-WEB-DOM-3: Sweep sources and sinks with DOM Invader
- GT-WEB-DOM-4: Referrer, window name, storage, cookies and API data as sources
- GT-WEB-DOM-5: JavaScript execution sinks
- GT-WEB-DOM-6: Navigation and URL attribute sinks with javascript URLs
- GT-WEB-DOM-7: Client-side resource manipulation
- GT-WEB-DOM-8: jQuery sinks and jQuery version checks
- GT-WEB-DOM-9: Framework escape hatches in React, Angular and Vue
- GT-WEB-DOM-10: Client-side template injection in AngularJS and Vue
- GT-WEB-DOM-11: Client-side prototype pollution as a DOM XSS source
- GT-WEB-DOM-12: Static review of bundles and Trusted Types sink discovery

### CSP and browser security headers

[Content Security Policy and Browser Security Headers](/web/web-content-security-policy-headers/) reviews the controls that limit what a page may load, where it may be framed and how it travels. It compares allow-list and strict CSP, and checks for unsafe keywords, allow-listed hosts with script gadgets, nonce quality, the directives that do not fall back to `default-src`, Trusted Types enforcement and reporting. It also covers HSTS, `nosniff`, Referrer-Policy, COOP, COEP, CORP and Permissions-Policy, across every response type and not only the home page. Header findings are rated by what they would have prevented.

- GT-WEB-CSP-1: Build a header inventory across response types
- GT-WEB-CSP-2: Confirm the policy is enforced, delivered by header and consistent
- GT-WEB-CSP-3: Review script-src for unsafe keywords, wildcards and schemes
- GT-WEB-CSP-4: Check allow-listed hosts for JSONP, old libraries and user content
- GT-WEB-CSP-5: Test nonce and hash quality
- GT-WEB-CSP-6: Check object-src, base-uri, form-action and other non-fallback directives
- GT-WEB-CSP-7: Verify frame-ancestors and X-Frame-Options
- GT-WEB-CSP-8: Review Trusted Types enforcement
- GT-WEB-CSP-9: Verify CSP reporting
- GT-WEB-CSP-10: Verify HSTS and the HTTP-to-HTTPS path
- GT-WEB-CSP-11: Check X-Content-Type-Options, Content-Type and Referrer-Policy
- GT-WEB-CSP-12: Review COOP, COEP, CORP, Permissions-Policy and deprecated headers

### CORS and cross-site script inclusion

[CORS Misconfiguration and Cross-Site Script Inclusion](/web/web-cors-xssi/) covers the two ways another site's page can read an application's authenticated data. One is a CORS policy that trusts the wrong origins: reflected, `null`, broken suffix and prefix checks, every subdomain, `http` origins, missing `Vary: Origin`, and preflight gaps. The other is a response that parses as script: JSONP and JavaScript files with user data. Every exploitable finding is confirmed with a local page that reads only your own account and sends nothing. The fixes cover Express, Django, Spring, Laravel and the proxy layer.

- GT-WEB-CORS-1: Inventory CORS behaviour and the authentication model
- GT-WEB-CORS-2: Arbitrary Origin reflection
- GT-WEB-CORS-3: Null origin trust
- GT-WEB-CORS-4: Origin-validation parsing flaws
- GT-WEB-CORS-5: Trusted subdomains and third-party origins
- GT-WEB-CORS-6: Insecure-scheme origins on HTTPS endpoints
- GT-WEB-CORS-7: Wildcard responses, non-credentialed data and internal hosts
- GT-WEB-CORS-8: Preflight policy and requests that skip the preflight
- GT-WEB-CORS-9: Vary: Origin and cache behaviour
- GT-WEB-CORS-10: Confirm a credentialed read with a local proof-of-concept page
- GT-WEB-CORS-11: JSONP and callback parameters
- GT-WEB-CORS-12: Script inclusion of dynamic JavaScript and data responses

### Clickjacking and reverse tabnabbing

[Clickjacking, UI Redressing and Reverse Tabnabbing](/web/web-clickjacking-tabnabbing/) covers pages that another site can frame and trick the user into clicking, and windows that keep a handle on the page that opened them. It starts from which pages have a one-click action worth stealing. It then checks `frame-ancestors` and `X-Frame-Options` across routes and status codes, whether session cookies reach a cross-site frame at all, frame busting, prefilled forms and timing attacks on consent pages, and `window.opener` access and COOP.

- GT-WEB-CLICK-1: Inventory frame-sensitive pages and one-click actions
- GT-WEB-CLICK-2: Check framing headers across routes, status codes and content types
- GT-WEB-CLICK-3: Confirm framing with a local proof-of-concept page
- GT-WEB-CLICK-4: Session cookies in a cross-site frame
- GT-WEB-CLICK-5: Frame busting scripts and sandboxed iframes
- GT-WEB-CLICK-6: Prefilled forms, multi-step flows and confirmation dialogs
- GT-WEB-CLICK-7: OAuth consent, payment and approval pages against timing attacks
- GT-WEB-CLICK-8: Review links and window.open calls for opener access
- GT-WEB-CLICK-9: Prove opener access from a user-supplied link
- GT-WEB-CLICK-10: Cross-Origin-Opener-Policy on document responses

### postMessage and web messaging

[postMessage and Web Messaging Security](/web/web-postmessage-web-messaging/) covers both ends of a cross-window message. On the receiving side that means listeners with no origin check or a bypassable one, message data in DOM sinks, and messages that change state or navigation. On the sending side it means tokens and personal data posted to `*`, especially in sign-in, payment and widget popups. It also covers BroadcastChannel, MessageChannel and worker messages. PoCs are local pages that send marker messages to your own window; the fixes give a TypeScript receiver and sender plus React and Angular patterns.

- GT-WEB-MSG-1: Inventory message listeners and senders
- GT-WEB-MSG-2: Establish how a foreign page can reach the target window
- GT-WEB-MSG-3: Review each receiver's origin and source checks
- GT-WEB-MSG-4: Send marker messages from a foreign origin
- GT-WEB-MSG-5: Test flawed origin checks with lookalike origins
- GT-WEB-MSG-6: Trace message data into DOM XSS sinks
- GT-WEB-MSG-7: Message-driven navigation, state and configuration changes
- GT-WEB-MSG-8: Wildcard targetOrigin and data sent to frames and openers
- GT-WEB-MSG-9: Sign-in, SSO and payment popup flows
- GT-WEB-MSG-10: BroadcastChannel, MessageChannel and worker messages

### DOM clobbering, CSS injection and scriptless attacks

[DOM Clobbering, CSS Injection and Scriptless Attacks](/web/web-dom-clobbering-css-injection/) covers what HTML injection still achieves when a sanitiser or CSP stops script. Named elements can shadow JavaScript globals that later reach a sink, injected CSS can restyle or read the page, and dangling markup can carry page content away. `base`, meta refresh and form hijacking change where the page loads from, goes to or submits. Proofs are a marker in a sink or one data-free request to your own collaborator. The fixes cover clobber-resistant JavaScript, sanitiser configuration on four stacks and the CSP directives that close scriptless channels.

- GT-WEB-CLOB-1: Map HTML injection points and what survives sanitising
- GT-WEB-CLOB-2: Review the sanitiser configuration and version
- GT-WEB-CLOB-3: Find clobberable references in the JavaScript
- GT-WEB-CLOB-4: Confirm a clobbered reference reaches a sink
- GT-WEB-CLOB-5: Find CSS injection in style attributes, style elements and theme values
- GT-WEB-CLOB-6: Prove that injected CSS can make an outbound request
- GT-WEB-CLOB-7: Dangling markup injection
- GT-WEB-CLOB-8: Base tag and meta refresh injection
- GT-WEB-CLOB-9: Form, button and formaction hijacking
- GT-WEB-CLOB-10: Review CSP for scriptless attacks

### Open redirects

[Open Redirects: Client-Side and Server-Side](/web/web-open-redirect/) covers `Location` headers and JavaScript navigation sinks that take their destination from input. It shows how allow-lists break: prefix and substring matching, userinfo and backslashes, encoding and control characters, and parsers that disagree with the browser. It also covers the flows where a redirect matters most (login, logout and SSO) and link wrappers. Proofs go to `https://example.org/` only, and standalone redirects are rated honestly as Low.

- GT-WEB-REDIR-1: Map redirect parameters and redirect sinks
- GT-WEB-REDIR-2: Server-side redirect to an external host
- GT-WEB-REDIR-3: Client-side redirect sinks
- GT-WEB-REDIR-4: Dangerous schemes in redirect targets
- GT-WEB-REDIR-5: Scheme-relative URLs, backslashes and extra slashes
- GT-WEB-REDIR-6: Userinfo, prefix, suffix and subdomain matching
- GT-WEB-REDIR-7: Encoding, whitespace and control characters
- GT-WEB-REDIR-8: Parser differentials between validator and browser
- GT-WEB-REDIR-9: Redirects in login, logout and SSO flows
- GT-WEB-REDIR-10: Link wrappers, signed redirects and interstitial pages

### Browser storage, client-side secrets and third-party scripts

[Browser Storage, Client-Side Secrets and Third-Party Scripts](/web/web-browser-storage-third-party-scripts/) covers what the browser keeps for an origin and whom the origin trusts. That means tokens and personal data in `localStorage`, `sessionStorage` and IndexedDB, data that outlives logout, and service workers that cache authenticated responses. It also covers server-side secrets and source maps in JavaScript bundles, and third-party and tag-manager scripts with their SRI, version pinning and dead domains. Secrets are classified, never used, and the fixes cover logout clean-up, service worker design, build-time secret checks and third-party governance.

- GT-WEB-STOR-1: Inventory browser storage for each origin
- GT-WEB-STOR-2: Session and refresh tokens in script-readable storage
- GT-WEB-STOR-3: Client data after logout, expiry and account switch
- GT-WEB-STOR-4: Service worker scope and cached authenticated responses
- GT-WEB-STOR-5: Service worker updates, kill switch and unregistration
- GT-WEB-STOR-6: Collect JavaScript bundles and find source maps
- GT-WEB-STOR-7: Scan bundles and source maps for secrets
- GT-WEB-STOR-8: Classify keys as publishable or secret
- GT-WEB-STOR-9: Internal URLs, debug flags and hidden routes in client code
- GT-WEB-STOR-10: Inventory third-party scripts and what they can reach
- GT-WEB-STOR-11: SRI, pinned versions and dead origins for external assets
- GT-WEB-STOR-12: Sensitive data sent to third parties in URLs, Referer and beacons

## All tests at a glance

Built by script from the Mapping tables of the nine notes, with titles from the test headings. Both ID columns list IDs only; qualifiers such as "blind XSS", "file uploads" or "defence in depth" are in each note's Mapping table. The ASVS 5.0 column drops the `v5.0.0-` prefix for space, gives each requirement's level from the ASVS 5.0 source, and marks with "(context)" a mapping test that gives context for a requirement rather than verifying it. CWE and Top 10 mappings per test are in each note.

| Test | Title | Note | WSTG | ASVS 5.0 |
|---|---|---|---|---|
| GT-WEB-XSS-1 | Map reflection and storage points with a unique canary | [XSS](/web/web-reflected-stored-xss/) | WSTG-INJT-01, WSTG-INJT-02, WSTG-INFO-06 | 1.2.1 L1 (context) |
| GT-WEB-XSS-2 | Probe special characters and identify the context | [XSS](/web/web-reflected-stored-xss/) | WSTG-INJT-01, WSTG-INJT-02 | 1.2.1 L1, 1.2.3 L1 |
| GT-WEB-XSS-3 | HTML body context, HTML injection and error pages | [XSS](/web/web-reflected-stored-xss/) | WSTG-CLNT-03, WSTG-INJT-01, WSTG-INJT-02 | 1.2.1 L1 |
| GT-WEB-XSS-4 | Quoted and unquoted attribute contexts | [XSS](/web/web-reflected-stored-xss/) | WSTG-INJT-01, WSTG-INJT-02 | 1.2.1 L1, 1.2.3 L1 |
| GT-WEB-XSS-5 | URL contexts and dangerous schemes | [XSS](/web/web-reflected-stored-xss/) | WSTG-INJT-01, WSTG-INJT-02 | 1.2.2 L1 |
| GT-WEB-XSS-6 | JavaScript string, template literal and JSON-in-script contexts | [XSS](/web/web-reflected-stored-xss/) | WSTG-INJT-01, WSTG-INJT-02 | 1.2.3 L1, 3.2.2 L1 |
| GT-WEB-XSS-7 | CSS, SVG and XML contexts | [XSS](/web/web-reflected-stored-xss/) | WSTG-INJT-01, WSTG-INJT-02, WSTG-CLNT-05 | 1.2.1 L1, 1.3.4 L2, 1.3.5 L2 |
| GT-WEB-XSS-8 | Stored XSS across write and render paths | [XSS](/web/web-reflected-stored-xss/) | WSTG-INJT-02 | 1.2.1 L1, 1.3.1 L1 |
| GT-WEB-XSS-9 | Blind XSS in back-office tools | [XSS](/web/web-reflected-stored-xss/) | WSTG-INJT-02 | 1.2.1 L1 |
| GT-WEB-XSS-10 | Rich text, Markdown and sanitiser review | [XSS](/web/web-reflected-stored-xss/) | WSTG-INJT-01, WSTG-INJT-02 | 1.3.1 L1, 1.3.5 L2 |
| GT-WEB-XSS-11 | Uploaded files, Content-Type and nosniff | [XSS](/web/web-reflected-stored-xss/) | WSTG-INJT-02 | 3.2.1 L1, 3.4.4 L2, 1.3.4 L2, 5.4.1 L2 |
| GT-WEB-XSS-12 | Framework escape-hatch and template review | [XSS](/web/web-reflected-stored-xss/) | WSTG-INJT-01, WSTG-INJT-02 | 1.1.2 L2, 1.2.1 L1, 1.2.3 L1, 3.2.2 L1 |
| GT-WEB-DOM-1 | Inventory client-side code, frameworks and library versions | [DOM XSS](/web/web-dom-xss-client-side-injection/) | WSTG-CLNT-01, WSTG-CLNT-15 | 15.2.1 L1, 15.1.2 L2, 3.7.1 L2 |
| GT-WEB-DOM-2 | Trace URL sources into HTML sinks with a canary | [DOM XSS](/web/web-dom-xss-client-side-injection/) | WSTG-CLNT-01, WSTG-CLNT-03 | 3.2.2 L1, 1.2.1 L1 |
| GT-WEB-DOM-3 | Sweep sources and sinks with DOM Invader | [DOM XSS](/web/web-dom-xss-client-side-injection/) | WSTG-CLNT-01 | 3.2.2 L1, 1.2.1 L1 |
| GT-WEB-DOM-4 | Referrer, window name, storage, cookies and API data as sources | [DOM XSS](/web/web-dom-xss-client-side-injection/) | WSTG-CLNT-01, WSTG-CLNT-01.1 | 3.2.2 L1, 1.3.1 L1 |
| GT-WEB-DOM-5 | JavaScript execution sinks | [DOM XSS](/web/web-dom-xss-client-side-injection/) | WSTG-CLNT-02 | 1.3.2 L1, 1.2.3 L1 |
| GT-WEB-DOM-6 | Navigation and URL attribute sinks with javascript URLs | [DOM XSS](/web/web-dom-xss-client-side-injection/) | WSTG-CLNT-02, WSTG-CLNT-04 | 1.2.2 L1, 3.7.2 L2 |
| GT-WEB-DOM-7 | Client-side resource manipulation | [DOM XSS](/web/web-dom-xss-client-side-injection/) | WSTG-CLNT-06 | 1.2.2 L1, 3.4.3 L2 |
| GT-WEB-DOM-8 | jQuery sinks and jQuery version checks | [DOM XSS](/web/web-dom-xss-client-side-injection/) | WSTG-CLNT-01 | 3.2.2 L1, 15.2.1 L1 |
| GT-WEB-DOM-9 | Framework escape hatches in React, Angular and Vue | [DOM XSS](/web/web-dom-xss-client-side-injection/) | WSTG-CLNT-01, WSTG-CLNT-15 | 3.2.2 L1, 1.3.1 L1, 1.2.2 L1 |
| GT-WEB-DOM-10 | Client-side template injection in AngularJS and Vue | [DOM XSS](/web/web-dom-xss-client-side-injection/) | WSTG-CLNT-15 | 1.3.7 L2, 15.2.1 L1 |
| GT-WEB-DOM-11 | Client-side prototype pollution as a DOM XSS source | [DOM XSS](/web/web-dom-xss-client-side-injection/) | WSTG-INJT-22, WSTG-CLNT-01 | 15.3.6 L2 |
| GT-WEB-DOM-12 | Static review of bundles and Trusted Types sink discovery | [DOM XSS](/web/web-dom-xss-client-side-injection/) | WSTG-CLNT-01 | 3.4.3 L2, 3.2.2 L1, 1.3.1 L1 |
| GT-WEB-CSP-1 | Build a header inventory across response types | [CSP](/web/web-content-security-policy-headers/) | WSTG-CONF-14, WSTG-CONF-12, WSTG-CONF-07 | 3.4.1 L1, 3.4.3 L2, 3.4.4 L2 |
| GT-WEB-CSP-2 | Confirm the policy is enforced, delivered by header and consistent | [CSP](/web/web-content-security-policy-headers/) | WSTG-CONF-12, WSTG-CONF-14 | 3.4.3 L2 |
| GT-WEB-CSP-3 | Review script-src for unsafe keywords, wildcards and schemes | [CSP](/web/web-content-security-policy-headers/) | WSTG-CONF-12 | 3.4.3 L2 |
| GT-WEB-CSP-4 | Check allow-listed hosts for JSONP, old libraries and user content | [CSP](/web/web-content-security-policy-headers/) | WSTG-CONF-12 | 3.4.3 L2, 3.5.6 L3 |
| GT-WEB-CSP-5 | Test nonce and hash quality | [CSP](/web/web-content-security-policy-headers/) | WSTG-CONF-12 | 3.4.3 L2 |
| GT-WEB-CSP-6 | Check object-src, base-uri, form-action and other non-fallback directives | [CSP](/web/web-content-security-policy-headers/) | WSTG-CONF-12 | 3.4.3 L2, 3.2.1 L1 |
| GT-WEB-CSP-7 | Verify frame-ancestors and X-Frame-Options | [CSP](/web/web-content-security-policy-headers/) | WSTG-CLNT-09, WSTG-CONF-12, WSTG-CONF-14 | 3.4.6 L2 |
| GT-WEB-CSP-8 | Review Trusted Types enforcement | [CSP](/web/web-content-security-policy-headers/) | WSTG-CONF-12, WSTG-CLNT-01 | 3.4.3 L2 |
| GT-WEB-CSP-9 | Verify CSP reporting | [CSP](/web/web-content-security-policy-headers/) | WSTG-CONF-12 | 3.4.7 L3 |
| GT-WEB-CSP-10 | Verify HSTS and the HTTP-to-HTTPS path | [CSP](/web/web-content-security-policy-headers/) | WSTG-CONF-07, WSTG-CONF-14 | 3.4.1 L1, 3.7.4 L3 |
| GT-WEB-CSP-11 | Check X-Content-Type-Options, Content-Type and Referrer-Policy | [CSP](/web/web-content-security-policy-headers/) | WSTG-CONF-14 | 3.4.4 L2, 3.4.5 L2, 3.2.1 L1 |
| GT-WEB-CSP-12 | Review COOP, COEP, CORP, Permissions-Policy and deprecated headers | [CSP](/web/web-content-security-policy-headers/) | WSTG-CONF-14, WSTG-CLNT-14 | 3.4.8 L3, 3.5.8 L3, 3.1.1 L3 |
| GT-WEB-CORS-1 | Inventory CORS behaviour and the authentication model | [CORS](/web/web-cors-xssi/) | WSTG-CLNT-07, WSTG-CLNT-13 | 3.4.2 L1 (context) |
| GT-WEB-CORS-2 | Arbitrary Origin reflection | [CORS](/web/web-cors-xssi/) | WSTG-CLNT-07 | 3.4.2 L1 |
| GT-WEB-CORS-3 | Null origin trust | [CORS](/web/web-cors-xssi/) | WSTG-CLNT-07 | 3.4.2 L1 |
| GT-WEB-CORS-4 | Origin-validation parsing flaws | [CORS](/web/web-cors-xssi/) | WSTG-CLNT-07 | 3.4.2 L1 |
| GT-WEB-CORS-5 | Trusted subdomains and third-party origins | [CORS](/web/web-cors-xssi/) | WSTG-CLNT-07 | 3.4.2 L1, 3.5.4 L2 |
| GT-WEB-CORS-6 | Insecure-scheme origins on HTTPS endpoints | [CORS](/web/web-cors-xssi/) | WSTG-CLNT-07 | 3.4.2 L1, 3.4.1 L1 |
| GT-WEB-CORS-7 | Wildcard responses, non-credentialed data and internal hosts | [CORS](/web/web-cors-xssi/) | WSTG-CLNT-07 | 3.4.2 L1 |
| GT-WEB-CORS-8 | Preflight policy and requests that skip the preflight | [CORS](/web/web-cors-xssi/) | WSTG-CLNT-07 | 3.5.1 L1, 3.5.2 L1, 3.4.2 L1 |
| GT-WEB-CORS-9 | Vary: Origin and cache behaviour | [CORS](/web/web-cors-xssi/) | WSTG-CLNT-07 | 3.4.2 L1 |
| GT-WEB-CORS-10 | Confirm a credentialed read with a local proof-of-concept page | [CORS](/web/web-cors-xssi/) | WSTG-CLNT-07 | 3.4.2 L1 |
| GT-WEB-CORS-11 | JSONP and callback parameters | [CORS](/web/web-cors-xssi/) | WSTG-CLNT-13 | 3.5.6 L3 |
| GT-WEB-CORS-12 | Script inclusion of dynamic JavaScript and data responses | [CORS](/web/web-cors-xssi/) | WSTG-CLNT-13 | 3.5.7 L3, 3.5.8 L3, 3.4.4 L2, 4.1.1 L1 |
| GT-WEB-CLICK-1 | Inventory frame-sensitive pages and one-click actions | [Clickjacking](/web/web-clickjacking-tabnabbing/) | WSTG-CLNT-09 | 3.4.6 L2 (context), 7.5.1 L2 |
| GT-WEB-CLICK-2 | Check framing headers across routes, status codes and content types | [Clickjacking](/web/web-clickjacking-tabnabbing/) | WSTG-CLNT-09 | 3.4.6 L2 |
| GT-WEB-CLICK-3 | Confirm framing with a local proof-of-concept page | [Clickjacking](/web/web-clickjacking-tabnabbing/) | WSTG-CLNT-09 | 3.4.6 L2 |
| GT-WEB-CLICK-4 | Session cookies in a cross-site frame | [Clickjacking](/web/web-clickjacking-tabnabbing/) | WSTG-CLNT-09 | 3.3.2 L2 |
| GT-WEB-CLICK-5 | Frame busting scripts and sandboxed iframes | [Clickjacking](/web/web-clickjacking-tabnabbing/) | WSTG-CLNT-09 | 3.4.6 L2 |
| GT-WEB-CLICK-6 | Prefilled forms, multi-step flows and confirmation dialogs | [Clickjacking](/web/web-clickjacking-tabnabbing/) | WSTG-CLNT-09 | 3.4.6 L2, 7.5.1 L2 |
| GT-WEB-CLICK-7 | OAuth consent, payment and approval pages against timing attacks | [Clickjacking](/web/web-clickjacking-tabnabbing/) | WSTG-CLNT-09 | 10.7.1 L2, 10.7.2 L2, 7.5.1 L2 |
| GT-WEB-CLICK-8 | Review links and window.open calls for opener access | [Clickjacking](/web/web-clickjacking-tabnabbing/) | WSTG-CLNT-14 | 3.4.8 L3 |
| GT-WEB-CLICK-9 | Prove opener access from a user-supplied link | [Clickjacking](/web/web-clickjacking-tabnabbing/) | WSTG-CLNT-14 | 3.4.8 L3 |
| GT-WEB-CLICK-10 | Cross-Origin-Opener-Policy on document responses | [Clickjacking](/web/web-clickjacking-tabnabbing/) | WSTG-CLNT-14 | 3.4.8 L3 |
| GT-WEB-MSG-1 | Inventory message listeners and senders | [postMessage](/web/web-postmessage-web-messaging/) | WSTG-CLNT-11 | 3.5.5 L2 (context) |
| GT-WEB-MSG-2 | Establish how a foreign page can reach the target window | [postMessage](/web/web-postmessage-web-messaging/) | WSTG-CLNT-11, WSTG-CLNT-09, WSTG-CLNT-14 | 3.4.6 L2, 3.4.8 L3 |
| GT-WEB-MSG-3 | Review each receiver's origin and source checks | [postMessage](/web/web-postmessage-web-messaging/) | WSTG-CLNT-11 | 3.5.5 L2 |
| GT-WEB-MSG-4 | Send marker messages from a foreign origin | [postMessage](/web/web-postmessage-web-messaging/) | WSTG-CLNT-11 | 3.5.5 L2 |
| GT-WEB-MSG-5 | Test flawed origin checks with lookalike origins | [postMessage](/web/web-postmessage-web-messaging/) | WSTG-CLNT-11 | 3.5.5 L2 |
| GT-WEB-MSG-6 | Trace message data into DOM XSS sinks | [postMessage](/web/web-postmessage-web-messaging/) | WSTG-CLNT-11, WSTG-CLNT-01, WSTG-CLNT-02 | 3.5.5 L2, 3.2.2 L1, 1.3.2 L1, 1.2.2 L1 |
| GT-WEB-MSG-7 | Message-driven navigation, state and configuration changes | [postMessage](/web/web-postmessage-web-messaging/) | WSTG-CLNT-11, WSTG-CLNT-04 | 3.5.5 L2, 2.2.1 L1, 3.7.2 L2, 10.1.2 L2, 15.3.6 L2 |
| GT-WEB-MSG-8 | Wildcard targetOrigin and data sent to frames and openers | [postMessage](/web/web-postmessage-web-messaging/) | WSTG-CLNT-11 | 10.1.1 L2, 3.4.8 L3 |
| GT-WEB-MSG-9 | Sign-in, SSO and payment popup flows | [postMessage](/web/web-postmessage-web-messaging/) | WSTG-CLNT-11, WSTG-CLNT-14 | 10.1.1 L2, 10.1.2 L2, 10.2.1 L2, 3.5.5 L2 |
| GT-WEB-MSG-10 | BroadcastChannel, MessageChannel and worker messages | [postMessage](/web/web-postmessage-web-messaging/) | WSTG-CLNT-11 | 3.5.5 L2, 3.5.4 L2, 10.1.1 L2 |
| GT-WEB-CLOB-1 | Map HTML injection points and what survives sanitising | [Clobbering](/web/web-dom-clobbering-css-injection/) | WSTG-CLNT-03, WSTG-CLNT-16, WSTG-CLNT-05 | 1.3.1 L1, 1.3.5 L2 |
| GT-WEB-CLOB-2 | Review the sanitiser configuration and version | [Clobbering](/web/web-dom-clobbering-css-injection/) | WSTG-CLNT-16, WSTG-CLNT-03, WSTG-CLNT-05 | 1.3.1 L1, 1.3.5 L2, 3.2.3 L3 |
| GT-WEB-CLOB-3 | Find clobberable references in the JavaScript | [Clobbering](/web/web-dom-clobbering-css-injection/) | WSTG-CLNT-16 | 3.2.3 L3 |
| GT-WEB-CLOB-4 | Confirm a clobbered reference reaches a sink | [Clobbering](/web/web-dom-clobbering-css-injection/) | WSTG-CLNT-16, WSTG-CLNT-04 | 3.2.3 L3 |
| GT-WEB-CLOB-5 | Find CSS injection in style attributes, style elements and theme values | [Clobbering](/web/web-dom-clobbering-css-injection/) | WSTG-CLNT-05 | 1.3.5 L2, 1.2.1 L1 |
| GT-WEB-CLOB-6 | Prove that injected CSS can make an outbound request | [Clobbering](/web/web-dom-clobbering-css-injection/) | WSTG-CLNT-05 | 1.3.5 L2, 3.4.3 L2 |
| GT-WEB-CLOB-7 | Dangling markup injection | [Clobbering](/web/web-dom-clobbering-css-injection/) | WSTG-CLNT-03 | 1.2.1 L1 |
| GT-WEB-CLOB-8 | Base tag and meta refresh injection | [Clobbering](/web/web-dom-clobbering-css-injection/) | WSTG-CLNT-03, WSTG-CLNT-04 | 3.4.3 L2 |
| GT-WEB-CLOB-9 | Form, button and formaction hijacking | [Clobbering](/web/web-dom-clobbering-css-injection/) | WSTG-CLNT-03 | 3.4.3 L2, 1.3.1 L1 |
| GT-WEB-CLOB-10 | Review CSP for scriptless attacks | [Clobbering](/web/web-dom-clobbering-css-injection/) | WSTG-CLNT-05, WSTG-CLNT-16, WSTG-CLNT-03 | 3.4.3 L2 |
| GT-WEB-REDIR-1 | Map redirect parameters and redirect sinks | [Redirect](/web/web-open-redirect/) | WSTG-CLNT-04, WSTG-INFO-06, WSTG-ATHN-12, WSTG-SESS-06 | 3.7.2 L2 (context) |
| GT-WEB-REDIR-2 | Server-side redirect to an external host | [Redirect](/web/web-open-redirect/) | WSTG-CLNT-04, WSTG-ATHN-12, WSTG-SESS-06 | 3.7.2 L2, 3.7.3 L3 |
| GT-WEB-REDIR-3 | Client-side redirect sinks | [Redirect](/web/web-open-redirect/) | WSTG-CLNT-04, WSTG-CLNT-01 | 3.7.2 L2 |
| GT-WEB-REDIR-4 | Dangerous schemes in redirect targets | [Redirect](/web/web-open-redirect/) | WSTG-CLNT-04, WSTG-CLNT-01 | 1.2.2 L1 |
| GT-WEB-REDIR-5 | Scheme-relative URLs, backslashes and extra slashes | [Redirect](/web/web-open-redirect/) | WSTG-CLNT-04 | 3.7.2 L2, 2.2.1 L1 |
| GT-WEB-REDIR-6 | Userinfo, prefix, suffix and subdomain matching | [Redirect](/web/web-open-redirect/) | WSTG-CLNT-04, WSTG-ATHZ-05 | 3.7.2 L2, 10.4.1 L1 (context) |
| GT-WEB-REDIR-7 | Encoding, whitespace and control characters | [Redirect](/web/web-open-redirect/) | WSTG-CLNT-04, WSTG-INJT-15 | 1.1.1 L2, 3.7.2 L2 |
| GT-WEB-REDIR-8 | Parser differentials between validator and browser | [Redirect](/web/web-open-redirect/) | WSTG-CLNT-04 | 3.7.2 L2, 1.1.1 L2 |
| GT-WEB-REDIR-9 | Redirects in login, logout and SSO flows | [Redirect](/web/web-open-redirect/) | WSTG-CLNT-04, WSTG-ATHN-12, WSTG-SESS-06, WSTG-ATHZ-05 | 3.7.2 L2, 3.4.5 L2, 10.4.1 L1 |
| GT-WEB-REDIR-10 | Link wrappers, signed redirects and interstitial pages | [Redirect](/web/web-open-redirect/) | WSTG-CLNT-04 | 3.7.2 L2, 3.7.3 L3 |
| GT-WEB-STOR-1 | Inventory browser storage for each origin | [Storage](/web/web-browser-storage-third-party-scripts/) | WSTG-CLNT-12 | 14.3.3 L2, 14.1.1 L2 |
| GT-WEB-STOR-2 | Session and refresh tokens in script-readable storage | [Storage](/web/web-browser-storage-third-party-scripts/) | WSTG-CLNT-12 | 14.3.3 L2, 3.3.4 L2, 10.1.1 L2 |
| GT-WEB-STOR-3 | Client data after logout, expiry and account switch | [Storage](/web/web-browser-storage-third-party-scripts/) | WSTG-CLNT-12, WSTG-SESS-06, WSTG-ATHN-06 | 14.3.1 L1, 14.3.2 L2, 7.4.1 L1 |
| GT-WEB-STOR-4 | Service worker scope and cached authenticated responses | [Storage](/web/web-browser-storage-third-party-scripts/) | WSTG-CLNT-12, WSTG-ATHN-06 | 14.3.1 L1, 14.3.3 L2 |
| GT-WEB-STOR-5 | Service worker updates, kill switch and unregistration | [Storage](/web/web-browser-storage-third-party-scripts/) | WSTG-CLNT-12 | 14.3.1 L1, 3.6.1 L3 |
| GT-WEB-STOR-6 | Collect JavaScript bundles and find source maps | [Storage](/web/web-browser-storage-third-party-scripts/) | WSTG-INFO-05, WSTG-CONF-02, WSTG-APIT-03 | 13.4.2 L2 |
| GT-WEB-STOR-7 | Scan bundles and source maps for secrets | [Storage](/web/web-browser-storage-third-party-scripts/) | WSTG-INFO-05 | 13.3.1 L2 |
| GT-WEB-STOR-8 | Classify keys as publishable or secret | [Storage](/web/web-browser-storage-third-party-scripts/) | WSTG-INFO-05 | 13.3.1 L2, 13.3.2 L2 |
| GT-WEB-STOR-9 | Internal URLs, debug flags and hidden routes in client code | [Storage](/web/web-browser-storage-third-party-scripts/) | WSTG-INFO-05, WSTG-CONF-15 | 13.4.2 L2 |
| GT-WEB-STOR-10 | Inventory third-party scripts and what they can reach | [Storage](/web/web-browser-storage-third-party-scripts/) | WSTG-INFO-05, WSTG-CONF-12 | 3.6.1 L3, 14.2.3 L2, 3.4.3 L2 |
| GT-WEB-STOR-11 | SRI, pinned versions and dead origins for external assets | [Storage](/web/web-browser-storage-third-party-scripts/) | WSTG-INFO-05, WSTG-CONF-12 | 3.6.1 L3, 3.7.1 L2, 15.2.1 L1 |
| GT-WEB-STOR-12 | Sensitive data sent to third parties in URLs, Referer and beacons | [Storage](/web/web-browser-storage-third-party-scripts/) | WSTG-INFO-05 | 14.2.1 L1, 14.2.3 L2, 3.4.5 L2 |

## ASVS 5.0 V3 coverage

The requirements of [ASVS 5.0 V3 Web Frontend Security](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md), with the tests that produce evidence for each. A requirement is verified at a level only if the application is assessed at that level or higher; at L1 we still report what we saw against an L2 or L3 item as an observation. Rows marked *later subcategory* are tested elsewhere in the series.

| Requirement | Level | What it asks for (paraphrased) | Verified by |
|---|---|---|---|
| `v5.0.0-3.1.1` | L3 | Documentation states the browser security features the application relies on and what happens without them | CSP-12 (review of the documented features) |
| `v5.0.0-3.2.1` | L1 | Content is not rendered in the wrong context (`Sec-Fetch-*`, CSP `sandbox`, `Content-Disposition: attachment`) | XSS-11, CSP-6, CSP-11 |
| `v5.0.0-3.2.2` | L1 | Text is rendered with safe functions such as `textContent` | XSS-6, XSS-12, DOM-2 to DOM-4, DOM-8, DOM-9, DOM-12, MSG-6 |
| `v5.0.0-3.2.3` | L3 | Client code avoids DOM clobbering | CLOB-2 to CLOB-4 |
| `v5.0.0-3.3.1` | L1 | Cookies have `Secure` and a `__Secure-` or `__Host-` prefix | *Later subcategory* (Session Management) |
| `v5.0.0-3.3.2` | L2 | `SameSite` set per cookie purpose, against UI redress and CSRF | CLICK-4 (the framing side); the CSRF side is a *later subcategory* (Session Management) |
| `v5.0.0-3.3.3` | L2 | `__Host-` prefix unless the cookie is meant to be shared | *Later subcategory* (Session Management) |
| `v5.0.0-3.3.4` | L2 | `HttpOnly` for cookies scripts do not need, and session tokens only in `Set-Cookie` | STOR-2 (tokens readable by script); cookie attributes in full: *later subcategory* (Session Management) |
| `v5.0.0-3.3.5` | L3 | Cookie name and value within 4096 bytes | *Later subcategory* (Session Management) |
| `v5.0.0-3.4.1` | L1 | HSTS on all responses, `max-age` at least a year, subdomains from L2 | CSP-1, CSP-10, CORS-6 |
| `v5.0.0-3.4.2` | L1 | `Access-Control-Allow-Origin` fixed or checked against an allow-list; `*` only without sensitive data | CORS-1 (context), CORS-2 to CORS-10 |
| `v5.0.0-3.4.3` | L2 | CSP with `object-src 'none'`, `base-uri 'none'` and an allow-list or nonces or hashes; per-response nonces or hashes at L3 | CSP-1 to CSP-6, CSP-8; DOM-7, DOM-12; CLOB-6, CLOB-8 to CLOB-10; STOR-10 |
| `v5.0.0-3.4.4` | L2 | `nosniff` on all responses | CSP-1, CSP-11, XSS-11, CORS-12 |
| `v5.0.0-3.4.5` | L2 | A referrer policy that stops sensitive data reaching third parties | CSP-11, REDIR-9, STOR-12 |
| `v5.0.0-3.4.6` | L2 | `frame-ancestors` on every response; `X-Frame-Options` not relied on | CSP-7, CLICK-1 (context), CLICK-2, CLICK-3, CLICK-5, CLICK-6, MSG-2 |
| `v5.0.0-3.4.7` | L3 | CSP names a reporting location | CSP-9 |
| `v5.0.0-3.4.8` | L3 | COOP `same-origin` or `same-origin-allow-popups` on document responses | CSP-12, CLICK-8 to CLICK-10, MSG-2, MSG-8 |
| `v5.0.0-3.5.1` | L1 | Where the preflight is not relied on, sensitive requests carry an anti-forgery token or a non-safelisted header | CORS-8; the CSRF side is a *later subcategory* (Session Management) |
| `v5.0.0-3.5.2` | L1 | Where the preflight is relied on, the function cannot be reached without one | CORS-8 |
| `v5.0.0-3.5.3` | L1 | Sensitive functions use unsafe methods, or `Sec-Fetch-*` is validated | No test in this subcategory; *later subcategory* (Session Management, with CSRF) |
| `v5.0.0-3.5.4` | L2 | Separate applications on separate hostnames | CORS-5, MSG-10 |
| `v5.0.0-3.5.5` | L2 | `postMessage` messages from untrusted origins or with invalid syntax are discarded | MSG-1 (context), MSG-3 to MSG-7, MSG-9, MSG-10 |
| `v5.0.0-3.5.6` | L3 | No JSONP anywhere | CORS-11, CSP-4 (JSONP on allow-listed hosts) |
| `v5.0.0-3.5.7` | L3 | No data requiring authorisation in script resources | CORS-12 |
| `v5.0.0-3.5.8` | L3 | Authenticated resources loadable cross-origin only when intended (`Sec-Fetch-*` or CORP) | CORS-12, CSP-12 |
| `v5.0.0-3.6.1` | L3 | External assets static, versioned and SRI-protected, or a documented decision | STOR-5, STOR-10, STOR-11 |
| `v5.0.0-3.7.1` | L2 | Only supported client-side technologies | DOM-1, STOR-11 |
| `v5.0.0-3.7.2` | L2 | Automatic redirects to other hosts only to allow-listed destinations | REDIR-1 (context), REDIR-2, REDIR-3, REDIR-5 to REDIR-10; DOM-6, MSG-7 |
| `v5.0.0-3.7.3` | L3 | A notice with an option to cancel before leaving the application | REDIR-2, REDIR-10 |
| `v5.0.0-3.7.4` | L3 | The top-level domain is on the HSTS preload list | CSP-10 |
| `v5.0.0-3.7.5` | L3 | The application behaves as documented when the browser lacks an expected feature | No test of its own; assess together with `3.1.1` in CSP-12 where the documentation exists |

The [Injection hub](/web/web-injection-testing-guide/) left the browser-facing parts of [ASVS V1](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md) to this subcategory. They are covered here:

| Requirement | Level | What it asks for (paraphrased) | Verified by |
|---|---|---|---|
| `v5.0.0-1.2.1` | L1 | Output encoding that matches the HTML, attribute, CSS or header context | XSS-1 (context), XSS-2 to XSS-4, XSS-7 to XSS-9, XSS-12; DOM-2, DOM-3; CLOB-5, CLOB-7 |
| `v5.0.0-1.2.2` | L1 | URL encoding and safe URL schemes only | XSS-5, DOM-6, DOM-7, DOM-9, MSG-6, REDIR-4 |
| `v5.0.0-1.2.3` | L1 | Encoding when building JavaScript and JSON | XSS-2, XSS-4, XSS-6, XSS-12, DOM-5 |
| `v5.0.0-1.3.1` | L1 | WYSIWYG HTML through a well-known sanitiser | XSS-8, XSS-10, DOM-4, DOM-9, DOM-12, CLOB-1, CLOB-2, CLOB-9 |
| `v5.0.0-1.3.4` | L2 | User-supplied SVG limited to safe content | XSS-7, XSS-11 |
| `v5.0.0-1.3.5` | L2 | Markdown, CSS, XSL, BBCode and similar sanitised or disabled | XSS-7, XSS-10, CLOB-1, CLOB-2, CLOB-5, CLOB-6 |

Outside V1 and V3 the notes also produce evidence for `1.1.1`, `1.1.2`, `1.3.2` and `1.3.7` (decoding, final-step encoding, no `eval`, no templates from input), V2 (`2.2.1`), V4 (`4.1.1` content types), V5 (`5.4.1`), V7 (`7.4.1`, `7.5.1`), V10 (`10.1.1`, `10.1.2`, `10.2.1`, `10.4.1`, `10.7.1`, `10.7.2` for token handling, consent and redirect URIs), V13 (`13.3.1`, `13.3.2`, `13.4.2`), V14 (`14.1.1`, `14.2.1`, `14.2.3`, `14.3.1` to `14.3.3`) and V15 (`15.1.2`, `15.2.1`, `15.3.6`). The all-tests table lists them per test.

## Rating client-side findings

The series uses one severity scale and one approach to CVSS; both are under *Rating findings* in the [series hub](/web/web-application-security-testing-guide/). Each note has its own rating table. This section collects the conventions those tables share, so that findings from different notes sit in one report without contradicting each other or the [Injection hub](/web/web-injection-testing-guide/).

### Conventions

1. **Rate what the victim's browser loses, not the technique.** Severity moves with the delivery (a link anyone can send, a page other users view, a value only the victim can type), who the victim is (any user, staff, administrators), what that session can do, and which mitigation holds today. Blind, DOM-based, message-driven and clobbering-based XSS are all rated as XSS with the same preconditions.
2. **Severity is ours; CVSS is an input.** Write every vector with its prefix (`CVSS:3.1/…`). Where the base score misstates the risk (a standalone redirect at 4.3, a credentialed CORS read capped at 6.5), report the vector and move the severity with a stated reason. Severity labels are Critical, High, Medium, Low and Info, and ranges run upwards ("Low to Medium").
3. **User interaction is Required** whenever a victim has to open a link, view a page, visit the attacker's page or click (`UI:R`). `UI:N` is for findings with no victim step: secrets in public bundles, public source maps, and data left on a shared device (`AV:P`).
4. **XSS is Scope Changed.** The vulnerable component is the web application and the impact lands in the victim's browser session, a separate security authority. The [FIRST CVSS v3.1 user guide](https://www.first.org/cvss/v3.1/user-guide) (section 3.5) gives cross-site scripting as the standard scope-change example. Its [examples document](https://www.first.org/cvss/v3.1/examples) scores reflected XSS in a WordPress plugin (CVE-2017-5942) at `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) and a stored XSS that reaches an administrator (CVE-2019-7551) at 9.0. The **reflected baseline is 6.1, Medium**. Use `C:H/I:H` (9.3, High) when you can show in prose, against your own account, that one visit lets the script take over the account (email or password change without re-authentication, tokens readable in the page). The same rule covers every way attacker script reaches the origin: DOM sinks, `javascript:` URLs, messages, clobbering gadgets, `base` injection, content sniffed into HTML and a compromised third-party script.
5. **Everything else is Scope Unchanged unless a separate authority is hit.** CORS, XSSI and JSONP reads, tokens and data posted to the attacker's window, dangling markup and CSS reads, clickjacking and message-driven actions all affect the same application's data and functions, read or changed through the browser without attacker script running in the origin. Use `S:C` when a leaked secret or token works against a different system (a cloud account, a payment provider, a partner API).
6. **Navigation-only outcomes are Scope Unchanged, by our choice.** FIRST lists URL redirection next to XSS as a scope-change example, and NVD often scores open redirects at 6.1. We score a plain redirect, a meta refresh, a clobbered link and reverse tabnabbing as `S:U/C:N/I:L` (4.3, or 3.5 when an account is needed to plant it) and rate them Low. Nothing runs in the origin, and the phishing page is the attacker's own site. Say so in the report. A `javascript:` target is XSS (convention 4), and a redirect that carries a token off-site is rated by the token (8.1, High).
7. **CORS.** `PR:N` (the attacker needs no account), `UI:R`, `S:U`. Use `AC:H` when exploitation needs a condition outside the attacker's control: a foothold on a trusted subdomain, a `SameSite=Lax` cookie that only same-site origins can use, or a browser that still sends third-party cookies. A credentialed read of sensitive data scores 6.5 and is rated High; a readable token that lets the attacker act scores 8.1. A bearer-token-only API is Info to Low.
8. **Clickjacking.** `PR:N`, `UI:R`, `S:U`, with integrity scaled to the action: `I:L` (4.3) for a minor setting, `I:H` (6.5, Medium) for disabling MFA, deleting the account or granting a role, and `C:H/I:H` (8.1, High) only when the whole takeover chain is shown on your own accounts. Use `AC:H` where only some mainstream browsers send the session cookie into a cross-site frame.
9. **postMessage.** Execution follows convention 4. A token or authorisation code posted to a window the attacker controls is `S:U/C:H/I:H` (8.1), and Critical for admin or broad scopes. A message that performs an action is rated like CSRF (`I:H`, 6.5, or `I:L`, 4.3). Registering a look-alike domain is attacker preparation, so it stays `AC:L`.
10. **Headers are mitigations.** Rate a header finding by what it would have prevented, on which responses and for which data. A missing or weak header with no bug to mitigate is Info or Low. When the bug exists, rate the bug and name the header gap in the same finding as a contributing factor; never add a second Medium for the same impact. Some gaps stand alone: no framing policy on a sensitive one-click action (rate as clickjacking), no HSTS on the login host, tokens sent to third parties through `Referer`.
11. **Network-position preconditions use `AV:A` with `AC:H`** (no HSTS, an `http://` origin trusted by CORS or by a message listener), not `AV:N` with `AC:H`.
12. **Blocked is lower, not gone.** Injection whose script is blocked by an enforced strict CSP or Trusted Types keeps the XSS vector with `AC:H` (4.7, Low to Medium). HTML injection without script is `S:U/C:N/I:L` (4.3). Self-only XSS with no delivery path is Info to Low until you show what makes it deliverable (CSRF on the field, login CSRF).

### Typical ratings

Scores are calculated with the FIRST v3.1 formulas; check them in the [calculator](https://www.first.org/cvss/calculator/3.1) if you reuse them. The Note column says which note's rating table has the detailed rows.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning | Note |
|---|---|---|---|---|
| Reflected or DOM XSS from a link on an authenticated page (also `javascript:` redirects, AngularJS expressions, pollution gadgets, listeners without origin checks) | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | The FIRST baseline; anyone can send the link | XSS, DOM, MSG, REDIR |
| As above, one visit can take over the account | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` (9.3) | Convention 4; describe the path, do not perform it | XSS, DOM, MSG |
| Stored XSS by any registered user, seen by other users (including clobbering gadgets and `base` injection) | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` (5.4) | Registration is a thin barrier; High when widely viewed or the sessions are powerful | XSS, DOM, CLOB |
| Stored XSS firing in an administrator's or support agent's browser | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` (8.7) | FIRST's Cantemo example adds `A:H` (9.0) | XSS, DOM, CLOB |
| Blind XSS from an unauthenticated channel firing in a staff tool | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` (9.3) | No account needed; staff sessions reach every customer | XSS |
| XSS needing a non-default interaction or a second, unproven flaw | Low to Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N` (4.7) | `AC:H`; explain the condition; `AV:A` (4.3) for an `http://` origin trusted by a listener | XSS, DOM, MSG |
| Injection with script blocked by enforced strict CSP or Trusted Types | Low to Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N` (4.7) | Convention 12; one policy change makes it XSS | XSS, DOM, CSP, MSG |
| HTML injection or CSS overlays without script | Low to Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` (4.3) | Content spoofing on the trusted origin; 3.5 with `PR:L` for stored | XSS, CLOB, MSG, CSP |
| Dangling markup or CSS injection reading a token or personal data through an open channel | Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` (5.3) | Convention 5; `AC:H` because page structure decides what is captured | CLOB |
| Form hijacking that captures autofilled credentials | High | `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:N` (6.4) | Rated above the score: credentials of every viewer whose browser autofills | CLOB |
| Self-XSS with no delivery path | Info to Low | none | Describe what would make it deliverable | XSS, DOM |
| Credentialed CORS read of sensitive data from any origin, cookie sent cross-site | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` (6.5) | Convention 7; JSONP and XSSI with sensitive data follow the same row (Medium to High) | CORS |
| As above, and the readable data includes a token that lets the attacker act | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (8.1) | Read becomes takeover; describe the chain | CORS |
| CORS trust that needs a same-site or subdomain foothold | Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` (5.3) | Rate as the first CORS row once a foothold is shown | CORS |
| `http://` origin trusted with credentials, no HSTS | Medium | `CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` (4.8) | Convention 11 | CORS |
| Sensitive one-click action clickjacked from a frame | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` (6.5) | Shown on your own account; 4.3 for minor actions, 8.1 for a full takeover chain | CLICK, CSP |
| No framing policy, nothing worth a stolen click or cookies not sent into frames | Info to Low | none | Hardening against `v5.0.0-3.4.6` | CLICK, CSP |
| Access token or authorisation code posted to `*` and received by an attacker window | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (8.1) | Convention 9; lower for short-lived, narrow or PKCE-bound codes | MSG |
| Personal data posted to `*` | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N` (4.3) | Only the posted item leaks, not the whole API as in a CORS read; 6.5 (Medium to High) for special-category or financial data | MSG |
| Message-driven state change or session swap | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` (6.5) | Rated as CSRF; login CSRF is 5.4 (`C:L/I:L`) | MSG |
| Standalone open redirect (GET), meta refresh or reverse tabnabbing | Low | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` (4.3) | Convention 6; 3.5 with `PR:L` for a stored link | REDIR, CLOB, CLICK, MSG |
| Open redirect that forwards an OAuth code, token or session identifier off-site | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (8.1) | `AC:H` (6.8) when the chain needs conditions outside the attacker's control | REDIR |
| Open redirect that turns a server-side fetch into SSRF | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` (8.6) | Rate as the SSRF; proven in the SSRF tests, not here | REDIR |
| No CSP, a weak CSP, or a reused nonce, with no known injection | Info to Low | none | Convention 10 | CSP |
| No HSTS on the login or authenticated host | Low to Medium | `CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N` (5.4) | Low without a port-80 listener | CSP |
| Missing `nosniff` where user content can be sniffed into HTML or script | Low to Medium | `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N` (4.4) | Rate as XSS once execution is shown | CSP |
| Reset or magic-link token sent to a third party (`Referer`, analytics) | Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N` (6.8) | Whoever reads the vendor's data can use an unexpired token | CSP, STOR |
| Live server-side secret in a public bundle or source map | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` (10.0) | Anonymous and trivial; report the same day for rotation | STOR |
| Script loaded from an unregistered or expired domain | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` (9.3) | Whoever registers it runs script on every visitor's page | STOR |
| Third-party script without SRI on a payment or login page, no documented decision | Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N` (8.0) | Needs the vendor or CDN to be compromised first; rated below the score | STOR |
| Tokens in `localStorage`, no injection path found | Low | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` (3.1) | Multiplies any future XSS; with a confirmed XSS, raise the XSS instead | STOR |
| Data and still-valid tokens left after logout on a shared device | Medium | `CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (6.1) | Higher for kiosk, clinic and call-centre user bases | STOR |
| Outdated jQuery, AngularJS or DOMPurify with no reachable vulnerable function | Info to Low | none | Component finding (`A03:2025`); rate as XSS once reachability is shown | DOM, CLOB, STOR |

## Prevention patterns

Each note gives the fixes in Node.js, Django, Spring and Laravel, plus React, Angular and Vue where the bug lives in the front end. The patterns behind them are few. When you write recommendations, name the pattern first and the API second, so the client fixes the class and not just the line.

### The patterns

| Pattern | What it means | Where it applies |
|---|---|---|
| **Context-aware output encoding** | Let the template engine's auto-escaping do the work and keep it on. Encode for the exact context (HTML text, quoted attribute, URL, JavaScript string, CSS value) as the last step, and serialise data for inline script with the framework's JSON-in-script helper | XSS (`1.2.1`–`1.2.3`), CLOB-5 |
| **Safe DOM APIs** | `textContent`, `createTextNode`, `setAttribute` on safe attributes and framework bindings instead of `innerHTML`, `document.write`, `eval`, string timers and `v-html`; no templates built from input | DOM (`3.2.2`, `1.3.2`, `1.3.7`), MSG-6 |
| **A maintained sanitiser, configured narrowly** | Where HTML must be allowed, DOMPurify in the browser (or the Sanitizer API where supported) and a maintained server-side library. Use a tag and attribute allow-list without `style`, `id` and `name` unless needed, and pin and patch the version | XSS-10, CLOB-2 (`1.3.1`, `1.3.5`, `3.2.3`) |
| **Strict CSP and Trusted Types** | Nonce- or hash-based `script-src` with `'strict-dynamic'`, `object-src 'none'` and `base-uri 'none'`, plus `form-action` and a report endpoint. Roll it out report-only first, then enforce, and add `require-trusted-types-for 'script'` | CSP (`3.4.3`, `3.4.7`), DOM-12, CLOB-10 |
| **Framing and opener policies** | `frame-ancestors 'none'` (or a short list) on every response; COOP `same-origin` on documents; `rel="noopener noreferrer"` on links and `noopener` in `window.open`; re-authentication for sensitive changes | CLICK (`3.4.6`, `3.4.8`, `7.5.1`) |
| **Exact-origin checks** | Compare `event.origin` and CORS `Origin` values against a set of full origins by string equality. No `indexOf`, prefix, suffix or unanchored regex checks, no `null`, and `Vary: Origin` on dynamic CORS responses. Send messages with an explicit `targetOrigin` | CORS (`3.4.2`), MSG (`3.5.5`) |
| **URL allow-lists** | Redirect to relative paths or to keys mapped to fixed URLs. Where a full URL is needed, parse it once with the same parser the browser uses, allow `https:` only, and compare the host against an exact list | REDIR (`3.7.2`, `1.2.2`), DOM-6 |
| **Minimal client storage** | Session tokens in `HttpOnly` cookies or behind a back-end-for-frontend; no sensitive data in `localStorage`; `Cache-Control: no-store` and `Clear-Site-Data` on logout; service workers that never cache authenticated responses | STOR (`14.3.1`–`14.3.3`, `3.3.4`) |
| **No secrets in the front end** | Anything shipped to the browser is public. Server-side keys stay on the server behind a proxy endpoint, publishable keys are restricted, and source maps are not deployed publicly | STOR (`13.3.1`, `13.4.2`) |
| **SRI and third-party governance** | Self-host where possible; otherwise static, versioned URLs with `integrity`, a CSP that names them, an inventory with an owner and a reason per script, and no tag-manager custom HTML on payment and login pages | STOR (`3.6.1`, `14.2.3`), DOM-7 |
| **Correct content types and headers everywhere** | `nosniff` and an accurate `Content-Type` with charset on every response; uploads served as attachments or from a separate origin; HSTS with `includeSubDomains`; headers set in one layer and tested on error pages and static files | CSP (`3.4.1`, `3.4.4`, `3.2.1`), XSS-11, CORS-12 |

### Regression tests

Every confirmed finding should leave a test behind, and in the browser that means a headless one. A Playwright test loads the page with the input that proved the bug and asserts that no dialog opened and the marker rendered as text. For postMessage it sends a marker message from a second local origin and asserts that the page ignored it. It also asserts that the framed page refused to load, that the redirect target stayed on an allowed host, and that storage is empty after logout. A cheaper layer runs on every build: a header check on representative responses (including a 404 and a static file), a bundle scan for secrets and `sourceMappingURL`, and lint rules that fail on new uses of `innerHTML`, `dangerouslySetInnerHTML`, `v-html` and message listeners without an origin check. The notes' *Regression tests* sections give the code.

## Practice path

A sequence that follows the order of this hub. Labs are where you may build full exploits with an exploit server, because the victim is simulated. Keep the client-system habits anyway: find the context first, and prove each step with a marker.

1. **XSS contexts (PortSwigger).** [Reflected XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded), [stored XSS into HTML context](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded), [attribute with angle brackets encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded), [anchor href with double quotes encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded) and [JavaScript string with angle brackets encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded).
2. **DOM XSS (PortSwigger, with DOM Invader).** [document.write sink](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink), [innerHTML sink](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink), [jQuery href sink](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink), [jQuery selector with hashchange](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event), [AngularJS expression](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression) and [DOM XSS via client-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-client-side-prototype-pollution).
3. **CSP and scriptless injection.** [Reflected XSS protected by CSP, with CSP bypass](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass), [very strict CSP with dangling markup](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack) and [exploiting DOM clobbering to enable XSS](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering).
4. **Cross-origin reads.** [Basic origin reflection](https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack), [trusted null origin](https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack) and [trusted insecure protocols](https://portswigger.net/web-security/cors/lab-breaking-https-attack), then the two-hostname XSSI lab described in the CORS note.
5. **Frames and windows.** [Basic clickjacking with CSRF token protection](https://portswigger.net/web-security/clickjacking/lab-basic-csrf-protected), [prefilled form input](https://portswigger.net/web-security/clickjacking/lab-prefilled-form-input), [frame buster script](https://portswigger.net/web-security/clickjacking/lab-frame-buster-script) and [multistep clickjacking](https://portswigger.net/web-security/clickjacking/lab-multistep); then [DOM XSS using web messages](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages), [with a JavaScript URL](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-a-javascript-url) and [with JSON.parse](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-json-parse).
6. **Redirects and the chains they feed.** [DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection), [stealing OAuth access tokens via an open redirect](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect), [via a proxy page](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page) and [SSRF filter bypass via open redirection](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection).
7. **OWASP Juice Shop.** From the [XSS chapter](https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html): *Reflected XSS*, *DOM XSS*, *API-only XSS* and *CSP Bypass*. From [Unvalidated Redirects](https://pwning.owasp-juice.shop/companion-guide/latest/part2/unvalidated-redirects.html): *Outdated Allowlist* and *Allowlist Bypass*. *Score Board* and *Exposed Credentials* exercise the bundle tests, and its token in browser storage suits STOR-1 to STOR-3.
8. **Your own two-origin lab.** Serve an app on `http://localhost:3000` and PoC pages on `http://127.0.0.1:8000`. They are different sites, so you can switch cookies between `SameSite=None; Secure` and `Lax`, add and remove `frame-ancestors`, and break and fix a message listener. Then write the Playwright regression test for each case.

## References

**OWASP**

- WSTG: [Client-side chapter](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/), [WSTG-INJT-01 Reflected XSS](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/01-Reflected_Cross_Site_Scripting/), [WSTG-INJT-02 Stored XSS](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/02-Stored_Cross_Site_Scripting/), [WSTG-CLNT-01 DOM-based XSS](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/01-DOM-based_Cross_Site_Scripting), [01.1 Self DOM-based XSS](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/01.1-Self_DOM_Based_Cross_Site_Scripting), [02 JavaScript Execution](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/02-JavaScript_Execution), [03 HTML Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/03-HTML_Injection), [04 Client-side URL Redirect](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/04-Client-side_URL_Redirect), [05 CSS Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/05-CSS_Injection), [06 Client-side Resource Manipulation](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/06-Client-side_Resource_Manipulation), [07 CORS](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/07-Cross_Origin_Resource_Sharing), [09 Clickjacking](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/09-Clickjacking), [11 Web Messaging](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/11-Web_Messaging), [12 Browser Storage](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/12-Browser_Storage), [13 XSSI](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/13-Cross_Site_Script_Inclusion), [14 Reverse Tabnabbing](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/14-Reverse_Tabnabbing), [15 Client-side Template Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/15-Client-Side_Template_Injection), [16 DOM Clobbering](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/16-DOM_Clobbering), [WSTG-CONF-12 CSP](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/12-Content_Security_Policy), [WSTG-CONF-14 other security headers](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/14-Other_HTTP_Security_Header_Misconfigurations), [WSTG-INFO-05 page content leakage](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage)
- ASVS 5.0: [V3 Web Frontend Security](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md), [V1 Encoding and Sanitization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md), [V14 Data Protection](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x23-V14-Data-Protection.md)
- OWASP Top 10:2025: [A01 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/), [A02 Security Misconfiguration](https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/), [A03 Software Supply Chain Failures](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/), [A05 Injection](https://top10.owasp.org/2025/A05_2025-Injection/), [A06 Insecure Design](https://top10.owasp.org/2025/A06_2025-Insecure_Design/), [A07 Authentication Failures](https://top10.owasp.org/2025/A07_2025-Authentication_Failures/), [A08 Software or Data Integrity Failures](https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/)
- Cheat Sheets: [XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), [DOM-based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html), [Content Security Policy](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html), [HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html), [HTML5 Security](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html), [Clickjacking Defense](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html), [DOM Clobbering Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html), [Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html), [Third Party JavaScript Management](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html)

**CWE**

- [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CWE-95](https://cwe.mitre.org/data/definitions/95.html), [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html), [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (mapping Discouraged by MITRE), [CWE-942](https://cwe.mitre.org/data/definitions/942.html), [CWE-346](https://cwe.mitre.org/data/definitions/346.html), [CWE-940](https://cwe.mitre.org/data/definitions/940.html), [CWE-201](https://cwe.mitre.org/data/definitions/201.html), [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html), [CWE-1022](https://cwe.mitre.org/data/definitions/1022.html), [CWE-601](https://cwe.mitre.org/data/definitions/601.html), [CWE-922](https://cwe.mitre.org/data/definitions/922.html), [CWE-540](https://cwe.mitre.org/data/definitions/540.html), [CWE-829](https://cwe.mitre.org/data/definitions/829.html)

**Scoring**

- FIRST: [CVSS v3.1 user guide](https://www.first.org/cvss/v3.1/user-guide) (section 3.5, Scope), [CVSS v3.1 examples](https://www.first.org/cvss/v3.1/examples), [CVSS v3.1 calculator](https://www.first.org/cvss/calculator/3.1)

**Browser and PortSwigger references**

- MDN: [Same-origin policy](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Same-origin_policy), [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS), [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP), [Trusted Types API](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API), [Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity), [Window.postMessage](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage); web.dev: [strict CSP](https://web.dev/articles/strict-csp), [Trusted Types](https://web.dev/articles/trusted-types)
- Web Security Academy topics: [Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) and its [cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet), [DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based), [CORS](https://portswigger.net/web-security/cors), [Clickjacking](https://portswigger.net/web-security/clickjacking), [Dangling markup](https://portswigger.net/web-security/cross-site-scripting/dangling-markup), [Client-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/client-side)

**Tools**

- [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader), [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator), [Playwright](https://playwright.dev/), [CSP Evaluator](https://csp-evaluator.withgoogle.com/), [DOMPurify](https://github.com/cure53/DOMPurify)
- Labs: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) and its [companion guide](https://pwning.owasp-juice.shop/)

**Elsewhere on this site**

- [Web Application Security testing guide](/web/web-application-security-testing-guide/) (rules of engagement, set-up, severity scale, reporting)
- [Injection Testing Guide](/web/web-injection-testing-guide/), with [CRLF and header injection](/web/web-crlf-header-log-csv-injection/) and [server-side prototype pollution](/web/web-server-side-prototype-pollution/) for the server-side neighbours of this subcategory
- [Access Control Testing Guide](/web/web-access-control-testing-guide/), for what a stolen session or token can reach
- [Bug Bounty Writeups](/bug-bounty-writeups/)
