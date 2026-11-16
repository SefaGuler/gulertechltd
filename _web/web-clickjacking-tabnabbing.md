---
title: "Clickjacking, UI Redressing and Reverse Tabnabbing"
date: 2026-11-15 22:08:00 +0000
subcategory: client-side
summary: "Testing clickjacking and reverse tabnabbing: which pages matter, frame-ancestors vs X-Frame-Options, cookies in frames, opener access, COOP and fixes."
refs: [WSTG-CLNT-09, WSTG-CLNT-14, v5.0.0-3.4.6, v5.0.0-3.4.8, v5.0.0-3.3.2, v5.0.0-10.7.1, v5.0.0-10.7.2, v5.0.0-7.5.1, "A06:2025", CWE-1021, CWE-1022, CWE-451]
tags: [web, clickjacking, ui-redressing, tabnabbing, security-headers, client-side]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Client-Side testing](/web/web-client-side-testing-guide/). It covers two ways another site can borrow your application's user interface without ever reading its data. **Clickjacking** (UI redressing, `WSTG-CLNT-09`) loads your page inside a frame on someone else's site and lines up a hidden button under the victim's cursor, so a click the victim meant for one thing performs an action in your application with their session. **Reverse tabnabbing** (`WSTG-CLNT-14`) runs the other way: a page your application opened in a new tab keeps a handle on the original tab through `window.opener` and quietly navigates it somewhere else. Both are old, both have well-understood header and markup fixes, and both are over-reported: most "page can be framed" findings are noise, while a frameable one-click account deletion or OAuth consent is a real bug. You get the model (how browsers decide whether a page may be framed, what cookies a framed page receives in current browsers, when `window.opener` still exists), the variants that still produce findings (partial header coverage, obsolete header values, framebusting scripts, multi-step and drag-and-drop attacks, double-click timing attacks on top-level windows, user-generated links), ten tests that use local proof-of-concept pages against your own test account, fixes in Express, Django, Spring Security and Laravel, and a rating scheme that explains why most of these findings sit between Low and Medium. The wider header set (CSP design, COOP, COEP, CORP) is covered in [CSP and browser security headers](/web/web-content-security-policy-headers/); cross-window messaging in [postMessage and web messaging](/web/web-postmessage-web-messaging/).

## Contents

- [How it works](#how-it-works)
  - [UI redressing in one picture](#ui-redressing-in-one-picture)
  - [Why CSRF tokens do not help](#why-csrf-tokens-do-not-help)
  - [Which pages matter](#which-pages-matter)
  - [How the browser decides whether a page may be framed](#how-the-browser-decides-whether-a-page-may-be-framed)
  - [Cookies inside a cross-site frame](#cookies-inside-a-cross-site-frame)
  - [window.opener and reverse tabnabbing](#windowopener-and-reverse-tabnabbing)
  - [Cross-Origin-Opener-Policy](#cross-origin-opener-policy)
- [What goes wrong](#what-goes-wrong)
  - [No framing policy on sensitive pages](#no-framing-policy-on-sensitive-pages)
  - [Partial coverage across routes and responses](#partial-coverage-across-routes-and-responses)
  - [Headers that look right but do nothing](#headers-that-look-right-but-do-nothing)
  - [Frame busting scripts as the only defence](#frame-busting-scripts-as-the-only-defence)
  - [Prefilled forms and multi-step flows](#prefilled-forms-and-multi-step-flows)
  - [Drag-and-drop, keystrokes and cursorjacking](#drag-and-drop-keystrokes-and-cursorjacking)
  - [Double-click and timing attacks on top-level windows](#double-click-and-timing-attacks-on-top-level-windows)
  - [Frameable by design](#frameable-by-design)
  - [Same-site framers](#same-site-framers)
  - [Links and popups that keep window.opener](#links-and-popups-that-keep-windowopener)
  - [User-generated links](#user-generated-links)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-WEB-CLICK-1: Inventory frame-sensitive pages and one-click actions](#gt-web-click-1-inventory-frame-sensitive-pages-and-one-click-actions)
  - [GT-WEB-CLICK-2: Check framing headers across routes, status codes and content types](#gt-web-click-2-check-framing-headers-across-routes-status-codes-and-content-types)
  - [GT-WEB-CLICK-3: Confirm framing with a local proof-of-concept page](#gt-web-click-3-confirm-framing-with-a-local-proof-of-concept-page)
  - [GT-WEB-CLICK-4: Session cookies in a cross-site frame](#gt-web-click-4-session-cookies-in-a-cross-site-frame)
  - [GT-WEB-CLICK-5: Frame busting scripts and sandboxed iframes](#gt-web-click-5-frame-busting-scripts-and-sandboxed-iframes)
  - [GT-WEB-CLICK-6: Prefilled forms, multi-step flows and confirmation dialogs](#gt-web-click-6-prefilled-forms-multi-step-flows-and-confirmation-dialogs)
  - [GT-WEB-CLICK-7: OAuth consent, payment and approval pages against timing attacks](#gt-web-click-7-oauth-consent-payment-and-approval-pages-against-timing-attacks)
  - [GT-WEB-CLICK-8: Review links and window.open calls for opener access](#gt-web-click-8-review-links-and-windowopen-calls-for-opener-access)
  - [GT-WEB-CLICK-9: Prove opener access from a user-supplied link](#gt-web-click-9-prove-opener-access-from-a-user-supplied-link)
  - [GT-WEB-CLICK-10: Cross-Origin-Opener-Policy on document responses](#gt-web-click-10-cross-origin-opener-policy-on-document-responses)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Node.js and Express](#nodejs-and-express)
  - [Django](#django)
  - [Spring Security](#spring-security)
  - [Laravel](#laravel)
  - [Web server and CDN layer](#web-server-and-cdn-layer)
  - [Pages that must be embeddable](#pages-that-must-be-embeddable)
  - [Sensitive actions that survive a stolen click](#sensitive-actions-that-survive-a-stolen-click)
  - [Links and popups](#links-and-popups)
  - [Regression tests](#regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### UI redressing in one picture

A clickjacking page has two layers. The top layer is your application, loaded in an `iframe` and made invisible with CSS (`opacity: 0` or close to it). The bottom layer is whatever the attacker wants the victim to see: a game, a "play video" button, a fake CAPTCHA. The attacker positions the frame so that the button they want pressed in your application (Delete account, Authorise, Make admin, Confirm payment) sits exactly over the decoy element. The victim clicks the decoy; the browser delivers the click to the topmost element under the pointer, which is your invisible button.

The term was coined by Jeremiah Grossman and Robert Hansen in 2008, and WSTG treats it as one member of a wider family, **UI redressing**: any technique that makes the user interact with something other than what they think they see. The same idea covers stolen keystrokes, stolen drags, a cursor drawn in the wrong place, and (more recently) a top-level window swapped in between the two clicks of a double-click.

Three properties make clickjacking different from most client-side bugs:

- **The attacker reads nothing.** Your page is cross-origin to the attacker's page, so the same-origin policy still stops the attacker from reading the frame's DOM, cookies or responses. What the attacker gains is the victim's *intent*: one or more clicks, applied to your UI.
- **Your server sees a legitimate request.** The click happens inside your genuine page, in the victim's browser, with whatever session that page has. The request carries your CSRF token, the right `Origin` (your own), and a real user gesture.
- **It needs a user.** No click, no attack. This is why the CVSS vector always has `UI:R`, and why the realistic question is "how much harm can one or two plausible clicks do here?".

### Why CSRF tokens do not help

Anti-CSRF tokens prove that a request came from a page your server rendered. In a clickjacking attack it did: the form, the token and the submit button are all yours, rendered inside the frame. The token defends against a *forged* request; clickjacking produces a *genuine* request with a hijacked click. WSTG makes the same point. This is also why "we have CSRF protection" is not a reason to close a clickjacking finding, and why fixes live in framing policy, cookie policy and the design of sensitive actions instead.

### Which pages matter

A page is a meaningful clickjacking target when all of these hold:

1. It performs a **state-changing action with one or a few clicks** (or with input the attacker can supply in advance, see [Prefilled forms and multi-step flows](#prefilled-forms-and-multi-step-flows)).
2. The action **matters**: it changes security settings, money, permissions, data or third-party access.
3. The page is **authenticated in the frame** (the victim's session reaches it, see [Cookies inside a cross-site frame](#cookies-inside-a-cross-site-frame)), or the action needs no authentication but is still harmful.
4. Nothing else in the flow stops a blind click: no re-authentication, no typed confirmation, no second channel.

| Usually matters | Usually does not |
|---|---|
| Account settings: change email or phone, disable MFA, remove a recovery method, delete the account, revoke other sessions | Static marketing pages, public documentation, status pages |
| OAuth and SSO consent ("Authorise this app", "Continue as …"), linking a social or payment account | Pages that only display data (framing does not let the attacker read it) |
| Payment confirmation, one-click purchase, transfer approval, subscription upgrade | Search pages and listings without state-changing controls |
| Admin consoles: role changes, user deletion, feature flags, API key creation | Login pages where the attacker cannot supply credentials (see the false positives in test 1) |
| Sharing and visibility toggles ("make public", "invite", "share with link") | Error pages, unless they carry a sensitive action |
| Social actions with reach: follow, like, post, which matter when they spread | Pages that require typing a secret the attacker does not know (current password, OTP) |
| Browser-extension, wallet and device-pairing approval pages | API endpoints that return JSON (nothing to click) |

The table is a starting point. The right answer comes from walking the application with a list of actions (test 1), not from scanning for a missing header.

### How the browser decides whether a page may be framed

Two response headers control framing. Both are delivered as HTTP response headers; neither works from a `meta` element.

**`Content-Security-Policy: frame-ancestors`** is the current mechanism and what ASVS 5.0 requires (`v5.0.0-3.4.6`, L2). It lists who may embed the response:

```http
Content-Security-Policy: frame-ancestors 'none'
Content-Security-Policy: frame-ancestors 'self'
Content-Security-Policy: frame-ancestors 'self' https://example.org
```

The browser checks **every ancestor** in the frame chain, not just the direct parent, so a page cannot be laundered through an intermediate frame. `frame-ancestors` does **not** fall back to `default-src`: a policy of `default-src 'none'` with no `frame-ancestors` leaves the page frameable. Like other CSP directives it applies to `frame`, `iframe`, `object` and `embed`.

**`X-Frame-Options`** is the legacy header. It has two working values: `DENY` (no framing at all) and `SAMEORIGIN` (every ancestor must be same-origin with the page). `ALLOW-FROM origin` is obsolete; modern browsers do not support it and MDN notes they ignore the header entirely when they see it, which leaves the page frameable. ASVS 5.0 calls `X-Frame-Options` obsolete and says it may not be relied upon; it still helps very old browsers.

**Precedence.** The CSP specification says `frame-ancestors` overrides `X-Frame-Options`, and the HTML standard's processing model implements it: if the response carries an **enforced** CSP with a `frame-ancestors` directive, the browser ignores `X-Frame-Options` completely. That cuts both ways:

| Response headers | Result in a current browser |
|---|---|
| `frame-ancestors 'none'` | Not frameable |
| `X-Frame-Options: DENY` only | Not frameable |
| `frame-ancestors 'none'` and `X-Frame-Options: DENY` | Not frameable (CSP decides; XFO covers old browsers) |
| `frame-ancestors *` (or `https:`) and `X-Frame-Options: DENY` | **Frameable**: the permissive CSP wins, XFO is ignored |
| `frame-ancestors 'none'` only in `Content-Security-Policy-Report-Only` | **Frameable**: report-only policies do not enforce, and they do not suppress XFO either |
| `X-Frame-Options: ALLOW-FROM https://example.org` | **Frameable** (value not supported) |
| `X-Frame-Options: DENY, SAMEORIGIN` (conflicting values) | Not frameable: the HTML standard treats a confused mix of valid values as a block |
| `X-Frame-Options` sent from a `meta` element | Frameable: ignored |

A response can carry more than one CSP header; the browser enforces each policy independently, so a separate `Content-Security-Policy: frame-ancestors 'none'` header alongside the main policy is valid and common.

### Cookies inside a cross-site frame

A clickjacking attack on an authenticated action needs the framed page to be logged in. Whether it is depends on the session cookie's `SameSite` attribute and on the browser's third-party cookie handling, and both have changed since most clickjacking write-ups were published.

- **`SameSite=Strict` or `SameSite=Lax`**: the cookie is not sent on requests made by a cross-site frame. The framed page loads logged out, and an authenticated action cannot be clickjacked from a cross-site page in any current browser. ASVS `v5.0.0-3.3.2` (L2) names UI redress attacks as one reason to set `SameSite` deliberately.
- **No `SameSite` attribute**: Chromium-based browsers treat it as `Lax`. Other browsers vary, so do not rely on the default.
- **`SameSite=None; Secure`**: the cookie is a candidate for third-party use. What happens next depends on the browser. At the time of writing, Chrome does not block third-party cookies by default (only in Incognito or when the user opts in); Google announced in 2024–2025 that it would keep this approach rather than deprecate them. Firefox's Total Cookie Protection gives each top-level site its own cookie jar, so your application framed under the attacker's site does not see the user's normal session cookie. Safari's tracking prevention blocks third-party cookies by default. A cookie set inside the frame as `Partitioned` (CHIPS) lives only in that partition and is not the user's normal session either.

So in practice: an application whose session cookie is `Lax` or `Strict` is not clickjackable on authenticated pages from a cross-site attacker, whatever its headers say; an application that needs `SameSite=None` (embedded widgets, some SSO and payment flows, cross-site APIs using cookies) is clickjackable at least in Chrome's default configuration. Two caveats keep the framing headers necessary: `SameSite` is about **sites**, not origins, so a same-site attacker (a sibling subdomain, see [Same-site framers](#same-site-framers)) still gets the cookie; and some harmful actions do not need a session at all. The OWASP cheat sheet makes the same point: `SameSite` is defence in depth, not a replacement for `frame-ancestors`. Browser cookie policy changes often; re-check the current behaviour when you test and write down the browser and version you used.

### window.opener and reverse tabnabbing

When page A opens page B in a new tab or window, browsers historically gave B a reference to A through `window.opener`. Even when A and B are cross-origin, B can do one thing with that reference that matters: **navigate it**. `window.opener.location = "https://example.org/"` replaces the original tab's page without the user seeing anything happen. The attack, as WSTG describes it: the user clicks a link in your application, a new tab opens on the attacker's page, and while the user reads it the attacker swaps your tab for a look-alike login page. When the user returns to "your" tab, they are asked to sign in again.

Browsers have since closed most of this:

- Since around 2021, browsers treat `target="_blank"` on `a`, `area` and `form` elements as if `rel="noopener"` were set: the new page gets `window.opener === null`. Caniuse lists Chrome and Edge 88, Firefox 79, Safari 12.1 (iOS 12.2) and Samsung Internet 15 as the first versions.
- The implicit rule only applies to `_blank`. A link with `rel="opener"` keeps the reference. A link with a **named** target (`target="preview"`) that opens a new window also keeps it, because the HTML standard only implies `noopener` for `_blank`.
- `window.open(url)` without the `noopener` (or `noreferrer`) window feature keeps the reference in every browser. With `noopener`, `window.open` returns `null`, which is why developers often leave it out: their code wanted the handle.
- `rel="noreferrer"` implies `noopener` and also drops the `Referer` header.

What remains of reverse tabnabbing today is therefore mostly in JavaScript: `window.open` calls, link handlers that call it, and markup that explicitly opts back into `opener`, combined with links whose destination someone other than you controls (user-generated content, or third-party sites that could be compromised). Old browsers still in use (embedded webviews in older apps, kiosks, unmanaged legacy desktops) are the other residue.

### Cross-Origin-Opener-Policy

`Cross-Origin-Opener-Policy` (COOP) is a response header on top-level documents that decides whether a document shares a browsing context group with the pages that open it or that it opens. When two documents end up in different groups, the opener relationship is severed: `window.opener` is `null` on one side and the other side's handle reports `closed === true`.

| Value | Effect |
|---|---|
| `unsafe-none` | Default; no isolation |
| `same-origin-allow-popups` | Isolates the document from cross-origin openers, but popups it opens keep their opener unless they set COOP themselves; used for OAuth and payment popups |
| `same-origin` | Shares a group only with same-origin documents that also send `same-origin`; cross-origin popups and openers are cut off |
| `noopener-allow-popups` | Newer value that isolates the document even from same-origin openers; check browser support before relying on it |

For reverse tabnabbing the important detail is that `same-origin-allow-popups` **keeps** the opener for popups your page opens to third-party sites, so it does not stop the attack from those links; `same-origin` does. ASVS `v5.0.0-3.4.8` (L3) asks for COOP `same-origin` or `same-origin-allow-popups` on every response that renders a document, naming tabnabbing and frame counting as the attacks it limits. COOP does not stop framing; it is a different header for a different relationship.

## What goes wrong

### No framing policy on sensitive pages

The baseline finding: a page with a sensitive one-click action sends neither `frame-ancestors` nor `X-Frame-Options`, and its session reaches a cross-site frame. Many frameworks now send `X-Frame-Options` by default (Django, Spring Security, Helmet), so a total absence usually points to a custom stack, a framework default someone turned off, or a component outside the main app: an identity provider, a payment page, an admin tool, a separately deployed SPA served from object storage or a CDN. **Where to look:** every host in scope, not just the main application; responses from the SPA's static host as well as from its API.

### Partial coverage across routes and responses

Framing policy is often set in one place and quietly missing in others. WSTG calls out mobile versions and pages that each had to set `X-Frame-Options` individually. Common gaps:

- **Routes outside the middleware.** Spring Security writes its headers only for requests that pass through the security filter chain; paths excluded with `web.ignoring()` get none. Express middleware mounted after a router does not run for that router's responses. Django views decorated with `xframe_options_exempt` (often added for one embed and copied elsewhere).
- **Only on some status codes.** nginx `add_header` applies only to 200, 201, 204, 206, 301, 302, 303, 304, 307 and 308 responses unless the `always` parameter is used, and a `location` block with its own `add_header` drops every header inherited from the server block. Error pages, `401` and `403` responses and custom `404`s then go out unprotected. An error page is rarely interesting by itself, but some applications render a full, working UI on a `403` or a "session expired, click to continue" page.
- **Only on HTML 200 responses from the app server.** Files served directly by the web server or CDN (static HTML pages, uploaded HTML or SVG, PDFs rendered by the browser's viewer) bypass application middleware.
- **Separate flows.** OAuth authorisation and consent endpoints, SSO pages, payment confirmation, invitation acceptance and "magic link" landing pages are often served by a different component than the rest of the site. The Coinbase report in [Real-world cases](#real-world-cases) is exactly this: the OAuth responses lacked the headers the rest of the site had.
- **Alternate hosts and legacy paths.** `m.` sites, old admin paths, API documentation consoles, versioned front-ends.
- **Proxies that strip or rewrite headers.** WSTG notes that proxies can strip `X-Frame-Options`; CDNs and load balancers can also add a second, conflicting value.

### Headers that look right but do nothing

- `X-Frame-Options: ALLOW-FROM https://example.org`: not supported by modern browsers, so the page is frameable by anyone. The Periscope report in [Real-world cases](#real-world-cases) is this case.
- `X-Frame-Options` or `frame-ancestors` in a `meta http-equiv` element: ignored for framing.
- `frame-ancestors` only in `Content-Security-Policy-Report-Only`: reports, does not block.
- A permissive `frame-ancestors` (`*`, `https:`, `*.example.com` where some subdomains host user content) next to `X-Frame-Options: DENY`: the CSP wins and the page is frameable from wherever the CSP allows.
- `frame-ancestors` with an allow-list that includes `http:` origins, staging hosts, or partner domains no longer under contract.
- Two `X-Frame-Options` headers with different values, or values the browser does not recognise such as `ALLOWALL`; recognised-but-conflicting combinations block, invalid-only combinations are treated as if the header were absent.

### Frame busting scripts as the only defence

Before the headers existed, pages defended themselves with JavaScript: "if I am not the top window, make myself the top window" (`if (top !== self) top.location = self.location`). Rydstedt, Bursztein, Boneh and Jackson's 2010 study "Busting Frame Busting" showed how unreliable this is, and the OWASP cheat sheet lists the classic bypasses. The decisive one today is the `sandbox` attribute on the attacker's `iframe`. A sandbox that allows forms and scripts but not top-level navigation lets the framebuster run but blocks its attempt to navigate the top window; a sandbox without `allow-scripts` stops the framebuster from running at all, which is enough for a server-rendered form that works without JavaScript. Other historical bypasses (an `onbeforeunload` prompt the user cancels, repeated navigations to a `204` response, double framing, browser XSS filters disabling the script) are mostly of historical interest but show the same lesson: a defence that runs inside the page it protects can be switched off by the page that frames it.

The cheat sheet's legacy pattern is better because it **fails closed**: the page is hidden by a style rule until a script confirms it is the top window. With scripts disabled the page stays blank; with scripts allowed but top navigation blocked, it still stays hidden. Treat it as a fallback for ancient browsers, never as the primary control.

### Prefilled forms and multi-step flows

Clickjacking is not limited to buttons that need no input. If a form takes its field values from URL parameters (`/account/email?new=…`), the attacker frames the URL with the values already filled in and needs only the submit click; PortSwigger has a lab for exactly this. Flows that need two or three clicks (add to basket, then confirm; delete, then "are you sure?") can be attacked with a sequence of decoys, each lining up with the next button. A confirmation step only helps if it requires something the attacker cannot line up: typing a value, re-entering a password, or a step on a page that is itself not frameable. A `window.confirm()` dialog is a weak extra: inside a sandboxed frame without `allow-modals` it returns `false` immediately (which blocks the action, a useful side effect), and outside a sandbox it appears as a browser dialog the victim may click through.

Clickjacking can also be a delivery mechanism for another bug: if a page has a DOM-based XSS that needs a click to fire, framing it with the payload in the URL and stealing that click turns a "self" XSS into one that works against others. PortSwigger's lab on triggering DOM XSS through clickjacking shows the pattern; see [DOM XSS and client-side injection](/web/web-dom-xss-client-side-injection/).

### Drag-and-drop, keystrokes and cursorjacking

Clicks are not the only input that can be redirected:

- **Drag-and-drop.** Paul Stone's "Next Generation Clickjacking" talk (Black Hat Europe 2010) showed that the browser drag-and-drop API could move data across the frame boundary under the user's own hand: the victim drags something in a game, and the drop lands in a hidden frame, injecting attacker-chosen text into a form field; or the victim drags content out of a hidden frame into the attacker's page, which reads the dropped data. Browsers have since restricted cross-origin drag data in various ways, so treat specific techniques from that era as historical, but the idea that a user's drag is just as hijackable as a click still holds for applications with drag-driven UIs (file managers, kanban boards, page builders).
- **Keystroke redirection** ("strokejacking"): focus is moved into the hidden frame while the victim types into what they think is the attacker's page. Most browsers now limit cross-frame focus tricks, but rich editors in frames are worth a look.
- **Cursorjacking**: the attacker hides the real pointer and draws a fake one with a CSS custom cursor image offset from the real hotspot, so the user aims at one place and clicks another. It needs no framing defence bypass by itself, but combined with a frameable page it relaxes the alignment problem. Browsers have added limits on large custom cursors; describe the variant in prose if it is relevant, do not build it.

### Double-click and timing attacks on top-level windows

Framing headers only control framing. A newer class of UI redressing does not frame anything: it swaps a **top-level** window under the victim's cursor between two clicks. Paulos Yibelo's "DoubleClickjacking" research (published at the end of December 2024, widely covered in January 2025) describes the pattern. The attacker's page opens a new window that asks the victim to double-click (a CAPTCHA-style prompt). While the victim reads it, that window navigates its opener, the original tab, to the target page, for example an OAuth consent screen. The first click of the double-click (the `mousedown`) closes the prompt window; the second click lands on whatever is now under the pointer in the original window, which is the Authorise button. The research reported account-takeover proofs against several large platforms and argued that `X-Frame-Options`, `frame-ancestors` and `SameSite` cannot stop it, because the target is a normal top-level navigation with first-party cookies.

What this means for testing: every page whose single click grants something large (OAuth consent, connecting an account, approving a payment, approving a device or extension, confirming an admin action) is exposed even when it is perfectly protected against framing. The OWASP Clickjacking Defense Cheat Sheet now covers this: it recommends server-side transaction authorisation for sensitive actions, notes that an extra confirmation button alone is not enough, and treats "disable the control until the user has genuinely interacted" as a supplementary measure that must not lock out keyboard, touch or assistive-technology users. In this note the variant is reviewed (test 7) and described in reports; we do not build timing proofs.

### Frameable by design

Some responses must be embeddable: chat widgets, video players, payment fields, embedded dashboards, "Sign in with" buttons. The mistakes here are usually scope: the whole application is made frameable because one route needed it, the allow-list is `*` because the list of customers was too long to maintain, or the embeddable route also contains a sensitive action (the embedded dashboard has a "delete widget" button that works with the viewer's session). A frameable route is acceptable when it carries no sensitive one-click action, or when the actions it carries need confirmation the framer cannot fake.

### Same-site framers

`SameSite` cookies stop cross-*site* frames, not cross-*origin* ones. Every subdomain of your registrable domain is the same site: if `tenant-a.example.com` serves customer-controlled HTML, or an old marketing subdomain can be taken over, a page there can frame `app.example.com` and the session cookie goes with it, `Lax` or not. `X-Frame-Options: SAMEORIGIN` and `frame-ancestors 'self'` still block it (they work on origins), which is one reason the headers matter even with good cookie settings. Watch for allow-lists such as `frame-ancestors https://*.example.com`, which hand framing rights to every subdomain, including the ones nobody maintains.

### Links and popups that keep window.opener

Variants that still work in current browsers:

- `window.open(url)` with no window features, or with features that do not include `noopener`/`noreferrer`; common in "open in new tab" buttons, preview links, help widgets and SSO popups.
- Links with `rel="opener"`, sometimes added on purpose by a developer who needed the handle and then copied to other links.
- Links with a named target (`target="docs"`, `target="external"`) that open a new window.
- Application code that opens an external URL with `window.open` and then sets `win.opener = null` afterwards; this works only if it runs before the opened page's script does, which is a race you should not rely on.
- Old browsers that do not apply implicit `noopener`, including embedded webviews in apps you do not control.

In the reverse direction, a page of yours that is *opened* by someone else's page can be navigated by its opener. That is the mechanism behind the DoubleClickjacking variant above and is what COOP `same-origin` severs.

### User-generated links

Reverse tabnabbing only matters when the opened page is hostile. That happens when users can put links in front of other users (profiles, comments, support tickets, chat, Markdown documents, report descriptions in a bug tracker) or when your application links to third-party sites that could be compromised. Two places to check: the renderer that turns user Markdown or rich text into links (does it add `rel`? does it use `target`?), and any JavaScript that intercepts link clicks and calls `window.open` itself, which silently undoes the browser's implicit `noopener` protection. The HackerOne inbox report in [Real-world cases](#real-world-cases) is a user-supplied link of this kind.

## Testing

Run these tests only within an authorised engagement (written scope and rules of engagement), a bug bounty programme whose rules allow them, or a lab. Request and response examples are illustrative; hosts, paths and headers are made up.

### Before you start

**Accounts.** You need your own test account (user A) for every role whose pages you will check, plus an administrator account if the client provides one, and where relevant a second account (user B) to see what another user would see. Every framed page, every clicked button and every link you plant belongs to **your own test accounts**. For OAuth consent tests, use an OAuth client registered for the test (in the client's test tenant or a lab), never a real third-party application.

**What a proof is here.** The proof for clickjacking is a **local HTML file** opened in your own browser that frames a page of your own test account and shows, visibly, that the page renders in the frame with your session and that a sensitive control sits where a click could reach it. Optionally, you click the control yourself in the frame, against your own test object, to show the action completes from inside the frame. The proof for reverse tabnabbing is a page **you** control that reports whether `window.opener` is available and, at most, navigates the opener to `https://example.org/`. Neither page sends anything anywhere.

**What we do not build.** No decoy pages designed to fool real users, no lures, no hosted clickjacking pages aimed at the client's users or staff, no look-alike login pages, no phishing flows after a tabnabbing proof, and no double-click timing exploits. Where the realistic attack needs those, describe it in the report and link the public research.

**Tooling.**

- A browser profile per test browser with default settings (cookie behaviour differs, and you want the victim's defaults, not yours): current Chrome, Firefox and Safari where you can. Record versions.
- A tiny local web server for the PoC files (`python3 -m http.server 8000 --bind 127.0.0.1`), so the PoC has an ordinary `http://127.0.0.1:8000` origin that is cross-site to the target. Opening files from `file://` mostly works too, but browsers treat `file://` origins in special ways that can confuse cookie results.
- Burp Suite (Proxy, Repeater, Logger). Burp Scanner raises *Frameable response (potential Clickjacking)*; **Burp Clickbandit** (Burp menu, Burp Clickbandit) records clicks on a page and generates an overlay file for demonstration; use it on your own test account and keep its output local.
- curl and a list of URLs for header sweeps (test 2).
- OWASP ZAP's passive rules *Anti-clickjacking Header* (10020) and *Reverse Tabnabbing* (10108) give a quick first pass over a proxied crawl.

**Stop rules.** If a framed page or a planted link unexpectedly shows or affects a real person's data (a real customer's account in a shared environment, a link that other users can see when you expected it private), stop, remove what you planted, keep only minimal redacted evidence and tell the client. Do not leave planted links in place after testing; record each place you put one and remove it at the end.

**Rate.** These tests are light: header sweeps at one or two requests per second, a handful of manual page loads per finding.

### GT-WEB-CLICK-1: Inventory frame-sensitive pages and one-click actions

*Guler Tech methodology.* Implements the scoping step of WSTG-CLNT-09 (identifying what an attacker would want a victim to click) and prepares the evidence a clickjacking finding needs.

#### What it checks

Which pages in the application carry actions that are worth stealing a click for, and what each action needs besides clicks.

#### Prerequisites

Logged-in browsing as each role you were given; Burp Logger running so every page you visit is recorded.

#### Steps

1. Walk the application per role and list every control that changes state. For each, record: URL of the page that hosts it, number of clicks needed, any input needed and whether that input can be supplied by URL parameter, whether a confirmation step exists, and whether re-authentication or a second factor is required.
2. Mark the high-value ones: security settings (email, phone, MFA, recovery, sessions, API keys), account deletion, payments and transfers, OAuth and SSO consent, account linking, sharing and visibility, admin role and user management, invitations, device or extension approval.
3. Note pages served by other components: identity provider, consent screen, payment page, admin console, separately hosted SPA, help-centre widgets.
4. For each high-value page, check whether the action is one request triggered by one click (a `POST` form, a button calling an API) or a flow; note the request in Burp.

#### Observation

A table like this (illustrative):

| Page | Action | Clicks | Input | Confirmation | Re-auth |
|---|---|---|---|---|---|
| `/account/security` | Disable MFA | 1 | none | none | no |
| `/account/delete` | Delete account | 2 | none | "Are you sure?" button | no |
| `/account/email` | Change email | 1 | new email, accepted from `?email=` | email to old address | no |
| `/oauth/authorize` | Authorise third-party app | 1 | none | none | no |
| `/admin/users/{id}` | Grant admin role | 1 | none | none | no |
| `/settings/profile` | Change display name | 1 | text | none | no |

#### Evaluation

This test produces a work list, not a finding. Pages with one- or two-click high-value actions and no step the attacker cannot fake go to tests 2–7. Pages whose only actions need typed secrets the attacker cannot know, or that have no state-changing controls, are out of scope for clickjacking.

#### False positives

- **Login pages.** A frameable login page is usually not a clickjacking finding: the attacker cannot type the victim's credentials for them, and cannot read what the victim types into a cross-origin frame. Password managers generally do not auto-submit into cross-origin frames without user action (behaviour varies by product; check if you rely on it). It becomes interesting only in specific cases: one-click "Continue as …" SSO buttons (those are consent pages, not login pages), or login CSRF where the attacker's credentials are prefilled by URL and the victim's click signs them into the attacker's account.
- **Read-only pages showing sensitive data.** Framing does not reveal the data to the attacker.
- **Actions needing a typed secret** (current password, OTP) at the moment of the action.

#### Automation

None useful; this is judgement. Keep the table in the engagement notes and reuse it for regression (test 2 sweeps the same URLs).

### GT-WEB-CLICK-2: Check framing headers across routes, status codes and content types

*Guler Tech methodology.* Implements the server-side protection checks of WSTG-CLNT-09 (CSP `frame-ancestors`, `X-Frame-Options`, proxies stripping headers, mobile versions) and ASVS `v5.0.0-3.4.6`.

#### What it checks

Whether every response that could render a sensitive page carries an effective framing policy, including the responses developers forget.

#### Prerequisites

The URL list from test 1, extended with: a non-existent path, a route that redirects (login redirect), a route that returns `401`/`403` when logged out, static HTML files, any uploaded-file or attachment URL of your own, the OAuth authorise URL with your test client, alternate hosts (`m.`, legacy admin), and trailing-slash and case variants of key routes.

#### Steps

1. Look at one response by hand first:

```http
GET /account/security HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
Accept: text/html
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-r4nd0m'; object-src 'none'; base-uri 'none'
X-Frame-Options: ALLOW-FROM https://example.org
Cross-Origin-Opener-Policy: same-origin-allow-popups
Set-Cookie: session=<SESSION_USER_A>; Path=/; Secure; HttpOnly; SameSite=None
```

This illustrative response is frameable by anyone in a current browser: the CSP has no `frame-ancestors` (and `default-src` does not cover it), `ALLOW-FROM` is ignored, and the session cookie is `SameSite=None`.

2. Sweep the list with a small script. It prints the status, content type and framing headers for each URL, using your own session, without following redirects (so each redirect's own headers are visible):

```bash
#!/usr/bin/env bash
# frame-headers.sh: framing headers per URL. Usage: ./frame-headers.sh urls.txt
# Uses your own test session; one request every half second.
COOKIE='session=<SESSION_USER_A>'
printf '%-6s %-24s %-22s %-36s %s\n' STATUS TYPE X-FRAME-OPTIONS FRAME-ANCESTORS URL
while IFS= read -r url; do
  [ -z "$url" ] && continue
  h=$(curl -s -o /dev/null -D - --max-time 15 -b "$COOKIE" "$url" | tr -d '\r')
  status=$(printf '%s\n' "$h" | awk 'toupper($1) ~ /^HTTP\// {s=$2} END {print s}')
  ctype=$(printf '%s\n' "$h" | awk -F': ' 'tolower($1)=="content-type" {print $2}' | tail -1 | cut -d';' -f1)
  xfo=$(printf '%s\n' "$h" | awk -F': ' 'tolower($1)=="x-frame-options" {printf "%s|", $2}')
  fa=$(printf '%s\n' "$h" | awk -F': ' 'tolower($1)=="content-security-policy" {print $2}' \
       | tr ';' '\n' | grep -i 'frame-ancestors' | sed 's/^ *//' | paste -sd'|' -)
  ro=$(printf '%s\n' "$h" | grep -ci '^content-security-policy-report-only:.*frame-ancestors')
  note=""; [ "$ro" -gt 0 ] && note="  (frame-ancestors also in Report-Only: does not enforce)"
  printf '%-6s %-24s %-22s %-36s %s%s\n' "${status:--}" "${ctype:--}" "${xfo:--}" "${fa:--}" "$url" "$note"
  sleep 0.5
done < "$1"
```

3. Repeat without the cookie (logged-out responses are sometimes built by a different code path) and against each alternate host.
4. Check the page source of key pages for `meta http-equiv` attempts at either header; they do not count.
5. If the CDN or load balancer is in scope, compare a response fetched through it with one from the origin, if the client gives you a direct origin URL; differences point to a proxy stripping or adding headers.

#### Observation

Illustrative sweep output:

```text
STATUS TYPE                     X-FRAME-OPTIONS        FRAME-ANCESTORS                      URL
200    text/html                DENY|                  frame-ancestors 'none'               https://app.example.com/account/security
302    -                        -                      -                                    https://app.example.com/account/delete
200    text/html                -                      -                                    https://app.example.com/oauth/authorize?client_id=gt-test-client&response_type=code&redirect_uri=https%3A%2F%2Fexample.org%2Fcb
404    text/html                -                      -                                    https://app.example.com/gt-does-not-exist
200    text/html                SAMEORIGIN|            frame-ancestors *                    https://app.example.com/embed/dashboard
200    application/json         -                      -                                    https://api.example.com/v1/me
```

Here the OAuth consent page and the `404` page have no policy, and the embed route's `frame-ancestors *` overrides its `X-Frame-Options`.

#### Evaluation

For each high-value page from test 1:

- **Pass:** an enforced `frame-ancestors 'none'` or `'self'` (or a short, justified allow-list of HTTPS origins), with or without `X-Frame-Options: DENY`/`SAMEORIGIN`; or, for very old browser support only, `X-Frame-Options` alone.
- **Fail (candidate, confirm in test 3):** no policy; `ALLOW-FROM` only; `meta` only; report-only only; permissive `frame-ancestors` (`*`, `https:`, wildcard subdomains that include user-content hosts, `http:` origins).
- **Fail (ASVS gap, lower priority):** `X-Frame-Options` present but no `frame-ancestors`, which does not meet `v5.0.0-3.4.6` (L2) but blocks framing in current browsers; or framing policy missing on responses that carry no sensitive UI (JSON, images, the 404 page). Report these as hardening, not as clickjacking.

#### False positives

- **JSON and other non-rendering responses** without the header. ASVS asks for `frame-ancestors` on every response; a missing header on an API response is a compliance gap, not a clickjacking bug.
- **A redirect without the header** whose target page has it. The frame follows the redirect and the final response's policy applies.
- **Scanner output that ignores CSP.** Some scanners flag "missing X-Frame-Options" on pages that are protected by `frame-ancestors`. Check by hand.
- **Logged-out variants** that show only a login form.

#### Automation

The script runs fine in CI against a staging environment: keep the high-value URL list from test 1 in the repository and fail the job if any of them lacks an enforced `frame-ancestors` with `'none'` or `'self'`. ZAP rule 10020 and Burp's *Frameable response* issue give broad coverage on a crawl; the URL list catches the flows crawlers do not reach (OAuth, payment, invitation links).

### GT-WEB-CLICK-3: Confirm framing with a local proof-of-concept page

*Guler Tech methodology.* Implements the core test of WSTG-CLNT-09 (load the target in an `iframe` from an HTML page you control) and turns a header observation into evidence.

#### What it checks

Whether a high-value page of your own test account actually renders inside a cross-site frame, logged in, with its sensitive control usable.

#### Prerequisites

A candidate from test 2; your own test account logged in to the target in the browser you test with; the local web server from [Before you start](#before-you-start).

#### Steps

1. Save this file as `gt-click-3.html` in the directory you serve on `127.0.0.1:8000`. Replace the `src` with the high-value page from your own test account. The frame starts half-transparent so a screenshot shows both layers; the slider lets you show it fully visible or fully transparent. The script only changes the frame's opacity and logs a marker to the console:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GT-WEB-CLICK-3 framing check (own test account, local only)</title>
<style>
  body { font: 14px system-ui, sans-serif; margin: 16px; }
  #wrap { position: relative; width: 960px; height: 640px; border: 2px dashed #b00020; }
  #target { position: absolute; inset: 0; width: 100%; height: 100%; border: 0; opacity: 0.5; z-index: 2; }
  #marker { position: absolute; top: 410px; left: 140px; z-index: 1; padding: 6px 12px; background: #ffe08a; }
</style>
</head>
<body>
  <p>GT-WEB-CLICK-3: does <code>https://app.example.com/account/security</code> render in a cross-site frame?</p>
  <label>Frame opacity <input id="opacity" type="range" min="0" max="1" step="0.1" value="0.5"></label>
  <div id="wrap">
    <div id="marker">Position of the sensitive control (marker)</div>
    <iframe id="target" src="https://app.example.com/account/security"></iframe>
  </div>
  <script>
    const frame = document.getElementById("target");
    document.getElementById("opacity").addEventListener("input", (e) => {
      frame.style.opacity = e.target.value;
    });
    // A load event fires even when framing is blocked, so this proves nothing by itself.
    frame.addEventListener("load", () => console.log("GT-WEB-CLICK-3: iframe load event"));
  </script>
</body>
</html>
```

2. Open `http://127.0.0.1:8000/gt-click-3.html`. Look at the frame: does it show your logged-in page, a login page, or the browser's "refused to connect" placeholder? Check the DevTools console for a message about `frame-ancestors` or `X-Frame-Options`.
3. Move the marker (edit `top` and `left`) to sit under the sensitive control and take a screenshot at opacity 0.5, then one at 1.0. The pair shows the overlay is possible without making a convincing lure.
4. Optionally, set opacity to 1, click the control **yourself** inside the frame against your own test object (for example, disable MFA on your own test account, then re-enable it), and capture the resulting request in Burp. This shows the action completes from within the frame.
5. Repeat in each browser you are testing (test 4 explains why results differ).

#### Observation

Vulnerable (illustrative): the frame shows the logged-in security settings page with your test user's name; the console has no framing error; the click in step 4 produces:

```http
POST /account/security/mfa/disable HTTP/1.1
Host: app.example.com
Origin: https://app.example.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Dest: iframe
Cookie: session=<SESSION_USER_A>
Content-Type: application/x-www-form-urlencoded

csrf_token=<CSRF_TOKEN_USER_A>
```

Note `Origin: https://app.example.com`, a valid CSRF token, and `Sec-Fetch-Dest: iframe`: the request is genuine apart from where the page was rendered. (`Sec-Fetch-Dest: iframe` appears because a classic form submission navigates the frame; if the button calls an API with `fetch`, you will see `Sec-Fetch-Dest: empty` instead and nothing in the request reveals the framing.)

Not vulnerable: the frame area shows the browser's blocked-content placeholder and the console reports that the page refused to be framed because of `frame-ancestors 'none'` or `X-Frame-Options: deny`.

#### Evaluation

- **Fail:** a high-value page renders logged in and its control works from inside the frame in at least one current mainstream browser with default settings. Record which browsers.
- **Fail (lower):** the page renders but logged out (cookies not sent, see test 4), and the unauthenticated page has no harmful action. Report the missing policy as hardening.
- **Pass:** framing is blocked, or the page renders but every sensitive action requires a step the attacker cannot supply (typed secret, re-authentication on a non-frameable page).

#### False positives

- **The load event or a 200 in DevTools' network tab.** Blocked frames still load and fire `load`; judge by what renders.
- **Your own extensions.** Ad blockers and privacy extensions change framing and cookie behaviour; use a clean profile.
- **Logged in only because of your settings.** If you relaxed cookie settings in your own profile, the result does not describe a real victim.

#### Automation

A headless browser test can assert that a known high-value URL refuses to frame: Playwright loads the PoC page from a local server and checks that the frame's content frame has no element from the target page (or listens for the console message). Keep it in the application's own test suite against staging; see [Regression tests](#regression-tests).

### GT-WEB-CLICK-4: Session cookies in a cross-site frame

*Guler Tech methodology.* Supports WSTG-CLNT-09 (the "victim is authenticated" precondition) and checks ASVS `v5.0.0-3.3.2`. It decides how far a framing gap actually reaches.

#### What it checks

Whether the cookies that authenticate the user are sent to a cross-site frame in current browsers, and whether a same-site position exists from which they would be sent anyway.

#### Prerequisites

Test 3's PoC page; clean browser profiles for Chrome, Firefox and Safari (or as many as you have); a list of the target's subdomains in scope.

#### Steps

1. Log in and list every cookie that can authenticate a request, not just the obvious session cookie: remember-me or refresh cookies, SSO cookies on the identity provider's host, and any cookie the API accepts. Note each one's `SameSite`, `Secure`, `Domain` and `Partitioned` attributes from the `Set-Cookie` headers:

```http
HTTP/1.1 200 OK
Set-Cookie: session=<SESSION_USER_A>; Path=/; Secure; HttpOnly; SameSite=Lax
Set-Cookie: remember_me=<REMEMBER_TOKEN_USER_A>; Path=/; Max-Age=2592000; Secure; HttpOnly; SameSite=None
```

2. Load test 3's PoC in each browser and note whether the frame renders logged in. If it does with a `Lax` session cookie, look for the second cookie that did it (in the example above, the `SameSite=None` remember-me cookie can re-establish a session inside the frame).
3. Compare with the browser's DevTools: Application (Chrome) or Storage (Firefox) shows which cookies were sent to the framed document and why others were blocked; Chrome's Network panel flags cookies filtered by `SameSite` or third-party settings.
4. Look for same-site positions: subdomains of the same registrable domain that serve user-controlled HTML (customer portals such as `tenant-a.example.com`, uploaded-file hosts, documentation platforms, marketing pages on third-party CMSs). Do not try to take over or upload HTML to any of them; just record that the position exists.

#### Observation

Illustrative result table:

| Browser (version) | Frame renders | Logged in | Why |
|---|---|---|---|
| Chrome (current, default settings) | yes | yes | `remember_me` is `SameSite=None`; Chrome sends third-party cookies by default |
| Firefox (current, ETP standard) | yes | no | Total Cookie Protection: the frame gets a partitioned, empty jar |
| Safari (current) | yes | no | Third-party cookies blocked |

#### Evaluation

- **Authenticated clickjacking possible:** at least one mainstream browser with default settings renders the frame logged in. Name the browsers in the finding; that is part of its likelihood.
- **Limited to same-site attackers:** frames load logged out cross-site, but a same-site position exists. Report the framing gap with that precondition (it usually lowers severity, but a subdomain that already hosts user HTML makes it practical).
- **Not reachable authenticated:** all authenticating cookies are `Lax`/`Strict`, no same-site position exists. A missing framing policy is then hardening, unless an unauthenticated harmful action exists.

#### False positives

- **Testing in a profile where you allowed third-party cookies** or added a site exception.
- **A session established inside the frame.** If you logged in inside the frame during an earlier test, the browser may have stored a partitioned cookie for that frame context; a real victim would not have it. Clear site data between runs.

#### Automation

Cookie attributes are easy to check in CI: fail when any authenticating cookie lacks an explicit `SameSite` or uses `None` without a documented reason. The browser behaviour itself is not stable enough to automate across vendors; re-check it manually at each test.

### GT-WEB-CLICK-5: Frame busting scripts and sandboxed iframes

*Guler Tech methodology.* Implements the "disabled JavaScript" and "sandbox attribute" checks of WSTG-CLNT-09.

#### What it checks

Whether a page that relies on JavaScript to break out of frames can still be framed and used when the framing page restricts the frame's scripts or navigation.

#### Prerequisites

A high-value page with no effective header (test 2) whose source contains frame-busting code; test 3's PoC page.

#### Steps

1. Find the framebuster. Search the page source and bundles for patterns such as `top.location`, `window.top !== window.self`, `self != top`, `parent.location`, `window.frameElement`, or a style rule hiding `body` that a script later removes.
2. Load the plain PoC from test 3 and confirm the framebuster fires (the tab navigates to the target, or the page stays blank).
3. Change the `iframe` in the PoC to each of these variants, one at a time, reloading between them:

```html
<!-- Scripts run, but the frame may not navigate the top window -->
<iframe id="target" src="https://app.example.com/account/security"
        sandbox="allow-forms allow-scripts allow-same-origin"></iframe>

<!-- No scripts at all: enough for server-rendered forms -->
<iframe id="target" src="https://app.example.com/account/security"
        sandbox="allow-forms allow-same-origin"></iframe>
```

`allow-same-origin` keeps the framed page's real origin, so its cookies and storage work and its form posts carry `Origin: https://app.example.com` instead of `Origin: null` (which many servers reject). `allow-top-navigation` and `allow-top-navigation-by-user-activation` are deliberately absent.

4. For each variant, note whether the page renders, whether it is logged in (test 4), and whether the sensitive control works when **you** click it.

#### Observation

Vulnerable (illustrative): with the first variant the framebuster runs, its attempt to navigate the top window is blocked (the console shows a sandbox navigation error), and the page remains fully usable in the frame. With the second variant the server-rendered form works without any script.

Fail-closed pattern (better): the page ships with `body { display: none }` and only reveals itself when `self === top`; both sandbox variants leave the frame blank.

#### Evaluation

- **Fail:** the page is usable in any sandbox variant. Report as missing framing protection; the framebuster is not a control.
- **Pass (weak):** the page fails closed in every variant. Still recommend `frame-ancestors`, because script-based defences depend on the page's own code staying correct and running first.

#### False positives

- **A SPA that does nothing without scripts** is not exploitable through the no-scripts variant; test the scripts-allowed variant before concluding.
- **Navigation you allowed by mistake.** If your variant includes `allow-top-navigation`, the framebuster working proves nothing.

#### Automation

Code review: flag framebusting snippets in templates as a sign that the header is missing. There is little value in automating the sandbox test itself; the header check from test 2 is what goes into CI.

### GT-WEB-CLICK-6: Prefilled forms, multi-step flows and confirmation dialogs

*Guler Tech methodology.* Implements the multi-action and input-carrying variants behind WSTG-CLNT-09 (the PortSwigger prefilled-input and multistep patterns) and checks whether confirmation steps actually stop a stolen click.

#### What it checks

Whether actions that look safe because they need input or a second click can still be completed with clicks alone inside a frame.

#### Prerequisites

Frameable high-value pages from tests 2–4; your own test account and your own test objects.

#### Steps

1. **Prefill.** For each form that takes input, try supplying the values by URL. Use only values that are yours, such as a mailbox you own:

```http
GET /account/email?email=gt-click-6%40example.org HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
```

Check whether the rendered form shows the value. Also try common alternative names the client-side code reads (`new_email`, `value`, fragments like `#email=`), and check whether a SPA route copies query parameters into its form state.
2. **Multi-step.** For each two-step action, check whether the second step (the "Are you sure?" page or modal) is itself frameable and whether it can be loaded directly by URL. A modal inside the same framed page is just one more click.
3. **Confirmation dialogs.** If the confirmation is `window.confirm()`, load the page in test 3's PoC without a sandbox and with `sandbox="allow-forms allow-scripts allow-same-origin"` (no `allow-modals`). Note whether the action proceeds when the dialog is suppressed.
4. **Input that cannot be prefilled.** Note where the action needs the user to type something the attacker can choose but not prefill (a free-text reason, a confirmation word). That is harder to clickjack but not impossible (users can be asked to type a word in a game); record it as friction, not as a defence.

#### Observation

Vulnerable (illustrative): `/account/email?email=gt-click-6@example.org` renders the form with the value filled in; one click on Update completes the change for your own test account. The "Are you sure?" step is a modal in the same page, one more click away.

Robust: the change requires the current password on a page that is not frameable, or the new email must be confirmed from the old address before it takes effect (ASVS `v5.0.0-7.5.1`, L2, asks for full re-authentication before changing email, phone, MFA or recovery data).

#### Evaluation

- **Fail:** a high-value action completes with clicks only, using values supplied by URL, in a frameable page.
- **Pass:** the action needs a secret, a re-authentication step, or an out-of-band confirmation that a click in a frame cannot produce.
- A `window.confirm()` that blocks the action when suppressed is a pass for the sandboxed variant only; the unsandboxed dialog is shown to the user and is weak.

#### False positives

- **Prefill that only affects display** (the form shows the value but the server ignores it or requires it to be retyped).
- **Out-of-band confirmation that actually gates the change.** An email change that only takes effect after the old address confirms is not a one-click takeover, even if the request itself is clickjackable.

#### Automation

Unit or integration tests for sensitive forms: assert that query parameters do not populate security-relevant fields, and that the change endpoint refuses requests without a fresh re-authentication marker.

### GT-WEB-CLICK-7: OAuth consent, payment and approval pages against timing attacks

*Guler Tech methodology.* Extends WSTG-CLNT-09 to top-level UI redressing (the DoubleClickjacking class) and checks the consent requirements in ASVS `v5.0.0-10.7.1` and `v5.0.0-10.7.2` (both L2). This is a review test; we do not build timing exploits.

#### What it checks

Whether one-click approvals that are correctly protected against framing could still be triggered by a click the user did not intend, because the page accepts the first click that lands on it.

#### Prerequisites

The list of top-level approval pages from test 1 (OAuth consent, account linking, payment approval, device or extension approval, admin confirmations); an OAuth client registered for the test; your own test account.

#### Steps

1. Confirm each page is non-frameable (test 2). If it is frameable, that is the more serious finding; report it first.
2. Open the consent page for your own test client:

```http
GET /oauth/authorize?client_id=gt-test-client&response_type=code&scope=profile%20repos.write&redirect_uri=https%3A%2F%2Fexample.org%2Fcb&state=gt-click-7 HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
```

3. Review how the approval control behaves: is it enabled at first paint? Does the page's script ignore activations that arrive immediately after the page loads or after the window regains focus? Is there any delay, gesture requirement or focus check in the bundle?
4. Review what the server requires: does approval of high-risk scopes or large payments need anything beyond the click (re-authentication, a typed confirmation, a second factor, a notification with an undo window)? Does the consent screen clearly show the client's identity, the scopes and their lifetime (`v5.0.0-10.7.2`)?
5. Check whether consent can be skipped entirely for clients the user has never approved (for example, a first-party flag misapplied to third-party clients, or `prompt=none` honoured without previous consent). That is a different, more serious flaw: no click is needed at all.
6. Manual sanity check, on your own account only: switch to the consent window with the keyboard and click the approval control at once. Note whether the click is accepted. This is not a proof of exploitability, only an observation of whether any gating exists.

#### Observation

Exposed (illustrative): the Authorise button is active the moment the page renders, the bundle has no gating logic, and approving `repos.write` needs nothing but the click.

Hardened: approval of write scopes requires re-entering the password or a passkey prompt, or the button only accepts activation after the page has had focus for a short time, with keyboard and assistive technology activation still working.

#### Evaluation

- **Finding (design weakness):** a single click on a top-level page grants broad third-party access, moves money, or changes security settings, with no server-side step beyond the click. Report with a reference to the DoubleClickjacking research; rate it on the scopes or value at stake and on the absence of server-side confirmation, and say clearly that no exploit was built.
- **Pass:** high-impact approvals require something the click cannot supply, or the client accepts the residual risk for low-impact scopes.
- **Separate, more serious finding:** consent skipped for untrusted clients (step 5) or the consent page frameable (step 1).

#### False positives

- **Low-impact consent** (read-only profile scope for a first-party client) where the click grants little.
- **Gating that only exists on the server** (for example, a consent token that must be at least a second old). That is a valid control even if the button looks active; ask the client or check the server logic in a grey-box test.

#### Automation

Not practical to automate as an attack. Add a design checklist item for every new approval page ("what does the server require besides the click?") and an integration test that high-risk scopes trigger step-up authentication.

### GT-WEB-CLICK-8: Review links and window.open calls for opener access

*Guler Tech methodology.* Implements the source-review steps of WSTG-CLNT-14 (links opening new tabs without `noopener`, `window.open()` calls without the `noopener` feature), adjusted for current browser defaults.

#### What it checks

Which links and scripts open other pages in a way that leaves `window.opener` set in a current browser, and where those pages' content comes from.

#### Prerequisites

Logged-in browsing of pages that show links, especially user-generated ones; access to the front-end source or bundles (grey box) if available.

#### Steps

1. **Rendered DOM.** On each page with outbound or user-supplied links, run this in the DevTools console. It lists elements that keep the opener in a current browser (`keeps`) and plain `_blank` links that rely on the browser default (`legacy`, a concern only for old browsers):

```javascript
// GT-WEB-CLICK-8: links and forms that may keep window.opener
[...document.querySelectorAll("a[target], area[target], form[target]")]
  .map((el) => {
    const rel = (el.getAttribute("rel") || "").toLowerCase().split(/\s+/);
    const target = (el.getAttribute("target") || "").toLowerCase();
    const cut = rel.includes("noopener") || rel.includes("noreferrer");
    const keeps = !cut && (rel.includes("opener") || !["_blank", "_self", "_top", "_parent"].includes(target));
    const legacy = !cut && target === "_blank";
    return { tag: el.tagName, target, rel: rel.join(" "), url: el.href || el.action, keeps, legacy };
  })
  .filter((r) => r.keeps || r.legacy);
```

2. **Scripts.** Search the bundles (DevTools Sources, search all files) or the repository for `window.open(` and other `.open(` calls on `window`, and for click handlers on links that call them. Compare the window features argument:

```javascript
// Keeps window.opener in every browser
window.open(link.href, "_blank");

// Cuts it (and returns null, so code must not rely on the handle)
window.open(link.href, "_blank", "noopener,noreferrer");
```

3. In a grey-box test, grep the source as well:

```bash
rg -nP -g '!node_modules' -g '!dist' \
  -e 'window\.open\s*\(' \
  -e 'rel\s*=\s*["\x27][^"\x27]*\bopener\b' \
  -e 'target\s*=\s*["\x27](?!_blank|_self|_top|_parent)[^"\x27]+["\x27]' \
  src/
```

4. For every hit, record where the URL comes from: a constant, a first-party route, a third-party site, or user input.

#### Observation

Illustrative findings: the comment renderer outputs `target="_blank"` with no `rel` (legacy only); a "preview link" button calls `window.open(comment.url)` with no features (keeps the opener); the help widget uses `target="helpdesk"` (named target, keeps the opener when it opens a new window).

#### Evaluation

- **Fail:** a `window.open` call, `rel="opener"` link or named-target link that opens a URL controlled by users or by a third party, without `noopener`. Confirm with test 9.
- **Hardening (Info):** plain `target="_blank"` without `rel`, which current browsers already treat as `noopener`; recommend explicit `rel="noopener noreferrer"` where the client supports old browsers or embedded webviews.
- **Pass:** opener cut everywhere content is not first-party, or COOP `same-origin` on the opening pages (test 10).

#### False positives

- **Named targets that point at an existing `iframe`** in the same page rather than opening a new window.
- **First-party destinations** under your own control (same origin, or a sister site the client operates securely). The opener relationship is harmless when the opened page is trustworthy.
- **`window.open` used for same-origin popups** that need the handle (OAuth popup flows on the client's own identity provider); judge by destination.

#### Automation

Lint rules catch most of this before it ships: `react/jsx-no-target-blank` in eslint-plugin-react flags `target="_blank"` without `rel="noreferrer"` in JSX, and a simple custom rule or grep in CI can flag `window.open(` calls without a features argument containing `noopener`. ZAP passive rule 10108 reports links with a `target` attribute that lack both `noopener` and `noreferrer`; expect it to be noisy on plain `_blank` links.

### GT-WEB-CLICK-9: Prove opener access from a user-supplied link

*Guler Tech methodology.* Implements the dynamic check of WSTG-CLNT-14 (insert a link to a page that tries to change `window.opener.location`, and see whether the original tab navigates).

#### What it checks

Whether a page opened from your application, through a link that a user can supply, can navigate the application's tab.

#### Prerequisites

A candidate from test 8 where users can supply the URL; a page you control on your own domain (written here as `https://example.org/gt-opener-check.html`); two test accounts (A plants, B clicks); a place to plant the link that only your test accounts can see (a private note, a ticket between A and B, a profile in a test tenant).

#### Steps

1. Publish this page on your domain. It only reports whether the opener is available and, if you press the button, navigates the opener to `https://example.org/`. It reads nothing and sends nothing:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GT-WEB-CLICK-9 opener check</title>
</head>
<body>
  <p id="out">GT-WEB-CLICK-9: checking window.opener</p>
  <button id="nav" hidden>Navigate the opener to https://example.org/</button>
  <script>
    const out = document.getElementById("out");
    if (window.opener) {
      out.textContent = "GT-WEB-CLICK-9: window.opener is available. The opening tab can be navigated.";
      const btn = document.getElementById("nav");
      btn.hidden = false;
      btn.addEventListener("click", () => { window.opener.location = "https://example.org/"; });
    } else {
      out.textContent = "GT-WEB-CLICK-9: window.opener is null (noopener or COOP in effect).";
    }
  </script>
</body>
</html>
```

2. As user A, put the link into the chosen field (**own test objects only**):

```http
PATCH /api/tickets/88412 HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
Content-Type: application/json

{"comment": "GT-WEB-CLICK-9 link test: https://example.org/gt-opener-check.html"}
```

3. As user B, open the ticket and click the link the way a normal user would (the rendered link, the preview button, whatever the UI offers). Note the marker text in the new tab. If the opener is available, press the button and switch back to the application's tab.
4. Repeat for each way the UI opens the link (inline link, preview button, notification email that opens the app and then the link).
5. Remove the comment afterwards and note the removal in your log.

#### Observation

Vulnerable (illustrative): the new tab shows "window.opener is available"; after pressing the button, user B's application tab shows `https://example.org/` with no visible sign that it changed.

Not vulnerable: "window.opener is null".

#### Evaluation

- **Fail:** a link any user can supply opens with the opener available in a current browser, so the original tab can be navigated to any URL. This is the reverse tabnabbing finding; describe the phishing follow-up (a look-alike login page) in prose.
- **Fail (legacy only):** the opener is available only in a browser the client still supports (a specific old webview or managed legacy browser). Rate lower and name the browser.
- **Pass:** opener null in all supported browsers.

#### False positives

- **Opening the link yourself from the address bar** or with a middle-click in some browsers changes the opener behaviour; use the application's own UI.
- **Your proof page on the same site as the application.** Use a separate registrable domain so the result is not distorted by same-site behaviour.

#### Automation

A Playwright test can click a seeded link in staging and assert that the new page's `window.opener` is `null`; it catches regressions in renderers and link handlers.

### GT-WEB-CLICK-10: Cross-Origin-Opener-Policy on document responses

*Guler Tech methodology.* Supports WSTG-CLNT-14 (COOP as the header-level control for opener access) and checks ASVS `v5.0.0-3.4.8` (L3).

#### What it checks

Whether document responses send COOP with a value that severs cross-origin opener relationships, both for pages your application opens and for pages that others open.

#### Prerequisites

The URL list from test 2; a browser console on the application.

#### Steps

1. Add a COOP column to the test 2 sweep, or check key pages directly:

```bash
curl -s -o /dev/null -D - -b 'session=<SESSION_USER_A>' https://app.example.com/account/security \
  | grep -i '^cross-origin-opener-policy'
```

2. Outbound: on an application page, open a third-party page and look at the handle after it loads:

```javascript
const w = window.open("https://example.org/", "_blank");
setTimeout(() => console.log("GT-WEB-CLICK-10 outbound closed =", w ? w.closed : "null handle"), 2000);
```

3. Inbound: from test 3's local PoC page (a cross-site opener), open an application page and check the same thing:

```javascript
const w = window.open("https://app.example.com/account/security", "_blank");
setTimeout(() => console.log("GT-WEB-CLICK-10 inbound closed =", w ? w.closed : "null handle"), 2000);
```

#### Observation

With `Cross-Origin-Opener-Policy: same-origin` on the application page, both checks report `closed = true`: the two pages are in different browsing context groups and cannot reach each other. With `same-origin-allow-popups`, the outbound check reports `false` (the popup to the third-party page keeps its opener) and the inbound check `true`. With no COOP, both report `false`, unless the other page sends a COOP header of its own (`https://example.org/` did not at the time of writing, which makes it a neutral destination for this check).

#### Evaluation

- **Pass (L3):** `same-origin` on documents that do not need cross-origin popups; `same-origin-allow-popups` where the page genuinely relies on popups (OAuth or payment), combined with `noopener` on every other outbound link.
- **Gap (Info, L3 only):** no COOP. Report as hardening, raising it only where test 9 found an exploitable opener and COOP would have stopped it.

#### False positives

- **COOP on non-document responses** (JSON, images) is irrelevant; check HTML.
- **Pages that legitimately need the opener** (a payment popup returning to the merchant page). Those need `same-origin-allow-popups` on the opener or a postMessage design that does not depend on the opener; see [postMessage and web messaging](/web/web-postmessage-web-messaging/).

#### Automation

Add COOP to the header check in CI next to `frame-ancestors`. Helmet and Django send `same-origin` by default; Spring Security needs it configured.

## Secure implementation

### Design rules

1. **Deny framing by default, everywhere.** Send `Content-Security-Policy: frame-ancestors 'none'` (or `'self'` if the application frames itself) on every response, plus `X-Frame-Options: DENY` (or `SAMEORIGIN`) for old browsers. Set it at the outermost layer you control (framework middleware *and* the web server or CDN for files the framework never sees), not per page.
2. **Make exceptions narrow.** If something must be embeddable, give it its own route or host, an explicit HTTPS allow-list in `frame-ancestors`, and no sensitive one-click actions.
3. **Set `SameSite` deliberately on every authenticating cookie.** `Lax` or `Strict` for sessions; `None` only for cookies that genuinely must work in third-party contexts, and never for a remember-me cookie that can recreate a session inside a frame.
4. **Do not let a click be the only authorisation for high-impact actions.** Re-authenticate before changing email, phone, MFA or recovery settings (ASVS `v5.0.0-7.5.1`); confirm payments and high-risk OAuth scopes with something the user must supply. This is the only defence that also covers top-level timing attacks.
5. **Cut opener relationships.** `rel="noopener noreferrer"` on links to anything you do not control, `noopener` in `window.open` features, COOP `same-origin` on documents.
6. **Test the headers in CI on a fixed list of high-value URLs**, including error responses and flows served by other components.

### Node.js and Express

Helmet sets sensible defaults already (its default CSP includes `frame-ancestors 'self'`, `X-Frame-Options: SAMEORIGIN` and `Cross-Origin-Opener-Policy: same-origin`). Tighten them and mount Helmet **before** routers and `express.static`, so every response passes through it:

```javascript
import express from "express";
import helmet from "helmet";

const app = express();

const strictHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      frameAncestors: ["'none'"], // merged with Helmet's default directives
    },
  },
  xFrameOptions: { action: "deny" },
  crossOriginOpenerPolicy: { policy: "same-origin" },
});

// Narrow exception for routes that partners embed
const embeddableHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      frameAncestors: ["'self'", "https://example.org"],
    },
  },
  xFrameOptions: false, // XFO cannot express an allow-list; old browsers simply will not embed
  crossOriginOpenerPolicy: { policy: "same-origin" },
});

app.use((req, res, next) =>
  (req.path.startsWith("/embed/") ? embeddableHeaders : strictHeaders)(req, res, next),
);

app.use(express.static("public"));
// ... routers and error handlers after this point
```

Session cookie (express-session shown; the same attributes apply to any cookie library):

```javascript
import session from "express-session";

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true, httpOnly: true, sameSite: "lax" },
}));
```

### Django

`XFrameOptionsMiddleware` is enabled in new projects and `X_FRAME_OPTIONS` defaults to `"DENY"`; `SecurityMiddleware` sends `Cross-Origin-Opener-Policy` with `SECURE_CROSS_ORIGIN_OPENER_POLICY` (default `"same-origin"`). Django 6.0 added built-in CSP (`ContentSecurityPolicyMiddleware`, `SECURE_CSP`), which is where `frame-ancestors` goes:

```python
# settings.py (Django 6.0+)
from django.utils.csp import CSP

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django.middleware.csp.ContentSecurityPolicyMiddleware",
]

X_FRAME_OPTIONS = "DENY"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = True

SECURE_CSP = {
    "default-src": [CSP.SELF],
    "object-src": [CSP.NONE],
    "base-uri": [CSP.NONE],
    "frame-ancestors": [CSP.NONE],
}
```

A narrow exception for one view uses the decorators. `csp_override` replaces the whole policy rather than merging, so repeat the directives you still need:

```python
from django.utils.csp import CSP
from django.views.decorators.clickjacking import xframe_options_sameorigin
from django.views.decorators.csp import csp_override


@xframe_options_sameorigin  # old browsers without frame-ancestors support will refuse the partner: fails closed
@csp_override({
    "default-src": [CSP.SELF],
    "object-src": [CSP.NONE],
    "base-uri": [CSP.NONE],
    "frame-ancestors": [CSP.SELF, "https://example.org"],
})
def embedded_dashboard(request):
    ...
```

Avoid `xframe_options_exempt` except on views that are deliberately embeddable and carry no sensitive actions; grep for it in review. On Django versions before 6.0, the `django-csp` package provides the CSP middleware; its settings format changed between major versions, so follow the documentation for the version you install.

### Spring Security

Spring Security sends `X-Frame-Options: DENY` by default but adds no CSP and no COOP unless configured. Configure all three on the main filter chain:

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain appChain(HttpSecurity http) throws Exception {
        http
            // ... authorizeHttpRequests(...) rules
            .headers(headers -> headers
                .frameOptions(frame -> frame.deny())
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                    "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"))
                .crossOriginOpenerPolicy(coop -> coop.policy(CrossOriginOpenerPolicy.SAME_ORIGIN)));
        return http.build();
    }
}
```

An embeddable area gets its own, higher-priority chain instead of relaxing the global one (a common mistake is `frameOptions(frame -> frame.disable())` globally to make the H2 console or one dashboard work):

```java
    @Bean
    @Order(1)
    SecurityFilterChain embedChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/embed/**")
            // ... authorizeHttpRequests(...) rules for embeds
            .headers(headers -> headers
                .frameOptions(frame -> frame.disable())
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                    "default-src 'self'; object-src 'none'; base-uri 'none'; "
                    + "frame-ancestors 'self' https://example.org")));
        return http.build();
    }
```

(`@Order` is `org.springframework.core.annotation.Order`.) Headers are written only for requests that pass through a `SecurityFilterChain`. Paths excluded with a `WebSecurityCustomizer` (`web.ignoring()`) get no headers at all; Spring Security itself warns against ignoring paths and suggests `permitAll()` in a chain instead, and missing headers are one more reason to follow that advice.

### Laravel

Laravel ships `Illuminate\Http\Middleware\FrameGuard`, which only sets `X-Frame-Options: SAMEORIGIN`. Add a small middleware that sends `frame-ancestors` as its own CSP header (browsers enforce every CSP header they receive, so this does not interfere with a separate main policy), plus XFO and COOP:

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class FramingHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        $response->headers->set('Content-Security-Policy', "frame-ancestors 'none'", false); // add, do not replace
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Cross-Origin-Opener-Policy', 'same-origin');

        return $response;
    }
}
```

Register it globally in `bootstrap/app.php`:

```php
use App\Http\Middleware\FramingHeaders;
use Illuminate\Foundation\Configuration\Middleware;

->withMiddleware(function (Middleware $middleware): void {
    $middleware->append(FramingHeaders::class);
})
```

Keep `'same_site' => 'lax'` (the default) in `config/session.php`. Files served straight from `public/` by the web server never reach PHP; cover them at the web server as below.

### Web server and CDN layer

Whatever the framework does, set the headers once more where static files and error pages are produced. In nginx, use `always`, and remember that an `add_header` inside a `location` block discards the inherited ones (nginx 1.29.3 added `add_header_inherit` to change that):

```text
server {
    # ...
    add_header Content-Security-Policy "frame-ancestors 'none'" always;
    add_header X-Frame-Options "DENY" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;

    location /assets/ {
        # Any add_header here would drop the three above: repeat them if you add one.
    }
}
```

For SPAs served from object storage behind a CDN, set the headers in the CDN's response-header configuration; object storage itself usually cannot (see [Amazon S3 security](/cloud/aws-s3-security/) for the AWS case).

### Pages that must be embeddable

- Serve them from dedicated routes (or a dedicated host) with `frame-ancestors` listing exact HTTPS origins, never `*`, and review the list when partnerships end.
- Keep them free of sensitive one-click actions. If an embedded widget needs one, open a top-level window for it (`window.open` to a non-frameable page of yours, with `noopener` if you do not need the handle) and confirm there.
- Do not rely on the user's main session inside embeds when you can avoid it; a scoped, short-lived token for the widget limits what a stolen click can do.
- As defence in depth for pages that should never be framed, a server can refuse state-changing form submissions whose `Sec-Fetch-Dest` is `iframe`. It does not help with `fetch`-based actions (they report `empty`), so it complements the headers, never replaces them.

### Sensitive actions that survive a stolen click

Framing headers do not help against top-level timing attacks (DoubleClickjacking) or against same-site framers that your allow-list trusts. The controls that do:

- **Server-side transaction authorisation** for high-impact actions: re-authentication, a passkey or second-factor prompt, a typed confirmation of the amount or account, or an out-of-band confirmation. The OWASP cheat sheet's recommendation for DoubleClickjacking is this, not another confirmation button.
- **Consent screens that say clearly what is granted** (client identity, scopes, lifetime; ASVS `v5.0.0-10.7.2`) and step-up for broad scopes.
- **Supplementary gesture gating** on top-level approval buttons: ignore activations that arrive before the window has had focus for a short time. Keep it accessible (keyboard and assistive technology activation must still work, and the cheat sheet warns against requiring mouse movement). A sketch:

```javascript
// Supplementary only: ignore clicks that land right after this window gains focus.
let focusedSince = document.hasFocus() ? performance.now() : 0;
window.addEventListener("focus", () => { focusedSince = performance.now(); });
window.addEventListener("blur", () => { focusedSince = 0; });

for (const btn of document.querySelectorAll("button[data-sensitive]")) {
  btn.addEventListener("click", (event) => {
    if (!focusedSince || performance.now() - focusedSince < 500) {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
  }, { capture: true });
}
```

### Links and popups

Markup:

```html
<a href="https://example.org/docs" target="_blank" rel="noopener noreferrer">Partner documentation</a>
```

Scripts: always pass the features, and do not write code that needs the handle for third-party destinations:

```javascript
export function openExternal(url) {
  // Returns null by design; the new page cannot reach this one.
  window.open(url, "_blank", "noopener,noreferrer");
}
```

User-generated content: make the renderer or sanitiser add `rel` to every link it outputs, instead of trusting each template. With DOMPurify, a hook does it after sanitising:

```javascript
import DOMPurify from "dompurify";

DOMPurify.addHook("afterSanitizeAttributes", (node) => {
  if (node.tagName === "A" && node.hasAttribute("href")) {
    node.setAttribute("rel", "noopener noreferrer nofollow ugc");
  }
});
```

React: enable `react/jsx-no-target-blank` from eslint-plugin-react. For sanitiser choices and safe link rendering in general see [Reflected and stored XSS](/web/web-reflected-stored-xss/); links that redirect through your own site are covered in [Open redirects](/web/web-open-redirect/).

Headers: COOP `same-origin` on documents (Helmet and Django send it by default; configure it in Spring and Laravel as above). Use `same-origin-allow-popups` only on pages that need cross-origin popups, and keep `noopener` on their other outbound links.

### Regression tests

Write the checks as tests against the application, using the high-value URL list from test 1 plus an error route:

```javascript
// framing.test.js (Jest + supertest)
import request from "supertest";
import { app } from "../src/app.js";

const mustNotFrame = [
  "/account/security",
  "/account/delete",
  "/oauth/authorize?client_id=gt-test-client&response_type=code",
  "/admin/users",
  "/gt-does-not-exist",
];

describe("framing policy", () => {
  test.each(mustNotFrame)("%s refuses to be framed", async (path) => {
    const res = await request(app).get(path);
    expect(res.headers["content-security-policy"] || "").toMatch(/frame-ancestors\s+'none'/);
    expect(res.headers["x-frame-options"]).toBe("DENY");
    expect(res.headers["cross-origin-opener-policy"]).toBe("same-origin");
  });
});
```

```python
# tests/test_framing.py (Django)
from django.contrib.auth import get_user_model
from django.test import TestCase


class FramingHeadersTests(TestCase):
    paths = ["/account/security/", "/account/delete/", "/gt-does-not-exist/"]

    def setUp(self):
        self.client.force_login(get_user_model().objects.create_user("gt-user-a", password="unused-in-test"))

    def test_sensitive_pages_refuse_framing(self):
        for path in self.paths:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
                self.assertIn("frame-ancestors 'none'", response.headers.get("Content-Security-Policy", ""))
```

For behaviour rather than headers, a browser test frames a staging page and asserts nothing of it renders:

```javascript
// framing.spec.js (Playwright, against staging)
import { test, expect } from "@playwright/test";

test("security settings page cannot be framed", async ({ page }) => {
  await page.setContent('<iframe id="f" src="https://app.example.com/account/security"></iframe>');
  await page.waitForTimeout(2000);
  await expect(page.frameLocator("#f").getByRole("heading", { name: "Security settings" })).toHaveCount(0);
});
```

And for links: a unit test of the Markdown or rich-text renderer asserting that every `a` element it emits has `rel` containing `noopener`, and a Playwright test that clicks a seeded user link and asserts `window.opener === null` in the new page.

## Practice labs

Labs are where you can build the full overlay, decoy and all, because the "victim" is a simulated user. Keep the habit from this note anyway: show the frame at partial opacity first, so you know what you are aligning.

**PortSwigger Web Security Academy** (free; the exploit server hosts your page):

- [Basic clickjacking with CSRF token protection](https://portswigger.net/web-security/clickjacking/lab-basic-csrf-protected): frame the account page and steal the click on Delete account; shows why the CSRF token does not help (tests 1 and 3).
- [Clickjacking with form input data prefilled from a URL parameter](https://portswigger.net/web-security/clickjacking/lab-prefilled-form-input): the prefill variant from test 6.
- [Clickjacking with a frame buster script](https://portswigger.net/web-security/clickjacking/lab-frame-buster-script): the sandbox bypass from test 5.
- [Exploiting clickjacking vulnerability to trigger DOM-based XSS](https://portswigger.net/web-security/clickjacking/lab-exploiting-to-trigger-dom-based-xss): clickjacking as the delivery step for a click-dependent DOM XSS (the lab's goal is a `print()` call).
- [Multistep clickjacking](https://portswigger.net/web-security/clickjacking/lab-multistep): two decoys for an action with a confirmation step (test 6).
- All of them are listed under [clickjacking on the all-labs page](https://portswigger.net/web-security/all-labs#clickjacking).

**OWASP Juice Shop**: at the time of writing its challenge list has no clickjacking or reverse tabnabbing challenge, but a local instance is a convenient target for practising the header sweep in test 2 and the console snippet in test 8.

**Build a two-origin lab locally.** The quickest way to see the browser behaviour from [How it works](#how-it-works) for yourself: run a small app on `http://localhost:3000` with a login, a session cookie and one "danger" button, and serve the PoC pages from `http://127.0.0.1:8000`. The two hosts are different sites, so you can switch the cookie between `SameSite=None; Secure` (needs HTTPS, for example a local TLS proxy) and `Lax`, and the headers between none, `X-Frame-Options`, `ALLOW-FROM` and `frame-ancestors`, and watch what each browser does. Add a link that calls `window.open` without `noopener` and test 9's opener-check page to see reverse tabnabbing work and stop.

## Real-world cases

- **OAuth consent missing the headers the rest of the site had (Coinbase, 2015).** Coinbase's summary says the Authorize button on its OAuth authorisation page could be clickjacked because of a misconfiguration, and that the fix was to make OAuth-related responses carry the same security headers, including `X-Frame-Options`, as the rest of the site. The partial-coverage pattern from test 2, on the most valuable page in the flow. Reported June 2015, disclosed February 2016. [HackerOne report 65825](https://hackerone.com/reports/65825).
- **`ALLOW-FROM` that browsers ignore (X / Periscope, 2019).** Periscope subdomains sent `X-Frame-Options: ALLOW-FROM https://twitter.com/`, which several browsers did not support, so the pages could be framed; the reporter's impact scenario was a victim deactivating their own account through a framed click, and the suggested fix was `frame-ancestors` in CSP. Rated Medium with a USD 1,120 bounty shown on the report; disclosed July 2019. [HackerOne report 591432](https://hackerone.com/reports/591432).
- **A destructive one-click action rated Low (TikTok, 2021).** TikTok's summary describes a clickjacking flaw on a subdomain that could trick a user into deleting their Developer App. Rated Low with a USD 500 bounty shown; disclosed May 2022. A useful calibration point: programmes often rate even destructive clickjacking Low when it needs a convincing lure and affects one account at a time. [HackerOne report 1416612](https://hackerone.com/reports/1416612).
- **DoubleClickjacking on an OAuth consent flow (WakaTime, 2025).** The report applies the double-click pattern to WakaTime's OAuth authorisation page: a prompt window lines a "double click" button up with "Connect my WakaTime account", while the original tab navigates to the consent URL, so the second click authorises the attacker's OAuth app. The reporter notes that `X-Frame-Options` does not prevent it. Rated Medium, no bounty; disclosed August 2025. This is the top-level variant reviewed in test 7. [HackerOne report 3287060](https://hackerone.com/reports/3287060).
- **The research behind it (Paulos Yibelo, December 2024).** "DoubleClickjacking: A New Era of UI Redressing" describes the `mousedown`-then-click timing gap, the opener navigation, the targets (OAuth consent, one-click account settings, wallet and extension approvals) and a client-side mitigation that keeps critical buttons disabled until genuine user interaction; it also proposes a browser-level header. [Paulos Yibelo's write-up](https://www.paulosyibelo.com/2024/12/doubleclickjacking-what.html).
- **Reverse tabnabbing through a user-supplied link (HackerOne, 2021).** A link written into a report description opened from the HackerOne inbox with `window.opener` available, so the opened page could navigate the inbox tab, demonstrated by setting `window.opener.location` from the console. Rated Low with a USD 500 bounty shown; disclosed August 2021. The user-generated-link case from test 9. [HackerOne report 1145563](https://hackerone.com/reports/1145563).

More write-ups are collected in [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

Rate on what one or two plausible clicks achieve, for whom, and under what conditions. Severity moves with: the action (security settings, money, third-party access and admin functions at the top; cosmetic settings at the bottom), whether the framed page is authenticated in mainstream browsers with default settings (test 4), how much input the attacker must get the victim to supply, whether a server-side step (re-authentication, out-of-band confirmation) still stands in the way, and how many users the action can reach (an admin console versus a social action that spreads). Most clickjacking findings are **Low to Medium**. Go higher only when you have shown a sensitive one-click action working from a frame against your own test account.

**CVSS reasoning.** Clickjacking always needs the victim to visit the attacker's page and click, so `UI:R`. `AV:N`, and `PR:N` because the attacker needs no account on the target (the victim's session does the work). Scope is **Unchanged**: unlike XSS, nothing executes in the victim's browser on the application's behalf; the application itself carries out an action within its own authority, so the impact is scored on the application's data and functions. `AC:L` is the default; use `AC:H` where success depends on conditions outside the attacker's control, for example when only a minority of victims' browsers send the session cookie into a cross-site frame, or when a same-site foothold is required. Reverse tabnabbing is also Scope **Unchanged**, with low integrity impact: it only navigates the victim's tab, nothing runs in the application's origin, and the phishing page is the attacker's own site (the navigation-only convention in [Rating client-side findings](/web/web-client-side-testing-guide/#rating-client-side-findings)). The credential theft that may follow is a separate phishing step and is not part of the base score; describe it.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Missing or ineffective framing policy on pages without sensitive actions | Info | none | Nothing worth a stolen click; report as hardening against `v5.0.0-3.4.6` |
| Framing policy missing, but all authenticating cookies `Lax`/`Strict` and no same-site position | Info to Low | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N` (3.1) | Framed page loads logged out cross-site; Low if an unauthenticated harmful action exists |
| Low-impact one-click action clickjackable (follow, like, cosmetic setting) | Low to Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` (4.3) | Real but small integrity impact; the base score lands just inside Medium, and many programmes rate it Low |
| Sensitive one-click action shown working from a frame (disable MFA, delete account, revoke sessions, grant role) | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` (6.5) | Demonstrated against your own test account; `I:H` because security state or the account itself changes; use `AC:H` (5.3) if it works only in some browsers' defaults |
| Clickjacking that leads to account takeover (email change with prefill and no re-authentication or confirmation) | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (8.1) | Takeover via password reset to the new address; only when the whole chain is shown on your own accounts; `AC:H` (6.8) when browser conditions limit it |
| Frameable OAuth consent or account-linking page granting broad scopes | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N` (7.1) | The attacker's app gets read access to the victim's data and some write; scale C and I to the scopes |
| Top-level one-click consent or payment approval with no server-side step (DoubleClickjacking exposure, reviewed not exploited) | Low to Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N` (4.2) | Framing headers cannot help; `AC:H` reflects the timing and lure the attack needs; raise it if the client asks for and approves a demonstration |
| Admin action clickjackable (role change, user deletion) | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` (6.5) | The victim must be an administrator, which narrows targets but raises the value of each success |
| Reverse tabnabbing via user-supplied link opened with `window.open` or `rel="opener"` | Low | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N` (3.5) | Any registered user can plant the link, a victim must click it; navigation only, so Scope Unchanged; rated Low because the harm needs a further phishing step |
| `target="_blank"` without `rel` in current browsers; missing COOP | Info | none | Browsers already imply `noopener` for `_blank`; COOP is an L3 requirement (`v5.0.0-3.4.8`) |

When you report, give: the page and action, the browsers (with versions and default settings) in which the framed page was authenticated, the headers observed, screenshots at partial and full opacity from the local PoC, the request captured when you clicked the control yourself, and any server-side step that still applied. State that the proof used your own test account and that no lure was hosted.

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 |
|---|---|---|---|---|
| GT-WEB-CLICK-1 | WSTG-CLNT-09 | v5.0.0-3.4.6 (context), v5.0.0-7.5.1 | CWE-1021 | A06:2025 |
| GT-WEB-CLICK-2 | WSTG-CLNT-09 | v5.0.0-3.4.6 | CWE-1021 | A06:2025 (often reported under A02:2025 as a header misconfiguration) |
| GT-WEB-CLICK-3 | WSTG-CLNT-09 | v5.0.0-3.4.6 | CWE-1021 | A06:2025 |
| GT-WEB-CLICK-4 | WSTG-CLNT-09 | v5.0.0-3.3.2 | CWE-1021 | A06:2025 |
| GT-WEB-CLICK-5 | WSTG-CLNT-09 | v5.0.0-3.4.6 | CWE-1021 | A06:2025 |
| GT-WEB-CLICK-6 | WSTG-CLNT-09 | v5.0.0-3.4.6, v5.0.0-7.5.1 | CWE-1021 | A06:2025 |
| GT-WEB-CLICK-7 | WSTG-CLNT-09 (top-level variant) | v5.0.0-10.7.1, v5.0.0-10.7.2, v5.0.0-7.5.1 | CWE-1021, CWE-451 | A06:2025 |
| GT-WEB-CLICK-8 | WSTG-CLNT-14 | v5.0.0-3.4.8 | CWE-1022 | A06:2025 |
| GT-WEB-CLICK-9 | WSTG-CLNT-14 | v5.0.0-3.4.8 | CWE-1022 | A06:2025 |
| GT-WEB-CLICK-10 | WSTG-CLNT-14 | v5.0.0-3.4.8 | CWE-1022 | A06:2025 |

ASVS levels: `v5.0.0-3.4.6` L2 (`frame-ancestors` on every response so the application cannot be embedded by default; `X-Frame-Options` is obsolete and may not be relied upon), `v5.0.0-3.4.8` L3 (COOP `same-origin` or `same-origin-allow-popups` on document responses, against tabnabbing and frame counting), `v5.0.0-3.3.2` L2 (`SameSite` set per cookie purpose, naming UI redress), `v5.0.0-7.5.1` L2 (full re-authentication before changing email, phone, MFA or recovery data), `v5.0.0-10.7.1` L2 (the authorisation server ensures the user consents to each request) and `v5.0.0-10.7.2` L2 (clear consent information). CWE choice: CWE-1021 (*Improper Restriction of Rendered UI Layers or Frames*, base level, alternate terms clickjacking, UI redress and tapjacking) is the default for clickjacking; CWE-1022 (*Use of Web Link to Untrusted Target with window.opener Access*, variant level) for reverse tabnabbing. Both are marked as allowed for vulnerability mapping. CWE-451 (*User Interface (UI) Misrepresentation of Critical Information*) is a class-level entry whose mapping status is allowed with review; use it only as a secondary for top-level redressing where no framing is involved. The OWASP Top 10:2025 lists both CWE-1021 and CWE-1022 under `A06:2025` Insecure Design. Pure header gaps are commonly reported as security misconfiguration (`A02:2025`); that is a reasonable secondary label, but the Top 10's own CWE mapping puts these weaknesses in A06. The OWASP API Security Top 10 2023 has no category for these browser-UI weaknesses.

## References

**OWASP**

- WSTG: [Testing for Clickjacking (WSTG-CLNT-09)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/09-Clickjacking), [Testing for Reverse Tabnabbing (WSTG-CLNT-14)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/14-Reverse_Tabnabbing)
- ASVS 5.0: [V3 Web Frontend Security](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md), [V7 Session Management](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x16-V7-Session-Management.md), [V10 OAuth and OIDC](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x19-V10-OAuth-and-OIDC.md)
- [A06:2025 Insecure Design](https://top10.owasp.org/2025/A06_2025-Insecure_Design/), [A02:2025 Security Misconfiguration](https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/)
- Cheat Sheets: [Clickjacking Defense](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html), [HTML5 Security](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) (tabnabbing section), [Content Security Policy](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- Community pages: [Clickjacking](https://owasp.org/www-community/attacks/Clickjacking), [Reverse Tabnabbing](https://owasp.org/www-community/attacks/Reverse_Tabnabbing)

**CWE**

- [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html), [CWE-1022](https://cwe.mitre.org/data/definitions/1022.html), [CWE-451](https://cwe.mitre.org/data/definitions/451.html)

**Specifications and browser documentation**

- W3C [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/), section [Relation to X-Frame-Options](https://www.w3.org/TR/CSP3/#frame-ancestors-and-frame-options); WHATWG HTML, [checking a navigation response's adherence to X-Frame-Options](https://html.spec.whatwg.org/multipage/speculative-loading.html#check-a-navigation-response%27s-adherence-to-x-frame-options)
- MDN: [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options), [CSP frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors), [Content-Security-Policy-Report-Only](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy-Report-Only), [Cross-Origin-Opener-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy), [rel=noopener](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Attributes/rel/noopener), [Window.open()](https://developer.mozilla.org/en-US/docs/Web/API/Window/open), [Window.opener](https://developer.mozilla.org/en-US/docs/Web/API/Window/opener), [iframe (sandbox attribute)](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe), [Set-Cookie (SameSite)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie), [Third-party cookies](https://developer.mozilla.org/en-US/docs/Web/Privacy/Guides/Third-party_cookies)
- [Can I use: implicit noopener for target=_blank](https://caniuse.com/mdn-html_elements_a_implicit_noopener); Chrome: [CHIPS (partitioned cookies)](https://developer.chrome.com/docs/privacy-sandbox/chips/); web.dev: [Making your website cross-origin isolated using COOP and COEP](https://web.dev/articles/why-coop-coep)
- FIRST: [CVSS v3.1 User Guide](https://www.first.org/cvss/v3.1/user-guide) (Scope), [CVSS v3.1 Examples](https://www.first.org/cvss/v3.1/examples), [calculator](https://www.first.org/cvss/calculator/3.1)

**PortSwigger**

- [Clickjacking (UI redressing)](https://portswigger.net/web-security/clickjacking), [all clickjacking labs](https://portswigger.net/web-security/all-labs#clickjacking)
- Burp: [Clickbandit](https://portswigger.net/burp/documentation/desktop/tools/clickbandit), [Testing for clickjacking](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/testing-for-clickjacking), issue definition [Frameable response (potential Clickjacking)](https://portswigger.net/kb/issues/005009a0_frameable-response-potential-clickjacking)

**Research**

- Gustav Rydstedt, Elie Bursztein, Dan Boneh and Collin Jackson, [Busting Frame Busting: a Study of Clickjacking Vulnerabilities on Popular Sites](https://seclab.stanford.edu/websec/framebusting/framebust.pdf) (2010)
- Paul Stone, [Next Generation Clickjacking](https://media.blackhat.com/bh-eu-10/presentations/Stone/BlackHat-EU-2010-Stone-Next-Generation-Clickjacking-slides.pdf), Black Hat Europe 2010 (slides)
- Paulos Yibelo, [DoubleClickjacking: A New Era of UI Redressing](https://www.paulosyibelo.com/2024/12/doubleclickjacking-what.html) (December 2024)
- Mathias Bynens, [About rel=noopener](https://mathiasbynens.github.io/rel-noopener/)

**Framework and server documentation**

- Express: [Helmet](https://helmet.js.org/) ([GitHub](https://github.com/helmetjs/helmet)), [Production best practices: security](https://expressjs.com/en/advanced/best-practice-security.html)
- Django: [Clickjacking protection](https://docs.djangoproject.com/en/stable/ref/clickjacking/), [Content Security Policy](https://docs.djangoproject.com/en/stable/ref/csp/), [Middleware](https://docs.djangoproject.com/en/stable/ref/middleware/) (cross-origin opener policy), [Settings](https://docs.djangoproject.com/en/stable/ref/settings/)
- Spring Security: [Security HTTP response headers](https://docs.spring.io/spring-security/reference/features/exploits/headers.html), [servlet header configuration](https://docs.spring.io/spring-security/reference/servlet/exploits/headers.html)
- Laravel: [Middleware](https://laravel.com/docs/13.x/middleware)
- nginx: [ngx_http_headers_module (add_header)](https://nginx.org/en/docs/http/ngx_http_headers_module.html)

**Tools**

- OWASP ZAP alerts: [Anti-clickjacking Header (10020)](https://www.zaproxy.org/docs/alerts/10020/), [Reverse Tabnabbing (10108)](https://www.zaproxy.org/docs/alerts/10108/)
- [eslint-plugin-react: jsx-no-target-blank](https://github.com/jsx-eslint/eslint-plugin-react/blob/master/docs/rules/jsx-no-target-blank.md)
- [Playwright](https://playwright.dev/), [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)
