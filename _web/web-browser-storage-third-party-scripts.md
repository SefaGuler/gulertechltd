---
title: "Browser Storage, Client-Side Secrets and Third-Party Scripts"
date: 2026-11-15 22:16:00 +0000
subcategory: client-side
summary: "Testing browser storage, service worker caches, secrets and source maps in JS bundles, and third-party scripts, with SRI, CSP and logout fixes."
refs: [WSTG-CLNT-12, WSTG-INFO-05, WSTG-CONF-02, WSTG-ATHN-06, v5.0.0-14.3.1, v5.0.0-14.3.2, v5.0.0-14.3.3, v5.0.0-14.2.3, v5.0.0-3.6.1, v5.0.0-3.7.1, v5.0.0-13.3.1, "A01:2025", "A08:2025", "A03:2025", CWE-922, CWE-312, CWE-540, CWE-829, CWE-1104]
tags: [web, client-side, browser-storage, service-workers, secrets, supply-chain]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Client-Side](/web/web-client-side-testing-guide/). It covers what a web application leaves in the browser and what it lets into the page: tokens, personal data and feature flags in `localStorage`, `sessionStorage`, IndexedDB and Cache Storage; service workers that keep serving authenticated responses after logout; API keys, internal URLs and debug switches compiled into JavaScript bundles and exposed again through source maps; and third-party scripts (tag managers, analytics, chat widgets, CDN libraries) that run with the same privileges as your own code. WSTG covers browser storage as `WSTG-CLNT-12` and bundle and source-map review as part of `WSTG-INFO-05`; ASVS 5.0 adds client-side data protection (`v5.0.0-14.3.1` to `14.3.3`) and external resource integrity (`v5.0.0-3.6.1`). None of these are injection bugs on their own. They decide how bad an injection bug is, what a shared computer gives away, and whose code your users actually run. You get the model, twelve tests that stop at identification, how to tell a publishable key from a real secret, and fixes for Express, Django, Spring and Laravel plus the build tools (webpack, Vite, Next.js) where most of these problems start. Script injection itself is covered in [Reflected and stored XSS](/web/web-reflected-stored-xss/) and [DOM XSS](/web/web-dom-xss-client-side-injection/); policy design is in [Content Security Policy and security headers](/web/web-content-security-policy-headers/).

## Contents

- [How it works](#how-it-works)
  - [What the browser keeps for an origin](#what-the-browser-keeps-for-an-origin)
  - [Why XSS turns storage into theft](#why-xss-turns-storage-into-theft)
  - [Service workers and Cache Storage](#service-workers-and-cache-storage)
  - [What ships in a JavaScript bundle](#what-ships-in-a-javascript-bundle)
  - [Source maps](#source-maps)
  - [Third-party scripts run as you](#third-party-scripts-run-as-you)
  - [Data that leaves through URLs and Referer](#data-that-leaves-through-urls-and-referer)
- [What goes wrong](#what-goes-wrong)
  - [Bearer tokens in script-readable storage](#bearer-tokens-in-script-readable-storage)
  - [Personal and business data cached in the browser](#personal-and-business-data-cached-in-the-browser)
  - [Storage that outlives the session](#storage-that-outlives-the-session)
  - [Service workers that cache authenticated responses](#service-workers-that-cache-authenticated-responses)
  - [Secrets compiled into the bundle](#secrets-compiled-into-the-bundle)
  - [Public source maps](#public-source-maps)
  - [Debug flags, internal hosts and hidden routes](#debug-flags-internal-hosts-and-hidden-routes)
  - [Unreviewed third-party and tag-manager scripts](#unreviewed-third-party-and-tag-manager-scripts)
  - [External assets without integrity, or from an origin nobody controls](#external-assets-without-integrity-or-from-an-origin-nobody-controls)
  - [Sensitive data in URLs handed to third parties](#sensitive-data-in-urls-handed-to-third-parties)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [Signals and false positives](#signals-and-false-positives)
  - [GT-WEB-STOR-1: Inventory browser storage for each origin](#gt-web-stor-1-inventory-browser-storage-for-each-origin)
  - [GT-WEB-STOR-2: Session and refresh tokens in script-readable storage](#gt-web-stor-2-session-and-refresh-tokens-in-script-readable-storage)
  - [GT-WEB-STOR-3: Client data after logout, expiry and account switch](#gt-web-stor-3-client-data-after-logout-expiry-and-account-switch)
  - [GT-WEB-STOR-4: Service worker scope and cached authenticated responses](#gt-web-stor-4-service-worker-scope-and-cached-authenticated-responses)
  - [GT-WEB-STOR-5: Service worker updates, kill switch and unregistration](#gt-web-stor-5-service-worker-updates-kill-switch-and-unregistration)
  - [GT-WEB-STOR-6: Collect JavaScript bundles and find source maps](#gt-web-stor-6-collect-javascript-bundles-and-find-source-maps)
  - [GT-WEB-STOR-7: Scan bundles and source maps for secrets](#gt-web-stor-7-scan-bundles-and-source-maps-for-secrets)
  - [GT-WEB-STOR-8: Classify keys as publishable or secret](#gt-web-stor-8-classify-keys-as-publishable-or-secret)
  - [GT-WEB-STOR-9: Internal URLs, debug flags and hidden routes in client code](#gt-web-stor-9-internal-urls-debug-flags-and-hidden-routes-in-client-code)
  - [GT-WEB-STOR-10: Inventory third-party scripts and what they can reach](#gt-web-stor-10-inventory-third-party-scripts-and-what-they-can-reach)
  - [GT-WEB-STOR-11: SRI, pinned versions and dead origins for external assets](#gt-web-stor-11-sri-pinned-versions-and-dead-origins-for-external-assets)
  - [GT-WEB-STOR-12: Sensitive data sent to third parties in URLs, Referer and beacons](#gt-web-stor-12-sensitive-data-sent-to-third-parties-in-urls-referer-and-beacons)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Session tokens out of script reach](#session-tokens-out-of-script-reach)
  - [Keep client storage minimal and short-lived](#keep-client-storage-minimal-and-short-lived)
  - [Clear the browser on logout](#clear-the-browser-on-logout)
  - [Service workers that do not leak](#service-workers-that-do-not-leak)
  - [No secrets in bundles](#no-secrets-in-bundles)
  - [Source maps in production](#source-maps-in-production)
  - [Third-party scripts: SRI, CSP, self-hosting and governance](#third-party-scripts-sri-csp-self-hosting-and-governance)
  - [URLs and Referrer-Policy](#urls-and-referrer-policy)
  - [Regression checks in CI](#regression-checks-in-ci)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### What the browser keeps for an origin

Every storage mechanism below is scoped to an **origin** (scheme, host and port), not to a user and not to a session. The browser has no idea who is logged in; if two people share a browser profile, they share the storage. Whatever the application writes stays until the application deletes it, the user clears site data, or the browser evicts it under storage pressure.

| Mechanism | Scope | Lifetime | Readable by page JavaScript | What usually ends up there |
|---|---|---|---|---|
| `localStorage` | Origin | Until deleted (persists across restarts) | Yes, synchronously, strings only | Access and refresh tokens, user profile JSON, feature flags, "remember me" state, draft form data |
| `sessionStorage` | Origin **and** tab (top-level browsing context) | Until the tab closes; survives reloads; a duplicated tab gets a copy | Yes | Short-lived tokens, OAuth `state` and PKCE verifier, wizard state |
| IndexedDB | Origin | Until deleted | Yes, asynchronously, structured objects and `CryptoKey` objects | Offline copies of API data (messages, records, documents), sync queues, keys |
| Cache Storage (`caches`) | Origin | Until deleted; ignores HTTP caching headers | Yes, from windows and workers | Responses stored by a service worker or by page code: app shell, API responses, images, PDFs |
| HTTP cache, back/forward cache | Origin (partitioned by top-level site in modern browsers) | Governed by `Cache-Control` | No (but **Back** and the browser's cache viewer show it) | Rendered pages and API responses that lacked `no-store` |
| Cookies | Domain and path | Session or `Expires`/`Max-Age` | Yes, unless `HttpOnly` | Session identifiers, CSRF tokens, consent and analytics IDs |
| `window` globals, framework stores | Page | Until reload | Yes | Redux/Pinia/NgRx state, `window.__INITIAL_STATE__` with server-rendered data |

Two properties matter for testing. First, **nothing in this table is encrypted against the user of the machine**: a person with access to the browser profile (DevTools, the profile folder on disk, a forensic copy) reads it all in clear. Second, **everything except `HttpOnly` cookies is readable by any script running in the origin**, which is the subject of the next section. ASVS 5.0 turns this into two requirements: `v5.0.0-14.3.3` (L2) says browser storage should not hold sensitive data, with the exception of session tokens, and `v5.0.0-14.3.1` (L1) says authenticated data must be cleared from client storage when the session ends.

All major browsers now also **partition** storage for embedded third-party contexts (Chrome since 2023, Firefox and Safari earlier): an iframe from `widget.example.org` embedded on `app.example.com` gets storage keyed to that pairing, not the widget's global storage. That limits cross-site tracking. It does not protect first-party storage from scripts that run in the first-party page itself, which is where third-party script tags run.

### Why XSS turns storage into theft

An `HttpOnly` session cookie is attached to requests by the browser but cannot be read by JavaScript. An attacker with script execution in the page can still *use* it (send requests as the victim while the page is open), but cannot take it away. A bearer token in `localStorage` is different: any script that runs in the origin can read it and send it out of the page (a strict CSP narrows the routes, rarely all of them). The attacker then replays it from their own machine, from another country, for as long as the token stays valid, and the victim closing the tab changes nothing. A refresh token in the same place extends that to the refresh token's lifetime, which is often days or weeks. Data in IndexedDB (an offline copy of the user's inbox, a cached document set) can be read in bulk the same way.

So the location of a token does not create a vulnerability by itself, but it changes the **impact** of every script-injection bug in the origin, and of every third-party script that turns hostile. That is why we test and report it, and why the rating depends on whether an injection path exists. Public research on the trade-off: the OWASP [HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) recommends against session identifiers in local storage, and [RFC 10017, OAuth 2.0 for Browser-Based Applications](https://www.rfc-editor.org/rfc/rfc10017) (a Best Current Practice published in August 2026) describes the token-theft scenarios and why a backend-for-frontend keeps tokens out of the browser altogether. This note never demonstrates token theft; impact is explained in the report.

### Service workers and Cache Storage

A service worker is a script the page registers with `navigator.serviceWorker.register()`. Once installed, it sits between every page in its **scope** and the network: each request in scope fires a `fetch` event, and the worker decides whether to answer from Cache Storage, from the network, or with something it builds itself. Its default scope is the directory the worker script lives in (`/js/sw.js` controls `/js/` only); a broader scope needs the `Service-Worker-Allowed` response header on the worker script. Service workers only run on HTTPS (and `localhost`).

Three properties create findings:

- **The cache ignores HTTP caching rules.** MDN is explicit: the Cache API does not honour HTTP caching headers, and entries do not expire until deleted. A response the server marked `Cache-Control: no-store` can still be written to Cache Storage by a worker that calls `cache.put()` on everything.
- **The cache is per origin, not per user.** A worker that caches `/api/me` or `/api/messages` serves user A's data to whoever opens the app next on that profile, sometimes even before the new user logs in, and offline.
- **The worker outlives the deployment.** A registered worker keeps running until the browser fetches an updated script (the browser checks for a new script on navigations and other events, by default without using its HTTP cache for the main script), the new version installs and activates, or someone calls `unregister()`. A buggy worker that caches the wrong things, or a worker from a domain you no longer control, keeps controlling pages until a fix reaches every installed client.

### What ships in a JavaScript bundle

Modern front ends (React, Angular, Vue, Svelte, Next.js, Nuxt) are compiled by a bundler (webpack, Vite/Rollup, esbuild, Turbopack) into a few minified files plus lazily loaded chunks. Everything the client needs to run is in there, and so is everything a developer *put* in there by mistake:

- **Build-time environment variables.** Bundlers replace references such as `import.meta.env.VITE_X` or `process.env.NEXT_PUBLIC_X` with the literal value at build time. Vite and Next.js only inline variables with their public prefix (`VITE_`, `NEXT_PUBLIC_`), and both document that these values become part of the client bundle. The mistake is putting a secret under the public prefix, or a custom webpack `DefinePlugin` that injects the whole environment.
- **Configuration objects.** API base URLs for every environment, third-party keys, OAuth client IDs, feature-flag defaults, `debug: true`.
- **The route table.** Every client route, including admin screens hidden from ordinary users, lives in the router configuration of some chunk.
- **API clients.** Every endpoint, parameter name and request shape the UI knows about, including ones the UI no longer calls.

Minification renames local variables and strips whitespace. It does not hide string literals, object keys or URLs, so a minified bundle is still readable with a formatter (DevTools "pretty print") and a search.

### Source maps

A source map is a JSON file that maps positions in the minified bundle back to the original files, so stack traces and debugger breakpoints show the authored code. The bundle points to it with a trailing `//# sourceMappingURL=main.3f9c1a.js.map` comment or a `SourceMap` response header, and DevTools fetches it when it is open. The interesting fields are `sources` (original file paths, often with the developer's home directory and the monorepo layout) and `sourcesContent` (the **full original source**, comments included). With `sourcesContent` present, tools rebuild the whole front-end source tree. Without it, you get the file list only.

Production builds do not need public source maps: error-tracking services accept uploaded maps privately. webpack's `devtool` defaults to no source map in production mode, Vite's `build.sourcemap` defaults to `false`, and Next.js disables browser source maps in production unless `productionBrowserSourceMaps` is set. Public maps in production are therefore a deliberate setting, a copied configuration, or an older toolchain's default (Create React App emitted them unless `GENERATE_SOURCEMAP=false` was set). WSTG-INFO-05 asks you to look for them, and WSTG-CONF-02 lists them as a platform misconfiguration.

### Third-party scripts run as you

A `script` element with a `src` on another host does not run "in the vendor's origin". It runs in **yours**, with full access to the DOM, to `localStorage`, `sessionStorage` and IndexedDB, to non-`HttpOnly` cookies, to every form field as the user types, and to `fetch()` with the user's cookies attached. The same-origin policy protects you from other origins' pages, not from code you invited in. Whoever can change that file can do anything your own code can do: the vendor, an attacker who compromises the vendor, or whoever buys the vendor's domain.

Tag managers multiply this. A Google Tag Manager or similar container is a script whose contents are edited in a web console, usually by marketing, outside code review and outside the deployment pipeline. Custom HTML tags inject arbitrary script into every page the container runs on. Chat widgets, A/B testing tools and session-replay scripts are designed to read the page.

Three controls exist, each with limits:

- **Subresource Integrity (SRI).** An `integrity="sha384-…"` attribute on a `script` (or a stylesheet, preload or modulepreload `link`) makes the browser refuse the file if its hash differs. Cross-origin SRI requires CORS: the element needs `crossorigin="anonymous"` and the CDN must send `Access-Control-Allow-Origin`. SRI only works for **static, versioned** files. A tag-manager container, an analytics loader or a chat widget that the vendor updates continuously changes hash daily, and those loaders then inject further scripts that carry no integrity attribute at all.
- **Content Security Policy.** `script-src` limits which origins may supply scripts and `connect-src` limits where scripts may send data. CSP cannot tell a well-behaved allowed script from a compromised one, and an allow-list that contains a large CDN or the tag manager's whole domain allows a lot. See [Content Security Policy and security headers](/web/web-content-security-policy-headers/).
- **Isolation.** A widget loaded in a cross-origin `iframe` (ideally with `sandbox`) runs in the vendor's origin, and the same-origin policy now protects your page from it. Self-hosting a reviewed copy removes the vendor from the runtime path entirely.

### Data that leaves through URLs and Referer

URLs are copied to more places than any other part of a request: browser history, server and proxy logs, analytics hits (which record `document.location` by default), error trackers, and the `Referer` header of every sub-resource and outgoing link. Browsers now default to `strict-origin-when-cross-origin`, which sends only the origin to other sites, but an application can weaken that with a `Referrer-Policy` header or a `referrerpolicy` attribute, and third-party scripts read the full URL directly from the page anyway. A password-reset token, an email address or a search term in a query string ends up with every analytics, advertising and session-replay vendor on the page. ASVS `v5.0.0-14.2.1` (L1) keeps sensitive data out of URLs, `v5.0.0-14.2.3` (L2) keeps it away from untrusted parties such as trackers, and `v5.0.0-3.4.5` (L2) requires a referrer policy.

## What goes wrong

### Bearer tokens in script-readable storage

The single most common observation. An SPA receives an access token (often a JWT) and a refresh token from the login or token endpoint and keeps both in `localStorage` so the user stays logged in across tabs and restarts. It matters because any script in the origin can read them (see [Why XSS turns storage into theft](#why-xss-turns-storage-into-theft)), they keep working from another machine, and the refresh token turns a one-off script execution into weeks of access. Look at the login response, the Application panel in DevTools, and the code that sets the `Authorization` header (search the bundle for `localStorage.setItem`, `Authorization`, `Bearer`, `refresh_token`). Also check auth SDKs: several OAuth and identity libraries store tokens in `localStorage` when configured for "persistent" or "local" caching; the setting is in the client configuration object.

### Personal and business data cached in the browser

Apps keep whole API responses on the client for speed or offline use: the user's profile with date of birth and address, order history, patient records, chat transcripts, a cached list of the user's colleagues. Some keep data the user should not see at all (the full API response including fields the UI hides, which is an [excessive data exposure](/web/web-mass-assignment-bopla/) problem showing up in storage). It matters on shared and lost devices, and as bulk loot for injected script. Look in IndexedDB (offline-first apps, messaging, PWAs), in Redux/NgRx persistence keys in `localStorage` (`persist:root` is the redux-persist default), and in Cache Storage. `CryptoKey` objects in IndexedDB are a special case: WSTG-CLNT-12 suggests checking whether keys that should be non-extractable were stored as `extractable: true`, which lets script export the raw key material.

### Storage that outlives the session

Logout calls the server, the server invalidates the session, the UI shows the login page, and `localStorage` still holds the profile, the cached messages and sometimes the tokens. Expiry is worse: when a session times out server-side, no logout code runs at all, so nothing is cleared unless the app checks on next load. Account switching on the same device has the same shape: user B logs in and the app briefly renders user A's cached data before the fresh request returns. On a shared or kiosk computer (libraries, hotel business centres, family laptops, hot desks), the next person gets the previous user's data from storage or from the **Back** button.

Two separate questions keep the finding precise. Is the *data* still on the device (a client-side storage issue, `v5.0.0-14.3.1`)? And do the *tokens* still work against the server (a revocation issue, `v5.0.0-7.4.1`)? The second one is covered in [Revocation, sharing and asynchronous access](/web/web-access-control-revocation-sharing-async/); test it whenever you find a token that survives logout.

### Service workers that cache authenticated responses

Workbox and hand-written workers often start with a "cache everything, serve stale while revalidating" strategy. Applied to the app shell and static assets that is fine. Applied to `/api/*`, or to server-rendered HTML pages that contain the user's name and data, it stores authenticated responses in Cache Storage, which is shared by every user of that browser profile, ignores `no-store`, and survives logout. Look at the worker script (Application panel, "Service workers", or the `register()` call in the bundle), its `fetch` handler, and the routes registered with caching strategies. Also look for workers whose scope is broader than they need (`Service-Worker-Allowed: /` on a worker that only serves an offline page), because a worker controls every page in its scope.

### Secrets compiled into the bundle

Server-side credentials that ended up in client code: a payment provider's secret key used to "simplify" a refund screen, a cloud access key for direct uploads, an email or SMS provider key, a database connection string in a forgotten config object, an internal API's static bearer token, a signing secret used to create JWTs client-side, credentials for a test account. Any visitor can read them, so the only question is what they unlock. Typical causes are the public-prefix mistake (`VITE_STRIPE_SECRET`, `NEXT_PUBLIC_API_SECRET`), a `.env` file bundled by a misconfigured plugin, and a "temporary" hard-coded value in a utility module. Look in every bundle and chunk, not just `main.js`: lazy-loaded admin chunks are where test credentials hide. ASVS `v5.0.0-13.3.1` (L2) says secrets must not be included in source code or build artifacts; CWE-540 and CWE-798 describe the weakness.

### Public source maps

The original source is published next to the minified bundle. On its own that is information disclosure: it speeds up an attacker's review, reveals comments ("TODO: remove admin bypass before launch"), file paths, internal package names and the full API surface. It becomes a real finding when the source contains secrets, internal hostnames or logic that should not be public, which is common because developers treat source as private. A related variant: maps stripped from production but still served from a staging host, or the build directory published wholesale with `.map` files included.

### Debug flags, internal hosts and hidden routes

Client configuration often includes switches the server also honours: `debug=true` query parameters that make the API return stack traces, a `X-Debug` header the front end adds when a flag is set, a `featureFlags` object whose defaults enable unreleased features if you edit `localStorage`. Internal hostnames (`api.internal.example.com`, `10.20.0.15`, staging and QA URLs) reveal infrastructure and sometimes point at environments with weaker controls. Hidden admin routes in the router are not a vulnerability by themselves (the server must enforce access anyway), but they are the work list for [authorization bypass testing](/web/web-authorization-bypass-techniques/) and [function-level authorization](/web/web-vertical-privilege-escalation-bfla/). WSTG-CONF-15 covers feature-flag bypass in its own right.

### Unreviewed third-party and tag-manager scripts

The application team knows about the libraries in `package.json`. It often does not know what the tag-manager container loads this week, which scripts the chat widget pulls in, or that the analytics snippet sits on the payment page. Every one of those runs with full access to that page. The ICO's penalty notice to Ticketmaster UK (2020) is the reference case: a third-party chatbot's JavaScript, hosted by the vendor and placed on the payment page, was modified by an attacker to skim card data; the ICO found that the risk of third-party scripts on payment pages was well known and that no risk assessment had been done (see [Real-world cases](#real-world-cases)). Look for scripts on the login, registration, password-reset, account-settings and payment pages, where the DOM holds the most valuable data.

### External assets without integrity, or from an origin nobody controls

A library loaded from a public CDN without `integrity` runs whatever that URL serves tomorrow. An unpinned URL (`/npm/library@latest/…`, `/lib/library.min.js` without a version) changes under you even without an attack. A domain that changes ownership is the worst case: in June 2024 the `cdn.polyfill.io` domain, sold earlier that year, started serving code that redirected some mobile visitors to sports-betting sites, on a domain embedded by more than 100,000 sites according to Sansec. SRI would have blocked the modified file on sites that pinned a hash; most sites could not, because the service generated a different polyfill per browser. Also look for references to domains that no longer resolve or have expired: anyone who registers them gets script execution on your pages. Outdated libraries with known client-side flaws (old jQuery, AngularJS, Bootstrap, Lodash) belong here too (CWE-1104, CWE-1395).

### Sensitive data in URLs handed to third parties

Password-reset and magic-link tokens, email addresses, names, phone numbers, search terms, internal record IDs and sometimes session identifiers in query strings or path segments, on pages that load analytics, advertising pixels, session replay or chat. The vendor receives the full URL in its page-view event regardless of `Referrer-Policy`, because its script reads `location.href`. A weakened referrer policy (`unsafe-url`, `no-referrer-when-downgrade`) additionally sends it to every linked site and image host. Under UK GDPR this is a disclosure of personal data to a third party the privacy notice may not mention; for reset tokens it is also a credential leak to every vendor on the page.

## Testing

Everything below assumes an **authorised** engagement with written scope and rules of engagement, a bug bounty programme whose rules allow this kind of testing, or a deliberately vulnerable lab. Requests, responses and console output in this note are **illustrative**: hosts are fictional and outputs are shortened.

### Before you start

**Agree the scope in writing.** Most tests here are passive (you read what the application already sends you), but a few touch things the client should know about:

| Item | What to agree |
|---|---|
| Targets | Hosts in scope, including the static asset and CDN hosts that serve the bundles, and whether staging builds are in scope (they often still ship source maps) |
| Accounts | At least two test accounts (user A, user B) per role, plus an admin account if the client provides one. All storage and logout tests run on these accounts only |
| Devices | A dedicated browser profile for the engagement (or a fresh profile per test run), so storage you inspect is yours and nothing else |
| Secrets policy | What happens when you find a live secret: our default is **stop at identification, do not use it, report it for rotation the same day** (see below) |
| Third parties | Third-party script hosts are **not** in scope as targets. You record what the page loads; you do not test the vendor's infrastructure |
| Domains | If a referenced domain is unregistered or expired, you report it; you do not register it. The client re-registers or removes the reference |

**Browser setup.** Use Chrome or Edge DevTools (Application panel: Local storage, Session storage, IndexedDB, Cache storage, Service workers, Storage → "Clear site data") and Firefox's Storage Inspector as a second opinion. Route the browser through Burp with Logger on, so every bundle and every third-party request is recorded. Turn on "Preserve log" in the Network panel when testing logout, and tick "Update on reload" in the Service workers pane only when you want to bypass the worker (otherwise you test the worker, not the server).

**Evidence hygiene.** You are inspecting your own session, which means tokens and session cookies appear in everything you capture. The console snippets in this note print **key names, types and lengths, not values**. Redact tokens in screenshots, sanitise HAR files before you attach them (strip `Cookie`, `Set-Cookie` and `Authorization` headers), and log out of every test session at the end so the tokens in your evidence are dead.

**If you find a live secret.** A secret in a bundle or source map (a payment provider secret key, a cloud access key, an SMS or email provider key, a database password, a static API token) is a finding the moment you can read it. Do not use it: no test API call to "confirm it works", no listing what it can access, no logging in with hard-coded credentials, unless the client has given explicit written permission for that specific check. Record where it is (URL, file, line or offset), the type of credential, the first and last four characters, and a SHA-256 of the value so the client can match it; keep the full value out of your notes and report. Tell the client the same day so they can rotate it, because anyone else can read the same file. Secret scanners that "verify" findings do so by calling the provider's API with the secret, which is using it; run them with verification switched off (see [GT-WEB-STOR-7](#gt-web-stor-7-scan-bundles-and-source-maps-for-secrets)).

**Stop on real data.** If storage, Cache Storage or a service worker on your test device shows data that belongs to a real user (for example on a shared test machine the client lent you, or a cached response that is not from your accounts), stop, keep only minimal redacted evidence (key name, a masked field), do not copy or retain more, and report it immediately. The same applies to real personal data inside a source map or bundle (customer records used as test fixtures).

**Rate limits.** Bundle collection is a handful of GET requests per page. Download only the files the application references (or that the source-map comments reference), at a low rate, and do not brute-force paths beyond appending `.map` to known file names.

**Payloads.** None are needed. This note never injects script. Where a test asks "what could an injected script do with this?", the answer goes into the report as prose.

### Signals and false positives

| Observation | Often a false positive when | How to tell |
|---|---|---|
| Token in `localStorage` | It is an ID token used only for display, an anti-CSRF token, or a short-lived token for a public API | Decode it locally (it is base64, not encrypted) and check `aud`, `scope` and `exp`; replay it against an authenticated endpoint from Repeater with your own account |
| Data left after logout | It is non-personal (theme, language, consent choice, tour completed) | Classify every key you find; only authenticated or personal data counts against `v5.0.0-14.3.1` |
| "API key" in bundle | It is publishable by design (Stripe `pk_`, Firebase web config, Sentry DSN, reCAPTCHA site key, Algolia search-only key) | Classify it with [GT-WEB-STOR-8](#gt-web-stor-8-classify-keys-as-publishable-or-secret); report publishable keys only when restrictions are missing and the client confirms it |
| High-entropy string flagged by a scanner | It is a hash, a nonce, a webpack chunk ID, a base64 image, an SRI hash or a public certificate | Look at the context: variable name, how the code uses it, which request it ends up in |
| Source map found | It is a CSS map, a map without `sourcesContent`, or the code is open source anyway | Check `sourcesContent`; severity follows what the source contains |
| Third-party script without SRI | It is a dynamic loader (tag manager, analytics) where SRI cannot work, and the client has documented the decision | `v5.0.0-3.6.1` (L3) allows a documented security decision instead of SRI; ask for it |
| Cached authenticated page | The browser's back/forward cache restored the page from memory without a request | Reload, then check Network: a `(ServiceWorker)` or `(disk cache)` entry is the finding; bfcache restoration on **Back** is a `Cache-Control` question for WSTG-ATHN-06 |
| Internal hostname in bundle | It is a public hostname with "internal" in the name, or a localhost default for development | Resolve it from outside (DNS only, no requests to internal ranges); note whether it is a private address |

### GT-WEB-STOR-1: Inventory browser storage for each origin

*Guler Tech methodology.* Implements the enumeration step of WSTG-CLNT-12 (localStorage, sessionStorage, IndexedDB, cookies and global window state), extended to Cache Storage.

#### What it checks

What the application writes to the browser, for which origin, at which point in the user journey, and how sensitive each item is. The output is the classification table that tests 2 to 5 work from.

#### Prerequisites

A fresh browser profile; test accounts for each role; the list of origins the application uses (`app.example.com`, `admin.example.com`, the login host if separate). Storage is per origin, so inventory each one.

#### Steps

1. Start from an empty profile. Open the application, log in as user A, and walk the main features: dashboard, profile, messages, documents, settings, any offline or "save for later" feature, and the payment flow if in scope.
2. In DevTools, open Application and look at Local storage, Session storage, IndexedDB, Cache storage, Cookies and Service workers for each origin listed under "Frames".
3. Run the snippet below in the console of each origin. It prints key names, value types and lengths, and flags values that look like JWTs or contain an `@`, without printing the values themselves.
4. For anything flagged, open the entry in the Application panel and classify it by hand. Decode JWT-shaped values locally (they are base64url) to see claims such as `exp`, `scope` and `aud`; do not paste them into online decoders.
5. Repeat for user B and for a privileged role. Note which keys differ: those are user-specific.
6. Check the global `window` state for server-rendered data (`__INITIAL_STATE__`, `__NEXT_DATA__`, `__NUXT__`) and for framework stores persisted to storage (`persist:root`).

```javascript
// Run in your own DevTools console, on your own test session. Prints metadata only.
(async () => {
  const looksJwt = v => /^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*$/.test(v);
  const hints = v => [looksJwt(v) && "jwt-shaped", /@/.test(v) && "contains @", v.length > 500 && "large"].filter(Boolean).join(", ");
  for (const [name, store] of [["localStorage", localStorage], ["sessionStorage", sessionStorage]]) {
    for (let i = 0; i < store.length; i++) {
      const k = store.key(i), v = store.getItem(k) || "";
      console.log(`[${name}] ${k}  len=${v.length}  ${hints(v)}`);
    }
  }
  if (indexedDB.databases) {
    for (const { name } of await indexedDB.databases()) {
      const db = await new Promise((ok, ko) => { const r = indexedDB.open(name); r.onsuccess = () => ok(r.result); r.onerror = ko; });
      for (const s of db.objectStoreNames) {
        const count = await new Promise(ok => { const r = db.transaction(s).objectStore(s).count(); r.onsuccess = () => ok(r.result); });
        console.log(`[IndexedDB] ${name}/${s}  records=${count}`);
      }
      db.close();
    }
  }
  for (const c of await caches.keys()) {
    const reqs = await (await caches.open(c)).keys();
    console.log(`[CacheStorage] ${c}  entries=${reqs.length}`);
    reqs.slice(0, 20).forEach(r => console.log(`    ${r.method} ${new URL(r.url).pathname}`));
  }
  console.log(`[cookies visible to script] ${document.cookie.split(";").map(c => c.split("=")[0].trim()).filter(Boolean).join(", ")}`);
})();
```

Opening an IndexedDB database without a version, as above, does not change its schema. Firefox's `indexedDB.databases()` support arrived later than Chrome's; if it is missing, use the Storage Inspector.

#### Observation

An inventory like this (illustrative):

| Origin | Mechanism | Key / store | Content | Class | Survives logout? (test 3) |
|---|---|---|---|---|---|
| `app.example.com` | localStorage | `auth` | JSON with `access_token` (JWT, 60 min) and `refresh_token` (opaque) | Credential | |
| `app.example.com` | localStorage | `persist:root` | Redux state: user profile with name, email, phone, address | Personal data | |
| `app.example.com` | localStorage | `ff_overrides` | `{"newBilling":false,"adminTools":false}` | Feature flags (test 9) | |
| `app.example.com` | IndexedDB | `offline/messages` | 1,240 message records | Personal data | |
| `app.example.com` | CacheStorage | `api-v3` | `GET /api/me`, `GET /api/messages?page=1` | Authenticated responses (test 4) | |
| `app.example.com` | sessionStorage | `pkce_verifier` | Random string | Transient OAuth state | |
| `app.example.com` | localStorage | `theme` | `dark` | Non-sensitive | |

#### Evaluation

No finding by itself; this is the work list. Note immediately anything outside the expected set: passwords, full card numbers, government identifiers, health data, or another user's data. Those are findings against `v5.0.0-14.3.3` (L2, no sensitive data in browser storage except session tokens) without further tests, rated by sensitivity. An extractable `CryptoKey` for a key that only needs to sign or decrypt locally is a Low finding (CWE-922) with a note on what the key protects.

#### False positives

Data the user typed and the app keeps as a draft (a half-written message) is personal but expected; it still needs clearing on logout. Third-party keys under your origin (analytics IDs, consent records) are written by vendor scripts; record them for test 10.

#### Automation

The snippet above runs unchanged in Playwright or Puppeteer via `page.evaluate()`, so the inventory can be captured in CI after a scripted login. An assertion that fails when an unexpected key appears (an allow-list of known keys) catches new storage use in pull requests.

### GT-WEB-STOR-2: Session and refresh tokens in script-readable storage

*Guler Tech methodology.* Implements the token checks in WSTG-CLNT-12 (security implications: authentication tokens in localStorage or sessionStorage), with the token-replay check borrowed from session testing.

#### What it checks

Whether the credentials that authenticate the user to the API are readable by JavaScript in the origin, how long they live, and whether they can be replayed from another client. This is the factor that decides whether a script-injection bug in the origin is a session-riding bug or an account takeover.

#### Prerequisites

The inventory from test 1; Burp with Repeater; test account A.

#### Steps

1. Log in and capture the login (or token) response in Burp. Note where each credential is delivered: `Set-Cookie` (check the `HttpOnly` flag), JSON body, URL fragment, or `postMessage` from an identity provider iframe.
2. Find where the client keeps it: `localStorage`, `sessionStorage`, IndexedDB, a non-`HttpOnly` cookie, or JavaScript memory only (gone after reload).
3. Note how authenticated requests carry it: `Authorization: Bearer <TOKEN_USER_A>`, a custom header, or the browser's cookie jar.
4. For each token, decode the claims locally and record lifetime (`exp` minus `iat`) and scope. For opaque refresh tokens, observe the refresh request and how long it keeps working (ask the client for the configured lifetime rather than waiting).
5. Replay check: copy the access token into a Repeater request to an authenticated endpoint such as `GET /api/me` with no cookies. A `200` with user A's data shows the token is a portable bearer credential.
6. Check whether the refresh token rotates (a new one per refresh, with the old one rejected) by replaying a used refresh token once in Repeater against your own account.
7. Search the bundle for the storage calls (`localStorage.setItem(`, `setItem("token"`, `refresh_token`) to confirm where the token is written, and the auth library's configuration (`cacheLocation`, `storage`, `persistence`) to see whether it is a setting.

```http
GET /api/me HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
Accept: application/json
```

```bash
curl -s https://api.example.com/api/me -H "Authorization: Bearer <TOKEN_USER_A>" | jq '{id, email}'
```

#### Observation

Vulnerable pattern (illustrative): the token endpoint returns both tokens in JSON, the SPA writes them to `localStorage.auth`, the access token lives 60 minutes, the refresh token 30 days and does not rotate, and Repeater replays both from a clean client. Preferred pattern: the session lives in an `HttpOnly` cookie set by a backend-for-frontend (BFF) and the browser never sees an API token, or the access token stays in memory only, lives minutes, and the refresh token is in an `HttpOnly` cookie scoped to the refresh path.

#### Evaluation

- **Report** access or refresh tokens in `localStorage`, `sessionStorage`, IndexedDB or a non-`HttpOnly` cookie as a defence-in-depth weakness (CWE-922). Rate it **Low** when no script-injection path is known, and say so; ASVS `v5.0.0-14.3.3` itself tolerates session tokens in browser storage, while `v5.0.0-3.3.4` (L2) requires `HttpOnly` for session cookies and `v5.0.0-10.1.1` (L2) prefers a BFF so OAuth tokens never reach the browser. Raise it when the refresh token is long-lived and non-rotating.
- **Rate it with the injection bug** when you found one (stored or DOM XSS, a hostile third party in test 10): the injection finding's impact becomes token theft and persistent account takeover, not just actions during the victim's visit. Explain this in prose; do not demonstrate it.
- **Pass:** session credentials are `HttpOnly` cookies (cookie attributes are covered in the Session Management note), or tokens live in memory only with short lifetimes and rotation.

#### False positives

ID tokens kept only to display the user's name (they should still not authenticate API calls; check). Anti-CSRF tokens. Tokens for public, unauthenticated APIs. Tokens that the server binds to the client (DPoP, mTLS), which fail the replay in step 5; record that as a mitigating control.

#### Automation

Burp's Logger filter on responses containing `access_token` or `refresh_token` finds the issuing endpoints. In CI, a Playwright test after login can assert that no storage value matches a JWT pattern and that the session cookie has `httpOnly: true` in `context.cookies()`.

### GT-WEB-STOR-3: Client data after logout, expiry and account switch

*Guler Tech methodology.* Implements the WSTG-CLNT-12 check that storage entries are cleared after logout or session expiration, together with WSTG-SESS-06 (logout) and WSTG-ATHN-06 (browser cache and history) for the shared-computer case.

#### What it checks

Whether authenticated data and credentials stay on the device after the session ends, in three situations: explicit logout, server-side expiry, and a second user logging in on the same profile. Covers ASVS `v5.0.0-14.3.1` (L1) and `v5.0.0-14.3.2` (L2).

#### Prerequisites

Test 1 inventory for user A; test account B; Network panel with "Preserve log" on.

#### Steps

1. **Logout.** Log in as A, use the features that populate storage, then log out through the UI. Watch the logout response in Network: is there a `Clear-Site-Data` header, and which directives does it carry? Rerun the test 1 snippet and compare.
2. **Closed tab without logout.** Log in as A, close the tab (not the browser), reopen the application URL. Does it open logged in? Close the browser entirely and repeat; `localStorage` survives, `sessionStorage` does not.
3. **Expiry.** Ask the client for the idle and absolute timeouts, or a test configuration with short ones. Let the session expire, reload, and check whether the app clears storage when it discovers the expired session, or leaves it.
4. **Account switch.** With A's data still present (from step 2 or 3), log in as B. Watch the first render: does any of A's data appear before B's arrives? After B's session is up, is any of A's data still in storage or Cache Storage?
5. **Back button and cache.** After logout, press **Back** and reload pages that showed personal data. Check the responses for `Cache-Control: no-store` (`v5.0.0-14.3.2`).
6. **Do the tokens still work?** If any token survived, replay it in Repeater against `GET /api/me`. A `200` means the server did not revoke the session either; continue with the tests in [Revocation, sharing and asynchronous access](/web/web-access-control-revocation-sharing-async/).

```http
POST /auth/logout HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>

HTTP/1.1 204 No Content
Set-Cookie: session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax
Clear-Site-Data: "cache", "cookies", "storage"
Cache-Control: no-store
```

#### Observation

A before-and-after table (illustrative):

| Item | Before logout | After logout | After B logs in |
|---|---|---|---|
| `localStorage.auth` (tokens) | present | **present** | replaced |
| `localStorage.persist:root` (A's profile) | present | **present** | **A's data until first API response** |
| IndexedDB `offline/messages` | 1,240 records | **1,240 records** | **1,240 of A's records + B's** |
| CacheStorage `api-v3` | 2 entries | **2 entries** | **served to B offline** |
| Logout response | | `204`, no `Clear-Site-Data` | |

#### Evaluation

- **Fail** when authenticated or personal data remains in any client store after logout or after the app has noticed expiry, or when user B can see user A's data on the same profile. That is `v5.0.0-14.3.1` (L1) and CWE-922; if a credential survives *and* still works server-side, add the revocation finding (`v5.0.0-7.4.1`, L1).
- **Fail** for `v5.0.0-14.3.2` when pages or API responses with personal data lack `Cache-Control: no-store` and are shown from cache after logout.
- **Pass** when logout returns `Clear-Site-Data` (or the client clears all stores itself) and the next load starts empty, and when the app clears storage on detecting an expired session. ASVS notes the client should also clean up when the server is unreachable at logout; check that logout still clears storage with the network offline (DevTools "Offline").

#### False positives

Non-personal preferences (language, theme, cookie-consent choice). Data the user explicitly chose to keep on a trusted device ("keep me signed in on this device"), if the choice is opt-in and documented; still note it for shared computers. A browser that ignores `Clear-Site-Data` directives it does not support: check the MDN compatibility table for the client's supported browsers before blaming the application.

#### Automation

A Playwright test: log in, populate, log out, then assert that `localStorage.length === 0` (or only allow-listed keys remain), that `indexedDB.databases()` returns none of the app's databases, that `caches.keys()` is empty, and that `navigator.serviceWorker.getRegistrations()` returns none if the app unregisters on logout. See [Regression checks in CI](#regression-checks-in-ci).

### GT-WEB-STOR-4: Service worker scope and cached authenticated responses

*Guler Tech methodology.* Extends WSTG-CLNT-12 to Cache Storage and service workers; WSTG treats the browser cache separately under WSTG-ATHN-06, and this test covers the cache that HTTP headers do not control.

#### What it checks

Whether a service worker is registered, what it controls, and whether it stores authenticated responses (API data, personalised HTML) in Cache Storage where they outlive the session and are served to the next user of the profile.

#### Prerequisites

Test accounts A and B; DevTools Application → Service workers and Cache storage; the worker script (download it from its `scriptURL`; it is a normal JavaScript file).

#### Steps

1. List registrations from the console: scope, script URL and state. Compare the scope with what the worker needs (an offline page under `/offline/` does not need scope `/`). If the scope is broader than the script's directory, find the `Service-Worker-Allowed` header on the script response.
2. Read the worker's `fetch` handler. Look for which requests it caches (`cache.put`, `cache.addAll`, Workbox `registerRoute` with `CacheFirst`, `StaleWhileRevalidate` or `NetworkFirst` strategies) and whether `/api/` routes, HTML navigations or authenticated downloads are included.
3. Log in as A and use the app. List Cache Storage entries (the test 1 snippet prints request paths). Open entries for API paths in the Application panel and check whether the stored response contains A's data.
4. Check whether caching respects the server's intent: an API response with `Cache-Control: no-store` that also appears in Cache Storage shows the worker ignores it.
5. Log out, switch DevTools Network to "Offline", and reload the app and a few authenticated routes. Then log in as B (online) and repeat. Note anything rendered from the cache that belongs to A.
6. In Network, entries served by the worker are labelled `(ServiceWorker)` in the Size column; use that to tell worker responses from network ones.

```javascript
// Your own DevTools console: list service worker registrations and cache names.
(async () => {
  for (const r of await navigator.serviceWorker.getRegistrations()) {
    const w = r.active || r.waiting || r.installing;
    console.log(`scope=${r.scope}  script=${w && w.scriptURL}  state=${w && w.state}`);
  }
  console.log("caches:", await caches.keys());
})();
```

#### Observation

Illustrative: the worker at `/sw.js` has scope `/`, uses `StaleWhileRevalidate` for every same-origin `GET`, and Cache Storage `runtime-v3` holds `/api/me`, `/api/messages?page=1` and `/account/statements/2026-10.pdf`. After logout and offline reload, the dashboard renders A's name and messages; after B logs in, B's first dashboard load briefly shows A's messages.

#### Evaluation

- **Fail** when authenticated responses are cached by the worker and remain after logout (`v5.0.0-14.3.1`), and more so when they are served to another user on the same profile (CWE-524 for cached sensitive data; CWE-922 as the storage class). Rate by data sensitivity and by how likely shared devices are for this user base.
- **Fail** (Low) when the scope is broader than the worker needs and the worker handles requests it has no reason to see, because a later bug or a compromised worker script then affects every page.
- **Pass** when the worker caches only static, versioned assets and an offline page, passes `/api/` and authenticated navigations straight to the network, and logout clears its caches.

#### False positives

Precached app-shell files (`index.html` with no user data, versioned JS and CSS) are expected. Responses that are personalised only by public data (a localised homepage). A response served from the HTTP cache (`(disk cache)`) rather than the worker is a `Cache-Control` issue for test 3.

#### Automation

Scanners do not see this, because the cached responses only exist inside a logged-in browser. Use a Playwright test that logs in, logs out, and asserts that no Cache Storage entry matches `/api/` or an authenticated route. In code review, flag any Workbox route whose matcher includes API paths without a `NetworkOnly` strategy.

### GT-WEB-STOR-5: Service worker updates, kill switch and unregistration

*Guler Tech methodology.* Extends WSTG-CLNT-12 to the service worker lifecycle; checks the clean-up side of ASVS `v5.0.0-14.3.1`.

#### What it checks

Whether the application can remove or replace a worker it no longer wants (a bug, a leak, a compromised script), and whether logout and account deletion remove the worker and its caches. A worker that cannot be retired keeps serving whatever it cached.

#### Prerequisites

Test 4 results; access to the client's deployment documentation or a short call with the front-end team; a staging environment where you may observe a worker update.

#### Steps

1. Check how the worker script is served: its `Cache-Control` (by default, `updateViaCache: 'imports'`, browsers bypass their HTTP cache for the main worker script during update checks, but imported scripts can come from the cache for up to 24 hours, a registration with `updateViaCache: 'all'` brings the cache back for the main script, and a CDN in front can still serve a stale copy), and whether `importScripts()` pulls code from another origin.
2. Ask, or read in the bundle, how updates are handled: does the new worker call `skipWaiting()` and `clients.claim()`, or wait until all tabs close? Is there a "new version available, reload" prompt?
3. Ask whether a **kill switch** exists: a replacement worker that deletes all caches and unregisters itself, ready to deploy at the same script URL. If the worker is served from a URL the team would struggle to deploy to (a CDN host, a third-party domain), note it.
4. Check logout: after logging out (test 3), are registrations still listed? Does the logout response include `Clear-Site-Data: "storage"` (which unregisters service workers) or does the client call `unregister()` and `caches.delete()`?
5. Check whether the worker script itself comes from your origin. A worker registered from a third-party or vendor-controlled path (some push-notification and A/B testing products ship one) puts that vendor between your pages and the network.

#### Observation

Illustrative: the worker script is served with `Cache-Control: max-age=31536000` from the CDN, imports `https://push.vendor.example.org/sw-lib.js`, has no kill-switch plan, and stays registered after logout.

#### Evaluation

- **Fail** (Low to Medium) when the worker stays registered and its caches remain after logout; this is part of the test 3 finding, reported once.
- **Fail** (Medium) when the worker imports code from a third-party origin (`importScripts` from another host): that code controls every request in scope, which is the third-party script risk of test 10 with more reach. Rate higher when scope is `/` and the app handles payments or credentials.
- **Observation** (Info) when no kill-switch or update plan exists; recommend one.
- **Pass** when the worker is first-party, revalidated on each deploy (`Cache-Control: no-cache` on the script), logout unregisters it or clears its caches, and the team can ship a self-destructing worker.

#### False positives

A long `max-age` on the main worker script matters mainly for CDN and intermediary caches, because browsers bypass their own HTTP cache for it by default; report it only when it actually delays updates in your observation.

#### Automation

A CI check that the deployed worker script is served with `no-cache` (or a short `max-age`), contains no `importScripts` with an absolute URL to another host, and that the logout end-to-end test finds zero registrations.

### GT-WEB-STOR-6: Collect JavaScript bundles and find source maps

*Guler Tech methodology.* Implements the "gather JavaScript files" and "identify source map files" steps of WSTG-INFO-05, the source-map check in WSTG-APIT-03, and the production-build check in WSTG-CONF-02.

#### What it checks

That you have every JavaScript file the application ships (including lazy-loaded chunks and admin-only chunks), and whether original source is published through source maps.

#### Prerequisites

A full walk-through in Burp for each role (chunks for admin screens load only when an admin opens them); a new, empty working directory for downloaded files.

#### Steps

1. Export the script URLs from Burp: Target → Site map, filter by MIME type "script", select the in-scope hosts, right-click → Copy URLs. Add chunk URLs listed in the build manifest if the app exposes one (`/asset-manifest.json`, `/_next/static/<build-id>/_buildManifest.js`, Vite's `manifest.json` if served).
2. Download them into the new directory. Downloaded files are untrusted data: you read them, you never run them or open them as HTML.
3. For each file, look for a `sourceMappingURL` comment at the end, a `SourceMap` or `X-SourceMap` response header, and request `<file>.map` once. Treat a `200` with JSON content (`"version":3`) as a hit; a `200` with the app's HTML (SPA fallback routing) is not.
4. For each map, check whether `sourcesContent` is present and non-empty, and list the `sources` paths.
5. If maps include source, rebuild the tree with **sourcemapper** into a separate output directory, or browse it in DevTools Sources (the "Authored" group shows original files). Repeat on staging hosts if they are in scope; they often build with maps.

```bash
# url-list.txt: one in-scope script URL per line, from Burp
mkdir -p ~/engagement/bundles && cd ~/engagement/bundles
while read -r u; do
  f=$(echo "$u" | sed 's#https\?://##; s#[/?&=]#_#g')
  curl -s --max-time 20 -o "$f" "$u"
  tail -c 300 "$f" | grep -o 'sourceMappingURL=[^ ]*' | sed "s#^#$u -> #"
  code=$(curl -s -o "$f.map" -w '%{http_code}' --max-time 20 "$u.map")
  if [ "$code" = 200 ] && head -c 200 "$f.map" | grep -q '"version"'; then
    echo "MAP $u.map  sourcesContent=$(jq 'has("sourcesContent")' "$f.map")  sources=$(jq '.sources|length' "$f.map")"
  else rm -f "$f.map"; fi
  sleep 1
done < url-list.txt
```

```bash
# Rebuild original sources from one map (sourcemapper, Go)
sourcemapper -output ~/engagement/src-main -url https://app.example.com/assets/main.3f9c1a.js.map
```

```http
GET /assets/main.3f9c1a.js.map HTTP/1.1
Host: app.example.com

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=31536000

{"version":3,"file":"main.3f9c1a.js","sources":["webpack://portal/./src/api/client.ts","webpack://portal/./src/admin/RefundPanel.tsx", "..."],"sourcesContent":["import axios from 'axios';\n// TODO remove staging fallback\n..."],"names":["..."],"mappings":"AAAA,..."}
```

#### Observation

A list of bundles and chunks with their sizes, and a list of maps: URL, whether `sourcesContent` is present, number of sources, and notable paths (`/home/<dev>/`, `src/admin/`, `packages/internal-*`).

#### Evaluation

- **Fail** (Low, CWE-540) when production serves source maps with `sourcesContent` to anonymous users and the client did not intend it; note `v5.0.0-13.4.2` (L2, debug features disabled in production). Raise the severity to whatever the source reveals: a secret found in the source is rated as a secret (test 7), not as a source map.
- **Info** for maps without `sourcesContent` (file list only) and for maps on non-production hosts, unless they contain secrets.
- **Pass** when production has no public maps (none referenced, `.map` returns `404` or `403`), or maps are restricted to an authenticated error-tracking service.

#### False positives

SPA hosting that answers every path with `index.html` and `200`: check the body. CSS source maps (usually harmless). Open-source front ends whose code is public anyway: report Info at most.

#### Automation

The loop above is the automation; keep it rate-limited. Burp's passive scanner and several BApp extensions flag `sourceMappingURL` comments. In CI, fail the build if the production artefact directory contains `*.map` files or bundles end with a `sourceMappingURL` comment (see [Regression checks in CI](#regression-checks-in-ci)).

### GT-WEB-STOR-7: Scan bundles and source maps for secrets

*Guler Tech methodology.* Implements the "review JavaScript for API keys, internal IP addresses, sensitive routes or credentials" step of WSTG-INFO-05, with secret scanners run on the files collected in test 6.

#### What it checks

Whether any credential, key, token or password is present in client-delivered code: bundles, chunks, inline scripts, server-rendered configuration (`__NEXT_DATA__`, `window.__CONFIG__`), source maps and their `sourcesContent`, and the service worker script.

#### Prerequisites

The bundle directory from test 6, and the rebuilt source tree if maps were public; the inline scripts of the main pages (save the HTML of each page as a file in the same directory); **gitleaks** and **TruffleHog** installed; **jsluice** optional.

#### Steps

1. Run gitleaks over the directory with redaction on, so values do not land in your terminal history or report.
2. Run TruffleHog over the same directory **with verification disabled**. TruffleHog's verification calls the provider's API with each candidate secret to see whether it works; against a client's secret that is using the credential, which this methodology does not do without written approval.
3. Run `jsluice secrets` for JavaScript-aware matches (it parses string literals and object keys instead of grepping lines).
4. Grep for what scanners miss: variable and key names (`secret`, `password`, `passwd`, `private`, `apiKey`, `token`, `auth`, `credential`, `connectionString`), basic-auth URLs (`https://user:pass@`), PEM headers, and `Authorization` headers built from constants.
5. For each hit, open the file at the offset and read the surrounding code. Decide what the value is used for (which request, which header, which SDK call); that, not the regex name, decides the finding.
6. Classify each confirmed credential with test 8, then apply the live-secret rule from [Before you start](#before-you-start): record location, type, first and last four characters and a hash; report for rotation immediately; do not use it.

```bash
cd ~/engagement
gitleaks dir bundles --redact --report-format json --report-path gitleaks-bundles.json
gitleaks dir src-main --redact --report-format json --report-path gitleaks-src.json

# Detection only: no calls to provider APIs
trufflehog filesystem bundles src-main --no-verification --json > trufflehog.jsonl

jsluice secrets bundles/*.js > jsluice-secrets.jsonl

grep -RIniE '(secret|passw(or)?d|private[_-]?key|api[_-]?key|client[_-]?secret|connection[_-]?string)["'"'"' ]*[:=]' bundles src-main | cut -c1-200
grep -RIlE -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' bundles src-main
grep -RIoE 'https?://[^/"'"'"' :]+:[^/"'"'"' @]+@[^/"'"'"' ]+' bundles src-main
```

```bash
# Summarise findings without printing values: rule, file, line
jq -r '.[] | "\(.RuleID)\t\(.File):\(.StartLine)"' gitleaks-bundles.json | sort | uniq -c
jq -r '"\(.DetectorName)\t\(.SourceMetadata.Data.Filesystem.file)"' trufflehog.jsonl | sort | uniq -c
```

#### Observation

Illustrative, with values redacted as they would be in a report:

| File | Offset | What | Used for | Class (test 8) |
|---|---|---|---|---|
| `assets/admin-refunds.8d2e.js` | line 1, col 48,211 | Payment provider key, prefix `sk_live_`, last four `…Q7f2` | `Authorization` header on `https://api.payments.example.net/v1/refunds` | **Secret, live** |
| `assets/main.3f9c1a.js` | line 1, col 2,040 | Payment provider key, prefix `pk_live_` | Client SDK initialisation | Publishable |
| `src-main/src/config/staging.ts` | line 14 | Basic-auth credentials in a staging API URL | Fallback when `API_URL` unset | Secret (staging); ask whether it is valid in production |
| `index.html` | inline `__CONFIG__` | Error-tracking DSN | SDK initialisation | Public by design |

#### Evaluation

- **Fail** for any secret that grants access to a server-side system: rate by what the client confirms it can do (see [Rating findings](#rating-findings)); a live payment-provider secret key or a cloud key with write access is Critical. CWE-798 (hard-coded credentials, mapping allowed with review) or CWE-540 (sensitive information in source code); ASVS `v5.0.0-13.3.1` (L2).
- **Fail** (lower) for test credentials, staging keys and keys the client says are revoked: confirm revocation with the client rather than by trying them, and report anyway, because "revoked" keys in public code are often still valid.
- **Pass** when only publishable identifiers remain and test 8 confirms their restrictions.

#### False positives

SRI hashes, webpack chunk hashes, base64-encoded images and fonts, public keys (JWKS, certificate pinning sets), CSP nonces in saved HTML (they are per response), random IDs used as analytics client IDs, and example values in library code (SDK documentation strings with placeholder keys). Scanner rules named after a vendor match the format only.

#### Automation

Run gitleaks on the build output in CI (see [Regression checks in CI](#regression-checks-in-ci)); it is fast and does not call external services. Keep an allow-list file for the publishable keys you have classified, so the scan fails only on new findings.

### GT-WEB-STOR-8: Classify keys as publishable or secret

*Guler Tech methodology.* Implements the WSTG-INFO-05 step "when an API key is found, check whether restrictions are set", without using the key.

#### What it checks

For every key, token or identifier found in client code, whether it is **designed to be public** (it identifies the application and is safe only if the provider enforces restrictions), or **a secret** (it authorises actions by itself). The answer decides between "no finding", "configuration finding for the client to check" and "Critical, rotate now".

#### Prerequisites

The findings from test 7; vendor documentation for each key type; a contact at the client who can look at the provider consoles.

#### Steps

1. Identify the provider and key type from the prefix, the SDK call it is passed to, and the request host it is sent to.
2. Look it up in the table below or in the provider's documentation. Providers state explicitly which keys are safe in front-end code.
3. For publishable keys, the security depends on server-side settings you cannot see without using the key: API restrictions, HTTP referrer or app restrictions, Security Rules, App Check, allowed origins. **Do not probe them with the key.** List the key IDs (last four characters) and ask the client to confirm the restrictions in the provider console. Observe only what the application itself does with the key.
4. For anything that is a secret by the provider's definition, apply the live-secret rule.
5. Check for **publishable keys that have become secrets**: Truffle Security's February 2026 research showed that Google API keys embedded for Maps or Firebase could call the Gemini API once the Generative Language API was enabled in the same Google Cloud project, because new keys default to unrestricted. A key that was fine to publish in 2024 may not be today; ask the client whether the project has the Generative Language API (or other billable APIs) enabled and whether the key is restricted.

| Seen in client code | Provider's position | What to report |
|---|---|---|
| Stripe publishable key (`pk_live_…`, `pk_test_…`) | Safe to expose; can create tokens and PaymentMethods, cannot charge or read account data | Nothing, unless the server trusts amounts or prices from the client (a business-logic issue) |
| Stripe secret (`sk_…`) or restricted (`rk_…`) key | Not safe to expose | Critical (live) or High (test mode, depending on what test data holds); rotate |
| Firebase web config (`apiKey`, `authDomain`, `projectId`, `appId`) | Public by design; data is protected by Security Rules and App Check, not by the key | Nothing for the config itself; recommend a separate test of Firestore, Realtime Database and Storage rules, and ask the client to confirm the key's API restrictions |
| Google API key (prefix `AIza`) used for Maps, Places or similar | Public only if restricted by API and by referrer or app | Medium when the client confirms it is unrestricted or allows billable APIs; High when the Generative Language API is reachable with it |
| Gemini Developer API key | Must never be in client code | High to Critical; rotate |
| Sentry DSN | Safe to keep public: allows submitting events only | Nothing; mention spam-event risk only if relevant |
| reCAPTCHA or Turnstile site key | Public by design; the secret key is server-side | Nothing for the site key; secret key in the bundle is High |
| Algolia search-only key | Safe in front-end code; prefer secured, restricted keys | Low if it is a plain search key over indices with private data; Admin API key in the bundle is Critical |
| OAuth / OIDC `client_id` | Public identifier | Nothing; a `client_secret` in a browser app is a finding (public clients should not have one) |
| Cognito identity pool ID, user pool client ID | Public identifiers; access depends on the IAM roles behind them | Nothing by itself; see [AWS Cognito security](/cloud/aws-cognito-security/) for testing the unauthenticated role |
| AWS access key ID with secret access key | Secret | Critical; rotate; see the client's cloud IAM review |
| Static bearer token for the application's own API | Secret | High to Critical depending on its privileges |

#### Observation

The classification column added to the test 7 table, plus a list of questions for the client ("please confirm API restrictions on key ending …8KxQ; is the Generative Language API enabled in that project?").

#### Evaluation

- **Fail** for secrets (as in test 7).
- **Fail** for publishable keys only when the client confirms missing restrictions or when the application itself shows the gap (for example the app calls a billable API directly from the browser with a key that is also used server-side). Rate by cost exposure and data reachable.
- **No finding** for publishable keys used as designed. Write them up as "reviewed, publishable by design" so the client knows they were checked.

#### False positives

This test exists to remove them. The common one is reporting a Firebase or Stripe publishable key as a "leaked API key": it is not, and programmes close such reports as informative.

#### Automation

Keep a per-client classification file (key type, last four, decision, date, who confirmed) and feed it to the CI secret scan as an allow-list, so a publishable key is not re-reported and a new secret is.

### GT-WEB-STOR-9: Internal URLs, debug flags and hidden routes in client code

*Guler Tech methodology.* Implements the "sensitive routes" and runtime-configuration review in WSTG-INFO-05, and feeds WSTG-CONF-15 (feature-flag bypass) and the access-control tests.

#### What it checks

What the client code tells you about the server: endpoints and parameters the UI no longer uses, admin routes, internal and non-production hostnames, debug switches and feature flags that the server honours.

#### Prerequisites

Bundles and rebuilt sources from test 6; **jsluice** or **LinkFinder** for URL extraction; the storage inventory from test 1 (flag overrides often live in `localStorage`).

#### Steps

1. Extract URLs and paths from every bundle and chunk. Separate them into: in-scope API endpoints, other environments (staging, QA, dev), internal hosts and private IP ranges, and third parties.
2. Diff the API endpoints against the ones you saw in Burp during the walk-through. Endpoints in code that the UI never called are the leads: old API versions, admin endpoints, export and debug endpoints.
3. Read the router configuration for routes guarded only on the client (`canActivate`, route `meta: { requiresAdmin: true }`, conditional rendering on `user.role`). Each one is a server-side authorization check to test with a low-privilege account in [authorization bypass testing](/web/web-authorization-bypass-techniques/).
4. Find flag and debug handling: query parameters (`?debug=1`, `?_mock=true`), headers the client adds when a flag is set (`X-Debug`, `X-Feature-*`), and flag overrides read from storage or cookies. Toggle them with your own account, one at a time, and compare server responses (more fields, stack traces, unreleased features reachable).
5. For internal hostnames, resolve them with DNS only. Do not send requests to private ranges or to hosts outside scope.

```bash
jsluice urls bundles/*.js | jq -r '.url' | sort -u > urls-from-js.txt
grep -E '^https?://' urls-from-js.txt | awk -F/ '{print $3}' | sort | uniq -c | sort -rn
grep -E '(staging|stage|qa|dev|test|internal|local)\.' urls-from-js.txt
grep -RhoE '\b(10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+)\b' bundles | sort -u
grep -RhoE '[?&](debug|test|mock|preview|internal|admin)[A-Za-z_]*=' bundles | sort | uniq -c
```

#### Observation

Illustrative: the admin chunk references `POST /api/v1/admin/users/{id}/impersonate`; the main bundle sets `X-Debug: 1` when `localStorage.debug === "true"`, and with that header the API adds `stack` and `sql` fields to error responses; `https://api.staging.example.com` and `10.20.0.15` appear in a config object.

#### Evaluation

- **Fail** when a client-side switch changes server behaviour in a way an ordinary user should not control (verbose errors, debug data, unreleased or paid features): report as a server-side issue (CWE-489 active debug code, or a feature-flag bypass under WSTG-CONF-15), rated by what it exposes.
- **Fail** (Low or Info) for internal hostnames and private IPs in production code, rated by what they reveal; Info when the hosts are not reachable and reveal nothing sensitive.
- Hidden routes and unused endpoints are **not findings by themselves**; they become findings only if the server-side test shows missing authorization.

#### False positives

Default development values (`http://localhost:3000`) left in a config fallback. Feature flags that only change UI and whose server-side counterpart is enforced. Third-party SDK internals that contain their own staging URLs.

#### Automation

The extraction commands above are repeatable per release; diffing `urls-from-js.txt` between releases highlights new endpoints for regression testing. LinkFinder and xnLinkFinder do similar extraction; the Burp extension JS Link Finder adds it passively.

### GT-WEB-STOR-10: Inventory third-party scripts and what they can reach

*Guler Tech methodology.* There is no dedicated WSTG test for third-party script governance; this test supports ASVS `v5.0.0-3.6.1` (L3) and `v5.0.0-14.2.3` (L2), and uses the JavaScript-gathering step of WSTG-INFO-05 and the CSP review of WSTG-CONF-12.

#### What it checks

Every script that runs in the application's origin but is controlled by someone else: CDN libraries, tag managers and everything they load, analytics, advertising, session replay, A/B testing, chat and support widgets, consent managers, payment and fraud scripts. For each: where it runs, who controls its content, and what it can reach on that page.

#### Prerequisites

A logged-in walk-through in Burp covering the sensitive pages (login, registration, password reset, MFA, account settings, payment); consent accepted **and** rejected (consent managers change what loads); a HAR export from DevTools for each sensitive page, sanitised.

#### Steps

1. From Burp or the HAR, list every script request whose host is not first-party, per page. Include scripts injected after load (tag managers inject further tags seconds later; scroll and wait).
2. For each host, record who operates it, whether the URL is versioned, whether the element has `integrity` (test 11), and which pages load it.
3. For tag managers, ask the client for an export or a read-only view of the container: which tags fire on which pages, and whether **Custom HTML** tags exist. Those are arbitrary script maintained outside code review.
4. For each script on a sensitive page, note what it can reach there: form fields (passwords, card numbers, MFA codes), personal data in the DOM, script-readable tokens from test 2, and the ability to send requests with the user's cookies.
5. Compare with what isolation exists: is the payment form in a provider-hosted iframe (good, the provider's script runs in its own origin) or are card fields in your DOM? Is the chat widget an iframe from the vendor's origin or a script injected into your page?
6. Check the CSP (`script-src`, `connect-src`): does it constrain where scripts come from and where data can go, or does it allow-list whole CDNs and `https:`? Details are in [Content Security Policy and security headers](/web/web-content-security-policy-headers/).

```bash
# Third-party script hosts per page from a sanitised HAR (first-party: *.example.com)
jq -r '.log.entries[]
  | select((.response.content.mimeType // "") | test("javascript|ecmascript"))
  | .request.url' payment-page.har \
  | awk -F/ '{print $3}' | grep -vE '(^|\.)example\.com$' | sort | uniq -c | sort -rn
```

#### Observation

An inventory table (illustrative):

| Script host | Operator | Loaded on | Versioned | SRI | Can read on that page |
|---|---|---|---|---|---|
| `www.googletagmanager.com` | Tag manager | All pages incl. `/checkout` | No (container) | Not possible | Everything in the DOM, card fields (in our DOM), `localStorage.auth` |
| `cdn.chat-vendor.example.net` | Chat widget | All pages | No | No | Everything, plus its own iframe |
| `cdn.jsdelivr.net/npm/chart.js@4.4.1` | Public CDN | Dashboard | Yes | **No** | Dashboard data |
| `js.payments.example.net` | Payment provider | `/checkout` | Provider-managed | Not offered | Provider iframe; card fields are in the iframe |

#### Evaluation

- **Fail** (Medium to High) when third-party scripts that are not needed for the function run on pages that handle credentials or payment data in the first-party DOM, without a documented risk assessment. Rate by the data on the page and how many vendors are involved. CWE-829 and CWE-830; `A08:2025`. This is the ICO's point in the Ticketmaster notice: the chatbot was not needed to take a payment.
- **Fail** (Medium) when a tag manager with Custom HTML tags runs on sensitive pages and container changes bypass review.
- **Fail** (Low to Medium) for script-readable tokens or personal data on pages that load several third parties; combine with test 2 rather than reporting twice.
- **Pass** when sensitive pages load only the scripts they need, payment and credential capture happen in provider-hosted iframes or first-party code, and remaining third parties are documented, reviewed and constrained by CSP.

#### False positives

Scripts that load only after consent and only on marketing pages. A payment provider's own script on the checkout page (required, and the card fields are normally in its iframe). Fonts and images from CDNs (no script execution, although they leak the visit to the CDN).

#### Automation

Script inventory is easy to automate: a Playwright crawl of the sensitive pages that records every script URL and fails when a new third-party host appears. Commercial client-side monitoring products do this continuously. For payment pages, PCI DSS v4.0.1 requirements 6.4.3 (an authorised, justified, integrity-checked inventory of payment-page scripts) and 11.6.1 (detection of unauthorised changes to scripts and security-impacting headers) became mandatory on 31 March 2025, when the future-dated v4.0 requirements took effect; if the client is in PCI scope, this test produces evidence for both.

### GT-WEB-STOR-11: SRI, pinned versions and dead origins for external assets

*Guler Tech methodology.* Implements ASVS `v5.0.0-3.6.1` (L3) and checks `v5.0.0-15.2.1` (L1) for client-side components; uses WSTG-INFO-05 for collection and WSTG-CONF-12 for the CSP side.

#### What it checks

For every script and stylesheet loaded from another origin: whether it is static and versioned, whether it carries a correct `integrity` hash with `crossorigin`, whether its origin is still controlled by the expected party, and whether the library version is supported and free of known client-side vulnerabilities (CWE-1104, CWE-1395).

#### Prerequisites

The inventory from test 10; saved HTML of the pages; the downloaded files from test 6; `openssl`; **Retire.js** (CLI or the Burp extension).

#### Steps

1. List the external `script` and `link` elements in each page's HTML with their `src`/`href`, `integrity` and `crossorigin` attributes. Include elements created dynamically (inspect the live DOM in DevTools Elements, not just the HTML source).
2. For each element **with** `integrity`: download the file and compute its hash; it must match. Check that `crossorigin="anonymous"` is present (without it a cross-origin SRI request fails) and that the URL pins an exact version.
3. For each element **without** `integrity`: is the asset static and versioned (then SRI is possible and missing) or dynamic (then ask for the documented decision `v5.0.0-3.6.1` allows)?
4. Check each external origin's status passively: does the domain resolve, has it recently changed registrar or name servers, is it a known compromised or retired service (the `polyfill.io` case)? Use DNS and public WHOIS/RDAP data only. **If a domain is unregistered or expired, report it; do not register it.**
5. Run Retire.js over the downloaded files and look up version banners (`/*! jQuery v1.12.4`) against advisories. Note unsupported major versions (AngularJS 1.x long-term support ended on 31 December 2021).
6. Check for obsolete client technologies covered by `v5.0.0-3.7.1` (L2): Flash, Java applets, Silverlight or ActiveX objects. Rare now, but legacy admin portals still embed them.

```bash
# Check an SRI hash (compare with the integrity attribute; prefix "sha384-")
curl -s https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js | openssl dgst -sha384 -binary | openssl base64 -A; echo

# Elements from saved HTML: external scripts and whether they carry integrity
grep -oE '<script[^>]+src="https?://[^"]+"[^>]*>' pages/*.html | sed -E 's/^([^:]+):.*src="([^"]+)".*/\1 \2/' | sort -u
grep -oE '<script[^>]+src="https?://[^"]+"[^>]*>' pages/*.html | grep -vc 'integrity='

# Known-vulnerable library versions in downloaded bundles (run from inside the bundle directory)
cd ~/engagement/bundles && retire --outputformat json --outputpath ../retire.json; cd ..
```

What a correct element looks like (hash shortened):

```html
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"
        integrity="sha384-<BASE64_HASH>"
        crossorigin="anonymous"></script>
```

#### Observation

Illustrative: three CDN libraries pinned to exact versions, one with SRI; `https://cdn.oldlib.example.org/lib.js` whose domain lapsed in 2025 and is now parked; jQuery 1.12.4 bundled in the main chunk.

#### Evaluation

- **Fail** (High to Critical) when a page loads script from a domain that is unregistered, expired, parked or owned by an unexpected party: anyone who controls it runs code on every user's page. Treat it as urgent; CWE-829, `A08:2025`.
- **Fail** (Low to Medium, by page sensitivity) for static, versioned third-party assets without SRI and without a documented decision (`v5.0.0-3.6.1`, L3; CWE-353, CWE-494). Report unpinned URLs (`@latest`, no version) in the same finding.
- **Fail** for SRI that cannot work: missing `crossorigin` (the browser blocks the file; usually noticed as a broken page) or a hash that does not match (a stale hash, or the file changed).
- **Fail** (rated by the advisory and reachability) for libraries with known vulnerabilities or past end of life (CWE-1104, CWE-1395, `A03:2025`); check whether the vulnerable function is used before rating above Low.
- **Pass** when every external static asset is versioned and SRI-protected, dynamic third parties are documented, and all external origins are controlled by the expected parties, or assets are self-hosted.

#### False positives

First-party assets on your own CDN hostname (SRI is optional for same-origin files; integrity there is a deployment-pipeline question). Libraries with advisories in functions the application never calls (note them, rate Info or Low). Dynamic loaders where SRI is impossible, if documented.

#### Automation

A CI test that parses the built HTML and fails on any cross-origin `script` or stylesheet `link` without `integrity` and `crossorigin`; Retire.js or `npm audit` in the pipeline; a scheduled DNS/RDAP check of every external asset domain. The `Integrity-Policy` response header (newer; MDN lists it as limited availability at the time of writing) can make the browser itself block scripts that lack integrity metadata; deploy `Integrity-Policy-Report-Only` first.

### GT-WEB-STOR-12: Sensitive data sent to third parties in URLs, Referer and beacons

*Guler Tech methodology.* Implements ASVS `v5.0.0-14.2.1` (L1), `v5.0.0-14.2.3` (L2) and `v5.0.0-3.4.5` (L2); WSTG covers the URL side under WSTG-INFO-05 and the session-identifier side under session management testing.

#### What it checks

Whether personal data, tokens or secrets travel to third parties: in URLs that analytics and replay scripts record, in the `Referer` header, and in the payloads of analytics, advertising and error-tracking beacons.

#### Prerequisites

The third-party inventory from test 10; a walk-through that exercises search, password reset, magic-link login, profile pages, checkout and error states; Burp Logger with all third-party traffic recorded.

#### Steps

1. List first-party URLs that carry sensitive values in the path or query: reset and verification tokens, magic-link tokens, email addresses, names, phone numbers, postcodes, search terms, invoice or patient numbers, session IDs.
2. Load each such URL and check what the page's third parties receive. In Burp, search third-party requests (Logger filter on host) for your test account's email address, name, user ID, and the token value from the URL. Analytics page-view hits commonly carry the full page URL in a parameter.
3. Check the `Referrer-Policy` header (and `referrerpolicy` attributes, and `meta name="referrer"`) on those pages. Note weakened policies (`unsafe-url`, `no-referrer-when-downgrade`, `origin-when-cross-origin` on pages with tokens in the path).
4. Check error trackers: do error events include request URLs with tokens, or form field values, or user data attached to the event context?
5. Check session replay: does it mask input fields and personal data, or record them? (The vendor's dashboard is out of scope; look at the beacon payloads and the SDK configuration in the bundle.)

```http
GET /collect?v=2&tid=G-XXXXXXX&dl=https%3A%2F%2Fapp.example.com%2Freset%3Ftoken%3D<RESET_TOKEN>%26email%3Dusera%2540example.org&dt=Reset%20password HTTP/2
Host: analytics.vendor.example.net
Referer: https://app.example.com/
```

#### Observation

Illustrative: the password-reset page URL carries the token and the email address; the analytics hit includes the full URL (`dl` parameter); the session-replay beacon includes the unmasked email field; `Referrer-Policy` is `unsafe-url` site-wide.

#### Evaluation

- **Fail** (Medium) when credentials or one-time tokens (reset, magic-link, invite) reach third parties: anyone with access to the vendor's data can use an unexpired token. Rate higher if tokens are long-lived or reusable. CWE-598.
- **Fail** (Low to Medium) when personal data reaches trackers that the client has not defined as recipients (`v5.0.0-14.2.3`; CWE-359). Flag it to the client's data protection contact as well.
- **Fail** (Low) for a weakened referrer policy on pages with sensitive URLs (`v5.0.0-3.4.5`).
- **Pass** when sensitive values are kept out of URLs (sent in bodies or headers), analytics receive sanitised page paths, replay masks inputs by default, and the referrer policy is the browser default or stricter.

#### False positives

Pseudonymous analytics IDs. Tokens that are already consumed or expired when the third party receives them (check: the page usually loads analytics before the user submits the reset form, so the token is still live). Data sent to a processor the client lists in its privacy notice and contract, if that is the agreed design; the finding then shrinks to data minimisation.

#### Automation

A Playwright or Burp-based check that loads token-bearing pages with a known marker (a test email such as `gt-marker@example.org`) and fails if the marker appears in any request to a third-party host. Keep it in the end-to-end suite so new tags cannot reintroduce the leak.

## Secure implementation

### Design rules

- **The browser is not a vault.** Anything stored client-side is readable by the person at the keyboard and by any script in the origin. Store only what the UI needs, for as long as it needs it.
- **Session credentials go where script cannot read them.** `HttpOnly` cookies, or a backend-for-frontend that holds OAuth tokens server-side. If the architecture forces tokens into the browser, keep them in memory, short-lived and rotated.
- **Logout clears the client as well as the server.** Server-side invalidation (see [Revocation, sharing and asynchronous access](/web/web-access-control-revocation-sharing-async/)) plus `Clear-Site-Data` plus client-side clean-up that also works offline.
- **Service workers cache static assets, not user data,** unless offline access to user data is a product requirement, in which case it is designed, encrypted per user where possible, and cleared on logout.
- **Secrets never reach the build that ships to browsers.** Anything a browser needs to call with a secret goes through your server.
- **Production ships no public source maps.**
- **Every third-party script on a sensitive page is a decision:** documented, reviewed, version-pinned with SRI where possible, isolated in an iframe where possible, constrained by CSP, and removed when no longer needed.
- **URLs carry no secrets and no personal data.**

### Session tokens out of script reach

The strongest fix for test 2 is architectural: the browser holds an `HttpOnly` session cookie for your own backend, and the backend holds any OAuth access and refresh tokens and attaches them to upstream calls. ASVS calls this the backend-for-frontend pattern (`v5.0.0-10.1.1`, L2), and RFC 10017 describes it in detail. Cookie attributes (`Secure`, `HttpOnly`, `SameSite`, prefixes) are covered in the Session Management note.

Where an SPA must hold a token (a third-party API with no BFF, a legacy architecture), keep the access token in a JavaScript closure or module variable, not in storage; keep its lifetime in minutes; deliver the refresh token as an `HttpOnly` cookie scoped to the refresh endpoint; and rotate refresh tokens on every use so a stolen one is detected. Many identity SDKs default to in-memory caching and offer `localStorage` as an option for convenience; leave the default. None of this helps against an attacker who already runs script in the page while the user is there, which is why script-injection prevention and CSP remain the primary controls.

### Keep client storage minimal and short-lived

- Prefer `sessionStorage` to `localStorage` for anything tied to the session; it disappears with the tab.
- Do not persist whole API responses. Persist the fields the UI needs (a display name, not the full profile); drop anything the server marks sensitive.
- Do not "encrypt" data in `localStorage` with a key that is also in the page; it adds nothing against script or against the device user.
- If offline data is a requirement (PWA, field app), keep it in IndexedDB under a per-user database name, store an expiry with each record, purge on logout and on expiry, and consider encrypting it with a non-extractable `CryptoKey` (generated with `extractable: false`) so the raw key cannot be exported, accepting that script in the page can still ask the browser to decrypt.
- Treat everything read back from storage as untrusted input: another script or a previous version of the app may have written it, and storage is a classic DOM XSS source (see [DOM XSS](/web/web-dom-xss-client-side-injection/)).

### Clear the browser on logout

**Server side: send `Clear-Site-Data` on the logout response**, together with the session invalidation and `Cache-Control: no-store` on responses that contain personal data (`v5.0.0-14.3.2`). The `"storage"` directive clears `localStorage`, `sessionStorage` and IndexedDB and unregisters service workers; `"cache"` clears the HTTP cache for the origin; `"cookies"` clears cookies for the registered domain, including subdomains, so check that this does not log users out of sibling applications you did not mean to touch. The header only works over HTTPS. Cache Storage is not named explicitly in the specification's list for `"storage"`, so clear it from the client as well and verify in the browsers you support.

Express:

```javascript
app.post("/auth/logout", requireSession, (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie("sid", { path: "/", secure: true, httpOnly: true, sameSite: "lax" });
    res.set("Clear-Site-Data", '"cache", "cookies", "storage"');
    res.set("Cache-Control", "no-store");
    res.status(204).end();
  });
});

// Personal data responses are never stored by the browser
app.use("/api", (req, res, next) => { res.set("Cache-Control", "no-store"); next(); });
```

Django (function view; `never_cache` adds `no-store` among other directives):

```python
from django.contrib.auth import logout
from django.http import HttpResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

@require_POST
@never_cache
def logout_view(request):
    logout(request)  # flushes the session
    response = HttpResponse(status=204)
    response["Clear-Site-Data"] = '"cache", "cookies", "storage"'
    return response
```

Spring Security (the header writer only emits the header on secure requests; behind a TLS-terminating proxy, configure forwarded headers, for example `server.forward-headers-strategy=framework` in Spring Boot, or it will silently do nothing):

```java
import org.springframework.security.web.authentication.logout.HeaderWriterLogoutHandler;
import org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter;
import static org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter.Directive.*;

@Bean
SecurityFilterChain security(HttpSecurity http) throws Exception {
    HeaderWriterLogoutHandler clearSiteData =
        new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(CACHE, COOKIES, STORAGE));
    http
        .logout(logout -> logout
            .logoutUrl("/auth/logout")
            .addLogoutHandler(clearSiteData)
            .invalidateHttpSession(true)
            .deleteCookies("JSESSIONID"));
    return http.build();
}
```

Laravel:

```php
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;

public function destroy(Request $request): Response
{
    Auth::guard('web')->logout();
    $request->session()->invalidate();
    $request->session()->regenerateToken();

    return response()->noContent()
        ->header('Clear-Site-Data', '"cache", "cookies", "storage"')
        ->header('Cache-Control', 'no-store');
}
```

**Client side: clean up even if the server is unreachable.** Run the same routine on explicit logout, when the API returns `401` for an expired session, and when another tab logs out (a `BroadcastChannel` message or a `storage` event; see [postMessage and web messaging](/web/web-postmessage-web-messaging/) for validating such messages):

```javascript
export async function clearClientState() {
  try { localStorage.clear(); sessionStorage.clear(); } catch (_) { /* storage disabled */ }
  if (indexedDB.databases) {
    for (const { name } of await indexedDB.databases()) indexedDB.deleteDatabase(name);
  } else {
    ["offline", "drafts"].forEach((n) => indexedDB.deleteDatabase(n)); // known names
  }
  if (self.caches) for (const key of await caches.keys()) await caches.delete(key);
  if (navigator.serviceWorker) {
    for (const reg of await navigator.serviceWorker.getRegistrations()) await reg.unregister();
  }
  store.reset(); // in-memory state: Redux, Pinia, NgRx, React Query caches
  new BroadcastChannel("auth").postMessage({ type: "logged-out" });
}
```

If the product needs some keys to survive logout (language, theme), clear by allow-list instead of calling `clear()`.

### Service workers that do not leak

- Precache only the versioned app shell; send `/api/` and authenticated navigations to the network. With Workbox:

```javascript
import { precacheAndRoute } from "workbox-precaching";
import { registerRoute } from "workbox-routing";
import { NetworkOnly, CacheFirst } from "workbox-strategies";

precacheAndRoute(self.__WB_MANIFEST); // build-time list of hashed static files

// Never cache API or HTML responses that carry user data
registerRoute(({ url }) => url.origin === self.location.origin && url.pathname.startsWith("/api/"), new NetworkOnly());
registerRoute(({ request }) => request.mode === "navigate", new NetworkOnly());

// Hashed static assets only
registerRoute(
  ({ request, url }) => url.origin === self.location.origin
    && ["script", "style", "font", "image"].includes(request.destination)
    && /\.[0-9a-f]{8,}\./.test(url.pathname),
  new CacheFirst({ cacheName: "static-v1" })
);
```

(An offline fallback page can be added with Workbox's offline fallback recipe without caching personalised navigations.)

- Keep the scope as narrow as the feature needs; do not send `Service-Worker-Allowed: /` unless required.
- Serve the worker script with `Cache-Control: no-cache` so deployments reach clients quickly, and do not `importScripts()` from third-party origins; self-host what the worker imports.
- Keep a **kill-switch worker** ready to deploy at the same URL:

```javascript
// sw.js: retire the worker, its caches and its control over open pages
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) await caches.delete(key);
    await self.registration.unregister();
    for (const client of await self.clients.matchAll({ type: "window" })) client.navigate(client.url);
  })());
});
```

### No secrets in bundles

**Proxy calls that need a secret through your server.** The browser calls your endpoint with its session; the server adds the key, applies authorization and rate limits, and returns only what the UI needs:

```javascript
// Express: the browser never sees GEO_API_KEY
import rateLimit from "express-rate-limit";

app.get("/api/geocode", requireSession, rateLimit({ windowMs: 60_000, limit: 30 }), async (req, res) => {
  const q = String(req.query.q || "").slice(0, 200);
  const upstream = await fetch(`https://geo.vendor.example.net/v1/search?q=${encodeURIComponent(q)}`, {
    headers: { Authorization: `Bearer ${process.env.GEO_API_KEY}` },
  });
  const data = await upstream.json();
  res.status(upstream.status).json({ results: (data.results || []).map(({ label, lat, lon }) => ({ label, lat, lon })) });
});
```

The same pattern in Django (a view using `requests` with the key from settings or a secrets manager), Spring (a `@RestController` calling the vendor with `RestClient` and a key injected from configuration) and Laravel (a controller using the `Http` client with `config('services.geo.key')`). The point is identical in each: the key lives in server configuration loaded from a secrets manager (`v5.0.0-13.3.1`), never in the front-end build.

**Keep environments and prefixes honest.**

- Vite exposes only `VITE_*` variables to client code and Next.js only `NEXT_PUBLIC_*`; both document that these values are inlined into the bundle. Name a variable with the public prefix only if you would put its value on a billboard.
- Do not inject `process.env` wholesale with webpack's `DefinePlugin` or `EnvironmentPlugin`; list the public variables explicitly.
- Build separate bundles per environment, or load public runtime configuration from an endpoint that returns an explicit allow-list (`{ "stripePublishableKey": …, "sentryDsn": … }`), so staging keys and URLs do not ship to production.
- Angular `environment.*.ts` files are compiled into the bundle; they are for public configuration only.
- Remove test credentials and debug code paths from production builds; dead-code elimination removes `if (import.meta.env.DEV)` branches, but not values referenced elsewhere.

**Check the output, not just the source.** A secret scan on the repository misses values injected at build time from CI variables. Scan the built `dist/` directory as well (see [Regression checks in CI](#regression-checks-in-ci)). If a secret ever shipped, rotate it; removing it from the next build does not remove it from caches, archives and anyone's copy.

### Source maps in production

Generate maps if you need readable stack traces, but do not serve them publicly: upload them to your error-tracking service during the build, then delete them from the deploy artefact.

```javascript
// webpack.config.js: no sourceMappingURL comment; maps are for error tooling only
module.exports = { mode: "production", devtool: "hidden-source-map" };
```

```javascript
// vite.config.js: 'hidden' writes .map files without the comment
import { defineConfig } from "vite";
export default defineConfig({ build: { sourcemap: "hidden" } });
```

```javascript
// next.config.js: false is the default; keep it that way
module.exports = { productionBrowserSourceMaps: false };
```

```bash
# after uploading maps to the error tracker in CI
find dist -name '*.map' -delete
```

webpack's `nosources-source-map` is a middle ground (file names and structure, no `sourcesContent`) if maps must be public for some reason. As a second layer, block `.map` at the web server or CDN for production hosts (an nginx `location ~* \.map$ { return 404; }`), or restrict it to the error-tracking service and your VPN. Apply the same settings to staging if staging is internet-facing.

### Third-party scripts: SRI, CSP, self-hosting and governance

**Prefer self-hosting** for static libraries: install them from your package registry, bundle them, and they go through your dependency review, lockfile and SCA scanning (`v5.0.0-15.1.2`, L2 SBOM; `v5.0.0-15.2.1`, L1 patch timeframes). This removes the third-party origin from the runtime path, which also removes the "domain sold" risk.

**When you must load from a CDN, pin and hash.** Use an exact version in the URL, an `integrity` hash and `crossorigin="anonymous"`:

```bash
curl -s https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js \
  | openssl dgst -sha384 -binary | openssl base64 -A | sed 's/^/sha384-/'
```

```html
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"
        integrity="sha384-<BASE64_HASH>"
        crossorigin="anonymous"></script>
```

For your own assets served from a separate CDN hostname, the bundler can add integrity attributes automatically (for webpack, the `webpack-subresource-integrity` plugin). Once all scripts carry integrity metadata, `Integrity-Policy: blocked-destinations=(script)` (start with `Integrity-Policy-Report-Only`) makes supporting browsers reject scripts without it; MDN marks browser support as limited at the time of writing, so treat it as an extra layer.

**Know what SRI cannot do.** It does not work for scripts that change by design (tag-manager containers, analytics loaders, chat widgets, payment SDKs that the provider updates), and it does not cover the scripts those loaders inject. The British Airways skimmer was inside a script served from BA's own site, where nobody would have expected SRI. For dynamic vendors, the controls are:

- **Isolation:** run the widget in a cross-origin `iframe` with `sandbox` (no `allow-same-origin`) and talk to it with validated `postMessage`; use the payment provider's hosted fields or hosted page so card data never enters your DOM.
- **Placement:** keep non-essential third parties off login, password-reset, MFA, account-settings and payment pages entirely. The ICO's Ticketmaster finding was that a chatbot did not need to be on the payment page.
- **CSP:** a nonce-based `script-src` limits which scripts run, and `connect-src` limits where scripts can send data, which constrains a compromised script's exfiltration routes. Tag managers need specific allowances (Google documents nonce support and which hosts each product needs); `'unsafe-eval'` for custom JavaScript variables is a cost to weigh. Design details are in [Content Security Policy and security headers](/web/web-content-security-policy-headers/).
- **Tag-manager governance:** restrict who can publish containers, require review for container changes, and block Custom HTML tags and custom JavaScript variables where the business does not need them. Google Tag Manager supports this from the page itself with a blocklist pushed before the container loads:

```javascript
window.dataLayer = window.dataLayer || [];
window.dataLayer.push({ "gtm.blocklist": ["customScripts"] }); // blocks Custom HTML tags and custom JS variables
```

- **Vendor review:** before adding a script, record what it does, which pages it runs on, what data it can reach, the vendor's security posture and change process, and a contract clause on code integrity; review the list periodically and remove what is unused. For payment pages, PCI DSS v4.0.1 requirements 6.4.3 and 11.6.1 make a script inventory and change detection mandatory.

### URLs and Referrer-Policy

- Keep tokens and personal data out of URLs (`v5.0.0-14.2.1`). Send them in request bodies or headers. Where a URL token is unavoidable (password reset, magic link, email verification), exchange it for a session or a short-lived form token on first load, then strip it with `history.replaceState()` **before** analytics initialises, and make the token single-use and short-lived.
- Set `Referrer-Policy: strict-origin-when-cross-origin` (the browser default) or stricter, and `no-referrer` on pages that carry tokens in the URL. Helmet for Express (default `no-referrer`), Django's `SECURE_REFERRER_POLICY` (default `same-origin`), Spring Security's `headers().referrerPolicy(...)` and a Laravel middleware all set it; header details are in [Content Security Policy and security headers](/web/web-content-security-policy-headers/).
- Configure analytics to send sanitised page paths (strip query strings, or allow-list parameters), configure session replay to mask all inputs and text by default, and scrub URLs and user context in error-tracking SDK hooks (`beforeSend`).
- Document which third parties receive which data (`v5.0.0-14.2.3`) and keep the list in step with the privacy notice.

### Regression checks in CI

Most findings in this note come back with the next release unless the pipeline checks the **built output**. A single script run after `npm run build` covers the common ones:

```bash
#!/usr/bin/env bash
# ci/check-frontend.sh: run against the production build directory
set -euo pipefail
DIST=${1:-dist}

# 1. Secrets in the shipped files (detection only, redacted output)
gitleaks dir "$DIST" --redact --no-banner --report-format sarif --report-path gitleaks-dist.sarif

# 2. No source maps and no sourceMappingURL comments
if find "$DIST" -name '*.map' | grep -q .; then echo "source maps in build output"; exit 1; fi
if grep -RIl 'sourceMappingURL=' "$DIST" --include='*.js' | grep -q .; then echo "sourceMappingURL comment in bundle"; exit 1; fi

# 3. Every cross-origin script tag carries integrity and crossorigin
bad=$(grep -RhoE '<script[^>]+src="https?://[^"]+"[^>]*>' "$DIST" --include='*.html' | grep -vE 'integrity="sha(256|384|512)-' || true)
if [ -n "$bad" ]; then echo "external script without SRI:"; echo "$bad"; exit 1; fi

# 4. No private-looking environment variables under public prefixes
if grep -RIoE '(VITE|NEXT_PUBLIC|REACT_APP)_[A-Z0-9_]*(SECRET|PRIVATE|PASSWORD|TOKEN)' "$DIST" | grep -q .; then
  echo "secret-looking public env variable name in bundle"; exit 1
fi
echo "front-end checks passed"
```

Keep a `.gitleaks.toml` allow-list for the publishable keys you have classified (test 8), so the scan fails only on new values.

Then an end-to-end test for storage and third-party leakage (Playwright, TypeScript):

```typescript
import { test, expect } from "@playwright/test";

const MARKER = "gt-marker@example.org"; // test account email

test("logout leaves no authenticated client state", async ({ page, context }) => {
  await page.goto("https://app.example.com/login");
  await page.getByLabel("Email").fill(MARKER);
  await page.getByLabel("Password").fill(process.env.TEST_USER_PASSWORD!);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByRole("link", { name: "Messages" }).click();
  await page.getByRole("button", { name: "Log out" }).click();
  await page.waitForURL("**/login");

  const state = await page.evaluate(async () => ({
    local: Object.keys(localStorage),
    session: Object.keys(sessionStorage),
    idb: indexedDB.databases ? (await indexedDB.databases()).map((d) => d.name) : [],
    caches: await caches.keys(),
    workers: navigator.serviceWorker ? (await navigator.serviceWorker.getRegistrations()).length : 0,
  }));
  expect(state.local.filter((k) => !["theme", "lang"].includes(k))).toEqual([]);
  expect(state.session).toEqual([]);
  expect(state.idb).toEqual([]);
  expect(state.caches).toEqual([]);
  expect(state.workers).toBe(0);
  expect((await context.cookies()).map((c) => c.name)).not.toContain("sid");
});

test("no personal data reaches third-party hosts", async ({ page }) => {
  const leaks: string[] = [];
  page.on("request", (req) => {
    const host = new URL(req.url()).hostname;
    const firstParty = host === "example.com" || host.endsWith(".example.com");
    const body = req.postData() || "";
    if (!firstParty && (decodeURIComponent(req.url()).includes(MARKER) || body.includes(MARKER))) leaks.push(host);
  });
  await page.goto(`https://app.example.com/reset?email=${encodeURIComponent(MARKER)}`);
  await page.waitForLoadState("networkidle");
  expect(leaks).toEqual([]);
});
```

The second test deliberately uses a URL that carries the marker; it fails as long as any third party on that page receives the URL. Pair these with the script-inventory crawl from test 10 (fail on a new third-party host on a sensitive page) and a scheduled DNS/RDAP check of external asset domains.

## Practice labs

There are few dedicated labs for storage and third-party script governance, because the issues show up in real applications rather than in a single vulnerable parameter. These come closest:

**PortSwigger Web Security Academy** (free):

- [Information disclosure on debug page](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page): an HTML comment points to a debug page that leaks a secret, the WSTG-INFO-05 pattern behind test 9.
- [Source code disclosure via backup files](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files): a hard-coded database password in leaked source, the server-side cousin of a public source map (tests 6 and 7).
- [Exploiting cross-site scripting to steal cookies](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies): in a lab, shows what script in the page can take when credentials are readable, which is the impact argument behind test 2. Never use this technique on a client system.

**OWASP Juice Shop** (companion guide chapters [Sensitive Data Exposure](https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html), [Vulnerable Components](https://pwning.owasp-juice.shop/companion-guide/latest/part2/vulnerable-components.html) and [Security through Obscurity](https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-through-obscurity.html)):

- *Score Board*: find a hidden route in the client-side code (test 9).
- *Exposed Credentials*: valid test-account credentials hard-coded in client-side code (test 7).
- *Outdated Allowlist*: redirect targets left behind in the compiled client code (test 9).
- *Blockchain Hype*: undo obfuscation of the route definitions to reach a hidden page (test 9).
- *Frontend Typosquatting* and *Vulnerable Library*: a malicious look-alike package in the front end and a known-vulnerable dependency (test 11).
- At the time of writing Juice Shop keeps its authentication token in browser storage, so tests 1 to 3 can be practised on it as they are.

**Your own build.** The most useful lab for this note is a small React or Vue app built twice: once with `build.sourcemap: true`, a `VITE_` variable holding a fake secret, a Workbox worker caching `/api/`, and a CDN script without SRI; and once fixed. Run tests 1 to 11 against both and the CI script from [Regression checks in CI](#regression-checks-in-ci) against both builds.

## Real-world cases

- **polyfill.io supply-chain compromise (June 2024).** The `cdn.polyfill.io` domain and its GitHub account were sold in February 2024; from June, Sansec reported, the service injected code that redirected some mobile visitors to sports-betting sites via a fake analytics domain, activating only on certain devices at certain hours and avoiding admin users. More than 100,000 sites embedded the script. The case shows the "origin nobody controls any more" risk from test 11 and why self-hosting beats trusting a URL. [Sansec research](https://sansec.io/research/polyfill-supply-chain-attack).
- **British Airways, Magecart skimmer (2018; ICO penalty October 2020).** Attackers who had reached BA's network modified a JavaScript file served from BA's own website, a copy of the Modernizr library according to RiskIQ's analysis, so that payment form data was also sent to a look-alike domain, `baways.com`. BA said the skimming ran from 21 August to 5 September 2018. The ICO fined BA £20 million in October 2020. Lessons for this note: first-party scripts on payment pages need integrity monitoring too, and a strict `connect-src` limits where a skimmer can send data. [The Register, September 2018 (RiskIQ findings)](https://www.theregister.com/2018/09/11/british_airways_website_scripts/), [The Register, October 2020 (ICO fine)](https://www.theregister.com/2020/10/16/british_airways_ico_fine_20m/).
- **Ticketmaster UK and a third-party chatbot (2018; ICO penalty November 2020).** Ticketmaster placed a chatbot from a supplier (Inbenta) on its payment page; the chatbot's JavaScript, hosted by the supplier, was modified to scrape payment and personal data. The ICO fined Ticketmaster £1.25 million, finding that third-party scripts on payment pages were a well-known risk, that no risk assessment had been done, that the chatbot was not needed on the payment page, and that SRI was "an appropriate measure" whose absence needed a justification (with CSP, iframes or local hosting as alternatives). This is test 10 and the SRI-or-documented-decision rule of `v5.0.0-3.6.1`. [Stephenson Harwood analysis of the ICO penalty notice](https://www.stephensonharwood.com/insights/an-analysis-of-the-monetary-penalty-notice-issued-by-the-information-commissioner-s-office-to-ticketmaster-uk-limited/).
- **API keys in a JavaScript bundle, and a key that was never revoked (Stripo, 2020).** A researcher reported third-party API credentials in cleartext in the main JavaScript bundle of a Stripo staging host; the report was resolved and publicly disclosed in September 2020, rated Medium. Two months later another researcher reported that a key visible in that disclosed report still worked against a Google API, also rated Medium. The lesson for test 7: removal from the bundle is not remediation; rotation is. [HackerOne report 983331](https://hackerone.com/reports/983331), [HackerOne report 1047125](https://hackerone.com/reports/1047125).
- **"Publishable" Google API keys gaining Gemini access (research, February 2026).** Truffle Security showed that Google API keys embedded in public web pages for services such as Maps or Firebase could call the Gemini API once the Generative Language API was enabled in the same project, and found 2,863 such live keys in a Common Crawl dataset. Google first treated it as intended behaviour and then reclassified it as a bug. The case is why test 8 asks the client about enabled APIs instead of assuming a key format is safe. [Truffle Security](https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules).

More write-ups are collected in [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

Rate on what the finding gives an attacker and under which preconditions. Storage findings are mostly **impact multipliers**: their severity depends on whether there is a way to run script in the origin (XSS, a hostile third party) or physical access to a shared device. Secrets are rated by what the secret unlocks, which the client confirms; you do not test it. Third-party script findings are rated by what the script can reach on the page it runs on and how plausible compromise of its origin is. CVSS v3.1 vectors below are examples.

**Scope.** Series convention for this round: script running in the victim's browser uses `UI:R` and `S:C`. For a secret in a bundle, the vulnerable component is the web application and the impacted component is usually another system (the payment provider account, the cloud account), so `S:C` applies when the client confirms the secret reaches it. Physical-access findings on shared devices use `AV:P`.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Live server-side secret in a public bundle or source map (payment provider secret key, cloud key with write access, admin API token) | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` (10.0) | Anonymous, trivial; impact lands in the third-party account. Report the same day for rotation |
| Secret limited to reading data in another system (read-only analytics export key, search admin key on private indices) | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` (8.6) | As above without integrity impact; lower to `C:L` if the data is not sensitive |
| Publishable key confirmed unrestricted, billable APIs reachable (incl. generative AI APIs) | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:L` (7.2) | Cost abuse and quota exhaustion; High if private data or AI files are reachable, Medium when only billing is affected. Confirmed by the client, not by you |
| Script loaded from an unregistered, expired or parked domain | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` (9.3) | Whoever registers the domain runs script on every visitor's page; `UI:R` because a user must load the page |
| Static third-party script without SRI on a payment or login page, no documented decision | Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N` (8.0) base; report Medium | `AC:H` because exploitation needs the CDN or vendor to be compromised first; the base score overstates likelihood, so rate the finding as Medium and explain |
| Unnecessary third-party scripts (chat, analytics, tag manager with Custom HTML) on payment or credential pages | Medium | — | Vector as above (8.0 base; report Medium). Same precondition; more vendors means more chances. The ICO treated this as a failure to implement appropriate measures |
| Tokens in `localStorage` with a confirmed XSS or hostile third party in the same origin | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` (9.3) for the combined XSS | Rate the XSS finding up: stored token theft gives persistent account takeover, not just actions during the visit. Report as part of the XSS finding |
| Tokens in `localStorage` (long-lived, non-rotating refresh token), no injection path found | Low | none, or `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` (3.1) | Defence in depth: raises the impact of any future XSS. Many programmes treat it as informative on its own |
| Authenticated data and tokens persist after logout, tokens still valid server-side | Medium | `CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (6.1) | Next user of a shared device reads the data and acts as the previous user. Higher for shared-device user bases (kiosks, clinics, call centres) |
| Personal data persists after logout or is shown to the next user (cache, IndexedDB, service worker), tokens revoked | Low to Medium | `CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` (5.2) | Confidentiality impact on a shared device; `C:H` for health, financial or large data sets, `C:L` (2.4 with `I:N`) for a display name |
| Service worker importing code from a third-party origin with scope `/` | Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N` (8.0) base; report Medium | Same reasoning as a script without SRI, with control over every request in scope |
| Public source maps with original source, no secrets | Low | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) base; report Low | Speeds up attacks and reveals internals; rate by content. Info for open-source front ends |
| Reset or magic-link tokens sent to third-party analytics | Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N` (6.8) | Anyone with access to the vendor's data can use an unexpired token; `AC:H` because it needs access to that data |
| Personal data in URLs or beacons sent to trackers not defined as recipients | Low to Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N` (4.3) | Privacy and data-protection issue more than an attack path; flag to the client's DPO |
| Client-side debug switch that makes the server return stack traces or hidden data | Low to Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | Rate by what the debug output reveals |
| Internal hostnames, private IPs, hidden routes in bundles | Info to Low | none | Reconnaissance value; findings come from the server-side tests they feed |
| Outdated client-side library with a known vulnerability, no reachable vulnerable function | Info to Low | — | Depends on the advisory: raise per the advisory if the vulnerable function is reachable (usually to XSS) |
| Publishable keys used as designed (Stripe `pk_`, Firebase config, Sentry DSN, site keys) | Info | none | Not a vulnerability by itself; write up as reviewed, so the client knows |

Compute exact scores for your vectors with the [FIRST CVSS v3.1 calculator](https://www.first.org/cvss/calculator/3.1). When you report, give: where the item is (origin, storage key or file and offset, or script URL and page), what it is (classified, with values redacted), what an attacker needs (script injection, physical access, compromise of a vendor), what you did not do (no secret was used, no domain registered), and the fix.

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 / API Top 10 |
|---|---|---|---|---|
| GT-WEB-STOR-1 | WSTG-CLNT-12 | v5.0.0-14.3.3, v5.0.0-14.1.1 | CWE-922, CWE-312 | A01:2025 |
| GT-WEB-STOR-2 | WSTG-CLNT-12 | v5.0.0-14.3.3, v5.0.0-3.3.4, v5.0.0-10.1.1 | CWE-922 | A01:2025 |
| GT-WEB-STOR-3 | WSTG-CLNT-12, WSTG-SESS-06, WSTG-ATHN-06 | v5.0.0-14.3.1, v5.0.0-14.3.2, v5.0.0-7.4.1 | CWE-922, CWE-525 | A01:2025; A07:2025 when tokens stay valid |
| GT-WEB-STOR-4 | WSTG-CLNT-12, WSTG-ATHN-06 | v5.0.0-14.3.1, v5.0.0-14.3.3 | CWE-524, CWE-922 | A01:2025 |
| GT-WEB-STOR-5 | WSTG-CLNT-12 | v5.0.0-14.3.1, v5.0.0-3.6.1 (imported scripts) | CWE-922, CWE-829 | A01:2025, A08:2025 |
| GT-WEB-STOR-6 | WSTG-INFO-05, WSTG-CONF-02, WSTG-APIT-03 | v5.0.0-13.4.2 | CWE-540, CWE-615 | A01:2025; API8:2023 |
| GT-WEB-STOR-7 | WSTG-INFO-05 | v5.0.0-13.3.1 | CWE-798, CWE-540 | A07:2025 (hard-coded credentials), A01:2025 |
| GT-WEB-STOR-8 | WSTG-INFO-05 | v5.0.0-13.3.1, v5.0.0-13.3.2 | CWE-798 | A07:2025 |
| GT-WEB-STOR-9 | WSTG-INFO-05, WSTG-CONF-15 | v5.0.0-13.4.2 | CWE-540, CWE-489 | A01:2025, A02:2025; API8:2023 |
| GT-WEB-STOR-10 | WSTG-INFO-05, WSTG-CONF-12 | v5.0.0-3.6.1, v5.0.0-14.2.3, v5.0.0-3.4.3 | CWE-829, CWE-830 | A08:2025 |
| GT-WEB-STOR-11 | WSTG-INFO-05, WSTG-CONF-12 | v5.0.0-3.6.1, v5.0.0-3.7.1, v5.0.0-15.2.1 | CWE-353, CWE-494, CWE-829, CWE-1104, CWE-1395 | A08:2025, A03:2025 |
| GT-WEB-STOR-12 | WSTG-INFO-05 | v5.0.0-14.2.1, v5.0.0-14.2.3, v5.0.0-3.4.5 | CWE-598, CWE-359 | A01:2025 |

ASVS levels: `v5.0.0-14.3.1` L1 (authenticated data cleared from client storage when the session ends; mentions `Clear-Site-Data`), `v5.0.0-14.3.2` L2 (`Cache-Control: no-store` for sensitive data), `v5.0.0-14.3.3` L2 (no sensitive data in browser storage except session tokens), `v5.0.0-14.1.1` L2 (sensitive data identified and classified), `v5.0.0-14.2.1` L1 (no sensitive data in URLs), `v5.0.0-14.2.3` L2 (sensitive data not sent to untrusted parties such as trackers), `v5.0.0-3.3.4` L2 (`HttpOnly` for session cookies), `v5.0.0-3.4.3` L2 (CSP), `v5.0.0-3.4.5` L2 (referrer policy), `v5.0.0-3.6.1` L3 (external assets static, versioned and SRI-protected, or a documented decision), `v5.0.0-3.7.1` L2 (only supported, secure client-side technologies), `v5.0.0-7.4.1` L1 (session termination enforced server-side), `v5.0.0-10.1.1` L2 (tokens only sent to components that need them; BFF), `v5.0.0-13.3.1` L2 (secrets in a secrets manager, not in source code or build artefacts), `v5.0.0-13.3.2` L2 (least privilege for secrets), `v5.0.0-13.4.2` L2 (debug modes disabled in production), `v5.0.0-15.2.1` L1 (components within remediation timeframes).

CWE choice: CWE-922 (*Insecure Storage of Sensitive Information*) is a class, and MITRE marks it as allowed with review; use its child CWE-312 (*Cleartext Storage of Sensitive Information*) when the issue is plainly sensitive data stored readable, and CWE-922 when the problem is the storage location's accessibility (tokens readable by script). CWE-524 (*Use of Cache Containing Sensitive Information*) fits service worker caches; CWE-525 (*Use of Web Browser Cache Containing Sensitive Information*) fits the HTTP cache and **Back** button. CWE-540 (*Inclusion of Sensitive Information in Source Code*) and its child CWE-615 (comments) cover source maps and bundles; CWE-798 (*Use of Hard-coded Credentials*, allowed with review) is the better fit when the item is a credential. CWE-829 (*Inclusion of Functionality from Untrusted Control Sphere*) and its child CWE-830 (*Inclusion of Web Functionality from an Untrusted Source*) cover third-party scripts; CWE-353 and CWE-494 the missing integrity check; CWE-1104 (*Use of Unmaintained Third Party Components*) covers unmaintained and end-of-life libraries; CWE-1395 (*Dependency on Vulnerable Third-Party Component*) is a class without base-level children, allowed with review, for libraries with known vulnerabilities. In the OWASP Top 10:2025, CWE-922, CWE-540, CWE-615 and CWE-359 are mapped to `A01:2025` Broken Access Control; CWE-829, CWE-830, CWE-353 and CWE-494 to `A08:2025` Software or Data Integrity Failures; CWE-1104 and CWE-1395 to `A03:2025` Software Supply Chain Failures; CWE-798 to `A07:2025` Authentication Failures; CWE-489 to `A02:2025` Security Misconfiguration. CWE-312 is not in any 2025 category's mapped list, so use the category of the related CWE-922. The OWASP API Security Top 10 2023 has no client-storage category; `API8:2023` Security Misconfiguration covers debug output and unnecessary exposure such as public source maps.

## References

**OWASP**

- WSTG: [Browser Storage (WSTG-CLNT-12)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/12-Browser_Storage), [Review Web Page Content for Information Leakage (WSTG-INFO-05)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage), [Application Platform Configuration (WSTG-CONF-02)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/02-Application_Platform_Configuration), [Content Security Policy (WSTG-CONF-12)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/12-Content_Security_Policy), [Feature Flag Security Bypass (WSTG-CONF-15)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/15-Feature_Flag_Security_Bypass), [Browser Cache Weaknesses (WSTG-ATHN-06)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/04-Authentication/06-Browser_Cache_Weaknesses), [Logout Functionality (WSTG-SESS-06)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/06-Session_Management/06-Logout_Functionality), [Excessive Data Exposure (WSTG-APIT-03)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/03-Excessive_Data_Exposure)
- ASVS 5.0: [V3 Web Frontend Security](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md), [V7 Session Management](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x16-V7-Session-Management.md), [V10 OAuth and OIDC](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x19-V10-OAuth-and-OIDC.md), [V13 Configuration](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md), [V14 Data Protection](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x23-V14-Data-Protection.md), [V15 Secure Coding and Architecture](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md)
- Top 10:2025: [A01 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/), [A02 Security Misconfiguration](https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/), [A03 Software Supply Chain Failures](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/), [A07 Authentication Failures](https://top10.owasp.org/2025/A07_2025-Authentication_Failures/), [A08 Software or Data Integrity Failures](https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/); [API8:2023 Security Misconfiguration](https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/)
- Cheat Sheets: [HTML5 Security](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) (local storage, session storage), [Third Party JavaScript Management](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html), [Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html), [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [Content Security Policy](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)

**CWE**

- [CWE-922](https://cwe.mitre.org/data/definitions/922.html), [CWE-312](https://cwe.mitre.org/data/definitions/312.html), [CWE-524](https://cwe.mitre.org/data/definitions/524.html), [CWE-525](https://cwe.mitre.org/data/definitions/525.html), [CWE-540](https://cwe.mitre.org/data/definitions/540.html), [CWE-615](https://cwe.mitre.org/data/definitions/615.html), [CWE-798](https://cwe.mitre.org/data/definitions/798.html), [CWE-489](https://cwe.mitre.org/data/definitions/489.html), [CWE-829](https://cwe.mitre.org/data/definitions/829.html), [CWE-830](https://cwe.mitre.org/data/definitions/830.html), [CWE-353](https://cwe.mitre.org/data/definitions/353.html), [CWE-494](https://cwe.mitre.org/data/definitions/494.html), [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html), [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html), [CWE-598](https://cwe.mitre.org/data/definitions/598.html), [CWE-359](https://cwe.mitre.org/data/definitions/359.html)

**Browser APIs and standards**

- MDN: [Web Storage API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API), [IndexedDB API](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API), [CacheStorage](https://developer.mozilla.org/en-US/docs/Web/API/CacheStorage), [Cache](https://developer.mozilla.org/en-US/docs/Web/API/Cache), [Service Worker API](https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API), [Using Service Workers](https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API/Using_Service_Workers), [Service-Worker-Allowed](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Service-Worker-Allowed), [ServiceWorkerRegistration.unregister()](https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorkerRegistration/unregister), [Clear-Site-Data](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Clear-Site-Data), [Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity), [Integrity-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy), [Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- W3C: [Subresource Integrity](https://www.w3.org/TR/SRI/), [Clear Site Data](https://w3c.github.io/webappsec-clear-site-data/), [Service Workers](https://www.w3.org/TR/service-workers/), [Web Cryptography API: key storage](https://www.w3.org/TR/WebCryptoAPI/#concepts-key-storage)
- IETF: [RFC 10017, OAuth 2.0 for Browser-Based Applications](https://www.rfc-editor.org/rfc/rfc10017) (BCP 212; backend-for-frontend and token storage)
- Chrome DevTools: [View and edit local storage](https://developer.chrome.com/docs/devtools/storage/localstorage), [Debug your original code with source maps](https://developer.chrome.com/docs/devtools/javascript/source-maps)

**Build tools and frameworks**

- [webpack devtool](https://webpack.js.org/configuration/devtool/), [Vite build options](https://vite.dev/config/build-options) (`build.sourcemap`), [Vite env variables and modes](https://vite.dev/guide/env-and-mode), [Next.js productionBrowserSourceMaps](https://nextjs.org/docs/app/api-reference/config/next-config-js/productionBrowserSourceMaps), [Next.js environment variables](https://nextjs.org/docs/app/guides/environment-variables), [Workbox](https://developer.chrome.com/docs/workbox), [webpack-subresource-integrity](https://github.com/waysact/webpack-subresource-integrity)
- Spring Security: [Logout (Clear-Site-Data)](https://docs.spring.io/spring-security/reference/servlet/authentication/logout.html), [ClearSiteDataHeaderWriter](https://docs.spring.io/spring-security/reference/api/java/org/springframework/security/web/header/writers/ClearSiteDataHeaderWriter.html); Django: [cache decorators (`never_cache`)](https://docs.djangoproject.com/en/stable/topics/http/decorators/#caching), [`SECURE_REFERRER_POLICY`](https://docs.djangoproject.com/en/stable/ref/settings/#secure-referrer-policy); Laravel: [Authentication, logging out](https://laravel.com/docs/13.x/authentication#logging-out); Express: [Helmet](https://helmet.js.org/)

**Vendor documentation on public and secret keys**

- [Stripe API keys](https://docs.stripe.com/keys), [Firebase API keys](https://firebase.google.com/docs/projects/api-keys), [Sentry DSN explainer](https://docs.sentry.io/concepts/key-terms/dsn-explainer/), [Algolia API keys](https://www.algolia.com/doc/guides/security/api-keys/)
- Google Tag Manager: [Using Tag Manager with a Content Security Policy](https://developers.google.com/tag-platform/security/guides/csp), [Restrict tag deployment](https://developers.google.com/tag-platform/tag-manager/restrict)

**Tools**

- Secret scanning: [gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- JavaScript analysis: [jsluice](https://github.com/BishopFox/jsluice), [LinkFinder](https://github.com/GerbenJavado/LinkFinder), [sourcemapper](https://github.com/denandz/sourcemapper), [Retire.js](https://github.com/RetireJS/retire.js)
- [FIRST CVSS v3.1 calculator](https://www.first.org/cvss/calculator/3.1)

**Incidents, research and compliance**

- [Sansec: polyfill.io supply-chain attack](https://sansec.io/research/polyfill-supply-chain-attack)
- The Register: [British Airways website scripts (RiskIQ findings)](https://www.theregister.com/2018/09/11/british_airways_website_scripts/), [ICO fines British Airways £20m](https://www.theregister.com/2020/10/16/british_airways_ico_fine_20m/)
- [Stephenson Harwood: analysis of the ICO penalty notice to Ticketmaster UK](https://www.stephensonharwood.com/insights/an-analysis-of-the-monetary-penalty-notice-issued-by-the-information-commissioner-s-office-to-ticketmaster-uk-limited/)
- HackerOne: [report 983331](https://hackerone.com/reports/983331), [report 1047125](https://hackerone.com/reports/1047125)
- [Truffle Security: Google API keys weren't secrets, but then Gemini changed the rules](https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules)
- [Report URI: PCI DSS 4.0.1 requirements 6.4.3 and 11.6.1](https://blog.report-uri.com/pci-dss-4-0-1-and-requirements-6-4-3-and-11-6-1-what-changed-for-payment-page-scripts/)
- Labs: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), [PortSwigger Web Security Academy](https://portswigger.net/web-security)
