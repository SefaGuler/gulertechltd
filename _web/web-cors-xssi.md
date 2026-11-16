---
title: "CORS Misconfiguration and Cross-Site Script Inclusion"
date: 2026-11-15 22:06:00 +0000
subcategory: client-side
summary: "Testing CORS origin checks, credentialed reads, null and subdomain trust, preflight and cache gaps, plus JSONP and XSSI, with local PoCs and fixes."
refs: [WSTG-CLNT-07, WSTG-CLNT-13, v5.0.0-3.4.2, v5.0.0-3.5.1, v5.0.0-3.5.2, v5.0.0-3.5.6, v5.0.0-3.5.7, v5.0.0-3.4.4, v5.0.0-3.5.8, v5.0.0-4.1.1, "API8:2023", "A01:2025", "A02:2025", CWE-942, CWE-346, CWE-359]
tags: [web, cors, xssi, jsonp, same-origin-policy, client-side]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Client-Side testing](/web/web-client-side-testing-guide/). It covers the two ways a page on another origin gets to *read* your application's responses in a logged-in user's browser. The first is **CORS misconfiguration** (`WSTG-CLNT-07`): the server tells the browser to let an untrusted origin read the response. The second is **cross-site script inclusion** (XSSI, `WSTG-CLNT-13`): no permission is needed at all, because the response is valid JavaScript that any page can load with a script tag. JSONP sits in between, since it is XSSI on purpose. You get the browser model (what CORS relaxes and what it never controlled), the misconfiguration classes that still produce findings (reflected origins, `null`, broken regexes, every-subdomain trust, `http` origins, missing `Vary: Origin`, preflight gaps), twelve tests that start with curl and end with a local proof-of-concept page that reads **your own** test account's data and shows it only on your screen, and fixes for Express, Django, Spring and Laravel. Sending cross-site requests that change state is CSRF, which belongs to Session Management (not written yet); this note mentions it only where CORS settings and CSRF defences overlap.

## Contents

- [How it works](#how-it-works)
  - [The same-origin policy and what CORS relaxes](#the-same-origin-policy-and-what-cors-relaxes)
  - [Simple requests, preflights and credentials](#simple-requests-preflights-and-credentials)
  - [What the browser checks in the response](#what-the-browser-checks-in-the-response)
  - [Cookies, SameSite and why the browser matters](#cookies-samesite-and-why-the-browser-matters)
  - [Script inclusion: the older hole CORS does not cover](#script-inclusion-the-older-hole-cors-does-not-cover)
  - [Browser-side read protections: nosniff, CORB and ORB](#browser-side-read-protections-nosniff-corb-and-orb)
- [What goes wrong](#what-goes-wrong)
  - [Reflecting any Origin with credentials](#reflecting-any-origin-with-credentials)
  - [Trusting the null origin](#trusting-the-null-origin)
  - [Origin-matching mistakes](#origin-matching-mistakes)
  - [Trusting every subdomain](#trusting-every-subdomain)
  - [Trusting http origins from an https site](#trusting-http-origins-from-an-https-site)
  - [Wildcards: what the browser refuses and what it allows](#wildcards-what-the-browser-refuses-and-what-it-allows)
  - [Missing Vary: Origin and caches](#missing-vary-origin-and-caches)
  - [Preflight gaps](#preflight-gaps)
  - [Private network targets](#private-network-targets)
  - [JSONP endpoints](#jsonp-endpoints)
  - [Authenticated data in JavaScript and script-parsable responses](#authenticated-data-in-javascript-and-script-parsable-responses)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [Signals and false positives](#signals-and-false-positives)
  - [GT-WEB-CORS-1: Inventory CORS behaviour and the authentication model](#gt-web-cors-1-inventory-cors-behaviour-and-the-authentication-model)
  - [GT-WEB-CORS-2: Arbitrary Origin reflection](#gt-web-cors-2-arbitrary-origin-reflection)
  - [GT-WEB-CORS-3: Null origin trust](#gt-web-cors-3-null-origin-trust)
  - [GT-WEB-CORS-4: Origin-validation parsing flaws](#gt-web-cors-4-origin-validation-parsing-flaws)
  - [GT-WEB-CORS-5: Trusted subdomains and third-party origins](#gt-web-cors-5-trusted-subdomains-and-third-party-origins)
  - [GT-WEB-CORS-6: Insecure-scheme origins on HTTPS endpoints](#gt-web-cors-6-insecure-scheme-origins-on-https-endpoints)
  - [GT-WEB-CORS-7: Wildcard responses, non-credentialed data and internal hosts](#gt-web-cors-7-wildcard-responses-non-credentialed-data-and-internal-hosts)
  - [GT-WEB-CORS-8: Preflight policy and requests that skip the preflight](#gt-web-cors-8-preflight-policy-and-requests-that-skip-the-preflight)
  - [GT-WEB-CORS-9: Vary: Origin and cache behaviour](#gt-web-cors-9-vary-origin-and-cache-behaviour)
  - [GT-WEB-CORS-10: Confirm a credentialed read with a local proof-of-concept page](#gt-web-cors-10-confirm-a-credentialed-read-with-a-local-proof-of-concept-page)
  - [GT-WEB-CORS-11: JSONP and callback parameters](#gt-web-cors-11-jsonp-and-callback-parameters)
  - [GT-WEB-CORS-12: Script inclusion of dynamic JavaScript and data responses](#gt-web-cors-12-script-inclusion-of-dynamic-javascript-and-data-responses)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Node.js and Express](#nodejs-and-express)
  - [Django](#django)
  - [Spring](#spring)
  - [Laravel](#laravel)
  - [Reverse proxies and CDNs](#reverse-proxies-and-cdns)
  - [Retiring JSONP](#retiring-jsonp)
  - [Serving data so it cannot run as script](#serving-data-so-it-cannot-run-as-script)
  - [Regression tests](#regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### The same-origin policy and what CORS relaxes

An origin is the triple **scheme, host, port**: `https://app.example.com` and `https://api.example.com` are different origins, and so are `http://app.example.com` and `https://app.example.com:8443`. The same-origin policy (SOP) lets a page on one origin **send** requests almost anywhere (links, forms, images, scripts, `fetch()`), but it stops the page from **reading** a response that came from another origin. That split is the key to this whole note:

| The browser lets a page on origin A... | Without CORS | What CORS changes |
|---|---|---|
| Send a GET or a form-style POST to origin B, with B's cookies if their `SameSite` attribute allows | Yes | Nothing; the request goes out either way |
| Send a request with a JSON body, a `PUT`/`DELETE`, or a custom header such as `Authorization` | Only after a preflight that B approves | The preflight is part of CORS; B decides |
| Read the status, headers and body of B's response from JavaScript | No | Yes, if B's response names A (or `*`) in `Access-Control-Allow-Origin` |
| Read B's response to a request that carried B's cookies | No | Yes, only if B also sends `Access-Control-Allow-Credentials: true` and names A exactly |
| Run B's response as a script with a script tag | Yes, always | Nothing; script inclusion predates CORS and is not governed by it |

CORS is therefore an **opt-in relaxation of read protection**, decided by the server that owns the data and enforced by the browser. It is defined in the [CORS protocol section of the WHATWG Fetch Standard](https://fetch.spec.whatwg.org/#http-cors-protocol), which replaced the retired W3C CORS specification. A CORS misconfiguration is a server that hands that read permission to origins it should not trust. It is never a defence against requests being sent: an endpoint that changes state on a cross-site POST is a CSRF problem whatever its CORS headers say, and is covered in Session Management (not written yet).

Two consequences that trip people up:

- **The `Origin` header is trustworthy only inside a browser.** Page JavaScript cannot set it (it is a forbidden request header), so the browser's value is reliable for deciding whether to hand a response to a page. Outside a browser anyone can send any `Origin`, which is fine: a curl user reading their own data with their own cookies is not an attack. CORS protects users from other websites, not servers from clients. Access control still has to happen in the application.
- **The server always sends the full response.** The browser withholds it from the page when the headers do not allow the read. That is why curl alone can show you the policy, but only a browser can prove whether the read actually works ([GT-WEB-CORS-10](#gt-web-cors-10-confirm-a-credentialed-read-with-a-local-proof-of-concept-page)).

### Simple requests, preflights and credentials

The browser sorts cross-origin `fetch()`/XHR requests into two kinds.

A **simple request** goes out directly. MDN's CORS guide lists the conditions: method `GET`, `HEAD` or `POST`; only CORS-safelisted request headers set by the page (`Accept`, `Accept-Language`, `Content-Language`, `Content-Type`, and a single-range `Range`); and a `Content-Type` of `application/x-www-form-urlencoded`, `multipart/form-data` or `text/plain`. These are the requests an HTML form could always send, so the server sees them even if it later refuses the read.

Anything else first triggers a **preflight**: an `OPTIONS` request, without cookies, that asks permission.

```http
OPTIONS /api/v1/me/settings HTTP/1.1
Host: api.example.com
Origin: https://app.example.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: content-type, x-csrf-token
```

```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, PUT
Access-Control-Allow-Headers: content-type, x-csrf-token
Access-Control-Max-Age: 600
Vary: Origin
```

Only if the preflight approves the origin, method and headers does the browser send the real `PUT`. `Access-Control-Max-Age` lets the browser cache that approval (MDN: default 5 seconds, capped by each browser's own maximum).

**Credentials** are cookies, HTTP authentication and TLS client certificates. A cross-origin `fetch()` sends them only when the page asks (`credentials: "include"`; XHR `withCredentials = true`), and the browser then applies stricter rules to the response. A bearer token in an `Authorization` header is *not* an ambient credential: the attacker's page does not have the victim's token, so it cannot attach it. That one fact decides many CORS findings (see [Signals and false positives](#signals-and-false-positives)).

### What the browser checks in the response

For the page to read a response, the browser requires:

| Request | Response must contain | Notes |
|---|---|---|
| Without credentials | `Access-Control-Allow-Origin: *` or the exact requesting origin | `*` means any page can read it; fine for genuinely public data |
| With credentials | `Access-Control-Allow-Origin: <exact origin>` **and** `Access-Control-Allow-Credentials: true` | The Fetch Standard: with credentials mode "include", `Access-Control-Allow-Origin` cannot be `*`; `Allow-Methods`, `Allow-Headers` and `Expose-Headers` only act as wildcards without credentials |
| Any | Optionally `Access-Control-Expose-Headers` | Without it, page JavaScript sees only the CORS-safelisted response headers |

`Access-Control-Allow-Origin` holds exactly one origin, `*` or `null`. It cannot list several origins or contain a pattern such as `https://*.example.com` (PortSwigger's page on the header calls that invalid). So any application that trusts more than one origin must choose the value per request from the request's `Origin`. That per-request code is where nearly every CORS bug lives.

### Cookies, SameSite and why the browser matters

CORS decides whether the page can read the response. Whether the victim's session cookie is sent at all is decided by cookie rules, and they have changed a lot since the classic CORS research:

- **`SameSite`.** A cookie marked `SameSite=Lax` or `Strict` (and, in Chromium-based browsers, a cookie with no `SameSite` attribute, which is treated as `Lax`) is not sent on a cross-**site** `fetch()`. "Site" means the registrable domain: `https://partner.example.org` → `https://api.example.com` is cross-site, but `https://blog.example.com` → `https://api.example.com` is **same-site**, and `Lax` and `Strict` cookies go with it. This is why trusted-subdomain CORS bugs are often more exploitable today than trusted-anything bugs.
- **Third-party cookie policies.** Even a `SameSite=None; Secure` cookie can be withheld in a third-party context. At the time of writing, Chrome still sends third-party cookies by default, Firefox partitions them per top-level site (Total Cookie Protection), so the first-party session cookie is not sent, and Safari blocks them. MDN's CORS guide notes that third-party cookie policies can stop credentialed requests even when the server permits them. WSTG-CLNT-13 makes the same point for XSSI.

So for every CORS or XSSI finding you record the cookie attributes and the browser in which the read worked. A permissive policy on an API whose session cookie is `SameSite=Lax` is still a finding (the policy is wrong, and same-site origins can use it), but the severity moves.

### Script inclusion: the older hole CORS does not cover

A script tag can load a script from any origin, and the browser sends the user's cookies with it (subject to the same `SameSite` and third-party rules). The page cannot read the script's source, but the script **runs in the including page's context**. If the response is executable JavaScript that contains user data, the including page can watch what the script does: read the global variables it sets, define the function it calls, or override built-in prototypes it uses. That is XSSI. WSTG-CLNT-13 lists four data-leak vehicles: global variables, global function parameters, CSV data with quotes that can be made to parse as script, and prototype overrides reached through `this`.

**JSONP** is the deliberate version: the endpoint wraps JSON in a function call named by a query parameter (`?callback=handle` returns `handle({...})`), so a page on another origin can define `handle` and receive the data. It was the cross-origin workaround before CORS existed. When the JSON is user-specific and the request carries cookies, *any* site can read it.

Sebastian Lekies, Ben Stock, Martin Wentzel and Martin Johns measured the problem in [The Unexpected Dangers of Dynamic JavaScript](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/lekies) (USENIX Security 2015): of 150 top-ranked domains, about a third (49 domains, 209 unique scripts) served JavaScript whose content depended on the user's session, and the abstract reports that more than 80% of the sites were susceptible to attacks through remote script inclusion. The paper also warns that moving inline scripts into external files (a common CSP migration step) can widen this attack surface when those scripts carry user data.

### Browser-side read protections: nosniff, CORB and ORB

Browsers no longer run just anything as script:

- **`X-Content-Type-Options: nosniff`.** For a script destination, the browser refuses the response unless its `Content-Type` is a JavaScript MIME type (MDN). A JSON API served as `application/json` with `nosniff` cannot be run as a script. ASVS `v5.0.0-3.4.4` (L2) requires `nosniff` on all responses.
- **CORB and ORB.** Cross-Origin Read Blocking (CORB) was Chromium's heuristic for stopping cross-origin "no-cors" loads (script, image) from pulling HTML, XML and JSON responses into the renderer process. Opaque Response Blocking (ORB) is its successor and the version being standardised through the Fetch Standard. At the time of writing, Chromium has shipped ORB in stages (blink-dev intent-to-ship threads for ORB v0.1 and v0.2), and the Firefox tracking bug was still open; check current browser status rather than relying on either. Both block obvious data responses (JSON with the right type), and neither blocks a response that **is** JavaScript, which JSONP and dynamic scripts are by definition.

The upshot: classic JSON hijacking through `Array` constructor overrides is dead in modern browsers (Django's `JsonResponse` documentation still explains why it refuses non-dict data by default), but JSONP endpoints and authenticated JavaScript files with user data are as exposed as ever. That is why ASVS `v5.0.0-3.5.6` (L3) bans JSONP and `v5.0.0-3.5.7` (L3) keeps authorised data out of script responses.

## What goes wrong

### Reflecting any Origin with credentials

The server copies the request's `Origin` into `Access-Control-Allow-Origin` and adds `Access-Control-Allow-Credentials: true`. James Kettle called this "the single most common CORS vulnerability" in [Exploiting CORS misconfigurations for Bitcoins and bounties](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties) (PortSwigger Research, 2016). It is usually not written on purpose. Developers hit the browser rule that `*` cannot be combined with credentials, and the quickest way to make the console error go away is to echo the origin. Framework settings make it a one-liner:

| Framework | Setting that reflects any origin with credentials |
|---|---|
| Express `cors` | `cors({ origin: true, credentials: true })` |
| django-cors-headers | `CORS_ALLOW_ALL_ORIGINS = True` with `CORS_ALLOW_CREDENTIALS = True` (the middleware then echoes the origin instead of sending `*`) |
| Spring | `allowedOriginPatterns("*")` with `allowCredentials(true)`; `allowedOrigins("*")` with credentials is rejected, so people switch to the pattern form |
| Laravel (`config/cors.php`) | `'allowed_origins' => ['*']` with `'supports_credentials' => true` |

With this in place, any website the victim visits while logged in can read every endpoint that answers with the reflected headers. Where to look: API gateways and BFF layers, older endpoints that pre-date a central CORS config, "debug" or partner profiles that were never removed.

### Trusting the null origin

Browsers send `Origin: null` for requests from opaque origins: a sandboxed iframe without `allow-same-origin`, documents loaded from `data:` URLs, local `file://` pages, and some redirect chains. Developers add `null` to the allow-list to make local development or a hybrid app work. Any website can create a sandboxed iframe, so trusting `null` is trusting everyone. Kettle's research found a Bitcoin exchange that trusted `null` and exposed encrypted wallet backups this way. Where to look: allow-lists in config files (`"null"` as a string), mobile/hybrid back-ends, and code that treats a missing or `null` origin as "same-origin".

### Origin-matching mistakes

When an allow-list has to cover many origins, developers write a matching rule instead of an exact list, and the rule matches more than intended. The common shapes, for an application that means to trust `https://example.com` and its subdomains:

| Check as written | Intended | Also accepts | Why |
|---|---|---|---|
| `origin.endsWith("example.com")` or regex `example\.com$` | `https://app.example.com` | `https://gtprobeexample.com` | No dot or scheme boundary before the trusted name |
| `origin.startsWith("https://example.com")` or regex `^https://example\.com` | `https://example.com` | `https://example.com.example.org` | No end anchor; the trusted name becomes a subdomain label of another domain |
| regex `^https://app.example.com$` | `https://app.example.com` | `https://appxexample.com` | Unescaped `.` matches any character |
| `origin.includes("example.com")` / `indexOf` | any of ours | anything containing the string, including paths in non-browser clients | Substring match |
| Host compared, scheme ignored | `https://app.example.com` | `http://app.example.com` | See [http origins](#trusting-http-origins-from-an-https-site) |
| Parsed with a URL library, then the hostname checked with `endsWith(".example.com")` | subdomains | every subdomain, including abandoned ones | Correct parsing, but the policy is "trust all subdomains" |

Framework documentation can lead you there. The Express `cors` documentation shows `/example\.com$/` as its RegExp example: it is anchored at the end but not at the start, so `https://gtprobeexample.com` matches. django-cors-headers matches `CORS_ALLOWED_ORIGIN_REGEXES` with Python's `re.match`, which anchors only at the start, so a pattern without `$` accepts `https://app.example.com.example.org`. Laravel's `allowed_origins_patterns` are passed to `preg_match`, which anchors nothing unless you write `^` and `$`. Kettle's research lists both a suffix case (a site that trusted `definitelynotadvisor.com`-style names) and a prefix case (`btc.net.evil.net`); Corsy's checks also cover browser-specific characters in hostnames that some parsers accept and others reject. You do not need to collect those variants: one confirmed bypass per rule shows the rule is wrong.

### Trusting every subdomain

`*.example.com` feels like "our own sites", but it makes the API's read protection as strong as the weakest subdomain:

- **XSS on any subdomain** (an old marketing microsite, a support portal, a staging host) lets the attacker run script on a trusted origin, which can then read the API with the user's cookies. Because the subdomain is same-site, `SameSite=Lax` and `Strict` cookies are sent.
- **Subdomain takeover** (a dangling DNS record pointing at a deprovisioned cloud resource) gives the attacker a trusted origin outright.
- **Third-party-hosted subdomains** (status pages, help centres, documentation platforms, landing-page builders) put content from other companies' customers, or other companies' staff, on a trusted origin.

Kettle's research describes this inheritance. Where to look: allow-lists built from a pattern, Spring `allowedOriginPatterns("https://*.example.com")`, django `CORS_ALLOWED_ORIGIN_REGEXES = [r"^https://\w+\.example\.com$"]` (the README's own example, correct as a regex and dangerous as a policy when the API is credentialed), CDN rules that allow `*.example.com`.

### Trusting http origins from an https site

If `https://api.example.com` trusts `http://app.example.com`, an attacker on the victim's network path (public Wi-Fi, a compromised router) can inject a redirect into any plain-HTTP page the victim loads, send the browser to `http://app.example.com`, and inject script into that unencrypted response. That script runs on a trusted origin and reads the HTTPS API with the user's cookies. PortSwigger's CORS topic and Kettle's research both describe it; it defeats HTTPS and `Secure` cookies for the data the API returns. HSTS on the trusted host (ASVS `v5.0.0-3.4.1`, L1), ideally preloaded with `includeSubDomains`, removes most of the attack, but the policy is still wrong and should be fixed.

### Wildcards: what the browser refuses and what it allows

- `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` is **not exploitable as written**: the browser refuses to expose a credentialed response with a wildcard (MDN: the browser blocks access and reports a CORS error), and a non-credentialed request carries no cookies. Report it as a misconfiguration (Info/Low) because it shows the developer intended credentialed cross-origin access, and the next "fix" is usually origin reflection. Retest it after any change.
- `Access-Control-Allow-Origin: *` without credentials is **correct for public data** (open datasets, public catalogues, fonts). ASVS `v5.0.0-3.4.2` (L1) allows it when the response carries no sensitive information. It becomes a finding when the response is sensitive for a reason other than cookies: the API authenticates by network location (an intranet app, an admin interface trusted by source IP, a cloud-internal service reachable from employee laptops), or it returns per-user data based on something ambient that is not a cookie, such as a TLS client certificate.

### Missing Vary: Origin and caches

When the value of `Access-Control-Allow-Origin` depends on the request's `Origin`, the response must carry `Vary: Origin` so that caches keep separate copies. MDN says so, and the Fetch Standard's [CORS protocol and HTTP caches](https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches) section explains why. Without it:

- A CDN or reverse proxy stores the response it saw first. A later request from another origin gets the first origin's header. Usually this breaks legitimate cross-origin clients (an availability bug that gets "fixed" by loosening the policy).
- A response cached in the browser from a non-CORS load (a navigation, a script tag) can be reused for a later CORS request, or the other way round, with the wrong headers.
- Kettle describes client-side cache poisoning: a response that reflects a request header unencoded, sent with CORS headers but without `Vary: Origin`, can be planted in the victim's browser cache and rendered later.

Missing `Vary: Origin` is rarely a confidentiality finding by itself, because shared caches should not be storing personalised, credentialed responses in the first place. When they are, that is a cache problem (web cache deception and poisoning belong to HTTP & Infrastructure, not written yet).

### Preflight gaps

The preflight is where the server approves methods and headers. It goes wrong in four ways:

- **Everything approved.** The preflight reflects `Access-Control-Request-Headers` and `Access-Control-Request-Method` back as allowed (the Express `cors` package reflects requested headers when `allowedHeaders` is not set; Spring copies them when you configure `*`). Combined with a permissive origin, the attacker's page can send any method with any header, including headers the application treats as proof that a request came from its own front end.
- **Preflight and real request handled by different layers.** An API gateway or CDN answers `OPTIONS` with one policy, the application answers the real request with another, or the `OPTIONS` handler is permissive while the real handler adds no CORS headers. Test both legs.
- **Relying on the preflight as a CSRF defence, then accepting simple requests.** A JSON API that only accepts `application/json` is protected from cross-site form posts by the preflight, because a page cannot send that content type without one. If the same endpoint also parses `text/plain` or form-encoded bodies, or honours a method-override parameter on a POST, a cross-site page can send it without any preflight. ASVS `v5.0.0-3.5.2` (L1) requires that functionality protected this way cannot be reached with a request that skips the preflight; `v5.0.0-3.5.1` (L1) requires anti-forgery tokens or non-safelisted headers where the preflight is not relied on. The state-change side of this is CSRF (Session Management); the CORS test is whether the preflight assumption holds.
- **Long `Access-Control-Max-Age` on a permissive preflight.** Browsers cap it, but a policy you tighten may keep being honoured from cache for a while. Check what the cap is in the browsers you care about before you rely on a quick rollback.

### Private network targets

Kettle noted that, without credentials, CORS attacks are usually low impact, with one exception: services that trust the network location. A public website can make the victim's browser fetch `http://10.0.0.5/` and, if that internal service answers `Access-Control-Allow-Origin: *`, read the response. Browsers are closing this: Chrome's earlier Private Network Access proposal (CORS preflights with `Access-Control-Allow-Private-Network`) was put on hold and replaced by **Local Network Access**, which gates public-to-local requests behind a user permission prompt; Chrome's documentation gives Chrome 142 for the prompt. Other browsers differ, and older browsers in a managed estate may have no protection, so internal services should still not send `*` on anything sensitive. You will see the old PNA settings in frameworks (`CORS_ALLOW_PRIVATE_NETWORK` in django-cors-headers, `allowPrivateNetwork` in Spring's `CorsConfiguration`); Chrome's guidance is that new code should not add PNA handling.

### JSONP endpoints

Any endpoint that wraps its output in a caller-named function is readable from every origin. Look for `callback`, `cb`, `jsonp`, `jsoncallback`, `_callback` parameters; responses typed `application/javascript` or `text/javascript` that start with an identifier and a parenthesis; old jQuery `$.ajax({ dataType: "jsonp" })` calls in bundles; analytics, comments, search-suggest and "widget" endpoints; and framework support that is still switched on (Express `res.jsonp()`; in Spring, `AbstractJsonpResponseBodyAdvice` and the JSONP option of `MappingJackson2JsonView`, deprecated in 5.0.7 after [CVE-2018-11040](https://spring.io/security/cve-2018-11040) and removed in 5.1, so finding them tells you how old the code is). Two separate problems live here:

- **Data exposure.** If the response depends on the session, any page can read it. ASVS `v5.0.0-3.5.6` (L3) says JSONP should not be enabled anywhere.
- **Callback injection.** If the callback name is not restricted to a safe identifier, the parameter controls the start of a JavaScript response. That can become reflected content in a script context, and a same-origin JSONP endpoint is also a well-known way to get around a CSP that trusts the host. The XSS side is covered in [Reflected and stored XSS](/web/web-reflected-stored-xss/) and the CSP side in [Content Security Policy and headers](/web/web-content-security-policy-headers/).

### Authenticated data in JavaScript and script-parsable responses

The quieter XSSI cases:

- **Server-generated JavaScript with user data**: `/js/config.js` or `/bootstrap.js` that sets `window.currentUser = {...}`, an API key, a CSRF token, feature flags tied to the account. Any page can include it and read the globals.
- **Scripts that call a global function or a built-in with the data**, so a page that defines the function or overrides `Array.prototype.forEach` receives it (WSTG-CLNT-13's examples, from Lekies' demonstration page).
- **Responses that are accidentally valid JavaScript**: JSON with a wrong or missing content type and no `nosniff`; CSV exports with attacker-influenced quoted fields (Takeshi Terada's [Identifier based XSSI attacks](https://www.mbsd.jp/Whitepaper/xssi.pdf) whitepaper, MBSD, 2015, which also covers older charset tricks such as forcing UTF-16).
- **Data embedded in templates for the SPA to pick up**, then moved to an external script during a CSP migration (the Lekies paper's warning).

ASVS `v5.0.0-3.5.7` (L3) asks that data requiring authorisation is not put in script resources at all, and `v5.0.0-3.5.8` (L3) asks that authenticated resources can only be loaded cross-origin when intended, using `Sec-Fetch-*` checks or `Cross-Origin-Resource-Policy`.

## Testing

Every test here assumes an authorised engagement with written scope, a bug bounty programme whose rules allow it, or a lab. Responses and outputs shown are illustrative.

### Before you start

**Scope and accounts.** Agree the hosts and API base paths in scope, and whether third-party-hosted subdomains are in scope (usually not: you test whether the API *trusts* them, never the subdomains themselves). You need your own test account on the application, ideally two (user A and user B), so that you can tell user-specific data from shared data. Every proof reads **your own** account's data in **your own** browser. If a response unexpectedly shows another person's data, stop that line of testing, keep only the minimum redacted evidence (endpoint, status, one masked field), do not request more, and report it immediately.

**Cookie and session facts.** Before testing, record how the application authenticates API calls and the attributes of the session cookie:

| Fact | Where to read it | Why it matters |
|---|---|---|
| Cookie or bearer token | Burp history: is there a `Cookie` header or an `Authorization` header on API calls? | Bearer tokens are not sent by the browser automatically, so a permissive CORS policy alone does not expose token-authenticated data |
| `SameSite` value | `Set-Cookie` at login | `None` → cross-site reads possible; `Lax`/`Strict`/absent → only same-site origins (subdomains) can use the session |
| `Secure`, `HttpOnly`, `__Host-` prefix | `Set-Cookie` | `http` origin attacks need the cookie to be sent to the HTTPS API, not to the http page; `HttpOnly` stops script reading the cookie, not CORS reads |
| Registrable domain | Host names in scope | Which origins are same-site with the API |

**Browser.** Run proofs in a separate Chromium profile used only for testing, logged into your test account, with no other sessions. Chromium matters because, at the time of writing, it is the major browser that still sends third-party cookies by default; a proof that only fails in Firefox or Safari because of cookie partitioning or blocking still documents a server-side flaw.

**Proxy.** One Burp project per engagement with the target scope set; Logger on. Two habits make CORS testing fast:

- A **Proxy match-and-replace rule** that adds `Origin: https://gt-cors-probe.example.org` to requests in scope, plus a Logger or HTTP-history filter on responses containing `Access-Control-Allow-Origin`. Every endpoint that reflects your probe shows up while you walk the application normally. Switch the rule off for state-changing requests if the application rejects unknown origins on POST (Django's CSRF middleware verifies `Origin` against the host and `CSRF_TRUSTED_ORIGINS` on unsafe-method requests, for example); otherwise you are testing your rule, not the app.
- Repeater tabs per endpoint with the `Origin` header as the only variable.

**The probe origins in this note are placeholders.** `https://gt-cors-probe.example.org`, `https://gtprobeexample.com` and similar stand for names *you* control. A curl request with an `Origin` header never contacts that host, so nothing needs to resolve or be registered for tests 2 to 9. The browser proof in test 10 maps the probe name to `127.0.0.1` in your own hosts file and serves the page locally. Never use a domain that belongs to someone else.

**Proof-of-concept pages.** Local HTML files, opened in your own browser, against your own account. They display what was readable on the page itself and **send nothing anywhere**: no second request, no logging endpoint, no collaborator. Show field names and masked values, not full records. No deceptive pages and nothing aimed at real users.

**Rate.** These tests need a handful of requests per endpoint. Keep to one or two requests per second; tools such as Corsy accept a delay (`-d`) and a thread count (`-t`), which you set to `1`.

### Signals and false positives

The signal is never "a CORS header is present". It is: *a page on an origin the attacker controls can read a response that contains something the attacker should not have.* Rule out these before you report:

| Looks like | Why it may not be a finding | How to tell |
|---|---|---|
| `Access-Control-Allow-Origin` reflects anything, no `Access-Control-Allow-Credentials` | Without credentials the browser sends no cookies; the attacker can only read what they could fetch themselves | Is the response identical with and without your session? Is it public? Is the API IP-restricted or internal? |
| Reflection with credentials on a **bearer-token** API | The attacker's page has no token to send | Check for a cookie that also authenticates (some SPAs accept both); if only `Authorization` works, report as hardening |
| Reflection with credentials, cookie is `SameSite=Lax` or `Strict` | Cross-site origins cannot use the session | Still a finding: same-site origins can, and the policy is one cookie change from exploitable. Rate with `AC:H` or lower |
| `*` with credentials | The browser refuses it | Confirm in the browser console; report as Info/Low and retest after fixes |
| Reflected origin on an error page or a 401 | Nothing sensitive to read | Repeat with a valid session; check whether the authenticated response gets the same headers |
| Endpoint that needs a custom header or a JSON body | The browser must preflight it; if the preflight refuses your origin, the real request never goes out | Test the `OPTIONS` response for your origin separately ([GT-WEB-CORS-8](#gt-web-cors-8-preflight-policy-and-requests-that-skip-the-preflight)) |
| Public data with `*` | Correct use | ASVS `v5.0.0-3.4.2` allows `*` when nothing sensitive is returned |
| CDN-cached CORS headers from someone else's request | You are seeing the cache, not the origin's logic | `Age`, `X-Cache`, `CF-Cache-Status`; repeat with a cache-busting parameter |
| JSONP endpoint returning only public data | Readable by design | Compare the response with and without your session (test 11) |
| JavaScript file that differs per session only by a nonce or build hash | Not user data | Diff the two sessions' versions; look for names, emails, IDs, tokens |

### GT-WEB-CORS-1: Inventory CORS behaviour and the authentication model

*Guler Tech methodology.* Implements the identification step of WSTG-CLNT-07 (identify endpoints that implement CORS) and the data-collection step of WSTG-CLNT-13.

#### What it checks

Which hosts and endpoints emit CORS headers, under which conditions, how API calls authenticate, and which responses carry user-specific data. The output is the work list for every later test.

#### Prerequisites

A logged-in test account; the Burp match-and-replace rule from [Before you start](#before-you-start); API documentation or a Postman/OpenAPI collection if the client provides one.

#### Steps

1. Walk every feature with Logger on and the probe-origin rule enabled. Include the SPA, the API host, admin hosts in scope, file download and export endpoints, and any "widget", "embed" or partner endpoints.
2. Filter history for responses containing `Access-Control-Allow-Origin`. For each, note the value, whether `Access-Control-Allow-Credentials: true` is present, and whether `Vary` includes `Origin`.
3. Send a baseline for each distinct host and API prefix, first without `Origin`, then with the application's own front-end origin:

```bash
curl -s -o /dev/null -D - "https://api.example.com/api/v1/me" \
  -H "Cookie: session=<SESSION_USER_A>"

curl -s -o /dev/null -D - "https://api.example.com/api/v1/me" \
  -H "Cookie: session=<SESSION_USER_A>" \
  -H "Origin: https://app.example.com"
```

4. Record the authentication facts (cookie vs bearer, `SameSite`) from the table in Before you start.
5. Mark which responses are user-specific: repeat a few with user B's session, or without a session, and compare. Those are the responses where a CORS or XSSI read matters.
6. Note the CORS layer: application framework headers, API gateway, CDN edge rules. Different `Server` or `Via` values on `OPTIONS` and `GET` responses suggest that different layers answer them.

#### Observation

A work list (illustrative):

| Endpoint | Auth | User-specific | ACAO for `https://app.example.com` | ACAC | `Vary: Origin` |
|---|---|---|---|---|---|
| `GET /api/v1/me` | cookie, `SameSite=None` | yes | reflected | true | no |
| `GET /api/v1/catalogue` | none | no | `*` | — | — |
| `GET /api/v1/orders` | cookie | yes | reflected | true | yes |
| `GET /js/bootstrap.js` | cookie | yes (sets `window.currentUser`) | none | — | — |
| `GET /api/v1/widgets/feed?callback=` | cookie | yes | none | — | — |

#### Evaluation

No finding by itself. The work list tells you where tests 2 to 12 can produce one: user-specific responses with credentials enabled, script responses that differ by session, and callback parameters.

#### False positives

CORS headers on static assets (fonts, images) are normal. Headers seen only through a cache are re-checked with a cache-buster.

#### Automation

Burp Logger filters; a short script that replays a list of URLs with and without `Origin` and prints the CORS headers. In CI, the equivalent is a header snapshot test per API route ([Regression tests](#regression-tests)).

### GT-WEB-CORS-2: Arbitrary Origin reflection

*Guler Tech methodology.* Implements WSTG-CLNT-07 (CORS misconfiguration: dynamic CORS policy, reflected origin).

#### What it checks

Whether the server echoes an origin it has no reason to trust, with or without credentials.

#### Prerequisites

Test 1's work list; a valid session for user A.

#### Steps

1. Send the user-specific request with an unrelated probe origin:

```http
GET /api/v1/me HTTP/1.1
Host: api.example.com
Origin: https://gt-cors-probe.example.org
Cookie: session=<SESSION_USER_A>
```

```bash
curl -s -D - -o /dev/null "https://api.example.com/api/v1/me" \
  -H "Origin: https://gt-cors-probe.example.org" \
  -H "Cookie: session=<SESSION_USER_A>" | grep -i '^access-control\|^vary'
```

2. Repeat without the cookie, so you know whether the policy differs for anonymous requests.
3. Repeat on one endpoint per controller or API prefix; reflection is usually global, but not always.
4. For each reflecting endpoint that needs a preflight in real use (JSON bodies, `PUT`, custom headers), run test 8's `OPTIONS` check with the same origin.

#### Observation

Vulnerable:

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Access-Control-Allow-Origin: https://gt-cors-probe.example.org
Access-Control-Allow-Credentials: true

{"id":"u_1042","email":"gt-user-a@example.org","name":"GT Test A","api_key":"<REDACTED>"}
```

Correct: no `Access-Control-Allow-Origin` header for the probe (or the fixed value of the application's own front end), so the browser refuses the read.

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Vary: Origin

{"id":"u_1042","email":"gt-user-a@example.org","name":"GT Test A","api_key":"<REDACTED>"}
```

#### Evaluation

- **Fail (finding):** the probe origin is reflected with `Access-Control-Allow-Credentials: true` on a response that contains user-specific or sensitive data, and the API accepts cookie authentication. Confirm in the browser with test 10 before you rate it High.
- **Fail (lower):** reflection without credentials on data that is protected by network location or other ambient context (see test 7).
- **Pass:** the probe is never reflected, or it is reflected only on public, non-credentialed responses.

#### False positives

See [Signals and false positives](#signals-and-false-positives): bearer-only APIs, `SameSite=Lax` cookies (lower severity, not a pass), error responses, public data.

#### Automation

Corsy (`python3 corsy.py -u https://api.example.com/api/v1/me --headers "Cookie: session=<SESSION_USER_A>" -t 1 -d 1`) checks reflection and the variants of tests 3 to 6 in one run; treat its severity labels as hints. Burp Scanner reports CORS issues passively when it sees an `Origin` it added reflected. In CI, assert that an untrusted origin never receives `Access-Control-Allow-Origin` ([Regression tests](#regression-tests)).

### GT-WEB-CORS-3: Null origin trust

*Guler Tech methodology.* Implements WSTG-CLNT-07 (allowlisted null origin value).

#### What it checks

Whether `Origin: null` is trusted, which any website can produce with a sandboxed iframe.

#### Prerequisites

Test 1's work list.

#### Steps

1. Send the user-specific request with the literal origin `null`:

```bash
curl -s -D - -o /dev/null "https://api.example.com/api/v1/me" \
  -H "Origin: null" \
  -H "Cookie: session=<SESSION_USER_A>" | grep -i '^access-control'
```

2. Repeat on the preflight for endpoints that need one:

```bash
curl -s -D - -o /dev/null -X OPTIONS "https://api.example.com/api/v1/me/settings" \
  -H "Origin: null" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: content-type"
```

#### Observation

Vulnerable: `Access-Control-Allow-Origin: null` with `Access-Control-Allow-Credentials: true`. Correct: no `Access-Control-Allow-Origin` header.

#### Evaluation

- **Fail:** `null` accepted with credentials on user-specific data; rate like test 2 (it is equivalent to trusting every site). Confirm with the sandboxed-iframe variant of test 10.
- **Fail (Low):** `null` accepted without credentials on non-public data.
- **Pass:** `null` never accepted.

#### False positives

Applications that genuinely serve `file://` clients (some desktop or hybrid apps) may need non-browser access; that is solved with a separate, token-authenticated API, not by trusting `null`. It is still a finding on a cookie-authenticated API.

#### Automation

Corsy's null-origin check; add `"null"` to the untrusted-origin list in your regression tests.

### GT-WEB-CORS-4: Origin-validation parsing flaws

*Guler Tech methodology.* Implements WSTG-CLNT-07 (dynamic CORS policy: incomplete regular expressions).

#### What it checks

Whether the allow-list logic accepts look-alike origins: suffix and prefix matches, unescaped dots, substring checks, wrong scheme or port.

#### Prerequisites

At least one origin the server *does* trust (from test 1, usually the SPA origin `https://app.example.com`). Without a trusted origin there is nothing to mutate.

#### Steps

1. Build a short list from the trusted origin. For `https://app.example.com` (all names are placeholders for names you control; curl never resolves them):

| Probe | Tests for |
|---|---|
| `https://gtprobeexample.com` | suffix match on `example.com` without a dot boundary |
| `https://app.example.com.example.org` | prefix match / missing end anchor |
| `https://appxexample.com` | unescaped dot in `app.example.com` |
| `https://example.org/app.example.com` | substring match (browsers never send a path in `Origin`, so this only shows the check is a substring test; report it as supporting evidence) |
| `http://app.example.com` | scheme ignored (test 6) |
| `https://app.example.com:8443` | port ignored |
| `https://APP.EXAMPLE.COM` | case handling (browsers lower-case hosts; this only shows how the check is written) |

2. Send each with the same request and session, one at a time:

```bash
for o in https://gtprobeexample.com https://app.example.com.example.org https://appxexample.com \
         http://app.example.com https://app.example.com:8443; do
  printf '%-40s ' "$o"
  curl -s -D - -o /dev/null "https://api.example.com/api/v1/me" \
    -H "Origin: $o" -H "Cookie: session=<SESSION_USER_A>" \
    | tr -d '\r' | grep -i '^access-control-allow-origin' || echo "-"
  sleep 1
done
```

3. If the source or configuration is available (grey-box), read the matching code instead of guessing: search for `Access-Control-Allow-Origin`, `CORS_`, `allowedOrigin`, `allowed_origins_patterns`, `origin:` in `cors()` calls, `endsWith`, `startsWith`, `indexOf`, `preg_match`, `re.match`.

#### Observation

Illustrative output:

```text
https://gtprobeexample.com               Access-Control-Allow-Origin: https://gtprobeexample.com
https://app.example.com.example.org      -
https://appxexample.com                  -
http://app.example.com                   Access-Control-Allow-Origin: http://app.example.com
https://app.example.com:8443             -
```

#### Evaluation

- **Fail:** any probe that an attacker could register or control is reflected with credentials on user-specific data. A suffix bypass (`gtprobeexample.com`) or prefix bypass (`app.example.com.example.org`) is exploitable by anyone who buys a domain, so it rates like test 2.
- **Fail (lower):** the scheme is ignored (test 6 rates it) or the port is ignored (needs a service on the trusted host and another port).
- **Pass:** only exact, configured origins are reflected.

#### False positives

Probes that only show *how* the check is written (path, case) are supporting evidence, not separate findings. Report one finding per matching rule, with the bypass that proves it.

#### Automation

Corsy's pre-domain, post-domain and unescaped-dot checks. In code review, a Semgrep rule or grep for regex literals in CORS configuration that lack `^` and `$` or contain an unescaped `.`.

### GT-WEB-CORS-5: Trusted subdomains and third-party origins

*Guler Tech methodology.* Implements WSTG-CLNT-07 (dynamic CORS policy for subdomains), with the subdomain-trust analysis from PortSwigger's CORS topic.

#### What it checks

Whether the API trusts every subdomain (including ones that do not exist), or specific third-party origins, and what that trust inherits.

#### Prerequisites

The list of subdomains in scope and, if the client shares it, their DNS inventory. You do **not** test subdomains that are out of scope; you test what the API accepts.

#### Steps

1. Send a subdomain that cannot exist:

```bash
curl -s -D - -o /dev/null "https://api.example.com/api/v1/me" \
  -H "Origin: https://gt-nonexistent-7f3a.example.com" \
  -H "Cookie: session=<SESSION_USER_A>" | grep -i '^access-control'
```

2. If it is reflected, the rule is "any subdomain". Repeat with a deeper name (`https://a.b.example.com`) to see whether nesting is allowed.
3. Note any third-party origins in the allow-list (from test 1 or from configuration): analytics, chat widgets, partner portals, `*.vercel.app`-style or other shared-hosting domains. A shared hosting suffix in the allow-list means anyone who can deploy there is trusted.
4. With the client, review the subdomains the rule covers: which are hosted by third parties, which have known XSS findings, and whether a subdomain-takeover check is part of the engagement (it belongs to recon and configuration, not written yet). Do not look for XSS on out-of-scope subdomains to prove this finding.
5. Record the cookie `SameSite` value: subdomains are same-site, so `Lax` and `Strict` cookies are sent from them.

#### Observation

Vulnerable: `Access-Control-Allow-Origin: https://gt-nonexistent-7f3a.example.com` with credentials. Partially acceptable: only an explicit list of known subdomains is reflected.

#### Evaluation

- **Fail (Medium by default):** any subdomain or a shared hosting suffix is trusted with credentials on sensitive data. The attacker needs a foothold on one subdomain (XSS, takeover, a third-party-hosted service), so on its own this is `AC:H`.
- **Fail (High or Critical):** the engagement has already shown XSS or a takeover on a covered subdomain; report the chain with the client's permission and rate it as test 2.
- **Pass:** only the specific origins that need access are trusted.

#### False positives

A wildcard limited to a dedicated, tightly controlled zone (for example `https://*.apps.example.com` where only the client's own CI deploys) is a design decision; record it and recommend an explicit list anyway.

#### Automation

Add a random non-existent subdomain to the regression tests' untrusted list. ASVS `v5.0.0-3.5.4` (L2, separate applications on separate hostnames) is the design-level counterpart: the fewer unrelated apps share the trusted space, the less a wildcard inherits.

### GT-WEB-CORS-6: Insecure-scheme origins on HTTPS endpoints

*Guler Tech methodology.* Implements WSTG-CLNT-07 (CORS misconfiguration), using the trusted-insecure-protocol case from PortSwigger's CORS topic.

#### What it checks

Whether an HTTPS API trusts `http://` origins, and whether HSTS on the trusted host makes that unreachable.

#### Prerequisites

A trusted origin from test 1.

#### Steps

1. Send the trusted host with the `http` scheme (test 4 already includes it):

```bash
curl -s -D - -o /dev/null "https://api.example.com/api/v1/me" \
  -H "Origin: http://app.example.com" \
  -H "Cookie: session=<SESSION_USER_A>" | grep -i '^access-control'
```

2. Check HSTS on the trusted host and its parent: `Strict-Transport-Security` header, `max-age`, `includeSubDomains`, and whether the registrable domain is on the browser preload list.
3. Check whether `http://app.example.com` answers at all on port 80 (a redirect to HTTPS is still a response a network attacker can replace if HSTS does not cover the host).

#### Observation

Vulnerable: `Access-Control-Allow-Origin: http://app.example.com` with credentials, and no HSTS (or HSTS without `includeSubDomains` for a trusted subdomain).

#### Evaluation

- **Fail (Medium):** an `http` origin is trusted with credentials on sensitive data. Exploitation needs a network position (`AV:A`, `AC:H`).
- **Fail (Low):** the same, but the trusted host has preloaded HSTS; the remaining risk is browsers that never saw the policy.
- **Pass:** only `https` origins are trusted.

#### False positives

Local development origins (`http://localhost:3000`) in a *production* allow-list are still a finding (any local process or page on the victim's machine can use them), but rate them Low.

#### Automation

Regression test: `http://` variants of every allowed origin are refused.

### GT-WEB-CORS-7: Wildcard responses, non-credentialed data and internal hosts

*Guler Tech methodology.* Implements WSTG-CLNT-07 (wildcard `Access-Control-Allow-Origin`) and checks ASVS `v5.0.0-3.4.2`.

#### What it checks

Whether responses sent with `Access-Control-Allow-Origin: *` are really public, whether `*` is combined with credentials, and whether internal or IP-restricted services send `*`.

#### Prerequisites

Test 1's work list; for internal services, a test position inside the client's network or VPN agreed in the scope.

#### Steps

1. For every response with `*`, request it with and without a session and compare:

```bash
curl -s "https://api.example.com/api/v1/catalogue?page=1" -o anon.json
curl -s "https://api.example.com/api/v1/catalogue?page=1" -H "Cookie: session=<SESSION_USER_A>" -o user-a.json
diff <(jq -S . anon.json) <(jq -S . user-a.json) && echo "identical: public"
```

2. Note any response that has both `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true`.
3. For internal services in scope (intranet apps, admin consoles reachable only from the office or VPN, internal APIs), check whether they send `*` or reflect origins, and whether they authenticate at all beyond network location:

```bash
curl -s -D - -o /dev/null "http://10.20.0.15:8080/api/status" -H "Origin: https://gt-cors-probe.example.org"
```

4. Do not prove internal reads by making a browser scan internal address ranges. Record the header, the data the endpoint returns, and the browser landscape (which browsers and versions the client's staff use; Local Network Access in current Chrome prompts the user before a public page reaches a local address).

#### Observation

Public by design: identical responses, nothing user-specific. Finding: an internal service returning staff names, configuration or health details with `*` and no authentication.

#### Evaluation

- **Pass:** `*` only on public, non-personalised responses.
- **Fail (Info/Low):** `*` with `Access-Control-Allow-Credentials: true`. Not exploitable as written; the intent is wrong and it tends to turn into reflection.
- **Fail (Low to Medium):** sensitive data on an internal or IP-trusted service with `*`; rate on the data, with `AC:H` because the victim must be on the internal network and the browser must allow the request.
- **Fail (High):** a non-credentialed response that is sensitive because it is personalised by something ambient other than cookies (client certificates, network-bound identity).

#### False positives

Responses whose only "sensitive" content is what any anonymous user can already fetch.

#### Automation

A CI check that fails the build when a route marked authenticated returns `Access-Control-Allow-Origin: *`.

### GT-WEB-CORS-8: Preflight policy and requests that skip the preflight

*Guler Tech methodology.* Implements WSTG-CLNT-07 (Access-Control-Request-Method/Headers and their responses) and checks ASVS `v5.0.0-3.5.1` and `v5.0.0-3.5.2`.

#### What it checks

What the preflight approves for an untrusted origin; whether the preflight and the real request are governed by the same policy; and whether functionality that relies on the preflight can be reached with a simple request that never triggers one.

#### Prerequisites

Endpoints from test 1 that use JSON bodies, non-GET methods or custom headers. For the simple-request check, an endpoint that changes a harmless field on **own test objects only** (your own display name or a preference), set back to its original value afterwards.

#### Steps

1. Preflight with the probe origin and an unusual method and header:

```bash
curl -s -D - -o /dev/null -X OPTIONS "https://api.example.com/api/v1/me/settings" \
  -H "Origin: https://gt-cors-probe.example.org" \
  -H "Access-Control-Request-Method: DELETE" \
  -H "Access-Control-Request-Headers: x-gt-probe, x-requested-with, content-type"
```

2. Repeat with the trusted origin. Compare: is the origin check the same as on the real request (test 2)? Are requested headers and methods reflected?
3. Note `Access-Control-Max-Age` on permissive preflights.
4. Simple-request check (**own test objects only**): send the JSON body the SPA normally sends, but with a CORS-safelisted content type and no custom headers, as a cross-site form could:

```http
POST /api/v1/me/preferences HTTP/1.1
Host: api.example.com
Origin: https://gt-cors-probe.example.org
Cookie: session=<SESSION_USER_A>
Content-Type: text/plain;charset=UTF-8

{"newsletter":false}
```

   Then try the form-encoded equivalent (`newsletter=false`) and, if the framework supports method override, `_method=PUT` in a form body. Use the value the field already has, or restore it straight after.

5. If the API requires a custom header (`X-Requested-With`, `X-CSRF-Token`) as its CSRF defence, send the simple request without it and confirm it is refused.

#### Observation

Permissive preflight (illustrative):

```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://gt-cors-probe.example.org
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: DELETE
Access-Control-Allow-Headers: x-gt-probe, x-requested-with, content-type
Access-Control-Max-Age: 86400
```

Preflight bypass: the `text/plain` POST returns `200` and the preference is saved, although the SPA only ever sends `application/json`.

#### Evaluation

- **Fail:** the preflight approves an untrusted origin; rate together with the real-request result from tests 2 to 6 (a permissive preflight widens what the attacker can call: write methods, custom headers).
- **Fail:** preflight and real request disagree in a way that allows more than intended (preflight permissive at the gateway, real request also reflecting).
- **Fail (ASVS `v5.0.0-3.5.2`):** a state-changing endpoint that relies on the preflight accepts a simple request. Report the CORS assumption here and the CSRF impact under Session Management.
- **Pass:** untrusted origins get no CORS headers on `OPTIONS`; allowed methods and headers are an explicit list; simple-request variants are refused with `415` or `400`, or a non-safelisted header or token is enforced.

#### False positives

A preflight that reflects requested headers for a *trusted* origin is a hardening point, not a vulnerability. A `text/plain` request that is accepted but ignored (no state change) is a pass; check the stored value, not just the status code.

#### Automation

Regression tests that send `OPTIONS` with an untrusted origin and a `text/plain` POST to each state-changing route and expect refusal.

### GT-WEB-CORS-9: Vary: Origin and cache behaviour

*Guler Tech methodology.* Implements WSTG-CLNT-07 (CORS header review), using the caching guidance in the Fetch Standard and MDN.

#### What it checks

Whether responses whose `Access-Control-Allow-Origin` depends on the request carry `Vary: Origin`, and whether a cache in front of the application mixes CORS headers between origins.

#### Prerequisites

Endpoints with a dynamic `Access-Control-Allow-Origin` from test 1; knowledge of any CDN or reverse proxy in front (headers such as `Via`, `X-Cache`, `CF-Cache-Status`, `Age`).

#### Steps

1. Check `Vary` on each dynamic-CORS response (tests 2 to 6 already print it).
2. If a shared cache is in front, use a **unique cache-buster** so you only ever touch a cache entry that no real user requests, and only on a **public, non-credentialed** endpoint:

```bash
cb="gtcb-$(date +%s)"
curl -s -D - -o /dev/null "https://api.example.com/api/v1/catalogue?cb=$cb" -H "Origin: https://app.example.com" | grep -i '^access-control-allow-origin\|^vary\|^age\|^x-cache'
curl -s -D - -o /dev/null "https://api.example.com/api/v1/catalogue?cb=$cb" -H "Origin: https://partner.example.org" | grep -i '^access-control-allow-origin\|^vary\|^age\|^x-cache'
```

3. Check whether authenticated, user-specific responses are cacheable at all (`Cache-Control: private` or `no-store` expected).

#### Observation

Mixed headers: the second request, from `https://partner.example.org`, receives a cached `Access-Control-Allow-Origin: https://app.example.com` with `Age: 3`. Correct: `Vary: Origin` and a fresh, origin-specific header.

#### Evaluation

- **Fail (Low):** dynamic `Access-Control-Allow-Origin` without `Vary: Origin`; higher only when a cache demonstrably stores personalised responses (then report the caching flaw, which is the bigger issue).
- **Pass:** `Vary: Origin` on every response whose CORS headers depend on the request, and personalised responses are not stored by shared caches.

#### False positives

Static `Access-Control-Allow-Origin: *` or a single fixed origin does not need `Vary: Origin`.

#### Automation

A header assertion in the regression tests. At the CDN, a configuration test that the cache key or `Vary` handling includes `Origin` for CORS routes.

### GT-WEB-CORS-10: Confirm a credentialed read with a local proof-of-concept page

*Guler Tech methodology.* Implements the proof step of WSTG-CLNT-07.

#### What it checks

That the policy found with curl really lets a page on an untrusted origin read your logged-in data **in a browser**, with the real cookie attributes and browser rules applied. This is what separates a header observation from a vulnerability.

#### Prerequisites

A test Chromium profile logged into **your own** test account (user A); a local web server; for name-based bypasses, a hosts-file entry pointing the probe name at `127.0.0.1`.

#### Steps

1. Pick the origin you will serve from, matching what tests 2 to 6 found:

| Finding | Serve the page from | How |
|---|---|---|
| Any origin reflected | `http://localhost:8000` | `python3 -m http.server 8000 --bind 127.0.0.1` in a folder holding only the PoC |
| Suffix/prefix/dot bypass | The probe name, e.g. `https://gtprobeexample.com:8443` | Hosts file `127.0.0.1 gtprobeexample.com`; HTTPS with a locally trusted certificate (for example from mkcert) when the rule requires `https`; use port 443 if the rule also checks the port |
| `null` trusted | Any local page with a sandboxed iframe (below) | Same local server |
| `http` origin trusted | `http://app.example.com:8000` via the hosts file | Shows the policy only; the real attack needs a network position, which you describe, not perform |

2. Save this page as `gt-cors-10.html` and open it from the chosen origin:

```html
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>GT-CORS-10 local read check</title></head>
<body>
  <h1>GT-CORS-10: credentialed cross-origin read check</h1>
  <p>Page origin: <code id="origin"></code> | Target: <code id="target"></code></p>
  <pre id="out">running...</pre>
  <script>
    // Local proof only. Reads YOUR test account's data and shows masked values on this page.
    // It makes no other request and sends nothing anywhere.
    const TARGET = "https://api.example.com/api/v1/me";
    const out = document.getElementById("out");
    document.getElementById("origin").textContent = location.origin;
    document.getElementById("target").textContent = TARGET;
    const mask = (v) => (v.length > 4 ? v.slice(0, 2) + "... (" + v.length + " chars)" : v);
    fetch(TARGET, { credentials: "include" })
      .then((r) => r.json().then((body) => ({ status: r.status, body })))
      .then(({ status, body }) => {
        const masked = Object.fromEntries(Object.entries(body).map(([k, v]) => [k, mask(String(v))]));
        out.textContent = "READABLE cross-origin, HTTP " + status + "\n" + JSON.stringify(masked, null, 2);
      })
      .catch((e) => {
        out.textContent = "NOT readable from this origin (" + e.name + "). See the console for the CORS error.";
      });
  </script>
</body>
</html>
```

3. For the `null` case, use a sandboxed iframe without `allow-same-origin`, so the frame's requests carry `Origin: null`. The frame shows only the field names it could read:

```html
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>GT-CORS-10 null origin check</title></head>
<body>
  <h1>GT-CORS-10: Origin null check (local only)</h1>
  <iframe sandbox="allow-scripts" width="700" height="160"
    srcdoc="<pre id='out'>running...</pre><script>
      fetch('https://api.example.com/api/v1/me', { credentials: 'include' })
        .then(r => r.json())
        .then(b => { document.getElementById('out').textContent = 'READABLE from Origin null. Fields: ' + Object.keys(b).join(', '); })
        .catch(e => { document.getElementById('out').textContent = 'NOT readable: ' + e.name; });
    </script>"></iframe>
</body>
</html>
```

4. Watch DevTools: the Network tab shows the request's `Origin` and whether the `Cookie` header was sent; the Console shows any CORS error. Screenshot the page and the request headers (session cookie redacted).
5. Log out, reload the PoC, and confirm it now shows no user data. That proves the read depended on your session.
6. Delete the hosts-file entry and stop the local server when you are done.

#### Observation

Vulnerable: the page shows "READABLE cross-origin" with your own masked email and ID, and the Network tab shows the session cookie was sent. Not exploitable in this browser: "NOT readable" with a CORS console error, or the request went out without the cookie (check `SameSite` and third-party cookie settings).

#### Evaluation

- **Confirmed:** your own user-specific data is readable from the untrusted origin while logged in, and not after logout. Rate with the table in [Rating findings](#rating-findings).
- **Policy flaw only:** curl shows the permissive headers but the browser does not send the cookie (`SameSite=Lax`/`Strict`, or third-party cookies blocked). Report the policy, state the browser condition, and rate lower; note that a same-site origin (any subdomain) would still be able to read.
- **Not a finding:** the browser blocks the read for a reason that does not depend on settings the client could change tomorrow (for example, the response really carries no `Access-Control-Allow-Origin` for that origin and curl was misleading because of a cache).

#### False positives

Browser extensions that rewrite CORS headers (common on developer machines) make everything readable; use a clean profile. Responses served from the browser's cache can show an older policy; disable the cache in DevTools.

#### Automation

None in the browser; the regression tests cover the headers. Keep the PoC file in the engagement folder, not in any shared or public location.

### GT-WEB-CORS-11: JSONP and callback parameters

*Guler Tech methodology.* Implements WSTG-CLNT-13 (collect data using authenticated and unauthenticated sessions; JSONP) and checks ASVS `v5.0.0-3.5.6`.

#### What it checks

Whether any endpoint returns JSONP, whether its content depends on the session, and whether the callback name is restricted.

#### Prerequisites

Test 1's work list; JavaScript bundles downloaded from the in-scope application for searching.

#### Steps

1. Find candidates: in Burp history, responses with `Content-Type: application/javascript` or `text/javascript` from API paths; parameter names `callback`, `cb`, `jsonp`, `jsoncallback`, `_callback`; in bundles, `dataType: "jsonp"`, `jsonp:` options, `script.src = ... + "callback="`. Also add `callback=gtProbe` to JSON endpoints from test 1: some frameworks enable JSONP on any JSON route when the parameter is present.

```bash
curl -s -D - "https://api.example.com/api/v1/me?callback=gtProbe" -H "Cookie: session=<SESSION_USER_A>" | head -20
curl -s "https://api.example.com/api/v1/me?callback=gtProbe" | head -c 300; echo
```

2. Compare the authenticated and unauthenticated bodies. User-specific content in the authenticated one is the finding.
3. Check the callback name handling with a harmless non-identifier value, for example `callback=gt.probe-1` or `callback=gt%20probe`. Note whether it is reflected verbatim, sanitised, or refused. Testing what an unrestricted callback lets you inject in a script context belongs to the XSS note; here you only record that the restriction is missing.
4. Confirm the read in the browser with a local page that defines the callback and shows only field names:

```html
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>GT-CORS-11 JSONP check</title></head>
<body>
  <h1>GT-CORS-11: JSONP read check (local only)</h1>
  <pre id="out">waiting for callback...</pre>
  <script>
    // Receives the JSONP payload for YOUR test account and lists field names on this page only.
    function gtProbe(data) {
      document.getElementById("out").textContent = "Callback received. Fields: " + Object.keys(data).join(", ");
    }
  </script>
  <script src="https://api.example.com/api/v1/me?callback=gtProbe"></script>
</body>
</html>
```

#### Observation

Vulnerable (illustrative):

```http
HTTP/1.1 200 OK
Content-Type: application/javascript; charset=utf-8

/**/ typeof gtProbe === 'function' && gtProbe({"id":"u_1042","email":"gt-user-a@example.org","plan":"pro"});
```

Correct: the parameter is ignored and the response stays `application/json` with `nosniff`, or JSONP is gone and the endpoint uses CORS with an allow-list.

#### Evaluation

- **Fail (High–Medium):** JSONP returns user-specific, sensitive data with cookie authentication; any site can read it (equivalent to test 2). Confirmed when the local page shows your fields while logged in, and not after logout.
- **Fail (Low):** JSONP enabled but returning only public data; still against ASVS `v5.0.0-3.5.6` (L3) and a CSP bypass gadget on the host.
- **Additional finding:** callback name reflected without restriction to a safe identifier; follow up under XSS and CSP.
- **Pass:** no JSONP anywhere.

#### False positives

A `callback` parameter used for something else (an OAuth redirect, a webhook URL) is not JSONP; check the response type and shape.

#### Automation

A regression test that adds `callback=` to every JSON route and asserts the content type stays `application/json`. Grep the code base for `res.jsonp(`, `jsonp` options and string concatenation of a callback parameter into a response.

### GT-WEB-CORS-12: Script inclusion of dynamic JavaScript and data responses

*Guler Tech methodology.* Implements WSTG-CLNT-13 (determine whether sensitive data can be leaked using JavaScript: global variables, global function parameters, CSV, prototype chaining) and checks ASVS `v5.0.0-3.5.7`, `v5.0.0-3.4.4`, `v5.0.0-3.5.8` and `v5.0.0-4.1.1`.

#### What it checks

Whether script resources contain data that depends on the session, and whether data responses (JSON, CSV, text) could be run as script by another origin because of a wrong `Content-Type` or missing `nosniff`.

#### Prerequisites

User A's and user B's sessions; the Burp extension **DetectDynamicJS** (a passive scanner that re-requests JavaScript without ambient credentials and reports differences) or a manual diff.

#### Steps

1. For every JavaScript response, request it with user A's session, user B's session and no session, and diff:

```bash
curl -s "https://app.example.com/js/bootstrap.js" -H "Cookie: session=<SESSION_USER_A>" > a.js
curl -s "https://app.example.com/js/bootstrap.js" -H "Cookie: session=<SESSION_USER_B>" > b.js
curl -s "https://app.example.com/js/bootstrap.js" > anon.js
sha256sum a.js b.js anon.js
diff a.js b.js | head -40
```

2. In scripts that differ, look for what the WSTG lists: assignments to globals (`window.x =`, top-level `var`), calls to global functions with the data, and built-in methods called on arrays or objects that hold it.
3. For data responses (JSON, CSV, text exports), record `Content-Type`, `X-Content-Type-Options`, `Content-Disposition`, `Cross-Origin-Resource-Policy`, and whether the server checks `Sec-Fetch-Dest`/`Sec-Fetch-Site`:

```bash
curl -s -D - -o /dev/null "https://api.example.com/api/v1/orders/export.csv" \
  -H "Cookie: session=<SESSION_USER_A>" \
  -H "Sec-Fetch-Site: cross-site" -H "Sec-Fetch-Mode: no-cors" -H "Sec-Fetch-Dest: script" \
  | grep -i '^content-type\|^x-content-type-options\|^cross-origin-resource-policy\|^content-disposition\|^http/'
```

4. Confirm a dynamic-script leak in the browser with a local page that lists the globals the script adds, with masked values:

```html
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>GT-CORS-12 script inclusion check</title></head>
<body>
  <h1>GT-CORS-12: XSSI global-variable check (local only)</h1>
  <pre id="out">running...</pre>
  <script>window.gtBefore = new Set(Object.keys(window));</script>
  <script src="https://app.example.com/js/bootstrap.js"></script>
  <script>
    // Lists globals the included script created and masks their values. Nothing is sent anywhere.
    const added = Object.keys(window).filter((k) => !window.gtBefore.has(k) && k !== "gtBefore");
    const show = added.map((k) => {
      const v = JSON.stringify(window[k]) || String(window[k]);
      return k + " = " + v.slice(0, 12) + "... (" + v.length + " chars)";
    });
    document.getElementById("out").textContent = "New globals:\n" + (show.join("\n") || "(none)");
  </script>
</body>
</html>
```

#### Observation

Vulnerable script (illustrative): `bootstrap.js` contains `window.currentUser = {"id":"u_1042","email":"gt-user-a@example.org","csrfToken":"<REDACTED>"}`, differs between users A and B, and the local page lists `currentUser` with your masked values. Vulnerable data response: a JSON or CSV export served as `text/html` or `text/plain` without `nosniff`. Correct: user data reaches the SPA only through a same-origin `fetch()` of an `application/json` response with `nosniff`; scripts are identical for every user.

#### Evaluation

- **Fail (Medium–High):** a script resource carries user-specific sensitive data (PII, tokens, CSRF tokens, API keys) and is sent with cookies cross-site; confirmed by the local page. A leaked CSRF token or API key raises the rating because it unlocks further actions.
- **Fail (Low):** data responses without `nosniff` or with a script-compatible `Content-Type`, with no working inclusion in current browsers (ORB/CORB and type checks may already block it); report against ASVS `v5.0.0-3.4.4` and `v5.0.0-4.1.1`.
- **Pass:** scripts are static, data is served with a correct `Content-Type` and `nosniff`, and authenticated resources reject unexpected cross-site loads (`Sec-Fetch-*` checks or `Cross-Origin-Resource-Policy: same-origin`).

#### False positives

Per-session differences that are not secrets (a CSP nonce, a build hash, a locale string). Scripts that require the session but return the same content for everyone (licence checks) leak only that you are logged in, which is a much smaller issue (login-state detection).

#### Automation

DetectDynamicJS in Burp; in CI, a test that fetches every script route with two different users and asserts identical bodies.

## Secure implementation

### Design rules

- **Do you need CORS at all?** Serving the SPA and the API from the same origin (or putting the API behind the SPA's host with a path prefix) removes the question. CORS is for genuinely cross-origin clients.
- **Exact-match allow-list.** Compare the full `Origin` string (scheme, host, port) against a fixed set. No `endsWith`, no `startsWith`, no substring, no regex unless you cannot avoid it; if you must, anchor both ends and escape every dot. ASVS `v5.0.0-3.4.2` (L1) asks for a fixed value or an allow-list.
- **Never reflect arbitrary origins, never trust `null`,** and never trust `http://` origins from an HTTPS API. Keep `localhost` and staging origins out of the production list (load the list per environment).
- **Separate credentialed and public APIs.** Public data can use `*` without credentials on its own path or host. Credentialed endpoints get the allow-list and nothing else. Do not let one global CORS setting serve both.
- **Explicit methods and headers** on preflights; a modest `Access-Control-Max-Age`.
- **`Vary: Origin`** on every response whose CORS headers depend on the request, including responses that refused the origin, so caches never mix them.
- **Keep CSRF defences.** CORS does not stop requests being sent. If a state-changing endpoint relies on the preflight, reject simple-request content types (ASVS `v5.0.0-3.5.2`); otherwise use tokens or a required non-safelisted header (`v5.0.0-3.5.1`). The detail is in Session Management.
- **No JSONP, no user data in scripts.** Data travels as `application/json` via same-origin or CORS `fetch()`; scripts are static and identical for every user (ASVS `v5.0.0-3.5.6`, `v5.0.0-3.5.7`).
- **Correct types and `nosniff`** on every response (ASVS `v5.0.0-4.1.1`, `v5.0.0-3.4.4`), and refuse unexpected cross-site loads of authenticated resources (`v5.0.0-3.5.8`).
- **One owner for the policy.** Configure CORS in one layer (application or gateway), not both, and test the deployed result, not the config file.

### Node.js and Express

The [`cors` middleware](https://expressjs.com/en/resources/middleware/cors.html) defaults to `origin: "*"` when called without options, reflects the request origin for `origin: true`, and reflects the requested headers on preflights when `allowedHeaders` is not set. Its RegExp example (`/example\.com$/`) is anchored only at the end. Use a function with an exact set:

```javascript
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");

const app = express();
app.use(helmet()); // includes X-Content-Type-Options: nosniff

// Exact origins, per environment. Never "null", never http:// in production.
const ALLOWED_ORIGINS = new Set(
  (process.env.CORS_ALLOWED_ORIGINS || "https://app.example.com,https://admin.example.com").split(",")
);

const credentialedCors = cors({
  origin(origin, callback) {
    // No Origin header: same-origin request or a non-browser client. No CORS headers needed.
    callback(null, Boolean(origin) && ALLOWED_ORIGINS.has(origin));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "X-CSRF-Token"], // explicit: do not reflect requested headers
  maxAge: 600,
});

// Vary on every API response, including refused origins.
app.use("/api", (req, res, next) => { res.vary("Origin"); next(); });
app.use("/api", credentialedCors);

// Public, non-credentialed data on its own prefix.
app.use("/public-api", cors({ origin: "*", methods: ["GET"] }));

// Data is JSON, never JSONP.
app.get("/api/v1/me", requireSession, (req, res) => res.json(publicProfile(req.user)));
```

Replace every `res.jsonp(` with `res.json(` and remove callers that depend on it ([Retiring JSONP](#retiring-jsonp)).

### Django

[django-cors-headers](https://github.com/adamchainz/django-cors-headers) is the usual choice. Place its middleware high, before anything that can generate a response, and keep the allow-list exact:

```python
# settings.py
INSTALLED_APPS = [
    # ...
    "corsheaders",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",      # before CommonMiddleware
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    # ...
]

CORS_ALLOWED_ORIGINS = [
    "https://app.example.com",
    "https://admin.example.com",
]
CORS_ALLOW_CREDENTIALS = True
CORS_URLS_REGEX = r"^/api/.*$"            # CORS only where it is needed
CORS_ALLOW_METHODS = ["GET", "POST", "PUT", "DELETE"]
CORS_ALLOW_HEADERS = ["content-type", "x-csrftoken"]
CORS_PREFLIGHT_MAX_AGE = 600

# Keep Django's own CSRF origin check consistent with the CORS list.
CSRF_TRUSTED_ORIGINS = CORS_ALLOWED_ORIGINS

SECURE_CONTENT_TYPE_NOSNIFF = True        # the default; do not turn it off
```

Pitfalls:

- `CORS_ALLOW_ALL_ORIGINS = True` makes every other origin setting irrelevant (the README calls it dangerous), and with `CORS_ALLOW_CREDENTIALS = True` the middleware echoes the request origin.
- `CORS_ALLOWED_ORIGIN_REGEXES` is matched with `re.match`, which anchors only the start. `r"^https://\w+\.example\.com"` without `$` accepts `https://app.example.com.example.org`; an unescaped dot widens it further. If you need a pattern, write it as tightly as an exact list would be: `r"^https://(app|admin)\.example\.com$"`.
- `"null"` in `CORS_ALLOWED_ORIGINS` is honoured literally. Do not add it.
- The middleware adds `Vary: Origin` to responses on CORS-enabled paths; check it survives any caching middleware or CDN in front.
- Return dictionaries from `JsonResponse` and keep `safe=True`; the documentation explains the old `Array`-constructor attack the default was designed for.

### Spring

With Spring Security, configure CORS through a `CorsConfigurationSource` bean and `http.cors(...)`, so that preflights (which carry no cookies) are handled before authentication, as the Spring Security reference explains:

```java
import static org.springframework.security.config.Customizer.withDefaults;

import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class CorsSecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.cors(withDefaults())               // uses the bean below
            .authorizeHttpRequests(a -> a
                .requestMatchers("/public-api/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration api = new CorsConfiguration();
        api.setAllowedOrigins(List.of("https://app.example.com", "https://admin.example.com"));
        api.setAllowCredentials(true);
        api.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        api.setAllowedHeaders(List.of("Content-Type", "X-XSRF-TOKEN"));
        api.setMaxAge(600L);

        CorsConfiguration publicApi = new CorsConfiguration();
        publicApi.setAllowedOrigins(List.of("*"));   // no credentials
        publicApi.setAllowedMethods(List.of("GET"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/public-api/**", publicApi);
        source.registerCorsConfiguration("/api/**", api);
        return source;
    }
}
```

Pitfalls:

- `@CrossOrigin` with no arguments allows **all origins**, all headers and the mapped methods (credentials off by default). On a credentialed controller, give it explicit `origins`, or leave CORS to the central configuration.
- `allowedOrigins("*")` with `allowCredentials(true)` fails validation (`IllegalArgumentException`), so people switch to `allowedOriginPatterns("*")`, which **does** work with credentials, because it sets `Access-Control-Allow-Origin` to the matched request origin. That is origin reflection.
- `allowedOriginPatterns("https://*.example.com")` trusts every subdomain ([Trusting every subdomain](#trusting-every-subdomain)). Prefer an explicit list.
- Setting `allowedHeaders` or `allowedMethods` to `*` makes Spring copy whatever the preflight asked for.
- `applyPermitDefaultValues()` switches a configuration to "all origins, GET/HEAD/POST, all headers"; it is used under the hood for `@CrossOrigin`.
- Spring Security sends `X-Content-Type-Options: nosniff` by default; keep the headers defaults on.

### Laravel

Laravel handles CORS through the `HandleCors` middleware in the global stack, configured in `config/cors.php` (publish it with `php artisan config:publish cors`). The framework's default file allows every origin, method and header on `api/*` and `sanctum/csrf-cookie`, with credentials off. For a credentialed SPA (for example with Sanctum):

```php
<?php
// config/cors.php

return [
    'paths' => ['api/*', 'sanctum/csrf-cookie'],

    'allowed_methods' => ['GET', 'POST', 'PUT', 'DELETE'],

    // Exact origins only. Wildcards such as 'https://*.example.com' are converted to patterns.
    'allowed_origins' => ['https://app.example.com', 'https://admin.example.com'],

    // Passed to preg_match: anchor both ends and escape dots, or leave empty.
    'allowed_origins_patterns' => [],

    'allowed_headers' => ['Content-Type', 'X-XSRF-TOKEN', 'X-Requested-With'],

    'exposed_headers' => [],

    'max_age' => 600,

    'supports_credentials' => true,
];
```

Pitfalls: `'allowed_origins' => ['*']` together with `'supports_credentials' => true` makes the underlying library echo the request origin; a pattern such as `'/example\.com/'` matches anywhere in the string. Laravel does not add `X-Content-Type-Options` by itself; add it in a small middleware:

```php
<?php
// app/Http/Middleware/SecurityHeaders.php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        return $response;
    }
}

// bootstrap/app.php
// ->withMiddleware(function (Middleware $middleware) {
//     $middleware->append(\App\Http\Middleware\SecurityHeaders::class);
// })
```

### Reverse proxies and CDNs

If the edge sets CORS headers, give it the same exact list and make the application stop setting them (two layers produce duplicate or contradictory headers, which browsers reject or, worse, accept inconsistently). In nginx, a `map` keeps the comparison exact:

```text
# nginx: exact-match CORS at the edge
map $http_origin $cors_origin {
    default                     "";
    "https://app.example.com"   $http_origin;
    "https://admin.example.com" $http_origin;
}

server {
    # ...
    location /api/ {
        add_header Access-Control-Allow-Origin      $cors_origin always;   # empty value = header not sent
        add_header Access-Control-Allow-Credentials "true"       always;
        add_header Vary                             "Origin"     always;
        add_header X-Content-Type-Options           "nosniff"    always;
        proxy_pass http://app_backend;
    }
}
```

Remember that an `add_header` inside a `location` replaces, rather than adds to, the ones inherited from the `server` block. On a CDN, make sure `Origin` is part of the cache key for CORS routes, or that `Vary: Origin` is honoured, and that personalised API responses are not cached at all.

### Retiring JSONP

1. Inventory: find JSONP routes (test 11), log which callers use them (the `callback` parameter in access logs, the `Referer` of those requests) for a few weeks.
2. Give each legitimate caller a CORS route with that caller's origin in an exact allow-list, or move the integration server-side.
3. Remove the JSONP handler. Make the `callback` parameter ignored, not an error that echoes it.
4. Add the regression test that asserts JSON routes never return a script type.

If a JSONP endpoint must survive for a while, restrict it to public data, validate the callback against a strict identifier pattern (for example `^[A-Za-z_$][A-Za-z0-9_$]{0,63}$`), and serve it with `nosniff` and the correct JavaScript type, but treat it as debt: it is still a CSP bypass gadget for the host.

### Serving data so it cannot run as script

- Serve JSON as `application/json; charset=utf-8` and every response with `nosniff`; serve CSV and other downloads with their real type and `Content-Disposition: attachment`.
- Keep scripts static. If the SPA needs the current user, it fetches `/api/v1/me` (same-origin or CORS with an allow-list); the server never writes user data into `.js` files or into inline scripts that might later be externalised.
- Add `Cross-Origin-Resource-Policy: same-origin` (or `same-site`) to authenticated API responses so that cross-origin "no-cors" loads, such as script tags, are blocked by the browser. CORP does not affect CORS `fetch()` requests, which the CORS policy governs.
- Use a Fetch Metadata resource isolation policy (see web.dev's [Protect your resources from web attacks with Fetch Metadata](https://web.dev/articles/fetch-metadata)): reject cross-site requests that are not navigations or CORS requests. For script routes, require `same-origin`:

```javascript
// Express: Fetch Metadata resource isolation policy (simplified)
function resourceIsolation(req, res, next) {
  const site = req.get("Sec-Fetch-Site");
  if (!site) return next();                                   // older browser or non-browser client
  if (site === "same-origin" || site === "none") return next();
  const mode = req.get("Sec-Fetch-Mode");
  const dest = req.get("Sec-Fetch-Dest");
  if (mode === "navigate" && req.method === "GET" && dest !== "object" && dest !== "embed") return next();
  if (mode === "cors") return next();                         // the CORS policy decides who may read
  return res.status(403).type("text/plain").send("Cross-site load refused");
}
app.use(["/api", "/js/private"], resourceIsolation);
```

- Legacy XSSI prefixes such as `)]}',` (which AngularJS's `$http` strips) protected old browsers from JSON hijacking; with correct types, `nosniff` and ORB/CORB they are defence in depth, not a substitute.

### Regression tests

Write the policy down as tests, using the same probe list as the manual tests, and run them against the deployed configuration as well as in unit tests (gateways and CDNs change headers).

```python
# tests/test_cors_policy.py  (pytest + Django test client)
import pytest

UNTRUSTED = [
    "https://gt-cors-probe.example.org", "null",
    "https://gtprobeexample.com", "https://app.example.com.example.org", "https://appxexample.com",
    "http://app.example.com", "https://app.example.com:8443", "https://gt-nonexistent-7f3a.example.com",
]

@pytest.mark.parametrize("origin", UNTRUSTED)
def test_untrusted_origin_gets_no_cors(client_user_a, origin):
    r = client_user_a.get("/api/v1/me", HTTP_ORIGIN=origin)
    assert "Access-Control-Allow-Origin" not in r.headers

@pytest.mark.parametrize("origin", UNTRUSTED)
def test_untrusted_preflight_refused(client, origin):
    r = client.options("/api/v1/me/settings", HTTP_ORIGIN=origin,
                       HTTP_ACCESS_CONTROL_REQUEST_METHOD="PUT",
                       HTTP_ACCESS_CONTROL_REQUEST_HEADERS="content-type")
    assert "Access-Control-Allow-Origin" not in r.headers

def test_trusted_origin_is_exact_and_varies(client_user_a):
    r = client_user_a.get("/api/v1/me", HTTP_ORIGIN="https://app.example.com")
    assert r.headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert "origin" in r.headers.get("Vary", "").lower()

def test_no_jsonp(client_user_a):
    r = client_user_a.get("/api/v1/me", {"callback": "gtProbe"})
    assert r.headers["Content-Type"].startswith("application/json")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert b"gtProbe(" not in r.content

def test_simple_request_content_type_refused(client_user_a):
    r = client_user_a.post("/api/v1/me/preferences", data='{"newsletter": false}', content_type="text/plain")
    assert r.status_code in (400, 415)
```

The same idea with Jest and supertest, plus the XSSI check that scripts do not depend on the user:

```javascript
const request = require("supertest");
const app = require("../app");

const UNTRUSTED = ["https://gt-cors-probe.example.org", "null", "https://gtprobeexample.com",
  "https://app.example.com.example.org", "http://app.example.com"];

test.each(UNTRUSTED)("no CORS headers for %s", async (origin) => {
  const res = await request(app).get("/api/v1/me").set("Origin", origin).set("Cookie", cookieUserA);
  expect(res.headers["access-control-allow-origin"]).toBeUndefined();
});

test("authenticated routes never send a wildcard", async () => {
  const res = await request(app).get("/api/v1/me").set("Origin", "https://app.example.com").set("Cookie", cookieUserA);
  expect(res.headers["access-control-allow-origin"]).toBe("https://app.example.com");
  expect(res.headers["vary"]).toMatch(/origin/i);
});

test("scripts are identical for different users", async () => {
  const a = await request(app).get("/js/bootstrap.js").set("Cookie", cookieUserA);
  const b = await request(app).get("/js/bootstrap.js").set("Cookie", cookieUserB);
  expect(a.text).toEqual(b.text);
});
```

## Practice labs

**PortSwigger Web Security Academy** ([CORS topic](https://portswigger.net/web-security/cors)). The labs ask you to steal an administrator's API key through an exploit server; that is fine in a lab and exactly what your client PoCs must not do.

- [CORS vulnerability with basic origin reflection](https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack) (Apprentice): tests 2 and 10.
- [CORS vulnerability with trusted null origin](https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack) (Apprentice): test 3 and the sandboxed-iframe PoC.
- [CORS vulnerability with trusted insecure protocols](https://portswigger.net/web-security/cors/lab-breaking-https-attack) (Practitioner): tests 5 and 6 together, a trusted `http` subdomain with an XSS.
- CORS vulnerability with internal network pivot attack (Expert, listed on the [CORS labs page](https://portswigger.net/web-security/all-labs#cross-origin-resource-sharing-cors)): the intranet case from test 7, which you describe rather than perform on engagements.

**Build your own XSSI lab.** We did not find a PortSwigger, Juice Shop, crAPI or VAmPI exercise dedicated to XSSI or JSONP at the time of writing. A two-hostname local setup takes minutes: run the Express example from [Node.js and Express](#nodejs-and-express) on `app.example.com` (hosts file → `127.0.0.1`), add a `res.jsonp()` route and a `bootstrap.js` that writes `window.currentUser`, and point the test 11 and 12 pages at it from `localhost`. Switch the cookie between `SameSite=None; Secure` and `Lax` to see how the browser changes the outcome.

**Research demos.** Lekies et al.'s demonstration page (archived, linked from WSTG-CLNT-13) shows the prototype-override variant.

## Real-world cases

- **Bitcoin exchanges and the classic classes (James Kettle, PortSwigger Research, 2016).** One exchange's `/api/requestApiKey` endpoint reflected any origin with credentials, exposing users' API keys (patched within 20 minutes of the report); another trusted origins that merely started with its domain; a third trusted `null`, exposing encrypted wallet backups. The write-up also covers subdomain and `http` trust, caching and intranet pivots. [Exploiting CORS misconfigurations for Bitcoins and bounties](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties).
- **Suffix match (Zomato, 2016).** The policy for `www.zomato.com` accepted any origin ending in `zomato.com`, so a domain like `notzomato.com` was trusted; the reporter suggested requiring the leading dot. Resolved; disclosed June 2017; no bounty shown on the report. [HackerOne report 168574](https://hackerone.com/reports/168574).
- **Look-alike origin with credentials (Zomato, 2018).** Two years later the reflected origin `developersxzomato.com` came back in `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`, a shape consistent with an unescaped dot in a pattern meant for `developers.zomato.com` (our inference from the request and response in the report). Rated Medium (5.9), USD 550 bounty shown; disclosed November 2018. [HackerOne report 426165](https://hackerone.com/reports/426165).
- **Ads portal user data (TikTok, 2020).** A CORS misconfiguration on `ads.tiktok.com` could expose the user IDs and usernames of logged-in users, per the programme's summary. Rated Low (3.7); disclosed December 2020. [HackerOne report 1006524](https://hackerone.com/reports/1006524).
- **JSONP versus privacy settings (Liberapay, 2018).** The `/<username>/charts.json` endpoint supported a JSONP callback, so third-party sites could read a user's donation data even when the user had chosen to hide it. Rated Medium (4.3); disclosed June 2018. [HackerOne report 361951](https://hackerone.com/reports/361951).
- **JSONP on by default (Spring Framework, CVE-2018-11040).** Once `MappingJackson2JsonView` was configured, JSONP was enabled through the `jsonp` and `callback` parameters unless switched off, which Spring's advisory says could expose sensitive user data to third-party browser scripts. Fixed in 5.0.7 and 4.3.18; JSONP support was later removed. [Spring advisory](https://spring.io/security/cve-2018-11040).

More write-ups are collected in [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

Rate on what a page on an attacker-controlled origin can read (or, via a leaked token, do) in a victim's session, and on what the attacker needs first. The factors: whether credentials are honoured and how the API authenticates (cookies vs bearer tokens), the cookie's `SameSite` value and which browsers send it, what kind of origin is trusted (anyone, anyone who registers a domain, anyone with a foothold on a subdomain, someone on the network path), the sensitivity of the readable data (PII, financial data, API keys, CSRF tokens), and whether that data unlocks further actions.

**User interaction and Scope.** Every exploit here needs the victim to visit the attacker's page while logged in, so `UI:R`. Scope is **Unchanged** by default: the vulnerable component is the application's server-side policy, and what is impacted is that same application's data, read through the browser. This differs from XSS, where the FIRST [CVSS v3.1 User Guide](https://www.first.org/cvss/v3.1/user-guide) treats impact on the victim's browser as a scope change, because a CORS or XSSI read does not run code in the victim's session on the vulnerable origin. Use **Scope Changed** only when the leaked data gives access to a different security authority (for example, a leaked key for a separate cloud service). `PR:N`: the attacker needs no account. Use `AC:H` when exploitation depends on conditions outside the attacker's control: a foothold on a trusted subdomain, a network position, or a cookie and browser combination that only some victims have.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Any origin (or `null`, or a registrable look-alike) reflected with credentials; response exposes sensitive user data; cookie sent cross-site | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` (6.5) | Rate above the base score when the data is sensitive at scale (PII, financial); the base score caps at Medium because `UI:R` and no integrity impact |
| As above, and the readable data includes an API key, CSRF token or similar that lets the attacker act as the victim | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (8.1) | Read becomes account takeover or unauthorised actions; describe the chain, do not perform it |
| Permissive policy with credentials, but the session cookie is `SameSite=Lax`/`Strict` or default, so only same-site origins can use it | Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` (5.3) | Exploitable from any subdomain and by any future cookie change; `AC:H` for the condition |
| Every subdomain (or a shared hosting suffix) trusted with credentials, no known foothold | Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` (5.3) | Needs XSS or a takeover on one covered subdomain; rate as the first row if such a foothold is shown |
| `http://` origin trusted with credentials on an HTTPS API, no HSTS on the trusted host | Medium | `CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` (4.8) | Needs a network position (`AV:A`) and an injected redirect; lower with preloaded HSTS |
| JSONP returning sensitive user data with cookie authentication | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` (6.5) | Readable by any site; same reasoning as origin reflection. `C:L` (4.3) for low-sensitivity data such as Liberapay's donation figures |
| Authenticated JavaScript file exposing user data or tokens (XSSI) | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` (6.5) | Sensitivity drives it; a leaked CSRF token or API key pushes it to the second row |
| `*` on an internal or IP-trusted service exposing sensitive data | Low to Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` (5.3) | Victim must be on the internal network; browser Local Network Access prompts reduce it further |
| Reflection with credentials on low-sensitivity data (user ID, display name) | Low | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N` (4.3) | Report the policy; the data limits the impact |
| Preflight-reliant endpoint accepts simple requests (ASVS 3.5.2) | Medium to High | — | Rate as CSRF (see Session Management): the CORS assumption is the root cause; impact is the state change |
| Reflection with credentials on a bearer-token-only API | Info to Low | none | No ambient credential for the attacker's page; hardening |
| `*` with credentials; missing `Vary: Origin`; reflected requested headers for trusted origins | Info to Low | none, or `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` (3.1) | Not exploitable as configured; likely to become so with the next change |
| JSON or CSV served without `nosniff` or with a script-compatible type, no working inclusion | Info to Low | none | Header hygiene (ASVS 3.4.4, 4.1.1); modern browsers already block most of it |

When you report, give: the endpoint and the exact `Origin` values that were accepted and refused, the full CORS headers returned, how the API authenticates and the cookie attributes, the browser and version in which test 10's PoC read your own data (and that it failed after logout), the fields that were readable (masked), and the matching rule you inferred or saw in code. State that the PoC was local, read only your own test account, and sent data nowhere.

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 / API Top 10 |
|---|---|---|---|---|
| GT-WEB-CORS-1 | WSTG-CLNT-07, WSTG-CLNT-13 | v5.0.0-3.4.2 (context) | CWE-942 (context) | A01:2025, A02:2025, API8:2023 |
| GT-WEB-CORS-2 | WSTG-CLNT-07 | v5.0.0-3.4.2 | CWE-942, CWE-346 | A01:2025, A02:2025, API8:2023 |
| GT-WEB-CORS-3 | WSTG-CLNT-07 | v5.0.0-3.4.2 | CWE-942, CWE-346 | A01:2025, A02:2025, API8:2023 |
| GT-WEB-CORS-4 | WSTG-CLNT-07 | v5.0.0-3.4.2 | CWE-346, CWE-942 | A01:2025, A02:2025, API8:2023 |
| GT-WEB-CORS-5 | WSTG-CLNT-07 | v5.0.0-3.4.2, v5.0.0-3.5.4 | CWE-942 | A01:2025, A02:2025, API8:2023 |
| GT-WEB-CORS-6 | WSTG-CLNT-07 | v5.0.0-3.4.2, v5.0.0-3.4.1 | CWE-942 | A01:2025, A02:2025, API8:2023 |
| GT-WEB-CORS-7 | WSTG-CLNT-07 | v5.0.0-3.4.2 | CWE-942 | A02:2025, API8:2023 |
| GT-WEB-CORS-8 | WSTG-CLNT-07 | v5.0.0-3.5.1, v5.0.0-3.5.2, v5.0.0-3.4.2 | CWE-942; CWE-352 for the CSRF impact | A01:2025, API8:2023 |
| GT-WEB-CORS-9 | WSTG-CLNT-07 | v5.0.0-3.4.2 (dynamic value implies `Vary`) | CWE-942 (context) | A02:2025 |
| GT-WEB-CORS-10 | WSTG-CLNT-07 | v5.0.0-3.4.2 | as the confirmed finding | as the confirmed finding |
| GT-WEB-CORS-11 | WSTG-CLNT-13 | v5.0.0-3.5.6 | CWE-359 (when PII leaks) | A01:2025 |
| GT-WEB-CORS-12 | WSTG-CLNT-13 | v5.0.0-3.5.7, v5.0.0-3.5.8, v5.0.0-3.4.4, v5.0.0-4.1.1 | CWE-359 (when PII leaks) | A01:2025, A02:2025 for header gaps |

ASVS levels: `v5.0.0-3.4.2` L1 (fixed `Access-Control-Allow-Origin` or an allow-list; `*` only without sensitive data), `v5.0.0-3.5.1` L1 (anti-forgery tokens or non-safelisted headers where the preflight is not relied on), `v5.0.0-3.5.2` L1 (preflight-protected functionality cannot be reached without a preflight), `v5.0.0-3.4.1` L1 (HSTS), `v5.0.0-4.1.1` L1 (correct `Content-Type` with charset), `v5.0.0-3.4.4` L2 (`nosniff` on all responses), `v5.0.0-3.5.4` L2 (separate applications on separate hostnames), `v5.0.0-3.5.6` L3 (no JSONP), `v5.0.0-3.5.7` L3 (no authorised data in script resources), `v5.0.0-3.5.8` L3 (authenticated resources only loadable cross-origin when intended, via `Sec-Fetch-*` or CORP).

CWE choice: CWE-942 (*Permissive Cross-domain Security Policy with Untrusted Domains*; the OWASP Top 10:2025 list still shows the older name without "Security") is a Variant that MITRE allows for mapping, and is the default for a CORS policy that trusts the wrong origins. CWE-346 (*Origin Validation Error*) is a Class that MITRE marks "allowed with review"; use it alongside CWE-942 when the root cause is a broken origin check (tests 2 to 4). CWE-1385 (*Missing Origin Validation in WebSockets*) is the WebSocket-specific child of CWE-346 and belongs to the WebSockets note (HTTP & Infrastructure, not written yet), not here. For XSSI and JSONP there is no dedicated CWE; use CWE-359 (*Exposure of Private Personal Information to an Unauthorized Actor*, Base, allowed) when personal data leaks, and avoid CWE-200, which MITRE now discourages for mapping. CWE-352 is the CSRF entry for the state-change side of test 8. OWASP Top 10:2025: `A01:2025` Broken Access Control lists "CORS misconfiguration allows API access from unauthorized or untrusted origins" among its examples, and `A02:2025` Security Misconfiguration includes CWE-942 in its mapped CWEs; we cite both for policy findings. `API8:2023` Security Misconfiguration names a missing or improperly set CORS policy.

## References

**OWASP**

- WSTG: [Testing Cross Origin Resource Sharing (WSTG-CLNT-07)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/07-Cross_Origin_Resource_Sharing), [Testing for Cross Site Script Inclusion (WSTG-CLNT-13)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/13-Cross_Site_Script_Inclusion)
- ASVS 5.0: [V3 Web Frontend Security](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md), [V4 API and Web Service](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x13-V4-API-and-Web-Service.md)
- [A01:2025 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/), [A02:2025 Security Misconfiguration](https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/); [API8:2023 Security Misconfiguration](https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/)
- Cheat Sheets: [HTML5 Security (Cross Origin Resource Sharing)](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing), [Cross-Site Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), [HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)

**CWE**

- [CWE-942](https://cwe.mitre.org/data/definitions/942.html), [CWE-346](https://cwe.mitre.org/data/definitions/346.html), [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html), [CWE-359](https://cwe.mitre.org/data/definitions/359.html), [CWE-352](https://cwe.mitre.org/data/definitions/352.html)

**Standards and browser documentation**

- WHATWG Fetch Standard: [CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol), [CORS protocol and credentials](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials), [CORS protocol and HTTP caches](https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches)
- MDN: [Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS), [Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin), [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options), [Same-origin policy](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Same-origin_policy)
- Chrome: [Local Network Access](https://developer.chrome.com/blog/local-network-access); blink-dev [Intent to Ship: Opaque Response Blocking (ORB) v0.2](https://groups.google.com/a/chromium.org/g/blink-dev/c/RcuAzHEI2CU); Mozilla [bug 1532642 (ORB)](https://bugzilla.mozilla.org/show_bug.cgi?id=1532642)
- web.dev: [Protect your resources from web attacks with Fetch Metadata](https://web.dev/articles/fetch-metadata)
- FIRST: [CVSS v3.1 User Guide](https://www.first.org/cvss/v3.1/user-guide)

**Research**

- James Kettle, [Exploiting CORS misconfigurations for Bitcoins and bounties](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties) (PortSwigger Research, 2016)
- Sebastian Lekies, Ben Stock, Martin Wentzel, Martin Johns, [The Unexpected Dangers of Dynamic JavaScript](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/lekies) (USENIX Security 2015; [paper PDF](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-lekies.pdf))
- Takeshi Terada, [Identifier based XSSI attacks](https://www.mbsd.jp/Whitepaper/xssi.pdf) (MBSD, 2015)

**PortSwigger**

- [Cross-origin resource sharing (CORS)](https://portswigger.net/web-security/cors), [Access-Control-Allow-Origin response header](https://portswigger.net/web-security/cors/access-control-allow-origin), [CORS labs](https://portswigger.net/web-security/all-labs#cross-origin-resource-sharing-cors)

**Framework documentation**

- Express: [cors middleware](https://expressjs.com/en/resources/middleware/cors.html) ([source](https://github.com/expressjs/cors)); [Helmet](https://helmet.js.org/)
- Django: [django-cors-headers](https://github.com/adamchainz/django-cors-headers), [JsonResponse](https://docs.djangoproject.com/en/stable/ref/request-response/#jsonresponse-objects), [Middleware: SecurityMiddleware](https://docs.djangoproject.com/en/stable/ref/middleware/), [CSRF protection](https://docs.djangoproject.com/en/stable/ref/csrf/)
- Spring: [CORS in Spring MVC](https://docs.spring.io/spring-framework/reference/web/webmvc-cors.html), [CorsConfiguration Javadoc](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/cors/CorsConfiguration.html), [Spring Security CORS](https://docs.spring.io/spring-security/reference/servlet/integrations/cors.html), [CVE-2018-11040](https://spring.io/security/cve-2018-11040)
- Laravel: [Routing: CORS](https://laravel.com/docs/13.x/routing#cors), [default config/cors.php](https://github.com/laravel/framework/blob/13.x/config/cors.php), [fruitcake/php-cors](https://github.com/fruitcake/php-cors)

**Tools**

- [Corsy](https://github.com/s0md3v/Corsy) (CORS misconfiguration checks)
- [DetectDynamicJS](https://github.com/luh2/DetectDynamicJS) (Burp extension for dynamic JavaScript, XSSI)
- Burp Suite: Proxy match-and-replace, Repeater, Logger; [mkcert](https://github.com/FiloSottile/mkcert) for a locally trusted certificate in test 10
