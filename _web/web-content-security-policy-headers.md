---
title: "Content Security Policy and Browser Security Headers"
date: 2026-11-15 22:04:00 +0000
subcategory: client-side
summary: "Reviewing CSP and browser security headers: strict vs allow-list CSP, bypass-prone policies, HSTS, nosniff, Referrer-Policy, COOP/CORP and fixes."
refs: [WSTG-CONF-12, WSTG-CONF-07, WSTG-CONF-14, WSTG-CLNT-09, v5.0.0-3.4.1, v5.0.0-3.4.3, v5.0.0-3.4.4, v5.0.0-3.4.5, v5.0.0-3.4.6, v5.0.0-3.4.7, v5.0.0-3.4.8, v5.0.0-3.5.8, v5.0.0-3.7.4, v5.0.0-3.2.1, "API8:2023", "A02:2025", "A04:2025", CWE-693, CWE-1021, CWE-319, CWE-598]
tags: [web, csp, security-headers, hsts, client-side, xss-mitigation]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Client-Side](/web/web-client-side-testing-guide/). It covers the response headers that tell a browser how to treat a page: Content Security Policy (CSP) first, then HTTP Strict Transport Security (HSTS), `X-Content-Type-Options`, `Referrer-Policy`, the cross-origin isolation trio (`Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy`), `Permissions-Policy`, and the headers you should stop sending. WSTG tests these under configuration management: `WSTG-CONF-12` (CSP), `WSTG-CONF-07` (HSTS) and `WSTG-CONF-14` (other security header misconfigurations), with framing in `WSTG-CLNT-09`. ASVS 5.0 puts them in V3 Web Frontend Security. The common failure in reports is a list of "missing headers" with no reasoning. This note does the opposite: it explains what each header actually stops, how to tell a strong CSP from one that only looks strong, how to collect headers across every kind of response (HTML, API, error pages, static files, redirects), twelve tests that end in a precise pass/fail, and fixes in Express, Django, Spring Security, Laravel, nginx and Apache. Headers are a defence-in-depth layer. The bugs they contain are covered elsewhere: [reflected and stored XSS](/web/web-reflected-stored-xss/), [DOM XSS and Trusted Types](/web/web-dom-xss-client-side-injection/), [clickjacking and tabnabbing](/web/web-clickjacking-tabnabbing/), [CORS and XSSI](/web/web-cors-xssi/), and [third-party scripts and SRI](/web/web-browser-storage-third-party-scripts/).

## Contents

- [How it works](#how-it-works)
  - [What CSP does and does not do](#what-csp-does-and-does-not-do)
  - [Directives, fallback and source expressions](#directives-fallback-and-source-expressions)
  - [Allow-list CSP and strict CSP](#allow-list-csp-and-strict-csp)
  - [How a policy is delivered](#how-a-policy-is-delivered)
  - [Which responses need which headers](#which-responses-need-which-headers)
  - [The other browser security headers](#the-other-browser-security-headers)
  - [Where headers are set and why they drift](#where-headers-are-set-and-why-they-drift)
- [What goes wrong](#what-goes-wrong)
  - [unsafe-inline and unsafe-eval](#unsafe-inline-and-unsafe-eval)
  - [Wildcards, schemes and broad hosts](#wildcards-schemes-and-broad-hosts)
  - [Allow-listed hosts that serve script gadgets](#allow-listed-hosts-that-serve-script-gadgets)
  - [Missing object-src, base-uri and form-action](#missing-object-src-base-uri-and-form-action)
  - [Weak, reused and cached nonces](#weak-reused-and-cached-nonces)
  - [Report-only forever](#report-only-forever)
  - [Meta-tag policies](#meta-tag-policies)
  - [Policies that skip error pages, redirects and static files](#policies-that-skip-error-pages-redirects-and-static-files)
  - [Framing left to X-Frame-Options or to nothing](#framing-left-to-x-frame-options-or-to-nothing)
  - [Trusted Types declared but not enforced](#trusted-types-declared-but-not-enforced)
  - [Reporting that is broken or leaky](#reporting-that-is-broken-or-leaky)
  - [HSTS that is short, partial or missing on some hosts](#hsts-that-is-short-partial-or-missing-on-some-hosts)
  - [Content sniffing and wrong Content-Type](#content-sniffing-and-wrong-content-type)
  - [Referrer leakage](#referrer-leakage)
  - [Cross-origin isolation headers misunderstood](#cross-origin-isolation-headers-misunderstood)
  - [Deprecated, duplicated and conflicting headers](#deprecated-duplicated-and-conflicting-headers)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [Collecting headers at scale](#collecting-headers-at-scale)
  - [GT-WEB-CSP-1: Build a header inventory across response types](#gt-web-csp-1-build-a-header-inventory-across-response-types)
  - [GT-WEB-CSP-2: Confirm the policy is enforced, delivered by header and consistent](#gt-web-csp-2-confirm-the-policy-is-enforced-delivered-by-header-and-consistent)
  - [GT-WEB-CSP-3: Review script-src for unsafe keywords, wildcards and schemes](#gt-web-csp-3-review-script-src-for-unsafe-keywords-wildcards-and-schemes)
  - [GT-WEB-CSP-4: Check allow-listed hosts for JSONP, old libraries and user content](#gt-web-csp-4-check-allow-listed-hosts-for-jsonp-old-libraries-and-user-content)
  - [GT-WEB-CSP-5: Test nonce and hash quality](#gt-web-csp-5-test-nonce-and-hash-quality)
  - [GT-WEB-CSP-6: Check object-src, base-uri, form-action and other non-fallback directives](#gt-web-csp-6-check-object-src-base-uri-form-action-and-other-non-fallback-directives)
  - [GT-WEB-CSP-7: Verify frame-ancestors and X-Frame-Options](#gt-web-csp-7-verify-frame-ancestors-and-x-frame-options)
  - [GT-WEB-CSP-8: Review Trusted Types enforcement](#gt-web-csp-8-review-trusted-types-enforcement)
  - [GT-WEB-CSP-9: Verify CSP reporting](#gt-web-csp-9-verify-csp-reporting)
  - [GT-WEB-CSP-10: Verify HSTS and the HTTP-to-HTTPS path](#gt-web-csp-10-verify-hsts-and-the-http-to-https-path)
  - [GT-WEB-CSP-11: Check X-Content-Type-Options, Content-Type and Referrer-Policy](#gt-web-csp-11-check-x-content-type-options-content-type-and-referrer-policy)
  - [GT-WEB-CSP-12: Review COOP, COEP, CORP, Permissions-Policy and deprecated headers](#gt-web-csp-12-review-coop-coep-corp-permissions-policy-and-deprecated-headers)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Rolling out CSP: report-only, then enforce](#rolling-out-csp-report-only-then-enforce)
  - [Nonces per response](#nonces-per-response)
  - [Node.js and Express (helmet)](#nodejs-and-express-helmet)
  - [Django](#django)
  - [Spring Security](#spring-security)
  - [Laravel](#laravel)
  - [nginx and Apache](#nginx-and-apache)
  - [CDNs and platform headers](#cdns-and-platform-headers)
  - [A reporting endpoint](#a-reporting-endpoint)
  - [Regression tests](#regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### What CSP does and does not do

A Content Security Policy is a list of rules the server sends with a document. The browser enforces it for that document: which scripts may run, where styles, images, frames, fonts and connections may come from, which URLs forms may submit to, who may frame the page, and whether dangerous DOM sinks accept plain strings. The browser makes every decision. The server only declares the policy.

That makes CSP a **mitigation**, not a fix. The useful way to think about it is: *assume an attacker has already injected markup into this page; what can they still do?* A good policy turns an injected script tag or event handler into a blocked request and a console error. It does not remove the injection.

CSP is good at:

- Blocking inline script the developer did not write (injected script tags, `onerror=` handlers, `javascript:` URLs), when the policy has no `'unsafe-inline'` or relies on nonces or hashes.
- Blocking script from hosts the developer did not choose, and blocking `eval()` and friends unless `'unsafe-eval'` is allowed.
- Blocking plugin content (`object-src 'none'`) and base-URL hijacking (`base-uri`).
- Controlling who may frame the page (`frame-ancestors`), which replaces `X-Frame-Options`.
- With Trusted Types (`require-trusted-types-for 'script'`), forcing DOM XSS sinks to accept only values that passed through a named policy.

CSP does not:

- Fix the injection. HTML injection that cannot run script can still deface the page, plant a fake login form, leak data with dangling markup or CSS, or clobber DOM globals (see [DOM clobbering and CSS injection](/web/web-dom-clobbering-css-injection/)).
- Reliably stop exfiltration. `connect-src`, `img-src` and friends restrict subresources, but top-level navigation is not covered (a `navigate-to` directive was proposed and dropped), and a script that runs can always find a channel.
- Protect anything on the server side: SQL injection, broken access control, SSRF and the rest are untouched.
- Protect users from a script you deliberately allowed. If a trusted third-party script is compromised, CSP lets it run (that is the supply-chain problem; SRI addresses part of it, see [third-party scripts](/web/web-browser-storage-third-party-scripts/)).
- Apply in a browser that ignores it, or to a response that does not carry it.

### Directives, fallback and source expressions

A policy is a semicolon-separated list of directives, each followed by a list of sources:

```http
Content-Security-Policy: default-src 'self'; script-src 'nonce-Q2hhbmdlTWVQZXJSZXNwb25zZQ' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'
```

Directives fall into groups, and the grouping matters because **only fetch directives fall back to `default-src`**:

| Group | Directives | Falls back to `default-src`? |
|---|---|---|
| Fetch | `script-src` (and `script-src-elem`, `script-src-attr`), `style-src` (and `-elem`, `-attr`), `img-src`, `font-src`, `connect-src`, `media-src`, `object-src`, `frame-src`, `child-src`, `worker-src`, `manifest-src` | Yes |
| Document | `base-uri`, `sandbox` | No |
| Navigation | `form-action`, `frame-ancestors` | No |
| Reporting | `report-to`, `report-uri` (deprecated, still widely supported) | n/a |
| Other | `require-trusted-types-for`, `trusted-types`, `upgrade-insecure-requests` | No |

So `default-src 'none'` on its own still lets anyone frame the page, lets an injected `base` element rewrite relative URLs, and lets an injected form post anywhere. The CSP Level 3 specification says explicitly that `frame-ancestors` does not fall back to `default-src`.

Source expressions you will meet in reviews:

| Expression | Meaning | Review note |
|---|---|---|
| `'self'` | Same origin (scheme, host, port) | Fine for most fetches; risky for scripts if the origin hosts user uploads or JSONP |
| `'none'` | Nothing | Correct for `object-src`, `base-uri`, `frame-ancestors` where possible |
| `https://cdn.example.net` | That host, any path (unless a path is given) | Every script on that host is trusted |
| `*.example.net` | Any subdomain | A takeover or user-content subdomain undoes it |
| `https:` / `data:` / `blob:` / `*` | Scheme or anything | In `script-src`, effectively no restriction |
| `'nonce-<value>'` | Elements carrying that `nonce` attribute | Must be unpredictable and fresh per response |
| `'sha256-<hash>'` | Inline script (or, with CSP3, external script with matching SRI) whose content hashes to that value | Good for static inline bootstraps |
| `'strict-dynamic'` | Scripts loaded by an already-trusted script are trusted too; host and scheme sources and `'self'` are ignored | The core of a strict CSP |
| `'unsafe-inline'` | Inline script, handlers and `javascript:` URLs allowed | Ignored by modern browsers when a nonce or hash is present |
| `'unsafe-eval'` | `eval()`, `new Function()`, string `setTimeout` | Widens DOM XSS and gadget attacks |
| `'unsafe-hashes'` | Hashes may match inline event handlers | Narrow, but extends trust to attribute sinks |
| `'wasm-unsafe-eval'` | WebAssembly compilation without `'unsafe-eval'` | Acceptable where WASM is needed |

### Allow-list CSP and strict CSP

There are two ways to restrict script, and the difference is the most important thing in this note.

An **allow-list CSP** names hosts: `script-src 'self' https://cdn.example.net https://www.googletagmanager.com`. The policy trusts every script those hosts serve. Google's 2016 study of about 26,000 unique policies found that 94.72% of them could be bypassed, and that 14 of the 15 hosts most commonly allow-listed for scripts served something an attacker could abuse: JSONP endpoints with a controllable callback, old AngularJS builds whose templates evaluate expressions, or open redirects onto such content ([Weichselbaum, Spagnuolo, Lekies and Janc, "CSP Is Dead, Long Live CSP!", ACM CCS 2016](https://research.google/pubs/csp-is-dead-long-live-csp-on-the-insecurity-of-whitelists-and-the-future-of-content-security-policy/)). Allow-lists also grow over time as marketing tags arrive, and nobody re-checks the old entries.

A **strict CSP** trusts specific script *elements*, not hosts. The server puts a random nonce in the header and in the `nonce` attribute of every script tag it writes, or lists the hashes of its inline scripts. `'strict-dynamic'` then lets those trusted scripts load further scripts (a bundler's chunks, a tag manager's children) without naming hosts. The baseline from Google's [strict CSP guidance on web.dev](https://web.dev/articles/strict-csp) is:

```http
Content-Security-Policy: script-src 'nonce-{RANDOM}' 'strict-dynamic'; object-src 'none'; base-uri 'none';
```

or, for static pages that cannot generate a nonce per response:

```http
Content-Security-Policy: script-src 'sha256-{HASHED_INLINE_SCRIPT}' 'strict-dynamic'; object-src 'none'; base-uri 'none';
```

The same guidance adds `https:` and `'unsafe-inline'` as fallbacks for very old browsers. Browsers that understand nonces ignore `'unsafe-inline'`, and browsers that understand `'strict-dynamic'` ignore `https:`, so the fallbacks do not weaken the policy where it matters. Keep that in mind when a scanner flags `'unsafe-inline'` in a nonce-based policy (see the false positives in [test 3](#gt-web-csp-3-review-script-src-for-unsafe-keywords-wildcards-and-schemes)).

| | Allow-list CSP | Strict CSP |
|---|---|---|
| Trust unit | Host (and optional path) | Script element (nonce) or exact content (hash) |
| Typical weakness | JSONP, old libraries, uploads, subdomain takeover on allowed hosts | Nonce reuse or leakage, script gadgets in trusted code, injection into a trusted script's inputs |
| Maintenance | Grows with every vendor | Template change once; new vendors need no policy edit |
| ASVS 5.0 | Meets `v5.0.0-3.4.3` at L2 if `object-src 'none'` and `base-uri 'none'` are present | Required for L3 (`v5.0.0-3.4.3`: per-response policy with nonces or hashes) |

A strict CSP is not bypass-proof. Script gadgets in libraries you load (code that turns attacker-controlled markup into script, such as framework template bindings) can still execute injected markup ([Lekies et al., "Code-Reuse Attacks for the Web", ACM CCS 2017](https://research.google/pubs/code-reuse-attacks-for-the-web-breaking-cross-site-scripting-mitigations-via-script-gadgets/)), and an injection *inside* a nonced script block runs with the nonce. It is still far harder to defeat than an allow-list.

### How a policy is delivered

| Delivery | Enforced? | Notes |
|---|---|---|
| `Content-Security-Policy` response header | Yes | The normal way |
| `Content-Security-Policy-Report-Only` header | No, reports only | For rollout; not protection |
| `meta http-equiv="Content-Security-Policy"` element | Yes, from that point in the document | Cannot carry `frame-ancestors`, `report-uri` or `sandbox`; report-only is not supported in `meta` |

When several policies apply (two headers, a header and a `meta` element, or one header with comma-separated policies), the browser enforces **all** of them: a resource must pass every policy. Adding a second policy can only tighten things, never loosen them. That is useful for testers: a weak policy plus a strict one is effectively strict. It is also a source of breakage when a CDN and the application each add a different `Content-Security-Policy`.

A `meta` policy applies only to content parsed after it. Anything earlier in the document, including resources fetched through `Link` headers, is not covered, and changing the `meta` element after parsing has no effect.

### Which responses need which headers

CSP, `frame-ancestors`, COOP and Trusted Types matter for responses a browser **renders as a document**: HTML, but also SVG, XML with stylesheets, and anything the browser might sniff into HTML. They matter less for a JSON API response that is only ever fetched by script, because nothing in it executes. That does not mean "skip the API". A JSON or text response opened directly in a tab is a document too, which is why the OWASP REST Security Cheat Sheet recommends `Content-Security-Policy: frame-ancestors 'none'` and `X-Content-Type-Options: nosniff` on API responses. ASVS 5.0 `v5.0.0-3.2.1` (L1) is about the same problem: stop an API response or uploaded file from being rendered in the wrong context, with `Sec-Fetch-*` checks, CSP `sandbox` or `Content-Disposition: attachment`.

| Header | HTML documents | API (JSON) | Error pages | Static files | Redirects |
|---|---|---|---|---|---|
| `Content-Security-Policy` | Full policy | `default-src 'none'; frame-ancestors 'none'` is cheap and enough | Same as HTML (error pages often reflect input) | Needed on HTML and SVG; not on JS/CSS/images | Not needed |
| `Strict-Transport-Security` | Yes | Yes | Yes | Yes | Yes, on the HTTPS redirect itself |
| `X-Content-Type-Options: nosniff` | Yes | Yes | Yes | Yes (this is where it matters most) | Optional |
| `Referrer-Policy` | Yes | Optional | Yes | Optional | Optional |
| `Cross-Origin-Opener-Policy` | Yes | No | Yes | No | No |
| `Cross-Origin-Resource-Policy` | Optional | Yes, for authenticated data | Optional | Yes, for authenticated assets | No |

ASVS words several of these as "all responses" (HSTS in `v5.0.0-3.4.1`, nosniff in `v5.0.0-3.4.4`, `frame-ancestors` in `v5.0.0-3.4.6`). Report against ASVS when the client tests to it, but rate on what a missing header on that response type exposes.

### The other browser security headers

| Header | What it does | Current recommendation |
|---|---|---|
| `Strict-Transport-Security` | Browser upgrades every request for this host (and subdomains with `includeSubDomains`) to HTTPS and refuses click-through on certificate errors, for `max-age` seconds | `max-age` of at least one year (`31536000`), `includeSubDomains` once every subdomain serves HTTPS. Only honoured over HTTPS |
| HSTS preload list | Browser ships with the domain already marked HTTPS-only, closing the first-visit gap | Requires `max-age` of at least one year, `includeSubDomains` and `preload` on the base domain plus a manual submission at hstspreload.org. Hard to undo |
| `X-Content-Type-Options: nosniff` | Browser trusts `Content-Type` instead of guessing; blocks scripts and styles served with the wrong type | Always, with correct `Content-Type` values |
| `Referrer-Policy` | Controls what the `Referer` request header carries to other origins | `strict-origin-when-cross-origin` (the default in modern browsers when no policy is set) or stricter, such as `no-referrer` on pages with tokens in the URL |
| `Cross-Origin-Opener-Policy` | Separates the page's browsing context group from cross-origin windows it opens or is opened by | `same-origin` (or `same-origin-allow-popups` when the page must open OAuth or payment pop-ups) |
| `Cross-Origin-Embedder-Policy` | Page may only load cross-origin resources that opt in (CORP or CORS), or loads them without credentials (`credentialless`) | Only when you need cross-origin isolation (for example `SharedArrayBuffer`) |
| `Cross-Origin-Resource-Policy` | Resource refuses to be loaded by other origins or sites in no-cors mode | `same-origin` or `same-site` for authenticated resources |
| `Permissions-Policy` | Disables powerful features (camera, microphone, geolocation, payment, USB) for the page and its frames | Deny what you do not use, for example `camera=(), microphone=(), geolocation=()` |
| `X-Frame-Options` | Legacy framing control | Superseded by `frame-ancestors`; keep `DENY` or `SAMEORIGIN` for old clients, never `ALLOW-FROM` |

Cross-origin isolation is the combination of COOP `same-origin` and COEP `require-corp` or `credentialless` on a document. The browser then exposes `self.crossOriginIsolated === true` and re-enables features such as `SharedArrayBuffer` and high-precision timers. The reason these headers exist is Spectre-class side channels: a page that can pull your authenticated resources into its own renderer process can, in principle, read them. CORP and Fetch Metadata keep authenticated resources out of attacker processes; COOP keeps your window out of the attacker's browsing context group. ASVS 5.0 asks for COOP at L3 (`v5.0.0-3.4.8`) and for CORP or `Sec-Fetch-*` validation on authenticated resources at L3 (`v5.0.0-3.5.8`).

Headers you should **not** send, or should send only in their disabled form:

| Header | Status | What to recommend |
|---|---|---|
| `X-XSS-Protection` | The XSS filters it controlled are gone: Chrome removed its filter in version 78 and Safari in 15.4; Firefox never had one (per MDN compatibility data). In older browsers the filter itself enabled data-leak and selective-script-blocking attacks | Omit the header or send `X-XSS-Protection: 0` (what helmet and Spring Security send by default). Flag `1; mode=block` only as an Info hygiene item |
| `Expect-CT` | Obsolete; Chrome removed support in version 107 (MDN marks it deprecated) because Certificate Transparency is enforced by default | Remove |
| `Feature-Policy` | Replaced by `Permissions-Policy` | Migrate the directives to `Permissions-Policy` syntax |
| `Public-Key-Pins` (HPKP) | Removed from browsers | Remove |
| `X-Frame-Options: ALLOW-FROM` | Not supported by modern browsers | Use `frame-ancestors` |

### Where headers are set and why they drift

The headers on a response can come from four places, and each place sees a different set of responses:

1. **The application or framework** (helmet, Django `SecurityMiddleware`, Spring Security's header writers, Laravel middleware). It only sees requests that reach the application. Static files served by the web server, CDN error pages and platform health checks never pass through it.
2. **The web server or reverse proxy** (nginx `add_header`, Apache `Header`). In nginx, `add_header` applies only to 200, 201, 204, 206, 301, 302, 303, 304, 307 and 308 responses unless you add `always`, and a `location` block that defines any `add_header` of its own **drops every header inherited from the server level** (nginx 1.29.3 added `add_header_inherit merge` to change that).
3. **The CDN or edge** (response header rules, edge functions, managed "security headers" features). These often apply only to cached paths or to specific hostnames.
4. **The hosting platform** (serverless function responses, object-storage static sites, managed identity pages). Often impossible to configure, which leaves the login page, the most sensitive page, with the weakest headers.

This is why a single `curl -I https://app.example.com/` proves almost nothing. The finding is usually "the policy exists but not on these responses", and the only way to see it is to collect headers across response types and hosts ([Collecting headers at scale](#collecting-headers-at-scale)).

## What goes wrong

Each item below is a **policy-review finding**: a weakness in a control, not a vulnerability on its own. Its severity depends on what it would have stopped (see [Rating findings](#rating-findings)).

### unsafe-inline and unsafe-eval

`script-src 'self' 'unsafe-inline'` allows every injected `script` element, every `on*=` attribute and every `javascript:` URL. Against reflected and stored XSS, such a policy does nothing; it only restricts where *external* scripts come from. Teams add `'unsafe-inline'` because templates contain inline bootstraps or handlers and the policy broke them. The fix is nonces or hashes, not the keyword.

`'unsafe-eval'` allows `eval()`, `new Function()` and string arguments to `setTimeout`/`setInterval`. On its own it does not let an attacker inject script, but it turns many DOM XSS sinks and library gadgets into code execution, and old template engines (AngularJS) need it in their default mode. Modern bundles rarely need it; look for it being kept "just in case".

`'unsafe-inline'` in `style-src` is far less serious than in `script-src`; it enables CSS injection and some scriptless exfiltration (see [CSS injection](/web/web-dom-clobbering-css-injection/)), and helmet's default policy includes it. Report it, but rate it separately.

Where to look: the `script-src` (or `default-src`, if `script-src` is absent) of every HTML response; `script-src-attr` and `script-src-elem` if present.

### Wildcards, schemes and broad hosts

`script-src *`, `https:`, `http:`, `data:` or `blob:` in `script-src` mean "any script from anywhere" in practice: the attacker hosts a script on any HTTPS site, or inlines it in a `data:` URL. `*.example.com` trusts every subdomain, so one forgotten marketing site, one user-content host (`files.example.com`), or one dangling DNS record that can be taken over becomes a script source for the main application. `http://` sources also allow a network attacker to replace the script in transit.

Where to look: every host and scheme in `script-src`, `object-src`, `base-uri` and `default-src`; for each wildcard, list the subdomains you can see (certificate transparency, DNS, the client's asset list) and ask who controls their content.

### Allow-listed hosts that serve script gadgets

Even a host with no wildcard can host attacker-usable scripts. The classes from the 2016 Google study and later research are:

- **JSONP endpoints** that echo a `callback` parameter into a JavaScript response. If `https://api.vendor.example/` is allowed and it serves `?callback=<anything>`, the attacker chooses the code. (JSONP itself is covered in [CORS and XSSI](/web/web-cors-xssi/); ASVS `v5.0.0-3.5.6` asks for it to be removed entirely.)
- **Old framework builds**, especially AngularJS, on a public CDN. Once AngularJS is loadable, injected markup carrying `ng-app` and an expression runs inside the framework, which CSP considers trusted. PortSwigger's [Piwik PRO write-up](https://portswigger.net/research/ambushed-by-angularjs-a-hidden-csp-bypass-in-piwik-pro) shows the pattern on a whole-domain allow-list.
- **User-controlled content** on an allowed host: uploads on the same origin (which `'self'` trusts), public buckets, paste sites, package CDNs that serve any published package (`cdn.jsdelivr.net`, `unpkg.com`).
- **Open redirects** on an allowed host: CSP checks the path of the original URL only for host-source paths; after a redirect, the path part of a source expression is not enforced, so a redirect on an allowed host can widen a path-restricted allow-list.

Tools such as Google's CSP Evaluator and [CSPBypass](https://cspbypass.com/) carry lists of known gadget hosts. Treat their output as a lead: a gadget is only exploitable through an injection point, and you confirm it in [test 4](#gt-web-csp-4-check-allow-listed-hosts-for-jsonp-old-libraries-and-user-content) without building an attack.

### Missing object-src, base-uri and form-action

- **`object-src`** missing (and no `default-src`): plugin content via `object` and `embed`. Most browsers no longer run NPAPI plugins, but `object` can still load HTML and SVG documents. ASVS `v5.0.0-3.4.3` requires `object-src 'none'` at minimum.
- **`base-uri`** missing: an injected `base` element changes where every *relative* script URL resolves. Nonced scripts loaded by relative path (`script nonce=… src="/js/app.js"`) are then fetched from the attacker's host with a valid nonce. This is the classic way around a nonce-based CSP, which is why both strict CSP guidance and ASVS insist on `base-uri 'none'` (or `'self'`).
- **`form-action`** missing: injected forms (or a hijacked existing form) can post credentials to any origin, and PortSwigger's 2026 research shows `form-action` gaps combined with referrer behaviour leaking credentials even without script ([Blind trust: stealing credentials through CSP](https://portswigger.net/research/blind-trust-stealing-credentials-through-csp)). It does not fall back to `default-src`.
- **`frame-ancestors`** missing: see [below](#framing-left-to-x-frame-options-or-to-nothing).

### Weak, reused and cached nonces

A nonce only works if the attacker cannot know it when they write the payload. Problems seen in practice:

- **Static nonce** hard-coded in configuration or the template (`'nonce-abc123'`), or one nonce per server process or per deployment.
- **Predictable nonce**: a timestamp, a counter, a hash of the session ID, `Math.random()` output, or fewer than 128 bits (CSP Level 3 says nonces should be at least 128 bits from a cryptographically secure generator).
- **Cached nonce**: the HTML page is cached by a CDN, reverse proxy or service worker, so every visitor gets the same nonce until the cache expires. Django's documentation warns about exactly this. Any reflected or stored injection on a cached page can then read the nonce once and reuse it.
- **Nonce reflected elsewhere**: the nonce appears in a URL, a JSON response, a data attribute, or is copied by front-end code into an attribute an injection can read.
- **Nonce applied to injected content**: templating that adds `nonce=` to every `script` tag in user-supplied HTML (a sanitiser allow-list that keeps `script`, or middleware that rewrites the response body to add nonces after rendering).

Hashes have the mirror problem: a hash allow-lists that exact inline script forever, so a hashed script that reads attacker-controlled data (a DOM sink, a JSON blob from the URL) is a gadget.

### Report-only forever

`Content-Security-Policy-Report-Only` was meant for a few weeks of rollout. Many sites never switch to enforcing. A report-only policy blocks nothing: the XSS runs, and at best someone receives a report. WSTG `WSTG-CONF-12` calls this out explicitly. Treat a report-only policy as "no CSP" for rating, while acknowledging the client has done the hard part (the policy may be ready to enforce).

### Meta-tag policies

A policy in a `meta` element works for script restrictions but cannot carry `frame-ancestors`, `sandbox` or `report-uri`, has no report-only mode, and only covers content after it in the document. If an injection point sits in the `head` *before* the `meta` element, the injected content is not covered. If the HTTP header and the `meta` policy differ, both are enforced, so a `meta` policy cannot weaken a header; but a `meta` policy that a template outputs conditionally (only on some layouts) leaves the other pages uncovered.

### Policies that skip error pages, redirects and static files

The application sets a good CSP on its own pages, but:

- **Error pages** (404, 405, 500, WAF block pages, maintenance pages) come from the web server, CDN or a framework error handler that bypasses the middleware. Error pages frequently reflect the requested path or a parameter, which makes them a prime XSS location, and they run on the same origin. An XSS on a header-less 404 page has full access to the origin.
- **Static HTML** (help centres, marketing pages, single-page app shells served from object storage) gets no application headers.
- **Redirect responses** usually do not need CSP, but they do need HSTS (the preload requirements say so explicitly), and nginx without `always` drops headers on some status codes.
- **Different hosts**: `www`, `app`, `api`, `auth` and `static` hostnames behind different stacks.
- **Authenticated and anonymous views**: some frameworks set a stricter policy only after login, or only on routes under a specific controller.

### Framing left to X-Frame-Options or to nothing

`frame-ancestors` is the current control; `X-Frame-Options` is legacy (ASVS `v5.0.0-3.4.6` calls it obsolete and says it may not be relied on). When both are present, browsers that support `frame-ancestors` ignore `X-Frame-Options`. Common mistakes: no framing control at all on pages with one-click actions; `X-Frame-Options: ALLOW-FROM` (ignored by modern browsers, which then allow framing); `frame-ancestors` in a `meta` policy (ignored); `frame-ancestors *` or `https:`; allowing framing on the whole site because one widget needs it. What framing enables (clickjacking, UI redressing, drag-and-drop) and how to prove it with a local proof-of-concept page are covered in [clickjacking and tabnabbing](/web/web-clickjacking-tabnabbing/); this note only reviews the header.

### Trusted Types declared but not enforced

Trusted Types make DOM XSS sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `script.src` and others) reject plain strings. Enforcement needs `require-trusted-types-for 'script'`. Seen in reviews: `trusted-types` with policy names but no `require-trusted-types-for` (nothing is enforced); `trusted-types *` or `'allow-duplicates'` that lets any code create a policy; a `default` policy that passes strings through unchanged; Trusted Types only in report-only mode. Browser support has widened: MDN compatibility data lists Chrome 83, Firefox 148 and Safari 26 for the directive at the time of writing. How to design policies and find the sinks is in [DOM XSS and client-side injection](/web/web-dom-xss-client-side-injection/).

### Reporting that is broken or leaky

`report-uri` (deprecated but still widely supported) posts a JSON body with content type `application/csp-report`. `report-to` names an endpoint declared in the `Reporting-Endpoints` header and uses the Reporting API (`application/reports+json`). Typical problems:

- `report-to csp` with no matching `Reporting-Endpoints: csp="…"` header, so reports are dropped silently.
- Only `report-to`, which older browsers ignore; send both during the transition (MDN compatibility data shows `report-to` support only arriving in Firefox 149).
- Reports sent to a third-party SaaS endpoint, carrying the full `document-uri` and `blocked-uri`, including query strings with tokens, reset codes or personal data.
- A reporting endpoint that renders reports in an internal dashboard without encoding (stored XSS in the security team's tooling) or accepts unlimited unauthenticated posts.
- No reporting at all, so nobody notices the policy is broken or under attack. ASVS asks for a reporting location at L3 (`v5.0.0-3.4.7`).

### HSTS that is short, partial or missing on some hosts

- **No HSTS**: the first request a user types (`app.example.com`) or a stale `http://` link goes over plain HTTP, and an on-path attacker can keep the session on HTTP (SSL stripping) or inject content into the redirect.
- **Short `max-age`** (minutes or days): protection lapses between visits. ASVS `v5.0.0-3.4.1` asks for at least one year.
- **No `includeSubDomains`**: a sibling subdomain over HTTP can set cookies for the parent domain, and users can be sent to plain-HTTP subdomains. ASVS requires it at L2 and up.
- **Header only on some responses**: missing on the base domain, on the `www` redirect, or on the login host.
- **Header over HTTP**: browsers ignore HSTS received over plain HTTP; it must be on the HTTPS response.
- **`preload` directive without list membership**: the directive alone does nothing; only inclusion on the list protects first visits.
- **Preloaded or `includeSubDomains` without checking subdomains**: an internal HTTP-only service becomes unreachable. Not a vulnerability, but a reason clients hesitate.

Note the change in guidance on preload. ASVS 5.0 asks for preload list inclusion at L3 (`v5.0.0-3.7.4`). hstspreload.org itself now says that, because Chrome and Safari upgrade navigations to HTTPS automatically, the extra benefit of preloading is small, and that while HSTS is recommended, HSTS preloading is not. Report missing preload only for L3 assessments, and present it as a client decision rather than a gap.

### Content sniffing and wrong Content-Type

Without `nosniff`, a browser may guess the type of a response from its content. The risks: a user upload or JSON response treated as HTML (stored XSS), or a text file loaded as a script or stylesheet. With `nosniff`, browsers refuse to execute a script whose `Content-Type` is not a JavaScript type and refuse stylesheets that are not `text/css`. That also defeats the "upload a file and load it with `script src`" route around `script-src 'self'` that PortSwigger demonstrated with [polyglot JPEGs](https://portswigger.net/research/bypassing-csp-using-polyglot-jpegs). `nosniff` cannot fix a wrong `Content-Type`: user uploads served as `text/html` on the main origin are a stored XSS regardless of headers (ASVS `v5.0.0-3.2.1`; serve them from a separate origin with `Content-Disposition: attachment`).

### Referrer leakage

The `Referer` header tells the next origin where the user came from. If the URL contains a password reset token, an invitation code, a session identifier, a search query with personal data, or an internal hostname, that value goes to every third-party script host, analytics provider, image host and external link target. Modern browsers default to `strict-origin-when-cross-origin`, which sends only the origin cross-origin, so the classic "reset token leaks through the footer link" report needs either an older browser, a page that sets `unsafe-url` or `no-referrer-when-downgrade`, or a per-element `referrerpolicy` attribute that loosens it. Check for those, and remember that same-origin requests still carry the full URL into your own logs. ASVS `v5.0.0-3.4.5` (L2) asks for a referrer policy. The real fix is not to put secrets in URLs (CWE-598).

### Cross-origin isolation headers misunderstood

- **COOP missing** on pages that open or are opened by other sites: a cross-origin window keeps a `window` reference and can navigate it or count its frames (an XS-Leaks primitive). Also the root of reverse tabnabbing via `window.opener` (see [tabnabbing](/web/web-clickjacking-tabnabbing/)).
- **COOP `same-origin` breaking OAuth or payment pop-ups**, followed by the team removing it entirely. `same-origin-allow-popups` keeps the protection for the page and allows the pop-up flow.
- **COEP added without need**: it breaks third-party embeds and gives no security benefit by itself. It exists to *enable* powerful features safely.
- **CORP `cross-origin` on authenticated resources**, or no CORP on authenticated images and documents: any site can pull them into its own process with `img`/`script` tags (the side-channel concern), and the response is protected only by Cross-Origin Read Blocking heuristics.
- **CORP confused with CORS**: CORP controls no-cors loads (images, scripts); CORS controls script-readable cross-origin fetches. One does not replace the other.

### Deprecated, duplicated and conflicting headers

- `X-XSS-Protection: 1; mode=block`: harmless in current browsers, harmful in old ones; recommend `0` or removal.
- `Expect-CT`, `Feature-Policy`, `Public-Key-Pins`: dead weight that signals the header set has not been reviewed.
- Two `Content-Security-Policy` headers from app and CDN: both enforced, usually breaking something and prompting someone to weaken one.
- Duplicate headers with different values behave differently per header: for HSTS the browser processes only the first one (RFC 6797), so the weaker value may win; conflicting `X-Frame-Options` values make browsers block framing, which can break legitimate embeds; duplicate CSPs are all enforced. WSTG `WSTG-CONF-14` lists empty values, typos (`Content-Security-Polcy`, or `Referer-Policy` used as the header name) and duplicates as misconfigurations.
- Headers injected via CRLF or reflected request values into response headers are a different bug (see [CRLF and header injection](/web/web-crlf-header-log-csv-injection/)).

## Testing

Everything below assumes an **authorised** engagement with written scope and rules of engagement, a bug bounty programme whose rules allow it, or a deliberately vulnerable lab. Many programmes list "missing security headers" as out of scope on its own; read the rules before reporting one. Requests and responses in this note are **illustrative**: hosts are fictional and outputs are shortened.

### Before you start

Header review is mostly passive: you read responses the application sends anyway. The parts that are not passive are triggering error responses, requesting many URLs, and confirming a CSP weakness through an injection point. Agree these in advance.

| Item | What to agree |
|---|---|
| Hosts | Every hostname in scope (`app`, `www`, `api`, `auth`, `static`, `admin`), and whether CDN edge hostnames and third-party-hosted pages (status page, help centre, identity provider) are in scope. Do not collect headers from hosts outside scope, even if they are linked |
| Accounts | One test account per role, so you can compare anonymous, logged-in and admin views; headers often differ after login |
| Request rate | A low, fixed rate for collection scripts (for example one request per second); no crawling of the whole site when a sample per route type is enough |
| Error responses | Which errors you may trigger: 404 (random path) and 405 (wrong method on your own endpoint) are harmless; do not try to force 500 errors on production without approval |
| Execution proofs | Whether you may confirm a CSP gap with a harmless marker (`alert(document.domain)`, `print()`, a `console.log` marker, or a visible text marker such as `GT-CSP-<id>`) through an injection point you found during XSS testing; stored markers only in objects only your test accounts can see, and removed at the end |
| Third-party tools | Whether you may paste the client's policy into hosted tools. CSP Evaluator and CSPBypass are convenient; if the policy lists internal hostnames, use the `csp_evaluator` library locally instead |

**Stop on real data.** Header collection should never return other users' data. If an error page or debug response shows another user's information, credentials or internal secrets, stop, keep only minimal redacted evidence, and report it immediately as its own finding.

**Tooling.**

- `curl` with `-sS -o /dev/null -D -` (headers only, body discarded) and **without** `-L`, so you see each redirect's own headers.
- Burp Suite: Proxy history with the response headers columns, Logger for bulk export, Repeater for single checks, Comparer for policies across responses. The [CSP Auditor](https://portswigger.net/bappstore/35237408a06043e9945a11016fcbac18) extension highlights weak policies; Burp Scanner's passive checks also report CSP and header issues.
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/) (web) or the [`csp_evaluator`](https://github.com/google/csp-evaluator) library for local and CI use.
- Browser DevTools: the **Network** panel (response headers per request, including those for frames and workers), the **Console** (CSP violation messages name the directive and the blocked URL), and the **Application** panel, which in Chromium shows per-frame security details such as whether the frame is cross-origin isolated and which COOP/COEP values apply.
- [MDN HTTP Observatory](https://developer.mozilla.org/en-US/observatory) for a quick external grade of public hosts in scope (it scans from Mozilla's infrastructure; the [CLI](https://github.com/mdn/mdn-http-observatory) runs from yours).
- ZAP passive scan rules such as *Content Security Policy (CSP) Header Not Set* (10038), *CSP* (10055), *Strict-Transport-Security Header* (10035), *X-Content-Type-Options Header Missing* (10021), *Anti-clickjacking Header* (10020) and *Permissions Policy Header Not Set* (10063).

### Collecting headers at scale

Build a URL list that covers **response types**, not just pages. For each host in scope, pick one or two of each:

| Response type | How to get one safely |
|---|---|
| HTML page, anonymous | Home page, login page, a public content page |
| HTML page, authenticated | Dashboard, settings, an admin page (with your admin test account) |
| API JSON | A `GET` on your own resource (`/api/me`) |
| Error pages | 404: `/gt-header-check-404`; 405: `POST` to a read-only endpoint you own; the framework's error route if documented |
| Static files | One `.js`, one `.css`, one image, one font, one uploaded file you own, the SPA shell (`index.html`) |
| Redirects | `http://` version of each host, bare domain to `www`, logout, a login redirect |
| Special | `robots.txt`, `/.well-known/security.txt`, OAuth callback, file download, embedded widget page, health check |

A `curl` loop is enough for a first pass. It records the status line and the headers that matter for every URL, at one request per second, with no redirects followed:

```bash
#!/usr/bin/env bash
# headers.sh - collect security headers for in-scope URLs (one per line in urls.txt)
# Usage: ./headers.sh urls.txt > headers.txt
set -euo pipefail
while IFS= read -r url; do
  [ -z "$url" ] && continue
  echo "=== $url"
  curl -sS -o /dev/null -D - --max-time 15 \
       -H 'User-Agent: GT-header-review (authorised test)' "$url" \
  | grep -iE '^(HTTP/|content-security-policy|strict-transport-security|x-content-type-options|referrer-policy|cross-origin-|permissions-policy|x-frame-options|x-xss-protection|reporting-endpoints|report-to|content-type|expect-ct|feature-policy|location|server|via|cache-control|age|x-cache|cf-cache-status):' \
  || echo "(no response)"
  sleep 1
done < "$1"
```

For authenticated URLs, add `-H 'Cookie: session=<SESSION_USER_A>'` to a second run. The `age`, `x-cache`, `cf-cache-status` and `via` lines tell you whether a response came from a CDN cache, which matters for nonce caching and for headers that only the origin sets.

When you need a table, a short Python script gives one row per URL and a pass/fail per header. It uses only the standard library, does not follow redirects, and sends nothing but the request you would send by hand:

```python
#!/usr/bin/env python3
"""header_matrix.py - one row per in-scope URL, one column per security header.
Usage: python3 header_matrix.py urls.txt > matrix.csv
Optional: GT_COOKIE='session=<SESSION_USER_A>' for an authenticated run."""
import csv, os, sys, time, urllib.request, urllib.error

HEADERS = ["content-security-policy", "content-security-policy-report-only",
           "strict-transport-security", "x-content-type-options", "referrer-policy",
           "cross-origin-opener-policy", "cross-origin-embedder-policy",
           "cross-origin-resource-policy", "permissions-policy", "x-frame-options",
           "x-xss-protection", "reporting-endpoints", "content-type"]

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # report the 3xx itself, do not follow it

opener = urllib.request.build_opener(NoRedirect)

def fetch(url):
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "GT-header-review (authorised test)"})
    if os.environ.get("GT_COOKIE"):
        req.add_header("Cookie", os.environ["GT_COOKIE"])
    try:
        resp = opener.open(req, timeout=15)
    except urllib.error.HTTPError as e:   # 3xx/4xx/5xx still carry headers
        resp = e
    # get_all keeps duplicates, which are themselves a finding
    return resp.status, {h: " || ".join(resp.headers.get_all(h) or []) for h in HEADERS}

writer = csv.writer(sys.stdout)
writer.writerow(["url", "status"] + HEADERS)
for line in open(sys.argv[1]):
    url = line.strip()
    if not url or url.startswith("#"):
        continue
    try:
        status, values = fetch(url)
        writer.writerow([url, status] + [values[h] for h in HEADERS])
    except Exception as exc:  # timeouts, TLS errors
        writer.writerow([url, f"error: {exc}"] + [""] * len(HEADERS))
    time.sleep(1)  # keep the rate low and predictable
```

Open the CSV in a spreadsheet, sort by header, and the gaps show up as empty cells next to a status code and a path. If the engagement already uses [httpx](https://github.com/projectdiscovery/httpx) for host inventory, restrict it to the in-scope host list and a low rate limit; do not point it at wildcard expansions.

### GT-WEB-CSP-1: Build a header inventory across response types

*Guler Tech methodology.* Implements the "fetch and review HTTP security headers" step of WSTG-CONF-14, the enforcement-and-consistency step of WSTG-CONF-12 ("confirm that the policy is consistently applied across sensitive endpoints"), and the presence check of WSTG-CONF-07.

#### What it checks

Which security headers each **response type** on each **host** carries, and where the gaps are. The output is the work list for every other test in this note.

#### Prerequisites

The in-scope host list; a test account per role; the URL list from [Collecting headers at scale](#collecting-headers-at-scale); Burp running so the collection is also in Proxy history.

#### Steps

1. Build the URL list per host and response type. Include at least one 404, one redirect from `http://`, one static file and one authenticated page per host.
2. Run `headers.sh` or `header_matrix.py` anonymously, then again with `GT_COOKIE` set for each role.
3. Repeat two or three requests to cached URLs (static pages, the SPA shell) and note whether `age` or cache-status headers change: a cache hit can carry different headers from a miss.
4. In the browser, load the main pages with DevTools open and note headers on documents loaded in frames (embedded widgets, payment pages, OAuth pop-ups) that `curl` does not request.
5. Fill in the inventory: one row per host and response type, one column per header, values verbatim.

#### Observation

An inventory like this (illustrative):

| Host / response | CSP | HSTS | nosniff | Referrer-Policy | COOP | XFO / frame-ancestors |
|---|---|---|---|---|---|---|
| `app` HTML (anon) | strict, enforced | `max-age=31536000; includeSubDomains` | yes | `strict-origin-when-cross-origin` | `same-origin` | `frame-ancestors 'none'` |
| `app` HTML (logged in) | same | same | yes | same | same | same |
| `app` 404 page | **none** | **none** | **none** | **none** | **none** | **none** |
| `app` `/static/app.js` | n/a | `max-age=31536000` | yes | none | n/a | n/a |
| `api` JSON | **none** | yes | yes | none | n/a | **none** |
| `http://app` redirect | n/a | ignored over HTTP | n/a | n/a | n/a | n/a |
| `auth` login (hosted IdP) | allow-list with `'unsafe-inline'` | yes | yes | none | none | `X-Frame-Options: SAMEORIGIN` |

Here the 404 page is served by the edge, not the app (no headers at all), and the hosted login page has its own weaker policy.

#### Evaluation

No finding by itself. Every empty or weak cell becomes input to tests 2 to 12, where it is evaluated against what that response type needs. A response type with *no* security headers at all is worth noting as a configuration-coverage issue even before rating individual headers.

#### False positives

- Static JavaScript, CSS, images and fonts without CSP or COOP: those headers do nothing on non-document responses.
- JSON API responses without a full CSP: a script-oriented policy adds little there; `frame-ancestors 'none'` and `nosniff` are what matter.
- A header missing on a CDN cache hit but present on a miss (or the reverse): real, but report it as a CDN configuration issue, with both responses as evidence.
- Hosted third-party pages (status page, help centre) that are out of scope.

#### Automation

Keep the URL list and `header_matrix.py` output with the engagement files. In CI the same idea becomes a header regression test that requests one URL per response type against a staging build (see [Regression tests](#regression-tests)).

### GT-WEB-CSP-2: Confirm the policy is enforced, delivered by header and consistent

*Guler Tech methodology.* Implements "Identify and Confirm CSP Enforcement" in WSTG-CONF-12 and the META-tag and duplicate-header checks in WSTG-CONF-14.

#### What it checks

Whether there is an **enforced** policy (not only report-only), how it is delivered (header, `meta`, or both), whether multiple policies interact, and whether the same policy covers every HTML response.

#### Prerequisites

The inventory from test 1.

#### Steps

1. For each HTML response, record `Content-Security-Policy` and `Content-Security-Policy-Report-Only` separately. A response can carry both.
2. Search the HTML for a `meta` policy:

   ```bash
   curl -sS https://app.example.com/ | grep -io '<meta[^>]*content-security-policy[^>]*>'
   ```

   Note where in the `head` it appears and whether anything (scripts, styles, `Link` preloads) comes before it.
3. Count policies. Two `Content-Security-Policy` header lines, or one line containing a comma, mean two policies that are both enforced. Write both down; the effective policy is the intersection.
4. Compare the policy text between pages, roles and hosts (Burp Comparer, or `sort | uniq -c` over the collected values). Note pages with a different or missing policy.
5. Load one page in the browser and check the Console for CSP messages. Violations on a normal page load tell you the policy is enforced (or reported) and what it blocks.

#### Observation

Vulnerable (illustrative): report-only, no enforcing header.

```http
HTTP/2 200
content-type: text/html; charset=utf-8
content-security-policy-report-only: script-src 'nonce-mD3kQ9yJ0b6vF1sXc7Ewgw' 'strict-dynamic'; object-src 'none'; base-uri 'none'; report-to csp
reporting-endpoints: csp="https://app.example.com/csp-reports"
```

Correct: the same policy enforced, and a candidate stricter policy in report-only alongside it.

```http
HTTP/2 200
content-type: text/html; charset=utf-8
content-security-policy: script-src 'nonce-mD3kQ9yJ0b6vF1sXc7Ewgw' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; report-to csp
content-security-policy-report-only: require-trusted-types-for 'script'; report-to csp
reporting-endpoints: csp="https://app.example.com/csp-reports"
```

#### Evaluation

- **Fail** if no enforcing policy exists on HTML responses (header or `meta`), including the case where only `Content-Security-Policy-Report-Only` is present.
- **Fail** if HTML responses of a type that can contain injected content (error pages, search results, user content pages) carry no policy while others do.
- **Fail (weakness)** if the policy is only in a `meta` element and the client relies on it for `frame-ancestors` or reporting, or if content precedes the `meta` element.
- **Pass** if every HTML response carries an enforced policy by header, and any report-only policy is an additional candidate rather than the only one.

Whether the enforced policy is any good is tests 3 to 6.

#### False positives

- Two policies where one is deliberately stricter (a site-wide baseline plus a route-specific policy): intersection is intended; check that it does not break the page rather than flagging it.
- A report-only policy that is explicitly in a time-boxed rollout with a date: still report the gap, but say so and rate as Info if an enforcing baseline exists.

#### Automation

ZAP rules 10038 and 10055 flag missing and report-only policies passively. In CI, assert that every HTML route returns `Content-Security-Policy` (not only the report-only header).

### GT-WEB-CSP-3: Review script-src for unsafe keywords, wildcards and schemes

*Guler Tech methodology.* Implements "Review High-Risk Directives" and "Assess Policy Strength" in WSTG-CONF-12.

#### What it checks

Whether the effective script policy can stop an injected inline script or an injected external script from an arbitrary host.

#### Prerequisites

The enforced policy text from test 2. If several policies apply, review each and reason about the intersection.

#### Steps

1. Find the directive that governs scripts: `script-src-elem`/`script-src-attr` if present, otherwise `script-src`, otherwise `default-src`. If none exists, there is no script restriction.
2. Paste the policy into CSP Evaluator (or run the library, see Automation). Note each finding and its severity.
3. Classify the policy:
   - **Strict**: nonce or hash plus `'strict-dynamic'`, no host allow-list doing real work.
   - **Nonce/hash without strict-dynamic**: hosts still matter; review them as an allow-list.
   - **Allow-list**: hosts and `'self'`; continue to test 4 for each host.
   - **Ineffective**: `'unsafe-inline'` without a nonce or hash; `*`, `https:`, `http:`, `data:` or `blob:` as script sources.
4. Check `'unsafe-eval'` and `'unsafe-hashes'`; note which code needs them (DevTools Console violations after removing them in a local override, or the client's explanation).
5. Check `style-src` separately and rate it separately.
6. If you have a confirmed HTML injection point from XSS testing, and execution proofs are agreed, inject a harmless marker (`alert(document.domain)` in an inline script) and observe whether the browser blocks it. Blocked with a CSP console error = the policy works for that vector.

#### Observation

Ineffective (illustrative):

```http
content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https: data:; style-src 'self' 'unsafe-inline'
```

CSP Evaluator output for it, paraphrased: `script-src` allows `'unsafe-inline'` (High), `https:` and `data:` allow any script (High), `'unsafe-eval'` (Medium), `object-src` and `base-uri` missing (High/Medium).

Strict (illustrative):

```http
content-security-policy: script-src 'nonce-mD3kQ9yJ0b6vF1sXc7Ewgw' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'
```

CSP Evaluator recognises the `https:` and `'unsafe-inline'` here as backward-compatibility fallbacks that modern browsers ignore.

#### Evaluation

- **Fail** if the effective script policy allows `'unsafe-inline'` without a nonce or hash, or `*`, `https:`, `http:`, `data:` or `blob:` as script sources: the policy does not mitigate XSS.
- **Fail (lesser)** for `'unsafe-eval'` without a documented need.
- **Weakness** for a host allow-list without nonces: carry each host to test 4.
- **Pass** for nonce- or hash-based policies with `'strict-dynamic'`, or a tight allow-list of first-party hosts that test 4 clears.

#### False positives

- `'unsafe-inline'` and `https:` next to a nonce or hash and `'strict-dynamic'`: fallbacks, ignored by modern browsers. Not a finding.
- `'unsafe-inline'` in `style-src` only: a separate, lower-rated finding, not "CSP allows inline script".
- `'wasm-unsafe-eval'`: allows WebAssembly compilation, not JavaScript `eval`.
- Scanner findings on a policy that a second, stricter enforced policy overrides through intersection.

#### Automation

The library runs in Node.js and fits a CI step that fails on High findings:

```javascript
// csp-check.js - node csp-check.js "<policy text>"
const { CspEvaluator } = require("csp_evaluator/dist/evaluator.js");
const { CspParser } = require("csp_evaluator/dist/parser.js");
const { Severity } = require("csp_evaluator/dist/finding.js");

const policy = process.argv[2];
const findings = new CspEvaluator(new CspParser(policy).csp).evaluate();
for (const f of findings) {
  console.log(`${Severity[f.severity]}\t${f.directive}\t${f.description}`);
}
// Severity.HIGH is the lowest number; fail the build on HIGH or SYNTAX
process.exit(findings.some((f) => f.severity <= Severity.SYNTAX) ? 1 : 0);
```

### GT-WEB-CSP-4: Check allow-listed hosts for JSONP, old libraries and user content

*Guler Tech methodology.* Implements the JSONP, wildcard and "trusted third-party endpoints" checks in WSTG-CONF-12 ("Determine whether allowlisted domains host JSONP endpoints or user-controlled content").

#### What it checks

Whether any host in `script-src` (or `default-src` when it governs scripts) serves content an attacker could use as script while staying inside the policy.

#### Prerequisites

The host list from test 3. Only relevant for allow-list policies, or nonce policies without `'strict-dynamic'`.

#### Steps

1. List every host and path in the script directive. Expand `'self'` to "this origin" and note whether the origin serves user uploads, user-controlled JavaScript, or JSONP.
2. Check each host against known-gadget lists: CSP Evaluator flags common JSONP and AngularJS hosts; [CSPBypass](https://cspbypass.com/) searches a community list by host.
3. For first-party hosts, look for JSONP yourself: in Burp history, search responses with `Content-Type: application/javascript` for parameters named `callback`, `cb`, `jsonp`. Request one with a harmless callback name and check whether it is echoed:

   ```bash
   curl -sS 'https://api.example.com/v1/status?callback=gtCspCheck' | head -c 120
   # gtCspCheck({"status":"ok"})   <- callback reflected into script: JSONP
   ```

   That response alone shows the endpoint is usable as a script source. Do not go further than reflecting a harmless identifier.
4. For CDN hosts, note whether the policy allows the whole host (`https://cdn.jsdelivr.net`) or a path (`https://cdn.jsdelivr.net/npm/some-lib@1.2.3/`). Whole-host allow-lists on package CDNs trust every package ever published there, including old AngularJS versions.
5. For wildcards, list the matching subdomains you know of and ask whether any serves user content or points to an unclaimed third-party service (a dangling DNS record is a subdomain-takeover lead; report it to the client, do not claim it).
6. If, and only if, you have an in-scope HTML injection point and execution proofs are agreed, confirm one gadget with a harmless marker (`alert(document.domain)` or a `console.log` marker) on a page only your test account sees. Otherwise stop at step 3 or 4 evidence.

#### Observation

Weak (illustrative):

```http
content-security-policy: script-src 'self' https://www.googleapis.example https://cdn.jsdelivr.net https://*.example.com; object-src 'none'
```

Findings from this policy: the whole of `cdn.jsdelivr.net` is trusted; `*.example.com` includes `files.example.com`, which serves user uploads; `'self'` includes `/v1/status?callback=` (JSONP).

#### Evaluation

- **Fail** if any allowed script host serves a JSONP endpoint with a controllable callback, user-uploaded or user-authored content served as script, or a framework known to evaluate markup (AngularJS 1.x); or if a wildcard covers a host with such content.
- **Weakness** for whole-host allow-lists on public package CDNs even without a demonstrated gadget.
- **Pass** if every allowed host serves only first-party, versioned, static scripts (ideally pinned by path and protected with SRI).

#### False positives

- A JSONP endpoint that ignores the callback value (fixed function name) or validates it against a strict pattern, such as letters and dots only: lower risk, though a fixed name can still sometimes be chained. Report it as a hardening item.
- Gadget-list entries for hosts that have since removed the endpoint: check that the endpoint still answers.
- Policies where `'strict-dynamic'` is present: browsers that support it ignore host sources entirely, so host gadgets do not apply.

#### Automation

CSP Evaluator's built-in bypass list in CI (test 3 script). A grep of Burp history for reflected `callback=` parameters is a quick repeatable check per engagement.

### GT-WEB-CSP-5: Test nonce and hash quality

*Guler Tech methodology.* Implements "Validate Nonce, Hash, and strict-dynamic Usage" and "Nonce Reuse or Predictable Nonces" in WSTG-CONF-12.

#### What it checks

That nonces are unpredictable, unique per response, never served from a shared cache, and not handed to injected content; and that hashed inline scripts are not gadgets.

#### Prerequisites

A nonce- or hash-based policy. Access to pages served both directly and through any CDN.

#### Steps

1. Request the same page five times and extract the nonce each time:

   ```bash
   for i in 1 2 3 4 5; do
     curl -sS -o /dev/null -D - https://app.example.com/ \
     | grep -io "nonce-[A-Za-z0-9+/=_-]*" | head -1
     sleep 1
   done
   ```

2. Compare: identical values, values that differ only in a counter or timestamp, or short values (under about 22 base64 characters, which is 128 bits) are findings.
3. Repeat with a session cookie and from a second account. A nonce derived from the session would repeat for the same session.
4. Check caching: request a cached page twice and compare `age`/cache-status and the nonce. Same nonce with a cache hit means the HTML and its nonce are shared between users.
5. Compare the header nonce with the `nonce` attributes in the HTML body. They must match. Check whether the nonce appears anywhere else: in URLs, JSON, `data-` attributes, or JavaScript variables.
6. Check that user-supplied HTML (comments, rich-text fields, profile bios in your own test account) does not come back with `nonce` attributes added. If the application uses a sanitiser, check that it strips `nonce` and `script`.
7. For hash-based policies, list the hashed inline scripts and read them: does any of them read from `location`, `document.cookie`, `postMessage`, `window.name` or a DOM element an injection could control, and write to a sink? If so, it is a gadget (carry it to [DOM XSS](/web/web-dom-xss-client-side-injection/)).
8. Check `base-uri` is `'none'` or `'self'` (test 6), since a missing `base-uri` lets an injected `base` element redirect relative nonced scripts.

#### Observation

Vulnerable (illustrative): the same nonce across requests and users, served from cache.

```text
nonce-R3VsZXJUZWNoMjAyNg   age: 0     cf-cache-status: MISS
nonce-R3VsZXJUZWNoMjAyNg   age: 112   cf-cache-status: HIT
nonce-R3VsZXJUZWNoMjAyNg   age: 113   cf-cache-status: HIT
```

Correct: a fresh 128-bit value per response, and the HTML marked uncacheable at shared caches (`Cache-Control: private` or `no-store`).

```text
nonce-mD3kQ9yJ0b6vF1sXc7Ewgw
nonce-2QfV0r8T1LkqvYc4oH9xNA
nonce-Zp6rB2u7JqW1sE0dKc3yTg
```

#### Evaluation

- **Fail** if the nonce repeats across responses, is predictable, is shorter than 128 bits, or is shared through a cache.
- **Fail** if injected or user-supplied markup receives a valid nonce.
- **Fail (gadget)** if a hashed or nonced inline script passes attacker-controlled input to a script sink.
- **Pass** if nonces are fresh, random and at least 128 bits on every response, never cached in shared caches, and appear only in the header and in server-written script tags.

#### False positives

- The same nonce on *every script tag within one response*: that is how nonces work.
- Browsers hide the `nonce` attribute value from the DOM (reading the attribute returns an empty string; the `nonce` IDL property keeps the value). Seeing an empty attribute in the Elements panel is not a bug.
- Static sites with hash-based policies: no nonce to test; focus on step 7.

#### Automation

The loop in step 1 is a good CI check against a staging build: fail if two consecutive responses share a nonce or if the nonce decodes to fewer than 16 bytes.

### GT-WEB-CSP-6: Check object-src, base-uri, form-action and other non-fallback directives

*Guler Tech methodology.* Implements "Missing Defense-in-Depth Directives" in WSTG-CONF-12 and the minimum directives in ASVS `v5.0.0-3.4.3`.

#### What it checks

That the policy sets the directives that close common gaps, including those that do **not** inherit from `default-src`.

#### Prerequisites

The enforced policy text.

#### Steps

1. Check `object-src`: explicitly `'none'`, or inherited from a `default-src 'none'`.
2. Check `base-uri`: `'none'` or `'self'`. Not inherited from `default-src`.
3. Check `form-action`: `'self'` plus the real form targets (payment provider, identity provider). Not inherited from `default-src`.
4. Check `frame-ancestors` (detail in test 7). Not inherited.
5. Note `upgrade-insecure-requests` (harmless and useful during HTTPS migrations) and deprecated directives (`block-all-mixed-content`, `plugin-types`, `prefetch-src`, `referrer`, `reflected-xss`), which are ignored and suggest an unreviewed policy.
6. For pages that render user uploads or untrusted HTML (preview pages, HTML email viewers), check for `sandbox` in the policy or a separate origin.

#### Observation

Incomplete (illustrative): looks restrictive, leaves three gaps.

```http
content-security-policy: default-src 'none'; script-src 'nonce-mD3kQ9yJ0b6vF1sXc7Ewgw' 'strict-dynamic'; style-src 'self'; img-src 'self'; connect-src 'self'
```

`object-src` is covered by `default-src 'none'`. `base-uri`, `form-action` and `frame-ancestors` are not: the page can be framed by anyone, an injected `base` redirects relative nonced scripts, and an injected form can post anywhere.

#### Evaluation

- **Fail** if `object-src` is not effectively `'none'` or if `base-uri` is absent (ASVS `v5.0.0-3.4.3` minimum).
- **Fail (lesser)** if `form-action` is absent on pages with forms that carry credentials or tokens.
- **Pass** if `object-src 'none'`, `base-uri 'none'` (or `'self'`) and a specific `form-action` are present on every HTML response.

#### False positives

- `base-uri 'self'` rather than `'none'`: acceptable when the page legitimately uses a same-origin `base` element.
- A missing `form-action` on pages with no forms at all: low value, still cheap to add.

#### Automation

A CI assertion that the CSP header contains `object-src 'none'`, `base-uri` and `form-action` on HTML routes; CSP Evaluator also flags missing `object-src` and `base-uri`.

### GT-WEB-CSP-7: Verify frame-ancestors and X-Frame-Options

*Guler Tech methodology.* Implements the header-review part of WSTG-CLNT-09 (clickjacking), the `frame-ancestors` checks in WSTG-CONF-12 and the X-Frame-Options checks in WSTG-CONF-14. The framing proof itself is in [clickjacking and tabnabbing](/web/web-clickjacking-tabnabbing/).

#### What it checks

Which origins may frame each HTML response, and whether the control is one that current browsers honour.

#### Prerequisites

The inventory from test 1, especially pages with state-changing actions (settings, payments, approvals, OAuth consent, account deletion).

#### Steps

1. For each HTML response, record `frame-ancestors` from the **header** policy and `X-Frame-Options`.
2. Discard `frame-ancestors` from `meta` policies; browsers ignore it there.
3. Classify: `'none'` (no framing), `'self'`, a list of specific origins, or permissive (`*`, `https:`, wildcard hosts).
4. If only `X-Frame-Options` is present, check its value: `DENY` and `SAMEORIGIN` work in current browsers; `ALLOW-FROM` does not, and browsers then allow framing.
5. For pages that legitimately need framing (an embeddable widget, a payment iframe), check that framing is allowed only on those routes and only for named origins.
6. If the header suggests framing is possible on a sensitive page, confirm it with a local proof-of-concept HTML file opened in your own browser against your own test account, as described in the clickjacking note. The file only shows that the page renders in a frame; it sends nothing anywhere.

#### Observation

```bash
curl -sS -o /dev/null -D - https://app.example.com/settings/delete-account \
  | grep -iE '^(content-security-policy|x-frame-options):'
# x-frame-options: ALLOW-FROM https://partner.example.org
#  -> ignored by modern browsers; no frame-ancestors: page is frameable by anyone
```

Correct:

```http
content-security-policy: ...; frame-ancestors 'none'
x-frame-options: DENY
```

#### Evaluation

- **Fail** if a page with sensitive one-click or few-click actions has no effective framing control (no `frame-ancestors` in a header policy and no valid `X-Frame-Options`), or allows any origin.
- **Weakness** if protection relies only on `X-Frame-Options` (ASVS `v5.0.0-3.4.6` expects `frame-ancestors`), or on `ALLOW-FROM`.
- **Pass** if every HTML response carries `frame-ancestors 'none'` or `'self'` by default, with named origins only on routes designed for embedding.

#### False positives

- Public, read-only pages without actions (marketing pages, documentation): framing them has little impact; report as Info at most.
- Routes deliberately embeddable (widgets, oEmbed endpoints), when they contain no authenticated actions.
- API JSON without framing headers: the impact is low; recommend `frame-ancestors 'none'` as cheap hardening.

#### Automation

ZAP rule 10020 checks for framing headers. A CI assertion that `frame-ancestors` is present on every HTML route, with an explicit allow-list of routes that may differ.

### GT-WEB-CSP-8: Review Trusted Types enforcement

*Guler Tech methodology.* Implements "Review Trusted Types Interaction" in WSTG-CONF-12. Sink-level testing belongs to WSTG-CLNT-01 and the [DOM XSS note](/web/web-dom-xss-client-side-injection/).

#### What it checks

Whether Trusted Types are actually enforced, and whether the declared policies are restrictive enough to matter.

#### Prerequisites

The enforced and report-only policies; access to the front-end JavaScript (source maps or bundle) to read policy implementations.

#### Steps

1. Look for `require-trusted-types-for 'script'` in the **enforced** policy. Without it, `trusted-types` alone enforces nothing.
2. Record the `trusted-types` value: named policies, `'none'`, `'allow-duplicates'`, or `*`.
3. In the bundle, search for `trustedTypes.createPolicy(` and read each policy's `createHTML`, `createScript` and `createScriptURL`. A policy that returns its input unchanged, or a `default` policy that does so, defeats the control.
4. In the browser with the page loaded, open the Console and assign a string to a sink in your own session (for example, run `document.body.innerHTML = 'GT-CSP-8'` in DevTools). With enforcement, the browser throws a Trusted Types error instead of rendering the text; with a permissive `default` policy, it renders. This touches only your own tab.
5. Check browser coverage in the client's supported-browser list; MDN compatibility data lists Trusted Types in Chrome 83, Firefox 148 and Safari 26 at the time of writing.

#### Observation

Not enforced (illustrative):

```http
content-security-policy: script-src 'nonce-mD3kQ9yJ0b6vF1sXc7Ewgw' 'strict-dynamic'; object-src 'none'; base-uri 'none'; trusted-types app-sanitizer
```

Enforced, with named policies:

```http
content-security-policy: script-src 'nonce-mD3kQ9yJ0b6vF1sXc7Ewgw' 'strict-dynamic'; object-src 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types app-sanitizer dompurify
```

#### Evaluation

- **Fail (weakness)** if `trusted-types` is declared but `require-trusted-types-for 'script'` is missing from the enforced policy; if `trusted-types *` is used; or if a `default` or named policy passes strings through without sanitising.
- **Not applicable / Info** if Trusted Types are not used at all: they are not required by ASVS 5.0, but recommend them for applications with many DOM sinks or a history of DOM XSS.
- **Pass** if Trusted Types are enforced with a small set of named policies whose implementations sanitise (for example with DOMPurify) or validate URLs.

#### False positives

- Trusted Types in report-only during migration, with an enforcing date: report as in-progress.
- Policies whose `createHTML` calls a sanitiser: that is the intended design, not a pass-through.

#### Automation

A unit test in the front-end suite that assigns a string to `innerHTML` under the production CSP (in a headless browser) and expects a `TypeError`. Lint rules that ban direct sink assignments outside policy modules.

### GT-WEB-CSP-9: Verify CSP reporting

*Guler Tech methodology.* Implements "Evaluate CSP Reporting Mechanisms" in WSTG-CONF-12, and the reporting requirement in ASVS `v5.0.0-3.4.7`.

#### What it checks

That violation reports are configured, actually delivered, go somewhere appropriate, and do not leak sensitive URL data or create new attack surface.

#### Prerequisites

The policies and `Reporting-Endpoints` header; a browser with DevTools.

#### Steps

1. Record `report-uri` and `report-to` values, and the `Reporting-Endpoints` header (or the legacy `Report-To` header).
2. Check that every `report-to` name matches an endpoint declared in `Reporting-Endpoints` on the same response.
3. Note where reports go: first-party endpoint, or a third-party reporting service. If third-party, consider what `document-uri`, `blocked-uri` and the `referrer` field carry for pages with tokens or personal data in the URL.
4. Trigger one violation in your own browser to confirm delivery: in DevTools on a page you are logged into as your test account, run a harmless statement the policy blocks (for example inserting an inline script element whose body is `console.log('GT-CSP-9')`). Watch the Network panel for the report request (`report-uri` sends a `POST` with `application/csp-report`; the Reporting API batches `application/reports+json` and may send later).
5. Send one well-formed report to a first-party endpoint yourself and check the response code. Do not flood it. If the client shows you the report dashboard, check that report fields are displayed encoded (a report field containing `GT-CSP-9-marker` should appear as text).

#### Observation

Broken (illustrative): the name in the policy has no endpoint.

```http
content-security-policy: script-src 'nonce-mD3kQ9yJ0b6vF1sXc7Ewgw' 'strict-dynamic'; object-src 'none'; base-uri 'none'; report-to csp-endpoint
reporting-endpoints: default="https://app.example.com/reports"
```

Correct, with a `report-uri` fallback for browsers without `report-to`:

```http
reporting-endpoints: csp="https://app.example.com/csp-reports"
content-security-policy: script-src 'nonce-mD3kQ9yJ0b6vF1sXc7Ewgw' 'strict-dynamic'; object-src 'none'; base-uri 'none'; report-uri https://app.example.com/csp-reports; report-to csp
```

#### Evaluation

- **Fail** (L3) if no reporting location is configured (ASVS `v5.0.0-3.4.7`), or if `report-to` references an undeclared endpoint and there is no `report-uri`.
- **Fail (data exposure)** if reports containing tokens or personal data in URLs go to a third party without the client having accepted that.
- **Fail** if the report viewer renders report fields unencoded (that is a stored XSS in internal tooling; report it as such).
- **Pass** if reports reach a first-party (or contractually covered) endpoint, both mechanisms are configured during the transition, and the endpoint is rate-limited.

#### False positives

- Reports that do not arrive immediately: the Reporting API batches and delays delivery; wait or check the browser's reporting internals before concluding it is broken.
- A missing reporting directive at L1/L2: recommended, not required.

#### Automation

Assert in CI that `report-to` names match `Reporting-Endpoints` keys. Monitor report volume in production; a sudden spike is either a broken deploy or an attack.

### GT-WEB-CSP-10: Verify HSTS and the HTTP-to-HTTPS path

*Guler Tech methodology.* Implements WSTG-CONF-07 (HSTS), including the preload and first-request checks, and the placement checks in WSTG-CONF-14.

#### What it checks

That every host forces HTTPS through HSTS with a long enough `max-age`, that subdomains are covered where appropriate, that the plain-HTTP entry point redirects to HTTPS on the same host, and what the preload status is.

#### Prerequisites

The host list; the inventory from test 1.

#### Steps

1. For each host, read the HSTS header on the HTTPS response:

   ```bash
   curl -sS -o /dev/null -D - https://app.example.com/ | grep -i '^strict-transport-security:'
   ```

2. Check `max-age` (at least `31536000`), `includeSubDomains`, and `preload`.
3. Check the plain-HTTP entry point and the redirect chain one hop at a time:

   ```bash
   curl -sS -o /dev/null -D - http://example.com/     | grep -iE '^(HTTP/|location):'
   curl -sS -o /dev/null -D - https://example.com/    | grep -iE '^(HTTP/|location|strict-transport-security):'
   curl -sS -o /dev/null -D - https://www.example.com/ | grep -iE '^(HTTP/|strict-transport-security):'
   ```

   The first hop from `http://example.com` should go to `https://example.com` (same host), and the HTTPS redirect response must itself carry HSTS.
4. Check that HSTS is present on error pages, static files and API hosts too (the inventory).
5. Check preload status for the registrable domain:

   ```bash
   curl -sS "https://hstspreload.org/api/v2/status?domain=example.com"
   ```

   Compare it with the `preload` directive. Never submit a client's domain yourself.
6. If `includeSubDomains` is absent, ask the client why: usually an HTTP-only internal subdomain. Note it rather than testing internal hosts outside scope.

#### Observation

Weak (illustrative):

```http
strict-transport-security: max-age=86400
```

Correct for L1:

```http
strict-transport-security: max-age=31536000
```

Correct for L2 and preload-eligible:

```http
strict-transport-security: max-age=63072000; includeSubDomains; preload
```

#### Evaluation

- **Fail** if HTTPS responses on a host carry no HSTS header, or `max-age` is below one year (ASVS `v5.0.0-3.4.1`, L1).
- **Fail** (L2+) if `includeSubDomains` is missing.
- **Fail** if `http://` does not redirect to HTTPS, or the redirect goes cross-host first (the HSTS header on the HTTPS redirect for the original host is then never seen).
- **L3 only**: report missing preload list membership against `v5.0.0-3.7.4`, and mention hstspreload.org's current position that preloading is not generally recommended. `preload` in the header without list membership is an Info note.
- **Pass** if every host sends HSTS of at least a year on every HTTPS response, with `includeSubDomains` at L2+.

#### False positives

- HSTS absent on plain-HTTP responses: browsers ignore it there by design; check the HTTPS side.
- `max-age=0`: intentional when the client is rolling HSTS back; confirm with the client.
- Hosts that are only reachable over HTTPS (no port 80 listener): the first-request gap is smaller, but HSTS still matters for typed `http://` URLs and old links.

#### Automation

ZAP rule 10035; SSL Labs and the MDN Observatory report HSTS. A CI check against staging is usually meaningless (staging rarely mirrors the edge); run this check against production edge configuration in a scheduled job instead.

### GT-WEB-CSP-11: Check X-Content-Type-Options, Content-Type and Referrer-Policy

*Guler Tech methodology.* Implements the X-Content-Type-Options and Referrer-Policy checks in WSTG-CONF-14, with ASVS `v5.0.0-3.4.4`, `v5.0.0-3.4.5` and `v5.0.0-3.2.1`.

#### What it checks

That responses cannot be sniffed into a more dangerous type, that `Content-Type` values are correct (especially for user content), and that URLs carrying sensitive data are not sent to other origins in `Referer`.

#### Prerequisites

The inventory; a file you uploaded with your own test account; the list of pages whose URLs contain tokens, codes or personal data (password reset, invitation, magic-link login, search, file share links).

#### Steps

1. Check `X-Content-Type-Options: nosniff` on every response type, especially static files, uploads, API responses and downloads.
2. For each static file type and for uploaded files, compare the `Content-Type` with the content. Look for user uploads served as `text/html`, `image/svg+xml` or with no `Content-Type` from the main application origin.
3. Record `Referrer-Policy` on HTML responses. Check for per-element `referrerpolicy` attributes and `meta name="referrer"` elements that loosen it (`unsafe-url`, `no-referrer-when-downgrade`).
4. On a page whose URL carries a token (for example the password-reset page reached through your own test account's reset email), open DevTools and look at the `Referer` sent with every third-party request (scripts, images, fonts, analytics, outbound links). With `strict-origin-when-cross-origin`, cross-origin requests carry only the origin.

#### Observation

Vulnerable (illustrative): the reset page loosens the policy and loads a third-party script.

```http
GET /widget.js HTTP/2
Host: cdn.thirdparty.example.org
Referer: https://app.example.com/reset-password?token=<RESET_TOKEN_TEST_ACCOUNT>
```

Correct:

```http
HTTP/2 200
referrer-policy: no-referrer
x-content-type-options: nosniff
content-type: text/html; charset=utf-8
```

#### Evaluation

- **Fail** if `nosniff` is missing on responses that could be sniffed into a script, stylesheet or HTML (uploads, user-influenced text, API responses), or if user uploads are served from the main origin with an executable type. The latter is an XSS finding, rated as such.
- **Fail** if a page with secrets or personal data in its URL sends the full URL to other origins (`unsafe-url`, `no-referrer-when-downgrade`, or an element-level override), and the third party can plausibly read it (its logs, its script).
- **Weakness** if no `Referrer-Policy` is set at all (ASVS `v5.0.0-3.4.5`, L2), even though browser defaults now limit cross-origin leakage.
- **Pass** if `nosniff` is on every response, types are correct, and the referrer policy is `strict-origin-when-cross-origin` or stricter, with `no-referrer` on token-bearing pages.

#### False positives

- A missing `Referrer-Policy` on pages with nothing sensitive in the URL: modern browser defaults already send only the origin cross-origin; Info.
- `Referer` with the full URL on same-origin requests: expected under `strict-origin-when-cross-origin`; it goes to your own servers.
- `nosniff` missing on images or fonts: browsers do not execute them; low value.

#### Automation

ZAP rule 10021 for `nosniff`. A CI assertion on `Referrer-Policy` and `nosniff` for every route type, and an upload test that fetches an uploaded file and asserts its `Content-Type` and `Content-Disposition`.

### GT-WEB-CSP-12: Review COOP, COEP, CORP, Permissions-Policy and deprecated headers

*Guler Tech methodology.* Implements the COOP/COEP, Permissions-Policy, deprecated-header and duplicate-header checks of WSTG-CONF-14, with ASVS `v5.0.0-3.4.8` and `v5.0.0-3.5.8`.

#### What it checks

That documents are isolated from cross-origin windows where required, that authenticated resources refuse cross-site embedding, that unused powerful features are disabled, and that the header set has no dead or conflicting entries.

#### Prerequisites

The inventory; a list of the application's pop-up flows (OAuth, payments, document viewers) and embedded third-party content.

#### Steps

1. Record `Cross-Origin-Opener-Policy` on HTML responses. Values: `same-origin`, `same-origin-allow-popups`, `noopener-allow-popups` (newer; MDN data shows Chrome 131 and Safari 18.4, not Firefox), `unsafe-none` (default).
2. Record `Cross-Origin-Embedder-Policy` (`require-corp`, `credentialless`, `unsafe-none`) and whether the page reports `self.crossOriginIsolated === true` in the Console. Ask whether the application needs isolation (for `SharedArrayBuffer`, precise timers); if not, COEP is optional.
3. Record `Cross-Origin-Resource-Policy` on authenticated resources: API responses, user files, avatars, generated documents. Alternatively, ask whether the server checks `Sec-Fetch-Site`/`Sec-Fetch-Mode`/`Sec-Fetch-Dest` and rejects cross-site no-cors loads (a "resource isolation policy").
4. Record `Permissions-Policy`. Check that features the application does not use (`camera`, `microphone`, `geolocation`, `payment`, `usb`) are disabled with `=()`, and that features it does use are limited to `self` or named origins. Note that MDN data lists the header as supported in Chromium-based browsers only at the time of writing; the iframe `allow` attribute has wider support.
5. List deprecated headers and values: `X-XSS-Protection` (anything other than `0`), `Expect-CT`, `Feature-Policy`, `Public-Key-Pins`, `X-Frame-Options: ALLOW-FROM`.
6. List duplicates and typos found in the inventory.

#### Observation

Typical (illustrative):

```http
HTTP/2 200
content-type: text/html; charset=utf-8
x-xss-protection: 1; mode=block
expect-ct: max-age=86400, enforce
feature-policy: camera 'none'
```

Correct for an application without isolation needs:

```http
cross-origin-opener-policy: same-origin-allow-popups
cross-origin-resource-policy: same-site
permissions-policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
x-xss-protection: 0
```

#### Evaluation

- **Fail** (L3) if HTML responses lack COOP `same-origin` or `same-origin-allow-popups` (`v5.0.0-3.4.8`), or if authenticated resources can be embedded cross-site with neither restrictive CORP nor `Sec-Fetch-*` validation (`v5.0.0-3.5.8`).
- **Weakness / Info** for missing COOP at L1/L2 when the page has `window.opener` exposure or opens third-party windows; carry to [tabnabbing](/web/web-clickjacking-tabnabbing/).
- **Info** for missing `Permissions-Policy`, unless the page embeds untrusted third-party frames (then recommend it).
- **Info** for deprecated headers, with the recommended replacement.
- **Pass** if COOP, CORP and `Permissions-Policy` match the application's needs and no deprecated headers remain.

#### False positives

- No COEP on an application that does not need cross-origin isolation: expected.
- `X-XSS-Protection: 0`: the recommended value, not a finding.
- COOP `unsafe-none` on a page that must keep a reference to a cross-origin pop-up and cannot use `same-origin-allow-popups`: a design constraint; document it.
- CORP `cross-origin` on genuinely public assets (a public CDN for logos).

#### Automation

ZAP rules 10063 (Permissions-Policy) and 90004 (*Insufficient Site Isolation Against Spectre Vulnerability*). A CI assertion that the header set matches an expected list, including the absence of deprecated headers.

## Secure implementation

### Design rules

- **Fix the injection first.** CSP limits the damage of XSS; output encoding, safe sinks and sanitisation prevent it (see [reflected and stored XSS](/web/web-reflected-stored-xss/) and [DOM XSS](/web/web-dom-xss-client-side-injection/)).
- **Use a strict CSP for script**: per-response nonce (or hashes for static pages) plus `'strict-dynamic'`, `object-src 'none'`, `base-uri 'none'`. Add `frame-ancestors` and `form-action` because they do not inherit from `default-src`.
- **Set headers at one layer, for every response.** Prefer the outermost layer you control (edge or reverse proxy) for static headers (HSTS, nosniff, Referrer-Policy, COOP, CORP, Permissions-Policy, a fallback CSP), and the application for the nonce-bearing CSP. Make sure error pages, redirects and static files get them.
- **Deliver CSP in a header**, not a `meta` element.
- **Roll out with report-only, then enforce**, and keep reporting on after enforcement.
- **Do not cache nonced HTML in shared caches.**
- **Send only headers you understand.** Remove `Expect-CT`, `Feature-Policy`, HPKP; send `X-XSS-Protection: 0` or nothing.
- **Write the header set down** (ASVS `v5.0.0-3.1.1` at L3 asks for documented browser security features) and test it in CI.

A baseline for an HTML application, before tuning (the nonce placeholder is filled per response):

```http
Content-Security-Policy: script-src 'nonce-{RANDOM}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; report-uri https://app.example.com/csp-reports; report-to csp
Reporting-Endpoints: csp="https://app.example.com/csp-reports"
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-site
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
X-Frame-Options: DENY
```

And for a JSON API:

```http
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Content-Type-Options: nosniff
Cross-Origin-Resource-Policy: same-origin
Cache-Control: no-store
```

### Rolling out CSP: report-only, then enforce

1. **Inventory** inline scripts, inline event handlers (`onclick=`), `javascript:` links and `eval` use. Event handlers and `javascript:` URLs cannot carry nonces; move them into script files with `addEventListener`.
2. **Add nonces** to every server-written `script` tag (templating does this once in the layout). Bundler-injected tags need the nonce too (Vite, webpack and framework integrations support it).
3. **Ship the strict policy as `Content-Security-Policy-Report-Only`** with reporting, alongside whatever enforced policy exists today. Watch reports for a few weeks; most will be browser extensions and can be filtered by `source-file`.
4. **Fix legitimate violations** in code, not by widening the policy.
5. **Switch to `Content-Security-Policy`**. Keep a report-only header for the next tightening step (Trusted Types, removing fallbacks).
6. **Add the policy to CI** so a new inline script fails tests rather than production.

### Nonces per response

- Generate at least 16 bytes from a CSPRNG and base64-encode them, for **each response**: `crypto.randomBytes(16)` in Node.js, `secrets.token_bytes(16)` or the framework's helper in Python, `SecureRandom` in Java, `random_bytes(16)` in PHP.
- Put the same value in the header and in every server-written `script` (and `style`, if used) tag in that response.
- Never derive it from the session, the time, or a counter, and never reuse it across responses.
- Mark nonced HTML `Cache-Control: private, no-store` (or vary it per user) so CDNs and shared proxies do not serve one nonce to many users. For static HTML that must be cached at the edge, use a hash-based policy or inject the nonce at the edge per response.
- Do not let sanitisers keep `nonce` attributes in user HTML, and do not run "add nonce to all script tags" filters over the final response body.

### Node.js and Express (helmet)

Helmet 8 sets a reasonable header set with one call. Its defaults at the time of writing (8.3.0) are: an allow-list CSP (`default-src 'self'; base-uri 'self'; font-src 'self' https: data:; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; object-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self' https: 'unsafe-inline'; upgrade-insecure-requests`), `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `Origin-Agent-Cluster: ?1`, `Referrer-Policy: no-referrer`, `Strict-Transport-Security: max-age=31536000; includeSubDomains` (raised from 180 days in version 8), `X-Content-Type-Options: nosniff`, `X-DNS-Prefetch-Control: off`, `X-Download-Options: noopen`, `X-Frame-Options: SAMEORIGIN`, `X-Permitted-Cross-Domain-Policies: none` and `X-XSS-Protection: 0`, and it removes `X-Powered-By`. `Cross-Origin-Embedder-Policy` has been off by default since version 7. The default CSP is an allow-list policy (`script-src 'self'`), so `'self'` must not serve user uploads or JSONP; for a strict policy, add a nonce:

```javascript
import crypto from "node:crypto";
import express from "express";
import helmet from "helmet";

const app = express();

// 1. A fresh nonce for every response
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString("base64");
  next();
});

// 2. Strict CSP plus the rest of helmet's headers
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        scriptSrc: [(req, res) => `'nonce-${res.locals.cspNonce}'`, "'strict-dynamic'"],
        objectSrc: ["'none'"],
        baseUri: ["'none'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
        reportUri: ["/csp-reports"],
        reportTo: ["csp"],
      },
    },
    strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" }, // if OAuth pop-ups are used
    xFrameOptions: { action: "deny" },
  }),
);

// 3. Headers helmet does not set
app.use((req, res, next) => {
  res.setHeader("Reporting-Endpoints", 'csp="https://app.example.com/csp-reports"');
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  next();
});

// 4. Nonced HTML must not be cached by shared caches
app.get("/", (req, res) => {
  res.set("Cache-Control", "private, no-store");
  res.render("index", { cspNonce: res.locals.cspNonce });
});
```

In an EJS template:

```html
<script nonce="<%= cspNonce %>" src="/static/app.js"></script>
```

Register helmet **before** `express.static` and the routes, and before your error handler, so static files and error responses get the headers too. If nginx or a CDN serves static files directly, set the static headers there as well (see [nginx and Apache](#nginx-and-apache)).

### Django

Django 6.0 added built-in CSP support (`django.middleware.csp.ContentSecurityPolicyMiddleware`, the `SECURE_CSP` and `SECURE_CSP_REPORT_ONLY` settings, and the `django.utils.csp.CSP` constants), and 6.1 added the `csp_nonce_attr` template tag. The other headers come from `SecurityMiddleware` and `XFrameOptionsMiddleware`, whose defaults are: `SECURE_CONTENT_TYPE_NOSNIFF = True`, `SECURE_REFERRER_POLICY = "same-origin"`, `SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"`, `X_FRAME_OPTIONS = "DENY"`, and **`SECURE_HSTS_SECONDS = 0`** (no HSTS until you set it).

```python
# settings.py (Django 6.x)
from django.utils.csp import CSP

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.csp.ContentSecurityPolicyMiddleware",
    # ... session, common, csrf, auth, messages ...
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "config.middleware.ExtraSecurityHeadersMiddleware",
]

SECURE_CSP = {
    "script-src": [CSP.NONCE, CSP.STRICT_DYNAMIC],
    "object-src": [CSP.NONE],
    "base-uri": [CSP.NONE],
    "frame-ancestors": [CSP.NONE],
    "form-action": [CSP.SELF],
    "report-uri": "/csp-reports/",
}

SECURE_HSTS_SECONDS = 63072000          # 2 years; ramp up from a short value first
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = False             # only after an organisational decision
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")  # only behind a proxy that sets it
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"

TEMPLATES[0]["OPTIONS"]["context_processors"].append("django.template.context_processors.csp")
```

`SecurityMiddleware` only adds HSTS to requests Django considers secure. Behind a TLS-terminating proxy, that requires `SECURE_PROXY_SSL_HEADER` (set it only if the proxy always overwrites that header), or HSTS silently never appears.

In templates, use the `csp_nonce` context variable for inline blocks and `csp_nonce_attr` for external tags:

{% raw %}
```html
<script nonce="{{ csp_nonce }}">
  window.appConfig = {{ config_json|safe }};
</script>
<script src="/static/app.js" {% csp_nonce_attr %}></script>
```
{% endraw %}

(`config_json` must be produced with `json_script` or equivalent escaping; a nonce on a block that interpolates unescaped data is the injection-inside-a-trusted-script case.)

`Reporting-Endpoints` and `Permissions-Policy` are not built in; a few lines of middleware cover them:

```python
# config/middleware.py
class ExtraSecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault("Reporting-Endpoints", 'csp="https://app.example.com/csp-reports/"')
        response.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        return response
```

Per-view exceptions use `django.views.decorators.csp.csp_override` and `csp_report_only_override`; Django's documentation notes that an override **replaces** the base policy (it does not merge), and that `csp_override({})` removes the enforced header for that view. Review every use in code review.

On Django 5.x and earlier, use **django-csp**. Version 4.0 changed the configuration format incompatibly: the old `CSP_*` settings are gone, replaced by a `CONTENT_SECURITY_POLICY` (and `CONTENT_SECURITY_POLICY_REPORT_ONLY`) dictionary with a `DIRECTIVES` key, constants from `csp.constants`, and `csp` in `INSTALLED_APPS`:

```python
# Django < 6 with django-csp 4.x
from csp.constants import NONCE, NONE, SELF, STRICT_DYNAMIC

INSTALLED_APPS += ["csp"]
MIDDLEWARE += ["csp.middleware.CSPMiddleware"]
CONTENT_SECURITY_POLICY = {
    "DIRECTIVES": {
        "script-src": [NONCE, STRICT_DYNAMIC],
        "object-src": [NONE],
        "base-uri": [NONE],
        "frame-ancestors": [NONE],
        "form-action": [SELF],
        "report-uri": "/csp-reports/",
    },
}
```

If you inherit a project with `CSP_DEFAULT_SRC`-style settings and django-csp 4.x installed, the old settings are ignored; check that the policy you think you have is the one being sent.

### Spring Security

Spring Security writes `Cache-Control`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security: max-age=31536000 ; includeSubDomains` (on HTTPS requests only), `X-Frame-Options: DENY` and `X-XSS-Protection: 0` by default. It does **not** add a CSP by default, because a sensible default depends on the application. Its `contentSecurityPolicy(...)` writer takes a fixed string, so for a nonce, generate it in a filter and write the header with a custom `HeaderWriter`:

```java
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

public class CspNonceFilter extends OncePerRequestFilter {
    public static final String ATTR = "cspNonce";
    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        request.setAttribute(ATTR, Base64.getEncoder().encodeToString(bytes));
        chain.doFilter(request, response);
    }
}
```

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;

@Configuration
public class SecurityHeadersConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .addFilterBefore(new CspNonceFilter(), HeaderWriterFilter.class)
            .headers(headers -> headers
                .addHeaderWriter((request, response) -> {
                    String nonce = (String) request.getAttribute(CspNonceFilter.ATTR);
                    response.setHeader("Content-Security-Policy",
                        "script-src 'nonce-" + nonce + "' 'strict-dynamic'; object-src 'none'; "
                        + "base-uri 'none'; frame-ancestors 'none'; form-action 'self'; "
                        + "report-uri /csp-reports; report-to csp");
                    response.setHeader("Reporting-Endpoints", "csp=\"https://app.example.com/csp-reports\"");
                })
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(63072000))
                .referrerPolicy(referrer -> referrer
                    .policy(ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                .crossOriginOpenerPolicy(coop -> coop
                    .policy(CrossOriginOpenerPolicy.SAME_ORIGIN))
                .permissionsPolicyHeader(permissions -> permissions
                    .policy("camera=(), microphone=(), geolocation=(), payment=()"))
            );
        // ... authorizeHttpRequests, login, csrf ...
        return http.build();
    }
}
```

In Thymeleaf, expose the request attribute as a model attribute (a `@ControllerAdvice` with a `@ModelAttribute("cspNonce")` method that returns `request.getAttribute(CspNonceFilter.ATTR)`) and write it with `th:attr="nonce=${cspNonce}"`; Thymeleaf 3.1 no longer exposes `#request` to templates. For a static policy without nonces, `.contentSecurityPolicy(csp -> csp.policyDirectives("..."))` is enough, and `.reportOnly()` switches it to report-only. Use `permissionsPolicyHeader(...)` rather than the deprecated `permissionsPolicy(...)` and `featurePolicy(...)`.

### Laravel

Laravel has no built-in security headers middleware. Two common approaches:

**spatie/laravel-csp (v3).** Version 3 replaced v2's *policy* classes with **presets** (`Spatie\Csp\Preset`), renamed `addDirective` to `add` and `addNonceForDirective` to `addNonce`, and changed the config keys from `policy`/`report_only_policy` to `presets`/`report_only_presets`. The shipped `Basic` preset is an allow-list with nonces (`'self'` plus a nonce for scripts and styles, `base-uri 'self'`, `object-src 'none'`). A strict preset:

```php
<?php
// app/Support/Csp/StrictPreset.php
namespace App\Support\Csp;

use Spatie\Csp\Directive;
use Spatie\Csp\Keyword;
use Spatie\Csp\Policy;
use Spatie\Csp\Preset;

class StrictPreset implements Preset
{
    public function configure(Policy $policy): void
    {
        $policy
            ->add(Directive::SCRIPT, Keyword::STRICT_DYNAMIC)
            ->addNonce(Directive::SCRIPT)
            ->add(Directive::OBJECT, Keyword::NONE)
            ->add(Directive::BASE, Keyword::NONE)
            ->add(Directive::FRAME_ANCESTORS, Keyword::NONE)
            ->add(Directive::FORM_ACTION, Keyword::SELF);
    }
}
```

```php
<?php
// config/csp.php (excerpt)
return [
    'presets' => [
        App\Support\Csp\StrictPreset::class,
    ],
    'report_uri' => env('CSP_REPORT_URI', ''),
    'report_to' => env('CSP_REPORT_TO', 'csp'),
    'reporting_endpoints' => [
        'csp' => 'https://app.example.com/csp-reports',
    ],
    'nonce_enabled' => true,
    // ...
];
```

```php
<?php
// bootstrap/app.php
use Illuminate\Foundation\Configuration\Middleware;
use Spatie\Csp\AddCspHeaders;

return Application::configure(basePath: dirname(__DIR__))
    // ->withRouting(...)
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->append(AddCspHeaders::class);
        $middleware->append(\App\Http\Middleware\SecurityHeaders::class);
    })
    ->create();
```

In Blade, add `@cspNonce` to inline `script` and `style` tags. For Vite-built assets, use a nonce generator that calls `Vite::useCspNonce()` (the package README shows one) so Vite's tags and the header share the value. Do not use the package's `@cspMetaTag` directive for the main policy; a `meta` policy cannot carry `frame-ancestors` or `report-uri`.

**Plain middleware.** Laravel's Vite documentation shows the same nonce pattern without a package. The other headers go in one middleware:

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

        $response->headers->set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        $response->headers->set('Cross-Origin-Opener-Policy', 'same-origin');
        $response->headers->set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
        $response->headers->set('X-Frame-Options', 'DENY');

        return $response;
    }
}
```

If you write the CSP yourself instead of using the package, call `Vite::useCspNonce()` before the view renders and build the header from `Vite::cspNonce()`, as the Laravel Vite documentation shows. Exceptions thrown inside the application are converted to responses within the middleware pipeline, so global middleware also covers Laravel's own 404 and 500 pages; responses generated by the web server (PHP-FPM failures, nginx 502/504, files nginx serves directly) are not, so set the static headers at the web server as well.

### nginx and Apache

Static headers belong at the web server so that static files, redirects and server-generated errors get them. In nginx, two rules decide whether they appear:

- Without `always`, `add_header` only applies to 200, 201, 204, 206, 301, 302, 303, 304, 307 and 308 responses; 404 and 500 pages get nothing.
- `add_header` directives are inherited from the enclosing level **only if the current level has none**. A `location` that adds one header (often `Cache-Control`) silently drops all the security headers set in `server`. Either repeat them (an `include` file keeps this manageable) or, on nginx 1.29.3 and later, use `add_header_inherit merge`.

```text
# /etc/nginx/snippets/security-headers.conf
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header X-Frame-Options "DENY" always;
```

```text
server {
    listen 443 ssl;
    server_name app.example.com;
    include snippets/security-headers.conf;

    # A fallback CSP for responses nginx serves itself (static HTML, error pages).
    # The application sends its own nonce-based CSP for dynamic pages.
    location /static/ {
        include snippets/security-headers.conf;        # re-include: this block adds its own header
        add_header Cache-Control "public, max-age=31536000, immutable" always;
    }

    error_page 404 /errors/404.html;
    location = /errors/404.html {
        internal;
        include snippets/security-headers.conf;
        add_header Content-Security-Policy "default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'" always;
    }
}

server {
    listen 80;
    server_name app.example.com;
    return 301 https://$host$request_uri;   # same host first, then HSTS on the HTTPS response
}
```

If both the application and nginx add `Content-Security-Policy`, the browser enforces both; pick one owner per route, or use `proxy_hide_header Content-Security-Policy` deliberately.

Apache `mod_headers` has the same split between the default ("on success") header table and `always`; use `always` so error responses are covered:

```text
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Cross-Origin-Opener-Policy "same-origin"
    Header always set X-Frame-Options "DENY"
    Header always unset X-XSS-Protection
</IfModule>
```

### CDNs and platform headers

- Configure response header rules on the CDN for **every** hostname and for cache hits and misses; then re-run the collection script against the edge, not the origin.
- If the CDN serves its own error and challenge pages, check what headers they carry; some products let you customise them.
- Hosted identity, payment and help-centre pages often have their own headers. Record them as third-party configuration and raise them with the vendor or the client's owner of that integration.
- Object-storage static sites usually need a CDN in front to add headers at all.

### A reporting endpoint

A first-party endpoint should accept both formats, store reports with a size limit and a rate limit, strip query strings from `document-uri` and `blocked-uri` before storage if they may contain tokens, and render stored fields as text. Minimal Express example:

```javascript
// Accepts report-uri (application/csp-report) and report-to (application/reports+json)
app.post(
  "/csp-reports",
  express.json({ type: ["application/csp-report", "application/reports+json"], limit: "16kb" }),
  (req, res) => {
    const reports = Array.isArray(req.body) ? req.body : [req.body];
    for (const r of reports.slice(0, 20)) {
      const body = r["csp-report"] || r.body || {};
      const strip = (u) => (typeof u === "string" ? u.split("?")[0] : u);
      logger.info({ // your structured logger
        type: "csp-violation",
        directive: body["effective-directive"] || body.effectiveDirective,
        documentUri: strip(body["document-uri"] || body.documentURL),
        blockedUri: strip(body["blocked-uri"] || body.blockedURL),
      });
    }
    res.sendStatus(204);
  },
);
```

Put a rate limiter in front of it, and treat it as an unauthenticated public endpoint in your threat model.

### Regression tests

Header regressions happen when someone adds a route, a CDN rule or a `location` block. Test **one URL per response type**, not just the home page, and assert values, not just presence.

Express with Jest and supertest:

```javascript
// test/security-headers.test.js
const request = require("supertest");
const app = require("../app");

const htmlRoutes = ["/", "/login", "/settings", "/does-not-exist-gt"];

describe.each(htmlRoutes)("security headers on %s", (path) => {
  test("strict CSP with fresh nonce", async () => {
    const a = await request(app).get(path);
    const b = await request(app).get(path);
    const csp = a.headers["content-security-policy"];
    expect(csp).toMatch(/script-src 'nonce-[A-Za-z0-9+/=]{22,}' 'strict-dynamic'/);
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain("'unsafe-inline'"); // this app sends no fallbacks; adjust if you add them
    const nonce = (h) => h["content-security-policy"].match(/'nonce-([^']+)'/)[1];
    expect(nonce(a.headers)).not.toEqual(nonce(b.headers));
  });

  test("baseline headers", async () => {
    const res = await request(app).get(path);
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["referrer-policy"]).toBe("strict-origin-when-cross-origin");
    expect(res.headers["cross-origin-opener-policy"]).toBeDefined();
    expect(res.headers["x-xss-protection"] ?? "0").toBe("0");
    expect(res.headers["expect-ct"]).toBeUndefined();
  });
});

test("API responses are not frameable or sniffable", async () => {
  const res = await request(app).get("/api/health");
  expect(res.headers["x-content-type-options"]).toBe("nosniff");
  expect(res.headers["content-security-policy"]).toContain("frame-ancestors 'none'");
});
```

Django:

```python
# tests/test_security_headers.py
import re
import pytest

NONCE_PATHS = ["/", "/accounts/login/"]          # pages whose templates use csp_nonce
HTML_PATHS = NONCE_PATHS + ["/gt-missing-page/"]  # include an error page for the baseline

@pytest.mark.parametrize("path", NONCE_PATHS)
def test_csp_is_strict_and_fresh(client, path):
    r1, r2 = client.get(path, secure=True), client.get(path, secure=True)
    csp = r1.headers["Content-Security-Policy"]
    assert re.search(r"script-src 'nonce-[A-Za-z0-9+/=_-]{22,}' 'strict-dynamic'", csp)
    assert "object-src 'none'" in csp and "base-uri 'none'" in csp
    n1 = re.search(r"'nonce-([^']+)'", csp).group(1)
    n2 = re.search(r"'nonce-([^']+)'", r2.headers["Content-Security-Policy"]).group(1)
    assert n1 != n2

@pytest.mark.parametrize("path", HTML_PATHS)
def test_baseline_headers(client, path):
    r = client.get(path, secure=True)
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert int(re.search(r"max-age=(\d+)", r.headers["Strict-Transport-Security"]).group(1)) >= 31536000
    assert r.headers["Referrer-Policy"] in {"strict-origin-when-cross-origin", "no-referrer", "same-origin"}
```

(The nonce only appears in Django's header when a template on that page uses it, which is why the nonce test uses pages with nonced scripts and the baseline test also covers an error page.)

Spring with MockMvc:

```java
@SpringBootTest
@AutoConfigureMockMvc
class SecurityHeadersTest {
    @Autowired MockMvc mvc;

    @Test
    void loginPageHasStrictCspAndBaseline() throws Exception {
        mvc.perform(get("/login").secure(true))
           .andExpect(header().string("Content-Security-Policy",
                matchesPattern(".*script-src 'nonce-[A-Za-z0-9+/=]{22,}' 'strict-dynamic'.*object-src 'none'.*base-uri 'none'.*")))
           .andExpect(header().string("X-Content-Type-Options", "nosniff"))
           .andExpect(header().string("Strict-Transport-Security", containsString("max-age=63072000")));
    }
}
```

Laravel (Pest or PHPUnit feature test):

```php
<?php
test('home page sends strict CSP and baseline headers', function () {
    $response = $this->get('/');
    $csp = $response->headers->get('Content-Security-Policy');
    expect($csp)->toMatch("/script-src[^;]*'strict-dynamic'/")
        ->and($csp)->toMatch("/'nonce-[A-Za-z0-9+\/=]{22,}'/")
        ->and($csp)->toContain("object-src 'none'");
    $response->assertHeader('X-Content-Type-Options', 'nosniff');
});
```

Then add two checks that unit tests cannot do: run `csp-check.js` (from [test 3](#gt-web-csp-3-review-script-src-for-unsafe-keywords-wildcards-and-schemes)) on the policy string in CI, and run `header_matrix.py` against the **production edge** on a schedule, alerting on any change. The second catches CDN and proxy drift, which is where most header regressions actually happen.

## Practice labs

- **PortSwigger Web Security Academy**, [Content security policy](https://portswigger.net/web-security/cross-site-scripting/content-security-policy) topic:
  - [Reflected XSS protected by CSP, with CSP bypass](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass): a policy-injection case where user input reaches the policy itself (a `report-uri` token parameter).
  - [Reflected XSS protected by very strict CSP, with dangling markup attack](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack): shows what a strict script policy does *not* stop. Do this in the lab only; the scriptless techniques it teaches are described in prose in our engagement work.
  - [Reflected XSS with AngularJS sandbox escape and CSP](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-and-csp): the allow-listed-framework gadget class from test 4.
  - Framing labs are listed in the [clickjacking](https://portswigger.net/web-security/clickjacking) topic and in our [clickjacking note](/web/web-clickjacking-tabnabbing/).
- **OWASP Juice Shop**: the **CSP Bypass** challenge (XSS category, four stars) combines a legacy page, a home-grown sanitiser and a policy the user can influence. Run [Juice Shop](https://github.com/juice-shop/juice-shop) locally and use `header_matrix.py` against it to practise the inventory; it is a good example of headers that differ between routes.
- **OWASP crAPI** and **VAmPI**: API-first labs ([crAPI](https://github.com/OWASP/crAPI), [VAmPI](https://github.com/erev0s/VAmPI)) for practising the API side of the header matrix (`nosniff`, `frame-ancestors`, `Cache-Control` on JSON).
- **Your own lab**: an Express or Django app with the configuration from [Secure implementation](#secure-implementation) behind a local nginx, where you deliberately add a `location` with its own `add_header` and watch the security headers disappear from that path. It is the fastest way to understand why header findings cluster on static files and error pages.

## Real-world cases

- **Most allow-list policies did not stop XSS (Google research, 2016).** Analysing about 100 billion pages from over a billion hostnames, Weichselbaum, Spagnuolo, Lekies and Janc found CSP on 1,680,867 hosts with 26,011 unique policies; 94.72% of distinct policies could be bypassed, 14 of the 15 hosts most often allow-listed for scripts had unsafe endpoints, and 99.34% of hosts with CSP used policies that gave no XSS protection. The paper proposed `'strict-dynamic'` and nonce-based policies, which became today's strict CSP guidance. [ACM CCS 2016 paper](https://research.google/pubs/csp-is-dead-long-live-csp-on-the-insecurity-of-whitelists-and-the-future-of-content-security-policy/).
- **A whole-domain allow-list that included AngularJS (Piwik PRO, 2023).** Gareth Heyes found that Piwik PRO's recommended CSP allowed its entire container domain, which also served AngularJS for a debugger; with any HTML injection, AngularJS expressions would run inside the policy. Reported on 2 March 2023 and fixed in the vendor's CSP deployment instructions on 7 March by allow-listing a single file and using nonces. This is the test 4 pattern, and it came from a vendor's *recommended* policy. [PortSwigger Research](https://portswigger.net/research/ambushed-by-angularjs-a-hidden-csp-bypass-in-piwik-pro).
- **Directives that do not fall back (PortSwigger, 2026).** PortSwigger's research on CSP and credential theft describes two ways a restrictive-looking policy still fails: allow-listed hosts with JSONP or old AngularJS, and the fact that `form-action` does not fall back to `default-src`, which combined with referrer behaviour lets injected markup move credentials without running any script. The defensive point is test 6: set `form-action` explicitly. [Blind trust: stealing credentials through CSP](https://portswigger.net/research/blind-trust-stealing-credentials-through-csp).
- **Password reset token leaked through Referer (Semrush, HackerOne, 2018).** The reporter opened a password reset link and clicked a social-media link on the reset page; the full reset URL, token included, went to the third party in `Referer`. Rated Low; disclosed August 2018. Browsers have since moved to `strict-origin-when-cross-origin` by default, which removes the path and query from such requests, so the same report today needs a page that loosens the policy; test 11 checks for that. [HackerOne report 342693](https://hackerone.com/reports/342693).
- **Spectre in the browser (Google, 2021).** Google published a proof of concept (leaky.page) that leaked memory from the renderer process at 1 kB/s on Chrome 88 on Intel Skylake, and asked web developers to deploy CORP and Fetch Metadata for authenticated resources, COOP for documents, and COEP where cross-origin isolation is needed. That is the rationale behind ASVS `v5.0.0-3.4.8` and `v5.0.0-3.5.8` and test 12. [Google Online Security Blog](https://security.googleblog.com/2021/03/a-spectre-proof-of-concept-for-spectre.html).
- **Uploads loaded as script under `'self'` (PortSwigger, 2016).** Gareth Heyes built a JPEG that was also valid JavaScript, so a site that allowed image uploads on its own origin and `script-src 'self'` could be made to run it. The recommended defences were hosting uploads on a separate domain and not allowing the upload domain in `script-src`; `nosniff` with correct types closes the script-load route too. [Bypassing CSP using polyglot JPEGs](https://portswigger.net/research/bypassing-csp-using-polyglot-jpegs).

More write-ups are collected in [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

Headers are mitigations, so rate a header finding by **what it would have prevented**, on **which responses**, for **which data**. Three rules keep reports honest:

1. **A missing or weak header alone is usually Low or Info.** Without an exploitable bug for it to mitigate, there is no direct impact. "No CSP" on an application with no injection point you could find is a defence-in-depth gap. Many bug bounty programmes exclude missing headers entirely.
2. **A weak CSP is rated by the bug it failed to stop.** If you found an XSS, rate the XSS (see [reflected and stored XSS](/web/web-reflected-stored-xss/)); then mention in that report that the CSP did not block it and why (`'unsafe-inline'`, a JSONP host, a reused nonce). Do not add the CSP weakness as a second Medium for the same impact. Where no XSS is known, the CSP finding is Low (high-value application, policy clearly ineffective) or Info.
3. **Some header gaps have direct impact.** Missing framing protection on a page with a sensitive one-click action, a reset token sent to a third party, an upload served as HTML because of sniffing, or no HSTS on a login host can each be rated on their own, with preconditions stated.

**CVSS notes.** For browser-side outcomes, the series convention follows the FIRST CVSS v3.1 User Guide in scoring script that runs in the victim's browser (XSS) as a Scope change; navigation-only outcomes stay Scope Unchanged ([Rating client-side findings](/web/web-client-side-testing-guide/#rating-client-side-findings)). Clickjacking and token leakage via `Referer` keep Scope Unchanged in the vectors below because the impact (an action or data in the same application) stays within the application's own authority. User interaction is Required for everything that needs a victim to visit, click or be on a hostile network. Network-position attacks (HSTS) use `AV:A` with `AC:H` when they need an on-path attacker on a shared network.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| No CSP, or report-only CSP, with no known injection | Info to Low | none | Defence-in-depth gap; Low for high-value applications (banking, admin portals) or where XSS has been found before |
| CSP present but ineffective (`'unsafe-inline'` without nonce, `https:`/`*` in `script-src`, JSONP host allow-listed), no known injection | Low | none | The control exists but would not stop XSS; recommend a strict CSP |
| XSS found, and the CSP failed to block it | Medium to Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | Rate as the XSS; describe the CSP gap in the same report as a contributing factor |
| XSS found, and a strict CSP blocked execution | Low to Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N` (4.7) | Rate the injection lower, not away: one policy change or bypass makes it XSS, and markup still lands (phishing forms, dangling markup). Where only HTML injection is possible, use `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` (4.3). Still report and fix |
| Nonce reused or cached across users, no known injection | Low | none | The strict policy is reduced to "any injection can read and reuse the nonce" |
| No framing protection on a page with a sensitive one-click action | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` (6.5) | Rate as clickjacking, as in [Clickjacking and tabnabbing](/web/web-clickjacking-tabnabbing/): `I:H` (6.5) for a sensitive action (disable MFA, account deletion, payment approval), `I:L` (4.3) for a low-impact one |
| No framing protection on read-only or public pages | Info | none | Little to gain from framing |
| No HSTS on the login or authenticated host | Low to Medium | `CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N` (5.4) | On-path attacker on a shared network can strip HTTPS on the first or typed request; Low when the host has no port-80 listener and the app is low-value |
| HSTS `max-age` short or `includeSubDomains` missing | Low | `CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N` (3.7) | Partial protection; rate by what the uncovered subdomains host |
| No preload list membership | Info | none | ASVS L3 item only; hstspreload.org now advises that preloading is not generally recommended |
| Reset or invitation token sent to a third party via `Referer` | Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N` (6.8) | Third-party operator (or anyone with its logs) can take over the account; `AC:H` because the token must be used before it expires and the victim must follow the flow. Lower if tokens are single-use and short-lived |
| No `Referrer-Policy`, nothing sensitive in URLs | Info | none | Browser default already strips cross-origin paths |
| Missing `nosniff` where user-influenced content can be sniffed into HTML or script | Low to Medium | `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N` (4.4) | Scope Changed because the outcome is script in the victim's browser; if you show the stored XSS, rate it as XSS instead |
| Missing COOP / CORP at L3, or on authenticated cross-site-embeddable resources | Info to Low | none | Side-channel and window-reference hardening; rate higher only with a demonstrated XS-Leak against sensitive state |
| CSP reports with tokens sent to a third party | Low | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` (3.1) | Depends on what the URLs contain and the reporting vendor's access controls |
| Deprecated headers (`X-XSS-Protection: 1`, `Expect-CT`, `Feature-Policy`) | Info | none | Hygiene; recommend removal or the modern replacement |

When you report, give: the exact responses (URL, status, response type, host, cache status) with the header values verbatim, which response types lack the header, what an attacker would need (an injection point, a network position, a victim click), what you confirmed and what you did not, and the concrete policy or configuration you recommend.

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 / API Top 10 |
|---|---|---|---|---|
| GT-WEB-CSP-1 | WSTG-CONF-14, WSTG-CONF-12, WSTG-CONF-07 | v5.0.0-3.4.1, v5.0.0-3.4.3, v5.0.0-3.4.4 (coverage) | CWE-693 | A02:2025; API8:2023 |
| GT-WEB-CSP-2 | WSTG-CONF-12, WSTG-CONF-14 | v5.0.0-3.4.3 | CWE-693 | A02:2025 |
| GT-WEB-CSP-3 | WSTG-CONF-12 | v5.0.0-3.4.3 | CWE-693 (CWE-79 when an XSS is confirmed) | A02:2025 (A05:2025 for the XSS) |
| GT-WEB-CSP-4 | WSTG-CONF-12 | v5.0.0-3.4.3, v5.0.0-3.5.6 | CWE-183, CWE-693 | A02:2025 |
| GT-WEB-CSP-5 | WSTG-CONF-12 | v5.0.0-3.4.3 (L3 per-response nonce) | CWE-693 | A02:2025 |
| GT-WEB-CSP-6 | WSTG-CONF-12 | v5.0.0-3.4.3, v5.0.0-3.2.1 | CWE-693 | A02:2025 |
| GT-WEB-CSP-7 | WSTG-CLNT-09, WSTG-CONF-12, WSTG-CONF-14 | v5.0.0-3.4.6 | CWE-1021 | A02:2025; A06:2025 (CWE-1021 mapping) |
| GT-WEB-CSP-8 | WSTG-CONF-12, WSTG-CLNT-01 | v5.0.0-3.4.3 (defence in depth) | CWE-693 (CWE-79 for a confirmed DOM XSS) | A02:2025 |
| GT-WEB-CSP-9 | WSTG-CONF-12 | v5.0.0-3.4.7 | CWE-693; CWE-598 if reports carry secrets | A02:2025 |
| GT-WEB-CSP-10 | WSTG-CONF-07, WSTG-CONF-14 | v5.0.0-3.4.1, v5.0.0-3.7.4 | CWE-319 | A04:2025, A02:2025 |
| GT-WEB-CSP-11 | WSTG-CONF-14 | v5.0.0-3.4.4, v5.0.0-3.4.5, v5.0.0-3.2.1 | CWE-693; CWE-598 for secrets in URLs | A02:2025 |
| GT-WEB-CSP-12 | WSTG-CONF-14, WSTG-CLNT-14 | v5.0.0-3.4.8, v5.0.0-3.5.8, v5.0.0-3.1.1 | CWE-693, CWE-1022 (opener) | A02:2025; A06:2025 (CWE-1022 mapping) |

ASVS levels: `v5.0.0-3.4.1` L1 (HSTS on all responses, `max-age` at least one year, subdomains at L2+), `v5.0.0-3.2.1` L1 (stop rendering in the wrong context: `Sec-Fetch-*`, CSP `sandbox`, `Content-Disposition: attachment`), `v5.0.0-3.4.3` L2 (CSP with `object-src 'none'` and `base-uri 'none'` and an allow-list or nonces/hashes; L3 requires per-response nonces or hashes), `v5.0.0-3.4.4` L2 (`nosniff` on all responses), `v5.0.0-3.4.5` L2 (referrer policy), `v5.0.0-3.4.6` L2 (`frame-ancestors` on every response; X-Frame-Options obsolete), `v5.0.0-3.5.6` L3 (no JSONP), `v5.0.0-3.4.7` L3 (CSP reporting location), `v5.0.0-3.4.8` L3 (COOP on document responses), `v5.0.0-3.5.8` L3 (CORP or `Sec-Fetch-*` validation for authenticated resources), `v5.0.0-3.7.4` L3 (HSTS preload list), `v5.0.0-3.1.1` L3 (documented browser security features).

CWE choice: there is no specific CWE for "missing security header". CWE-693 (*Protection Mechanism Failure*) is the honest class for a mitigation that is absent or ineffective, but it is a Pillar and MITRE marks it **Discouraged** for mapping; use it only when nothing more specific fits, and prefer the CWE of the weakness the header would have mitigated when you have one (CWE-79 for XSS, CWE-1021 for framing, CWE-319 for cleartext transmission, CWE-598 for secrets in query strings, CWE-1022 for `window.opener`). CWE-183 (*Permissive List of Allowed Inputs*) fits an over-broad script allow-list. CWE-16 (*Configuration*) is a category that MITRE has marked Obsolete and Prohibited for mapping, even though the OWASP Top 10:2025 still lists it under A02; do not use it in findings. `A02:2025` is Security Misconfiguration, whose description includes servers that do not send security headers or send them with insecure values; CWE-319 maps to `A04:2025` Cryptographic Failures, which recommends HSTS; CWE-1021 and CWE-1022 appear in the `A06:2025` Insecure Design list. `API8:2023` Security Misconfiguration names missing security headers for API responses consumed by browsers.

## References

**OWASP**

- WSTG: [Test for Content Security Policy (WSTG-CONF-12)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/12-Content_Security_Policy), [Test HTTP Strict Transport Security (WSTG-CONF-07)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/07-HTTP_Strict_Transport_Security), [Test for Other HTTP Security Header Misconfigurations (WSTG-CONF-14)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/14-Other_HTTP_Security_Header_Misconfigurations), [Testing for Clickjacking (WSTG-CLNT-09)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/09-Clickjacking), [Testing for DOM-Based XSS (WSTG-CLNT-01)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/01-DOM-based_Cross_Site_Scripting), [Testing for Reverse Tabnabbing (WSTG-CLNT-14)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/14-Reverse_Tabnabbing)
- ASVS 5.0: [V3 Web Frontend Security](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md)
- [A02:2025 Security Misconfiguration](https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/), [A04:2025 Cryptographic Failures](https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/), [A06:2025 Insecure Design](https://top10.owasp.org/2025/A06_2025-Insecure_Design/); [API8:2023 Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- Cheat Sheets: [Content Security Policy](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html), [HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html), [HTTP Strict Transport Security](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html), [Clickjacking Defense](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html), [Cross Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), [REST Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [OWASP Secure Headers Project](https://owasp.org/projects/secure-headers-project) ([repository](https://github.com/OWASP/www-project-secure-headers), including the `ci/headers_add.json` recommended values)

**Standards and browser documentation**

- W3C: [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/) ([editor's draft](https://w3c.github.io/webappsec-csp/)), [Reporting API](https://www.w3.org/TR/reporting-1/), [Trusted Types](https://w3c.github.io/trusted-types/dist/spec/); IETF [RFC 6797 (HSTS)](https://datatracker.ietf.org/doc/html/rfc6797)
- MDN: [CSP guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP), [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy), [Content-Security-Policy-Report-Only](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy-Report-Only), [frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors), [form-action](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/form-action), [report-to](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/report-to), [require-trusted-types-for](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/require-trusted-types-for), [Reporting-Endpoints](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Reporting-Endpoints), [Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security), [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options), [Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy), [Cross-Origin-Opener-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy), [Cross-Origin-Embedder-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy), [Cross-Origin-Resource-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Resource-Policy), [Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy), [Sec-Fetch-Site](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Site), [crossOriginIsolated](https://developer.mozilla.org/en-US/docs/Web/API/Window/crossOriginIsolated), [Trusted Types API](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API), [X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-XSS-Protection), [Expect-CT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Expect-CT)
- [hstspreload.org](https://hstspreload.org/) (requirements, removal, status API)
- FIRST: [CVSS v3.1 User Guide](https://www.first.org/cvss/v3.1/user-guide), [CVSS v3.1 calculator](https://www.first.org/cvss/calculator/3.1)

**Google guidance and research**

- web.dev: [Mitigate XSS with a strict CSP](https://web.dev/articles/strict-csp), [Trusted Types](https://web.dev/articles/trusted-types), [Making your website cross-origin isolated using COOP and COEP](https://web.dev/articles/coop-coep), [Why you need cross-origin isolation](https://web.dev/articles/why-coop-coep), [Fetch Metadata](https://web.dev/articles/fetch-metadata), [Referrer best practices](https://web.dev/articles/referrer-best-practices), [Security headers quick reference](https://web.dev/articles/security-headers); [csp.withgoogle.com strict CSP](https://csp.withgoogle.com/docs/strict-csp.html)
- Research: [CSP Is Dead, Long Live CSP! (CCS 2016)](https://research.google/pubs/csp-is-dead-long-live-csp-on-the-insecurity-of-whitelists-and-the-future-of-content-security-policy/), [Code-Reuse Attacks for the Web: script gadgets (CCS 2017)](https://research.google/pubs/code-reuse-attacks-for-the-web-breaking-cross-site-scripting-mitigations-via-script-gadgets/), [A Spectre proof-of-concept for a Spectre-proof web](https://security.googleblog.com/2021/03/a-spectre-proof-of-concept-for-spectre.html)

**PortSwigger**

- [Content security policy](https://portswigger.net/web-security/cross-site-scripting/content-security-policy), [Clickjacking](https://portswigger.net/web-security/clickjacking), [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader), [CSP Auditor extension](https://portswigger.net/bappstore/35237408a06043e9945a11016fcbac18)
- Research: [Ambushed by AngularJS: a hidden CSP bypass in Piwik PRO](https://portswigger.net/research/ambushed-by-angularjs-a-hidden-csp-bypass-in-piwik-pro), [Blind trust: stealing credentials through CSP](https://portswigger.net/research/blind-trust-stealing-credentials-through-csp), [Bypassing CSP with policy injection](https://portswigger.net/research/bypassing-csp-with-policy-injection), [Bypassing CSP using polyglot JPEGs](https://portswigger.net/research/bypassing-csp-using-polyglot-jpegs)

**Framework and server documentation**

- Express: [helmet](https://helmetjs.github.io/) ([GitHub](https://github.com/helmetjs/helmet))
- Django: [Content Security Policy reference](https://docs.djangoproject.com/en/stable/ref/csp/), [How to use Django's CSP](https://docs.djangoproject.com/en/stable/howto/csp/), [Security middleware](https://docs.djangoproject.com/en/stable/ref/middleware/), [Settings](https://docs.djangoproject.com/en/stable/ref/settings/), [Clickjacking protection](https://docs.djangoproject.com/en/stable/ref/clickjacking/); [django-csp](https://django-csp.readthedocs.io/en/latest/) and its [4.0 migration guide](https://django-csp.readthedocs.io/en/latest/migration-guide.html)
- Spring Security: [Security HTTP response headers (servlet)](https://docs.spring.io/spring-security/reference/servlet/exploits/headers.html), [default headers](https://docs.spring.io/spring-security/reference/features/exploits/headers.html)
- Laravel: [spatie/laravel-csp](https://github.com/spatie/laravel-csp), [Vite CSP nonce](https://laravel.com/docs/13.x/vite), [Middleware](https://laravel.com/docs/13.x/middleware)
- Web servers: [nginx ngx_http_headers_module](https://nginx.org/en/docs/http/ngx_http_headers_module.html) (`add_header ... always`, `add_header_inherit`), [Apache mod_headers](https://httpd.apache.org/docs/current/mod/mod_headers.html)

**Tools**

- [CSP Evaluator](https://csp-evaluator.withgoogle.com/) ([library](https://github.com/google/csp-evaluator)), [CSPBypass](https://cspbypass.com/), [MDN HTTP Observatory](https://developer.mozilla.org/en-US/observatory) ([CLI](https://github.com/mdn/mdn-http-observatory)), [httpx](https://github.com/projectdiscovery/httpx)
- ZAP alerts: [CSP Header Not Set (10038)](https://www.zaproxy.org/docs/alerts/10038/), [CSP (10055)](https://www.zaproxy.org/docs/alerts/10055/), [Strict-Transport-Security Header (10035)](https://www.zaproxy.org/docs/alerts/10035/), [X-Content-Type-Options Header Missing (10021)](https://www.zaproxy.org/docs/alerts/10021/), [Permissions Policy Header Not Set (10063)](https://www.zaproxy.org/docs/alerts/10063/), [Insufficient Site Isolation Against Spectre (90004)](https://www.zaproxy.org/docs/alerts/90004/)
- Labs: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) ([companion guide](https://pwning.owasp-juice.shop/)), [OWASP crAPI](https://github.com/OWASP/crAPI), [VAmPI](https://github.com/erev0s/VAmPI)

**CWE**

- [CWE-693](https://cwe.mitre.org/data/definitions/693.html), [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html), [CWE-319](https://cwe.mitre.org/data/definitions/319.html), [CWE-598](https://cwe.mitre.org/data/definitions/598.html), [CWE-1022](https://cwe.mitre.org/data/definitions/1022.html), [CWE-183](https://cwe.mitre.org/data/definitions/183.html), [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CWE-16](https://cwe.mitre.org/data/definitions/16.html)
