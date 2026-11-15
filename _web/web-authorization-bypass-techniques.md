---
title: "Bypassing the Authorization Schema: Forced Browsing, Path and Header Tricks"
date: 2026-11-15 18:04:00 +0000
subcategory: access-control
summary: "Find where authorisation only holds at the edge: stripped sessions, forced browsing, path and method variants, override and IP headers, client-side checks."
refs: [WSTG-ATHZ-02, WSTG-CONF-05, WSTG-CONF-06, WSTG-CONF-13, WSTG-ATHN-04, v5.0.0-8.3.1, v5.0.0-8.2.1, v5.0.0-4.1.3, v5.0.0-4.1.4, v5.0.0-15.3.4, v5.0.0-13.4.5, v5.0.0-8.4.2, "API5:2023", "API8:2023", "API9:2023", "A01:2025", CWE-285, CWE-288, CWE-425, CWE-602, CWE-290, CWE-647, CWE-650, CWE-293]
tags: [web, access-control, authorization-bypass, forced-browsing, path-normalisation, http-methods]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and its [Access Control hub](/web/web-access-control-testing-guide/). It covers the bypasses that work because an authorisation decision is made in the wrong place or on the wrong input. Sometimes nothing checks the request at all, because a page or API route was never registered with the auth middleware. Sometimes a reverse proxy or gateway checks a path that the back-end then reads differently: different case, a trailing slash, an encoded character, a `;` path parameter, a `.json` suffix. Sometimes a rule matches `GET` but the handler also answers `HEAD`, `POST` or an override header. Sometimes the application trusts something the client controls: `X-Original-URL`, `X-Forwarded-For`, `Referer`, a `role` cookie, or a check that only exists in the single-page app's JavaScript. The note also covers published framework CVEs of this class, such as the Next.js middleware bypass (CVE-2025-29927) and the Spring Security path-matching advisories. We treat those as version checks plus a harmless confirmation, not as exploitation recipes. It implements WSTG-ATHZ-02 (Bypassing Authorization Schema) and the access-control parts of WSTG-CONF-06 (HTTP Methods) and WSTG-CONF-13 (Path Confusion). Object-level checks are covered in [IDOR and BOLA](/web/web-idor-bola/), and role and function-level checks in [vertical privilege escalation and BFLA](/web/web-vertical-privilege-escalation-bfla/).

## Contents

- [How it works](#how-it-works)
  - [Where the decision is made](#where-the-decision-is-made)
  - [How a request reaches a handler](#how-a-request-reaches-a-handler)
  - [Why two parsers disagree](#why-two-parsers-disagree)
  - [What changes in SPAs, APIs and mobile back-ends](#what-changes-in-spas-apis-and-mobile-back-ends)
- [What goes wrong](#what-goes-wrong)
  - [Routes outside the auth layer](#routes-outside-the-auth-layer)
  - [Unlinked is not protected](#unlinked-is-not-protected)
  - [Path normalisation mismatch](#path-normalisation-mismatch)
  - [Method-specific rules](#method-specific-rules)
  - [Headers that rewrite the request](#headers-that-rewrite-the-request)
  - [Trusting the client's network location](#trusting-the-clients-network-location)
  - [Referer and step-order checks](#referer-and-step-order-checks)
  - [Authorisation state the client controls](#authorisation-state-the-client-controls)
  - [Framework bugs of the same class](#framework-bugs-of-the-same-class)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-WEB-BYP-1: Strip the session from authenticated requests](#gt-web-byp-1-strip-the-session-from-authenticated-requests)
  - [GT-WEB-BYP-2: Forced browsing to unlinked pages and API routes](#gt-web-byp-2-forced-browsing-to-unlinked-pages-and-api-routes)
  - [GT-WEB-BYP-3: Path normalisation variants against edge rules](#gt-web-byp-3-path-normalisation-variants-against-edge-rules)
  - [GT-WEB-BYP-4: Path parameters and suffix matching on Java stacks](#gt-web-byp-4-path-parameters-and-suffix-matching-on-java-stacks)
  - [GT-WEB-BYP-5: HTTP method tampering](#gt-web-byp-5-http-method-tampering)
  - [GT-WEB-BYP-6: Method override headers and parameters](#gt-web-byp-6-method-override-headers-and-parameters)
  - [GT-WEB-BYP-7: URL override headers](#gt-web-byp-7-url-override-headers)
  - [GT-WEB-BYP-8: Client IP trust through forwarding headers](#gt-web-byp-8-client-ip-trust-through-forwarding-headers)
  - [GT-WEB-BYP-9: Referer checks and multi-step flows](#gt-web-byp-9-referer-checks-and-multi-step-flows)
  - [GT-WEB-BYP-10: Client-controlled role and privilege flags](#gt-web-byp-10-client-controlled-role-and-privilege-flags)
  - [GT-WEB-BYP-11: Client-side-only enforcement in SPAs](#gt-web-byp-11-client-side-only-enforcement-in-spas)
  - [GT-WEB-BYP-12: Known framework authorisation bypass CVEs](#gt-web-byp-12-known-framework-authorisation-bypass-cves)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Edge proxy configuration](#edge-proxy-configuration)
  - [Node.js and Express](#nodejs-and-express)
  - [Django and Django REST framework](#django-and-django-rest-framework)
  - [Spring Security](#spring-security)
  - [Laravel](#laravel)
  - [Next.js](#nextjs)
  - [Authorisation regression tests](#authorisation-regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Where the decision is made

Every request should get one question answered before any business logic runs: *is this subject allowed to perform this operation on this resource?* ASVS 5.0 states the rule directly. Authorisation is enforced at a trusted service layer and does not rely on anything an untrusted consumer can change, such as client-side JavaScript (`v5.0.0-8.3.1`, L1). Function-level access is restricted to consumers with explicit permission (`v5.0.0-8.2.1`, L1).

In a typical deployment there are several places where some kind of check can live:

| Layer | Examples | What it usually sees |
|---|---|---|
| CDN / WAF | Cloudflare, Akamai, AWS WAF rules | Raw request line, headers, client IP |
| Reverse proxy / ingress / API gateway | nginx `location` blocks, Envoy, Kong, AWS API Gateway authorizers, Kubernetes ingress annotations | Normalised or raw path (depends on product and config), headers |
| Framework middleware | Express `app.use()`, Django middleware, Spring Security filter chain, Laravel route middleware, Next.js `middleware.ts` / `proxy.ts` | The framework's parsed path and method, session, user object |
| Handler / controller | `@PreAuthorize`, DRF `permission_classes`, `Gate::authorize()`, an explicit `if (!user.can(...))` | Typed parameters, the authenticated principal, the loaded object |
| Service / data layer | Policy objects, scoped queries, row-level security | The domain object and the principal |

The bypasses in this note all exploit one pattern. **The check runs at a layer that sees a different request from the layer that acts on it**, or it runs on input the client controls. An nginx rule that denies `/admin` protects nothing if the application also serves `/Admin`, `/admin/` or `/admin;x`. A Spring Security rule protects nothing if it is written for a pattern that Spring MVC matches more broadly. A `middleware.ts` check protects nothing if the framework can be told to skip middleware. The fix is always the same: keep a coarse check at the edge if you like, but make the authoritative decision next to the handler or the data, on the same parsed request the handler uses.

### How a request reaches a handler

Each layer turns the raw request into a "path" and a "method" by its own rules:

1. **Percent-decoding.** `%61dmin` becomes `admin`. Some components decode once, some twice, some never. Some decode `%2F` to `/`, and some reject it or keep it as data.
2. **Dot-segment removal.** RFC 3986 defines how `/a/./b` and `/a/b/../c` are resolved. nginx matches `location` blocks against a URI that has already been decoded, had `.`/`..` resolved and had duplicate slashes merged ([nginx docs](https://nginx.org/en/docs/http/ngx_http_core_module.html#location)). When `proxy_pass` has no URI part, nginx forwards the request URI to the upstream *in the form the client sent it* ([nginx docs](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass)). So nginx can decide on `/admin` while the back-end receives the raw `/%61dmin` or `/x/../admin` and normalises it again by its own rules.
3. **Path parameters.** RFC 3986 allows `;` parameters in any path segment (`/admin;jsessionid=1`). Servlet containers differ in whether they strip them before `servletPath` and `pathInfo` are built. Spring Security's documentation calls this out as a source of pattern-match bypasses, and that is why its `StrictHttpFirewall` rejects un-normalised requests and removes path parameters before matching ([Spring Security: HttpFirewall](https://docs.spring.io/spring-security/reference/servlet/exploits/firewall.html)).
4. **Case and trailing slash.** Express treats `/Foo` and `/foo`, and `/foo` and `/foo/`, as the same route unless `case sensitive routing` or `strict routing` is enabled ([Express 5 app settings](https://expressjs.com/en/5x/api/application/)). Spring Framework 6.0 deprecated trailing-slash matching and set its default to `false`, so `/some/greeting/` stopped matching a `@GetMapping("/some/greeting")` handler by default ([Spring Framework 6.0 release notes](https://github.com/spring-projects/spring-framework/wiki/Spring-Framework-6.0-Release-Notes)). nginx prefix locations are case-sensitive on most operating systems (the docs note macOS and Cygwin as exceptions), and regex locations only ignore case with `~*`.
5. **Suffix and extension matching.** Before Spring Framework 5.3, `useSuffixPatternMatch` was on by default, so `/admin/deleteUser.anything` matched `/admin/deleteUser` ([PortSwigger](https://portswigger.net/web-security/access-control#broken-access-control-resulting-from-url-matching-discrepancies)). Spring MVC 6 uses `PathPatternParser` by default, which does not support suffix patterns.
6. **Method resolution.** Frameworks map `HEAD` onto `GET` handlers (Express's router does this whenever no explicit `HEAD` route exists). Some honour method override headers or a `_method` form field. Some legacy servers treat an unknown verb such as `FOO` as `GET` ([WSTG-CONF-06](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/06-HTTP_Methods)).
7. **URL and identity rewriting from headers.** Some stacks let headers replace parts of the request: `X-Original-URL` / `X-Rewrite-URL` replace the path (an IIS convention that Symfony honoured until CVE-2018-14773), and `X-Forwarded-For`, `X-Real-IP` and `Forwarded` replace the client IP when the app trusts them.

Wherever two of these layers apply different rules and only one of them checks authorisation, you have a candidate bypass.

### Why two parsers disagree

The research that made this class well known is Orange Tsai's Black Hat USA 2018 talk, [Breaking Parser Logic](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf). Its best-known example is nginx in front of Tomcat. nginx treats `/public/..;/admin/` as a path under `/public/`. Tomcat treats `..;` as a `..` segment carrying an empty path parameter, normalises it, and serves `/admin/` ([Acunetix description](https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/)). PortSwigger's later research on web cache deception ([Gotta cache 'em all](https://portswigger.net/research/gotta-cache-em-all), 2024) catalogues delimiter and normalisation differences between caches and origins. The same differences break access rules whenever the edge enforces them.

WSTG-CONF-13 frames it the same way. A path-confusion finding is a path that stays inside the intended scope and is syntactically valid, but different components identify it differently. That differs from directory traversal (WSTG-ATHZ-01), where the aim is to escape a directory.

### What changes in SPAs, APIs and mobile back-ends

- **SPAs** decide what to *show* in the browser: route guards in React Router, Angular `canActivate`, Vue Router `beforeEach`. Those guards are UX. The API behind them is the security boundary, and it must check every call itself. If the bundle contains an admin route table, you have a list of API endpoints to try with a normal user's token.
- **APIs** often sit behind a gateway that authenticates and then forwards identity to the back-end in a header (`X-User-ID`, `X-Auth-Request-Email`). If a client can set that header, or can reach the back-end without going through the gateway, the gateway's decision is void. ASVS `v5.0.0-4.1.3` (L2) requires that headers set by an intermediary cannot be overridden by the end user.
- **Versioned and legacy routes** (`/api/v1/` next to `/api/v2/`, `/internal/`, `/actuator/`, `/swagger.json`) are classic forced-browsing targets. OWASP API Security lists this as [API9:2023 Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/).
- **Mobile back-ends** often expose the same API as the web app with different routing, sometimes via a separate gateway with older rules. Test both hostnames. Unprotected mobile components are covered in [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/).

## What goes wrong

### Routes outside the auth layer

**What it is.** A page or API route that never passes through the authentication or authorisation check. Typical causes: the auth middleware is mounted on `/app` but the API lives on `/api`; a router is registered before `app.use(requireAuth)`; a DRF view inherits the default `AllowAny` permission because `DEFAULT_PERMISSION_CLASSES` was never set; a Spring Security chain ends in `.anyRequest().permitAll()`; a new Laravel route is added outside the `auth` middleware group; a Next.js matcher regex excludes a path that later gained sensitive data.

**Why it matters.** This is the most direct form of [CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html) and [CWE-862 Missing Authorisation](https://cwe.mitre.org/data/definitions/862.html). It is often unauthenticated and needs no tricks. The OWASP Top 10 2025 lists "force browsing ... to authenticated pages as an unauthenticated user or to privileged pages as a standard user" under [A01:2025 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/).

**Where to look.** Endpoints added late (exports, reports, webhooks, health and metrics, file downloads); API routes that the SPA calls with a token but that also answer without one; endpoints that redirect to the login page in the browser but still return data in the redirect body (PortSwigger's "data leakage in redirect" pattern).

### Unlinked is not protected

**What it is.** Functionality that is protected only because nobody links to it: `/admin`, `/administrator-panel-yb556`, `/debug`, `/api/internal/users`, `/v1/` routes left over after a migration, documentation and monitoring endpoints. The URL leaks through `robots.txt`, JavaScript bundles, source maps, OpenAPI documents, old mobile builds or error pages.

**Why it matters.** Obscurity is not access control. ASVS `v5.0.0-13.4.5` (L2) requires that documentation and monitoring endpoints are not exposed unless intended, and `v5.0.0-15.2.3` (L2) that production contains no test or development functionality.

**Where to look.** WSTG-CONF-05 (admin interfaces), WSTG-CONF-04 (old and unreferenced files), WSTG-INFO-06 (entry points), WSTG-APIT-01 (API reconnaissance).

### Path normalisation mismatch

**What it is.** The component that enforces the rule and the component that routes the request disagree on what the path is. [CWE-647 Use of Non-Canonical URL Paths for Authorisation Decisions](https://cwe.mitre.org/data/definitions/647.html) and [CWE-41 Improper Resolution of Path Equivalence](https://cwe.mitre.org/data/definitions/41.html) describe it.

**Variants.**

| Variant | Example of a request for a protected `/admin/users` | Typical disagreement |
|---|---|---|
| Case | `/ADMIN/users`, `/Admin/Users` | Case-sensitive edge rule; case-insensitive routing (Express default, IIS, Windows file systems) |
| Trailing slash | `/admin/users/` | Exact-match rule; router that ignores the trailing slash (Express default, Spring before 6.0) |
| Dot segment | `/admin/./users`, `/admin/users/.` | Raw-string rule; back-end that resolves dot segments |
| Duplicate slash | `//admin/users`, `/admin//users` | Rule anchored on `^/admin`; router that merges slashes |
| Percent-encoding | `/%61dmin/users`, `/admin%2Fusers` | Rule matched before decoding, route matched after (or the reverse) |
| Double encoding | `/%2561dmin/users` | One layer decodes once, another decodes twice |
| Path parameter | `/admin;x=1/users`, `/admin/users;` | Edge keeps `;...`, servlet container strips it |
| Dot-dot with parameter | `/public/..;/admin/users` | nginx treats it as under `/public/`, Tomcat resolves it to `/admin/users` |
| Suffix | `/admin/users.json`, `/admin/users.css` | Suffix pattern matching (Spring < 5.3 default), content negotiation by extension, frameworks that strip format suffixes |
| Unicode / overlong forms | Full-width characters, `%c0%ae` | Rare in modern stacks; mention only if the fingerprint suggests an old component |

**Why it matters.** Each successful variant shows that the authorisation rule is attached to a string, not to the resource. Fixing one variant leaves the others open, so report the root cause: the check is at the wrong layer.

### Method-specific rules

**What it is.** A rule restricts `POST /admin/deleteUser` but the handler also accepts `GET`, or `HEAD`, or any verb. Or the rule names methods (`requestMatchers(HttpMethod.GET, "/api/reports/**")`) and forgets that the same handler answers `PUT`. Or a framework honours `X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override` or a `_method` parameter. The edge then sees `POST` while the application executes `DELETE`. [CWE-650 Trusting HTTP Permission Methods on the Server Side](https://cwe.mitre.org/data/definitions/650.html) covers the server assuming a method implies intent.

**Why it matters.** WSTG-CONF-06 describes the classic `HEAD /admin/` that returns `200` instead of a `302` to login while the side effects of the `GET` handler still run. ASVS `v5.0.0-4.1.4` (L3) requires that only explicitly supported methods are accepted.

**Where to look.** Edge rules written per method; Spring Security matchers with an `HttpMethod` argument; Laravel and Symfony apps, where `_method` works on `POST` by default; Express apps using the `method-override` middleware; ASP.NET and Java apps behind WAF rules that block `PUT`/`DELETE`.

### Headers that rewrite the request

**What it is.** The back-end takes the effective path from `X-Original-URL` or `X-Rewrite-URL` instead of the request line. The front end applies its `/admin` rule to `GET /` and lets the request through; the back-end then serves `/admin`. This is an IIS URL Rewrite convention. Symfony's HttpFoundation honoured both headers until [CVE-2018-14773](https://symfony.com/blog/cve-2018-14773-remove-support-for-legacy-and-risky-http-headers) (fixed in 2.7.49, 2.8.44, 3.3.18, 3.4.14, 4.0.14 and 4.1.3; James Kettle reported it through the Drupal security team), so every Symfony-based application inherited it. The same pattern appears with `X-Forwarded-Prefix` and similar headers that change how the app builds paths.

**Why it matters.** The edge control is bypassed completely, often without authentication. It is an alternate path to protected functionality ([CWE-288](https://cwe.mitre.org/data/definitions/288.html)).

### Trusting the client's network location

**What it is.** "Internal" functionality (admin panel, status endpoint, metrics, debug, rate-limit exemptions) is allowed when the client IP is loopback or private, and the IP is read from `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `True-Client-IP`, `Forwarded` or similar headers that the client can set. Express with `trust proxy` set to `true` takes the *left-most* `X-Forwarded-For` entry as the client IP. That is the entry the client wrote ([Express: behind proxies](https://expressjs.com/en/5x/guide/behind-proxies)). [CWE-290 Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html) and [CWE-348 Use of Less Trusted Source](https://cwe.mitre.org/data/definitions/348.html) describe it.

**Why it matters.** The Fortinet CVE-2022-40684 chain set `Forwarded: for="[127.0.0.1]..."` together with a trusted `User-Agent` and got unauthenticated administrative API access ([Horizon3 analysis](https://horizon3.ai/attack-research/attack-blogs/cve-2022-40684/), [Fortinet advisory](https://www.fortiguard.com/psirt/FG-IR-22-377)). ASVS `v5.0.0-15.3.4` (L2) requires that proxies pass the original IP in fields the client cannot manipulate, and `v5.0.0-8.4.2` (L3) that network location is never the only factor for admin access.

### Referer and step-order checks

**What it is.** A sub-action (`/admin/roles/upgrade`) checks only that `Referer` contains `/admin`, on the assumption that a user can only arrive from the protected page. Or a multi-step flow (select user → review → confirm) checks authorisation on steps 1 and 2 but not on step 3. [CWE-293 Using Referer Field for Authentication](https://cwe.mitre.org/data/definitions/293.html) covers the first case. The second is an authorisation check tied to navigation rather than to the operation.

**Why it matters.** Both are trivially forged by sending the final request directly. PortSwigger has a lab for each.

### Authorisation state the client controls

**What it is.** The server stores the decision with the client and believes it on the way back: `admin=true` or `role=1` in a cookie, query parameter or hidden field; `isAdmin` in `localStorage` that the SPA sends as a header; an unsigned or unverified token claim. WSTG-ATHN-04 shows `authenticated=no` → `yes` in a parameter as the classic form. [CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html), [CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html) and [CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html) apply. Role self-assignment through profile updates is covered in [vertical privilege escalation](/web/web-vertical-privilege-escalation-bfla/), and writable fields in [mass assignment and BOPLA](/web/web-mass-assignment-bopla/).

**Why it matters.** It is a full vertical escalation from any account, and sometimes from none.

### Framework bugs of the same class

Frameworks occasionally ship the mismatch themselves. The ones below are useful because their advisories name exact versions, which gives you a version check to run:

| CVE | Component | Problem | Affected (per vendor advisory) | Fixed |
|---|---|---|---|---|
| [CVE-2025-29927](https://github.com/advisories/GHSA-f82v-jwr5-mffw) | Next.js middleware | An internal `x-middleware-subrequest` header supplied by the client could make the server skip middleware, so authorisation done only in middleware was bypassed | 12.0.0–12.3.4, 13.0.0–13.5.8, 14.0.0–14.2.24, 15.0.0–15.2.2; 11.x has no patch (use the workaround) | 12.3.5, 13.5.9, 14.2.25, 15.2.3 |
| [CVE-2016-5007](https://spring.io/security/cve-2016-5007) | Spring Security / Spring MVC | Spring Security and Spring MVC matched patterns with different strictness (for example, trimming spaces in segments) | Spring Security 4.1.0.RELEASE and earlier | 4.1.1.RELEASE with `MvcRequestMatcher` and Spring Framework 4.3.1+ |
| [CVE-2022-22978](https://spring.io/security/cve-2022-22978) | Spring Security `RegexRequestMatcher` | Regexes containing `.` could be bypassed on some servlet containers | 5.6.0–5.6.3, 5.5.0–5.5.6, 5.4.10 and earlier | 5.6.4, 5.5.7, 5.4.11 |
| [CVE-2023-20860](https://spring.io/security/cve-2023-20860) | Spring Framework with `mvcRequestMatcher` | An un-prefixed `**` pattern matched differently in Spring Security and Spring MVC | Spring Framework 6.0.0–6.0.6, 5.3.25 and earlier | 6.0.7, 5.3.26 |
| [CVE-2023-34034](https://spring.io/security/cve-2023-34034) | Spring Security WebFlux | Same `**` mismatch between Spring Security and WebFlux | 6.1.0–6.1.1, 6.0.0–6.0.4, 5.8.0–5.8.4, 5.7.0–5.7.9, 5.6.0–5.6.11 | 6.1.2, 6.0.5, 5.8.5, 5.7.10, 5.6.12 |
| [CVE-2024-38821](https://spring.io/security/cve-2024-38821) | Spring Security WebFlux static resources | Non-`permitAll` rules on static resources could be bypassed in WebFlux apps | 6.3.0–6.3.3, 6.2.0–6.2.6, 6.1.0–6.1.10, 6.0.0–6.0.12, 5.8.0–5.8.14, 5.7.12 and earlier | 6.3.4, 6.2.7 (OSS); older lines via enterprise support |
| [CVE-2018-14773](https://symfony.com/blog/cve-2018-14773-remove-support-for-legacy-and-risky-http-headers) | Symfony HttpFoundation | `X-Original-URL` / `X-Rewrite-URL` could override the request path | 2.7.0–2.7.48, 2.8.0–2.8.43, 3.3.0–3.3.17, 3.4.0–3.4.13, 4.0.0–4.0.13, 4.1.0–4.1.2 | 2.7.49, 2.8.44, 3.3.18, 3.4.14, 4.0.14, 4.1.3 |
| [CVE-2022-40684](https://www.fortiguard.com/psirt/FG-IR-22-377) | FortiOS / FortiProxy / FortiSwitchManager admin API | Trusted `Forwarded` client IP plus `User-Agent` gave unauthenticated admin API access (alternate path, CWE-288) | FortiOS 7.2.0–7.2.1 and 7.0.0–7.0.6, plus FortiProxy and FortiSwitchManager versions listed in the advisory | See advisory |

Version ranges are copied from the vendor advisories at the time of writing; re-read the advisory before you put a range in a report.

## Testing

Every test here assumes an **authorised** engagement (written scope and rules of engagement), a **bug bounty programme whose rules allow** this kind of testing, or a deliberately vulnerable **lab**. The tests are detection and verification checks: you send a variant of a request you are allowed to make and compare the response with a baseline. They are not WAF-evasion techniques. If a variant is blocked, record it and move on. All responses shown are **illustrative**; we ran nothing against a real target for this note.

### Before you start

**Accounts and roles.** Ask for at least two users per role (user A and user B), one account in every higher role the client can provide (for example support, manager, admin), and an anonymous profile (no cookies, no `Authorization` header). For multi-tenant applications, ask for two tenants with users in each. Cross-tenant proofs are covered in [multi-tenant isolation](/web/web-multi-tenant-isolation/). Record which functions each role is *meant* to reach. Without that matrix you cannot tell a bypass from intended behaviour.

**Burp project setup.**

1. Browse the whole application as the highest role you have, so that Burp's site map and Logger contain every privileged request. Then repeat as a normal user and as anonymous.
2. Add the in-scope hosts to the target scope (`app.example.com`, `api.example.com`, `admin.example.com`) and exclude everything else.
3. Install **Autorize** (or **Auth Analyzer**, or **AuthMatrix** if you prefer a role matrix). In Autorize, paste the low-privilege user's cookie or `Authorization` header and enable the unauthenticated check. Autorize then replays every request you make as admin twice more, once with the low-privilege session and once with no session, and flags responses that look the same.
4. Keep a **baseline** for each sensitive request: status, length, a distinctive marker string (for example `"role":"admin"` or the heading of the admin page), and the response time.
5. Use **Comparer** for anything Autorize marks "bypassed?" or "is enforced???". Look at the body, not only the status.

**A session-swap workflow** that you will reuse in most tests:

```text
1. Capture the request as the role that is allowed (admin)       -> baseline A
2. Replay unchanged with the low-privilege session                -> expect 403 / 404 / redirect
3. Replay unchanged with no session                               -> expect 401 / redirect to login
4. Replay with ONE variant (path, method, header) as low-priv/anon -> compare with A and with 2/3
5. If 4 matches A: repeat once to rule out caching, then stop and record
```

Only ever change one thing at a time. If two variants are combined and the request succeeds, you do not know which one the fix has to address.

**Stop on real data.** If a variant returns another real person's or organisation's data (not your test accounts), stop. Keep only the minimum redacted evidence (status line, a few redacted lines that prove the issue), do not download or keep more, and report it to the client or programme immediately.

**Rate and scope.** Keep forced browsing and variant lists small and slow: a bounded wordlist (hundreds, not hundreds of thousands, of entries), one to five requests per second unless the client agrees otherwise, and no recursive brute-forcing of identifiers. State-changing requests (create, update, delete, invite, role change) are only ever sent against **your own test objects**, and you prefer the least destructive proof: read before write, a harmless field change before a delete.

**Tell the client's SOC** your source IPs and test window. Header and path variants look like attacks in WAF logs, and that is what they should look like.

### GT-WEB-BYP-1: Strip the session from authenticated requests

*Guler Tech methodology.* Implements WSTG-ATHZ-02 (basic unauthenticated access) and the forced-browsing part of WSTG-ATHN-04.

#### What it checks

Whether pages and API endpoints that are reached after login still answer when the request carries no session: no cookie, no `Authorization` header, no API key. It also checks that a logged-out or expired session is rejected the same way.

#### Prerequisites

The admin and normal-user site map from [Before you start](#before-you-start). One valid session per role, plus one session token you have logged out (for the logout variant).

#### Steps

1. Export the list of authenticated requests from Burp's site map (filter on requests that carry `Cookie` or `Authorization`). Include static-looking authenticated assets such as `/exports/*.csv`, `/files/`, `/reports/`, and the JSON endpoints the SPA calls.
2. Replay each one with all credentials removed. In Repeater, delete the `Cookie` and `Authorization` headers. In Autorize, the unauthenticated column does this for you.

```http
GET /api/v2/account/invoices?page=1 HTTP/1.1
Host: api.example.com
Accept: application/json
```

```bash
# Same request with credentials (baseline) and without
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
  -H 'Authorization: Bearer <TOKEN_USER_A>' 'https://api.example.com/api/v2/account/invoices?page=1'
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
  'https://api.example.com/api/v2/account/invoices?page=1'
```

3. Repeat with a **logged-out** session token, and with a session that has expired, to catch endpoints that check "a cookie is present" rather than "the session is valid".
4. For every redirect to the login page, read the **body** of the `302`. Some applications render the protected page and only then add a `Location` header.
5. Repeat the anonymous run against the other hostnames that reach the same back-end (`app.` and `api.`, the mobile API host, a direct origin hostname if the client provided one).

#### Observation

Correct behaviour:

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
WWW-Authenticate: Bearer

{"error":"authentication_required"}
```

Vulnerable behaviour (data returned without a session):

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"items":[{"id":"inv_1042","customer":"Test User A","total":"120.00"}],"page":1}
```

Also vulnerable: a `302 Found` with `Location: /login` whose body still contains the rendered invoice table.

#### Evaluation

- **Fail:** an endpoint that requires authentication by design returns the protected data or performs the action without a valid session, including in the body of a redirect; or a logged-out or expired token is still accepted.
- **Pass:** every such endpoint returns `401`, `403` or a redirect with an empty body, consistently across hostnames.

#### False positives

- Public-by-design endpoints (product catalogue, public profiles, marketing pages). Check them against the access matrix before you report.
- A CDN or browser cache that serves an earlier authenticated response. Add a cache-busting query parameter (`?cb=1731690000`) and check `Age`, `X-Cache` or `CF-Cache-Status`. If the issue only reproduces from the cache, it is a different finding (web cache deception) to be handled in the HTTP and infrastructure part of the series.
- `200 OK` with an error body (`{"error":"unauthorised"}`) or a login page served with `200`. Compare content, not status.

#### Automation

Autorize's unauthenticated check during browsing; ZAP's Access Control Testing add-on with an "unauthenticated" user. In CI, generate one test per route from the router table that asserts `401` without credentials (see [Authorisation regression tests](#authorisation-regression-tests)).

### GT-WEB-BYP-2: Forced browsing to unlinked pages and API routes

*Guler Tech methodology.* Implements WSTG-ATHZ-02 (forced browsing), WSTG-CONF-05 (admin interfaces), WSTG-CONF-04 (unreferenced files) and the route-discovery part of WSTG-APIT-01.

#### What it checks

Whether functionality that is not linked for the current role (admin pages, internal APIs, old API versions, debug and monitoring endpoints, documentation) can be reached by requesting it directly, as anonymous or as a low-privilege user.

#### Prerequisites

Low-privilege and anonymous sessions; the client's agreement on the wordlist size and request rate; [ffuf](https://github.com/ffuf/ffuf) and a short wordlist (for example a trimmed list from [SecLists](https://github.com/danielmiessler/SecLists) plus words taken from the application itself).

#### Steps

1. **Harvest candidate routes from what the application already gives you**, before guessing anything:
   - `robots.txt`, `sitemap.xml`, `/.well-known/`;
   - JavaScript bundles and source maps: search for path literals (`"/api/`, `"/admin`, `path:`), role checks (`isAdmin`, `hasRole(`) and router definitions;
   - OpenAPI / Swagger documents (`/swagger.json`, `/openapi.json`, `/v3/api-docs`, `/api-docs`), GraphQL introspection (where allowed), and the API calls of the mobile app if it is in scope;
   - admin traffic you captured with the high-privilege account. Every admin request is a forced-browsing candidate for the low-privilege user.
2. Request each harvested route as the low-privilege user and as anonymous, using the session-swap workflow.
3. Then run a **bounded** discovery pass for routes you cannot see, at a low rate, with the low-privilege session:

```bash
# ~500 words, 2 requests/second, follow no redirects, keep everything for review
ffuf -u 'https://app.example.com/FUZZ' -w routes-small.txt \
     -H 'Cookie: session=<SESSION_USER_A>' \
     -rate 2 -t 2 -mc all -fc 404 -o ffuf-userA.json -of json
```

4. For APIs, also try version and prefix siblings of known routes: `/api/v1/users` next to `/api/v2/users`; `/api/internal/...`; `/api/admin/...`; the same path on `admin.example.com`.
5. Look for framework management endpoints that the fingerprint suggests (Spring Boot Actuator `/actuator`, Laravel Telescope or Horizon, Django admin `/admin/`, Rails `/rails/info`). Note that they exist and whether they need authentication; do not browse their contents beyond what proves the point.

#### Observation

```http
GET /api/v1/admin/users?limit=1 HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
```

Vulnerable: `200 OK` with a user list, while the v2 equivalent returns `403`. Correct: `403` or `404` on both versions.

#### Evaluation

- **Fail:** a route outside the low-privilege user's (or anonymous user's) permissions returns protected data or performs a protected action. Document whether the URL was guessable, leaked by the application (bundle, docs, `robots.txt`), or found only by brute force. This affects the rating, not the pass/fail.
- **Pass:** every discovered privileged route enforces the same check as its linked equivalent.
- **Info:** a privileged route is *disclosed* (in the bundle or docs) but enforces authorisation correctly. Report it as information disclosure only if the disclosure itself is sensitive.

#### False positives

- Generic SPA fallbacks that return `200` and the same `index.html` for every path. Filter by response size or by a marker string (`-fs`, `-fr` in ffuf).
- A page that renders an empty admin shell and loads its data from an API that correctly returns `403`. That is the [GT-WEB-BYP-11](#gt-web-byp-11-client-side-only-enforcement-in-spas) pattern, and on its own it is Info.
- Health endpoints that return only `{"status":"UP"}` by design.

#### Automation

ffuf with a bounded list in a scheduled job against staging. In CI, compare the router's route table against an allowlist of public routes. Any route that is neither public nor protected by a policy fails the build.

### GT-WEB-BYP-3: Path normalisation variants against edge rules

*Guler Tech methodology.* Implements WSTG-CONF-13 (Path Confusion) and the URL-matching part of WSTG-ATHZ-02.

#### What it checks

Whether an access rule that blocks a protected path also blocks equivalent spellings of that path: case, trailing slash, dot segments, duplicate slashes, percent-encoding and double encoding.

#### Prerequisites

A protected path that returns a clear denial for your low-privilege or anonymous session (for example `GET /admin/users` → `403`), and its baseline as admin. Knowing whether a proxy or CDN sits in front helps (`Server`, `Via`, `X-Cache` headers; WSTG-INFO-02 and INFO-08).

#### Steps

1. Confirm the denial and note **who** denies it. An nginx-style HTML `403` page or a CDN error page points to an edge rule. A JSON `{"error":"forbidden"}` in the app's format points to the application. Edge-only denials are the ones that normalisation variants tend to bypass.
2. Send each variant once, with the low-privilege session, and compare it with both the denial and the admin baseline:

```text
/admin/users            baseline (denied)
/ADMIN/users            case
/Admin/Users            case
/admin/users/           trailing slash
/admin/users/.          trailing dot segment
/admin/./users          inner dot segment
//admin/users           leading duplicate slash
/admin//users           inner duplicate slash
/%61dmin/users          encoded first letter
/admin%2Fusers          encoded separator
/%2561dmin/users        double-encoded letter
/admin/users?           empty query
/admin/users#           fragment (curl strips it; send raw from Repeater)
```

3. Use `curl --path-as-is`, or Burp Repeater, so that the client does not normalise the path for you:

```bash
for p in '/admin/users' '/ADMIN/users' '/admin/users/' '/admin/./users' '//admin/users' '/%61dmin/users' '/%2561dmin/users'; do
  printf '%-22s ' "$p"
  curl -s --path-as-is -o /dev/null -w '%{http_code} %{size_download}\n' \
       -H 'Cookie: session=<SESSION_USER_A>' "https://app.example.com$p"
  sleep 1
done
```

4. For every variant that does not return the denial, decide whether it reached the **protected handler** (body matches the admin baseline) or just a different route (`404`, the SPA shell, a redirect to the canonical path).

#### Observation

```text
/admin/users           403 162
/ADMIN/users           200 8410     <- matches admin baseline (8,412 bytes, same heading)
/admin/users/          403 162
/admin/./users         403 162
//admin/users          301 0        (redirect to /admin/users, then 403)
/%61dmin/users         403 162
/%2561dmin/users       400 0
```

Here the edge rule is case-sensitive and the application router is not.

#### Evaluation

- **Fail:** any variant returns the protected content or performs the protected action for a subject that the canonical path denies.
- **Pass:** every variant is denied, rejected (`400`), not found (`404`), or redirected to the canonical path where it is then denied.

#### False positives

- A `200` that is the SPA's `index.html` or a generic "not found" page served with `200`.
- A redirect to the canonical path (`301` to `/admin/users`) is the correct behaviour, as long as the redirect body is empty.
- CDN-cached copies of a public page with a similar name.

#### Automation

Turn the variant list into a parameterised test that runs against staging through the real proxy, not only against the application. Unit tests that call the router directly will not see the edge-versus-origin difference. Burp Intruder with the variant list as payloads, at a low rate, works for one-off checks.

### GT-WEB-BYP-4: Path parameters and suffix matching on Java stacks

*Guler Tech methodology.* Implements WSTG-CONF-13 for servlet containers and Spring, and the URL-matching discrepancies described in WSTG-ATHZ-02.

#### What it checks

Whether `;` path parameters, a `..;` segment, or a format suffix make a protected route reachable when the edge proxy or the security filter matches the raw path and the servlet container or framework matches a cleaned one.

#### Prerequisites

A fingerprint that suggests a Java back-end (`JSESSIONID` cookie, Tomcat or Jetty error pages, Spring Whitelabel error page, Spring Boot Actuator), ideally behind a proxy. A protected path and a public path under a different prefix (for example `/public/` or `/static/`).

#### Steps

Send each request once with the low-privilege or anonymous session and compare it with the denial and the admin baseline:

```text
/admin/users;x=1            parameter on the last segment
/admin;x=1/users            parameter on an inner segment
/admin/users;               empty parameter
/public/..;/admin/users     dot-dot carrying a parameter (proxy prefix /public/, container resolves ..)
/admin/users.json           format suffix
/admin/users.css            static-looking suffix (also relevant to cache rules)
```

```bash
curl -s --path-as-is -o /dev/null -w '%{http_code} %{size_download}\n' \
     'https://app.example.com/public/..;/admin/users'
```

If the application is in scope as grey-box, read the configuration instead of guessing:

- Spring Security version and how matchers are built: `requestMatchers(String)`, `AntPathRequestMatcher`, `MvcRequestMatcher`, `RegexRequestMatcher`, `PathPatternRequestMatcher`;
- whether a custom `HttpFirewall` relaxes `StrictHttpFirewall` (`setAllowSemicolon(true)`, `setAllowUrlEncodedSlash(true)`, `setUnsafeAllowAnyHttpMethod(true)`);
- Spring MVC path-match settings (`setUseTrailingSlashMatch(true)`, suffix pattern options on Spring 5.x);
- the proxy's `location` and `proxy_pass` rules for the same prefix.

#### Observation

Correct for a Spring Security application with the default firewall: `400 Bad Request` (rejected by `StrictHttpFirewall`, which by default rejects un-normalised requests and semicolons). Vulnerable: `200` with the admin page for `/public/..;/admin/users`, because nginx allowed everything under `/public/` and Tomcat normalised the path.

#### Evaluation

- **Fail:** any variant reaches the protected handler for a subject that the canonical path denies.
- **Pass:** the variants are rejected, routed to `404`, or denied by the same rule.
- Record which layer failed (proxy prefix rule, security filter, framework matcher). The fix differs per layer.

#### False positives

- `jsessionid` URL rewriting (`/app;jsessionid=...`) on public pages is normal and not a bypass.
- A `400` from `StrictHttpFirewall` is a pass, not an error to report.

#### Automation

Add these variants to the parameterised path test from GT-WEB-BYP-3. In Spring projects, write `MockMvc` tests for `;` and suffix variants that assert `400` or `403`, and run an integration test through the real proxy. `MockMvc` does not reproduce container normalisation.

### GT-WEB-BYP-5: HTTP method tampering

*Guler Tech methodology.* Implements the access control bypass part of WSTG-CONF-06 (HTTP Methods).

#### What it checks

Whether a protected function can be reached with a method other than the one the access rule names: `HEAD` instead of `GET`, `GET` instead of `POST`, an arbitrary verb, or a mixed-case verb. It also checks whether the method set the application accepts is limited to what it uses.

#### Prerequisites

A protected request with a known denial for the low-privilege or anonymous session (for example `POST /admin/users/delete` → `403`, or `GET /admin/` → `302` to login). For state-changing functions, a target object that is **yours** (a test user you created).

#### Steps

1. Ask the server what it allows, but do not trust the answer:

```http
OPTIONS /admin/users HTTP/1.1
Host: app.example.com
```

2. Replay the denied **read** request with other methods, as the low-privilege user:

```bash
for m in GET HEAD POST PUT PATCH FOO get; do
  printf '%-6s ' "$m"
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -X "$m" \
       -H 'Cookie: session=<SESSION_USER_A>' 'https://app.example.com/admin/users'
  sleep 1
done
```

For `HEAD`, use `curl -I`. `-X HEAD` makes curl wait for a body that never arrives. With `HEAD`, look at status and headers: a `200` with `Content-Length` matching the admin page, or a `Set-Cookie` that only admins get, is enough.

3. For a denied **state-changing** request, try it as `GET` with the parameters in the query string. Do this only against **own test objects**:

```http
GET /admin/users/delete?username=gt-test-user-b HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
```

Prefer a harmless function for this proof (for example "resend invite" or "rename" on your own test user) over a delete.

4. If an edge component (CDN, WAF, gateway) sits in front, note where each method is rejected. A `405` from the CDN and a `200` from the origin means the edge is the only thing blocking the method.

#### Observation

```text
GET    403 162
HEAD   200 0        Content-Length: 8412, matches admin page
POST   403 162
FOO    200 8412     <- unknown verb served as GET by the handler
```

#### Evaluation

- **Fail:** any alternative method returns protected content, sets privileged state, or performs the protected action for a subject that the original method denies.
- **Fail (lower severity):** the application accepts methods it does not use (arbitrary verbs answered like `GET`, `TRACE` enabled), even without a bypass. This is ASVS `v5.0.0-4.1.4` (L3) and, for `TRACE`, `v5.0.0-13.4.4` (L2).
- **Pass:** alternative methods return `405 Method Not Allowed` (or the same denial), and `HEAD` returns the same status as the denied `GET`.

#### False positives

- `PUT`, `PATCH` and `DELETE` on a REST API are not findings in themselves. WSTG-CONF-06 is explicit that their presence is not a security issue. Only a missing authorisation check is.
- `HEAD` returning `200` on a public page.
- An `OPTIONS` response that lists methods for CORS preflight purposes.

#### Automation

A method matrix test in CI: for each route, call every method the route does *not* declare and assert `405` or `403`. Burp Intruder with a method list as the payload (on a request you are allowed to replay) works for spot checks.

### GT-WEB-BYP-6: Method override headers and parameters

*Guler Tech methodology.* Implements the HTTP method overriding part of WSTG-CONF-06.

#### What it checks

Whether the application lets a header or parameter change the effective method, so that a `POST` (or `GET`) accepted by the edge or by a method-specific rule is executed as `PUT`, `PATCH` or `DELETE`.

#### Prerequisites

A method that is blocked for your session or at the edge (for example `DELETE /api/projects/{id}` → `403` or `405`), and a project **you own** to use as the target.

#### Steps

1. Baseline the blocked method:

```http
DELETE /api/projects/prj_test_b HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
```

2. Replay as `POST` with each override signal, one at a time. Use a benign target first: a `PATCH` override that renames your own project is a safer proof than a `DELETE`:

```http
POST /api/projects/prj_test_b HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
X-HTTP-Method-Override: PATCH
Content-Type: application/json

{"name":"gt-override-check"}
```

```text
X-HTTP-Method-Override: PATCH
X-HTTP-Method: PATCH
X-Method-Override: PATCH
POST /api/projects/prj_test_b?_method=PATCH
POST body: _method=PATCH   (application/x-www-form-urlencoded)
```

3. Read the project back as its owner. Did the name change?
4. Repeat with `GET` as the carrier (`GET ...?_method=DELETE`) only if the `POST` carrier worked. Most frameworks only honour overrides on `POST`, and a `GET` carrier also matters for CSRF.

#### Observation

Vulnerable: the `PATCH` override returns `200` and the project is renamed, although `PATCH` and `DELETE` are blocked for this role at the gateway. Correct: `403`/`405`, or the override is ignored and the request is processed as a plain `POST` (`405` if the route has no `POST` handler).

#### Evaluation

- **Fail:** an override header or parameter makes the application perform an operation that the same session cannot perform with the real method, or that the edge blocks.
- **Pass:** overrides are ignored, or honoured only where the authorisation check applies to the *effective* method and gives the same result as the real method.
- **Note:** support for overrides without a bypass is worth a Low or Info observation if no client needs it. It defeats method-based edge rules and can turn CSRF-safe methods into unsafe ones.

#### False positives

- Laravel and Symfony applications honour `_method` on `POST` by design for HTML forms. That is only a finding when it bypasses a check.
- Overrides that the application honours *after* authorisation for the effective method: same result, no bypass.

#### Automation

Param Miner's header guessing can find unusual override headers. In CI, add tests that send each override header with `POST` to routes that do not accept the overridden method and assert `405`/`403`.

### GT-WEB-BYP-7: URL override headers

*Guler Tech methodology.* Implements the special request header handling part of WSTG-ATHZ-02.

#### What it checks

Whether the back-end takes the effective URL from `X-Original-URL` or `X-Rewrite-URL` (or a similar header), so that an edge rule applied to the request line can be bypassed.

#### Prerequisites

A path that the **edge** denies (WAF or proxy `403` page) and that the application would otherwise serve; an allowed path such as `/`.

#### Steps

1. Detect support first, with a harmless non-existent target, following WSTG:

```http
GET / HTTP/1.1
Host: app.example.com
X-Original-URL: /gt-does-not-exist-1
```

```http
GET / HTTP/1.1
Host: app.example.com
X-Rewrite-URL: /gt-does-not-exist-2
```

If either returns the application's `404` (instead of the home page), the back-end honours that header.

2. Only if support is confirmed, send the allowed path in the request line and the protected path in the header:

```http
GET / HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
X-Original-URL: /admin/users
```

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
     -H 'X-Original-URL: /admin/users' -H 'Cookie: session=<SESSION_USER_A>' 'https://app.example.com/'
```

3. If the protected route needs query parameters, put them in the **request line** (`GET /?id=1`) as well as the header. Some implementations take the query from the request line.

#### Observation

```text
GET /admin/users                               403 (edge HTML page)
GET /  + X-Original-URL: /gt-does-not-exist-1  404 (application JSON)   <- header honoured
GET /  + X-Original-URL: /admin/users          200 8412                  <- bypass
```

#### Evaluation

- **Fail:** the protected content is served or the action performed through the override header for a subject that the direct request denies.
- **Fail (lower severity):** the header is honoured (step 1) even though no bypass was found. The protection now depends on the application's own checks, and any edge-only rule is void.
- **Pass:** the header is ignored (home page returned in step 1) or stripped by the edge.

#### False positives

- An application `404` for `/gt-does-not-exist-1` that you get without the header too (for example because `/` itself returns `404`). Always compare with and without the header.
- Caches: a poisoned cached response is a cache finding. Use a cache-busting parameter.

#### Automation

Param Miner (header guessing) on a few representative requests. At the edge, add a rule that strips these headers and a synthetic check that sends `X-Original-URL: /gt-canary` and expects the normal home page.

### GT-WEB-BYP-8: Client IP trust through forwarding headers

*Guler Tech methodology.* Implements the "other headers to consider" part of WSTG-ATHZ-02.

#### What it checks

Whether functionality restricted to internal or allow-listed IP addresses (admin panels, status and metrics endpoints, debug routes, rate-limit or MFA exemptions) can be reached by supplying a client IP header.

#### Prerequisites

An endpoint that denies your real source IP, and some idea of what the client considers "internal". Ask; it saves requests.

#### Steps

1. Baseline the denial from your real IP.
2. Send the request once per header with a loopback value, then with a private address that the client says is internal:

```text
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
True-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
X-Forwarded-For: 10.0.0.5
X-Forwarded-For: 127.0.0.1, 203.0.113.10
```

```bash
for h in 'X-Forwarded-For' 'X-Real-IP' 'X-Client-IP' 'True-Client-IP'; do
  printf '%-18s ' "$h"
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -H "$h: 127.0.0.1" \
       'https://app.example.com/internal/status'
  sleep 1
done
curl -s -o /dev/null -w '%{http_code}\n' -H 'Forwarded: for=127.0.0.1' 'https://app.example.com/internal/status'
```

3. If one header works, try the same header on one or two other restricted functions to establish scope. Do not go further than proving the trust.
4. Note what the client IP is used for elsewhere (audit logs, rate limiting, geo-blocking, risk scoring). The same spoofing affects all of them, and ASVS `v5.0.0-15.3.4` covers both logging and security decisions.

#### Observation

```text
(no header)                        403 {"error":"forbidden"}
X-Forwarded-For: 127.0.0.1         200 {"host":"app-7f9c","uptime":178784,...}
```

#### Evaluation

- **Fail:** any client-supplied header changes the authorisation outcome. Severity follows what the trusted path exposes (Yelp's status and API documentation in the cases below versus a full admin API in the Fortinet case).
- **Pass:** the restricted endpoint ignores all client IP headers, and the edge overwrites or strips them before they reach the application.

#### False positives

- A different response caused by geo or language routing rather than authorisation.
- Endpoints that are public by design and merely log the header.

#### Automation

At the edge, a synthetic check that sends `X-Forwarded-For: 127.0.0.1` to a canary internal endpoint and expects a denial. In the application, a unit test that the IP resolver returns the socket peer (or the right-most untrusted hop) when the request comes from an untrusted address.

### GT-WEB-BYP-9: Referer checks and multi-step flows

*Guler Tech methodology.* Implements WSTG-ATHZ-02 (access to administrative functions) for Referer-based and step-order controls.

#### What it checks

Whether a privileged sub-action is authorised on its own, or only because the request "came from" a protected page (Referer) or followed earlier protected steps.

#### Prerequisites

Admin captures of the full flow (for example `/admin` → `/admin/roles?user=...` → `POST /admin/roles/confirm`). A low-privilege session. A target user that is **your own test account**.

#### Steps

1. As the low-privilege user, request the final step directly with no `Referer` header, then with `Referer: https://app.example.com/admin`:

```http
POST /admin/roles/confirm HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
Referer: https://app.example.com/admin
Content-Type: application/x-www-form-urlencoded

username=gt-test-user-b&role=support&confirmed=true
```

2. If the flow has a review step that issues a token or sets session state, check whether the final step accepts the request without it, or with a token taken from your own admin session for a different action.
3. Use a harmless role or field change on your own test user. Revert it afterwards with the admin account.

#### Observation

Vulnerable: `302` back to `/admin` with "Role updated" and the test user now has the new role, only when the `Referer` is present. Or: the confirm step succeeds without the earlier steps. Correct: `403` regardless of `Referer` and step order.

#### Evaluation

- **Fail:** the outcome of any step depends on `Referer`, or a later step succeeds for a subject that earlier steps would deny.
- **Pass:** every step authorises the subject for the operation, independently.

#### False positives

- `Referer` or `Origin` checks used as CSRF defence *in addition to* authorisation are fine. The question is only whether they replace it.

#### Automation

In CI, call the final step of each multi-step flow directly as a low-privilege user and assert `403`. Autorize covers this automatically if you walk the admin flow with it enabled.

### GT-WEB-BYP-10: Client-controlled role and privilege flags

*Guler Tech methodology.* Implements the parameter modification part of WSTG-ATHN-04 and the vertical part of WSTG-ATHZ-02. Browser storage review follows WSTG-CLNT-12.

#### What it checks

Whether the server makes authorisation decisions on values the client stores and sends back: cookies (`admin=true`, `role=user`), hidden form fields, query parameters (`?admin=1`), custom headers (`X-Role`, `X-User-Id`), values in `localStorage` that the SPA sends to the API, or unverified token claims.

#### Prerequisites

A low-privilege session; the admin capture to compare against; the browser's DevTools for storage.

#### Steps

1. List every client-side value that looks like a role, flag, user ID or tenant ID: cookies other than the session cookie, hidden inputs, query parameters on post-login redirects, request headers that the SPA adds, keys in `localStorage`/`sessionStorage`. Decode base64 or URL-encoded values: a preferences cookie that turns out to be base64-encoded JSON with a `role` key is a common find.
2. Change **one** value at a time to the privileged equivalent and replay a request that the low-privilege user is denied:

```http
GET /admin/ HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>; Admin=true
```

```http
GET /api/reports/all HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
X-User-Role: admin
```

3. If the application uses signed tokens (JWT or similar), do not try to forge them here. Token signature and claim validation is covered in the Session part of the series. Only check whether the API reads a role from an **unsigned** place in addition to the token.

#### Observation

Vulnerable: `200` with the admin page after `Admin=true`. Correct: `403`, and the flag is ignored (or the cookie is server-signed and rejected when modified).

#### Evaluation

- **Fail:** changing a client-stored value changes the authorisation outcome.
- **Pass:** roles and permissions are derived on the server from the authenticated principal. Client-side copies exist only for display.

#### False positives

- UI preference cookies (`theme=dark`, `admin_ui_collapsed=1`) that change rendering but not access.
- A signed session cookie (for example a framework's signed cookie session) that contains the role. The value is client-held but tamper-evident. Confirm that modification invalidates it.

#### Automation

Param Miner can guess hidden parameters and headers on admin requests. In CI, add negative tests that send common role headers and parameters (`X-Role`, `role=admin`, `isAdmin=true`) as a normal user and assert no change in outcome.

### GT-WEB-BYP-11: Client-side-only enforcement in SPAs

*Guler Tech methodology.* Implements WSTG-ATHZ-02 for single-page applications, together with WSTG-APIT-04 (API function-level authorisation).

#### What it checks

Whether the API enforces the restrictions that the SPA's route guards and hidden buttons suggest, or whether the only control is in the browser.

#### Prerequisites

The SPA's JavaScript bundles (and source maps if they are served); a low-privilege session and its API token.

#### Steps

1. Find the client-side guards and the API calls behind them. Search the bundle for route definitions, `canActivate`, `beforeEach`, `RequireAdmin`, `isAdmin`, `hasRole`, and the API client functions those components call.
2. Confirm in the browser that the admin view is hidden for the low-privilege user. That alone is not a finding.
3. Call the API functions that the hidden view uses, directly, with the low-privilege token. Use read operations first:

```bash
curl -s -H 'Authorization: Bearer <TOKEN_USER_A>' 'https://api.example.com/api/admin/audit-log?limit=1' | jq '.items | length'
```

4. Optionally, flip the client-side flag in DevTools (for example set `isAdmin` to `true` in the store) so that the SPA renders the admin view and issues its calls for you. Then watch the API responses in Burp. The API's answers are the result. The rendered view is not.

#### Observation

Vulnerable: the API returns audit-log entries to the low-privilege token. Correct: the admin view renders after the flag flip, but every API call it makes returns `403`.

#### Evaluation

- **Fail:** any API call behind a client-side guard succeeds for a subject the guard is meant to exclude (rate it by what the API exposes).
- **Info:** the admin view or its route list is visible or renderable, but every server call is denied. This is the "hidden-UI-only defect without a reachable server-side gap" case.
- **Pass:** the API denies the calls. Disclosure of route names alone is Info at most.

#### False positives

- Admin views that use only public data (for example a static help page shown to admins).

#### Automation

Generate API tests from the OpenAPI document or the SPA's API client and run them as each role. Autorize does this as you click through the app with the flag flipped.

### GT-WEB-BYP-12: Known framework authorisation bypass CVEs

*Guler Tech methodology.* Implements WSTG-ATHZ-02 with the fingerprinting of WSTG-INFO-08 (web application framework) and the component checks behind ASVS `v5.0.0-15.2.1`.

#### What it checks

Whether the application runs a framework version that is affected by a published authorisation-bypass advisory, *and* whether the application uses the feature the advisory depends on. The test is a version check plus a harmless confirmation. It is not an exploitation exercise.

#### Prerequisites

A fingerprint of the stack. In grey-box tests, ask for the dependency manifest (`package-lock.json`, `pom.xml`/`build.gradle`, `composer.lock`). It is faster and more reliable than black-box guessing.

#### Steps

1. **Identify the framework and version.**
   - Next.js: `X-Powered-By: Next.js`, `/_next/` asset paths; the version is exposed in the browser as `window.next.version` (open DevTools on any page and evaluate it).
   - Spring: Whitelabel error page, `JSESSIONID`, Actuator endpoints (do not browse their contents). The exact Spring Security version normally needs the manifest.
   - Symfony and Drupal: `composer.lock` or a changelog file, if exposed; otherwise the manifest.
2. **Compare with the advisory** (table in [Framework bugs of the same class](#framework-bugs-of-the-same-class)). Read the vendor advisory itself, including its conditions. For example, CVE-2024-38821 only affects WebFlux apps that use Spring's static resources support with a non-`permitAll` rule on them. CVE-2022-31692 needs forward or include dispatch to a more privileged endpoint.
3. **Confirm the precondition**, not the exploit. For CVE-2025-29927, the question is "does this app make authorisation decisions only in middleware?". Grey-box: read `middleware.ts`/`proxy.ts` and the route handlers. Black-box: note which routes redirect to login before any API call is made. A harmless confirmation that the vendor workaround is in place is to send a request carrying an `x-middleware-subrequest` header to a **public** page you are allowed to reach. Then check that the edge drops or rejects the header, or that the response is unchanged. Do not aim it at protected routes in production unless the client has explicitly approved it. In that case use a protected page of your own test account in a staging environment.
4. Record the version evidence, the advisory URL and the precondition evidence, and recommend the fixed version.

#### Observation

```text
window.next.version            "14.2.10"         -> inside 14.0.0–14.2.24 (CVE-2025-29927)
middleware.ts                  redirects unauthenticated users away from /dashboard
app/dashboard/page.tsx         renders data without a server-side session check
```

#### Evaluation

- **Fail:** an affected version *and* the vulnerable configuration (for Next.js: authorisation relies on middleware alone). Rate as the advisory's impact, adjusted by what the protected routes expose.
- **Fail (vulnerable component):** an affected version where you could not establish the precondition. Report it as an outdated component with the advisory, and say what you could not confirm.
- **Pass:** a fixed version, or an affected version with the vendor workaround verified (for Next.js, external `x-middleware-subrequest` headers are stripped), and authorisation repeated at the handler or data layer.

#### False positives

- Version strings in cached or third-party assets that do not reflect the server (a static export of Next.js has no middleware at all).
- Deployments the vendor protects automatically. GitHub's advisory notes that Next.js deployments hosted on Vercel were protected against CVE-2025-29927.

#### Automation

Software composition analysis in CI (`npm audit`, OWASP Dependency-Check, GitHub Dependabot, or your SCA tool), with a policy that blocks advisories tagged as authorisation bypass. Nuclei has public templates for some of these CVEs. Run them only against systems in scope, and read each template before you run it.

## Secure implementation

### Design rules

1. **Decide at the handler or service layer.** Keep edge rules (WAF, proxy, gateway) as defence in depth if you want them, but the authoritative check runs where the framework has already parsed the path and method that the handler will use, and ideally again next to the data (policy object, scoped query). Spring Security's own documentation recommends method security at the service layer over relying only on URL rules, because URLs change and are easy to manipulate.
2. **Deny by default.** Unmatched routes require authentication (or are denied); public routes are an explicit allowlist. A new route should fail closed until someone adds a rule for it.
3. **Normalise once, consistently.** Pick one component to decode, resolve dot segments and merge slashes, and reject what you do not use (`;` parameters, encoded slashes, backslashes, double encoding). Do not write your own path canonicaliser in the application. Rely on the framework's router and firewall and keep their defaults strict.
4. **Bind rules to resources and operations, not to strings and verbs.** If a rule names a method, make sure the same path has a rule for every other method the handler accepts. Better: put the permission on the handler.
5. **Disable what you do not use**: method override headers and `_method` parameters, `TRACE`, WebDAV, URL override headers, management and debug endpoints.
6. **Never trust client-supplied identity or location.** Client IP, `X-User-ID`-style identity headers, `Referer`, role cookies and SPA state are input, not authorisation. Accept forwarding headers only from proxies you run, and make the edge overwrite or strip them.
7. **Patch the framework.** Track the authorisation-bypass advisories for your framework and gateway. Several entries in the table above are configuration-independent once the version is affected.

### Edge proxy configuration

The edge should overwrite client IP headers with what it saw on the socket, and drop headers that the application must never get from a client. An nginx example (an empty value means nginx does not pass the header upstream, per the [proxy module docs](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header)):

```text
location / {
    proxy_set_header Host                    $host;
    # At the outermost proxy, overwrite rather than append ($proxy_add_x_forwarded_for appends).
    proxy_set_header X-Forwarded-For         $remote_addr;
    proxy_set_header X-Real-IP               $remote_addr;
    proxy_set_header X-Forwarded-Proto       $scheme;
    proxy_set_header Forwarded               "";
    # Headers the application must never receive from a client
    proxy_set_header X-Original-URL          "";
    proxy_set_header X-Rewrite-URL           "";
    proxy_set_header X-HTTP-Method-Override  "";
    proxy_set_header X-HTTP-Method           "";
    proxy_set_header X-Method-Override       "";
    proxy_set_header x-middleware-subrequest "";
    proxy_pass http://app_upstream;
}
```

Remember that `proxy_set_header` directives in a `location` replace all inherited ones, so repeat the full set wherever you override it. Inner proxies (between the edge and the app) should *append* and the application should trust only the hops it knows (`set_real_ip_from` plus `real_ip_recursive on` in nginx's realip module, or the framework settings below). Also make sure the origin is not reachable directly, bypassing the edge: security groups, private networking, or mutual TLS between proxy and origin.

### Node.js and Express

Mount authentication once, before every non-public router, and repeat the permission check in the service that does the work. Express's router applies `app.use()` middleware with the same case and trailing-slash rules it uses to dispatch to handlers, so a check inside Express sees `/ADMIN/users` the same way the handler does. A check in an upstream proxy does not.

```javascript
// app.js (Express 5)
const express = require('express');
const { loadUser, requireAuth, requirePermission } = require('./authz');

const app = express();
app.disable('x-powered-by');

// Trust only your own proxies; req.ip is then the nearest untrusted address.
// Never `true` unless the last trusted proxy overwrites X-Forwarded-For.
app.set('trust proxy', ['10.0.1.10', '10.0.1.11']);

app.use(express.json());
app.use(loadUser); // resolves req.user from the server-side session, or leaves it undefined

// Explicit public allowlist
app.use('/public', require('./routes/public'));
app.post('/login', require('./routes/login'));

// Deny by default: everything below needs a valid session
app.use(requireAuth);
app.use('/api/admin', requirePermission('admin:access'), require('./routes/admin'));
app.use('/api', require('./routes/api'));

app.use((req, res) => res.status(404).json({ error: 'not_found' }));
module.exports = app;
```

```javascript
// authz.js
function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'authentication_required' });
  return next();
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user || !req.user.permissions.includes(permission)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    return next();
  };
}

// Internal-only endpoints: combine authentication with a network check on req.ip,
// which honours the `trust proxy` setting. Never read the X-Forwarded-For header yourself.
function requireInternalNetwork(allowed) {
  return (req, res, next) => (allowed.has(req.ip) ? next() : res.status(403).json({ error: 'forbidden' }));
}

module.exports = { requireAuth, requirePermission, requireInternalNetwork, loadUser: require('./load-user') };
```

```javascript
// routes/admin.js: declare the methods each path supports and reject the rest
const router = require('express').Router();
const users = require('../services/users');

router.route('/users/:id')
  .get(async (req, res) => res.json(await users.getUser(req.user, req.params.id)))
  .delete(async (req, res) => { await users.deleteUser(req.user, req.params.id); res.status(204).end(); })
  .all((req, res) => res.set('Allow', 'GET, HEAD, DELETE').status(405).end());

module.exports = router;

// services/users.js: the service checks again, whoever calls it
async function deleteUser(actor, id) {
  if (!actor.permissions.includes('user:delete')) throw Object.assign(new Error('forbidden'), { status: 403 });
  // ... delete
}
```

Do not install the `method-override` middleware unless HTML forms need it. If they do, keep its default of only honouring overrides on `POST` requests ([method-override README](https://github.com/expressjs/method-override)), mount it on the form routes only, and make sure the authorisation check runs on the overridden method. Note that Express answers `HEAD` with the `GET` handler when no `HEAD` route exists, so a `GET` handler's checks must not depend on the method.

### Django and Django REST framework

Django 5.1 added `LoginRequiredMiddleware`, which makes authentication the default for every view and lets you opt out with `@login_not_required` ([Django docs](https://docs.djangoproject.com/en/stable/ref/middleware/#django.contrib.auth.middleware.LoginRequiredMiddleware)). DRF's default permission is `AllowAny` unless you set `DEFAULT_PERMISSION_CLASSES` ([DRF permissions](https://www.django-rest-framework.org/api-guide/permissions/)), so set both.

```python
# settings.py
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.auth.middleware.LoginRequiredMiddleware",  # Django 5.1+
    "django.contrib.messages.middleware.MessageMiddleware",
]

REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
}

# Leave these at their defaults unless your proxy guarantees it strips and sets them
SECURE_PROXY_SSL_HEADER = None
USE_X_FORWARDED_HOST = False
```

`LoginRequiredMiddleware` checks `request.user` before the view runs. DRF token or JWT authentication happens inside the DRF view, so check how the middleware treats your API views in your version. If it redirects token-authenticated API calls, mark the DRF views `login_not_required` and rely on `DEFAULT_PERMISSION_CLASSES` and per-view permissions for them. Do not simply drop the middleware.

```python
# views.py
from django.contrib.auth.decorators import login_not_required, permission_required
from django.views.decorators.http import require_http_methods, require_POST


@login_not_required
@require_http_methods(["GET", "HEAD"])
def pricing(request):
    ...


@require_POST
@permission_required("accounts.change_role", raise_exception=True)
def change_role(request, user_id):
    ...  # also verify the actor may manage this particular user (object-level check)
```

```python
# api.py (DRF)
from rest_framework import permissions, viewsets


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):  # list/retrieve only; other methods get 405
    permission_classes = [permissions.IsAdminUser]
    serializer_class = AuditLogSerializer
    queryset = AuditLog.objects.all()
```

For the client IP, Django gives you `request.META["REMOTE_ADDR"]` and does not rewrite it from `X-Forwarded-For` on its own. If you need the original client behind your proxy, take the hop your own proxy added, never the left-most value:

```python
TRUSTED_PROXIES = {"10.0.1.10", "10.0.1.11"}


def client_ip(request):
    remote = request.META.get("REMOTE_ADDR", "")
    if remote not in TRUSTED_PROXIES:
        return remote  # direct connection: the socket peer is the client
    hops = [h.strip() for h in request.META.get("HTTP_X_FORWARDED_FOR", "").split(",") if h.strip()]
    return hops[-1] if hops else remote  # right-most entry was appended by our proxy
```

Django's documentation on `SECURE_PROXY_SSL_HEADER` lists the conditions that must all be true before you set it: the app is behind a proxy, the proxy strips the header from every incoming request, and the proxy sets it only for HTTPS requests ([Django settings](https://docs.djangoproject.com/en/stable/ref/settings/#secure-proxy-ssl-header)). The same reasoning applies to any forwarded header you use.

### Spring Security

Write rules so that the last one fails closed, give every method on a path a rule, and put the real permission on the service method. In Spring Security 7, `AntPathRequestMatcher` and `MvcRequestMatcher` are no longer supported and `PathPatternRequestMatcher` (Spring's `PathPattern`, the same matcher Spring MVC uses) is the default for `requestMatchers(String)` ([migration guide](https://docs.spring.io/spring-security/reference/6.5/migration-7/web.html)). That removes most of the Spring Security versus Spring MVC disagreement behind CVE-2016-5007, CVE-2023-20860 and CVE-2023-34034.

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class SecurityConfig {

    @Bean
    SecurityFilterChain web(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/", "/login", "/assets/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                // A method-specific rule needs a companion rule for the other methods on the same path,
                // otherwise POST/PUT/DELETE fall through to the catch-all below.
                .requestMatchers(HttpMethod.GET, "/api/reports/**").hasAuthority("reports:read")
                .requestMatchers("/api/reports/**").hasAuthority("reports:write")
                .anyRequest().authenticated() // or .denyAll() to make the rule set a strict allowlist
            )
            .formLogin(Customizer.withDefaults());
        return http.build();
    }
}
```

```java
@Service
class UserAdminService {

    @PreAuthorize("hasAuthority('user:delete')")
    public void deleteUser(UUID userId) {
        // ...
    }
}
```

Keep the default `StrictHttpFirewall`. It rejects un-normalised paths and, by default, semicolons, encoded slashes and HTTP methods outside its allowlist ([Spring Security: HttpFirewall](https://docs.spring.io/spring-security/reference/servlet/exploits/firewall.html)). Every `setAllowSemicolon(true)`, `setAllowUrlEncodedSlash(true)` or `setUnsafeAllowAnyHttpMethod(true)` in a code base deserves a review comment. Leave `spring.mvc.hiddenmethod.filter.enabled` at its default of `false` unless HTML forms need `_method`. Avoid `setUseTrailingSlashMatch(true)` in Spring MVC 6. If you need both forms of a URL, declare them explicitly or redirect at the proxy, as the Spring Framework 6.0 release notes suggest.

**Forwarded headers.** Spring's documentation says forwarded headers must be set by trusted proxies and never allowed in from the outside, that the edge proxy must remove both `Forwarded` and `X-Forwarded-*`, and that `ForwardedHeaderFilter` can run in `removeOnly` mode to discard them ([Spring Framework: Forwarded Headers](https://docs.spring.io/spring-framework/reference/web/webmvc/filters.html#filters-forwarded-headers)). With Spring Boot on Tomcat, `server.forward-headers-strategy=native` uses Tomcat's `RemoteIpValve`. Set `server.tomcat.remoteip.internal-proxies` to a regex that matches only your proxies, because at the time of writing the default trusts common private and loopback address ranges ([Spring Boot: behind a proxy](https://docs.spring.io/spring-boot/how-to/webserver.html)). Use `framework` (which installs `ForwardedHeaderFilter`) only when the edge strips client-supplied values.

### Laravel

Group routes under `auth`, attach a Gate or Policy to each admin route, and authorise again in the controller or a Form Request. Laravel registers its default middleware in `bootstrap/app.php` (Laravel 11 and later).

```php
// routes/web.php
use App\Http\Controllers\AdminUserController;
use App\Http\Controllers\DashboardController;
use Illuminate\Support\Facades\Route;

Route::middleware('auth')->group(function () {
    Route::get('/dashboard', DashboardController::class);

    Route::middleware('can:access-admin')->prefix('admin')->group(function () {
        Route::get('/users', [AdminUserController::class, 'index']);
        Route::delete('/users/{user}', [AdminUserController::class, 'destroy'])->can('delete', 'user');
    });
});
```

```php
// app/Providers/AppServiceProvider.php (boot)
use App\Models\User;
use Illuminate\Support\Facades\Gate;

Gate::define('access-admin', fn (User $user) => $user->is_admin);

// app/Http/Controllers/AdminUserController.php
public function destroy(User $user)
{
    Gate::authorize('delete', $user); // UserPolicy::delete, checked again in the controller
    $user->delete();

    return response()->noContent();
}
```

Laravel honours the `_method` field on `POST` requests (HTML form method spoofing is a documented feature), and Symfony's `Request` also reads `X-HTTP-Method-Override` on `POST`. Route-level `can:` middleware runs on the overridden method's route, so the protection holds as long as every route has its own authorisation. If your installed `symfony/http-foundation` is 7.4 or later, `Request::setAllowedHttpMethodOverride()` lets you limit which methods may be overridden (an empty array disables overrides). Call it before the request method is first read, and test it.

Trust only your load balancers:

```php
// bootstrap/app.php
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;

->withMiddleware(function (Middleware $middleware): void {
    $middleware->trustProxies(
        at: ['10.0.1.10', '10.0.1.11'],
        headers: Request::HEADER_X_FORWARDED_FOR | Request::HEADER_X_FORWARDED_PROTO
    );
})
```

The Laravel documentation allows `at: '*'` for cloud load balancers with unknown addresses ([Laravel: trusted proxies](https://laravel.com/docs/13.x/requests#configuring-trusted-proxies)). That is only safe if the application cannot be reached except through that load balancer, and the load balancer overwrites the headers. Otherwise every client can set its own IP.

### Next.js

Treat `middleware.ts` (renamed `proxy.ts` in Next.js 16) as an optimistic redirect layer, not as authorisation. The Next.js authentication guide says it should not be the only line of defence, and that most checks belong close to the data, in a Data Access Layer ([Next.js: Authentication](https://nextjs.org/docs/app/guides/authentication)). CVE-2025-29927 showed why.

```typescript
// app/lib/dal.ts
import 'server-only';
import { cache } from 'react';
import { cookies } from 'next/headers';
import { decrypt } from '@/app/lib/session';

export const getSession = cache(async () => {
  const token = (await cookies()).get('session')?.value;
  const session = token ? await decrypt(token) : null;
  return session?.userId ? { userId: session.userId, role: session.role } : null;
});
```

```typescript
// app/api/admin/users/route.ts
import { getSession } from '@/app/lib/dal';
import { listUsers } from '@/app/lib/users';

export async function GET() {
  const session = await getSession();
  if (!session) return Response.json({ error: 'authentication_required' }, { status: 401 });
  if (session.role !== 'admin') return Response.json({ error: 'forbidden' }, { status: 403 });
  return Response.json(await listUsers());
}
```

Upgrade to a fixed release. If you cannot, strip `x-middleware-subrequest` from external requests at the edge (the advisory's workaround), as in the nginx example above.

### Authorisation regression tests

Turn the bypass variants into tests that run on every build:

- **Route coverage.** Enumerate the router's route table in a test (Express router stack, Django `URLResolver`, Spring `RequestMappingHandlerMapping`, `php artisan route:list --json`). Fail when a route is neither on the public allowlist nor protected by a named policy.
- **Role matrix.** For each route and role, assert the expected status: anonymous `401`/redirect, wrong role `403`, right role `2xx`.
- **Variants.** For each privileged route, assert that case, trailing slash, `;`, suffix, method and override variants are denied or rejected.
- **Headers.** Assert that `X-Forwarded-For: 127.0.0.1`, `X-Original-URL` and role headers change nothing.
- **Run some tests through the real proxy** in a staging environment. Unit tests call the application directly and cannot see edge-versus-origin differences.

```javascript
// test/admin-bypass.test.js (Jest + supertest)
const request = require('supertest');
const app = require('../app');

const TOKEN = `Bearer ${process.env.TEST_TOKEN_USER_A}`; // normal user, test environment only
const paths = ['/api/admin/users', '/API/admin/users', '/api/admin/users/', '/api/admin//users'];

describe('admin API denies a normal user', () => {
  test.each(paths)('GET %s', async (path) => {
    const res = await request(app).get(path).set('Authorization', TOKEN);
    expect([401, 403, 404]).toContain(res.status);
  });

  test.each(['head', 'post', 'put', 'patch', 'delete'])('%s /api/admin/users', async (method) => {
    const res = await request(app)[method]('/api/admin/users').set('Authorization', TOKEN);
    expect([401, 403, 404, 405]).toContain(res.status);
  });

  test('override and IP headers change nothing', async () => {
    const res = await request(app)
      .post('/api/admin/users')
      .set('Authorization', TOKEN)
      .set('X-HTTP-Method-Override', 'DELETE')
      .set('X-Forwarded-For', '127.0.0.1');
    expect([401, 403, 404, 405]).toContain(res.status);
  });
});
```

```java
// Spring Boot + MockMvc (includes the Spring Security filter chain and StrictHttpFirewall); JUnit and Spring test imports trimmed
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@SpringBootTest
@AutoConfigureMockMvc
class AdminBypassTests {

    @Autowired MockMvc mvc;

    @ParameterizedTest
    @ValueSource(strings = {"/admin/users", "/ADMIN/users", "/admin/users/", "/admin/users.json", "/admin/users;x=1"})
    @WithMockUser(roles = "USER")
    void normalUserIsDenied(String path) throws Exception {
        int status = mvc.perform(get(path)).andReturn().getResponse().getStatus();
        assertThat(status).isIn(400, 403, 404);
    }

    @Test
    void anonymousIsSentToLogin() throws Exception {
        int status = mvc.perform(get("/admin/users")).andReturn().getResponse().getStatus();
        assertThat(status).isIn(302, 401);
    }
}
```

```python
# Django
from django.contrib.auth import get_user_model
from django.test import TestCase


class InternalEndpointTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("gt-user-a", password="test-only-password")

    def test_spoofed_ip_is_ignored(self):
        self.client.force_login(self.user)
        resp = self.client.get("/internal/status/", HTTP_X_FORWARDED_FOR="127.0.0.1")
        self.assertEqual(resp.status_code, 403)

    def test_staff_variants_denied(self):
        self.client.force_login(self.user)
        for path in ["/staff/users/", "/STAFF/users/", "/staff/users"]:
            self.assertIn(self.client.get(path).status_code, {301, 302, 403, 404})
```

```php
// Laravel feature test
public function test_normal_user_cannot_use_method_spoofing_on_admin_routes(): void
{
    $user = User::factory()->create(['is_admin' => false]);
    $target = User::factory()->create();

    $this->actingAs($user)
        ->post("/admin/users/{$target->id}", ['_method' => 'DELETE'])
        ->assertForbidden();

    foreach (['/admin/users', '/ADMIN/users', '/admin/users/'] as $path) {
        $this->assertContains($this->actingAs($user)->get($path)->status(), [301, 403, 404]);
    }
}
```

## Practice labs

**PortSwigger Web Security Academy** ([access control topic](https://portswigger.net/web-security/access-control)):

| Lab | Practises | Test |
|---|---|---|
| [Unprotected admin functionality](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality) | Admin path disclosed in `robots.txt` | BYP-2 |
| [Unprotected admin functionality with unpredictable URL](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url) | Admin URL leaked in JavaScript | BYP-2, BYP-11 |
| [User role controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter) | `Admin=true` cookie | BYP-10 |
| [User role can be modified in user profile](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile) | Role in a writable profile field | BYP-10 |
| [URL-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented) | `X-Original-URL` past a front-end rule | BYP-7 |
| [Method-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented) | Alternative method for an admin action | BYP-5 |
| [Multi-step process with no access control on one step](https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step) | Unchecked confirmation step | BYP-9 |
| [Referer-based access control](https://portswigger.net/web-security/access-control/lab-referer-based-access-control) | Forged `Referer` on an admin sub-action | BYP-9 |
| [Finding and exploiting an unused API endpoint](https://portswigger.net/web-security/api-testing/lab-exploiting-unused-api-endpoint) | Methods the UI does not use | BYP-2, BYP-5 |
| [Host header authentication bypass](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-authentication-bypass) | "Local users only" decided from a request header | BYP-8 |

**OWASP Juice Shop** ([guide](https://pwning.owasp-juice.shop/)): *Score Board* (find a hidden route from the bundle), *Admin Section* (reach the administration page as a normal user), *Web3 Sandbox* (an accidentally deployed hidden route), *Deprecated Interface* (an old interface that was not shut down), *Confidential Document* and *Forgotten Developer Backup* (unlinked files).

**OWASP [crAPI](https://github.com/OWASP/crAPI)**: Challenge 7, "Delete a video of another user", is the textbook guess-the-admin-route-and-method case; Challenge 14, "Find an endpoint that does not perform authentication checks for a user", is BYP-1.

**[VAmPI](https://github.com/erev0s/VAmPI)**: the `/users/v1/_debug` endpoint, which returns details of all users, is a forced-browsing target. Run it with `vulnerable=1` and `vulnerable=0` and compare.

## Real-world cases

- **Next.js middleware bypass, CVE-2025-29927 (2025).** Rachid and Yasser Allam showed that the internal `x-middleware-subrequest` header, used by Next.js to avoid recursive middleware calls, could be supplied by a client so that the server skipped middleware altogether. Any application that authorised only in middleware lost its authorisation. Vercel's postmortem documents the disclosure timeline and the fixes. Write-ups: [zhero: Next.js and the corrupt middleware](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware), [Vercel postmortem](https://vercel.com/blog/postmortem-on-next-js-middleware-bypass), [GitHub advisory GHSA-f82v-jwr5-mffw](https://github.com/advisories/GHSA-f82v-jwr5-mffw).
- **Clario (MacKeeper), HackerOne report 737323 (2019, disclosed 2020).** The front nginx server returned `403` for `/admin`, but the back-end honoured `X-Rewrite-URL` / `X-Original-URL`. A request for `/` with the header pointing at `admin/login` returned the admin login page. Resolved, rated Medium, and the report shows a $300 bounty. [HackerOne #737323](https://hackerone.com/reports/737323).
- **Yelp, HackerOne report 1011767 (2020).** Requests to `biz-app.yelp.com` endpoints such as `/status` and `/swagger.json` were refused normally but answered when the request carried `X-Forwarded-For: 127.0.0.1`. The server treated the caller as internal. Resolved, rated Medium. [HackerOne #1011767](https://hackerone.com/reports/1011767).
- **Acronis, HackerOne report 1224089 (2021, disclosed 2024).** An `nginx_status` page that returned `403` was served when the request carried `X-Forwarded-For: 127.0.0.1:80`. Low impact (status data), rated Low with a $250 bounty, but the same trust applied to anything else behind that rule. [HackerOne #1224089](https://hackerone.com/reports/1224089).
- **FortiOS / FortiProxy / FortiSwitchManager, CVE-2022-40684 (2022).** Horizon3's analysis shows the management API's "trusted access" check accepted requests whose client IP, taken from a client-supplied `Forwarded` header, was loopback and whose `User-Agent` was an internal value, giving unauthenticated administrative access. Fortinet reported in-the-wild exploitation. [Horizon3 deep dive](https://horizon3.ai/attack-research/attack-blogs/cve-2022-40684/), [Fortinet FG-IR-22-377](https://www.fortiguard.com/psirt/FG-IR-22-377).
- **Breaking Parser Logic (Orange Tsai, Black Hat USA 2018).** The research that popularised proxy-versus-back-end path disagreements, including the nginx-in-front-of-Tomcat `..;/` pattern used to reach paths the proxy was meant to block. [Slides (PDF)](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf).

More of our own write-ups are collected in [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

Rate by what the bypass reaches, not by how clever the request is. A trailing slash that exposes the admin panel is as severe as any other route to the admin panel. Use the series anchors: unauthenticated access to admin functions or to all users' sensitive data is Critical; any-user access to privileged functions is High to Critical; a hidden UI with no reachable server-side gap is Info.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Unauthenticated access to admin functions (any technique: missing auth, path variant, override header, IP header, framework CVE) | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | No precondition; full read and write over application data and users. Add `A:H` (9.8) if admin functions can delete data or disable the service |
| Unauthenticated read of all users' sensitive data via an unprotected API route | Critical (by series anchor) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | CVSS stays at 7.5 because there is no integrity impact; rate Critical when the data is PII, financial or credentials at scale, and say why the rating exceeds the score |
| Normal user reaches admin functions via path normalisation, method tampering, method override or URL override header | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1) | Any registered user (self-registration makes `PR:L` close to `PR:N` in practice) gains admin capability |
| Normal user reaches admin functions through a role cookie, parameter or header (`Admin=true`) | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1) | Trivial and reliable; Critical when self-registration is open and admin covers all tenants |
| Referer-only or step-order-only check on an admin action | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` (6.5) for a write-only action | Score the action reached (role change = integrity); rate High because it usually leads to full admin through role self-assignment |
| Internal status, metrics or API documentation reachable via `X-Forwarded-For` | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | Limited data, but it proves that every IP-based rule on that stack is void; rises with what the internal endpoints expose |
| Affected framework version with the vulnerable configuration confirmed (for example Next.js with middleware-only auth) | Critical (as the advisory) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1, the vector in the CVE-2025-29927 advisory) | Adjust confidentiality and integrity to what the protected routes expose |
| Affected framework version, precondition not established | Medium (vulnerable component) | Vendor vector, noted as "not confirmed" | Report the advisory and what remains to be checked |
| Override or URL-rewrite header honoured, no bypass found | Low | none (no direct impact) | Latent: any edge-only rule is void, now or after the next config change |
| Unused methods accepted (`FOO` answered as `GET`, `TRACE` enabled) without a bypass | Low / Info | none | Hardening against ASVS `v5.0.0-4.1.4` / `v5.0.0-13.4.4` |
| Admin view or route list visible in the SPA, every API call denied | Info | none | No reachable server-side gap |
| Privileged route disclosed in bundle or docs, correctly protected | Info | none | Report only if the disclosure itself is sensitive |

In the report, state the canonical request and its denial, the variant and its response, which layer made the wrong decision (edge, security filter, framework matcher, handler), and whether the same root cause applies to other routes.

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 / API Top 10 |
|---|---|---|---|---|
| GT-WEB-BYP-1 | WSTG-ATHZ-02, WSTG-ATHN-04 | v5.0.0-8.2.1 (L1), v5.0.0-7.2.1 (L1) | CWE-862, CWE-306, CWE-425 | A01:2025; API2:2023, API5:2023 |
| GT-WEB-BYP-2 | WSTG-ATHZ-02, WSTG-CONF-05, WSTG-CONF-04, WSTG-APIT-01 | v5.0.0-8.2.1 (L1), v5.0.0-13.4.5 (L2), v5.0.0-15.2.3 (L2) | CWE-425, CWE-285 | A01:2025; API5:2023, API9:2023 |
| GT-WEB-BYP-3 | WSTG-CONF-13, WSTG-ATHZ-02 | v5.0.0-8.3.1 (L1), v5.0.0-8.2.1 (L1) | CWE-647, CWE-41, CWE-436 | A01:2025; API5:2023 |
| GT-WEB-BYP-4 | WSTG-CONF-13, WSTG-ATHZ-02 | v5.0.0-8.3.1 (L1) | CWE-647, CWE-436 | A01:2025; API8:2023 |
| GT-WEB-BYP-5 | WSTG-CONF-06 | v5.0.0-4.1.4 (L3), v5.0.0-13.4.4 (L2), v5.0.0-8.2.1 (L1) | CWE-650, CWE-285 | A01:2025; API5:2023, API8:2023 |
| GT-WEB-BYP-6 | WSTG-CONF-06 | v5.0.0-4.1.4 (L3), v5.0.0-8.2.1 (L1) | CWE-650, CWE-285 | A01:2025; API5:2023, API8:2023 |
| GT-WEB-BYP-7 | WSTG-ATHZ-02 | v5.0.0-4.1.3 (L2), v5.0.0-8.3.1 (L1) | CWE-288, CWE-436 | A01:2025; API8:2023 |
| GT-WEB-BYP-8 | WSTG-ATHZ-02 | v5.0.0-15.3.4 (L2), v5.0.0-4.1.3 (L2), v5.0.0-8.4.2 (L3) | CWE-290, CWE-348 | A01:2025; API8:2023 |
| GT-WEB-BYP-9 | WSTG-ATHZ-02 | v5.0.0-8.2.1 (L1), v5.0.0-8.3.1 (L1) | CWE-293, CWE-285 | A01:2025; API5:2023 |
| GT-WEB-BYP-10 | WSTG-ATHN-04, WSTG-ATHZ-02, WSTG-CLNT-12 | v5.0.0-8.3.1 (L1) | CWE-602, CWE-565, CWE-807 | A01:2025; API5:2023 |
| GT-WEB-BYP-11 | WSTG-ATHZ-02, WSTG-APIT-04 | v5.0.0-8.3.1 (L1), v5.0.0-8.2.1 (L1) | CWE-602, CWE-285 | A01:2025; API5:2023 |
| GT-WEB-BYP-12 | WSTG-ATHZ-02, WSTG-INFO-08 | v5.0.0-15.2.1 (L1), v5.0.0-8.3.1 (L1) | CWE-288, CWE-647, CWE-1395 | A01:2025, A03:2025; API8:2023 |

CWE names: [CWE-41](https://cwe.mitre.org/data/definitions/41.html) Improper Resolution of Path Equivalence; [CWE-285](https://cwe.mitre.org/data/definitions/285.html) Improper Authorisation; [CWE-288](https://cwe.mitre.org/data/definitions/288.html) Authentication Bypass Using an Alternate Path or Channel; [CWE-290](https://cwe.mitre.org/data/definitions/290.html) Authentication Bypass by Spoofing; [CWE-293](https://cwe.mitre.org/data/definitions/293.html) Using Referer Field for Authentication; [CWE-306](https://cwe.mitre.org/data/definitions/306.html) Missing Authentication for Critical Functionality; [CWE-348](https://cwe.mitre.org/data/definitions/348.html) Use of Less Trusted Source; [CWE-425](https://cwe.mitre.org/data/definitions/425.html) Direct Request ('Forced Browsing'); [CWE-436](https://cwe.mitre.org/data/definitions/436.html) Interpretation Conflict; [CWE-565](https://cwe.mitre.org/data/definitions/565.html) Reliance on Cookies without Validation and Integrity Checking; [CWE-602](https://cwe.mitre.org/data/definitions/602.html) Client-Side Enforcement of Server-Side Security; [CWE-647](https://cwe.mitre.org/data/definitions/647.html) Use of Non-Canonical URL Paths for Authorisation Decisions; [CWE-650](https://cwe.mitre.org/data/definitions/650.html) Trusting HTTP Permission Methods on the Server Side; [CWE-807](https://cwe.mitre.org/data/definitions/807.html) Reliance on Untrusted Inputs in a Security Decision; [CWE-862](https://cwe.mitre.org/data/definitions/862.html) Missing Authorisation; [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) Dependency on Vulnerable Third-Party Component.

## References

**OWASP**

- WSTG: [WSTG-ATHZ-02 Bypassing Authorization Schema](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/02-Bypassing_Authorization_Schema), [WSTG-CONF-06 HTTP Methods](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/06-HTTP_Methods), [WSTG-CONF-13 Path Confusion](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/13-Path_Confusion), [WSTG-CONF-05 Enumerate Infrastructure and Application Admin Interfaces](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces), [WSTG-CONF-04 Review Old Backup and Unreferenced Files](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information), [WSTG-ATHN-04 Bypassing Authentication Schema](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/04-Authentication/04-Bypassing_Authentication_Schema), [WSTG-APIT-04 API Broken Function Level Authorization](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/04-API_Broken_Function_Level_Authorization)
- [ASVS 5.0 on GitHub](https://github.com/OWASP/ASVS/tree/master/5.0) (V8 Authorization, V4 API and Web Service, V13 Configuration, V15 Secure Coding and Architecture)
- [OWASP Top 10:2025 A01 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/)
- API Security Top 10 2023: [API2 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [API5 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/), [API8 Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/), [API9 Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)
- Cheat Sheets: [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [Authorization Testing Automation](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html), [Insecure Direct Object Reference Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html), [Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [OWASP community: Forced browsing](https://owasp.org/www-community/attacks/Forced_browsing)

**PortSwigger**

- [Access control vulnerabilities and privilege escalation](https://portswigger.net/web-security/access-control) (URL-matching discrepancies, platform misconfiguration, Referer- and location-based controls)
- [API testing](https://portswigger.net/web-security/api-testing), [HTTP Host header attacks](https://portswigger.net/web-security/host-header)
- [Gotta cache 'em all: bending the rules of web cache exploitation](https://portswigger.net/research/gotta-cache-em-all)

**Framework and server documentation**

- Express: [application settings](https://expressjs.com/en/5x/api/application/) (`case sensitive routing`, `strict routing`, `trust proxy`), [behind proxies](https://expressjs.com/en/5x/guide/behind-proxies), [method-override](https://github.com/expressjs/method-override)
- Django: [LoginRequiredMiddleware](https://docs.djangoproject.com/en/stable/ref/middleware/#django.contrib.auth.middleware.LoginRequiredMiddleware), [`login_not_required`](https://docs.djangoproject.com/en/stable/topics/auth/default/), [`SECURE_PROXY_SSL_HEADER`](https://docs.djangoproject.com/en/stable/ref/settings/#secure-proxy-ssl-header); DRF [permissions](https://www.django-rest-framework.org/api-guide/permissions/)
- Spring: [Authorize HttpServletRequests](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html), [HttpFirewall](https://docs.spring.io/spring-security/reference/servlet/exploits/firewall.html), [Spring Security 7 migration: PathPatternRequestMatcher](https://docs.spring.io/spring-security/reference/6.5/migration-7/web.html), [Forwarded headers](https://docs.spring.io/spring-framework/reference/web/webmvc/filters.html#filters-forwarded-headers), [Spring Framework 6.0 release notes](https://github.com/spring-projects/spring-framework/wiki/Spring-Framework-6.0-Release-Notes) (trailing-slash matching), [Spring Boot: web server behind a proxy](https://docs.spring.io/spring-boot/how-to/webserver.html), [Spring security advisories](https://spring.io/security)
- Laravel: [trusted proxies](https://laravel.com/docs/13.x/requests#configuring-trusted-proxies), [form method spoofing](https://laravel.com/docs/13.x/routing#form-method-spoofing), [authorisation](https://laravel.com/docs/13.x/authorization)
- Next.js: [Authentication guide](https://nextjs.org/docs/app/guides/authentication), [`proxy.ts` file convention](https://nextjs.org/docs/app/api-reference/file-conventions/proxy), [Next.js 16 release notes](https://nextjs.org/blog/next-16)
- nginx: [`location`](https://nginx.org/en/docs/http/ngx_http_core_module.html#location), [`proxy_pass` and `proxy_set_header`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html), [realip module](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
- RFCs: [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986) (URI syntax, dot segments, path parameters), [RFC 7239](https://datatracker.ietf.org/doc/html/rfc7239) (`Forwarded`)

**Advisories and research**

- [GHSA-f82v-jwr5-mffw / CVE-2025-29927](https://github.com/advisories/GHSA-f82v-jwr5-mffw); Spring [CVE-2016-5007](https://spring.io/security/cve-2016-5007), [CVE-2022-22978](https://spring.io/security/cve-2022-22978), [CVE-2022-31692](https://spring.io/security/cve-2022-31692), [CVE-2023-20860](https://spring.io/security/cve-2023-20860), [CVE-2023-34034](https://spring.io/security/cve-2023-34034), [CVE-2023-34035](https://spring.io/security/cve-2023-34035), [CVE-2024-38821](https://spring.io/security/cve-2024-38821); [Symfony CVE-2018-14773](https://symfony.com/blog/cve-2018-14773-remove-support-for-legacy-and-risky-http-headers); [Fortinet FG-IR-22-377](https://www.fortiguard.com/psirt/FG-IR-22-377)
- Orange Tsai, [Breaking Parser Logic](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf) (Black Hat USA 2018); [Acunetix: Tomcat path traversal via reverse proxy mapping](https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/)

**Tools**

- Burp extensions: [Autorize](https://github.com/Quitten/Autorize), [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix), [Auth Analyzer](https://github.com/PortSwigger/auth-analyzer), [Param Miner](https://github.com/PortSwigger/param-miner)
- [ZAP Access Control Testing add-on](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/)
- [ffuf](https://github.com/ffuf/ffuf), [SecLists](https://github.com/danielmiessler/SecLists), [Arjun](https://github.com/s0md3v/Arjun), [Nuclei](https://github.com/projectdiscovery/nuclei)
