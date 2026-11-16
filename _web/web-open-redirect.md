---
title: "Open Redirects: Client-Side and Server-Side"
date: 2026-11-15 22:14:00 +0000
subcategory: client-side
summary: "Testing open redirects in Location headers and JavaScript: where they hide, how allow-lists break, parser differentials, chains, ratings and fixes."
refs: [WSTG-CLNT-04, WSTG-ATHN-12, WSTG-ATHZ-05, WSTG-SESS-06, WSTG-CLNT-01, v5.0.0-3.7.2, v5.0.0-3.7.3, v5.0.0-1.2.2, v5.0.0-1.1.1, v5.0.0-2.2.1, v5.0.0-10.4.1, v5.0.0-15.3.2, "A01:2025", CWE-601, CWE-79, CWE-113]
tags: [web, client-side, open-redirect, url-parsing, allow-list, secure-coding]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Client-Side](/web/web-client-side-testing-guide/). It covers open redirects: an application that sends the browser to a destination taken from the request (a `next` parameter, a `RelayState`, a URL fragment) without checking that the destination is one it meant to allow. WSTG tests this as `WSTG-CLNT-04` (Client-side URL Redirect). At the time of writing WSTG has no separate test for server-side redirects; the server-side checks appear inside other tests, such as `RelayState` handling in SAML (`WSTG-ATHN-12`) and `redirect_uri` validation in OAuth (`WSTG-ATHZ-05`). This note covers both halves. On its own, an open redirect is usually a Low finding, and many bug bounty programmes exclude it. It matters more when it becomes the missing step in a bigger attack: it can carry an OAuth token off-site, get a server-side fetch past an SSRF allow-list, or let a script past a Content Security Policy path restriction. You get the model (who resolves the destination, and with which parser), the places redirects hide, ten tests that prove the issue with a redirect to `https://example.org/` and nothing more, the validator weaknesses worth a handful of variants each, and fixes in Express, browser JavaScript, Django, Spring Security and Laravel. A `javascript:` URL that reaches a client-side redirect sink is DOM XSS; the redirect side is covered here, and the sink side in [DOM XSS and client-side injection](/web/web-dom-xss-client-side-injection/).

## Contents

- [How it works](#how-it-works)
  - [Server-side redirects](#server-side-redirects)
  - [Client-side redirects](#client-side-redirects)
  - [Where redirects live](#where-redirects-live)
  - [Who resolves the destination](#who-resolves-the-destination)
  - [Why an open redirect matters](#why-an-open-redirect-matters)
- [What goes wrong](#what-goes-wrong)
  - [No validation](#no-validation)
  - [Prefix, suffix and substring matching](#prefix-suffix-and-substring-matching)
  - [Validating with one parser, redirecting with another](#validating-with-one-parser-redirecting-with-another)
  - [Validating one string, emitting another](#validating-one-string-emitting-another)
  - [No scheme allow-list in client-side redirects](#no-scheme-allow-list-in-client-side-redirects)
  - [Whitespace and control characters](#whitespace-and-control-characters)
  - [Trusting Referer and Host for the way back](#trusting-referer-and-host-for-the-way-back)
  - [Allow-lists that are too wide](#allow-lists-that-are-too-wide)
  - [Unsigned link wrappers and missing interstitials](#unsigned-link-wrappers-and-missing-interstitials)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [Signals and false positives](#signals-and-false-positives)
  - [GT-WEB-REDIR-1: Map redirect parameters and redirect sinks](#gt-web-redir-1-map-redirect-parameters-and-redirect-sinks)
  - [GT-WEB-REDIR-2: Server-side redirect to an external host](#gt-web-redir-2-server-side-redirect-to-an-external-host)
  - [GT-WEB-REDIR-3: Client-side redirect sinks](#gt-web-redir-3-client-side-redirect-sinks)
  - [GT-WEB-REDIR-4: Dangerous schemes in redirect targets](#gt-web-redir-4-dangerous-schemes-in-redirect-targets)
  - [GT-WEB-REDIR-5: Scheme-relative URLs, backslashes and extra slashes](#gt-web-redir-5-scheme-relative-urls-backslashes-and-extra-slashes)
  - [GT-WEB-REDIR-6: Userinfo, prefix, suffix and subdomain matching](#gt-web-redir-6-userinfo-prefix-suffix-and-subdomain-matching)
  - [GT-WEB-REDIR-7: Encoding, whitespace and control characters](#gt-web-redir-7-encoding-whitespace-and-control-characters)
  - [GT-WEB-REDIR-8: Parser differentials between validator and browser](#gt-web-redir-8-parser-differentials-between-validator-and-browser)
  - [GT-WEB-REDIR-9: Redirects in login, logout and SSO flows](#gt-web-redir-9-redirects-in-login-logout-and-sso-flows)
  - [GT-WEB-REDIR-10: Link wrappers, signed redirects and interstitial pages](#gt-web-redir-10-link-wrappers-signed-redirects-and-interstitial-pages)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Node.js and Express](#nodejs-and-express)
  - [Browser JavaScript](#browser-javascript)
  - [Django](#django)
  - [Spring Security](#spring-security)
  - [Laravel](#laravel)
  - [Link wrappers and interstitial pages](#link-wrappers-and-interstitial-pages)
  - [Regression tests](#regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

A redirect is the application telling the browser "go there instead". Either the server says it, with a status code and a header, or a script in the page says it, by changing the window's location. The security question is the same in both cases: **who chose "there"?** If the destination is fixed in code, or picked by the server from a list it owns, there is no finding. If any part of it comes from the request and the application does not check where it leads, an attacker can build a link that starts on the real site and ends on theirs.

### Server-side redirects

A server-side redirect is a `3xx` response with a `Location` header. The browser reads the header, resolves the value and navigates:

```http
GET /login?next=%2Faccount%2Fbilling HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
```

```http
HTTP/1.1 302 Found
Location: /account/billing
Content-Length: 0
```

Points from the HTTP specification that matter for testing:

- **`Location` takes a URI reference, not only an absolute URL** (RFC 9110, section 10.2.2). The browser resolves a relative value against the URL of the request. `/account/billing` stays on the same host; `//example.org/` is a *network-path reference* that keeps the scheme but replaces the host. Code that thinks "it does not start with `http`, so it must be local" is wrong for exactly that reason.
- **Fragments are inherited.** If the `Location` value has no fragment, the browser keeps the fragment of the original URL (RFC 9110, section 10.2.2). OAuth implicit and fragment-mode responses put tokens in the fragment, so a redirect that forwards the browser somewhere else carries the token along. This is the mechanism behind the OAuth chain described below.
- **Browsers only follow `Location` redirects to `http:` and `https:` URLs.** The Fetch standard returns a network error when a redirect points at any other scheme, so `Location: javascript:...` does not run script in a current browser. The response *body* of a redirect is another matter: many frameworks render a "Redirecting to …" page with a link, and some applications show a "click here if you are not redirected" link built from the same input.
- **There are other server-side mechanisms.** A `Refresh` response header and an HTML `meta` refresh tag (`<meta http-equiv="refresh" content="0;url=...">`) navigate as well, and both are common in interstitial pages and legacy code.

Every framework has a helper that builds the response for you: `res.redirect()` in Express, `redirect()` and `HttpResponseRedirect` in Django, `"redirect:"` view names, `sendRedirect()` and `RedirectStrategy` in Spring, `redirect()->to()` and `redirect()->away()` in Laravel. None of the generic helpers check where the URL points. Some higher-level features do (Django's `LoginView`, ASP.NET Core's `LocalRedirect`), and those are covered in [Secure implementation](#secure-implementation).

### Client-side redirects

In the browser, a script redirects by assigning to the location or by opening a window. The sinks PortSwigger lists for DOM-based open redirection include `location`, `location.href`, `location.assign()`, `location.replace()`, `location.host`, `location.hostname`, `location.pathname`, `location.search`, `location.protocol` and `open()`. A typical vulnerable pattern reads a source (`location.search`, `location.hash`, `document.referrer`, `postMessage` data, `localStorage`) and passes it to one of those sinks:

```javascript
// Vulnerable: the destination comes from the query string, unchecked
const next = new URLSearchParams(location.search).get("returnTo");
if (next) {
  window.location.href = next;
}
```

Three things make client-side redirects different from server-side ones:

- **The server may never see the input.** Values in the fragment (`#returnTo=...`) are not sent in the request, so server logs, a WAF and a proxy-only review all miss them. You find them by reading the JavaScript or with a DOM tool.
- **The `javascript:` scheme works.** Assigning `javascript:...` to `location.href` runs the code in the page's origin. A client-side open redirect without a scheme check is usually also DOM XSS, which raises the rating (test 4).
- **Single-page app routers** often treat a full URL as an external navigation. A `router.push(next)` or a framework `navigate(next)` call fed from the query string is a redirect sink even though it does not look like one; check how the router you see handles absolute URLs.

Redirects can also be assembled in markup: an `href` attribute built from a parameter is not an automatic redirect, but it becomes one when a script clicks it, and it becomes XSS when the user clicks a `javascript:` link. Those cases sit with [Reflected and stored XSS](/web/web-reflected-stored-xss/) and [DOM XSS](/web/web-dom-xss-client-side-injection/).

### Where redirects live

Redirects are a feature, not an accident. Most of them exist to bring a user back to where they were. That makes them easy to find once you know the shapes:

| Feature | Typical parameters or sources | Side | Notes |
|---|---|---|---|
| Login "return to" | `next`, `returnUrl`, `return_to`, `redirect`, `redirect_url`, `continue`, `dest`, `goto`, `target`, `r`, `url` | Server or client | The most common open redirect, and the most credible for phishing: the victim just entered their password on the real site |
| Logout | `next`, `post_logout_redirect_uri`, `returnTo` | Server | Often less carefully checked than login, and fires without user interaction |
| OAuth and OIDC | `redirect_uri`, `state` (some apps put the return path inside it), `post_logout_redirect_uri` | Server | `redirect_uri` validation at the authorization server is an OAuth topic; the client's own "return to" after the callback is in scope here |
| SAML | `RelayState` | Server | WSTG-ATHN-12 asks you to try an external URL here |
| Language and region switchers | `lang=fr&back=/products` | Server | Sends you back to the page you were on, often via `Referer` |
| Out-link wrappers and trackers | `/out?url=`, `/leaving?to=`, `/r/<id>` | Server | Exist precisely to send users off-site; the question is whether *any* site is allowed |
| Email click tracking | `https://click.example.com/l?u=...&sig=...` | Server | Usually third-party infrastructure; check whether the signature is enforced |
| Payment and checkout | `success_url`, `cancel_url`, `return_url` | Server | Sometimes passed to the payment provider and reflected back |
| Error and maintenance pages | `from=`, `retry=` | Client | "Try again" buttons that `location.replace()` the value |
| Mobile and deep-link bridges | `/app-link?target=`, `intent=` | Client | Web pages that forward to an app scheme or a web fallback |
| "Back" helpers | `Referer` header | Server | `back()` style helpers; see [Trusting Referer and Host for the way back](#trusting-referer-and-host-for-the-way-back) |

### Who resolves the destination

The validator and the browser each parse the destination. They do not always agree, and the browser's view is the only one that decides where the user ends up. Browsers follow the WHATWG URL Standard, which is more forgiving than RFC 3986 in ways that matter here:

- leading and trailing C0 control characters and spaces are removed, and ASCII tab and newline characters are removed from **anywhere** in the input;
- for special schemes (`http`, `https` and a few others) a backslash is treated like a forward slash;
- any number of slashes after the scheme, or at the start of a relative reference, leads into the host;
- the host is lower-cased, and internationalised names are converted to punycode.

Server-side URL libraries vary. Some implement WHATWG (Node.js `URL`), some follow RFC 3986 closely, and some do neither exactly. The table below resolves a few inputs against `https://app.example.com/login` with the WHATWG parser (Node.js `URL`, the same algorithm the browser uses) and with Python's `urllib.parse.urlsplit`, the kind of function a hand-written validator might call. Output is from our own lab run and shortened.

| Input | Browser (WHATWG) lands on | `urlsplit` sees | Why it matters |
|---|---|---|---|
| `/account` | `app.example.com` | path only | Safe relative path |
| `//example.org/` | `example.org` | netloc `example.org` | Scheme-relative; "starts with a slash" checks pass it |
| `/\example.org/` | `example.org` | path only, empty netloc | Python thinks it is a local path; the browser does not |
| `https:/\example.org/` | `example.org` | path only, empty netloc | Same differential with a scheme |
| `///example.org/` | `example.org` | path `/example.org/`, empty netloc | Extra slashes are absorbed by the browser |
| `https://app.example.com@example.org/` | `example.org` | netloc `app.example.com@example.org` | `app.example.com` is userinfo, not the host |
| `https://example.org\@app.example.com/` | `example.org` | hostname `app.example.com` | The backslash ends the host for the browser but not for `urlsplit` |
| `https:example.org` | `app.example.com/example.org` | scheme `https`, path `example.org` | Harmless here: same scheme as the base means relative |

That table is the whole idea of a parser differential: **the validator approved one URL and the browser visited another.** Orange Tsai's Black Hat USA 2017 talk *A New Era of SSRF* showed this between URL parsers and HTTP clients on the server side, and the 2022 Claroty Team82 and Snyk research *Exploiting URL Parsing Confusion* compared 16 parsers and grouped the confusions into scheme, slashes, backslash, URL-encoding and scheme-mixup cases. The same mismatches produce open redirects whenever the validator and the browser are different parsers.

### Why an open redirect matters

On its own, an open redirect lets an attacker send a link that **starts** on the real domain. It does not let them read anything, change anything or run code. What it changes is trust, and trust is what other controls are built on:

- **Phishing credibility.** The link shows the real host, the real certificate and, for a post-login redirect, a real login page. Mail filters and users that check the domain let it through. This is the impact WSTG-CLNT-04 describes, and it is real, but it is also why many programmes rate it low: an attacker can send a link to their own site anyway, and the redirect only makes it a little more convincing.
- **OAuth token and code theft.** If an OAuth client has an open redirect and the authorization server matches `redirect_uri` by prefix or pattern, the attacker sets `redirect_uri` to the client's open redirect; the code or token arrives on the real client host and is then forwarded off-site, in the query string or, through fragment inheritance, in the fragment. RFC 9700 (OAuth 2.0 Security Best Current Practice) section 4.11.1 says clients MUST NOT expose open redirectors for this reason, and PortSwigger's OAuth topic calls an open redirect "one of the most useful vulnerabilities" for stealing codes and tokens via a proxy page. Testing `redirect_uri` validation itself belongs to the Authentication notes of this series (not yet published); here we only check whether the client gives an attacker the forwarding step.
- **SSRF filter bypass.** A server-side feature that fetches URLs (webhooks, link previews, import from URL) may allow only certain hosts. If an allowed host has an open redirect and the server's HTTP client follows redirects, the fetch ends somewhere the allow-list never approved, including internal addresses. PortSwigger's SSRF topic has a section and a lab on exactly this, and ASVS `v5.0.0-15.3.2` asks back-ends not to follow redirects unless intended. SSRF testing belongs to the Server-Side Request & Files notes (not yet published).
- **CSP and other allow-list bypasses.** Content Security Policy ignores the path part of a source expression once a load has been redirected (CSP Level 3, section 7.6, Paths and Redirects). If a policy allows `https://static.example.com/js/` and some host in the policy has an open redirect, a script tag pointing at that redirect can load any path on `static.example.com`, not only `/js/`. The redirect target still has to match a host in the policy, so this widens a path restriction rather than defeating the policy. See [Content Security Policy and headers](/web/web-content-security-policy-headers/) for how policies are rated. The same pattern applies to anything that trusts "a URL on our domain": referrer checks, link-preview allow-lists, `postMessage` targets and SSO return URLs.
- **`javascript:` execution.** A client-side redirect without a scheme check runs attacker-supplied script in the application's origin (test 4). That is XSS and rated as such.

Google's Bug Hunters guidance, for example, lists open redirectors among reports it does not treat as vulnerabilities on their own and asks reporters to show impact beyond the redirect, such as the CSP and `javascript:` cases above (at the time of writing). Bugcrowd's Vulnerability Rating Taxonomy puts a GET-based open redirect at P4 and POST-based and header-based variants at P5. Rate the chain, not the redirect, whenever there is a chain.

## What goes wrong

### No validation

The destination goes straight into the helper:

```javascript
// Express: vulnerable
app.get("/login/complete", (req, res) => {
  res.redirect(req.query.next || "/");
});
```

```php
// Laravel: vulnerable (to() returns any absolute or scheme-relative URL unchanged)
return redirect()->to($request->query('next', '/dashboard'));
```

This is still the most common form. It survives because the developer tested it with `/dashboard` and it worked. Look in login and logout handlers, "continue" endpoints, out-link routes, and any controller that reads a parameter whose name contains `url`, `uri`, `next`, `return`, `redirect`, `dest`, `target`, `continue` or `goto`.

### Prefix, suffix and substring matching

A string check on the whole URL, rather than a comparison on the parsed host:

```javascript
// Vulnerable variants
if (next.startsWith("https://app.example.com")) { /* … */ }  // passes https://app.example.com.example.org/
if (next.includes("app.example.com")) { /* … */ }            // passes https://example.org/?app.example.com
if (/example\.com/.test(next)) { /* … */ }                   // unanchored; passes https://example.org/#example.com
if (new URL(next).hostname.endsWith("example.com")) { /* … */ } // passes any registrable name ending in "example.com"
```

The OWASP Unvalidated Redirects and Forwards Cheat Sheet says plainly not to use raw prefix or suffix matching. A suffix check on the hostname is only correct when it includes the leading dot (`.example.com`) **and** you really want to allow every subdomain (see [Allow-lists that are too wide](#allow-lists-that-are-too-wide)). Regular expressions built for the job tend to miss an anchor or an escaped dot.

### Validating with one parser, redirecting with another

The validator parses the input with library A to find the host, and the browser parses the `Location` value with the WHATWG algorithm. When A and the browser disagree on backslashes, slashes, userinfo or encoding, the validator approves a URL that the browser resolves to a different host. Public examples:

- **Express** before 4.19.2 passed redirect targets through `encodeurl` before writing the `Location` header; the GitHub advisory for CVE-2024-29041 says malformed URLs produced by that encoding could be interpreted differently by common allow-list validators, so input that passed the application's check redirected elsewhere.
- **Spring Framework** CVE-2024-22243 (and the follow-ups CVE-2024-22259 and CVE-2024-22262): applications that parsed an external URL with `UriComponentsBuilder` and then validated its host could be open to open redirect or SSRF, according to the Spring advisories.
- **Django** has fixed its own redirect validator several times: CVE-2016-2512 (redirect URLs containing basic-auth userinfo) and CVE-2017-7233 (numeric redirect URLs) are two of the entries in its security archive. The current validator's source comments explain the browser quirks it now guards against (backslashes, three leading slashes, leading control characters).
- **GitHub, 2014**: Egor Homakov's write-up chained a `redirect_uri` path traversal with a URL that Ruby's URI parser and the browser read differently (a `///host` form), so a Gist page could load an image from an outside host despite GitHub's image proxy, and the OAuth code leaked to that host in the `Referer`.

### Validating one string, emitting another

The check runs on one representation and the response carries another:

- the input is validated, then URL-decoded (or decoded twice) before it goes into `Location` (ASVS `v5.0.0-1.1.1` asks for decoding once, before validation);
- the validator approves a same-origin URL, and the code then emits only `url.pathname + url.search`. `new URL("/.//example.org/", "https://app.example.com")` is same-origin, but its `pathname` is `//example.org/`, which the browser reads as a scheme-relative reference to `example.org`;
- the framework rewrites or encodes the value after your check (the Express case above).

The rule that avoids all three: **validate the parsed URL, then emit the serialisation of that same parsed object** (or a value you looked up server-side), never the raw input.

### No scheme allow-list in client-side redirects

A client-side redirect that checks the host but not the scheme, or checks nothing, will happily assign `javascript:alert(document.domain)` to `location.href`. Chrome and Firefox block script-initiated top-level navigation to `data:` URLs, but `javascript:` still runs. ASVS `v5.0.0-1.2.2` (L1) asks that only safe URL protocols are permitted when URLs are built dynamically, and gives `javascript:` and `data:` as the examples to disallow. Look for this anywhere a redirect is implemented in JavaScript: login pages of SPAs, OAuth callback pages, "continue" buttons, deep-link bridges.

### Whitespace and control characters

Validators often check the raw value, while the browser strips leading and trailing spaces and control characters and removes tabs and newlines from anywhere. ` //example.org/` (leading space) and `/<TAB>/example.org/` both resolve to `example.org` in the browser. Some server stacks also turn encoded CR and LF into header line breaks, which is header injection rather than an open redirect; see [CRLF, header, log and CSV injection](/web/web-crlf-header-log-csv-injection/).

### Trusting Referer and Host for the way back

"Send them back where they came from" helpers read the `Referer` header: Express 4's `res.redirect("back")` (removed in Express 5, whose migration guide suggests `req.get("Referrer") || "/"` instead), Laravel's `back()`, Spring Security's `setUseReferer(true)`. An attacker's page can link to the target, so the `Referer` is the attacker's page and "back" goes back to them. That is a weak redirect (the victim was already on the attacker's site), and we rarely report it alone; it matters when the "back" value is stored and reused later, for example as the post-login destination.

The opposite direction is the `Host` header. Post-login redirects are often rebuilt from the request: Spring Security's saved request builds its redirect URL from the scheme, server name and port of the original request, and Django's `LoginView` allows `request.get_host()` as a destination. If the application trusts a client-supplied `Host` or `X-Forwarded-Host` header, those destinations are attacker-influenced. Testing host-header trust belongs to `WSTG-INJT-17` and the HTTP & Infrastructure notes of this series (not yet published); here, note when a redirect depends on it.

### Allow-lists that are too wide

`*.example.com` sounds strict until you count what lives under it: marketing sites run by agencies, user-content subdomains, forgotten staging hosts, a dangling DNS record waiting for a subdomain takeover, and other applications that have their own open redirects. An allow-list is only as strong as the weakest host on it. ASVS `v5.0.0-3.7.2` (L2) asks that automatic redirects to hosts the application does not control go only to destinations on an allow-list; keep that list to exact hostnames you can name.

### Unsigned link wrappers and missing interstitials

Out-link wrappers (`/out?url=`), email click trackers and "you are leaving our site" pages exist to send users elsewhere. They are fine when the destination is one the application put there: an ID that maps to a stored URL, or a URL carrying a signature the server checks. They are open redirects when the signature is optional, when an empty or missing signature is accepted, or when the signature covers something other than the destination. ASVS `v5.0.0-3.7.3` (L3) asks for a notification with an option to cancel when the user is sent outside the application's control; an interstitial that auto-continues after a second with a meta refresh does not meet that.

## Testing

Everything below assumes an **authorised** engagement with written scope and rules of engagement, a bug bounty programme whose rules allow redirect testing, or a deliberately vulnerable lab. Requests and responses in this note are **illustrative**: hosts are fictional (`app.example.com` is the target, `example.org` the external destination) and outputs are shortened.

### Before you start

**One destination: `https://example.org/`.** Every redirect proof in this note goes to `https://example.org/` (a domain reserved for documentation), or to a hostname under `example.org` when a test needs a different-looking host. Never point a proof at a site you run, a look-alike domain or a page that asks for anything. No phishing pages, no lures, no links sent to real users or staff. A redirect to a reserved domain proves the flaw as well as anything else would.

**Accounts.** Your own test accounts only. Login, logout and SSO flows (test 9) need an account you can sign in with; for OAuth-related checks use a test client or a test tenant if the client provides one.

**Keep tokens at home.** When a redirect would carry a code, token or session identifier off-site (test 9), intercept the final hop in Burp and **drop it**: the proof is the `Location` header and the URL that would have been requested, not a token arriving somewhere. Use your own test account even so, and revoke or let expire anything that was issued.

**Browsers decide.** The finding is where the browser goes, not what the server printed. Confirm each candidate in a current Chrome and a current Firefox, because their URL handling and warnings differ slightly (Firefox, for example, can prompt before following a URL with userinfo). Use a separate browser profile for testing.

**Proxy setup.** One Burp project per engagement with scope set; **Logger** on; **Repeater** for single variants; Burp's embedded browser with **DOM Invader** enabled for client-side sinks (test 3); **Param Miner** to guess unlinked parameters (test 1). Burp Scanner reports *Open redirection (reflected)* and *Open redirection (stored)* issues; treat them as leads to confirm by hand. OWASP ZAP's active scanner has an external-redirect rule that does the same job.

**Variant discipline.** Tests 5 to 7 check whether a validator is incomplete. Use the small sets given there (three to six inputs each), stop at the first one that redirects to `example.org`, and report the finding as a weakness of the validator with the variants you used. Do not run large bypass wordlists against production; PortSwigger's URL validation bypass cheat sheet exists if you need a list in a lab.

**Request rate.** Manual testing at one or two requests per second is plenty; redirect tests need few requests.

**Stop rules.** If a redirect flow shows another user's data (a return URL containing someone else's identifier or token, a shared link wrapper that reveals other users' destinations), stop, keep only the minimum redacted evidence, and report it immediately. If a test triggers account lockouts or emails to real people (for example a logout that notifies), pause and ask the client.

### Signals and false positives

The signal for a server-side redirect is a `3xx` response whose `Location` value the **browser** resolves to `example.org`. For a client-side redirect it is the browser's address bar after the page's script has run. Rule out these before you report:

| Impostor | What it looks like | How to tell |
|---|---|---|
| **Redirect stays on the host after normalisation** | `Location: /%2F%2Fexample.org/` or `Location: https://app.example.com//example.org/` | Resolve it the way the browser does (test 8 helper): both stay on `app.example.com`. Not a finding |
| **Intermediate warning page** | `200 OK` page saying "You are leaving app.example.com for example.org" with a link | Not an open redirect if the user has to click and the page shows the full destination. Report only if it auto-continues (meta refresh, `Refresh` header, script) or hides the destination |
| **Reflected but not followed** | `next` echoed into a hidden form field or an `href` | Not a redirect by itself; check whether a script navigates to it, and test `javascript:` for XSS (test 4) |
| **Redirect to an allowed partner** | `Location: https://help.example.com/` | On the allow-list by design; check that the list is exact (test 6), not that one host is allowed |
| **Your own input, your own session only** | The destination is read from a value only you can set (a per-user setting) | Self-redirect; low or no impact unless another user can be made to load it |
| **Referer-based "back"** | `Location:` equals your `Referer` | The victim must already be on the attacker's page; usually informational (see What goes wrong) |
| **Off-site by design, with consent** | A "visit website" button on a user profile that goes to the user's stated site | Intended; still check for an interstitial on L3 targets (ASVS `v5.0.0-3.7.3`) and for `javascript:` in the stored value |
| **The browser blocks it** | `Location: javascript:...` does nothing | Browsers do not follow non-HTTP(S) redirects; look at the response body instead (test 4) |

### GT-WEB-REDIR-1: Map redirect parameters and redirect sinks

*Guler Tech methodology.* Implements the identification step of WSTG-CLNT-04 (identify injection points that handle URLs or paths), with WSTG-INFO-06 (entry points), WSTG-ATHN-12 (`RelayState`) and WSTG-SESS-06 (logout).

#### What it checks

Every place the application decides a navigation destination from input: query and body parameters, path segments, headers, cookies, the URL fragment, `postMessage` data and stored values.

#### Prerequisites

A crawl of the application in Burp with at least one logged-in session; access to the JavaScript bundles; the client's list of SSO integrations if they will share it.

#### Steps

1. In Burp's **HTTP history**, filter on `3xx` responses and list every request whose `Location` value contains part of a request parameter, path segment or header. Burp's search across requests and responses for the parameter value is the fastest way.
2. Search request parameters for redirect-shaped names: `next`, `url`, `uri`, `return`, `returnUrl`, `return_to`, `redirect`, `redirect_uri`, `redirect_url`, `continue`, `dest`, `destination`, `goto`, `target`, `to`, `out`, `r`, `u`, `RelayState`, `callback`, `success_url`, `cancel_url`, `back`.
3. Walk the redirect-heavy flows by hand: log in from a deep link (`/account/billing` while logged out), log out from each place that offers it, switch language, open external links from content, follow a link from a notification email in a test account, start every SSO option the application offers.
4. Run **Param Miner** ("Guess params") against the login, logout and out-link endpoints to find parameters the UI never sends.
5. In the JavaScript, search for sinks and the sources feeding them:

```bash
# Look for redirect sinks in downloaded bundles (own copy, offline)
grep -nE "location(\.href)?\s*=|location\.(assign|replace)\(|window\.open\(|\.navigate\(|router\.(push|replace)\(" -r ./bundles/ | head -50
grep -nE "(returnTo|returnUrl|redirect|next|continue)" -r ./bundles/ | head -50
```

6. Note `meta` refresh tags and `Refresh` headers in responses, and any page that renders "Redirecting to …" with a link.

#### Observation

A table you keep for the rest of the tests:

| # | Endpoint or page | Input | Side | Current behaviour |
|---|---|---|---|---|
| 1 | `GET /login` then `POST /login` | `next` (query, carried in a hidden field) | Server | `Location: /account/billing` |
| 2 | `GET /logout` | `returnTo` | Server | `Location: https://www.example.com/` (marketing site) |
| 3 | `/app/#/callback` | `returnTo` inside the fragment | Client | `location.replace(returnTo)` in `auth.js` |
| 4 | `GET /out` | `url`, `sig` | Server | Interstitial page, then link |
| 5 | `POST /saml/acs` | `RelayState` | Server | `Location:` equals `RelayState` |

#### Evaluation

This is an inventory, so there is no pass or fail. Every row goes into tests 2 to 10. A redirect endpoint you could not reach (an SSO you have no account for) is a gap to note in the report.

#### False positives

Parameters with redirect-like names that only feed analytics (`ref=`, `utm_source=`), and `Location` values that match your input by coincidence (a fixed `/dashboard` default).

#### Automation

Burp Scanner and ZAP find many reflected server-side redirects during a crawl. In CI, a simple test that lists routes whose handlers call the framework's redirect helper with request data is a good review trigger; CodeQL ships queries for this (`js/server-side-unvalidated-url-redirection`, `js/client-side-unvalidated-url-redirection`, `py/url-redirection`, `java/unvalidated-url-redirection`).

### GT-WEB-REDIR-2: Server-side redirect to an external host

*Guler Tech methodology.* Implements WSTG-CLNT-04 for server-built redirects, the `RelayState` check in WSTG-ATHN-12, and the redirect part of WSTG-SESS-06.

#### What it checks

Whether a server-side redirect sends the browser to `https://example.org/` when you supply it, by `Location`, `Refresh`, meta refresh or a body link.

#### Prerequisites

The inventory from test 1.

#### Steps

1. Replace the destination with the absolute URL and send it in Repeater:

```http
GET /login?next=https%3A%2F%2Fexample.org%2F HTTP/1.1
Host: app.example.com
```

```bash
curl -s -o /dev/null -D - "https://app.example.com/login?next=https%3A%2F%2Fexample.org%2F" | grep -i "^location"
```

2. For flows where the parameter is used later (login), carry it through the whole flow: open `/login?next=...`, sign in with your test account, and watch the response to `POST /login`. Many applications copy `next` into a hidden field or the session and only use it after authentication.
3. Try the same destination in every carrier the endpoint accepts: query string, form body, JSON body, and, where step 1 of test 1 suggested it, a cookie or header. Bugcrowd's taxonomy separates GET-based from POST-based and header-based redirects because the attacker can only deliver some of them in a link.
4. If the endpoint shows an interstitial, read its markup: does it auto-continue (meta refresh, `Refresh` header, a timer script)? Does it show the full destination?
5. Open the final URL in the browser to confirm you land on `example.org`.

#### Observation

Vulnerable:

```http
HTTP/1.1 302 Found
Location: https://example.org/
```

Not vulnerable (destination ignored or replaced):

```http
HTTP/1.1 302 Found
Location: /dashboard
```

Not vulnerable (rejected):

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"error":"invalid_redirect"}
```

#### Evaluation

**Fail** if the browser ends up on `example.org` without the user making an informed choice, from a link an attacker could send (GET, or a POST an attacker page can auto-submit). **Fail at L3** (ASVS `v5.0.0-3.7.3`) if an interstitial exists but does not show the destination or does not let the user cancel. **Pass** if the destination is ignored, replaced with a default, or rejected, and an interstitial (where used) requires a click.

#### False positives

An allow-listed external host (check the list in test 6), the intermediate warning page that requires a click, and a `Location` that looks external but resolves to the same host (see [Signals and false positives](#signals-and-false-positives)).

#### Automation

A Burp Intruder run with your few destinations across the parameters from test 1 (one thread, throttled) or a scanner pass with only the redirect checks enabled. In CI, an integration test that requests each redirecting route with `next=https://example.org/` and asserts the `Location` is relative or on the allow-list (see [Regression tests](#regression-tests)).

### GT-WEB-REDIR-3: Client-side redirect sinks

*Guler Tech methodology.* Implements WSTG-CLNT-04 for JavaScript redirects; uses the source-and-sink approach of WSTG-CLNT-01 (DOM-based XSS).

#### What it checks

Whether page JavaScript navigates to a destination taken from a source you control: query string, fragment, `postMessage`, storage, `document.referrer`.

#### Prerequisites

The client-side rows from test 1; Burp's embedded browser with DOM Invader, or the browser developer tools.

#### Steps

1. Open the page in Burp's browser with **DOM Invader** on. It injects a canary into sources and reports when the canary reaches a sink such as `location.href` or `location.assign`. Note which source and which sink.
2. Without DOM Invader, set a breakpoint on the sink in the developer tools (search the bundle for the line found in test 1), load the page with a marker value, and step through the checks applied to it.
3. Supply the external destination through the source:

```text
https://app.example.com/app/#/callback?returnTo=https://example.org/
https://app.example.com/app/?returnTo=https%3A%2F%2Fexample.org%2F
```

4. If the source is `postMessage`, the proof is a local HTML file opened in your own browser that frames or opens the target and posts the message; it displays nothing and sends nothing elsewhere. Message handling itself is tested in [postMessage and web messaging](/web/web-postmessage-web-messaging/).
5. Confirm in Chrome and Firefox that the address bar ends on `example.org`.

#### Observation

The vulnerable code path, as seen in the debugger:

```javascript
// auth.js (illustrative, de-minified)
const query = location.hash.split("?")[1] || "";      // "#/callback?returnTo=..."
const returnTo = new URLSearchParams(query).get("returnTo");
if (returnTo && (returnTo.startsWith("/") || returnTo.startsWith("http"))) {
  location.replace(returnTo);
}
```

The condition allows anything starting with `/` (including `//example.org/`) and anything starting with `http`.

#### Evaluation

**Fail** if the page navigates to `example.org` from a source an attacker can set in a link or from another origin. **Pass** if the script resolves the value with `new URL()` against `location.origin` and only navigates when the resulting origin is the application's own (or on an exact allow-list), falling back to a fixed page otherwise.

#### False positives

Navigation to values set only by the application (a server-rendered configuration object), and sources an attacker cannot set cross-site (a value only your own session can write to `localStorage` is a self-redirect).

#### Automation

DOM Invader in Burp's browser; Burp Scanner's DOM analysis in a crawl. CodeQL's `js/client-side-unvalidated-url-redirection` query in CI for code you own, with the sink grep from test 1 as a cheaper first gate in code review.

### GT-WEB-REDIR-4: Dangerous schemes in redirect targets

*Guler Tech methodology.* Implements the JavaScript-injection case of WSTG-CLNT-04 and checks ASVS `v5.0.0-1.2.2` (safe URL protocols only).

#### What it checks

Whether a redirect target can use a scheme other than `https:` (and `http:` where still allowed), above all `javascript:` in client-side sinks and in links rendered on redirect pages.

#### Prerequisites

Client-side sinks from test 3; server-side redirect endpoints from test 2 whose responses have a body.

#### Steps

1. Client-side sinks: supply a harmless marker through the same source.

```text
https://app.example.com/app/#/callback?returnTo=javascript:alert(document.domain)
```

2. If that is rejected, try **at most three** variants that test whether the scheme check is a string comparison rather than a parsed one: mixed case (`JaVaScRiPt:alert(document.domain)`), a tab inside the scheme (`java%09script:alert(document.domain)`, which the URL parser removes), and a leading control character or space (`%01javascript:alert(document.domain)` or `%20javascript:...`). Stop at the first that fires.
3. Server-side redirects: send `next=javascript:alert(document.domain)` and read the **body** and any interstitial. A `Location: javascript:...` header alone does nothing in a current browser; a "click here" link or a meta refresh built from the same value may.
4. `data:` targets: note whether they are accepted. Chrome and Firefox refuse to open `data:` URLs as a top-level page when a script navigates to them, so this is normally a validator observation, not a working proof.

#### Observation

Vulnerable client-side sink: the browser shows an alert containing `app.example.com`.

Vulnerable redirect page (server-side redirect with a rendered link):

```http
HTTP/1.1 200 OK
Content-Type: text/html

<p>Redirecting… If nothing happens, <a href="javascript:alert(document.domain)">continue</a>.</p>
```

Not vulnerable:

```javascript
// The application resolved and rejected the value; the console shows the fallback
// navigation to https://app.example.com/
```

#### Evaluation

**Fail** (rate as DOM XSS or reflected XSS, not as an open redirect) if script runs in the application's origin. **Fail** (validator weakness, lower) if a non-HTTP(S) scheme is accepted but no browser executes it. **Pass** if only `https:` (and `http:` where intended) URLs are navigated to, decided on the parsed URL's `protocol`.

#### False positives

An alert that fires on a sandboxed or different origin (check `document.domain` in the alert); a `javascript:` value that is HTML-escaped into text rather than placed in an attribute or sink.

#### Automation

DOM Invader flags sinks reachable from sources; the PortSwigger XSS cheat sheet covers further payload forms if a lab needs them. In CI, unit-test the redirect helper with `javascript:` and `data:` inputs (see [Regression tests](#regression-tests)).

### GT-WEB-REDIR-5: Scheme-relative URLs, backslashes and extra slashes

*Guler Tech methodology.* Extends WSTG-CLNT-04 to validator bypasses, in the spirit of the filter-bypass section WSTG-ATHZ-05 points to for `redirect_uri` checks.

#### What it checks

Whether a validator that blocks `https://example.org/` still lets a relative-looking value through that the browser resolves to `example.org`.

#### Prerequisites

An endpoint from test 2 or 3 that **rejects** or rewrites an absolute external URL. If test 2 already redirected to `example.org`, skip this test: the finding is made.

#### Steps

Send these, one at a time, URL-encoded where they go into a query string. Stop at the first that lands on `example.org`.

| # | Value | Encoded for a query string | Browser destination |
|---|---|---|---|
| 1 | `//example.org/` | `%2F%2Fexample.org%2F` | `https://example.org/` (scheme-relative) |
| 2 | `/\example.org/` | `%2F%5Cexample.org%2F` | `https://example.org/` (backslash read as slash) |
| 3 | `\\example.org/` | `%5C%5Cexample.org%2F` | `https://example.org/` |
| 4 | `///example.org/` | `%2F%2F%2Fexample.org%2F` | `https://example.org/` |
| 5 | `https:/\example.org/` | `https%3A%2F%5Cexample.org%2F` | `https://example.org/` (for validators that only look for `://`) |

```bash
curl -s -o /dev/null -D - "https://app.example.com/login?next=%2F%5Cexample.org%2F" | grep -i "^location"
```

#### Observation

Vulnerable (the validator allowed a "relative" value):

```http
HTTP/1.1 302 Found
Location: /\example.org/
```

Not vulnerable (normalised to a path on the same host):

```http
HTTP/1.1 302 Found
Location: https://app.example.com/%5Cexample.org/
```

#### Evaluation

**Fail** if any variant makes the browser leave `app.example.com`. Report which variants passed and which were blocked; that pattern tells the developer what the validator checks (for example, "rejects `//` but not `/\`"). **Pass** if every variant is rejected or ends on the same host.

#### False positives

A `Location` that contains the backslash percent-encoded (`%5C`) stays on the host. So does `/%2F%2Fexample.org/`: the encoded slashes are part of the path.

#### Automation

These five inputs belong in the redirect helper's unit tests. A scanner will try more; confirm its hits by hand in a browser.

### GT-WEB-REDIR-6: Userinfo, prefix, suffix and subdomain matching

*Guler Tech methodology.* Extends WSTG-CLNT-04 to allow-list logic; checks ASVS `v5.0.0-3.7.2` (allow-listed destinations only).

#### What it checks

Whether an allow-list of external hosts compares the parsed hostname exactly, or matches strings in a way an attacker can satisfy.

#### Prerequisites

An endpoint that redirects to at least one allowed external or sibling host (for example `https://help.example.com/`) but rejects `https://example.org/`.

#### Steps

Send these (with `app.example.com` replaced by whichever host the allow-list accepts). Stop at the first that lands on `example.org` or one of its subdomains.

| # | Value | Browser destination | What it shows |
|---|---|---|---|
| 1 | `https://app.example.com@example.org/` | `example.org` | The check looked at the text before `@` (userinfo) |
| 2 | `https://app.example.com.example.org/` | a subdomain of `example.org` (reserved, does not serve content) | Prefix match on the URL or hostname |
| 3 | `https://example.org/?app.example.com` | `example.org` | Substring match on the whole URL |
| 4 | `https://example.org/#app.example.com` | `example.org` | Unanchored regular expression or "ends with" on the URL |
| 5 | `https://example.org\@app.example.com/` | `example.org` | Validator and browser disagree about where the host ends (test 8) |

For **suffix matching on the hostname without a leading dot** (`hostname.endsWith("example.com")`), the only working proof is a registrable domain that ends with the client's name. Do not register or use look-alike domains. If the patterns above suggest a suffix check, confirm it from the source (grey-box), from the client, or from a decision you can observe without leaving reserved names, and report it as a validator weakness with that evidence.

For **wildcard allow-lists** (`*.example.com`), a redirect to an allowed subdomain is by design. Record the breadth of the list and, where the client agrees, check whether any allowed host has its own open redirect or user-controlled content; that is how a wide allow-list becomes a working redirect.

#### Observation

Vulnerable:

```http
GET /out?url=https%3A%2F%2Fhelp.example.com%40example.org%2F HTTP/1.1
Host: app.example.com
```

```http
HTTP/1.1 302 Found
Location: https://help.example.com@example.org/
```

Some browsers warn about or strip userinfo on navigation; the validator finding stands either way, and variant 3 or 4 usually makes the same point without userinfo.

#### Evaluation

**Fail** if any variant reaches `example.org`, or if source or client confirms a suffix check without a leading dot. **Pass** if only exact hostnames on the list are accepted, the URL is rejected when it has userinfo, and the decision is made on the parsed hostname.

#### False positives

A redirect to a subdomain that is legitimately on a wildcard list; a `Location` with your input in the query string of an allowed host (`https://help.example.com/?u=example.org`), which stays on the allowed host.

#### Automation

Parameterised unit tests over these values for the allow-list function; in CI, fail the build if the allow-list configuration contains wildcards outside a reviewed set.

### GT-WEB-REDIR-7: Encoding, whitespace and control characters

*Guler Tech methodology.* Extends WSTG-CLNT-04; checks ASVS `v5.0.0-1.1.1` (decode once, before validation).

#### What it checks

Whether the application decodes the destination after validating it, or validates a value that the browser then trims or cleans into something else.

#### Prerequisites

An endpoint that rejects `//example.org/` and the variants in tests 5 and 6.

#### Steps

One at a time, stop at the first that lands on `example.org`:

| # | Value as sent in the query string | Tests for |
|---|---|---|
| 1 | `%252F%252Fexample.org%252F` | Decoding twice (validated as `%2F%2F…`, used as `//…`) |
| 2 | `%20%2F%2Fexample.org%2F` | Leading space: validator sees a non-slash first character, browser strips it |
| 3 | `%2F%09%2Fexample.org%2F` | Tab inside the value: browser removes it and sees `//example.org/` |
| 4 | `%2F%0A%2Fexample.org%2F` | Newline inside the value, same idea; also watch for a broken header |
| 5 | `https%3A%2F%2Fexample%E3%80%82org%2F` | Ideographic full stop (U+3002), which IDNA maps to a dot; tests a string check that runs before host normalisation |

If variant 4 (or a `%0D%0A` you try separately) produces a new header line in the response, stop: that is CRLF injection, tested and rated in [CRLF, header, log and CSV injection](/web/web-crlf-header-log-csv-injection/).

#### Observation

Vulnerable (double decoding):

```http
HTTP/1.1 302 Found
Location: //example.org/
```

Vulnerable (raw tab passed through; the browser drops it):

```text
Location: /[TAB]/example.org/        <- a literal tab character between the slashes
```

Not vulnerable: the response keeps the encoded characters in a path on the same host, or rejects the request.

#### Evaluation

**Fail** if any variant lands on `example.org`. **Pass** if the application decodes once, validates the decoded value with a real URL parser, and emits that parsed value.

#### False positives

A `Location` containing `%09` or `%0A` still encoded stays on the host. Some servers reject raw control characters in headers with a `500`; that is not an open redirect (but note it).

#### Automation

Keep these inputs in the unit tests. For a double-decoding bug, a regression test that round-trips the helper's output through the framework's redirect function catches the "framework encodes after my check" case too.

### GT-WEB-REDIR-8: Parser differentials between validator and browser

*Guler Tech methodology.* Extends WSTG-CLNT-04 with the parser-confusion approach from Orange Tsai's *A New Era of SSRF* and the Claroty/Snyk URL-parsing research.

#### What it checks

Whether the value the server emits is resolved by the browser to the host the validator approved. Tests 5 to 7 probe this from the outside; this test explains the results and checks the cases those tests cannot see.

#### Prerequisites

Results from tests 5 to 7. Grey-box access (source or the client's description of the validator) makes this test much faster.

#### Steps

1. For every variant that was **accepted** in tests 5 to 7, write down the exact `Location` value. For every variant that was **rejected**, write down the response. Together they show what the validator looks at.
2. Resolve each emitted value the way the browser does. Node.js implements the WHATWG URL Standard, so a few lines give you the browser's answer offline:

```javascript
// predict-destination.js: resolve Location values against the page URL, as a browser would
// Usage: node predict-destination.js https://app.example.com/login '/\example.org/' '//example.org/'
const [base, ...values] = process.argv.slice(2);
for (const v of values) {
  try {
    const u = new URL(v, base);
    const same = u.origin === new URL(base).origin;
    console.log(`${JSON.stringify(v).padEnd(44)} -> ${u.href}  ${same ? "same origin" : "LEAVES " + new URL(base).host}`);
  } catch {
    console.log(`${JSON.stringify(v).padEnd(44)} -> not a valid URL`);
  }
}
```

```text
"/\\example.org/"                            -> https://example.org/  LEAVES app.example.com
"//example.org/"                             -> https://example.org/  LEAVES app.example.com
"/%2F%2Fexample.org/"                        -> https://app.example.com/%2F%2Fexample.org/  same origin
```

3. If you know the validator's language, run the same inputs through the library it uses and compare host by host. For Python's `urllib.parse.urlsplit`, `/\example.org/` has an empty netloc (a path), and `https://example.org\@app.example.com/` has hostname `app.example.com`; the browser goes to `example.org` for both.
4. Check the **emitted** value, not only the decision. If the application accepts same-origin URLs, send `/.//example.org/` and `/a/..//example.org/`. Both are same-origin as full URLs, but if the code emits only the path, the `Location` becomes `//example.org/`.
5. Check the framework version against known differentials: Express before 4.19.2 (CVE-2024-29041), Spring Framework versions listed in CVE-2024-22243, CVE-2024-22259 and CVE-2024-22262 where the application validates hosts parsed by `UriComponentsBuilder`. Report outdated versions as a patching item unless you confirmed the bypass.

#### Observation

Vulnerable (emits the path of a same-origin URL):

```http
GET /login?next=%2F.%2F%2Fexample.org%2F HTTP/1.1
Host: app.example.com
```

```http
HTTP/1.1 302 Found
Location: //example.org/
```

Not vulnerable (emits the full, re-serialised URL):

```http
HTTP/1.1 302 Found
Location: https://app.example.com//example.org/
```

#### Evaluation

**Fail** if the browser's resolution of an emitted value leaves the approved hosts. **Pass** if the validator and the browser agree for every variant, which in practice means the application parses with a WHATWG-compatible parser (or rejects backslashes, control characters and unusual slash runs outright) and emits the parsed result.

#### False positives

Differences in how two parsers *print* a URL that do not change the host; a server parser that rejects input the browser would accept (fails closed, which is fine).

#### Automation

The helper above, run in CI against the redirect helper's outputs for a fixed list of inputs, catches regressions and framework upgrades that change encoding.

### GT-WEB-REDIR-9: Redirects in login, logout and SSO flows

*Guler Tech methodology.* Implements WSTG-CLNT-04 in authentication flows, the `RelayState` check in WSTG-ATHN-12 and the redirect handling in WSTG-SESS-06; it identifies, but does not test, the OAuth `redirect_uri` checks of WSTG-ATHZ-05.

#### What it checks

Whether redirects that run around authentication (after login, after logout, at the end of an SSO round trip) can be sent off-site, and whether anything sensitive travels with them.

#### Prerequisites

A test account for each login method in scope; Burp with interception on.

#### Steps

1. **Post-login.** Log out, open `/login?next=https%3A%2F%2Fexample.org%2F` (and the variants that worked elsewhere), sign in. Note where the destination is stored between the two requests: hidden field, cookie, session, `state` parameter.
2. **Logout.** Send `GET /logout?returnTo=https%3A%2F%2Fexample.org%2F` and the OIDC-style `post_logout_redirect_uri` if the application uses an identity provider. A logout redirect needs no interaction from a logged-in victim beyond opening the link.
3. **SAML.** Start an SP-initiated login, change `RelayState` to `https://example.org/` before it reaches the identity provider, and complete the flow with your test account.
4. **OAuth or OIDC client callbacks.** After the callback, applications often redirect to a "return to" value kept in `state` or a cookie. Change it the same way.
5. **What travels with it.** For each off-site redirect found, check before letting the browser follow:
   - Does the final URL contain a code, token, session identifier or personal data in the query string? (Intercept the request to `example.org` and **drop it**.)
   - Does the original URL have a fragment (implicit or `response_mode=fragment` flows)? If the `Location` has none, the browser carries the fragment over (RFC 9110, section 10.2.2).
   - What `Referrer-Policy` applies? A URL with a token in it leaks through `Referer` to the next site under a permissive policy (ASVS `v5.0.0-3.4.5`).
6. **Chain check, identify only.** If the authorization server is in scope, note whether its registered `redirect_uri` for this client is an exact URL or a prefix that would include the path of the open redirect you found. Testing `redirect_uri` validation and token theft belongs to the Authentication notes of this series (not yet published); here record the precondition and stop.

#### Observation

Vulnerable post-login redirect:

```http
POST /login HTTP/1.1
Host: app.example.com
Content-Type: application/x-www-form-urlencoded

username=gt-user-a%40example.com&password=<PASSWORD_USER_A>&next=https%3A%2F%2Fexample.org%2F
```

```http
HTTP/1.1 303 See Other
Location: https://example.org/
Set-Cookie: session=<SESSION_USER_A>; Path=/; Secure; HttpOnly; SameSite=Lax
```

Vulnerable with leakage (the request you drop):

```http
GET /?code=<AUTH_CODE_TEST_ACCOUNT>&state=<STATE> HTTP/1.1
Host: example.org
```

#### Evaluation

**Fail** if any authentication-related redirect reaches `example.org`. **Fail, higher severity** if a code, token or session identifier would leave with it, or if the open redirect sits on a path an authorization server accepts as `redirect_uri`. **Pass** if every flow ignores, replaces or rejects external destinations and nothing sensitive appears in URLs handed to other sites.

#### False positives

A logout that ends on the identity provider's own logout page (expected); a post-login redirect to a partner host that is on the documented allow-list; tokens that appear in the URL only on the application's own callback host.

#### Automation

End-to-end tests for each login method with a hostile `next`, `returnTo` and `RelayState`, asserting the final URL is on the application's origin. ZAP and Burp can replay authenticated flows with session handling rules if you want scanner coverage.

### GT-WEB-REDIR-10: Link wrappers, signed redirects and interstitial pages

*Guler Tech methodology.* Implements WSTG-CLNT-04 for intentional off-site redirects; checks ASVS `v5.0.0-3.7.2` and `v5.0.0-3.7.3`.

#### What it checks

Whether features built to send users elsewhere (out-link wrappers, email click trackers, "you are leaving" pages) only send them where the application intended, and warn them as designed.

#### Prerequisites

At least one wrapped link created by your own test account (a link in a message, a profile website, an email notification sent to your test mailbox).

#### Steps

1. Collect a few wrapped links from your own content and notifications. Note their shape: an ID (`/r/8f2c…`), a URL plus a signature (`/out?url=…&sig=…`), or a bare URL.
2. **Bare URL:** replace it with `https://example.org/` (this is test 2).
3. **URL plus signature:** with one of your own links, try in turn: changing the URL and keeping the signature; removing `sig`; sending `sig=` empty; using the signature of a different link of yours; changing the case or encoding of the URL while keeping the signature. Stop at the first that redirects to `example.org`.
4. **ID-based:** check that the ID maps to the destination stored for it and that you cannot create a mapping to an arbitrary destination without the content that should carry it (for example an API that issues short links for any URL, unauthenticated). Use only IDs you created; do not iterate IDs.
5. **Interstitial:** open a wrapped link. Does the page show the full destination (at least its host)? Does the user have to click to continue, with a way to cancel? Does it auto-continue through a meta refresh, a `Refresh` header or a script timer? What `Referrer-Policy` does it send?

#### Observation

Vulnerable (signature not enforced):

```http
GET /out?url=https%3A%2F%2Fexample.org%2F HTTP/1.1
Host: app.example.com
```

```http
HTTP/1.1 302 Found
Location: https://example.org/
```

Interstitial that does not meet ASVS `v5.0.0-3.7.3`:

```html
<meta http-equiv="refresh" content="1;url=https://example.org/">
<p>Taking you to our partner…</p>
```

#### Evaluation

**Fail** if a wrapped link can be pointed at `example.org` without the server having issued it, or if the signature check can be skipped. **Fail at L3** if there is no notification with a cancel option for off-site navigation. **Pass** if destinations come from server-side records or verified signatures, and the interstitial shows the destination and waits for the user.

#### False positives

Third-party email tracking domains that are outside the client's scope (report them to the client, do not test them); deliberately public link shorteners that are labelled as such.

#### Automation

Unit tests for the signer and verifier (wrong key, missing signature, modified URL, replayed signature from another link); an integration test that asserts the interstitial's response has no `Refresh` header or meta refresh.

## Secure implementation

### Design rules

1. **Don't take a destination from the request if you can avoid it.** Store the "return to" value server-side (in the session, keyed by the flow) and redirect to fixed routes. This is the first recommendation of the OWASP Unvalidated Redirects and Forwards Cheat Sheet.
2. **Prefer relative paths on your own origin.** Most "return to" features only need a path. Accept a path with exactly one leading slash, or parse the value against your own origin and require the result to be same-origin.
3. **For external destinations, use an allow-list of exact hostnames** (and scheme and port), compared on the **parsed** URL. No prefix, suffix, substring or regular-expression matching on the raw string (ASVS `v5.0.0-3.7.2`).
4. **Map IDs to destinations** when the set of external targets is known: `?dest=billing-portal` looks up a URL on the server. Unknown IDs go to a default.
5. **Use one parser that matches the browser,** or reject what browsers rewrite (backslashes, whitespace, control characters, more than one leading slash) before parsing. Decode once, before validation (ASVS `v5.0.0-1.1.1`).
6. **Emit what you validated.** Redirect to the serialisation of the parsed URL (or the value you looked up), not the raw input and not a fragment of the parsed URL such as its path.
7. **Allow only `https:`** (and `http:` only where you still need it) for any URL that ends up in a client-side sink or a link (ASVS `v5.0.0-1.2.2`).
8. **Show an interstitial for off-site navigation** at L3 (ASVS `v5.0.0-3.7.3`): the full destination, a continue button and a way back, no automatic refresh.
9. **Keep tokens out of URLs** that may be handed to other sites, and set a `Referrer-Policy` that does not leak full URLs cross-origin (ASVS `v5.0.0-3.4.5`).
10. **Back-end HTTP clients should not follow redirects** unless that is the intended behaviour (ASVS `v5.0.0-15.3.2`), so an open redirect on an allowed host does not turn into SSRF.

### Node.js and Express

`res.redirect()` and `res.location()` do not validate destinations. Express before 4.19.2 also had the `encodeurl` differential (CVE-2024-29041); upgrade, and validate with the WHATWG `URL` class before calling either function. Express 5 removed the magic `"back"` value; if you rebuild it from `Referer`, run that through the same helper.

```javascript
// safe-redirect.js
const APP_ORIGIN = "https://app.example.com";
const EXTERNAL_HOSTS = new Set(["help.example.com", "status.example.com"]); // exact names only

function safeRedirectTarget(raw, fallback = "/dashboard") {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 2048) return fallback;

  let url;
  try {
    url = new URL(raw, APP_ORIGIN); // the WHATWG parser, the same algorithm the browser uses
  } catch {
    return fallback;
  }

  if (url.username !== "" || url.password !== "") return fallback;

  if (url.origin === APP_ORIGIN) {
    return url.href; // absolute and re-serialised: never a bare "//host" path
  }
  if (url.protocol === "https:" && url.port === "" && EXTERNAL_HOSTS.has(url.hostname)) {
    return url.href;
  }
  return fallback;
}

module.exports = { safeRedirectTarget };
```

```javascript
// routes/auth.js
const { safeRedirectTarget } = require("../safe-redirect");

router.post("/login", async (req, res) => {
  // ... authenticate, regenerate the session ...
  res.redirect(303, safeRedirectTarget(req.body.next));
});

router.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect(safeRedirectTarget(req.query.returnTo, "/")));
});
```

Why this shape works: `new URL()` resolves the value exactly as the browser will, so `//example.org/`, `/\example.org/`, `///example.org/`, tabs, leading spaces, userinfo and `javascript:` all produce an origin other than `APP_ORIGIN` and fall back. The `typeof` check handles `next[]=a&next[]=b`, which Express's query parser turns into an array. Returning `url.href` rather than `url.pathname` closes the `/.//example.org/` case: the browser receives `https://app.example.com//example.org/`, which stays on the host. `url.hostname` is already lower-cased and converted to punycode, so write the allow-list in that form.

### Browser JavaScript

Apply the same rule in the page. Resolve against `location.origin`, compare origins, navigate to the parsed URL:

```javascript
function safeNavigate(raw, fallback = "/") {
  let target = null;
  if (typeof raw === "string" && raw.length > 0 && raw.length <= 2048) {
    try {
      target = new URL(raw, location.origin);
    } catch {
      target = null;
    }
  }
  const sameOrigin = target !== null && target.origin === location.origin && !target.username && !target.password;
  location.assign(sameOrigin ? target.href : fallback);
}

safeNavigate(new URLSearchParams(location.search).get("returnTo"));
```

A `javascript:` or `data:` URL has the origin `"null"`, so it fails the comparison without a separate scheme check. If you must allow external hosts, add an exact `Set` of hostnames and require `target.protocol === "https:"`. For SPA routers, pass only paths you validated this way to `navigate()` or `router.push()`. The DOM side (sinks, Trusted Types) is covered in [DOM XSS and client-side injection](/web/web-dom-xss-client-side-injection/).

### Django

Use the built-in views where you can. `LoginView` and `LogoutView` read `next` (`redirect_field_name`), accept it only when it points at `request.get_host()` or a host in `success_url_allowed_hosts`, require HTTPS when the request is secure, and otherwise use `next_page` or `LOGIN_REDIRECT_URL`/`LOGOUT_REDIRECT_URL`. Keep `success_url_allowed_hosts` empty or short, and keep `ALLOWED_HOSTS` strict: `request.get_host()` is only trustworthy because Django checks the `Host` header against it.

For your own views, Django's views use `url_has_allowed_host_and_scheme()` from `django.utils.http`. The Django 3.0 release notes describe it as a private internal utility (renamed from `is_safe_url()`) and warn that an allowed host and scheme do not by themselves make a URL "safe"; it is widely used, but pin its behaviour with your own tests:

```python
# views.py
from django.conf import settings
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme


def safe_next(request, fallback=None):
    target = request.POST.get("next", request.GET.get("next", ""))
    if url_has_allowed_host_and_scheme(
        url=target,
        allowed_hosts={request.get_host()},   # plus exact partner hosts if needed
        require_https=request.is_secure(),
    ):
        return target
    return fallback or settings.LOGIN_REDIRECT_URL


def switch_language(request):
    # ... set the language ...
    return redirect(safe_next(request, fallback="/"))
```

The function strips surrounding whitespace, rejects values starting with three slashes, a control character or a scheme without a host, and checks the value twice (once as given and once with backslashes turned into slashes) because browsers treat them alike. `HttpResponseRedirect` itself refuses schemes other than `http`, `https` and `ftp`, but it does **not** check the host, so `redirect(request.GET["next"])` is an open redirect.

### Spring Security

Spring Security's `DefaultRedirectStrategy` writes whatever URL it is given: absolute URLs go out unchanged, and relative ones get the context path prefixed (when the application runs at the root context, a value such as `//example.org/` therefore passes through as a scheme-relative URL; this is from our reading of the source at the time of writing). The post-login handlers decide what that URL is:

- `SavedRequestAwareAuthenticationSuccessHandler` (the form-login default) redirects to the saved request, which Spring rebuilds from the scheme, server name and port of the original request. That is safe as long as the application does not trust a client-supplied `Host` or `X-Forwarded-*` header; only enable forwarded-header processing behind a proxy that sets those headers itself.
- `setTargetUrlParameter("next")` and `setUseReferer(true)` on any `AbstractAuthenticationTargetUrlRequestHandler` (success and logout handlers) take the destination from the request parameter or `Referer` and pass it straight to the redirect strategy. Both are off by default; leave them off, or put a validating strategy in front.
- In Spring Security 6 the post-login URL often carries `?continue`. That parameter only tells the request cache to look up the saved request; it is not a destination, and changing it is not a finding.

A validating redirect strategy, with a validator that rejects what browsers rewrite before parsing with `java.net.URI`:

```java
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Set;

public final class RedirectTargets {
    private static final Set<String> ALLOWED_HOSTS = Set.of("app.example.com", "help.example.com");

    private RedirectTargets() {}

    /** Returns raw if it is a local path or an allow-listed https URL, otherwise the fallback. */
    public static String safe(String raw, String fallback) {
        if (raw == null || raw.isEmpty() || raw.length() > 2048) return fallback;
        // Reject what browsers silently rewrite: backslashes, whitespace, control characters
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '\\' || c <= 0x20 || c == 0x7f) return fallback;
        }
        final URI uri;
        try {
            uri = new URI(raw);
        } catch (URISyntaxException e) {
            return fallback;
        }
        if (uri.getScheme() == null && uri.getRawAuthority() == null) {
            // Relative reference: exactly one leading slash on the raw input, never "//"
            return (raw.startsWith("/") && !raw.startsWith("//")) ? raw : fallback;
        }
        boolean ok = "https".equalsIgnoreCase(uri.getScheme())
                && uri.getRawUserInfo() == null
                && (uri.getPort() == -1 || uri.getPort() == 443)
                && uri.getHost() != null
                && ALLOWED_HOSTS.contains(uri.getHost().toLowerCase(Locale.ROOT));
        return ok ? raw : fallback;
    }
}
```

```java
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

final class AllowListRedirectStrategy implements RedirectStrategy {
    private final DefaultRedirectStrategy delegate = new DefaultRedirectStrategy();

    @Override
    public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url)
            throws IOException {
        delegate.sendRedirect(request, response, RedirectTargets.safe(url, "/home"));
    }
}

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    SecurityFilterChain web(HttpSecurity http) throws Exception {
        SavedRequestAwareAuthenticationSuccessHandler success = new SavedRequestAwareAuthenticationSuccessHandler();
        success.setDefaultTargetUrl("/home");
        success.setRedirectStrategy(new AllowListRedirectStrategy());
        // targetUrlParameter and useReferer stay at their defaults (unset / false)

        http
            .formLogin(form -> form.successHandler(success))
            .logout(logout -> logout.logoutSuccessUrl("/login?logout"));
        return http.build();
    }
}
```

The raw-string check for a single leading slash matters: in our own tests, `java.net.URI` parses `///example.org/` as a relative reference with path `/example.org/`, so checking the parsed path alone would let it through, while the browser goes to `example.org`. In Spring MVC controllers, `return "redirect:" + next;` is the same open redirect; pass `next` through `RedirectTargets.safe()` first. If you parse external URLs with `UriComponentsBuilder` and check their host, stay on a Spring Framework release that includes the fixes for CVE-2024-22243, CVE-2024-22259 and CVE-2024-22262.

### Laravel

`redirect()->to($path)` (and the `redirect($path)` helper) returns any value that looks like a full URL, including one starting with `//`, without changes. `redirect()->away()` is documented as doing no encoding, validation or verification at all. Neither is safe with request input.

`redirect()->intended($default)` redirects to the `url.intended` value in the session, also without validation. Laravel normally sets that value itself: when the auth middleware sends a guest to the login page, it stores the full URL of the GET request they were trying to open. Two caveats, from our reading of the 12.x and 13.x `Redirector` source at the time of writing: for a non-GET request it stores the *previous* URL instead, which comes from the `Referer` header when present, so a cross-site form post to a protected route can leave an external intended URL; and any code that calls `redirect()->setIntendedUrl($request->input('next'))` or writes `url.intended` from input creates an open redirect on the next login. Validate before storing, and keep the default a route:

```php
// app/Support/RedirectTargets.php
namespace App\Support;

final class RedirectTargets
{
    private const ALLOWED_HOSTS = ['app.example.com', 'help.example.com'];

    public static function safe(mixed $raw, string $fallback): string
    {
        if (! is_string($raw) || $raw === '' || strlen($raw) > 2048) {
            return $fallback;
        }
        // Reject what browsers silently rewrite: backslashes, whitespace, control characters
        if (preg_match('/[\x00-\x20\x7f\\\\]/', $raw)) {
            return $fallback;
        }
        // Relative path: exactly one leading slash
        if (str_starts_with($raw, '/')) {
            return str_starts_with($raw, '//') ? $fallback : $raw;
        }
        $parts = parse_url($raw);
        if ($parts === false) {
            return $fallback;
        }
        $ok = strtolower($parts['scheme'] ?? '') === 'https'
            && ! isset($parts['user'])
            && ! isset($parts['pass'])
            && (! isset($parts['port']) || $parts['port'] === 443)
            && in_array(strtolower($parts['host'] ?? ''), self::ALLOWED_HOSTS, true);

        return $ok ? $raw : $fallback;
    }
}
```

```php
// app/Http/Controllers/Auth/AuthenticatedSessionController.php
use App\Support\RedirectTargets;

public function store(LoginRequest $request): RedirectResponse
{
    $request->authenticate();
    $request->session()->regenerate();

    if ($request->filled('next')) {
        return redirect()->to(RedirectTargets::safe($request->input('next'), route('dashboard', absolute: false)));
    }

    return redirect()->intended(route('dashboard', absolute: false));
}
```

If you rely on `intended()`, check the stored value the same way before using it (for example by reading `redirect()->getIntendedUrl()`, validating it, and calling `redirect()->to()` with the result). For a fixed set of external destinations, map keys to URLs instead:

```php
$destinations = [
    'billing-portal' => 'https://billing.example.com/portal',
    'status'         => 'https://status.example.com/',
];

return redirect()->away($destinations[$request->query('dest')] ?? route('dashboard'));
```

Here `away()` is fine because every value it can receive was written by you.

### Link wrappers and interstitial pages

For out-links in user content and email, store the destination server-side and send users to `/r/<id>`, or sign the destination and verify the signature before redirecting. Laravel's signed routes (`URL::signedRoute()` with the `signed` middleware) do this for you; in Node.js:

```javascript
const crypto = require("node:crypto");
const KEY = Buffer.from(process.env.OUTLINK_SIGNING_KEY, "base64"); // from your secret store

function signOutlink(url) {
  return crypto.createHmac("sha256", KEY).update(url, "utf8").digest("base64url");
}

function verifyOutlink(url, sig) {
  if (typeof url !== "string" || typeof sig !== "string") return false;
  const expected = Buffer.from(signOutlink(url));
  const given = Buffer.from(sig);
  return expected.length === given.length && crypto.timingSafeEqual(expected, given);
}
```

A missing, empty or wrong signature must be rejected, not treated as "unsigned link, show anyway". Then show an interstitial that meets ASVS `v5.0.0-3.7.3`:

```html
<!-- /leaving?to=... after verification; Referrer-Policy: no-referrer on this response -->
<h1>You are leaving app.example.com</h1>
<p>This link goes to <strong>https://example.org/</strong>.</p>
<a href="https://example.org/" rel="noopener noreferrer">Continue to example.org</a>
<a href="/">Go back</a>
```

No meta refresh, no `Refresh` header, no timer. Render the destination with normal output encoding (it is user content), and keep the `rel` values so the new page cannot reach back through `window.opener` (see [Clickjacking and tabnabbing](/web/web-clickjacking-tabnabbing/)).

### Regression tests

Unit-test the helper with the inputs from tests 4 to 7, and add an end-to-end test that resolves the real `Location` header the way a browser does:

```javascript
// test/redirect.test.js (Jest + supertest)
const request = require("supertest");
const app = require("../app");
const { safeRedirectTarget } = require("../safe-redirect");

const hostile = [
  "https://example.org/", "//example.org/", "/\\example.org/", "\\\\example.org/", "///example.org/",
  "https:/\\example.org/", " //example.org/", "/\t/example.org/", "/.//example.org/",
  "https://app.example.com@example.org/", "https://app.example.com.example.org/",
  "https://example.org/?app.example.com", "https://example.org\\@app.example.com/",
  "javascript:alert(document.domain)", "data:text/html,x",
];

test.each(hostile)("helper never leaves the origin for %j", (input) => {
  const out = new URL(safeRedirectTarget(input), "https://app.example.com/login");
  expect(["https://app.example.com", "https://help.example.com"]).toContain(out.origin);
});

test.each(hostile)("GET /logout does not redirect off-site for %j", async (returnTo) => {
  const res = await request(app).get("/logout").query({ returnTo });
  const dest = new URL(res.headers.location, "https://app.example.com/logout");
  expect(dest.origin).toBe("https://app.example.com");
});
```

```python
# tests/test_redirects.py (pytest-django)
import pytest

HOSTILE = [
    "https://example.org/", "//example.org/", "/\\example.org/", "///example.org/",
    " //example.org/", "https://app.example.com@example.org/", "javascript:alert(document.domain)",
]


@pytest.mark.parametrize("target", HOSTILE)
def test_language_switch_stays_on_site(client, target):
    response = client.get("/i18n/switch/", {"lang": "fr", "next": target}, HTTP_HOST="app.example.com")
    assert response.status_code in (301, 302, 303)
    assert response["Location"] == "/"
```

Run the same list against every route that redirects (test 1's inventory is the list of routes), and keep it in one shared fixture so new redirect endpoints get the same checks. When a framework upgrade changes encoding, these tests are what tell you.

## Practice labs

Labs are where you can follow a chain to the end (token theft, SSRF to an internal admin page), which helps you explain impact in a report. Keep the habit of proving each step with the smallest change.

**PortSwigger Web Security Academy** (free):

- [DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection): a client-side redirect fed from the URL (tests 3 and 4).
- [SSRF with filter bypass via open redirection vulnerability](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection): an allowed host's open redirect turns a restricted server-side fetch into SSRF (the chain in [Why an open redirect matters](#why-an-open-redirect-matters)).
- [Stealing OAuth access tokens via an open redirect](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect): a lax `redirect_uri` check plus a client-side open redirect leaks the token (test 9's chain).
- [OAuth account hijacking via redirect_uri](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri) and [Stealing OAuth access tokens via a proxy page](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page): the authorization-server side of the same story, for context.

**OWASP Juice Shop** ([companion guide, Unvalidated Redirects](https://pwning.owasp-juice.shop/companion-guide/latest/part2/unvalidated-redirects.html)): *Outdated Allowlist* (one star; find a destination the redirect allow-list still accepts) and *Allowlist Bypass* (four stars; get past the allow-list check, which is tests 5 to 7 in miniature).

**OWASP crAPI and VAmPI**: at the time of writing neither lists an open-redirect challenge in its published documentation. They remain useful for the SSRF and authentication flows that redirect chains feed into.

## Real-world cases

- **Prefix-matched `redirect_uri` (Bohemia Interactive, 2018).** The OAuth endpoint on `accounts.bistudio.com` only checked that `redirect_uri` started with the client's URL, so a value with extra characters appended to the hostname (the report's example joins a second domain name straight onto the client's host) passed and received the code and `state`. This is the prefix-matching weakness from test 6, at the authorization server. Rated Medium on the report; disclosed September 2018. [HackerOne report 405100](https://hackerone.com/reports/405100).
- **Arbitrary `redirect_uri` on a government login (GSA Bounty, 2019).** The reporter showed that `login.fr.cloud.gov/oauth/authorize` with `response_type=token` accepted an external `redirect_uri`, so the access token would be sent to the attacker's host after login. Rated High, with a USD 750 bounty shown on the report; disclosed October 2019. [HackerOne report 665651](https://hackerone.com/reports/665651).
- **Token theft through a signup callback (lemlist, 2025).** HackerOne's summary describes an open redirect in the email signup flow of `taplio.com`: a changed `callbackUrl` sent the victim, with their authentication tokens, to another domain after they clicked the verification link. A modern example of test 9's "what travels with it" question; the report shows Critical severity; disclosed November 2025. [HackerOne report 3419636](https://hackerone.com/reports/3419636).
- **Five small bugs into private repository access (GitHub, 2014).** Egor Homakov chained a `redirect_uri` path traversal, a token endpoint that did not re-check `redirect_uri`, a `///host` URL that Ruby's parser and the browser read differently, a Gist session that exposed the user's token and automatic scope approval for a pre-approved client. He reports a USD 4,000 reward. The parser-differential step is test 8 in practice. [Egor Homakov, "How I hacked Github again"](https://homakov.blogspot.com/2014/02/how-i-hacked-github-again.html).
- **Framework-level differential (Express, CVE-2024-29041).** Express encoded redirect targets with `encodeurl` before writing `Location`; the advisory says the resulting malformed URLs could be read differently by common allow-list validators, so input that passed an application's check redirected elsewhere. Fixed in 4.19.2 and 5.0.0-beta.3. [GitHub advisory GHSA-rv95-896h-c2vc](https://github.com/expressjs/express/security/advisories/GHSA-rv95-896h-c2vc).
- **Host validation on a parsed URL (Spring Framework, CVE-2024-22243).** Applications that parsed an externally provided URL with `UriComponentsBuilder` and then validated its host could be vulnerable to open redirect or SSRF; two follow-up advisories (CVE-2024-22259, CVE-2024-22262) covered further cases. [Spring advisory CVE-2024-22243](https://spring.io/security/cve-2024-22243).

More write-ups are collected in [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

Rate the redirect by what it **enables**, and say plainly when it enables nothing beyond the redirect. Factors that move severity: whether the redirect needs a click on a link (GET) or a cross-site form (POST) or cannot be delivered at all (header-based); whether it fires inside an authentication flow, where the user has just trusted the site with credentials; whether a code, token or session identifier travels with it; whether a `javascript:` URL executes; and whether a second control (an OAuth `redirect_uri` pattern, an SSRF allow-list, a CSP host list) trusts the host with the redirect.

**Standalone open redirects are usually Low.** Many bug bounty programmes list them as out of scope or informational unless chained, Bugcrowd's taxonomy places a GET-based open redirect at P4, and Google's Bug Hunters guidance asks for demonstrated impact beyond the redirect. The reason is that the attacker gains only credibility: they could send a link to their own site anyway. NVD and vendor advisories often score open redirects at 6.1 (`S:C/C:L/I:L`, the same vector as reflected XSS; the Express advisory in [Real-world cases](#real-world-cases) is one example); we think that overstates a redirect that runs no code, and use a lower vector below. State your reasoning in the report either way.

**Scope and UI.** Every redirect needs the victim to follow a link (`UI:R`). Scope is Unchanged for a plain redirect (nothing happens to another security authority's data; the phishing page is a separate site the attacker runs). Scope is Changed for `javascript:` execution (impact lands in the victim's browser session, as for XSS) and for SSRF chains where the impact is on internal systems behind the vulnerable server.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Open redirect, GET, ordinary page, no chain | Low | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` (4.3) | The base score falls in the Medium band, but we rate Low: the only gain is a more credible link, the attacker still needs a separate deceptive site, and programmes commonly exclude it |
| Open redirect in login or logout flow, no token leakage | Low to Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` (4.3) | Same vector; Medium where the redirect follows a real credential entry (a convincing "session expired, sign in again" phishing step) |
| Open redirect, POST-based or header-based only | Info to Low | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N` (3.1) | Delivery needs an auto-submitting form or cannot be triggered cross-site at all; P5 in Bugcrowd's taxonomy |
| Validator weakness, no reachable redirect (allows `data:`, wildcard allow-list with no vulnerable host) | Info | none | A hardening item; rate as a redirect if you show a working path |
| Client-side redirect accepting `javascript:` (DOM XSS) | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | Script runs in the application's origin; rate as XSS, higher where the page offers sensitive actions (see [DOM XSS](/web/web-dom-xss-client-side-injection/)) |
| Open redirect that forwards an OAuth code, access token or session identifier off-site | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (8.1) | One click gives the attacker the victim's session or account; use `AC:H` (6.8) if the chain needs conditions outside the attacker's control (a specific `response_mode`, a race) |
| Open redirect on an allowed host that turns a server-side fetch into SSRF to internal services | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` (8.6) | Rate as the SSRF: the redirect is a step; the finding is the SSRF and its reach. Proven in the SSRF tests, not here |
| Open redirect that widens a CSP path restriction | Low to Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` (4.3) | Only matters with an injection the CSP was stopping; rate with that injection and the CSP finding (see [CSP and headers](/web/web-content-security-policy-headers/)) |
| Signed out-link wrapper accepts missing or reused signatures | Low | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` (4.3) | An open redirect on a host users are told to trust in emails |
| No interstitial for off-site navigation (L3 target) | Info to Low | none | ASVS `v5.0.0-3.7.3` gap; only relevant where the client targets L3 |

When you report, give: the endpoint, the parameter and how it is carried (query, body, fragment), the exact input and the `Location` value or sink assignment, which browsers followed it, the variants that were blocked (tests 5 to 7), and any chain you confirmed or only identified. State that the proof redirected to `https://example.org/` and that no tokens left the test environment.

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 |
|---|---|---|---|---|
| GT-WEB-REDIR-1 | WSTG-CLNT-04, WSTG-INFO-06, WSTG-ATHN-12, WSTG-SESS-06 | v5.0.0-3.7.2 (context) | CWE-601 (context) | A01:2025 |
| GT-WEB-REDIR-2 | WSTG-CLNT-04, WSTG-ATHN-12, WSTG-SESS-06 | v5.0.0-3.7.2, v5.0.0-3.7.3 | CWE-601 | A01:2025 |
| GT-WEB-REDIR-3 | WSTG-CLNT-04, WSTG-CLNT-01 | v5.0.0-3.7.2 | CWE-601 | A01:2025 |
| GT-WEB-REDIR-4 | WSTG-CLNT-04, WSTG-CLNT-01 | v5.0.0-1.2.2 | CWE-79, CWE-601 | A05:2025 when script runs; A01:2025 otherwise |
| GT-WEB-REDIR-5 | WSTG-CLNT-04 | v5.0.0-3.7.2, v5.0.0-2.2.1 | CWE-601 | A01:2025 |
| GT-WEB-REDIR-6 | WSTG-CLNT-04, WSTG-ATHZ-05 (redirect URI validation) | v5.0.0-3.7.2, v5.0.0-10.4.1 (authorization server context) | CWE-601 | A01:2025 |
| GT-WEB-REDIR-7 | WSTG-CLNT-04, WSTG-INJT-15 (if CRLF) | v5.0.0-1.1.1, v5.0.0-3.7.2 | CWE-601; CWE-113 if headers split | A01:2025; A05:2025 for CRLF |
| GT-WEB-REDIR-8 | WSTG-CLNT-04 | v5.0.0-3.7.2, v5.0.0-1.1.1 | CWE-601 | A01:2025 |
| GT-WEB-REDIR-9 | WSTG-CLNT-04, WSTG-ATHN-12, WSTG-SESS-06, WSTG-ATHZ-05 | v5.0.0-3.7.2, v5.0.0-3.4.5, v5.0.0-10.4.1 | CWE-601 | A01:2025 |
| GT-WEB-REDIR-10 | WSTG-CLNT-04 | v5.0.0-3.7.2, v5.0.0-3.7.3 | CWE-601 | A01:2025 |

ASVS levels: `v5.0.0-3.7.2` L2 (automatic redirects to hosts outside the application's control only to allow-listed destinations), `v5.0.0-3.7.3` L3 (notify the user, with an option to cancel, before navigating outside the application's control), `v5.0.0-1.2.2` L1 (context encoding when building URLs, and only safe URL protocols, with `javascript:` and `data:` named), `v5.0.0-1.1.1` L2 (decode once, before validation), `v5.0.0-2.2.1` L1 (positive validation against allow-lists), `v5.0.0-3.4.5` L2 (a referrer policy that stops technically sensitive data leaking to third parties), `v5.0.0-10.4.1` L1 (authorization servers compare redirect URIs against a per-client allow-list using exact string comparison), `v5.0.0-15.3.2` L2 (back-ends do not follow redirects unless intended; relevant to the SSRF chain). CWE choice: CWE-601 (*URL Redirection to Untrusted Site ('Open Redirect')*) for every redirect finding; CWE-79 when a `javascript:` URL executes; CWE-113 (*Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')*) when an encoded line break splits the `Location` header. `A01:2025` is Broken Access Control in the OWASP Top 10:2025, whose mapped CWEs include CWE-601 (and CWE-918, SSRF, for the chain). The OWASP API Security Top 10 2023 has no redirect category; SSRF chains through an API map to `API7:2023` in the SSRF notes.

## References

**OWASP**

- WSTG: [Client-side URL Redirect (WSTG-CLNT-04)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/04-Client-side_URL_Redirect), [DOM-Based Cross Site Scripting (WSTG-CLNT-01)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/01-DOM-based_Cross_Site_Scripting), [SAML Authentication (WSTG-ATHN-12)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/04-Authentication/12-SAML_Authentication), [OAuth Weaknesses (WSTG-ATHZ-05)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/05-OAuth_Weaknesses) with its [Authorization Server](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/05.1-OAuth_Authorization_Server_Weaknesses) and [Client](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/05.2-OAuth_Client_Weaknesses) sub-pages, [Logout Functionality (WSTG-SESS-06)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/06-Session_Management/06-Logout_Functionality), [Identify Application Entry Points (WSTG-INFO-06)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points), [HTTP Response Splitting (WSTG-INJT-15)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/15-HTTP_Response_Splitting), [Host Header Injection (WSTG-INJT-17)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/17-Host_Header_Injection), [Server-Side Request Forgery (WSTG-INJT-19)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/19-Server-Side_Request_Forgery)
- ASVS 5.0: [V3 Web Frontend Security](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md), [V1 Encoding and Sanitization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md), [V10 OAuth and OIDC](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x19-V10-OAuth-and-OIDC.md), [V15 Secure Coding and Architecture](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md)
- [A01:2025 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/)
- Cheat Sheets: [Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)

**CWE**

- [CWE-601](https://cwe.mitre.org/data/definitions/601.html), [CWE-79](https://cwe.mitre.org/data/definitions/79.html)

**Standards**

- [WHATWG URL Standard](https://url.spec.whatwg.org/) (basic URL parser: whitespace, tab and newline removal, backslashes in special URLs)
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) (URI generic syntax, relative references), [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) (section 10.2.2, `Location` and fragment inheritance)
- [WHATWG Fetch Standard](https://fetch.spec.whatwg.org/) (HTTP-redirect fetch: non-HTTP(S) redirect targets are a network error)
- [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/) (section 7.6, Paths and Redirects)
- [RFC 9700, OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700) (section 4.11, Open Redirection)

**PortSwigger**

- [DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection), [OAuth 2.0 authentication vulnerabilities](https://portswigger.net/web-security/oauth), [Server-side request forgery](https://portswigger.net/web-security/ssrf), [URL validation bypass cheat sheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet), [Cross-site scripting cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- Burp issue definitions: [Open redirection (reflected)](https://portswigger.net/kb/issues/00500100_open-redirection-reflected), [Open redirection (stored)](https://portswigger.net/kb/issues/00500101_open-redirection-stored); [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)

**Research**

- Orange Tsai, [A New Era of SSRF: Exploiting URL Parser in Trending Programming Languages](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) (Black Hat USA 2017, slides)
- Claroty Team82 and Snyk, [Exploiting URL Parsing Confusion](https://claroty.com/team82/research/exploiting-url-parsing-confusion) (2022)
- Egor Homakov, [How I hacked Github again](https://homakov.blogspot.com/2014/02/how-i-hacked-github-again.html) (2014)
- Programme policies: [Bugcrowd Vulnerability Rating Taxonomy](https://github.com/bugcrowd/vulnerability-rating-taxonomy), [Google Bug Hunters: Open redirectors](https://bughunters.google.com/learn/invalid-reports/navigation/6680364896223232)

**Framework documentation and source**

- Express: [API reference (`res.redirect`, `res.location`)](https://expressjs.com/en/api.html), [Migrating to Express 5](https://expressjs.com/en/guide/migrating-5.html), [GHSA-rv95-896h-c2vc (CVE-2024-29041)](https://github.com/expressjs/express/security/advisories/GHSA-rv95-896h-c2vc); MDN [`URL()` constructor](https://developer.mozilla.org/en-US/docs/Web/API/URL/URL)
- Django: [Using the authentication system (`LoginView`, `LogoutView`)](https://docs.djangoproject.com/en/stable/topics/auth/default/), [Django 3.0 release notes](https://docs.djangoproject.com/en/stable/releases/3.0/) (`url_has_allowed_host_and_scheme()`), [`django/utils/http.py`](https://github.com/django/django/blob/main/django/utils/http.py), [security archive](https://docs.djangoproject.com/en/dev/releases/security/)
- Spring: [Spring Security architecture (saved requests, `RequestCache`)](https://docs.spring.io/spring-security/reference/servlet/architecture.html), [Form login](https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/form.html), [`DefaultRedirectStrategy` API](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/DefaultRedirectStrategy.html) and [source](https://github.com/spring-projects/spring-security/blob/main/web/src/main/java/org/springframework/security/web/DefaultRedirectStrategy.java); advisories [CVE-2024-22243](https://spring.io/security/cve-2024-22243), [CVE-2024-22259](https://spring.io/security/cve-2024-22259), [CVE-2024-22262](https://spring.io/security/cve-2024-22262)
- Laravel: [HTTP Responses (redirects, `away()`)](https://laravel.com/docs/13.x/responses), [Authentication (`intended()`)](https://laravel.com/docs/13.x/authentication), [URL Generation (signed URLs)](https://laravel.com/docs/13.x/urls), [`Redirector` source](https://github.com/laravel/framework/blob/13.x/src/Illuminate/Routing/Redirector.php)

**Tools**

- Static analysis: [CodeQL js/server-side-unvalidated-url-redirection](https://codeql.github.com/codeql-query-help/javascript/js-server-side-unvalidated-url-redirection/), [js/client-side-unvalidated-url-redirection](https://codeql.github.com/codeql-query-help/javascript/js-client-side-unvalidated-url-redirection/), [py/url-redirection](https://codeql.github.com/codeql-query-help/python/py-url-redirection/), [java/unvalidated-url-redirection](https://codeql.github.com/codeql-query-help/java/java-unvalidated-url-redirection/)
- Burp extension: [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943)
- Labs: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)
