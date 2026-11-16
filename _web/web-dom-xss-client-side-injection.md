---
title: "DOM XSS and Client-Side Injection"
date: 2026-11-15 22:02:00 +0000
subcategory: client-side
summary: "Finding DOM XSS safely: sources and sinks, javascript: URLs, resource manipulation, AngularJS template injection, pollution gadgets and Trusted Types."
refs: [WSTG-CLNT-01, WSTG-CLNT-02, WSTG-CLNT-06, WSTG-CLNT-15, WSTG-INJT-22, v5.0.0-3.2.2, v5.0.0-1.2.1, v5.0.0-1.2.2, v5.0.0-1.2.3, v5.0.0-1.3.1, v5.0.0-1.3.2, v5.0.0-1.3.7, v5.0.0-3.4.3, v5.0.0-15.2.1, v5.0.0-15.3.6, "A05:2025", "A03:2025", CWE-79, CWE-95, CWE-1336, CWE-1321, CWE-829, CWE-1104]
tags: [web, xss, dom-xss, client-side, javascript, trusted-types]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Client-Side](/web/web-client-side-testing-guide/). It covers DOM-based cross-site scripting and its close relatives: JavaScript running in the browser reads a value the attacker controls (a *source*, such as the URL fragment) and hands it to an API that parses it as HTML, runs it as code or loads it as a resource (a *sink*). The server may never see the payload, so server-side filters, WAFs and response scanners often miss the bug completely. WSTG tests it as `WSTG-CLNT-01` (DOM-based XSS, with a sub-page on self DOM XSS), `WSTG-CLNT-02` (JavaScript execution), `WSTG-CLNT-06` (client-side resource manipulation) and `WSTG-CLNT-15` (client-side template injection); the client-side half of prototype pollution sits in `WSTG-INJT-22`. You get the model (sources, sinks and the taint path between them, and what React, Angular and Vue change), the patterns that keep producing findings, twelve tests that stop at a harmless marker (`alert(document.domain)`, `print()`, a `console.log` line or a visible `GT-DOM-<n>` string), a DOM Invader workflow, static review of bundles, and fixes built on safe DOM APIs, URL scheme checks, DOMPurify and Trusted Types. Server-reflected and stored XSS, output contexts and blind XSS are in [Reflected and stored XSS](/web/web-reflected-stored-xss/); message-driven DOM XSS is in [postMessage and web messaging](/web/web-postmessage-web-messaging/); scriptless injection and DOM clobbering are in [DOM clobbering and CSS injection](/web/web-dom-clobbering-css-injection/); and CSP design is in [Content Security Policy and security headers](/web/web-content-security-policy-headers/).

## Contents

- [How it works](#how-it-works)
  - [Sources, sinks and the taint path](#sources-sinks-and-the-taint-path)
  - [Which sources an attacker controls](#which-sources-an-attacker-controls)
  - [Sink families](#sink-families)
  - [What frameworks change](#what-frameworks-change)
  - [How DOM XSS differs from reflected and stored XSS](#how-dom-xss-differs-from-reflected-and-stored-xss)
- [What goes wrong](#what-goes-wrong)
  - [HTML built from strings](#html-built-from-strings)
  - [Strings turned into code](#strings-turned-into-code)
  - [URLs that are not checked for their scheme](#urls-that-are-not-checked-for-their-scheme)
  - [Resource URLs taken from the page address](#resource-urls-taken-from-the-page-address)
  - [jQuery selector and HTML sinks](#jquery-selector-and-html-sinks)
  - [Framework escape hatches](#framework-escape-hatches)
  - [Client-side template injection](#client-side-template-injection)
  - [Prototype pollution feeding a gadget](#prototype-pollution-feeding-a-gadget)
  - [Sanitising, then breaking it](#sanitising-then-breaking-it)
  - [Outdated client-side libraries](#outdated-client-side-libraries)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [Signals and false positives](#signals-and-false-positives)
  - [GT-WEB-DOM-1: Inventory client-side code, frameworks and library versions](#gt-web-dom-1-inventory-client-side-code-frameworks-and-library-versions)
  - [GT-WEB-DOM-2: Trace URL sources into HTML sinks with a canary](#gt-web-dom-2-trace-url-sources-into-html-sinks-with-a-canary)
  - [GT-WEB-DOM-3: Sweep sources and sinks with DOM Invader](#gt-web-dom-3-sweep-sources-and-sinks-with-dom-invader)
  - [GT-WEB-DOM-4: Referrer, window name, storage, cookies and API data as sources](#gt-web-dom-4-referrer-window-name-storage-cookies-and-api-data-as-sources)
  - [GT-WEB-DOM-5: JavaScript execution sinks](#gt-web-dom-5-javascript-execution-sinks)
  - [GT-WEB-DOM-6: Navigation and URL attribute sinks with javascript URLs](#gt-web-dom-6-navigation-and-url-attribute-sinks-with-javascript-urls)
  - [GT-WEB-DOM-7: Client-side resource manipulation](#gt-web-dom-7-client-side-resource-manipulation)
  - [GT-WEB-DOM-8: jQuery sinks and jQuery version checks](#gt-web-dom-8-jquery-sinks-and-jquery-version-checks)
  - [GT-WEB-DOM-9: Framework escape hatches in React, Angular and Vue](#gt-web-dom-9-framework-escape-hatches-in-react-angular-and-vue)
  - [GT-WEB-DOM-10: Client-side template injection in AngularJS and Vue](#gt-web-dom-10-client-side-template-injection-in-angularjs-and-vue)
  - [GT-WEB-DOM-11: Client-side prototype pollution as a DOM XSS source](#gt-web-dom-11-client-side-prototype-pollution-as-a-dom-xss-source)
  - [GT-WEB-DOM-12: Static review of bundles and Trusted Types sink discovery](#gt-web-dom-12-static-review-of-bundles-and-trusted-types-sink-discovery)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Text instead of HTML](#text-instead-of-html)
  - [URLs and navigation](#urls-and-navigation)
  - [Rendering HTML safely with DOMPurify and the Sanitizer API](#rendering-html-safely-with-dompurify-and-the-sanitizer-api)
  - [Trusted Types](#trusted-types)
  - [No strings to code](#no-strings-to-code)
  - [Loading scripts and frames](#loading-scripts-and-frames)
  - [React](#react)
  - [Angular](#angular)
  - [Vue](#vue)
  - [Legacy AngularJS and jQuery](#legacy-angularjs-and-jquery)
  - [Prototype-safe client code](#prototype-safe-client-code)
  - [Headers from Express, Django, Spring and Laravel](#headers-from-express-django-spring-and-laravel)
  - [Lint rules and static analysis](#lint-rules-and-static-analysis)
  - [Regression tests with a headless browser](#regression-tests-with-a-headless-browser)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Sources, sinks and the taint path

DOM XSS needs three things: a **source** whose value an attacker can influence, a **sink** that interprets a string as markup, code or a URL to execute or load, and a **path** between them that does not neutralise the value for that sink. A typical single-page application has hundreds of sources and sinks; the bug is the one path where the two meet without the right encoding or validation in between.

```javascript
// Illustrative vulnerable code on https://app.example.com/search
const params = new URLSearchParams(location.search);       // source
const term = params.get("q");
document.getElementById("heading").innerHTML =             // sink
  "Results for " + term;                                   // no encoding on the path
```

The browser decodes the query string, the script concatenates it into an HTML string, and `innerHTML` parses that string as markup. If `q` contains an element with an event handler, the handler runs in the page's origin. Swap `innerHTML` for `textContent` and the same value is shown as text: same source, same path, a different sink, no vulnerability. That is why this note is organised around sinks: each one has its own "safe" and "unsafe" input.

Three properties of the path decide exploitability:

- **Encoding the browser applies to the source.** Current Chrome, Firefox and Safari return `location.search` and `location.hash` percent-encoded for some characters, so a payload read without decoding may arrive harmless. Code that calls `decodeURIComponent()`, `URLSearchParams.get()` or a router's parameter parser decodes it again, which is the usual way an exploitable path appears. PortSwigger's DOM XSS page notes that pre-Chromium Edge and IE11 did not encode these sources at all.
- **Transformations on the way.** Splitting, `replace()`, `JSON.parse()`, routers and template helpers can remove, add or re-encode characters. A path that escapes `<` but not `"` is still exploitable when the sink is an attribute.
- **Timing.** Some sinks run only on an event: a `hashchange` handler, a click, a mouseover, an `IntersectionObserver` callback. Tools that load the page once and look for an alert miss these.

### Which sources an attacker controls

| Source | How an attacker sets it | Notes |
|---|---|---|
| `location.search`, `URLSearchParams` | A link the victim opens | Sent to the server too, so it also appears in logs and may be reflected server-side |
| `location.hash` | A link; can be changed later without reloading (fires `hashchange`) | Never sent to the server, so server-side controls cannot see it |
| `location.pathname`, `document.URL`, `document.documentURI`, `document.baseURI` | A link to a path the router accepts | Catch-all routes and 404 pages that echo the path are common |
| `document.referrer` | The page the victim came from | Attacker controls it when they own the linking page; limited by `Referrer-Policy` |
| `window.name` | Set by the page that opens or frames the target; survives navigation | Classic cross-origin carrier; current browsers clear it on cross-site top-level navigations in some cases, so test rather than assume |
| `postMessage` data | Any window that holds a reference to the target | Covered in [postMessage and web messaging](/web/web-postmessage-web-messaging/) |
| `localStorage`, `sessionStorage`, IndexedDB | Anything that wrote there earlier: another feature, another XSS, a shared subdomain origin | Turns a one-off injection into a persistent one; see [browser storage and third-party scripts](/web/web-browser-storage-third-party-scripts/) |
| `document.cookie` | A sibling subdomain that can set cookies for the parent domain, a CRLF bug, or the application itself | Cookie values are often trusted as if they were server-issued |
| API responses and server-rendered data | A user who stored the value earlier (profile fields, comments, file names) | Stored DOM XSS: the server returns JSON safely, the client renders it unsafely |
| Form fields and pasted content | The victim types or pastes it | Only "self" XSS unless something else fills the field (WSTG-CLNT-01.1) |

### Sink families

| Family | Examples | What makes input dangerous |
|---|---|---|
| HTML parsing | `innerHTML`, `outerHTML`, `insertAdjacentHTML()`, `document.write()`, `document.writeln()`, `DOMParser.parseFromString()` followed by insertion, `Range.createContextualFragment()`, `iframe.srcdoc`, `setHTMLUnsafe()` | Markup with event-handler attributes or script-bearing elements. `innerHTML` does not run inserted `script` elements, but event handlers on other elements fire; `document.write()` does run scripts |
| JavaScript execution | `eval()`, `Function()`, `setTimeout()` and `setInterval()` with a string, `script.text` / `textContent` on a script element, `new Worker()` with a blob built from input | Any input that is not a fixed literal |
| URL and navigation | `location = …`, `location.href`, `location.assign()`, `location.replace()`, `window.open()`, `a.href`, `form.action`, `button.formAction`, `iframe.src` | A `javascript:` URL runs code in the page's origin when navigated to; any other scheme or host makes it an open redirect |
| Resource loading | `script.src`, dynamic `import()`, `iframe.src`, `link.href` (stylesheets), `object.data`, `fetch()` / `XMLHttpRequest` URLs whose response is then written to an HTML sink | Attacker-chosen origin supplies code or markup |
| Library and framework sinks | jQuery `html()`, `append()`, `prepend()`, `after()`, `before()`, `replaceWith()`, `wrap()`, `$()` with a string, `$.parseHTML()`; React `dangerouslySetInnerHTML`; Angular `bypassSecurityTrust…` plus `[innerHTML]`; Vue `v-html`; AngularJS `ng-bind-html` with `$sce.trustAsHtml()` and template compilation | Each wraps one of the families above, often with different rules |

The MDN Trusted Types page groups browser sinks the same way (HTML sinks, JavaScript sinks and script-URL sinks) and lists every API that enforces a type check, which makes it a useful checklist when you review a bundle.

### What frameworks change

React, Angular and Vue escape interpolated values by default: text bound into a template is set as text, and attribute bindings are set as properties. That removes most HTML-sink bugs from ordinary components. What remains:

- **Explicit escape hatches.** React's `dangerouslySetInnerHTML` prop, Angular's `DomSanitizer.bypassSecurityTrustHtml()` (and its `Script`, `Style`, `Url` and `ResourceUrl` siblings), Vue's `v-html` and render-function `innerHTML`. They exist to render HTML, and they are where a sanitiser either is or is not called.
- **Direct DOM access.** A React ref, an Angular `ElementRef.nativeElement` or a Vue template ref gives the component a real DOM node; writing `innerHTML` to it bypasses everything the framework does. Angular's security guide says this explicitly.
- **URL attributes.** Angular sanitises URLs bound to `href` and `src`. React's current source (the `sanitizeURL` helper) replaces `javascript:` URLs in the attributes it handles with a URL that only throws, while older React versions only warned in development; Vue documents that it does not sanitise `:href` bindings at all. Navigation done in code (`location.href = value`, `window.open(value)`, `router.push(value)` to an external URL) is never covered by template escaping.
- **Templates compiled at run time.** AngularJS compiles the live DOM, so any text inside an `ng-app` element that contains expression delimiters is evaluated, including text the server reflected safely as HTML. Vue does the same when it is mounted on existing server-rendered markup or when the full build with the run-time compiler is shipped. Angular (2+) with the default ahead-of-time compiler does not compile templates at run time.
- **Third-party components.** Rich-text editors, Markdown renderers, chart tooltips, toast and modal libraries often render HTML strings internally. Their options (`html: true`, `allowHTML`, `sanitize: false`) are sinks too.

### How DOM XSS differs from reflected and stored XSS

The impact is identical: script running in the victim's session on the vulnerable origin, able to read what the page can read and act as the user. What differs is where the bug is and how you prove it:

| | Reflected / stored XSS | DOM XSS |
|---|---|---|
| Where the unsafe write happens | Server builds the HTML response | Client script writes to the DOM |
| Visible in the raw HTTP response | Yes | Often not; "view source" shows the original page, not the modified DOM |
| Server-side defences that help | Output encoding, WAF (partially) | Only CSP and headers; payloads in the fragment never reach the server |
| Where to look | Templates and controllers | Bundles, inline scripts, third-party scripts, framework escape hatches |
| How to prove | Request/response pair | Browser session: URL, DOM state, console, stack trace to the sink |

Hybrids are common. In *reflected DOM XSS* the server reflects a value safely into a data attribute or JSON block, and a script then moves it into a sink. In *stored DOM XSS* an API returns stored data as JSON and the client renders it with `innerHTML`. Both are DOM XSS for remediation purposes: the fix is in the client code.

## What goes wrong

### HTML built from strings

The most common root cause: a developer wants bold text, a link or a list item, builds it with string concatenation or a template literal, and assigns it to `innerHTML` or passes it to `insertAdjacentHTML()`. Search results headings ("Results for …"), breadcrumb trails built from the path, "welcome back" banners using a name from storage, notification toasts and error messages that echo a parameter are the places to look. A related pattern is the "strip tags" helper that assigns input to `innerHTML` of a detached `div` and reads back `textContent`: the parsing step alone fires event handlers on an `img` element, even though the element is never attached to the page. WSTG's self DOM XSS example is exactly this helper.

**Why it matters:** any markup the attacker controls can carry an event handler, which runs in the application's origin with the user's session.

### Strings turned into code

`eval()` on a fragment value "to parse JSON", `new Function()` to build a formatter, `setTimeout("doThing('" + name + "')", 0)`, and analytics snippets that execute a callback name taken from the URL. WSTG-CLNT-02's example reads `location.hash` and passes it to `eval()`. These sinks need no markup at all, so HTML encoding on the path does not help; a single quote or a closing parenthesis is enough to break out of the intended string.

**Why it matters:** direct code execution, no browser parsing quirks required. ASVS `v5.0.0-1.3.2` (L1) asks you to avoid `eval()` and similar dynamic code execution altogether.

### URLs that are not checked for their scheme

A "return to" or "next" parameter is copied into `location.href`, into an anchor's `href` or into `window.open()`. If the value is `javascript:` followed by code, navigating to it runs that code in the page's origin; if it is any external URL, it is an open redirect (see [open redirects](/web/web-open-redirect/)). Filters that check for `http` at the start, search for the substring `javascript`, or use a regular expression without anchoring are frequently incomplete, because the URL parser ignores leading control characters and strips tabs and newlines inside the scheme. Checking the scheme with the browser's own `URL` parser avoids that class of mistake. ASVS `v5.0.0-1.2.2` (L1) asks that only safe URL protocols be permitted when URLs are built from untrusted data.

**Why it matters:** `javascript:` navigation is full XSS; anything else is still a redirect or phishing aid.

### Resource URLs taken from the page address

WSTG-CLNT-06 covers code that sets `script.src`, `iframe.src` or the URL of an `XMLHttpRequest` from `location.hash` or a parameter: "load the widget named in the fragment", "embed the help page given in `?doc=`", "fetch the partial whose path is in the hash and insert it". If the value can point to another origin, the attacker chooses the code or markup. Even when only same-origin paths are accepted, a user-upload area, a JSONP endpoint or an open redirect on the same origin can turn a path into attacker-controlled content.

**Why it matters:** a script loaded from an attacker's origin runs with the full privileges of the page; an attacker-chosen frame can spoof content inside a trusted page.

### jQuery selector and HTML sinks

`$(location.hash)` was the classic DOM XSS of the 2010s: jQuery's `$()` accepts both selectors and HTML, and before 1.9.0 it treated any string containing `<` as HTML (CVE-2012-6708). Since 1.9.0 a string is only HTML when it starts with `<`, and a fragment always starts with `#`, so that specific pattern was closed, but PortSwigger notes that `$()` is still a sink whenever the input does not need a `#` prefix. `html()`, `append()` and the other manipulation methods parse HTML by design. Before 3.5.0, these methods could execute code from HTML that had already been sanitised (CVE-2020-11022, and CVE-2020-11023 for `option` elements). `$.extend(true, …)` before 3.4.0 allowed prototype pollution (CVE-2019-11358), and cross-domain `$.ajax` without `dataType` executed `text/javascript` responses before 3.0.0 (CVE-2015-9251).

**Why it matters:** jQuery is still everywhere in content management systems, admin panels and marketing pages, often in old versions bundled by plugins.

### Framework escape hatches

The React, Angular and Vue escape hatches are legitimate when the HTML comes from a trusted build-time source or passes through a well-configured sanitiser. Findings arise when:

- the prop or directive receives a field from an API response that a user can edit (comments, bios, product descriptions, CMS blocks), with no sanitiser in between;
- a sanitiser is called, but with a configuration that re-enables dangerous elements or attributes, or on a different value from the one rendered;
- `bypassSecurityTrustHtml()` or `bypassSecurityTrustResourceUrl()` is called on a value built from route parameters "because Angular was stripping things";
- code obtains a DOM node through a ref and writes `innerHTML`, `outerHTML` or `insertAdjacentHTML()` directly.

**Why it matters:** these are the places where a framework-based application is as exposed as hand-written DOM code, and they are easy to find by name.

### Client-side template injection

AngularJS (1.x) compiles everything inside the element that carries `ng-app`. If the server places user input inside that element, even correctly HTML-encoded, AngularJS evaluates any expression delimiters in it. Angle brackets are not needed, so output encoding and many WAF rules do not help. AngularJS had an expression sandbox, never intended as a security boundary, which researchers bypassed repeatedly; it was removed in 1.6, so in 1.6 and later any expression injection is script execution. AngularJS support ended in January 2022 (the project's repository says so on its front page), so an AngularJS application is also a component finding. Vue has the same class of issue when it is mounted on a server-rendered element that contains user input, or when user input becomes a template string compiled at run time. ASVS `v5.0.0-1.3.7` (L2) asks that templates are never built from untrusted input.

**Why it matters:** XSS through a channel that bypasses HTML encoding, on pages whose server-side code is otherwise correct.

### Prototype pollution feeding a gadget

A client-side query-string or hash parser that builds nested objects (`?a[b]=c`) with an unsafe merge lets a key such as `__proto__` write to `Object.prototype`. Nothing visible happens until other code reads a property it never set: a library that builds an element from an options object, a sanitiser configuration that falls back to a default, a script loader that reads `src` from a config object. That property is the *gadget*, and if it ends in an HTML, code or script-URL sink, the pollution becomes DOM XSS. The same root cause on the server is covered in [server-side prototype pollution](/web/web-server-side-prototype-pollution/). ASVS `v5.0.0-15.3.6` (L2) asks for JavaScript written to prevent prototype pollution.

**Why it matters:** the injection point and the sink are in unrelated code, often in two different third-party libraries, so neither code review of one file nor a scanner looking for reflection finds it.

### Sanitising, then breaking it

DOMPurify and the framework sanitisers are reliable when the sanitised output goes straight into the sink. They fail when the output is modified afterwards (string replacements, a second "formatting" step, decoding entities), when it is parsed in a different context from the one it was sanitised for (sanitised as HTML, inserted into an SVG or a `textarea` re-parse), when hooks or configuration re-allow risky attributes, or when the library is out of date. DOMPurify has shipped fixes for mutation-XSS bypasses over the years; treat its version as a component check and do not attempt to rediscover bypasses on a client engagement.

**Why it matters:** "we use DOMPurify" is a statement about one call site, not the application.

### Outdated client-side libraries

Old jQuery, AngularJS, Bootstrap's tooltip and popover components, Handlebars, Lodash and DOMPurify versions with published XSS or pollution advisories are frequently present in bundles. A vulnerable version is a component finding by itself (ASVS `v5.0.0-15.2.1`, L1; `A03:2025` Software Supply Chain Failures, CWE-1395 or CWE-1104 for unmaintained components). It becomes an XSS finding only when you show that the vulnerable function is reachable with attacker-controlled input.

## Testing

Everything below assumes an **authorised** engagement with written scope and rules of engagement, a bug bounty programme whose rules allow client-side testing, or a deliberately vulnerable lab. Code, URLs and console output in this note are **illustrative**: hosts are fictional and outputs are shortened.

### Before you start

**Scope and accounts.** Agree the in-scope origins (including subdomains that serve static assets or embedded widgets), whether third-party scripts loaded by the application are in scope for review (usually: you may report how the application uses them, not test the vendor's own servers), and which environment you will use for stored payloads. You need at least two test accounts of your own (user A plays the attacker, user B the victim), plus a privileged role if the client provides one, so that a stored or shared DOM XSS can be proven from A to B without touching real users.

**Browser set-up.**

- **Burp's embedded browser with DOM Invader.** Open it from **Proxy > Intercept**, click the Burp Suite logo in the browser toolbar (behind the jigsaw icon if it is hidden), switch DOM Invader on and click **Reload**. Then open DevTools (right-click, **Inspect**) and select the **DOM Invader** tab. PortSwigger's documentation lists DOM Invader for both Professional and Community editions. It is off by default because instrumentation can change site behaviour; enable prototype pollution and postMessage interception only when you need them.
- **Set your own canary.** In the DOM Invader settings, replace the random canary with a project marker such as `gtdom7q3k` (alphanumeric, not present on the site) and click **Update canary**, then **Reload**. A fixed marker makes screenshots and notes consistent.
- **DevTools habits.** Use the **Elements** panel (not "view source") to see the live DOM; global search across all loaded scripts (Ctrl+Shift+F, or Cmd+Option+F on macOS) to find where a source is read; **Pretty print** for minified files; breakpoints on DOM subtree modifications and on event listeners (such as `hashchange`) from the **Sources** panel; and the **Console** to read values and stack traces. Keep "Preserve log" on so a redirect does not clear the evidence.
- **A clean profile.** Run tests in a browser profile used only for this engagement, signed in only to test accounts. Do not disable CSP in the browser for proof: record what the real policy does (see [Signals and false positives](#signals-and-false-positives)).

**Marker payloads only.** Every proof in this note uses one of: the canary itself, an inert tag carrying a visible marker (`GT-DOM-<n>`), `alert(document.domain)`, `print()` or `console.log('GT-DOM-<n>')`. `document.domain` in the alert proves which origin ran the code, which is the question that matters. Never use payloads that read or send cookies, tokens, storage or page content, load external hook frameworks, act as the user, or spread. Describe impact (session riding, account takeover through an email change without re-authentication, reading data the page can read) in the report, with references, rather than demonstrating it.

**Escalation ladder.** For each candidate path, go one step at a time and stop at the first step that proves the point:

1. Canary reaches the sink (DOM Invader or DevTools shows it).
2. Context characters survive (`<`, `"`, `'`, `` ` ``, `)` appended to the canary appear unencoded in the sink).
3. Inert markup renders: an element such as `<b>GT-DOM-2</b>` appears as bold text (HTML injection, `WSTG-CLNT-03`).
4. A marker executes: `alert(document.domain)` or `print()` fires, or `console.log` prints the marker.

**Stored payloads.** If a source is stored data (profile field, comment, file name, saved filter), store markers only in objects that only your test accounts can see, or in staging. Keep a list of every object you changed, and remove each payload at the end of testing (restore the original value). If the stored field is rendered in a back-office tool you cannot see, that is blind XSS: it needs the client's written approval and the limited callback described in [Reflected and stored XSS](/web/web-reflected-stored-xss/).

**Rate limits.** DOM testing is mostly local, but some steps generate server traffic: DOM Invader's **Inject URL params** opens a new tab per parameter, crawlers load every page, and Burp Scanner's DOM analysis requests resources. Keep crawls scoped, one or two requests per second unless the rules say otherwise, and never run an active scan against stored-data endpoints in production.

**Stop rules.** Stop and contact the client if any test shows another user's data (for example, a stored-DOM path renders a real customer's content), if a marker fires anywhere you did not put it, or if a stored marker becomes visible to real users. Keep only minimum redacted evidence and report immediately.

### Signals and false positives

| Observation | What it means | What to do |
|---|---|---|
| Canary in the sink, but `<` and `"` arrive as `%3C`, `&lt;` or `<` | The path encodes for this sink | Not exploitable as XSS through this path; note it only if another browser behaves differently, and check the other characters (an attribute sink may still break on a quote) |
| Canary in `innerHTML`, markup renders, but the event handler does not run | A sanitiser (DOMPurify, a framework sanitiser) removed it, or CSP blocked it | Read the console: a CSP violation message means the injection is real and the policy stopped it. A clean console with stripped attributes means sanitisation worked |
| Console shows "This document requires 'TrustedHTML' assignment" or a similar Trusted Types error | Trusted Types enforcement blocked a string at the sink | The source-to-sink path still exists; report it as a finding mitigated by Trusted Types and check whether a `default` policy or another policy can be reached (test 12) |
| `alert` fires only with CSP disabled in your browser | The injection exists; the deployed CSP prevents execution | A finding, rated lower; it becomes exploitable the day CSP is relaxed, on an endpoint without CSP, or through a CSP bypass. Say so in the report |
| Marker executes only when you type or paste it | Self DOM XSS (WSTG-CLNT-01.1) | Low or informational unless another source (URL, stored data, a message) can fill the same field |
| Payload fires in DevTools Console | You ran it yourself | Not evidence. Only execution triggered by the application counts |
| Alert from a browser extension or Burp's own instrumentation | Tooling noise | Reproduce in a clean profile with DOM Invader off |
| Canary appears in a sink only from a parameter the server rejects or that the page never reads in normal use | Dead code or a test harness | Confirm that a normal user's link can carry the value |

### GT-WEB-DOM-1: Inventory client-side code, frameworks and library versions

*Guler Tech methodology.* Implements the identification steps of WSTG-CLNT-01 (crawl to find where JavaScript runs and where input is accepted) and the framework-identification step of WSTG-CLNT-15.

#### What it checks

Which scripts the application loads, which frameworks and libraries (with versions) are present, whether source maps are exposed, and whether known-vulnerable client-side components are in use. The output is the work list for every later test.

#### Prerequisites

Burp's browser; a walk-through of every feature as user A; read access to the client's repository if this is a grey-box test.

#### Steps

1. Walk every feature with Burp Logger on. Filter the HTTP history by MIME type *script* and list every script URL, including inline scripts (they appear in HTML responses) and third-party origins.
2. Identify frameworks in the page and the console. Read-only expressions such as these print versions without changing state:

   ```javascript
   // Run in the DevTools console on a page of the application
   window.jQuery && jQuery.fn.jquery;          // e.g. "1.12.4"
   window.angular && angular.version.full;     // AngularJS 1.x, e.g. "1.5.8"
   window.Vue && Vue.version;                  // Vue exposed globally, e.g. "2.6.14"
   window.DOMPurify && DOMPurify.version;      // e.g. "2.0.8"
   document.querySelector("[ng-app], [data-ng-app], .ng-scope") !== null;  // AngularJS markers
   document.querySelector("[ng-version]")?.getAttribute("ng-version");     // Angular 2+
   ```

   Frameworks bundled without a global need a search in the bundle: version banners in license comments (`/*! jQuery v3.4.1`), React's version string, `ng-version` attributes rendered by Angular, Vue's `__VUE__` hooks.
3. Check for source maps: a `//# sourceMappingURL=` comment at the end of each bundle or a `SourceMap` response header. Request the `.map` file for one bundle. If it is served, recover the original sources locally (for example `sourcemapper -output ./src-app -url https://app.example.com/static/js/main.4f1c.js.map`) and keep them in the engagement folder only.
4. Run a component check over the scripts: **Retire.js** (browser extension or `retire --path ./downloaded-js`) or the Burp extension of the same name, and note each library with a published advisory.
5. For each vulnerable library, look up the advisory and write down what has to be reachable for it to matter (for example "jQuery below 3.5.0: HTML passed to `html()`/`append()` from an untrusted source, even after sanitising").
6. Record the CSP and any `require-trusted-types-for` / `trusted-types` directives on the main HTML responses; they change how you interpret later results.

#### Observation

An inventory such as (illustrative):

| Asset | Library / framework | Version | Notes |
|---|---|---|---|
| `/static/js/main.4f1c.js` | React | 18.2 | Source map served (`main.4f1c.js.map`) |
| `/legacy/admin/app.js` | AngularJS | 1.5.8 | `ng-app` on `body`; sandbox era; end of life |
| `/vendor/jquery.min.js` | jQuery | 1.12.4 | Below 3.5.0 (CVE-2020-11022/11023), below 3.4.0 (CVE-2019-11358) |
| `/static/js/editor.js` | DOMPurify | 2.0.8 | Old 2.x release; check advisories |
| `https://widgets.example.org/embed.js` | Third-party widget | n/a | Reads `location.href` on load |
| Main HTML | CSP | `script-src 'self' 'unsafe-inline'` | No Trusted Types |

#### Evaluation

Pass: all client-side components are supported and free of published advisories relevant to how they are used; no source maps in production unless the client decided to publish them. Fail (component finding): an unsupported framework (AngularJS) or a library version with a published XSS or prototype-pollution advisory. Rate it as XSS only after a later test shows the vulnerable function is reachable with attacker input. Public source maps are a finding for [browser storage and third-party scripts](/web/web-browser-storage-third-party-scripts/) if they expose secrets or internal paths; here they are mainly a testing aid.

#### False positives

Version strings in comments of a file that is never loaded; a library present in the bundle but tree-shaken to unused code; scanners that flag a version range the vendor backported a fix into (some distributions patch jQuery without changing the banner). Confirm by checking which functions the application actually calls.

#### Automation

Retire.js in CI (`retire --path ./dist --severity high`, which exits non-zero when it finds advisories at that level) or `npm audit` / an SCA tool on the lockfile, failing the build on high-severity client-side advisories. Keep the inventory in the repository (an SBOM, ASVS `v5.0.0-15.1.2`) so the next test starts from it.

### GT-WEB-DOM-2: Trace URL sources into HTML sinks with a canary

*Guler Tech methodology.* Implements WSTG-CLNT-01 (identify DOM sinks and build payloads that pertain to each sink type) for URL-derived sources.

#### What it checks

Whether `location.search`, `location.hash` or `location.pathname` reaches an HTML-parsing sink (`innerHTML`, `outerHTML`, `insertAdjacentHTML()`, `document.write()`, `srcdoc`) without encoding, and whether a marker executes.

#### Prerequisites

Test 1 inventory; Burp's browser with DevTools.

#### Steps

1. Put the canary into each URL source in turn, one at a time:

   ```text
   https://app.example.com/search?q=gtdom7q3k
   https://app.example.com/search#gtdom7q3k
   https://app.example.com/help/gtdom7q3k
   ```

2. In **Elements**, search the DOM (Ctrl+F / Cmd+F) for the canary. For each hit, note the context: element text, attribute value (which quote), inside a `script` block, inside a URL attribute.
3. Find the code that wrote it. Search all scripts for the source name (`location.search`, `URLSearchParams`, `location.hash`, `pathname`, router parameter helpers) and set a breakpoint where the value is read; step until it reaches the sink.
4. Append context characters to the canary and see what survives: `gtdom7q3k<>"'`. If they arrive unencoded in an HTML sink, move to inert markup:

   ```text
   https://app.example.com/search?q=%3Cb%3EGT-DOM-2%3C%2Fb%3E
   ```

5. If the marker renders as bold text, test execution with one event-handler marker suited to the sink. For `innerHTML`, `insertAdjacentHTML()` and `outerHTML`, inserted `script` elements do not run, so use an element with an error handler:

   ```text
   https://app.example.com/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E
   ```

   For `document.write()`, a `script` element with `alert(document.domain)` runs. If the canary sits inside an attribute, close the attribute and add an event handler instead of new markup; if it sits inside an existing `script` string, see test 5.
6. Repeat with the fragment (`#`) if the code reads `location.hash`; for `hashchange` handlers, load the page first, then change only the fragment in the address bar.

#### Observation

Vulnerable (illustrative): the bold marker renders, and the alert shows `app.example.com`. DevTools shows the call stack:

```text
Dialog: "app.example.com"
Handler:   HTMLImageElement.onerror  (inserted into #heading)
Write site: renderHeading  main.4f1c.js:1:48211  ->  src/search/Heading.js:22 (via source map)
Source:    URLSearchParams.get("q")  src/search/useQuery.js:9
```

Not vulnerable: the heading shows the literal text `<b>GT-DOM-2</b>`, because the code uses `textContent`, or the DOM shows `&lt;b&gt;` inside a text node.

#### Evaluation

Fail: an attacker-supplied URL causes markup to render (HTML injection) or a marker to execute (DOM XSS) in the application origin. Record the full URL, the source, the sink, the file and line, and the browser and version used. Pass: the value is inserted as text, or encoded for the context, in every browser in scope.

#### False positives

The canary appearing in a `data-` attribute or a hidden input set safely through `setAttribute()` or `.value` is not a sink. A value visible in the DOM because the server reflected it (check the raw response in Burp) belongs to reflected XSS testing, unless a script then moves it into a sink.

#### Automation

Burp Scanner's DOM analysis finds many direct URL-to-sink flows; DOM Invader (test 3) speeds up manual tracing. In CI, add the failing URL to the headless regression suite described in [Regression tests with a headless browser](#regression-tests-with-a-headless-browser).

### GT-WEB-DOM-3: Sweep sources and sinks with DOM Invader

*Guler Tech methodology.* Implements WSTG-CLNT-01 (identify sinks across the application's JavaScript, including code from third parties) using Burp's DOM Invader.

#### What it checks

Every source that DOM Invader instruments, on every page, for flows into its instrumented sinks, including flows that happen only after user events.

#### Prerequisites

DOM Invader enabled with your project canary; test 1 inventory.

#### Steps

1. Load a page. In the DevTools **DOM Invader** tab, stay in the **DOM** view. Click **Inject URL params** to place the canary into each query parameter (one tab per parameter), and **Inject forms** to fill detected forms (submit them yourself).
2. For sources other than query parameters, click **Copy canary** and paste it into the fragment, a path segment, a search box, a profile field of user A, or any other input.
3. Review the sinks DOM Invader lists for each page. They are ordered by interest; the **outer HTML**, frame path and event details show the context. Click the **Stack Trace** link to print the stack in the console and follow the topmost frame into the **Sources** panel at the line that writes the sink.
4. If sinks fire only on interaction, enable **Auto-fire events** (Misc settings): DOM Invader then triggers a click and mouseover on every element after load. If a redirect clears the results, enable **Redirection prevention**, or **Add breakpoint before redirect** to see which code navigates.
5. Optional, on a page with many sources: **Inject canary into all sources** appends a unique suffix per source so you can see which source reached which sink. Use the cog icon to disable noisy sources; injecting everywhere usually breaks the page.
6. For each interesting sink, append context characters to the canary (`gtdom7q3k<>"'`) and check how they appear in the sink. Then confirm manually as in test 2, with a marker payload.
7. If the application uses `postMessage`, enable **Postmessage interception** and follow [postMessage and web messaging](/web/web-postmessage-web-messaging/); if it uses query-string or hash parsers, test 11.

#### Observation

The DOM view lists, for example, `innerHTML` with the canary followed by `<>"'` unencoded, written from `widgets.example.org/embed.js` in a `hashchange` handler. Manual confirmation then shows `alert(document.domain)` reporting `app.example.com`.

#### Evaluation

DOM Invader's list is a lead list, not a result. Fail only after a manual marker executes (or markup renders) from a URL or stored value that an attacker can set. Pass when no instrumented sink receives the canary with its context characters intact.

#### False positives

Sinks that receive the canary only through DOM Invader's own injection into a source no attacker can control (for example a value only the server sets in an `HttpOnly` cookie); sinks reached only because instrumentation changed the code path (instrumenting `eval()` can change its behaviour, as PortSwigger warns). Reproduce with DOM Invader off before reporting.

#### Automation

DOM Invader is interactive; its callbacks setting can log every finding to the console for export. For repeatable checks, move confirmed flows into the Playwright regression tests.

### GT-WEB-DOM-4: Referrer, window name, storage, cookies and API data as sources

*Guler Tech methodology.* Implements WSTG-CLNT-01 (input from client-side JavaScript objects such as `document.referrer`) and WSTG-CLNT-01.1 (self DOM XSS evaluation), extending the source list to stored and cross-window data.

#### What it checks

Whether values that do not come from the current URL (the referrer, `window.name`, web storage, cookies, API responses) reach a sink, and whether an attacker can actually set them for a victim.

#### Prerequisites

User A and user B accounts; a local HTML file for cross-window sources (opened in your own browser only, sending nothing anywhere).

#### Steps

1. **API data (stored DOM XSS).** As user A, set a stored field that is shown to other users (display name, comment, project name) to an inert marker such as `<b>GT-DOM-4</b>` on an object only your accounts can see. As user B, open every view that renders it. If it renders bold, replace it with an execution marker (`<img src=x onerror=alert(document.domain)>`), view it as B once, record the evidence, then restore the original value.
2. **Storage.** In DevTools **Application**, list `localStorage` and `sessionStorage` keys the application reads on load. Edit one value to the canary and reload; check whether it reaches a sink. Then work out how an attacker could write that key. Storage is per origin, so only code running on the same origin counts: another feature that copies URL input into storage, another application hosted on the same origin, or an existing XSS elsewhere on it.
3. **Cookies.** Do the same with non-`HttpOnly` cookies the client reads (`document.cookie`). Note which cookies could be planted from a sibling subdomain (cookies set with `Domain=example.com`).
4. **Referrer.** If code reads `document.referrer`, create a local page that links to the target and open it from your browser. Serve the file from a local web server you run (for example `python3 -m http.server --bind 127.0.0.1`), because a page opened from `file:` sends no referrer. Check whether the referrer reaches a sink. The *referring* page's `Referrer-Policy` decides how much of its URL is sent; the browser default sends only the origin cross-site, but an attacker's page can usually opt in to sending its full URL (browsers differ in how far they honour that), so the default is not a defence. Set the same policy on your local page to reproduce that.
5. **window.name.** If code reads `window.name`, use a local page that opens the target in a named window:

   ```html
   <!-- gt-dom-4-name.html: opened locally in your own browser; sends nothing -->
   <a href="https://app.example.com/welcome" target="gtdom7q3k" rel="opener">Open target</a>
   ```

   Check whether the window name reaches a sink on the target. Current browsers may reset `window.name` on cross-site navigations, so record the browser and version.
6. **Typed or pasted input.** If a sink is reached only from a form field (WSTG-CLNT-01.1), check for another way to fill that field: a URL parameter that pre-fills it, a stored draft, a message from another window. If none exists, record it as self DOM XSS.

#### Observation

Vulnerable (illustrative): user B's project list renders user A's project name with `innerHTML`, and the marker alert shows `app.example.com`; the API response itself is correct JSON with the name as a string. Self-only: the contact form's "strip HTML" helper fires the handler for text the user pastes, and there is no other way to fill the field.

#### Evaluation

Fail: an attacker-controllable value from any of these sources executes a marker in another user's session (A to B), or from a cross-window source in a page the attacker controls. Self DOM XSS (only the victim can supply the value): report as Low or informational, noting the social-engineering precondition and any CSP effect, as WSTG-CLNT-01.1 does. Pass: values are rendered as text, or no attacker can set the source.

#### False positives

Storage values that only the application writes, from server data that is already validated, are not attacker-controlled unless another bug writes them; say so instead of reporting a storage "source". The marker seen by user B only because both accounts are the same person in two tabs: check that B's session is genuinely separate.

#### Automation

For stored DOM XSS, a Playwright test can create an object through the API with a marker value and assert, in a second browser context logged in as another user, that no dialog fires and the marker appears as text.

### GT-WEB-DOM-5: JavaScript execution sinks

*Guler Tech methodology.* Implements WSTG-CLNT-02 (JavaScript execution: identify sinks and possible JavaScript injection points).

#### What it checks

Whether attacker-controlled data reaches `eval()`, `Function()`, `setTimeout()` or `setInterval()` with a string argument, a script element's `text`/`textContent`, or a string that the page later executes (a JSONP callback name, an inline script built at run time).

#### Prerequisites

Test 1 inventory; pretty-printed bundles or recovered sources.

#### Steps

1. Search all loaded scripts for the execution sinks: `eval(`, `Function(`, `setTimeout(` and `setInterval(` whose first argument is not a function, `.text =` and `.textContent =` on a script element, `execScript`, `callback=` parameters. DevTools global search accepts regular expressions.
2. For each hit, work backwards to its argument. Set a breakpoint on the sink and reload; inspect the argument's value and the call stack.
3. If the argument contains a URL-derived or stored value, put the canary into that source and confirm at the breakpoint that it arrives in the code string.
4. Determine the syntactic context (inside a single-quoted string, a double-quoted string, a template literal, a bare expression) and append the closing character to the canary to see whether it breaks the context. A syntax error in the console at that line is a strong signal.
5. Confirm with one marker that closes the context and calls `print()` or `alert(document.domain)`. For WSTG's example, where the fragment after `message=` is passed to `eval()` as an object literal, a value of `({"message":"GT-DOM-5"})` showing the marker proves the data is evaluated, and a value that calls `alert(document.domain)` proves execution.

   ```text
   https://app.example.com/notice#message=({"message":"GT-DOM-5"})
   ```

6. Check the CSP for `'unsafe-eval'`. Without it, `eval()` and friends throw an `EvalError` (CSP violation), which mitigates but does not remove the finding.

#### Observation

Vulnerable (illustrative): a breakpoint on `eval` in `notice.js` shows the argument `({"message":"GT-DOM-5"})` taken from `location.hash`, and the marker alert shows `app.example.com`. Mitigated: the console shows a CSP violation for `script-src` blocking `'unsafe-eval'`.

#### Evaluation

Fail: an attacker-controlled value becomes part of code executed by the page. Pass: execution sinks receive only literals or functions; data is parsed with `JSON.parse()` instead of `eval()`.

#### False positives

`setTimeout` and `setInterval` called with a function reference are not sinks. Bundler runtime code (webpack's chunk loader, polyfills) that calls `Function()` with constant strings. `eval` inside a dev-only module that is not shipped.

#### Automation

CodeQL `js/code-injection` and Semgrep's `javascript/browser/security/eval-detected.yaml` and `javascript/lang/security/audit/code-string-concat.yaml` find most of these statically; a CSP without `'unsafe-eval'` makes regressions throw in tests.

### GT-WEB-DOM-6: Navigation and URL attribute sinks with javascript URLs

*Guler Tech methodology.* Implements WSTG-CLNT-02 (the `window.location` example) and the script-execution half of WSTG-CLNT-04 (client-side URL redirect); the redirect half is tested in [open redirects](/web/web-open-redirect/).

#### What it checks

Whether a value used as a navigation target (`location.href`, `location.assign()`, `location.replace()`, `window.open()`) or as a URL attribute (`a.href`, `form.action`, `iframe.src`, jQuery `attr("href", …)`) accepts the `javascript:` scheme and other dangerous schemes (`data:` in frames and top-level navigations, `vbscript:` on legacy browsers).

#### Prerequisites

Test 1 inventory; a list of parameters that look like URLs (`next`, `returnUrl`, `redirect`, `continue`, `url`, `target`, `link`, `back`).

#### Steps

1. Find every parameter or stored field that ends up in a navigation or URL attribute. Search the bundle for `location.href =`, `location =`, `.assign(`, `.replace(` on location, `window.open(`, `.href =`, `setAttribute("href"`, `attr("href"` and router calls to external URLs.
2. Supply an external URL first: `https://example.org/`. If the page navigates there, record it as a client-side open redirect (test it further in the open redirect note) and continue.
3. Supply a `javascript:` URL with a marker:

   ```text
   https://app.example.com/login?returnUrl=javascript:alert(document.domain)
   https://app.example.com/profile?website=javascript:print()
   ```

   For anchors, click the link to trigger it; for navigation sinks, complete the flow that triggers the redirect (log in, save the form).
4. If a filter blocks the plain form, try a small number of variants that the URL parser normalises (mixed case, a leading space or control character, a tab inside the scheme, an HTML entity if the value passes through an HTML parser first). Keep it to a handful and report the filter as incomplete; do not build a bypass list.
5. Check how the URL is validated in code. A check with the `URL` constructor that compares `url.protocol` against an allow-list is robust; prefix checks, `indexOf("javascript")` and unanchored regular expressions usually are not.

#### Observation

Vulnerable (illustrative): after login, `location.href = params.get("returnUrl")` navigates to the `javascript:` URL and the marker alert shows `app.example.com`. Open redirect only: the page navigates to `https://example.org/`, while `javascript:` is rejected.

#### Evaluation

Fail (XSS): a `javascript:` URL from an attacker-controllable source is navigated to, or set on a link that the victim is likely to click, and the marker executes. Fail (redirect): external origins are accepted where only internal paths are intended (ASVS `v5.0.0-3.7.2`, L2). Pass: only same-origin paths, or URLs whose scheme and host are on an allow-list, are accepted.

#### False positives

Current React (19, according to its `sanitizeURL` source at the time of writing) neutralises `javascript:` URLs in the attributes it renders (the link points to a URL that only throws; React 16.9 to 18 only warned in development), so a React anchor with such an `href` usually does not execute; navigation done in code is not covered. A `javascript:` URL that runs only in a sandboxed iframe without `allow-scripts`, or that is blocked by an enforced Trusted Types policy (the spec routes `javascript:` navigations through the `default` policy), is mitigated: report the gap with the mitigation noted.

#### Automation

CodeQL `js/client-side-unvalidated-url-redirection`; Semgrep `javascript/browser/security/open-redirect.yaml` and `typescript/react/security/audit/react-href-var.yaml`; eslint-plugin-react's `jsx-no-script-url` for literal `javascript:` links. Add the URL to the Playwright regression suite.

### GT-WEB-DOM-7: Client-side resource manipulation

*Guler Tech methodology.* Implements WSTG-CLNT-06 (client-side resource manipulation: identify resource sinks with weak input validation and assess the impact).

#### What it checks

Whether an attacker-controlled value selects the URL of a script, frame, stylesheet, object, or an `XMLHttpRequest`/`fetch()` whose response is written to an HTML sink.

#### Prerequisites

Test 1 inventory; a URL on an origin you control that serves a harmless resource, or a lab. A script file that only calls `alert(document.domain)` is enough; nothing else may be in it.

#### Steps

1. Search for resource sinks: `.src =` on `script` and `iframe` elements, `createElement("script")`, dynamic `import(`, `srcdoc`, `link.href`, `object.data`, and `fetch(`/`open(` calls whose URL contains a variable. WSTG-CLNT-06 lists the common ones: frame `src`, anchor `href`, XHR URL, stylesheet `href`, image `src`, object `data`, script `src`.
2. For each, trace the URL back to its source (fragment, query parameter, config object, `data-` attribute rendered from user input).
3. Supply a same-origin path first, then a path on another origin you control:

   ```text
   https://app.example.com/embed#/widgets/clock.js
   https://app.example.com/embed#https://gt-test.example.org/gt-dom-7.js
   https://app.example.com/help?doc=https://gt-test.example.org/gt-dom-7.html
   ```

   `gt-test.example.org` stands for your own test host; it serves only the marker resource and logs nothing about the visitor beyond a normal access log.
4. Observe in the **Network** panel whether the resource is requested from your host, and whether the marker executes in the application's origin (scripts) or the content is shown inside the page (frames, fetched HTML).
5. If only certain paths are allowed, check how the allow-list is enforced: a prefix match on `https://app.example.com` also matches `https://app.example.com.example.org/`; a relative path may be turned into an absolute URL by a leading `//`.
6. Check CSP `script-src`, `frame-src` and `connect-src`: they may block loading from your host, which mitigates the finding.

#### Observation

Vulnerable (illustrative): the **Network** panel shows `GET https://gt-test.example.org/gt-dom-7.js` initiated by `embed.js`, and the marker alert shows `app.example.com`. Frame only: the help page shows your test page inside an `iframe` on the application, with no script running in the application's origin.

#### Evaluation

Fail (XSS): an attacker-chosen script is loaded into the page, or an attacker-chosen response is written to an HTML sink. Fail (lower severity): an attacker-chosen page is framed or linked inside the application (content spoofing, phishing aid). Pass: resource URLs come from a fixed map keyed by an identifier, or are validated against an exact allow-list of origins and paths, and CSP restricts the same origins.

#### False positives

A request to your host that CSP blocks before execution (the console shows the violation): report it as mitigated. Images and other passive resources loaded from an attacker URL are not XSS; at most they leak the referrer or confirm a visit.

#### Automation

Semgrep `javascript/angular/security/detect-angular-resource-loading.yaml` for AngularJS resource URLs; CodeQL `js/xss` covers many URL-to-script-source flows. Enforcing Trusted Types makes any string assigned to `script.src` fail unless a policy creates a `TrustedScriptURL`.

### GT-WEB-DOM-8: jQuery sinks and jQuery version checks

*Guler Tech methodology.* Implements WSTG-CLNT-01 (sinks in third-party libraries) for jQuery, with version checks for its published XSS and prototype-pollution advisories.

#### What it checks

Whether attacker-controlled data reaches jQuery's HTML-parsing methods or `$()` with a string, and whether the jQuery version in use has published advisories that change what is exploitable.

#### Prerequisites

jQuery version from test 1; pretty-printed application code.

#### Steps

1. Note the version (`jQuery.fn.jquery`) and compare it with the advisories:

   | Version | Advisory | What it means for testing |
   |---|---|---|
   | Below 1.9.0 | CVE-2012-6708 | `$()` treats any string containing `<` as HTML, so `$(location.hash)` and similar selector code are HTML sinks |
   | Below 3.0.0 | CVE-2015-9251 | Cross-domain `$.ajax` without `dataType` executes `text/javascript` responses; matters if the URL is attacker-influenced (test 7) |
   | Below 3.4.0 | CVE-2019-11358 | `$.extend(true, {}, input)` can pollute `Object.prototype`; matters if input is attacker-controlled (test 11) |
   | Below 3.5.0 | CVE-2020-11022, CVE-2020-11023 | HTML passed to `html()`, `append()` and others can execute code even after sanitising; matters wherever sanitised user HTML is inserted with jQuery |

2. Search the application code (not jQuery itself) for `$(` and `jQuery(` called with a variable, and for `.html(`, `.append(`, `.prepend(`, `.after(`, `.before(`, `.replaceWith(`, `.wrap(`, `.wrapAll(`, `$.parseHTML(` and `.attr("href"` / `.attr("src"` with a variable.
3. Trace each argument to a source and test as in test 2. For selector sinks, the source matters: a value that starts with `#` is a selector in 1.9.0 and later, while a value from a query parameter can start with `<`.
4. For `hashchange`-driven selector code, change only the fragment after the page has loaded (or use the PortSwigger lab's framing technique in a lab only).
5. For `attr("href", value)`, test `javascript:` as in test 6.

#### Observation

Vulnerable (illustrative): `$(".notice").html("Saved " + params.get("item"))` renders `<b>GT-DOM-8</b>` as bold text and then fires the marker alert. Version-only: jQuery 1.12.4 is loaded, but the application never passes non-literal strings to `$()` or the manipulation methods.

#### Evaluation

Fail (XSS): a marker executes through a jQuery sink. Fail (component): a jQuery version below 3.5.0 is in use (report as outdated component; rate as XSS only if the vulnerable behaviour is reachable). Pass: current jQuery, and application code uses `.text()`, `.val()` or `document.getElementById()` for untrusted values.

#### False positives

`$()` with a literal selector string; `.html()` used as a getter; jQuery plugins that are included but never initialised.

#### Automation

Semgrep `javascript/jquery/security/audit/jquery-insecure-selector.yaml`, `jquery-insecure-method.yaml` and `prohibit-jquery-html.yaml`; CodeQL `js/unsafe-jquery-plugin` for plugin options that reach jQuery sinks; Retire.js for the version.

### GT-WEB-DOM-9: Framework escape hatches in React, Angular and Vue

*Guler Tech methodology.* Implements WSTG-CLNT-01 and the grey-box code-review part of WSTG-CLNT-15 (Angular, Vue and React sinks) for modern frameworks.

#### What it checks

Whether user-controlled data reaches React's `dangerouslySetInnerHTML`, a ref or `ElementRef` that writes `innerHTML`, Angular's `bypassSecurityTrust…` methods, or Vue's `v-html` / render-function `innerHTML`, without a sanitiser on the exact value rendered.

#### Prerequisites

Recovered sources (test 1) or repository access; user A and user B accounts for stored values.

#### Steps

1. Search the sources (or the pretty-printed bundle, where names often survive) for the escape hatches:

   ```bash
   # In the recovered or checked-out source tree
   grep -rnE "dangerouslySetInnerHTML|__html" src/
   grep -rnE "bypassSecurityTrust(Html|Script|Style|Url|ResourceUrl)" src/
   grep -rnE "nativeElement\.(innerHTML|outerHTML|insertAdjacentHTML)" src/
   grep -rnE "\.current\.(innerHTML|outerHTML|insertAdjacentHTML)|ref\.(innerHTML|outerHTML)" src/
   grep -rnE "v-html|innerHTML:|domProps" src/
   grep -rnE "sanitize:\s*false|allowHTML|html:\s*true|escapeMarkup|unsafeHTML" src/
   ```

   Minified bundles keep property names: `dangerouslySetInnerHTML` and `bypassSecurityTrustHtml` are searchable in production JavaScript.
2. For each hit, find where the value comes from: a constant or translation file (fine), a build-time Markdown file (usually fine), an API field a user can edit (test it), a URL parameter (test it).
3. Check what sits between the value and the sink. Is DOMPurify (or another sanitiser) called on the same value that is rendered? Is the output modified afterwards? What configuration is used (`ADD_TAGS`, `ADD_ATTR`, `ALLOW_UNKNOWN_PROTOCOLS`, custom hooks)?
4. Test the reachable ones with markers, A to B for stored values, as in test 4: inert markup first, then an event-handler marker.
5. Check URL bindings separately: in Vue, a `:href` bound to user data is not sanitised; in React, an `href` set through a ref or a navigation in code is not covered; in Angular, `bypassSecurityTrustUrl()` or `bypassSecurityTrustResourceUrl()` on user data disables URL sanitisation. Test with a `javascript:` marker as in test 6.
6. For Angular, confirm the application uses the ahead-of-time compiler in production (no `@angular/compiler` JIT in the bundle, no `angular#unsafe-jit` Trusted Types policy needed): run-time compilation of user-influenced templates is template injection.

#### Observation

Vulnerable (illustrative), React: a comment component renders the `body_html` field of an API response with `dangerouslySetInnerHTML`; the field is whatever the author typed. Mitigated: the same component calls `DOMPurify.sanitize(body_html)` directly in the prop, and the marker's `onerror` attribute is removed (no console error, no alert).

{% raw %}
```javascript
// Illustrative: the escape hatch and its two typical states
<div dangerouslySetInnerHTML={{ __html: comment.body_html }} />                    // unsafe: user-authored HTML
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.body_html) }} /> // sanitised at the sink
```
{% endraw %}

#### Evaluation

Fail: a marker executes, or user-controlled markup with active content renders, through a framework escape hatch or direct DOM write. Pass: escape hatches receive only trusted constants or values sanitised at the sink with a current sanitiser and a default-strict configuration.

#### False positives

`dangerouslySetInnerHTML` used for a CSS-in-JS style block or an inline JSON data island built from constants; `bypassSecurityTrustResourceUrl()` used on a fixed, allow-listed embed URL; `v-html` on Markdown rendered at build time from the repository.

#### Automation

Semgrep `typescript/react/security/audit/react-dangerouslysetinnerhtml.yaml`, `react-unsanitized-property.yaml`, `react-unsanitized-method.yaml`, `typescript/angular/security/audit/angular-domsanitizer.yaml` and `javascript/vue/security/audit/xss/templates/avoid-v-html.yaml`; eslint-plugin-react `no-danger`; eslint-plugin-no-unsanitized for ref writes. Fail the build when a new escape hatch appears without an approved sanitiser call.

### GT-WEB-DOM-10: Client-side template injection in AngularJS and Vue

*Guler Tech methodology.* Implements WSTG-CLNT-15 (client-side template injection: identify the framework and version, detect injection points, assess whether expressions execute).

#### What it checks

Whether user input ends up inside a region that AngularJS or Vue compiles at run time, so that template expressions in the input are evaluated.

#### Prerequisites

Test 1 inventory showing AngularJS (`ng-app`, `angular.version`) or Vue mounted on server-rendered markup, or a run-time template compiler in the bundle; the AngularJS version.

#### Steps

1. Find the compiled region. For AngularJS, the element carrying `ng-app` (often `html` or `body`) and everything inside it is compiled; `ng-non-bindable` excludes a subtree. For Vue, the element the application is mounted on, if it contains server-rendered content.
2. Find inputs reflected inside that region: search results, names, error messages, breadcrumbs. These are usually HTML-encoded correctly by the server, which is why plain XSS tests pass.
3. Send an arithmetic probe with a unique prefix, using the framework's double-brace interpolation:

   {% raw %}
   ```text
   https://app.example.com/search?q=gtdom10{{7*7}}
   ```
   {% endraw %}

   If the page shows `gtdom1049`, the expression was evaluated. If it shows the probe literally, it was not.
4. Record the AngularJS version. In 1.6 and later there is no expression sandbox, and a constructor-based expression that calls `alert(document.domain)` executes:

   {% raw %}
   ```text
   https://app.example.com/search?q={{constructor.constructor('alert(document.domain)')()}}
   ```
   {% endraw %}

   In versions before 1.6, the sandbox blocks this simple form and version-specific escapes are needed. Do not develop or iterate escapes on a client system: an evaluated arithmetic probe on a known version is sufficient evidence, and you can reference PortSwigger's published research on sandbox escapes for that version. Use the labs to see the escapes work.
5. For Vue, the same arithmetic probe applies when user input lands inside the mounted element's server-rendered HTML or in a template string compiled at run time. Check the Vue version (`Vue.version`) and whether the full build with the compiler is shipped.
6. Note the CSP. AngularJS has a CSP-compatible mode in which it evaluates expressions with its own interpreter instead of `Function()`, so a policy without `'unsafe-eval'` does not stop expression evaluation; record what does and does not execute.

#### Observation

Vulnerable (illustrative): the search page on `admin.example.com` (AngularJS 1.5.8, `ng-app` on `body`) shows "No results for gtdom1049". The server's HTML response contains the probe unchanged, so the evaluation happened in the browser.

#### Evaluation

Fail: an expression in user input is evaluated (arithmetic probe proves template injection; a marker alert proves XSS). Rate an evaluated probe on a sandbox-era AngularJS version as XSS when public escapes exist for that version, and say so. Also report AngularJS itself as an unsupported component (end of support January 2022). Pass: user input is outside compiled regions, or inside `ng-non-bindable`, or the framework compiles templates ahead of time only.

#### False positives

Pages that display `49` because the application itself calculates something (use the unique prefix); Angular (2+) applications, which do not compile the DOM at run time (template injection there requires run-time compilation of user-influenced templates, which test 9 checks); Handlebars or Mustache rendered on the server (that is server-side template injection, see [server-side template injection](/web/web-server-side-template-injection/)).

#### Automation

Burp Scanner reports client-side template injection; Semgrep's `javascript/angular/security/detect-angular-sce-disabled.yaml` and the `detect-angular-trust-as-*` rules cover AngularJS `$sce` misuse. In CI, fail the build if `angular.js` 1.x is present in production assets without an approved migration exception.

### GT-WEB-DOM-11: Client-side prototype pollution as a DOM XSS source

*Guler Tech methodology.* Implements the client-side part of WSTG-INJT-22 (prototype pollution: probe a source, confirm on a fresh object, then look for a gadget) as a DOM XSS source for WSTG-CLNT-01.

#### What it checks

Whether a URL or message parser lets an attacker add properties to `Object.prototype` in the victim's page, and whether any script reads such a property into an HTML, code or script-URL sink (a gadget).

#### Prerequisites

Burp's browser with DOM Invader's **Prototype pollution** attack type switched on (it is off by default); test 1 inventory (libraries with known gadgets).

#### Steps

1. Probe the URL sources manually with a uniquely named property. These requests change only your own tab's JavaScript state; a reload clears them:

   ```text
   https://app.example.com/?__proto__[gtpp]=GT-DOM-11
   https://app.example.com/#__proto__[gtpp]=GT-DOM-11
   https://app.example.com/?constructor[prototype][gtpp]=GT-DOM-11
   https://app.example.com/?__proto__.gtpp=GT-DOM-11
   ```

2. After each load, check in the console whether a new, empty object inherits the property:

   ```javascript
   ({}).gtpp;            // "GT-DOM-11" -> Object.prototype was polluted through this source
   Object.prototype.hasOwnProperty("gtpp");   // true confirms it is on the prototype itself
   ```

3. Let DOM Invader find sources automatically: it lists them in the **DOM** view; click **Test** next to a source, and in the new tab confirm in the console that a new object has DOM Invader's `testproperty`.
4. Look for a gadget. Click **Scan for gadgets** next to the confirmed source. DOM Invader reports sinks reached through polluted properties (for example a property named `html` that a library passes to `innerHTML`). The BlackFan *client-side-prototype-pollution* repository lists known gadgets per library, which you can match against the test 1 inventory.
5. If a gadget is found, use DOM Invader's **Exploit** button, which generates a proof that calls `alert()`, or build the equivalent URL by hand with `alert(document.domain)` as the value. Stop there.
6. If you find pollution without a gadget, record the source and the parser responsible (often an old query-string library, a hand-written `deparam`, or `$.extend(true, …)` in jQuery below 3.4.0).

#### Observation

Vulnerable (illustrative): `?__proto__[gtpp]=GT-DOM-11` makes `({}).gtpp` return `"GT-DOM-11"`; **Scan for gadgets** reports that a property named `innerHTML` reaches `Element.innerHTML` inside a video-embed script, and the generated proof shows an alert for `app.example.com`. Pollution only: the property is inherited, but no gadget is found in the loaded code.

#### Evaluation

Fail (XSS): a URL that pollutes the prototype leads, through a gadget, to a marker executing. Fail (lower severity): prototype pollution confirmed without a known gadget; it is a latent XSS that the next library update may arm, and it can also break client-side security checks that read missing properties. Pass: no source pollutes `Object.prototype`.

#### False positives

A property that appears on the object your probe created rather than on the prototype (`Object.prototype.hasOwnProperty("gtpp")` is false); pollution reproducible only in the console (you wrote it yourself); DOM Invader instrumentation side effects (reproduce without it).

#### Automation

CodeQL `js/prototype-polluting-assignment` and `js/prototype-pollution-utility` on the client code; Retire.js for libraries with pollution advisories. A Playwright test can load the probe URLs and assert that `({}).gtpp` is `undefined`. Server-side pollution, which is a different test entirely, is in [server-side prototype pollution](/web/web-server-side-prototype-pollution/).

### GT-WEB-DOM-12: Static review of bundles and Trusted Types sink discovery

*Guler Tech methodology.* Implements the manual code-review approach of WSTG-CLNT-01 (examine code where parameters are referenced, where code is written to the page and where scripts are executed), with tool support, and checks the state of DOM-level mitigations.

#### What it checks

Every sink in the shipped JavaScript, not only those a crawl happens to exercise, and whether CSP and Trusted Types are in a state that would block the DOM XSS you found.

#### Prerequisites

Downloaded bundles or recovered sources (test 1); repository access for grey-box tests; Burp's browser.

#### Steps

1. **Grep the sinks.** On recovered sources or pretty-printed bundles:

   ```bash
   # Run against a local copy of the client code
   grep -rnE "\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write(ln)?\(|srcdoc|createContextualFragment|setHTMLUnsafe|parseFromString" src/
   grep -rnE "\beval\(|new Function\(|setTimeout\(\s*['\"\`]|setInterval\(\s*['\"\`]" src/
   grep -rnE "location(\.href)?\s*=|location\.(assign|replace)\(|window\.open\(" src/
   grep -rnE "\.src\s*=|import\(\s*[a-zA-Z_]" src/
   grep -rnE "location\.(search|hash|pathname)|document\.(URL|referrer|cookie)|window\.name|URLSearchParams|localStorage|sessionStorage" src/
   ```

   The first four lines give sinks, the last one sources. Work through files where both appear, then follow imports.
2. **Run data-flow tools** if you have the source: CodeQL's JavaScript suite (`js/xss` for client-side flows from the URL, `js/xss-through-dom` for text read from the DOM and written back as HTML, `js/code-injection`, `js/client-side-unvalidated-url-redirection`, `js/html-constructed-from-input`) and Semgrep's `javascript/browser/security/` rules (`dom-based-xss.yaml`, `insecure-document-method.yaml`, `insecure-innerhtml.yaml`, `raw-html-concat.yaml`). Triage every result by tracing it to a real source.
3. **Let the browser list the sinks.** In your own browser only, add a report-only Trusted Types policy to the application's HTML responses with a Burp **Match and replace** rule on response headers:

   ```http
   Content-Security-Policy-Report-Only: require-trusted-types-for 'script'
   ```

   Reload and use the application. Each string assigned to an HTML, script or script-URL sink produces a report-only console violation (for example that the document requires a `TrustedHTML` assignment) with the script location, without blocking anything. This is a quick way to list sinks in code paths the crawl reaches; remove the rule afterwards. (If the application already sends a report-only policy, add yours as a separate header rather than replacing it.)
4. **Record the deployed mitigations.** For each page with a confirmed DOM XSS, note the enforced CSP (`script-src`, `'unsafe-inline'`, `'unsafe-eval'`, nonces, `strict-dynamic`), whether `require-trusted-types-for 'script'` is enforced, which `trusted-types` policy names are allowed, and whether a `default` policy exists and what it does (a `default` policy that returns its input unchanged disables the protection).
5. **Check sanitiser versions and configuration.** DOMPurify version against its security advisories; configuration options that widen the allow-list; hooks that edit attributes.

#### Observation

An illustrative triage table:

| File:line | Sink | Source | Reachable | Result |
|---|---|---|---|---|
| `src/search/Heading.js:22` | `innerHTML` | `URLSearchParams.get("q")` | Yes | DOM XSS (test 2) |
| `src/legacy/notice.js:14` | `eval` | `location.hash` | Yes | DOM XSS, mitigated by CSP without `'unsafe-eval'` |
| `src/ui/Tooltip.js:40` | `innerHTML` | i18n constant | No | Not a finding |
| `src/editor/Preview.js:61` | `innerHTML` | `DOMPurify.sanitize(markdown)` | Yes | Safe at this call site; DOMPurify current |

#### Evaluation

Each confirmed flow is reported under the test that matches its sink. This test fails on its own when: an enforced Trusted Types policy is undermined by a permissive `default` policy; CSP allows `'unsafe-inline'` or `'unsafe-eval'` on pages with confirmed DOM-sink flows; or the sanitiser in use has a published bypass advisory. Pass: every sink is fed only by constants, safe APIs or a sanitiser at the sink, and the mitigations are enforced.

#### False positives

Sinks in vendor code that the application never calls; grep hits in comments, tests and source maps of development tools; report-only violations from browser extensions (use a clean profile).

#### Automation

This is the test most worth moving into CI: CodeQL or Semgrep on every pull request, eslint-plugin-no-unsanitized as a lint gate, and a staging environment that sends `Content-Security-Policy-Report-Only: require-trusted-types-for 'script'` with a `report-to` endpoint, so new sinks show up as reports before they reach production.

## Secure implementation

### Design rules

- **Text by default.** Untrusted data goes into the DOM as text (`textContent`, `createTextNode()`, framework interpolation). ASVS `v5.0.0-3.2.2` (L1) asks for exactly this.
- **HTML only through a sanitiser at the sink.** If a feature genuinely needs user-authored HTML, sanitise it with a maintained sanitiser immediately before insertion and do not touch the output afterwards (ASVS `v5.0.0-1.3.1`, L1).
- **URLs are parsed, not pattern-matched.** Build and check URLs with the `URL` API and an allow-list of schemes and, for navigation and resources, of origins (ASVS `v5.0.0-1.2.2`, L1).
- **No strings become code.** No `eval()`, `Function()`, string timers or run-time template compilation of anything that contains data (ASVS `v5.0.0-1.3.2`, L1; `v5.0.0-1.3.7`, L2). When data must be embedded in a script, encode it for that context (ASVS `v5.0.0-1.2.3`, L1), typically as JSON in a non-executable `script type="application/json"` block read with `JSON.parse()`.
- **Let the browser enforce it.** Trusted Types turn the rules above into a runtime check on every sink; a nonce- or hash-based CSP without `'unsafe-eval'` limits what an injection can run (ASVS `v5.0.0-3.4.3`, L2).
- **Keep client-side components current** and remove unsupported frameworks (ASVS `v5.0.0-15.2.1`, L1).

### Text instead of HTML

```javascript
// Unsafe: parses the search term as HTML
heading.innerHTML = "Results for " + term;

// Safe: the term is a text node, whatever it contains
heading.textContent = "Results for " + term;

// Building structure without HTML strings
const li = document.createElement("li");
const link = document.createElement("a");
link.textContent = project.name;                  // text
link.href = `/projects/${encodeURIComponent(project.id)}`;  // built from a fixed path
li.append(link);
list.replaceChildren(li);                         // replaces old content without innerHTML
```

Setting non-URL, non-event attributes with `setAttribute()` (`title`, `aria-label`, `data-*`) is safe. Never set attributes whose name comes from input, never set `on…` handler attributes or `style` from input, and treat `href`, `src`, `action` and `formaction` as URL sinks (next section). The "strip tags" helper that parses into a detached `div` should be replaced by `textContent` on the original string, or by DOMPurify with `ALLOWED_TAGS: []` if tags really must be removed.

### URLs and navigation

```javascript
// url-safety.js
const SAFE_SCHEMES = new Set(["https:", "http:", "mailto:"]);

/** Returns a normalised URL string, or null if the URL is not allowed. */
export function safeUrl(input, { sameOrigin = false } = {}) {
  let url;
  try {
    url = new URL(String(input), window.location.origin);  // resolves relative paths; normalises case and whitespace
  } catch {
    return null;
  }
  if (!SAFE_SCHEMES.has(url.protocol)) return null;          // blocks javascript:, data:, vbscript:, blob: ...
  if (sameOrigin && url.origin !== window.location.origin) return null;
  return url.href;
}

// After login: only same-origin destinations, with a safe fallback
const next = safeUrl(new URLSearchParams(location.search).get("next") ?? "/", { sameOrigin: true }) ?? "/";
window.location.assign(next);

// A user-supplied website link on a profile page
const href = safeUrl(profile.website);
if (href) { link.href = href; link.rel = "noopener noreferrer"; } else { link.removeAttribute("href"); }
```

Validate on the server as well when the URL is stored, so that every client (web, mobile, email templates) receives safe values; Vue's security guide makes the same point. Redirect allow-lists for external destinations are covered in [open redirects](/web/web-open-redirect/).

### Rendering HTML safely with DOMPurify and the Sanitizer API

```javascript
import DOMPurify from "dompurify";

// Sanitise at the sink, with a profile instead of a hand-made allow-list
const clean = DOMPurify.sanitize(commentHtml, {
  USE_PROFILES: { html: true },   // HTML only: no SVG or MathML
  RETURN_TRUSTED_TYPE: true,      // returns TrustedHTML where the browser supports Trusted Types
});
container.innerHTML = clean;      // nothing modifies `clean` between sanitising and insertion
```

Rules for DOMPurify: keep it current (watch its GitHub security advisories), call it on the final string immediately before the sink, do not post-process its output, avoid `ADD_TAGS`/`ADD_ATTR` and custom hooks unless reviewed, and do not sanitise for one context and insert into another. `RETURN_TRUSTED_TYPE: true` returns `TrustedHTML` when Trusted Types are available; DOMPurify then uses an internal policy named `dompurify`, which must be listed in your `trusted-types` directive (or pass `TRUSTED_TYPES_POLICY: null` when you call DOMPurify from inside your own policy, as below). On the server, DOMPurify needs a DOM implementation such as an up-to-date jsdom.

The browser's own HTML Sanitizer API (`Element.setHTML()`) sanitises during insertion and is the long-term replacement; MDN marks it as limited availability at the time of writing, so use it with feature detection and keep DOMPurify as the fallback.

### Trusted Types

Trusted Types make every HTML, script and script-URL sink reject plain strings once the page's CSP requires it. Code then has to pass values created by a named policy, which concentrates the security review into a few functions. MDN lists the API as Baseline 2026 (newly available across current browsers since February 2026); older browsers ignore the directives, so treat it as a strong second layer, not the only one.

```javascript
// trusted-types-policies.js: loaded before application code
import DOMPurify from "dompurify";

export const htmlPolicy = window.trustedTypes?.createPolicy("app-html", {
  createHTML: (input) => DOMPurify.sanitize(input, { TRUSTED_TYPES_POLICY: null }),
});

const WIDGET_PATH = "/static/widgets/";
export const scriptUrlPolicy = window.trustedTypes?.createPolicy("app-script-url", {
  createScriptURL: (input) => {
    const url = new URL(input, window.location.origin);
    if (url.origin === window.location.origin && url.pathname.startsWith(WIDGET_PATH)) return url.href;
    throw new TypeError(`Script URL not allowed: ${input}`);
  },
});

// Usage
preview.innerHTML = htmlPolicy ? htmlPolicy.createHTML(markdownHtml) : DOMPurify.sanitize(markdownHtml);
```

Enforce it with CSP. Roll out in report-only mode first, fix each reported sink, then enforce:

```http
Content-Security-Policy-Report-Only: require-trusted-types-for 'script'; trusted-types app-html app-script-url; report-to csp-endpoint
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types app-html app-script-url
```

`require-trusted-types-for 'script'` switches on enforcement; `trusted-types` lists the policy names that may be created, so unexpected code cannot create its own permissive policy. A policy named `default` is applied automatically to any string that reaches a sink; MDN recommends it only as a migration aid. A `default` policy must sanitise or reject (returning `null` or `undefined` makes the assignment throw) and must never return its input unchanged. Per the specification, an enforcing page also runs `javascript:` URL navigations through the `default` policy's `createScript`, which blocks them when no such policy exists. Frameworks integrate with Trusted Types: Angular documents its own policy names (below), and DOMPurify returns `TrustedHTML` as described above.

### No strings to code

```javascript
// Unsafe
const data = eval("(" + location.hash.slice(1) + ")");
setTimeout("refresh('" + panelId + "')", 1000);
window[params.get("callback")](result);

// Safe
const data = JSON.parse(decodeURIComponent(location.hash.slice(1)));   // data, never code
setTimeout(() => refresh(panelId), 1000);                               // a function, not a string
const CALLBACKS = new Map([["onReady", onReady], ["onClose", onClose]]); // fixed dispatch table
CALLBACKS.get(params.get("callback"))?.(result);
```

Remove `'unsafe-eval'` from CSP; libraries that still need it (some template engines and older AngularJS builds outside CSP mode) are a reason to replace them.

### Loading scripts and frames

```javascript
// Resource identifiers, not URLs, travel in the page address
const WIDGETS = new Map([
  ["clock", "/static/widgets/clock.js"],
  ["map", "/static/widgets/map.js"],
]);
const src = WIDGETS.get(new URLSearchParams(location.search).get("widget"));   // Map: no prototype lookups
if (src) {
  const s = document.createElement("script");
  s.src = scriptUrlPolicy ? scriptUrlPolicy.createScriptURL(src) : src;
  document.head.append(s);
}
```

A `Map` (or `Object.hasOwn()`) avoids inheriting `__proto__` and friends when the key comes from the URL. Frames that must show user-chosen content get an origin allow-list and the `sandbox` attribute without `allow-scripts` unless the content is trusted; CSP `script-src`, `frame-src` and `connect-src` back this up. Integrity of third-party scripts (SRI) is covered in [browser storage and third-party scripts](/web/web-browser-storage-third-party-scripts/).

### React

{% raw %}
```javascript
import DOMPurify from "dompurify";
import { safeUrl } from "./url-safety";

// Text: JSX escapes it
export function Comment({ comment }) {
  return <p className="comment">{comment.body}</p>;
}

// HTML that must be rendered: one reviewed component, sanitising at the sink
export function SafeHtml({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html, { USE_PROFILES: { html: true } }) }} />;
}

// URLs: validate even though React 19 neutralises javascript: in href
export function Website({ url }) {
  const href = safeUrl(url);
  return href ? <a href={href} rel="noopener noreferrer">Website</a> : null;
}
```
{% endraw %}

Keep `dangerouslySetInnerHTML` inside a single `SafeHtml`-style component and ban it elsewhere with eslint-plugin-react's `no-danger` rule; never write `innerHTML` through a ref (`ref.current.innerHTML`); validate URLs used in `href`, `src` and code navigation (`window.location`, `router.push()` to external URLs) because React 19's `javascript:` neutralisation covers only the attributes React renders; and add `jsx-no-script-url`.

### Angular

```typescript
import { Component, inject, SecurityContext } from "@angular/core";
import { DomSanitizer } from "@angular/platform-browser";

@Component({
  selector: "app-comment",
  // [innerHTML] is sanitised by Angular automatically; interpolation is always text
  template: `<div class="comment" [innerHTML]="comment.bodyHtml"></div>`,
})
export class CommentComponent {
  comment = { bodyHtml: "" };
}

// When code must produce HTML outside a template binding, sanitise explicitly
export class LegacyBridge {
  private sanitizer = inject(DomSanitizer);
  toSafeHtml(input: string): string {
    return this.sanitizer.sanitize(SecurityContext.HTML, input) ?? "";
  }
}
```

Angular's guidance: treat templates as code and never build them from user input; use the ahead-of-time compiler in production; avoid direct DOM access through `ElementRef.nativeElement` (use templates or `Renderer2`); and call `bypassSecurityTrustHtml()`, `bypassSecurityTrustScript()`, `bypassSecurityTrustStyle()`, `bypassSecurityTrustUrl()` or `bypassSecurityTrustResourceUrl()` only on values you construct from constants, never on input. Angular supports Trusted Types with named policies: `angular` (always needed), `angular#bundler` (lazy chunks), `angular#unsafe-bypass` (only if the bypass methods are used, so its absence from your header is a useful control), `angular#unsafe-jit` and `angular#unsafe-upgrade`. A typical header is:

```http
Content-Security-Policy: trusted-types angular angular#bundler; require-trusted-types-for 'script'
```

### Vue

{% raw %}
```html
<!-- Comment.vue: compiled at build time (single-file component) -->
<template>
  <p class="comment">{{ comment.body }}</p>                       <!-- text: escaped -->
  <div class="comment-html" v-html="sanitisedHtml"></div>          <!-- only sanitised HTML -->
  <a v-if="website" :href="website" rel="noopener noreferrer">Website</a>
</template>

<script setup>
import { computed } from "vue";
import DOMPurify from "dompurify";
import { safeUrl } from "./url-safety";

const props = defineProps({ comment: Object });
const sanitisedHtml = computed(() => DOMPurify.sanitize(props.comment.bodyHtml ?? "", { USE_PROFILES: { html: true } }));
const website = computed(() => safeUrl(props.comment.authorWebsite));   // Vue does not sanitise :href
</script>
```
{% endraw %}

Vue's first security rule is never to use non-trusted templates: do not mount an application on server-rendered markup that contains user input, do not pass user input to the run-time compiler, and ship the runtime-only build with templates compiled at build time. Use interpolation or `v-text` for text, keep `v-html` behind a sanitiser, and validate URL bindings yourself.

### Legacy AngularJS and jQuery

**AngularJS.** Plan the migration: support ended in January 2022 and no further security fixes are published by the project. Until then, keep user input out of compiled regions (render it outside the `ng-app` element or wrap it in `ng-non-bindable`), bind text with `ng-bind` rather than server-reflected interpolation, keep `$sce` strict contextual escaping enabled, use `ngSanitize` for `ng-bind-html` and never call `$sce.trustAsHtml()` on input.

**jQuery.** Upgrade to a current release (at least 3.5.0 to close CVE-2020-11022 and CVE-2020-11023). Use `.text()` and `.val()` for untrusted values, never pass untrusted strings to `$()`, and select by id with `document.getElementById()` (wrapped in `$()` if you need jQuery methods):

```javascript
// Unsafe: $() may parse the value as HTML
$(location.hash).addClass("highlight");
$(".notice").html("Saved " + itemName);

// Safe
const target = document.getElementById(decodeURIComponent(location.hash.slice(1)));
if (target) $(target).addClass("highlight");
$(".notice").text("Saved " + itemName);
```

### Prototype-safe client code

Parse query strings with `URLSearchParams`, which produces flat strings and no nested objects. If you need nested structures, build them with an allow-list of keys, reject `__proto__`, `constructor` and `prototype`, and use `Map` or `Object.create(null)` for lookup tables keyed by input. Keep merge, clone and query-string libraries current; old versions of several popular ones had pollution advisories. Some teams also freeze `Object.prototype` early in page load (`Object.freeze(Object.prototype)`), which turns pollution into a silent no-op or an error but can break libraries that patch prototypes, so test it before adopting. The server-side equivalents are in [server-side prototype pollution](/web/web-server-side-prototype-pollution/).

### Headers from Express, Django, Spring and Laravel

The header that switches on Trusted Types is set by the server. Policy design (nonces, `strict-dynamic`, reporting) is in [Content Security Policy and security headers](/web/web-content-security-policy-headers/); these snippets add the Trusted Types directives to an existing policy. Adjust the policy names to the ones your code creates.

**Node.js / Express (helmet):**

```javascript
import helmet from "helmet";

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'none'"],
      requireTrustedTypesFor: ["'script'"],          // helmet writes require-trusted-types-for
      trustedTypes: ["app-html", "app-script-url"],
    },
  },
}));
```

**Django** (6.0 and later ship CSP support; earlier versions use the django-csp package):

```python
# settings.py
from django.utils.csp import CSP

MIDDLEWARE = [
    # ...
    "django.middleware.csp.ContentSecurityPolicyMiddleware",
]

SECURE_CSP = {
    "script-src": [CSP.SELF, CSP.NONCE],
    "object-src": [CSP.NONE],
    "base-uri": [CSP.NONE],
    "require-trusted-types-for": ["'script'"],
    "trusted-types": ["app-html", "app-script-url"],
}
```

**Spring Security:**

```java
@Bean
SecurityFilterChain security(HttpSecurity http) throws Exception {
    http.headers(headers -> headers.contentSecurityPolicy(csp -> csp.policyDirectives(
        "script-src 'self'; object-src 'none'; base-uri 'none'; "
        + "require-trusted-types-for 'script'; trusted-types app-html app-script-url")));
    return http.build();
}
```

**Laravel** (middleware registered for the `web` group in `bootstrap/app.php`):

```php
<?php
// app/Http/Middleware/TrustedTypesPolicy.php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class TrustedTypesPolicy
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);
        $response->headers->set(
            'Content-Security-Policy',
            "script-src 'self'; object-src 'none'; base-uri 'none'; "
            . "require-trusted-types-for 'script'; trusted-types app-html app-script-url"
        );
        return $response;
    }
}

// bootstrap/app.php
// ->withMiddleware(function (Middleware $middleware) {
//     $middleware->web(append: [\App\Http\Middleware\TrustedTypesPolicy::class]);
// })
```

### Lint rules and static analysis

| Tool | Rules / queries | What it catches |
|---|---|---|
| eslint-plugin-no-unsanitized (Mozilla) | `no-unsanitized/method`, `no-unsanitized/property` (enabled by the plugin's `recommended` config) | Assignments to `innerHTML`/`outerHTML` and calls such as `insertAdjacentHTML()` and `document.write()` with non-literal values, unless an approved escaping function is used; `setHTML()` calls are allowed by default |
| eslint-plugin-react | `no-danger`, `jsx-no-script-url` | Any use of `dangerouslySetInnerHTML`; literal `javascript:` URLs in JSX |
| CodeQL (JavaScript) | `js/xss`, `js/xss-through-dom`, `js/code-injection`, `js/client-side-unvalidated-url-redirection`, `js/html-constructed-from-input`, `js/unsafe-jquery-plugin`, `js/prototype-polluting-assignment`, `js/prototype-pollution-utility` | Taint flows from URL and DOM sources into sinks, across files |
| Semgrep (semgrep-rules) | `javascript/browser/security/` (`dom-based-xss`, `insecure-document-method`, `insecure-innerhtml`, `eval-detected`, `open-redirect`), `javascript/jquery/security/audit/`, `typescript/react/security/audit/`, `typescript/angular/security/audit/angular-domsanitizer`, `javascript/angular/security/`, `javascript/vue/security/audit/xss/templates/avoid-v-html` | Sinks and framework escape hatches by pattern and taint |
| Retire.js / SCA | n/a | Vulnerable jQuery, AngularJS, DOMPurify and other client libraries |

```javascript
// eslint.config.js
import nounsanitized from "eslint-plugin-no-unsanitized";
import react from "eslint-plugin-react";

export default [
  nounsanitized.configs.recommended,
  {
    files: ["src/**/*.{js,jsx,ts,tsx}"],
    plugins: { react },
    rules: {
      "react/no-danger": "error",
      "react/jsx-no-script-url": "error",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
    },
  },
  // The one reviewed component that may render sanitised HTML
  { files: ["src/components/SafeHtml.jsx"], rules: { "react/no-danger": "off" } },
];
```

`no-eval`, `no-implied-eval` (string arguments to `setTimeout`/`setInterval`) and `no-new-func` are core ESLint rules.

### Regression tests with a headless browser

Turn every confirmed DOM XSS and a set of generic probes into browser tests that assert the markers do **not** execute and that input appears as text. Playwright auto-dismisses dialogs by default, so register a handler and record them. Build the execution marker so that the literal string the test looks for never appears in the input itself (the application might echo the input into the console).

```typescript
// tests/dom-xss.spec.ts (Playwright)
import { test, expect, Page } from "@playwright/test";

const EXEC = "GT-" + "EXEC";                          // only appears if injected code runs
const run = `console.log('GT-'+'EXEC')`;

const CASES: string[] = [
  "/search?q=" + encodeURIComponent(`<img src=x onerror="${run}">`),
  "/search#" + encodeURIComponent(`<img src=x onerror="${run}">`),
  "/notice#message=" + encodeURIComponent(`(${run})`),
  "/profile/me?website=" + encodeURIComponent(`javascript:${run}`),
  "/?__proto__[gtpp]=GT-DOM-REG",
];

async function watch(page: Page) {
  const events: string[] = [];
  page.on("dialog", (d) => { events.push(`dialog:${d.message()}`); d.dismiss(); });
  page.on("console", (m) => { if (m.text().includes(EXEC)) events.push(`console:${m.text()}`); });
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) =>
      console.warn(`csp-violation:${e.violatedDirective}:${e.sourceFile}:${e.lineNumber}`));
  });
  return events;
}

for (const path of CASES) {
  test(`no script execution for ${path}`, async ({ page }) => {
    const events = await watch(page);
    await page.goto(path);
    await page.waitForLoadState("networkidle");
    expect(events).toEqual([]);
    expect(await page.evaluate(() => (({}) as any).gtpp)).toBeUndefined();
  });
}

test("search term is rendered as text", async ({ page }) => {
  await page.goto("/search?q=" + encodeURIComponent("<b>GT-DOM-REG</b>"));
  await expect(page.locator("#heading")).toContainText("<b>GT-DOM-REG</b>");   // literal text
  await expect(page.locator("#heading b")).toHaveCount(0);                    // no element created
});

test("website link never carries a javascript: URL", async ({ page }) => {
  await page.goto("/profile/me?website=" + encodeURIComponent("javascript:print()"));
  const href = await page.locator("a[data-test=website]").getAttribute("href").catch(() => null);
  expect(href === null || !/^\s*javascript:/i.test(href)).toBe(true);
});
```

For stored DOM XSS, create the object through the API as one test user and load it in a second browser context logged in as another (`browser.newContext({ storageState: "user-b.json" })`), with the same assertions. Run the suite against staging with Trusted Types enforced, and also once with the policy in report-only mode while collecting `csp-violation` lines: any new violation is a new sink to review.

## Practice labs

Labs are where you can try the parts this note keeps in prose: sandbox escapes, gadget chains and exploit delivery pages. Keep the habit of proving the source-to-sink path with the debugger, not only the alert.

**PortSwigger Web Security Academy** (free; DOM Invader works in all of them):

- [DOM XSS in document.write sink using source location.search](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink) and [inside a select element](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element): test 2, and why context matters.
- [DOM XSS in innerHTML sink using source location.search](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink): the `innerHTML` rule that inserted scripts do not run.
- [DOM XSS in jQuery anchor href attribute sink using location.search source](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink): `javascript:` URLs through `attr("href")` (tests 6 and 8).
- [DOM XSS in jQuery selector sink using a hashchange event](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event): the classic `$(location.hash)` pattern (test 8).
- [DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression), [Reflected XSS with AngularJS sandbox escape without strings](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-without-strings) and [with AngularJS sandbox escape and CSP](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-and-csp): test 10, including the escapes you should not develop on client systems.
- [Reflected DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected) and [Stored DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-stored): server data moved into sinks by client code (test 4).
- [DOM XSS via client-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-client-side-prototype-pollution), [via an alternative prototype pollution vector](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-an-alternative-prototype-pollution-vector), [client-side prototype pollution in third-party libraries](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-client-side-prototype-pollution-in-third-party-libraries) and [via browser APIs](https://portswigger.net/web-security/prototype-pollution/client-side/browser-apis/lab-prototype-pollution-client-side-prototype-pollution-via-browser-apis): test 11 with DOM Invader's gadget scan.
- [DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection): the redirect half of test 6.
- Related, in sibling notes: [DOM XSS using web messages](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages) and [Exploiting DOM clobbering to enable XSS](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering).

**OWASP Juice Shop** ([companion guide, XSS](https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html)): *DOM XSS* (the search field), *Bonus Payload* (the same sink with an embedded player), and *Reflected XSS* to compare a server-reflected flow with a DOM one.

**Google XSS game** ([xss-game.appspot.com](https://xss-game.appspot.com/)): short levels built around `innerHTML`, `location.hash`, `javascript:` URLs and script-URL sinks.

## Real-world cases

- **Self DOM XSS behind a CSP (HackerOne, 2018).** On `www.hackerone.com`, a marketing form's "strip HTML" helper assigned textarea contents to `innerHTML` of a detached `div` to read back `textContent`. The parse fired an event-handler payload, but the site's CSP blocked inline execution, and exploitation needed the victim to paste the payload, so it was rated Low. WSTG uses this report as its self DOM XSS example; it illustrates both the "strip tags" anti-pattern and how CSP and the self-only precondition lower severity without removing the bug. Disclosed November 2018. [HackerOne report 406587](https://hackerone.com/reports/406587).
- **Two "harmless" issues combined into reflected DOM XSS (Starbucks, 2020).** An attribute injection into a `link rel="canonical"` element on `www.starbucks.co.uk`, unfixed for a year because it seemed unexploitable, combined with the third-party prettyPhoto module, which reads a value from the URL fragment and triggers a click on a matching element. Together they ran script in the page. Rated Medium; disclosed June 2020. A reminder that third-party scripts reading `location` are sources too (test 3). [HackerOne report 396493](https://hackerone.com/reports/396493).
- **AngularJS template injection (Uber, 2016).** `developer.uber.com` reflected a search parameter inside an AngularJS-compiled page; an arithmetic probe was evaluated, and a sandbox escape for the version in use reached `alert(1)`. The report, by the PortSwigger researcher who published the client-side template injection technique, was rewarded USD 3,000 according to the report page; disclosed April 2016. This is test 10's pattern exactly: correct HTML encoding on the server, script execution in the browser. [HackerOne report 125027](https://hackerone.com/reports/125027).
- **Prototype pollution through a third-party embed script (HackerOne, 2020).** The video-embed script on the HackerOne marketing site parsed the page URL and the referrer with a parser that let `__proto__` keys pollute `Object.prototype`, and later built elements from option objects, so a polluted `innerHTML` property became a DOM XSS gadget. Rated Low, with a USD 500 bounty shown on the report; disclosed September 2020. Source and gadget were both inside a vendor's script, which is why test 11 relies on DOM Invader's gadget scan. [HackerOne report 986386](https://hackerone.com/reports/986386).
- **Stored DOM XSS from API data (GitHub Security Bug Bounty, 2016).** GitHub describes a report in which HTML stored in a user profile was returned by the GitHub API and inserted with `innerHTML` by a GitHub web application, producing DOM-based XSS. The affected site was static, with no session or sensitive data, which limited impact; the fix replaced `innerHTML` with a safe DOM API. [GitHub Bug Bounty write-up](https://bounty.github.com/2016/03/05/dom-xss-other-app.html).

More write-ups are collected in [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

DOM XSS is rated like any other XSS: on what the script can do in the victim's session on that origin, who can be targeted, and what the victim must do. Severity moves with: the delivery (a link anyone can send, a stored value seen by other users, a value only the victim can type), whether the page is authenticated and what the session allows (read personal data, change email or password without re-authentication, admin functions), the victim population (any user, staff, administrators), and mitigations that hold today (enforced CSP without `'unsafe-inline'`, enforced Trusted Types). Report a blocked injection as a real finding with a lower rating, because mitigations get relaxed and bypasses appear.

**Scope and user interaction.** XSS is scored with `UI:R` (the victim must open a link or view a page) and `S:C`: the vulnerable component is the web application, but the impact lands in the victim's browser session, a different security scope. The FIRST CVSS v3.1 user guide names cross-site scripting as the standard example of a scope change, and its examples document scores reflected XSS in a WordPress plugin (CVE-2017-5942) at `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) and stored XSS that reaches an administrator (CVE-2019-7551) at `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H` (9.0). Vectors below are examples; adjust them to what you confirmed.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| DOM XSS from a URL source (query, fragment, path) on an authenticated page | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | Anyone can send the link; the baseline assumes limited data and actions. Rate `C:H/I:H` (9.3) when the session can change the email address or password without re-authentication, read sensitive data at scale, or reach admin functions, and explain the path in prose |
| Stored DOM XSS (API data rendered with `innerHTML`) visible to other users | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` (5.4) | Needs an account to plant, fires for every viewer; raise to High when it reaches staff or many users |
| Stored DOM XSS that fires in an administrator's view | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` (8.7) | Administrator session actions are high impact (FIRST's Cantemo example adds `A:H` when admins can disrupt the service: 9.0) |
| `javascript:` URL in a link or navigation target from a URL parameter | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | Same impact as other DOM XSS; if the victim must click a link that the attacker cannot place convincingly, consider `AC:H` (4.7) and say why |
| Client-side resource manipulation loading an attacker script | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | Full script execution in the origin; raise like other XSS |
| Attacker-chosen page framed inside the application (no script in the origin) | Low to Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` (4.3) | Content spoofing and phishing aid; no access to the session |
| Client-side template injection in AngularJS with executable expressions | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | Rated as DOM XSS: XSS through template syntax; rate on the same factors. Add a separate component finding for AngularJS end of life |
| Client-side prototype pollution with a working XSS gadget | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | Equivalent to DOM XSS from a URL source |
| Client-side prototype pollution without a known gadget | Low | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N` (3.1) | Latent: depends on a gadget appearing; also breaks assumptions in client-side checks |
| DOM XSS blocked by an enforced CSP or Trusted Types policy | Low to Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N` (4.7) | The defect is real; `AC:H` records that execution needs a mitigation bypass or a page without the policy |
| Self DOM XSS (only the victim can supply the value) | Info to Low | none | Requires the victim to paste attacker content (WSTG-CLNT-01.1); many programmes treat it as out of scope unless chained with another source. Describe what would make it deliverable, then rate it as DOM XSS |
| Outdated jQuery, AngularJS or DOMPurify without a reachable vulnerable function | Info to Low | none | Component finding (`A03:2025`, CWE-1395/CWE-1104); rate as XSS only when reachability is shown |
| Sink reached only with encoded data | Info | none | Code-quality note: a fragile path worth refactoring before a change in encoding makes it exploitable |

When you report, give: the full URL or stored object, the source and the sink (with file and line from the stack trace or source map), the browser and version, the marker used and a screenshot of it firing with `document.domain`, the CSP and Trusted Types state, and the impact in prose (what the session can do) without demonstrating it. Note the stored payloads you placed and confirm they were removed.

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 |
|---|---|---|---|---|
| GT-WEB-DOM-1 | WSTG-CLNT-01, WSTG-CLNT-15 (framework identification) | v5.0.0-15.2.1, v5.0.0-15.1.2, v5.0.0-3.7.1 | CWE-1395, CWE-1104 | A03:2025 |
| GT-WEB-DOM-2 | WSTG-CLNT-01, WSTG-CLNT-03 | v5.0.0-3.2.2, v5.0.0-1.2.1 | CWE-79 | A05:2025 |
| GT-WEB-DOM-3 | WSTG-CLNT-01 | v5.0.0-3.2.2, v5.0.0-1.2.1 | CWE-79 | A05:2025 |
| GT-WEB-DOM-4 | WSTG-CLNT-01, WSTG-CLNT-01.1 | v5.0.0-3.2.2, v5.0.0-1.3.1 | CWE-79 | A05:2025 |
| GT-WEB-DOM-5 | WSTG-CLNT-02 | v5.0.0-1.3.2, v5.0.0-1.2.3 | CWE-95, CWE-79 | A05:2025 |
| GT-WEB-DOM-6 | WSTG-CLNT-02, WSTG-CLNT-04 | v5.0.0-1.2.2, v5.0.0-3.7.2 | CWE-79; CWE-601 for the redirect | A05:2025; A01:2025 for CWE-601 |
| GT-WEB-DOM-7 | WSTG-CLNT-06 | v5.0.0-1.2.2, v5.0.0-3.4.3 | CWE-829, CWE-79 | A08:2025 (CWE-829), A05:2025 |
| GT-WEB-DOM-8 | WSTG-CLNT-01 | v5.0.0-3.2.2, v5.0.0-15.2.1 | CWE-79, CWE-1395 | A05:2025, A03:2025 |
| GT-WEB-DOM-9 | WSTG-CLNT-01, WSTG-CLNT-15 (code review) | v5.0.0-3.2.2, v5.0.0-1.3.1, v5.0.0-1.2.2 | CWE-79 | A05:2025 |
| GT-WEB-DOM-10 | WSTG-CLNT-15 | v5.0.0-1.3.7, v5.0.0-15.2.1 | CWE-1336, CWE-79 | A05:2025 |
| GT-WEB-DOM-11 | WSTG-INJT-22, WSTG-CLNT-01 | v5.0.0-15.3.6 | CWE-1321, CWE-79 | A08:2025 (CWE-915 family), A05:2025 |
| GT-WEB-DOM-12 | WSTG-CLNT-01 | v5.0.0-3.4.3, v5.0.0-3.2.2, v5.0.0-1.3.1 | CWE-79 | A05:2025 |

ASVS levels: `v5.0.0-3.2.2` L1 (safe rendering functions such as `createTextNode` or `textContent` for text), `v5.0.0-1.2.1` L1 (context-relevant output encoding), `v5.0.0-1.2.2` L1 (URL encoding and safe URL protocols only), `v5.0.0-1.2.3` L1 (encoding when building JavaScript and JSON), `v5.0.0-1.3.1` L1 (sanitise untrusted HTML with a well-known library), `v5.0.0-1.3.2` L1 (avoid `eval()` and dynamic code execution), `v5.0.0-1.3.7` L2 (no templates built from untrusted input), `v5.0.0-3.4.3` L2 (CSP with `object-src 'none'`, `base-uri 'none'` and an allow-list, nonces or hashes; per-response nonces or hashes at L3), `v5.0.0-3.7.1` L2 (only supported client-side technologies), `v5.0.0-3.7.2` L2 (redirects to other hosts only via an allow-list), `v5.0.0-15.1.2` L2 (component inventory / SBOM), `v5.0.0-15.2.1` L1 (no components beyond their remediation time frames), `v5.0.0-15.3.6` L2 (JavaScript written to prevent prototype pollution). ASVS 5.0 has no requirement that names Trusted Types; they are the strongest way to meet 3.2.2 and 1.3.1 in a browser. CWE choice: CWE-79 (*Improper Neutralization of Input During Web Page Generation*) is the default for every DOM XSS finding, and MITRE lists DOM-based XSS as one of its types. CWE-95 (eval injection) fits execution sinks, CWE-1336 (*Improper Neutralization of Special Elements Used in a Template Engine*) fits template injection, CWE-1321 (prototype pollution) the pollution source, CWE-829 (*Inclusion of Functionality from Untrusted Control Sphere*) an attacker-chosen script source, and CWE-1395 or CWE-1104 outdated and unmaintained components. `A05:2025` Injection maps CWE-79, CWE-94 and CWE-95; `A03:2025` Software Supply Chain Failures maps CWE-1395 and CWE-1104; `A08:2025` Software or Data Integrity Failures maps CWE-829 and CWE-915 (the parent of CWE-1321); `A01:2025` maps CWE-601. The OWASP API Security Top 10 has no client-side category and is not mapped here.

## References

**OWASP**

- WSTG: [DOM-Based Cross Site Scripting (WSTG-CLNT-01)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/01-DOM-based_Cross_Site_Scripting), [Self DOM Based Cross Site Scripting (WSTG-CLNT-01.1)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/01.1-Self_DOM_Based_Cross_Site_Scripting), [JavaScript Execution (WSTG-CLNT-02)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/02-JavaScript_Execution), [HTML Injection (WSTG-CLNT-03)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/03-HTML_Injection), [Client-side URL Redirect (WSTG-CLNT-04)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/04-Client-side_URL_Redirect), [Client-side Resource Manipulation (WSTG-CLNT-06)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/06-Client-side_Resource_Manipulation), [Client-side Template Injection (WSTG-CLNT-15)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/15-Client-Side_Template_Injection), [Prototype Pollution (WSTG-INJT-22)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/22-Prototype_Pollution)
- ASVS 5.0: [V3 Web Frontend Security](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md), [V1 Encoding and Sanitization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md), [V15 Secure Coding and Architecture](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md)
- Top 10:2025: [A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/), [A03:2025 Software Supply Chain Failures](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/), [A08:2025 Software or Data Integrity Failures](https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/), [A01:2025 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/)
- Cheat Sheets: [DOM based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html), [Cross Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), [Content Security Policy](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html), [Prototype Pollution Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
- Community page: [DOM Based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS); Stefano Di Paola's [DOM XSS wiki](https://github.com/wisec/domxsswiki/wiki) (sources, sinks and browser encoding behaviour)

**CWE and CVSS**

- [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CWE-95](https://cwe.mitre.org/data/definitions/95.html), [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html), [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html), [CWE-829](https://cwe.mitre.org/data/definitions/829.html), [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html), [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html), [CWE-601](https://cwe.mitre.org/data/definitions/601.html)
- FIRST: [CVSS v3.1 User Guide](https://www.first.org/cvss/v3.1/user-guide) (scope change for XSS), [CVSS v3.1 Examples](https://www.first.org/cvss/v3.1/examples) (CVE-2017-5942, CVE-2019-7551)

**PortSwigger**

- Web Security Academy: [DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based), [DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based), [Client-side template injection](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection), [Prototype pollution](https://portswigger.net/web-security/prototype-pollution) and [client-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/client-side), [DOM clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering), [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) (payload reference, for labs)
- DOM Invader documentation: [overview](https://portswigger.net/burp/documentation/desktop/tools/dom-invader), [enabling](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/enabling), [testing for DOM XSS](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/dom-xss), [web messages](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/web-messages), [client-side prototype pollution](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution), [DOM clobbering](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/dom-clobbering), [settings](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/settings)
- Research: [XSS without HTML: Client-Side Template Injection with AngularJS](https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs), [DOM based AngularJS sandbox escapes](https://portswigger.net/research/dom-based-angularjs-sandbox-escapes), [Widespread prototype pollution gadgets](https://portswigger.net/research/widespread-prototype-pollution-gadgets)

**Browser platform**

- MDN: [Trusted Types API](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API), [CSP require-trusted-types-for](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/require-trusted-types-for), [CSP trusted-types](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/trusted-types), [Content-Security-Policy-Report-Only](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy-Report-Only), [Element.innerHTML](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML), [Node.textContent](https://developer.mozilla.org/en-US/docs/Web/API/Node/textContent), [HTML Sanitizer API](https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API) and [Element.setHTML()](https://developer.mozilla.org/en-US/docs/Web/API/Element/setHTML)
- W3C: [Trusted Types specification](https://www.w3.org/TR/trusted-types/) ([editor's draft](https://w3c.github.io/trusted-types/dist/spec/)); web.dev: [Prevent DOM-based cross-site scripting vulnerabilities with Trusted Types](https://web.dev/articles/trusted-types)
- Chrome DevTools: [breakpoints](https://developer.chrome.com/docs/devtools/javascript/breakpoints), [source maps](https://developer.chrome.com/docs/devtools/javascript/source-maps)

**Frameworks and libraries**

- React: [common components](https://react.dev/reference/react-dom/components/common) (`dangerouslySetInnerHTML`); Angular: [Security](https://angular.dev/best-practices/security), [DomSanitizer](https://angular.dev/api/platform-browser/DomSanitizer); Vue: [Security](https://vuejs.org/guide/best-practices/security.html), [built-in directives](https://vuejs.org/api/built-in-directives.html) (`v-html`, `v-text`)
- AngularJS: [repository and end-of-support notice](https://github.com/angular/angular.js), [version support status](https://docs.angularjs.org/misc/version-support-status), [security guide](https://docs.angularjs.org/guide/security)
- jQuery: [3.5.0 release notes](https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/), [3.5 upgrade guide](https://jquery.com/upgrade-guide/3.5/); NVD: [CVE-2012-6708](https://nvd.nist.gov/vuln/detail/CVE-2012-6708), [CVE-2015-9251](https://nvd.nist.gov/vuln/detail/CVE-2015-9251), [CVE-2019-11358](https://nvd.nist.gov/vuln/detail/CVE-2019-11358), [CVE-2020-11022](https://nvd.nist.gov/vuln/detail/CVE-2020-11022), [CVE-2020-11023](https://nvd.nist.gov/vuln/detail/CVE-2020-11023)
- [DOMPurify](https://github.com/cure53/DOMPurify) ([security advisories](https://github.com/cure53/DOMPurify/security/advisories)), [DOMFortify](https://github.com/cure53/DOMFortify) (a DOMPurify-backed Trusted Types default policy)
- Server headers: [Django CSP reference](https://docs.djangoproject.com/en/6.0/ref/csp/) and [how-to](https://docs.djangoproject.com/en/6.0/howto/csp/)

**Tools**

- [Burp Suite DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader); Burp extension [Retire.js](https://portswigger.net/bappstore/36238b534a78494db9bf2d03f112265c); [Retire.js](https://github.com/RetireJS/retire.js)
- [sourcemapper](https://github.com/denandz/sourcemapper)
- [BlackFan client-side prototype pollution gadgets](https://github.com/BlackFan/client-side-prototype-pollution)
- Static analysis: [CodeQL js/xss](https://codeql.github.com/codeql-query-help/javascript/js-xss/), [js/xss-through-dom](https://codeql.github.com/codeql-query-help/javascript/js-xss-through-dom/), [js/code-injection](https://codeql.github.com/codeql-query-help/javascript/js-code-injection/), [js/client-side-unvalidated-url-redirection](https://codeql.github.com/codeql-query-help/javascript/js-client-side-unvalidated-url-redirection/), [js/html-constructed-from-input](https://codeql.github.com/codeql-query-help/javascript/js-html-constructed-from-input/), [js/unsafe-jquery-plugin](https://codeql.github.com/codeql-query-help/javascript/js-unsafe-jquery-plugin/), [js/prototype-polluting-assignment](https://codeql.github.com/codeql-query-help/javascript/js-prototype-polluting-assignment/), [js/prototype-pollution-utility](https://codeql.github.com/codeql-query-help/javascript/js-prototype-pollution-utility/); [semgrep-rules](https://github.com/semgrep/semgrep-rules) (for example [insecure-document-method](https://github.com/semgrep/semgrep-rules/blob/develop/javascript/browser/security/insecure-document-method.yaml), [react-dangerouslysetinnerhtml](https://github.com/semgrep/semgrep-rules/blob/develop/typescript/react/security/audit/react-dangerouslysetinnerhtml.yaml), [angular-domsanitizer](https://github.com/semgrep/semgrep-rules/blob/develop/typescript/angular/security/audit/angular-domsanitizer.yaml), [avoid-v-html](https://github.com/semgrep/semgrep-rules/blob/develop/javascript/vue/security/audit/xss/templates/avoid-v-html.yaml), [jquery-insecure-selector](https://github.com/semgrep/semgrep-rules/blob/develop/javascript/jquery/security/audit/jquery-insecure-selector.yaml))
- Lint: [eslint-plugin-no-unsanitized](https://github.com/mozilla/eslint-plugin-no-unsanitized), eslint-plugin-react [no-danger](https://github.com/jsx-eslint/eslint-plugin-react/blob/master/docs/rules/no-danger.md) and [jsx-no-script-url](https://github.com/jsx-eslint/eslint-plugin-react/blob/master/docs/rules/jsx-no-script-url.md)
- Playwright: [dialogs](https://playwright.dev/docs/dialogs), [Page](https://playwright.dev/docs/api/class-page)
- Labs: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), [Google XSS game](https://xss-game.appspot.com/)
