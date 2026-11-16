---
title: "postMessage and Web Messaging Security"
date: 2026-11-15 22:10:00 +0000
subcategory: client-side
summary: "Testing postMessage receivers and senders: origin checks, message data in DOM sinks, wildcard targetOrigin leaks, SSO popups, channels and fixes."
refs: [WSTG-CLNT-11, WSTG-CLNT-01, v5.0.0-3.5.5, v5.0.0-3.2.2, v5.0.0-1.3.2, v5.0.0-10.1.1, v5.0.0-3.4.8, "A07:2025", "A05:2025", "A01:2025", CWE-346, CWE-940, CWE-79, CWE-201]
tags: [web, postmessage, client-side, dom-xss, oauth, browser-security]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Client-Side](/web/web-client-side-testing-guide/). It covers web messaging: `window.postMessage()` between windows, frames and popups of different origins, plus its relatives `MessageChannel`, `BroadcastChannel` and worker messages. WSTG tests it as `WSTG-CLNT-11`; ASVS 5.0 has one requirement aimed squarely at it (`v5.0.0-3.5.5`, L2: discard messages from untrusted origins or with invalid syntax). The API is the one sanctioned hole in the same-origin policy for scripts, which is why its bugs are interesting: a receiver that does not check who sent a message gives every website on the internet a way to call into the page, and a sender that addresses its message to `*` hands the content to whatever document happens to be in the target window. Both halves show up constantly in single sign-on popups, payment and chat widgets, analytics SDKs and embedded editors. You get the model (who may send, who may read, and how an attacker gets a window reference at all), the receiver-side and sender-side failures, ten tests that prove a finding with local proof-of-concept pages and harmless marker messages, and fixes in plain TypeScript, React and Angular with Playwright regression tests. When message data reaches an HTML or script sink, the sink side is the same as in [DOM XSS and client-side injection](/web/web-dom-xss-client-side-injection/); framing and `window.opener` defences are covered in more depth in [Clickjacking and reverse tabnabbing](/web/web-clickjacking-tabnabbing/) and [CSP and browser security headers](/web/web-content-security-policy-headers/).

## Contents

- [How it works](#how-it-works)
  - [Sending: targetOrigin decides who can read](#sending-targetorigin-decides-who-can-read)
  - [Receiving: origin, source and data](#receiving-origin-source-and-data)
  - [How a foreign page gets a window reference](#how-a-foreign-page-gets-a-window-reference)
  - [Other messaging channels](#other-messaging-channels)
- [What goes wrong](#what-goes-wrong)
  - [No origin check](#no-origin-check)
  - [Origin checks that can be bypassed](#origin-checks-that-can-be-bypassed)
  - [Trusting the window instead of the origin](#trusting-the-window-instead-of-the-origin)
  - [Message data in dangerous sinks](#message-data-in-dangerous-sinks)
  - [Message-driven state changes](#message-driven-state-changes)
  - [Wildcard targetOrigin on sensitive data](#wildcard-targetorigin-on-sensitive-data)
  - [Leaks in sign-in, payment and widget flows](#leaks-in-sign-in-payment-and-widget-flows)
  - [Channels that are less private than they look](#channels-that-are-less-private-than-they-look)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [Signals and false positives](#signals-and-false-positives)
  - [GT-WEB-MSG-1: Inventory message listeners and senders](#gt-web-msg-1-inventory-message-listeners-and-senders)
  - [GT-WEB-MSG-2: Establish how a foreign page can reach the target window](#gt-web-msg-2-establish-how-a-foreign-page-can-reach-the-target-window)
  - [GT-WEB-MSG-3: Review each receiver's origin and source checks](#gt-web-msg-3-review-each-receivers-origin-and-source-checks)
  - [GT-WEB-MSG-4: Send marker messages from a foreign origin](#gt-web-msg-4-send-marker-messages-from-a-foreign-origin)
  - [GT-WEB-MSG-5: Test flawed origin checks with lookalike origins](#gt-web-msg-5-test-flawed-origin-checks-with-lookalike-origins)
  - [GT-WEB-MSG-6: Trace message data into DOM XSS sinks](#gt-web-msg-6-trace-message-data-into-dom-xss-sinks)
  - [GT-WEB-MSG-7: Message-driven navigation, state and configuration changes](#gt-web-msg-7-message-driven-navigation-state-and-configuration-changes)
  - [GT-WEB-MSG-8: Wildcard targetOrigin and data sent to frames and openers](#gt-web-msg-8-wildcard-targetorigin-and-data-sent-to-frames-and-openers)
  - [GT-WEB-MSG-9: Sign-in, SSO and payment popup flows](#gt-web-msg-9-sign-in-sso-and-payment-popup-flows)
  - [GT-WEB-MSG-10: BroadcastChannel, MessageChannel and worker messages](#gt-web-msg-10-broadcastchannel-messagechannel-and-worker-messages)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [A receiver in TypeScript](#a-receiver-in-typescript)
  - [A sender with an exact targetOrigin](#a-sender-with-an-exact-targetorigin)
  - [Private channels with MessageChannel](#private-channels-with-messagechannel)
  - [React](#react)
  - [Angular](#angular)
  - [Cutting window references: COOP, frame-ancestors and noopener](#cutting-window-references-coop-frame-ancestors-and-noopener)
  - [Static analysis](#static-analysis)
  - [Regression tests](#regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Sending: targetOrigin decides who can read

Any script holding a reference to another window can call `postMessage` on it, whatever that window's origin:

```javascript
// Positional form
otherWindow.postMessage(message, targetOrigin, transfer);

// Options form
otherWindow.postMessage(message, { targetOrigin: "https://widget.example.com", transfer: [] });
```

`message` is copied with the structured clone algorithm, so it can be a string, an object, an array, a `Map`, a `Blob` and so on (WSTG still describes it as plain text; most modern code sends objects). `transfer` hands over ownership of transferable objects such as a `MessagePort`.

`targetOrigin` is the sender's only control over **who can read the message**. The browser compares it with the origin of the document that is in `otherWindow` *at the moment the message is delivered*, and silently drops the message on a mismatch. The sender gets no error and no delivery receipt.

| `targetOrigin` | Delivered to | When it is right |
|---|---|---|
| `"https://widget.example.com"` | Only a document whose origin is exactly that scheme, host and port | Almost always |
| `"/"` | Only a document with the sender's own origin | Same-origin frames and popups |
| omitted | Same as `"/"` (the HTML standard and MDN document this default) | Same as above, but write it out |
| `"*"` | Whatever document is in the window, from any origin | Only for data you would publish on a public web page, such as "I am ready" or an iframe height |

The point of an exact `targetOrigin` is not to stop the wrong window being addressed; it is to stop the message landing in the right window after it has been **navigated somewhere else**. A popup the user was sent to, an iframe whose `src` changed, an opener tab that moved on: the window object stays the same, the document inside it does not. MDN puts it bluntly: a malicious site can change the location of the window without your knowledge and then intercept data sent with `*`.

### Receiving: origin, source and data

The receiving window gets a `message` event (a `MessageEvent`):

```javascript
window.addEventListener("message", (event) => {
  event.origin; // "https://app.example.com" - set by the browser, cannot be forged by the sender
  event.source; // WindowProxy of the sending window, usable to reply
  event.data;   // whatever the sender chose to send
  event.ports;  // MessagePorts transferred with the message
});
```

Three properties, three levels of trust:

- **`event.origin`** is serialised by the browser from the sender's origin at the time `postMessage` was called: scheme, `://`, host, and `:port` only when it is not the default. No path, no trailing slash. It is the only identity the receiver can rely on. For an opaque origin (a sandboxed iframe without `allow-same-origin`, and in most browsers a page loaded from `file:`) the string is `"null"`, which any attacker can produce, so `"null"` must never be on an allow-list.
- **`event.source`** is a reference to the sending window. It tells you *which window*, not *which origin*; the same window can hold a different document a moment later (see [Trusting the window instead of the origin](#trusting-the-window-instead-of-the-origin)).
- **`event.data`** is entirely under the sender's control. Even after a correct origin check it is input from another security principal and needs validation, which is the second half of `v5.0.0-3.5.5` and of the guidance in both the HTML standard and the OWASP HTML5 Security Cheat Sheet.

The comparison has to be exact. WSTG's own receiver example compares `event.origin` with `chat.example.com` without a scheme, a check that can never match. It fails closed, but it shows how easily origin checks are written wrong, and the rest of this note is mostly about checks that fail open.

A page that does not expect messages from other origins should not register a `message` listener at all. Every listener is attack surface, including the ones third-party scripts add: analytics, error trackers, A/B testing tools, chat and consent widgets register their own, and they run with your origin's privileges.

### How a foreign page gets a window reference

Nothing happens until an attacker-controlled page holds a reference to the target window or the target holds a reference to it. Which of these paths exists decides whether a finding is exploitable, so you establish them in [GT-WEB-MSG-2](#gt-web-msg-2-establish-how-a-foreign-page-can-reach-the-target-window):

| Path | Reference | What stops it |
|---|---|---|
| Attacker page frames the target | `iframe.contentWindow` | CSP `frame-ancestors` or `X-Frame-Options` on the target response |
| Attacker page opens the target | the return value of `window.open()` | `Cross-Origin-Opener-Policy: same-origin` (or `noopener-allow-popups`) on the target, which severs the reference; popup blockers need a user click |
| Target opens the attacker page | `window.opener` inside the attacker page | `noopener` on the link or `window.open` call; COOP on the target |
| Target frames attacker-influenced content (ads, user HTML, a third-party widget) | `window.parent`, `window.top` | Not framing untrusted content, or framing it in a sandboxed iframe |
| A frame inside a page the attacker already references | `win.frames[0]`, `win.frames[1]` | Same as the outer path; nested frames are reachable through their parent |

Two consequences matter for testing. First, an attacker who frames or opens the target can also reach the target's **child frames** and, when it is the top-level page, can generally navigate them, which is how a target's own iframe can be swapped for an attacker document just before the target posts to it with `*`. Second, a framed target may not be logged in: cookies marked `SameSite=Lax` or `Strict` are not sent to a cross-site iframe, and browsers increasingly block or partition third-party cookies. A popup is a top-level window and usually carries the session. Test both paths before deciding a receiver is unreachable.

### Other messaging channels

| Channel | Who can talk | Identity available to the receiver | Typical use |
|---|---|---|---|
| `window.postMessage` | Any window holding a reference, any origin | `event.origin`, `event.source` | Frames, popups, SSO, widgets |
| `MessageChannel` / `MessagePort` | Whoever holds a port | None: possession of the port is the authority | A private pipe after a one-time handshake |
| `BroadcastChannel` | Every same-origin context that opens a channel with the same name (in browsers with storage partitioning, only within the same top-level site) | Same origin only | Cross-tab logout, session sync, cache invalidation |
| `Worker.postMessage` | The page and the dedicated worker it created | Implicit | Off-main-thread work |
| Service worker `message` events | Same-origin clients controlled by the worker | `event.source` (a client), `event.origin` | Cache control, push handling |
| `window.name` | The next document loaded in the same window or frame | None | Legacy cross-domain transport; avoid |

WebSockets and server-sent events are network protocols, not in-browser messaging; their origin problem (CWE-1385, *Missing Origin Validation in WebSockets*) belongs to the HTTP and infrastructure part of the series, which is not yet published.

## What goes wrong

### No origin check

The listener processes `event.data` without looking at `event.origin`:

```javascript
// Vulnerable: any website that frames or opens this page can drive it
window.addEventListener("message", (event) => {
  const msg = typeof event.data === "string" ? JSON.parse(event.data) : event.data;
  if (msg.type === "render") document.getElementById("panel").innerHTML = msg.html;
  if (msg.type === "navigate") location.href = msg.url;
});
```

Why it matters: the message is a cross-origin call into your page that the browser lets through by design. Whatever the handler does (render HTML, navigate, store a token, change settings) any website can make it do. Where to look: listeners in your own bundles, but just as often in third-party SDKs loaded on every page (form builders, analytics, consent banners, chat widgets), and in pages that are themselves meant to be embedded (`/embed`, `/widget`, `/frame`, editor and preview pages). PMForce (Steffens and Stock, CCS 2020) studied handlers on the top 100,000 sites and reported 252 handlers with potentially exploitable flows, 111 automatically confirmed; Son and Shmatikov found the same pattern in the Alexa top 10,000 back in 2013. The bug class has not gone away.

### Origin checks that can be bypassed

A check exists but does not mean what the developer thinks. These are the patterns you will see (all of them have been reported against real products):

| Check | Intended to allow | Also allows | Why |
|---|---|---|---|
| `event.origin.indexOf("example.com") > -1` / `.includes(...)` | `https://app.example.com` | `https://app.example.com.example.org`, or any host containing the string | Substring anywhere |
| `event.origin.startsWith("https://app.example.com")` | that origin | `https://app.example.com.example.org`, `https://app.example.com:8443` | No end anchor; host can continue |
| `event.origin.endsWith("example.com")` | subdomains of `example.com` | `https://<anything>example.com`, a different registrable domain the attacker can buy | No dot boundary |
| `event.origin.endsWith(".example.com")` | subdomains | every subdomain, including user-content hosts, forgotten staging hosts and takeover candidates | Correct syntax, too broad a trust boundary |
| `/^https:\/\/app.example.com$/.test(event.origin)` | that origin | `https://app<any character>example.com` | Unescaped `.` matches any character |
| `/https:\/\/app\.example\.com/.test(event.origin)` | that origin | `https://app.example.com.example.org` | No `^` and `$` anchors |
| `event.origin.match("app.example.com")`, `.search(...)` | that origin | `https://app<any character>example.com`, and any origin containing the pattern | A string argument is turned into a regular expression, unanchored |
| `expected.indexOf(event.origin) === 0` where `expected` is a full URL | `https://forms.example.com` | any origin that is a string prefix of the expected URL, such as a short domain under another top-level domain whose name matches the start of the host | Reversed comparison; this exact bug bypassed a fix on hackerone.com (see [Real-world cases](#real-world-cases)) |
| `allowed.includes(event.origin)` with `"null"` in the list | sandboxed or `file:` documents | any attacker using a sandboxed iframe | `"null"` is not an identity |
| `event.origin === document.referrer` or compared with `location.ancestorOrigins` | "whoever embedded us" | the attacker's page when the attacker embeds you | Trusting the embedder is trusting the attacker |
| `event.data.origin === "https://app.example.com"` | that origin | anyone | The checked field is part of the attacker's message |
| Check that logs but does not `return` | that origin | anyone | The code after the `if` still runs |
| An `http://` origin on the allow-list | the HTTP site | a network attacker who injects into the HTTP site | No TLS, no identity |

The DOM Invader documentation describes its own origin-spoofing test as using a fake origin that *starts and ends with* the expected domain, which tells you how common the `startsWith` and `endsWith` variants are. Microsoft's MSRC described the subdomain-wildcard variant in 2025: allow-lists such as `*.azurewebsites.net` or `*.sharepoint.com` turn any attacker-controlled or compromised host in that space into a trusted sender.

### Trusting the window instead of the origin

Some receivers check `event.source` only:

```javascript
// Weak: the iframe's WindowProxy stays the same when its document changes
if (event.source !== paymentFrame.contentWindow) return;
```

This proves the message came from that frame, not that the frame still holds the payment provider's document. If an attacker can navigate the frame (because the attacker is the top-level page framing your app, or because the frame `src` is built from a URL parameter), the check passes for the attacker's document. Checking `event.source` **in addition to** an exact `event.origin` is good practice for frame-to-frame protocols; on its own it is a finding. Comparing `event.source` with `window.parent` or `window.opener` has the same problem when the attacker is the parent or opener. Code that tries to read `event.source.location.href` throws for a cross-origin sender, and code that catches the exception and carries on has no check at all.

### Message data in dangerous sinks

Once a message is accepted, its data is a DOM XSS source like `location.hash`. The sinks are the usual ones from [DOM XSS and client-side injection](/web/web-dom-xss-client-side-injection/):

| Sink | Example | Outcome |
|---|---|---|
| HTML | `el.innerHTML = msg.html`, `insertAdjacentHTML`, `document.write`, jQuery `$(msg.html)`, `.html()`, `.append()` | Script execution through event-handler attributes |
| Script | `eval(msg.code)`, `new Function(msg.code)`, `setTimeout(msg.code)` with a string | Direct execution (CWE-95) |
| URL | `location.href = msg.url`, `location.assign`, `window.open(msg.url)`, `iframe.src`, `script.src` | Open redirect, or execution with a `javascript:` URL, or loading an attacker script |
| Framework escape hatches | React `dangerouslySetInnerHTML`, Angular `bypassSecurityTrustHtml` / `bypassSecurityTrustResourceUrl`, Vue's raw-HTML directive | The framework's escaping is switched off |
| Object merge | `Object.assign(config, msg)`, `_.merge(state, msg)`, recursive merges of parsed JSON | Prototype pollution (CWE-1321) that later reaches a sink |
| Storage | `localStorage.setItem("theme", msg.theme)` read later into a sink | Stored, cross-session DOM XSS |
| Requests | `fetch(msg.endpoint, { credentials: "include" })` | Client-side request forgery against your own API |

A correct origin check does not make these safe. The OWASP HTML5 Security Cheat Sheet points out that one XSS flaw on the trusted sender lets an attacker send messages of any format, so an allow-listed partner with a bug becomes your bug. ASVS `v5.0.0-3.2.2` (L1) asks for text-only rendering functions such as `textContent` for data meant as text, and `v5.0.0-1.3.2` (L1) asks you to avoid `eval()`.

### Message-driven state changes

Not every finding is script execution. Many message protocols carry commands:

- **Session and identity.** `{type: "login", token: …}` stored as the user's token logs the victim into an account the attacker controls (login CSRF through messaging), or swaps an access token used for later API calls. ASVS `v5.0.0-10.1.2` (L2) requires OAuth clients to accept codes and tokens only from flows the same user agent started.
- **Configuration.** `{type: "init", apiBase: "https://…"}` that sets the API base URL sends every later request, with its bearer token, to the attacker's host.
- **Navigation.** `{type: "redirect", url: …}` is a client-side open redirect at best (CWE-601; ASVS `v5.0.0-3.7.2`, L2) and DOM XSS when `javascript:` URLs get through.
- **Actions.** Messages that submit a form, accept a consent, start a payment, add a collaborator or change a setting are cross-site request forgery without the request: the victim's own page performs the action.
- **Harmless by design.** `{type: "resize", height: 812}` that sets an iframe's height is usually just UI. It becomes interesting only if the value reaches a style string or an HTML sink.

### Wildcard targetOrigin on sensitive data

The sender-side bug is the mirror image:

```javascript
// Vulnerable: whatever document is in the opener receives the token
window.opener.postMessage({ type: "auth", accessToken, user }, "*");

// Vulnerable: the iframe may have been navigated to another origin
iframe.contentWindow.postMessage({ type: "config", apiKey, sessionId }, "*");

// Vulnerable: reflects the embedder, which is whoever frames the page
parent.postMessage({ type: "profile", email }, document.referrer || "*");
```

Why it matters: the data goes to whoever controls the document in that window, and the attacker usually does. If the attacker opened the popup, `window.opener` is the attacker's page. If the attacker framed your page, `parent` is the attacker's page. If your page frames a widget and the attacker is the top-level page, the attacker can navigate that widget frame before you post to it. CodeQL's `js/cross-window-information-leak` query exists for exactly this pattern and maps it to CWE-201 (*Insertion of Sensitive Information Into Sent Data*) and CWE-359. ASVS `v5.0.0-10.1.1` (L2) states the design rule for tokens: send them only to components that strictly need them. MSRC's 2025 write-up describes two such cases in Microsoft services, one sending an access token scoped for user impersonation to a Marketplace iframe with `*`.

Deriving `targetOrigin` from `document.referrer`, `location.ancestorOrigins`, a `?origin=` URL parameter or `event.origin` of an unchecked earlier message is the same bug written more politely: the attacker chooses the value.

### Leaks in sign-in, payment and widget flows

Popup and iframe flows are where sender-side bugs carry the most impact:

- **OAuth and SSO popups.** The site opens the identity provider in a popup; the callback page posts the code, token or session to `window.opener`. If the callback page uses `*`, any page that opens the login popup (or the callback URL directly) receives the credential. The DISTINCT study (Jannett, Mladenov, Mainka and Schwenk, CCS 2022) found dual-window SSO on 56% of the top 1,000 sites, many implemented without the official SDKs, and identity theft or XSS in 31% of the self-implemented ones.
- **URL leaks.** Frans Rosén's 2022 Detectify research on "dirty dancing" in OAuth flows shows the other route: force the flow onto an error page so the code stays in the URL, then use a postMessage "gadget" on the same origin to leak `location.href`. His gadgets include an analytics SDK listener that returned the page URL to any origin, a storage iframe that synced the last URL to any parent, and a chat widget whose API token was exposed through postMessage.
- **Payment widgets.** The page and the provider's iframe exchange card-tokenisation results, order totals and 3-D Secure status. A wildcard sender leaks tokens and personal data; an unchecked receiver lets a foreign page report "payment succeeded".
- **Chat, support and analytics widgets.** They often post the current URL, user identifiers, email addresses or JWT-style identity tokens into their iframe, and accept configuration from the parent.
- **Relays.** A page that forwards any message it receives to another frame, or to its opener, turns one weak hop into a chain.

Report the flaw against the component that has it. A wildcard sender in a vendor SDK is the vendor's bug and your client's exposure: tell the client, and let them involve the vendor.

### Channels that are less private than they look

- **`BroadcastChannel`** is same-origin only, so it cannot be reached from another site. Its weakness is that it trusts the whole origin: every page, legacy endpoint, user-uploaded HTML file served from the origin, and XSS anywhere on the origin can post `{"type":"logout"}` or read `{"type":"token-refreshed","token":…}`. Session tokens on a broadcast channel spread the impact of an XSS on a minor page to the main application.
- **`MessageChannel`** is private by construction, but the handshake that hands over the port is a normal `postMessage`. A port sent with `*` goes to whoever is in the frame; a receiver that accepts a port from any origin talks privately to the attacker from then on.
- **Workers and service workers** are same-origin, but a service worker that acts on `message` events (cache purges, URL fetches, client navigation) is reachable from every page of the origin, including ones with weaker defences.
- **`window.name`** survives navigations within a frame and is readable by the next document loaded there. MDN notes that modern browsers reset it when a top-level tab moves to a different domain, but frame names set by a parent are still visible to whatever loads in the frame, which is how one of Rosén's gadgets read a URL from an iframe name. Treat any data in `window.name` as public.
- **`window.opener`** gives a popup a reference back to the page that opened it; the navigation abuse of that reference (reverse tabnabbing) is covered in [Clickjacking and reverse tabnabbing](/web/web-clickjacking-tabnabbing/). Here it matters as a messaging path.

## Testing

### Before you start

**Authorisation.** Every test here assumes an authorised engagement with written scope and rules of engagement, a bug bounty programme whose rules allow client-side testing, or a deliberately vulnerable lab. Confirm in writing that local proof-of-concept pages and framing or opening the application in your own browser are in scope.

**Accounts.** You test in **your own session**: a test account (two, if you need to show that a message changes state for one user and not another) on staging where the client offers it. Every proof shows a cross-origin page affecting *your* logged-in window. You never send a proof page to anyone else, and you never host one where real users could open it.

**Proof-of-concept pages are local.** Keep them in a folder on your machine and serve them from loopback so they get a real, foreign origin:

```bash
mkdir -p ~/gt-poc && cd ~/gt-poc
python3 -m http.server 8000 --bind 127.0.0.1
# PoC origin seen by the target: http://127.0.0.1:8000
```

A PoC page frames or opens the target, sends **marker messages** (`{"type":"GT-MSG-4"}`, a text marker such as `GT-MSG-6`, or when you need to prove script execution, `print()` or `alert(document.domain)`), and writes whatever it receives into its own page. It sends nothing to any other host: no `fetch`, no image beacons, no logging endpoint. A page opened from `file:` has the origin `"null"` in most browsers, which is useful for one specific check in [GT-WEB-MSG-5](#gt-web-msg-5-test-flawed-origin-checks-with-lookalike-origins) and confusing for everything else, so serve from loopback by default.

**What you may not do.** No payloads that read or transmit cookies, tokens, storage or page content; no messages that perform real transactions (payments, invites, deletions) except against your own test objects; no fuzzing of third-party iframes (payment providers, chat vendors, identity providers) unless they are explicitly in scope. You may *observe* messages those frames exchange with the target, because that traffic is in your own browser.

**Stop on real data.** If a message you receive contains anything other than your own test account's data (another customer's details, staff data, production secrets), stop, keep only the minimum redacted evidence, do not store the rest, and report it to the client immediately.

**Received tokens.** In sender-side tests you will often capture your own access token or authorisation code. Show it in the PoC page, screenshot it with most of the value masked, and invalidate it afterwards (log out, revoke the session, or ask the client to). Do not paste it into reports or chat tools.

**Tooling.**

- Burp Suite's built-in browser with **DOM Invader** and its web message features switched on (the switch is called *Postmessage interception*; reload the page after enabling it). Its *Postmessage origin spoofing*, *Canary injection into intercepted messages* and *Generate automated messages* settings change and send messages to the page, so use them only in your own session and on environments where changed state is acceptable.
- A separate Chrome profile with Frans Rosén's **postMessage-tracker** extension, which counts listeners per window and frame and shows where they were registered. Leave its *Log URL* option empty: it would send listener code to that URL.
- Chrome DevTools Console utilities `getEventListeners(window)` and `monitorEvents(window, "message")` (they only work when typed into the Console, not from page scripts), and the Sources panel's *Global Listeners* and *Event Listener Breakpoints* panes.
- Playwright, for a repeatable harness that serves lookalike origins locally (see [GT-WEB-MSG-5](#gt-web-msg-5-test-flawed-origin-checks-with-lookalike-origins) and [Regression tests](#regression-tests)).

Outputs shown in this note are illustrative.

### Signals and false positives

| Signal | What it usually means | Rule it out before reporting |
|---|---|---|
| A `message` listener exists | Attack surface, not a finding | Read the handler; many only handle their own SDK's messages and check origin correctly |
| Listener never reads `event.origin` (DOM Invader: origin not accessed) | Likely no origin check | Confirm that a message from your PoC origin actually reaches the code after the check point |
| Your marker appears in the target's DOM | Data reaches a sink | Is it rendered as text (`textContent`) or as HTML? Text is not XSS |
| The target posts with `*` | Possible leak | What is in the message? An iframe height or "ready" event is not sensitive |
| Messages in DOM Invader that you did not send | Normal chatter | Browser extensions (password managers, developer tools, grammar checkers), development-server hot-reload messages and widget heartbeats all show up; disable extensions in the test profile |
| Message accepted in the iframe path but the frame is logged out | Real flaw, maybe limited reachability | Try the popup path, which is a top-level window with the session |
| A check against an allow-list of many subdomains | Possibly too broad | Only a finding if one of those hosts can be attacker-controlled (user content, takeover, XSS); otherwise a hardening note |

### GT-WEB-MSG-1: Inventory message listeners and senders

*Guler Tech methodology.* Implements the static code analysis step of WSTG-CLNT-11 (find the message event listeners and their callbacks) and extends it to senders and to third-party scripts.

#### What it checks

Every place the application receives or sends cross-window messages, on every page type, including listeners registered by third-party scripts and inside iframes. The output is the work list for tests 3 to 10.

#### Prerequisites

Your test account; Burp's browser with DOM Invader; the postMessage-tracker profile; access to the JavaScript bundles (and source maps, if the client provides them or they are public).

#### Steps

1. Walk the application with postMessage-tracker enabled. Visit page types, not just pages: login and SSO callback pages, embedded or widget pages (`/embed`, `/widget`, `/frame`, `/iframe`, `/preview`), editors, checkout and payment steps, help and chat, account settings, admin areas in scope. Note the listener count per window and per frame.
2. In each interesting window, list listeners from the DevTools Console. For an iframe, first select the frame's context in the Console's context drop-down:

```javascript
getEventListeners(window).message
// [{listener: ƒ (e), useCapture: false, passive: false, once: false, type: "message"}, ...]
```

Right-click the listener function and choose to show the function definition to jump to its source, or use the Sources panel's *Global Listeners* pane. Libraries wrap handlers (jQuery, error-tracking SDKs); postMessage-tracker unwraps several common wrappers and shows the real function.

3. With DOM Invader's *Postmessage interception* on, use the features normally and watch the *Messages* view: which messages arrive, from which origin, with what data, and whether the page code accessed `origin`, `data` and `source`.
4. Search the bundles for receivers and senders. Download the scripts you were served (from Burp's HTTP history or the browser's Sources panel) into a working folder and grep:

```bash
# Receivers
grep -rnoE "addEventListener\(\s*['\"]message['\"]|onmessage\s*=|\\\$\(window\)\.on\(\s*['\"]message|fromEvent\([^)]*['\"]message" ./bundles | head -50

# Senders, and wildcard senders in particular
grep -rnoE "\.postMessage\([^;]{0,200}" ./bundles | head -100
grep -rnoE "postMessage\([^;]{0,200}['\"]\*['\"]" ./bundles

# Other channels
grep -rnoE "new (BroadcastChannel|MessageChannel|SharedWorker|Worker)\(|navigator\.serviceWorker\.controller\.postMessage|window\.name\s*=" ./bundles
```

5. For each listener, record: page, window or frame, script file and owner (first party or vendor), message types it handles (`msg.type`, `msg.action`, `msg.event` switch cases), and whether it reads `origin` and `source`. For each sender: target window (`parent`, `opener`, `iframe.contentWindow`, `top`), `targetOrigin`, and the fields sent.

#### Observation

An inventory like this (illustrative):

| Page | Window | Listener or sender | Script | Origin read | Handles / sends |
|---|---|---|---|---|---|
| `/editor/42` | top | listener | `app.4f1c.js` (first party) | yes | `preview:update`, `preview:resize` |
| `/embed/editor` | iframe | listener | `embed.9b2e.js` (first party) | no | `init`, `render`, `navigate` |
| `/checkout` | top | sender to payment iframe | `checkout.js` | n/a | `{amount, currency, customerEmail}` to `"*"` |
| `/oauth/callback` | popup | sender to `window.opener` | inline | n/a | `{code, state}` to `"*"` |
| all pages | top | listener | vendor chat SDK | yes | `chat:open`, `chat:identify` |
| all pages | top | `BroadcastChannel("session")` | `app.4f1c.js` | n/a | `logout`, `token-refreshed` |

#### Evaluation

No finding by itself. A listener that does not read `event.origin` and an inline sender with `*` are the leads for tests 3 and 8.

#### False positives

Listeners added by your own browser extensions, development tooling present only on local builds, and listeners that exist but are unreachable because the page cannot be framed or opened by another origin (decided in test 2).

#### Automation

postMessage-tracker and DOM Invader for runtime discovery; CodeQL and Semgrep for source discovery (see [Static analysis](#static-analysis)). In CI, keep a list of approved listeners and senders and fail the build when a new `addEventListener("message"` or `postMessage(` call site appears without review.

### GT-WEB-MSG-2: Establish how a foreign page can reach the target window

*Guler Tech methodology.* Supports WSTG-CLNT-11 by establishing the delivery paths that make a messaging flaw exploitable; uses the framing checks of WSTG-CLNT-09 and the opener checks of WSTG-CLNT-14.

#### What it checks

For each page from the inventory, whether another origin can obtain a window reference to it (framing, opening, being opened by it, or a child frame), and whether the target is logged in on that path. This decides reachability and therefore the rating of everything that follows.

#### Prerequisites

The inventory from test 1; the local PoC server.

#### Steps

1. Read the framing and opener headers on each page's HTML response:

```bash
curl -s -D - -o /dev/null -b 'session=<SESSION_USER_A>' https://app.example.com/embed/editor \
  | grep -iE '^(content-security-policy|x-frame-options|cross-origin-opener-policy):'
```

2. Save this page as `~/gt-poc/msg2.html` and open `http://127.0.0.1:8000/msg2.html` in the browser where you are logged in. It tries both paths and only reports locally:

```html
<!doctype html>
<meta charset="utf-8">
<title>GT-MSG-2 reachability (local)</title>
<p>Target: <input id="url" size="70" value="https://app.example.com/embed/editor"></p>
<button id="frame">Frame it</button>
<button id="open">Open it in a popup</button>
<pre id="log"></pre>
<script>
  const log = (m) => { document.getElementById("log").textContent += m + "\n"; };
  document.getElementById("frame").onclick = () => {
    const f = document.createElement("iframe");
    f.src = document.getElementById("url").value;
    f.width = 900; f.height = 500;
    f.onload = () => log("iframe load event fired (check visually: blank or error page means framing is blocked)");
    document.body.appendChild(f);
  };
  document.getElementById("open").onclick = () => {
    const w = window.open(document.getElementById("url").value, "gt_target");
    setTimeout(() => log(w && !w.closed ? "popup reference usable" : "popup reference severed or blocked"), 3000);
  };
</script>
```

3. In the framed copy, check whether you are logged in (your account name visible, or the page shows the login form). Repeat in the popup.
4. For pages that open other windows or frame other content, note whether the reverse paths exist: links with `target="_blank"` or `window.open` calls without `noopener` to user-controlled or third-party URLs, and iframes that load user-supplied or vendor URLs.

#### Observation

| Page | Framable cross-site | Logged in when framed | Popup reference usable | Opens or frames untrusted content |
|---|---|---|---|---|
| `/editor/42` | no (`frame-ancestors 'self'`) | n/a | yes (no COOP) | no |
| `/embed/editor` | yes (no `frame-ancestors`) | no (`SameSite=Lax` session) | yes | no |
| `/oauth/callback` | no | n/a | n/a (opened by the app) | posts to opener |

#### Evaluation

No finding by itself; record which path each later finding uses. A page that **must** not be framed and is framable is a clickjacking finding for [Clickjacking and reverse tabnabbing](/web/web-clickjacking-tabnabbing/). Missing COOP on sensitive pages is a hardening item against `v5.0.0-3.4.8` (L3).

#### False positives

An `onload` event fires even when the browser refuses to render a framed page, so judge framing by what you see, not by the event. Popup blockers block `window.open` without a click; the PoC uses buttons for that reason.

#### Automation

The header check is a one-line test per route in CI. A Playwright test can assert that `frame-ancestors` and COOP are present on every HTML response that handles messages.

### GT-WEB-MSG-3: Review each receiver's origin and source checks

*Guler Tech methodology.* Implements "Examine Origin Security" and the static analysis part of WSTG-CLNT-11 for each listener in the inventory.

#### What it checks

Whether each listener rejects messages from origins it should not trust, using an exact comparison, before doing anything with the data.

#### Prerequisites

The inventory; readable source (pretty-printed bundles or source maps).

#### Steps

1. Open each listener in the Sources panel, pretty-print it, and find the first use of `event.data`. Everything executed before a correct origin check is reachable by any origin.
2. Classify the check against the table in [Origin checks that can be bypassed](#origin-checks-that-can-be-bypassed):

```javascript
// None
handler = (e) => route(e.data);

// Flawed: prefix, substring, suffix without boundary, unanchored or unescaped regex
if (e.origin.startsWith("https://app.example.com")) route(e.data);
if (/^https:\/\/.*\.example\.com$/.test(e.origin)) route(e.data);  // anchored, but trusts every subdomain

// Window only
if (e.source === window.parent) route(e.data);

// Correct
const ALLOWED = new Set(["https://app.example.com", "https://widget.example.com"]);
if (!ALLOWED.has(e.origin)) return;
```

3. Where the allow-list comes from configuration or a server response, find where it is built: a list fetched from an API, a `data-allowed-origins` attribute, or a URL parameter (`?parentOrigin=`) that the attacker can set when framing the page.
4. Check what runs *before* the check: `JSON.parse` followed by a merge into global state, logging that writes data into the DOM, or another listener in a different script that handles the same message type without a check.
5. Note subdomain trust (`endsWith(".example.com")`, `*.example.com` patterns). List which subdomains exist and whether any serve user content, run third-party platforms, or point to deprovisioned resources; that list goes in the report even if you cannot prove control of one.

#### Observation

Per listener: check type (none / flawed / window-only / broad subdomain / exact), the exact expression, and what the handler does after it (illustrative):

| Listener | Check | Expression | After the check |
|---|---|---|---|
| `/embed/editor` `embed.9b2e.js:1:48211` | none | n/a | `render` to `innerHTML`, `navigate` to `location.href` |
| `/editor/42` `app.4f1c.js:1:90233` | flawed | `e.origin.indexOf("example.com") !== -1` | `preview:update` to state store |
| vendor chat SDK | exact | `e.origin === "https://chat.example.net"` | UI only |

#### Evaluation

- **Fail:** no origin check, or a check from the bypassable table, on a listener whose handler does anything beyond cosmetic UI. Confirm with tests 4 and 5 before rating; a static finding alone is reported as such.
- **Fail (lower):** exact origin check but no validation of `event.data` before it reaches a sink or a state change (`v5.0.0-3.5.5` requires both). Exploitable only through a bug on the trusted sender, so rate as hardening unless you find that bug.
- **Pass:** exact match against a fixed allow-list before any processing, plus a schema check of the data.

#### False positives

Listeners that only act on messages from their own frame through a `MessagePort` after a correct handshake; handlers whose only effect is to set an iframe's height from a number.

#### Automation

CodeQL's `js/missing-origin-check` and Semgrep's `insufficient-postmessage-origin-validation` find the "none" case; the flawed variants need review or a custom rule that flags `indexOf`, `includes`, `startsWith`, `endsWith`, `match` and `search` applied to `.origin`.

### GT-WEB-MSG-4: Send marker messages from a foreign origin

*Guler Tech methodology.* Implements the dynamic side of "Examine Origin Security" in WSTG-CLNT-11: prove that a message from an untrusted origin is processed.

#### What it checks

Whether a listener processes a message from an origin it has no reason to trust, using the reachability path from test 2.

#### Prerequisites

A listener with no or doubtful origin check; a reachability path; the target's message format (from DOM Invader's *Messages* view or the handler's `switch` statement).

#### Steps

1. In the target window, open DevTools, select the right frame context, and start logging message events, or set a breakpoint on the first line after the origin check:

```javascript
monitorEvents(window, "message")
```

2. Save `~/gt-poc/msg4.html`, adjust `TARGET` and the marker to match the handler's format, and open it from `http://127.0.0.1:8000/msg4.html`:

```html
<!doctype html>
<meta charset="utf-8">
<title>GT-MSG-4 marker sender (local)</title>
<button id="frame">Frame target</button>
<button id="open">Open target</button>
<button id="send">Send marker</button>
<pre id="log"></pre>
<script>
  const TARGET = "https://app.example.com/embed/editor";
  const TARGET_ORIGIN = new URL(TARGET).origin;
  const log = (m) => { document.getElementById("log").textContent += m + "\n"; };
  let win = null;

  document.getElementById("frame").onclick = () => {
    const f = document.createElement("iframe");
    f.src = TARGET; f.width = 900; f.height = 500;
    document.body.appendChild(f);
    win = f.contentWindow;
  };
  document.getElementById("open").onclick = () => { win = window.open(TARGET, "gt_target"); };

  document.getElementById("send").onclick = () => {
    if (!win) { log("frame or open the target first"); return; }
    // A harmless, visible marker in the format the handler expects
    const marker = { type: "render", html: "GT-MSG-4 marker from " + location.origin };
    // Exact targetOrigin: the marker only goes to the target, never to anything else in that window
    win.postMessage(marker, TARGET_ORIGIN);
    log("sent: " + JSON.stringify(marker));
  };

  // Display anything the target sends back, locally only
  window.addEventListener("message", (e) => log("received from " + e.origin + ": " + JSON.stringify(e.data)));
</script>
```

3. Click *Frame target* (or *Open target*), wait for the page to load, then *Send marker*. If the handler expects a handshake first (an `init` or `ready` exchange), send that message first, mirroring what the legitimate parent sends.
4. Check the target: the marker text visible in the page, the breakpoint hit past the origin check, or the `monitorEvents` log showing the event followed by the handler's effect.

#### Observation

Vulnerable (illustrative): the marker text appears in the editor's preview panel and the Console shows the event with `origin: "http://127.0.0.1:8000"`.

```text
message MessageEvent {isTrusted: true, data: {type: "render", html: "GT-MSG-4 marker from http://127.0.0.1:8000"}, origin: "http://127.0.0.1:8000", ...}
```

Correct: the event arrives (the browser always delivers it), but the handler returns before using the data, and nothing changes in the page.

#### Evaluation

- **Fail:** the handler acts on a message from your loopback origin. Rate by what the handler then does (tests 6 and 7) and by the reachability path from test 2.
- **Pass:** no effect, and the breakpoint shows the handler returning at the origin check.

#### False positives

The event appearing in `monitorEvents` is not a finding: delivery is the browser's job, filtering is the handler's. A visible change caused by a different listener (for example a vendor SDK that also listens and logs) is not the listener you are testing.

#### Automation

DOM Invader's message replay (edit the *Data* field, click *Send*) does this inside the page; its *Build PoC* button produces a starting HTML page, which you should rewrite to the local, display-only pattern above. The [Regression tests](#regression-tests) section turns this PoC into a Playwright test.

### GT-WEB-MSG-5: Test flawed origin checks with lookalike origins

*Guler Tech methodology.* Implements the origin-check bypass analysis of WSTG-CLNT-11 (the `indexOf` example) dynamically, for every flawed pattern found in test 3.

#### What it checks

Whether a listener with a flawed check accepts a message from an origin crafted to satisfy the check but not owned by the trusted party, without registering any domain: the lookalike origins exist only inside your own browser.

#### Prerequisites

A listener with a check from the bypassable table; a reachability path; Playwright installed locally, or DOM Invader.

#### Steps

1. **Quick look with DOM Invader.** Turn on *Postmessage origin spoofing*. DOM Invader rewrites the origin of intercepted messages to a fake one that starts and ends with the real domain and flags handlers that still process them. Treat its result as a lead; it tests the pattern, you still need a reproducible proof.
2. **Reproducible proof with locally served lookalikes.** Playwright's `route.fulfill()` answers a request without touching the network, so a PoC page can be "served" from any origin you name. Save your logged-in test session first (`await context.storageState({ path: "gt-test-user-a.json" })` after logging in manually), then run this harness. It generates lookalikes from the origin the listener intends to trust, frames the target from each one, sends one marker, and reports whether the marker rendered:

```typescript
// gt-msg5-lookalikes.mts  (run: npx tsx gt-msg5-lookalikes.mts; .mts allows top-level await)
import { chromium } from "playwright";

const TARGET = "https://app.example.com/embed/editor";
const TRUSTED = new URL("https://app.example.com"); // the origin the listener means to trust
const MARKER = "GT-MSG-5";

function lookalikes(trusted: URL): string[] {
  const host = trusted.hostname;                          // app.example.com
  const site = host.split(".").slice(-2).join(".");       // example.com
  const out = new Set<string>([
    `https://${host}.attacker.test`,                      // startsWith, indexOf, unanchored regex
    `https://x${site}`,                                   // endsWith without a dot boundary
    `http://${host}`,                                     // scheme not checked
    `https://${host}:8443`,                               // port not checked
  ]);
  [...host].forEach((c, i) => {                           // unescaped dots in a regex
    if (c === ".") out.add(`https://${host.slice(0, i)}x${host.slice(i + 1)}`);
  });
  return [...out];
}

const browser = await chromium.launch({ headless: false });
const context = await browser.newContext({ storageState: "gt-test-user-a.json" });

for (const origin of lookalikes(TRUSTED)) {
  const page = await context.newPage();
  // Only the PoC origin is fulfilled locally; the target loads normally
  await page.route(`${origin}/**`, (route) =>
    route.fulfill({
      contentType: "text/html",
      body: `<!doctype html><iframe id="t" src="${TARGET}" width="900" height="500"></iframe>`,
    }),
  );
  await page.goto(`${origin}/poc.html`);
  const frame = await (await page.waitForSelector("#t")).contentFrame();
  await frame!.waitForLoadState("load");

  await page.evaluate(([target, marker]) => {
    const t = document.getElementById("t") as HTMLIFrameElement;
    t.contentWindow!.postMessage({ type: "render", html: marker }, new URL(target).origin);
  }, [TARGET, `${MARKER} from ${origin}`]);

  await page.waitForTimeout(1000);
  const accepted = (await frame!.getByText(MARKER).count()) > 0;
  console.log(`${accepted ? "ACCEPTED" : "rejected"}  ${origin}`);
  await page.close();
}
await browser.close();
```

3. If the listener needs the session and the framed target is logged out (cross-site iframe, `SameSite` cookies), change the PoC body to open the target with `window.open` and post to the returned window instead.
4. Test `"null"` separately: open your PoC page from `file:` (double-click the file) or from inside a sandboxed iframe, and send the same marker. A listener that accepts it has `"null"` on its allow-list or a check that a missing origin passes.
5. For broad subdomain trust (`*.example.com`) you cannot prove control of a subdomain you do not own. Report the trust boundary and list candidate hosts (user-content hosts, third-party platforms on client subdomains, dangling DNS records found during reconnaissance) without trying to take any of them over.

#### Observation

Illustrative harness output for `e.origin.indexOf("example.com") !== -1`:

```text
ACCEPTED  https://app.example.com.attacker.test
ACCEPTED  https://xexample.com
ACCEPTED  http://app.example.com
ACCEPTED  https://app.example.com:8443
ACCEPTED  https://appxexample.com
rejected  https://app.examplexcom
```

#### Evaluation

- **Fail:** any lookalike accepted that the trusted party does not control. The finding is the flawed check; its severity follows from what the handler does (tests 6 and 7). Note in the report what an attacker would need in reality: registering a domain is cheap and needs no victim interaction; an `http://` origin needs a network position; a subdomain needs a separate vulnerability.
- **Pass:** every lookalike rejected, and the legitimate sender still works.

#### False positives

A route-fulfilled origin is real to the browser, so acceptance is real. The `http://` and port variants are findings only if those origins are not controlled by the same party; an allow-list including `http://` is still a weakness because of network attackers.

#### Automation

Keep the `lookalikes()` generator as a unit test for the origin-check function itself (see [Regression tests](#regression-tests)): a table of lookalikes that must be rejected catches every pattern above in milliseconds.

### GT-WEB-MSG-6: Trace message data into DOM XSS sinks

*Guler Tech methodology.* Implements "Examine Input Validation" in WSTG-CLNT-11 and the web-message source of WSTG-CLNT-01 (DOM-based XSS); WSTG-CLNT-02 (JavaScript execution) where data reaches `eval` or a `javascript:` URL.

#### What it checks

Whether data from an accepted message (from any origin, or from a lookalike) reaches an HTML, script or URL sink and is interpreted, not just displayed.

#### Prerequisites

A listener that accepts messages from your PoC origin (test 4 or 5), or one with a correct check whose data reaches a sink (report that separately as a hardening issue); the handler code.

#### Steps

1. Follow `event.data` through the handler to every sink. DOM Invader's canary injection does this automatically: it puts its canary into the message in the format the page expects and reports the sinks it reaches with a stack trace. Note the sink and what happens to the data on the way (`JSON.parse`, string concatenation, a template, a property lookup).
2. Prove HTML interpretation with a non-executing marker first. Send it in the expected format from the PoC page of test 4:

```javascript
win.postMessage({ type: "render", html: "<b id=gt-msg-6>GT-MSG-6</b>" }, TARGET_ORIGIN);
```

Rendered as bold text (and `document.getElementById("gt-msg-6")` exists in the target's Console) means HTML injection. Shown with the tags visible means the sink treats it as text: pass for this sink.

3. Only if HTML is interpreted and the engagement allows execution proofs, send a single harmless execution marker for the sink type:

```javascript
// HTML sink
win.postMessage({ type: "render", html: "<img src=x onerror=print()>" }, TARGET_ORIGIN);
// URL sink (location.href, window.open, iframe.src)
win.postMessage({ type: "navigate", url: "javascript:print()" }, TARGET_ORIGIN);
// Script sink (eval, Function, string setTimeout)
win.postMessage("print()", TARGET_ORIGIN);
// String message parsed as JSON by the handler
win.postMessage(JSON.stringify({ type: "load-channel", url: "javascript:print()" }), TARGET_ORIGIN);
```

4. If execution is blocked, find out why: a CSP that forbids inline handlers and `javascript:` URLs, Trusted Types, or a sanitiser. Record the console's CSP violation message. Do not try a list of bypass variants; whether the policy itself is weak is a question for [CSP and browser security headers](/web/web-content-security-policy-headers/).
5. For sinks that load a script or frame (`script.src`, `iframe.src`), show that the URL is attacker-chosen by pointing it at a file on your loopback server that only calls `print()`, and observe the request in DevTools. Do not host anything on the internet for this.

#### Observation

Vulnerable (illustrative): the bold marker renders, then `print()` opens the print dialog in the target window, whose `document.domain` is `app.example.com`. The DOM Invader *Messages* view shows the canary reaching `element.innerHTML` in `embed.9b2e.js`.

Correct: the marker appears with its tags as literal text, or nothing happens because the handler rejects the message type or the field fails a schema check.

#### Evaluation

- **Fail (DOM XSS):** script execution in the target origin from a message sent by an origin the attacker can control. CWE-79 (or CWE-95 for `eval`); `v5.0.0-3.5.5`, `v5.0.0-3.2.2`, `v5.0.0-1.3.2`.
- **Fail (HTML injection, execution blocked by CSP):** still a finding; the CSP is a mitigating control, rated lower, and the client should know it is the only thing between a foreign site and script execution.
- **Fail (hardening):** a correct origin check, but data from the trusted sender reaches a sink unsanitised.
- **Pass:** the data is rendered as text or rejected.

#### False positives

Markers that only appear in the DOM Invader canary report but are HTML-encoded on the way; data reaching `innerText` or `textContent` (not a sink); `print()` triggered by your own Console rather than by the message.

#### Automation

DOM Invader's canary injection. CodeQL's JavaScript library models message-event data as its own source kind (`browser-message-event`), so client-side queries such as `js/xss` can follow it into sinks; check which threat models your configuration enables. Semgrep's browser rules flag `innerHTML` and `eval`. The Playwright test in [Regression tests](#regression-tests) asserts that a hostile message renders as text.

### GT-WEB-MSG-7: Message-driven navigation, state and configuration changes

*Guler Tech methodology.* Implements "Examine Input Validation" in WSTG-CLNT-11 for non-XSS effects; uses WSTG-CLNT-04 (client-side URL redirect) for navigation messages.

#### What it checks

Whether an accepted message can navigate the page, change the session or identity, change configuration such as API endpoints, perform an action, or pollute object prototypes.

#### Prerequisites

A listener that accepts foreign messages; its list of message types; your two test accounts (A and B) for identity tests. **Own test objects only** for any action message.

#### Steps

1. **Navigation.** Send the navigation message type with the series' standard redirect target:

```javascript
win.postMessage({ type: "navigate", url: "https://example.org/" }, TARGET_ORIGIN);
```

2. **Identity.** If a message type sets a token or session (`login`, `setToken`, `auth`), log in as user B in a separate profile, take B's token (your own), and send it to the window where A is logged in. Then reload a page that shows the account name:

```javascript
win.postMessage({ type: "auth", token: "<TOKEN_USER_B>" }, TARGET_ORIGIN);
```

3. **Configuration.** If a message sets an API base, a CDN path or an upload endpoint, point it at a closed port on your own machine so any request fails locally and no credential leaves it, then use the feature and watch DevTools *Network*:

```javascript
win.postMessage({ type: "init", config: { apiBase: "http://127.0.0.1:9/gt-msg-7/" } }, TARGET_ORIGIN);
```

4. **Actions.** For message types that save, submit, invite, approve or pay, send one against an object your test account owns (rename your own draft, toggle your own preference) and check the server-side effect by reloading. Do not trigger actions that cost money, notify other people or delete data.
5. **Prototype pollution.** If the handler parses and merges message data into an object, send the JSON string form (so `__proto__` arrives as an own property) and check in the target's Console:

```javascript
win.postMessage('{"type":"settings","__proto__":{"gtMsg7Polluted":"yes"} }', TARGET_ORIGIN);
// then, in the target's Console:
({}).gtMsg7Polluted   // "yes" means the global Object prototype was polluted
```

Reload the target afterwards; client-side pollution lasts until the page is reloaded. How a polluted property reaches a sink is a separate gadget hunt, covered in [DOM XSS and client-side injection](/web/web-dom-xss-client-side-injection/); its server-side relative is [Server-side prototype pollution](/web/web-server-side-prototype-pollution/).

#### Observation

Vulnerable examples (illustrative): the target window navigates to `https://example.org/`; after the `auth` message, the header shows user B in user A's window; DevTools shows the editor's next save request going to `http://127.0.0.1:9/gt-msg-7/documents/42` with an `Authorization` header; your draft's title changes server-side.

#### Evaluation

- **Fail (account confusion):** a foreign message can set the session or token (login CSRF; the victim works inside the attacker's account and may enter data into it). `v5.0.0-10.1.2` when the token comes from an OAuth flow.
- **Fail (credential redirection):** a foreign message changes where authenticated requests go. Treat as token disclosure: rate like test 8.
- **Fail (action):** a foreign message performs a state-changing action for the victim (CSRF by messaging).
- **Fail (redirect):** client-side open redirect (CWE-601); DOM XSS if `javascript:` URLs are accepted (test 6).
- **Fail (pollution):** prototype pollution (CWE-1321; `v5.0.0-15.3.6`, L2); severity depends on a reachable gadget.
- **Pass:** these message types are rejected from foreign origins and validated (URL allow-list, no token or config from messages) from trusted ones.

#### False positives

Navigation that only happens inside the iframe that the attacker already controls; state changes that are purely local UI (a panel opens) and revert on reload; configuration messages that are accepted but then ignored because the configuration is frozen after start-up (confirm by using the feature).

#### Automation

A Playwright test per message type that posts the message from a foreign origin and asserts no navigation (`page.url()` unchanged), no change in the stored token, and no request to an unexpected host (`page.on("request")`).

### GT-WEB-MSG-8: Wildcard targetOrigin and data sent to frames and openers

*Guler Tech methodology.* Implements the sender-side check of WSTG-CLNT-11 ("ensure that the receiving domain is explicitly stated, and that `*` is not used").

#### What it checks

Whether the application sends sensitive data (tokens, codes, session identifiers, personal data, the current URL when it carries secrets) with `targetOrigin` `"*"` or with a target origin the attacker can influence, and whether the attacker can be the window that receives it.

#### Prerequisites

The senders from test 1; reachability from test 2; your own logged-in session.

#### Steps

1. For each sender, read what it sends and to which window. DOM Invader's *Detect cross-domain leaks* setting reports URL data with sensitive values sent to another origin. To see every call, set a DevTools *logpoint* on the `postMessage` line in the target's code that logs the message and the `targetOrigin` argument.
2. Decide which window the attacker can be:
   - **`window.opener`**: the attacker page opens the target page (or the flow that ends on it) with `window.open`, so the attacker page is the opener.
   - **`parent` or `top`**: the attacker page frames the target (test 2 says whether it can).
   - **A child iframe of the target**: the attacker page frames or opens the target, then navigates the target's child frame to the attacker's own document before the target posts to it.
   - **A derived target origin**: the target uses `document.referrer`, a URL parameter or an earlier message's origin as `targetOrigin`; the attacker sets that value.
3. Build a local catcher. For the opener case, `~/gt-poc/msg8.html` opens the target and displays what arrives:

```html
<!doctype html>
<meta charset="utf-8">
<title>GT-MSG-8 opener catcher (local, display only)</title>
<button id="open">Open target</button>
<pre id="log"></pre>
<script>
  const TARGET = "https://app.example.com/connect/finish";
  const log = (m) => { document.getElementById("log").textContent += m + "\n"; };
  document.getElementById("open").onclick = () => { window.open(TARGET, "gt_target"); };
  window.addEventListener("message", (e) => {
    // Shown on this page only; nothing is stored or sent anywhere
    log(new Date().toISOString() + "  from " + e.origin + "\n" + JSON.stringify(e.data, null, 2));
  });
</script>
```

For the child-frame case, the catcher is a page on your loopback server (`catch.html`) with only the `message` listener and the log above. After the target has loaded in your framing PoC, navigate the target's first child frame to it with `win.frames[0].location = "http://127.0.0.1:8000/catch.html"` and use the feature that makes the target post.

4. When the message arrives, mask the sensitive values before taking a screenshot, then revoke what you received (log out, revoke the session, or disconnect the integration).

#### Observation

Vulnerable (illustrative), with values masked:

```text
2026-11-15T21:04:12.418Z  from https://app.example.com
{
  "type": "connect-complete",
  "accessToken": "<ACCESS_TOKEN_USER_A - masked>",
  "email": "gt-test-a@example.com"
}
```

Correct: the catcher stays empty because the sender used `"https://partner.example.com"` (or `"/"`) and the browser dropped the message for your origin.

#### Evaluation

- **Fail:** sensitive data delivered to a window the attacker can control. Rate by the data: tokens and authorisation codes (account takeover within the token's scope), personal data, or secrets in a URL. CWE-201; `v5.0.0-10.1.1` for tokens.
- **Fail (latent):** `"*"` used for sensitive data, but no path for the attacker to be the recipient today (page not framable, opened only by a COOP-protected page, child frame not navigable). Report as Low or hardening: it becomes exploitable the moment one of those controls changes.
- **Pass:** exact `targetOrigin`, or `"*"` only for data with no confidentiality value.

#### False positives

`"*"` with a payload such as `{type: "resize", height: 640}` or `{type: "ready"}`; messages you receive in the catcher that come from your own browser extensions; your own test page's messages echoed back.

#### Automation

CodeQL `js/cross-window-information-leak` and Semgrep `wildcard-postmessage-configuration` flag `"*"`. Outgoing calls to another window cannot be wrapped from inside the page under test, so test from the receiving end: a Playwright test opens or frames the page from a route-fulfilled foreign origin, records every message that origin receives, and fails if any arrives with sensitive fields (see [Regression tests](#regression-tests)).

### GT-WEB-MSG-9: Sign-in, SSO and payment popup flows

*Guler Tech methodology.* Applies WSTG-CLNT-11 to dual-window flows (popups and iframes that carry authentication or payment results), together with WSTG-CLNT-14 for the opener relationship.

#### What it checks

Whether a popup or iframe flow that returns an authorisation code, token, session or payment result delivers it only to the application's own origin, and whether the application accepts such results only from the expected provider origin and only for a flow it started.

#### Prerequisites

Your own accounts at the application and at the identity or payment provider (provider test mode where available); Burp history of one complete flow; the senders and receivers from test 1.

#### Steps

1. Map the flow: which page opens the popup or iframe, its URL (authorisation endpoint with `redirect_uri`, `response_mode`, `state`), which page posts the result, to which window, with which `targetOrigin`, and which listener in the application receives it. Some providers offer a web message response mode, in which the authorisation server itself posts the response to the opener or parent (specified in an IETF Internet-Draft, not an RFC); there, the provider's allowed-origins setting for the client is what decides the `targetOrigin`.
2. **Sender side.** From the local opener catcher of test 8, open the flow's starting URL (the login popup URL, or the callback URL with your own fresh parameters) instead of letting the application open it, complete the login with your own account, and see whether the result reaches the catcher.
3. **Receiver side.** From the local PoC of test 4, open the application page that waits for the result and post a fabricated result message to it (an invalid code, your own account B's code, `{"status":"paid"}`). Check whether it is accepted from your origin, and whether it is accepted at all when the application never started a flow (`state` and PKCE binding, `v5.0.0-10.1.2`, `v5.0.0-10.2.1`).
4. **Opener and name channels.** Check whether the popup or callback page also writes data into `window.name`, `window.opener.location` or a query string that later pages read.
5. **Error paths.** Rosén's research shows that the error page of a flow (wrong `state`, mixed response types) can leave a valid code in the URL. If any page on the origin posts `location.href` to `"*"` or answers a URL request from any origin, the code leaks through it. Check the error page of your own flow for such listeners and senders; do not try to break flows for other users.

#### Observation

Vulnerable (illustrative): the catcher receives `{"type":"oauth-result","code":"<CODE - masked>","state":"…"}` from `https://app.example.com/oauth/popup-callback` when opened by the loopback page; or the application's listener accepts `{"type":"payment","status":"succeeded"}` from `http://127.0.0.1:8000` and moves to the confirmation step.

Correct: the callback posts with the application's exact origin, the catcher stays empty, and the application's listener ignores results from other origins and results with an unknown `state`.

#### Evaluation

- **Fail (Critical or High):** a code or token for your account delivered to your loopback page: any site can obtain users' credentials by opening the flow.
- **Fail:** the application accepts a result message from a foreign origin, or a result for a flow it did not start.
- **Fail (payment):** a foreign message moves the client into a "paid" state. Verify on the server side: if the order is still unpaid server-side, the issue is client-side state confusion (lower); if the server trusts the client's report, it is a business logic finding.
- **Pass:** exact origins in both directions and results bound to the flow.

#### False positives

A code that reaches the catcher but cannot be redeemed because PKCE binds it to a verifier that only the legitimate client holds lowers the impact (report it, rated down); a provider SDK that posts with `"*"` but only an opaque "flow finished" signal, with the code exchanged server-side.

#### Automation

The DISTINCT framework (RUB-NDS) traces and analyses in-browser messaging in SSO flows and is useful in a lab. For regression, a Playwright test that opens the callback page from a route-fulfilled foreign origin and asserts that no message arrives.

### GT-WEB-MSG-10: BroadcastChannel, MessageChannel and worker messages

*Guler Tech methodology.* Extends WSTG-CLNT-11 to the other messaging APIs of the HTML Living Standard and to worker messaging.

#### What it checks

Whether same-origin channels carry secrets or accept commands without validation, and whether `MessageChannel` handshakes hand a port to the right party only.

#### Prerequisites

The channel inventory from test 1; two tabs of the application in your own session.

#### Steps

1. **BroadcastChannel.** In a second tab of the application, open the Console and join each channel name found in the bundles. Use the application in the first tab (log in, refresh a token, log out) and watch:

```javascript
const gt = new BroadcastChannel("session");
gt.onmessage = (e) => console.log("GT-MSG-10 observed", e.data);
// After observing, send one marker and see whether the other tab reacts
gt.postMessage({ type: "GT-MSG-10-marker" });
```

Then send the application's own command types only if they are harmless for your session (`logout` is fine; data-changing commands only against your own test objects).

2. List what else runs on the same origin and could therefore use the channel: user-uploaded HTML or SVG served from the application origin, legacy pages, documentation or marketing pages on the same host. Do not upload active content to prove it; the list is the evidence.
3. **MessageChannel.** Watch the handshake in DOM Invader or with a logpoint: the message that carries `event.ports[0]`. Check that the sender transfers the port with an exact `targetOrigin`, and that the receiver checks `event.origin` before keeping the port. To test the receiver, send a handshake from your loopback PoC with a port you created, and see whether the target starts sending over it:

```javascript
const ch = new MessageChannel();
ch.port1.onmessage = (e) => log("over the port: " + JSON.stringify(e.data));
win.postMessage({ type: "connect" }, TARGET_ORIGIN, [ch.port2]);
```

4. **Workers and service workers.** In the DevTools *Application* panel, under *Service workers*, open the worker script and find its `message` handler. Note what commands it accepts (cache purge, prefetch a URL, navigate clients) and whether it checks `event.origin` and the message format.

#### Observation

Illustrative: the second tab logs `{type: "token-refreshed", accessToken: "<masked>"}` on the `session` channel; the target sends `{type: "document", id: 42, title: "…"}` over the port your loopback page supplied.

#### Evaluation

- **Fail:** a `MessagePort` accepted from a foreign origin, or a port transferred with `"*"` (same impact as test 8 for everything later sent over it).
- **Fail (Low, amplifier):** tokens or other secrets on a `BroadcastChannel`, or channel commands that do something sensitive without validation. Same-origin only, so exploitation needs a foothold on the origin (XSS on a minor page, active user content); report it because it widens the blast radius of such a foothold.
- **Pass:** no secrets on broadcast channels, validated command schema, ports only from exact origins.

#### False positives

Broadcast messages that carry only state flags (`{type: "logout"}` with no data); service worker message handlers that only reply with version information.

#### Automation

Grep for `new BroadcastChannel(` in CI and require review; unit-test the port handshake receiver with a fake event whose origin is foreign.

## Secure implementation

### Design rules

1. **No listener unless you need one.** If a page does not expect messages from other windows, do not register a `message` handler, and review the ones third-party scripts add.
2. **Exact origin allow-list, first.** Compare `event.origin` with a fixed set of full origins (`scheme://host[:port]`) using `===` or `Set.has()`, before reading `event.data`. No substring, prefix, suffix or regular expression matching, no `"null"`, no `http://`, no origins taken from the URL, the referrer or the message itself. Keep the list small; prefer named hosts over subdomain wildcards.
3. **Pin the window too, where you can.** For frame-to-frame protocols, also require `event.source === iframe.contentWindow` (or `window.parent`); it complements the origin check, it never replaces it.
4. **Validate the message.** Treat `event.data` as untrusted input: a discriminated union of known message types, each with a strict schema and size limits; drop everything else (`v5.0.0-3.5.5`, `v5.0.0-2.2.1`).
5. **No sinks.** Render message text with `textContent` or framework bindings, never `innerHTML`, `eval` or string timers (`v5.0.0-3.2.2`, `v5.0.0-1.3.2`). URLs go through an allow-list of schemes and hosts. Messages never carry configuration that redirects requests, and never set sessions or tokens.
6. **Exact targetOrigin on every send.** Derive it from build-time configuration, not from `document.referrer`, a URL parameter or an unverified event. Use `"*"` only for content you would be happy to publish. Reply to a verified sender with `event.origin` as the target.
7. **Keep credentials out of messages.** Prefer a backend-for-frontend or a server-side code exchange so the popup only signals "done" (`v5.0.0-10.1.1`). If a code must cross windows, bind it to `state` and PKCE (`v5.0.0-10.1.2`).
8. **Use a private channel after the handshake.** One exact-origin `postMessage` that transfers a `MessagePort`, then everything over the port.
9. **Cut window references you do not need.** COOP, `frame-ancestors` and `noopener` remove most attack paths before any handler runs.

### A receiver in TypeScript

```typescript
// messaging/receiver.ts
type PreviewMessage =
  | { type: "preview:update"; docId: string; text: string }
  | { type: "preview:resize"; height: number };

const ALLOWED_ORIGINS: ReadonlySet<string> = new Set([
  "https://app.example.com",
  "https://widget.example.com",
]);

// Exact string match. "null", lookalikes, other schemes and ports all fail.
export function isAllowedOrigin(origin: string): boolean {
  return ALLOWED_ORIGINS.has(origin);
}

export function parsePreviewMessage(data: unknown): PreviewMessage | null {
  if (typeof data !== "object" || data === null) return null;
  const m = data as Record<string, unknown>;
  switch (m.type) {
    case "preview:update":
      if (typeof m.docId !== "string" || !/^[a-z0-9-]{1,64}$/.test(m.docId)) return null;
      if (typeof m.text !== "string" || m.text.length > 100_000) return null;
      return { type: "preview:update", docId: m.docId, text: m.text };
    case "preview:resize":
      if (typeof m.height !== "number" || !Number.isInteger(m.height)) return null;
      if (m.height < 0 || m.height > 10_000) return null;
      return { type: "preview:resize", height: m.height };
    default:
      return null;
  }
}

export function startPreviewReceiver(frame: HTMLIFrameElement): () => void {
  const onMessage = (event: MessageEvent): void => {
    if (!isAllowedOrigin(event.origin)) return;          // 1. who sent it
    if (event.source !== frame.contentWindow) return;    // 2. from which window
    const msg = parsePreviewMessage(event.data);         // 3. what it is
    if (!msg) return;

    switch (msg.type) {
      case "preview:update":
        document.getElementById("preview")!.textContent = msg.text;  // text, not HTML
        break;
      case "preview:resize":
        frame.style.height = `${msg.height}px`;
        break;
    }
  };
  window.addEventListener("message", onMessage);
  return () => window.removeEventListener("message", onMessage);
}
```

With a schema library the parser shrinks to a declaration. Zod's `discriminatedUnion` and `strictObject` reject unknown types and unknown keys (which also keeps `__proto__` out of your objects):

```typescript
import { z } from "zod";

export const PreviewMessage = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("preview:update"),
    docId: z.string().regex(/^[a-z0-9-]{1,64}$/),
    text: z.string().max(100_000),
  }),
  z.strictObject({
    type: z.literal("preview:resize"),
    height: z.number().int().min(0).max(10_000),
  }),
]);

// in the listener, after the origin check:
const parsed = PreviewMessage.safeParse(event.data);
if (!parsed.success) return;
```

When a message legitimately carries a URL to open, check it against an allow-list after parsing it:

```typescript
const NAV_HOSTS: ReadonlySet<string> = new Set(["app.example.com", "help.example.com"]);

export function safeNavigate(raw: string): void {
  let url: URL;
  try {
    url = new URL(raw, location.origin);
  } catch {
    return;
  }
  if (url.protocol !== "https:" || !NAV_HOSTS.has(url.hostname)) return; // no javascript:, data:, other hosts
  location.assign(url.href);
}
```

If a message must carry HTML (a rich preview from your own editor frame), sanitise it with DOMPurify before insertion and enforce Trusted Types so that no other code path can write unsanitised HTML; both are covered in [DOM XSS and client-side injection](/web/web-dom-xss-client-side-injection/).

### A sender with an exact targetOrigin

```typescript
// The widget origin comes from build-time configuration, never from location, referrer or a message
const WIDGET_ORIGIN = new URL(import.meta.env.VITE_WIDGET_URL).origin;

const frame = document.querySelector<HTMLIFrameElement>("#widget")!;
frame.contentWindow?.postMessage({ type: "theme", value: "dark" }, WIDGET_ORIGIN);

// Replying to a message you have already verified
window.addEventListener("message", (event) => {
  if (!isAllowedOrigin(event.origin)) return;
  (event.source as Window | null)?.postMessage({ type: "ack" }, event.origin);
});
```

A sign-in popup callback should not hand a credential to the opener at all. Let the server complete the code exchange and set the session cookie, then send a content-free signal to the exact application origin:

```javascript
// /oauth/popup-callback (served by app.example.com after the server-side code exchange)
const APP_ORIGIN = "https://app.example.com";
if (window.opener) {
  window.opener.postMessage({ type: "signin-complete" }, APP_ORIGIN);
}
window.close();
```

The opener still checks `event.origin === APP_ORIGIN` before reacting, and reacts by fetching the session state from its own back end, not by trusting anything in the message.

### Private channels with MessageChannel

The handshake is the only `postMessage` on the window; it has an exact `targetOrigin`, and the receiver accepts the port only from the expected origin and window. After that, nobody else can inject into or read from the channel.

```typescript
// Parent page (app.example.com)
const WIDGET_ORIGIN = "https://widget.example.com";
const frame = document.querySelector<HTMLIFrameElement>("#widget")!;

frame.addEventListener("load", () => {
  const { port1, port2 } = new MessageChannel();
  port1.onmessage = (e) => {
    const msg = parseWidgetMessage(e.data);   // still validate: the widget can have bugs too
    if (msg) handleWidgetMessage(msg);
  };
  frame.contentWindow?.postMessage({ type: "connect", version: 1 }, WIDGET_ORIGIN, [port2]);
});
```

```typescript
// Inside the widget (widget.example.com)
const PARENT_ORIGIN = "https://app.example.com";
let port: MessagePort | null = null;

window.addEventListener("message", (e) => {
  if (port !== null) return;                                   // accept one handshake only
  if (e.origin !== PARENT_ORIGIN || e.source !== window.parent) return;
  if (e.data?.type !== "connect" || e.ports.length !== 1) return;
  port = e.ports[0];
  port.onmessage = (m) => {
    const msg = parseParentMessage(m.data);
    if (msg) handleParentMessage(msg);
  };
});
```

For `BroadcastChannel`, apply the same schema validation to every message, keep channel payloads to state flags (`{type: "logout"}`) rather than tokens or personal data, and remember that the whole origin is the trust boundary. Serving user-uploaded HTML from a separate origin (`v5.0.0-3.5.4`, L2) keeps it out of that boundary.

### React

A hook that owns the listener's lifecycle. The origin set and the parser are module-level constants so the effect does not re-subscribe on every render; the latest handler is kept in a ref.

```typescript
// useWindowMessages.ts
import { useEffect, useRef } from "react";

export function useWindowMessages<T>(
  allowedOrigins: ReadonlySet<string>,
  parse: (data: unknown) => T | null,
  onMessage: (msg: T, event: MessageEvent) => void,
): void {
  const handler = useRef(onMessage);
  useEffect(() => {
    handler.current = onMessage;
  }, [onMessage]);

  useEffect(() => {
    const listener = (event: MessageEvent) => {
      if (!allowedOrigins.has(event.origin)) return;
      const msg = parse(event.data);
      if (msg !== null) handler.current(msg, event);
    };
    window.addEventListener("message", listener);
    return () => window.removeEventListener("message", listener);
  }, [allowedOrigins, parse]);
}
```

```typescript
// Preview.tsx
import { useState } from "react";
import { useWindowMessages } from "./useWindowMessages";
import { parsePreviewMessage } from "./messaging/receiver";

const PREVIEW_ORIGINS: ReadonlySet<string> = new Set(["https://widget.example.com"]);

export function Preview() {
  const [text, setText] = useState("");
  useWindowMessages(PREVIEW_ORIGINS, parsePreviewMessage, (msg) => {
    if (msg.type === "preview:update") setText(msg.text);
  });
  return <div className="preview">{text}</div>; // JSX text is escaped; never dangerouslySetInnerHTML with message data
}
```

### Angular

Bind the global listener through the component's `host` property (the Angular documentation now prefers it over `@HostListener`, and both accept the `window:` prefix). Angular removes the listener when the component is destroyed.

```typescript
// preview.component.ts
import { Component, signal } from "@angular/core";
import { parsePreviewMessage } from "./messaging/receiver";

const PREVIEW_ORIGINS: ReadonlySet<string> = new Set(["https://widget.example.com"]);

@Component({
  selector: "app-preview",
  template: `<div class="preview" [textContent]="text()"></div>`,
  host: { "(window:message)": "onMessage($event)" },
})
export class PreviewComponent {
  readonly text = signal("");

  onMessage(event: MessageEvent): void {
    if (!PREVIEW_ORIGINS.has(event.origin)) return;
    const msg = parsePreviewMessage(event.data);
    if (msg?.type === "preview:update") this.text.set(msg.text);
  }
}
```

For a service rather than a component, RxJS `fromEvent(window, "message")` with `takeUntilDestroyed()` from `@angular/core/rxjs-interop` gives the same lifecycle. Angular sanitises values bound to `[innerHTML]`, but calling `DomSanitizer.bypassSecurityTrustHtml()` or `bypassSecurityTrustResourceUrl()` on message data switches that protection off; treat any such call fed from a message as a finding.

### Cutting window references: COOP, frame-ancestors and noopener

Most of the attack paths in [How a foreign page gets a window reference](#how-a-foreign-page-gets-a-window-reference) can be closed with headers and attributes, which is cheaper than perfect handlers everywhere:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Security-Policy: frame-ancestors 'self' https://portal.example.com
Cross-Origin-Opener-Policy: same-origin
```

- `frame-ancestors` (`v5.0.0-3.4.6`, L2) decides who may frame the page, so pages that are not widgets cannot be framed by an attacker and receive messages that way.
- `Cross-Origin-Opener-Policy: same-origin` (`v5.0.0-3.4.8`, L3) puts the page in its own browsing context group when a cross-origin page opens it, so the attacker's `window.open` reference is severed and there is no window to post to. Pages that open OAuth or payment popups and need to keep the reference use `same-origin-allow-popups`, which MDN describes for exactly that case. Test sign-in and payment flows after any COOP change.
- `rel="noopener"` on links and the `noopener` feature in `window.open(url, "_blank", "noopener")` stop pages you open from getting `window.opener`; modern browsers apply `noopener` by default to `target="_blank"` links, not to `window.open`.
- Untrusted content you must embed goes in a sandboxed iframe on a separate origin. Its messages arrive with origin `"null"`, so identify it by `event.source === frame.contentWindow` and talk to it over a `MessageChannel` you created.

### Static analysis

- **CodeQL**: `js/missing-origin-check` (*Missing origin verification in postMessage handler*, CWE-020 and CWE-940) and `js/cross-window-information-leak` (*Cross-window communication with unrestricted target origin*, CWE-201 and CWE-359). The first is in the `security-extended` suite.
- **Semgrep**: `insufficient-postmessage-origin-validation` and `wildcard-postmessage-configuration` in the `javascript/browser/security` rules (they tag CWE-345 and A08, a different mapping from the one this note uses; see [Mapping](#mapping)).
- **ESLint**: Mozilla's `eslint-plugin-no-unsanitized` flags `innerHTML` and similar sinks; a `no-restricted-syntax` rule bans wildcard sends outright:

```json
{
  "rules": {
    "no-restricted-syntax": [
      "error",
      {
        "selector": "CallExpression[callee.property.name='postMessage'][arguments.1.value='*']",
        "message": "postMessage with targetOrigin '*' needs a security review; use an exact origin."
      }
    ]
  }
}
```

Neither tool catches a flawed check reliably (`startsWith`, `endsWith`, regexes); keep the review in [GT-WEB-MSG-3](#gt-web-msg-3-review-each-receivers-origin-and-source-checks) and the unit test below.

### Regression tests

**Unit test the origin check** with the lookalikes from GT-WEB-MSG-5 (Vitest or Jest):

```typescript
// receiver.test.ts
import { describe, it, expect } from "vitest";
import { isAllowedOrigin } from "./messaging/receiver";

describe("isAllowedOrigin", () => {
  it.each([
    "https://app.example.com.attacker.test",
    "https://xapp.example.com",
    "http://app.example.com",
    "https://app.example.com:8443",
    "https://app.example.com/",
    "HTTPS://APP.EXAMPLE.COM",
    "null",
    "",
  ])("rejects %s", (origin) => {
    expect(isAllowedOrigin(origin)).toBe(false);
  });

  it("accepts the exact origin", () => {
    expect(isAllowedOrigin("https://app.example.com")).toBe(true);
  });
});
```

**Playwright: a foreign origin cannot drive the receiver, and receives nothing sensitive.** The foreign origin is fulfilled by `context.route`, so it never resolves or leaves the test machine; context-level routes also apply to popups.

```typescript
// postmessage.spec.ts
import { test, expect } from "@playwright/test";

const APP = process.env.APP_URL ?? "https://app.example.com";
const FOREIGN = "https://foreign.example.org";

test.beforeEach(async ({ context }) => {
  await context.route(`${FOREIGN}/**`, (route) =>
    route.fulfill({
      contentType: "text/html",
      body: `<!doctype html>
        <script>window.received = []; addEventListener("message", (e) => received.push(e.data));</script>
        <iframe id="t" src="${APP}/embed/editor" width="800" height="400"></iframe>`,
    }),
  );
});

test("embedded editor ignores render messages from a foreign origin", async ({ page }) => {
  await page.goto(`${FOREIGN}/host.html`);
  const editor = page.frameLocator("#t");
  await expect(editor.locator("#preview")).toBeVisible();

  await page.evaluate((app) => {
    const t = document.getElementById("t") as HTMLIFrameElement;
    t.contentWindow!.postMessage({ type: "render", html: "<b id=gt-regress>GT</b>" }, new URL(app).origin);
  }, APP);

  await page.waitForTimeout(300);
  await expect(editor.locator("#gt-regress")).toHaveCount(0);
  await expect(editor.locator("#preview")).not.toContainText("GT");
});

test("connect flow sends nothing sensitive to a foreign opener", async ({ page, context }) => {
  await page.goto(`${FOREIGN}/host.html`);
  const popupPromise = context.waitForEvent("page");
  await page.evaluate((app) => {
    window.open(`${app}/connect/finish`, "gt");
  }, APP);
  const popup = await popupPromise;
  await popup.waitForLoadState("load");
  await page.waitForTimeout(500);

  const received = await page.evaluate(() => JSON.stringify((window as any).received));
  expect(received).not.toMatch(/token|code|session|secret|email/i);
});
```

Run the suite against staging with a test account's saved `storageState` so the pages behave as for a logged-in user. If the editor page is not meant to be framed by other origins at all, replace the first test with an assertion that the `frame-ancestors` header is present: the strongest regression test is the one that proves the attack path does not exist.

## Practice labs

**PortSwigger Web Security Academy** (free; use DOM Invader in Burp's built-in browser alongside):

- [DOM XSS using web messages](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages): a listener with no origin check writes message data into the page (tests 4 and 6).
- [DOM XSS using web messages and a JavaScript URL](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-a-javascript-url): message data becomes a navigation target; the URL check can be satisfied while still running script (tests 6 and 7).
- [DOM XSS using web messages and JSON.parse](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-json-parse): the handler expects a JSON string and routes on a `type` field, the common real-world shape (test 6).
- [Stealing OAuth access tokens via a proxy page](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page): a comment-form iframe posts `window.location.href` to its parent with `*`, which turns a loose `redirect_uri` into token theft (tests 8 and 9).

In the labs the exploit server plays the attacker's site. Use it there; on client work, the equivalent is the local, display-only PoC page from this note.

**A two-origin lab of your own.** `http://127.0.0.1:8000` and `http://localhost:8001` are different origins, so two `python3 -m http.server` processes give you a sender and a receiver. Put the vulnerable listener from [No origin check](#no-origin-check) on one and the PoC pages from tests 4 and 8 on the other, then fix the listener with the TypeScript receiver and watch the same PoC fail. It is the fastest way to see how `targetOrigin` drops messages silently.

OWASP Juice Shop, crAPI and VAmPI focus on server-side and API flaws and, at the time of writing, have no challenge built around web messaging. For SSO popup flows, the [DISTINCT](https://github.com/RUB-NDS/DISTINCT) framework from Ruhr University Bochum runs locally in Docker and traces in-browser messages across windows.

## Real-world cases

- **No origin check in a vendor form script (HackerOne, 2018).** The Marketo forms script on www.hackerone.com's contact page registered a jQuery `message` listener with no origin check. A `mktoResponse` message with a `followUpUrl` set to a `javascript:` URL reached `location.href`. The reporter noted that HackerOne's Content Security Policy blocked the `javascript:` navigation in current browsers and that the victim first had to visit the attacker's page; the report is rated Low, with a USD 500 bounty shown, and was disclosed in February 2019. A clean example of a third-party listener on a first-party page and of CSP as the mitigating control (tests 4, 6 and 7). [HackerOne report 398054](https://hackerone.com/reports/398054).
- **The fix bypassed with a reversed prefix check (HackerOne, 2019).** The vendor's fix compared origins with `0 === expectedUrl.indexOf(event.origin)`, which accepts any origin that is a *prefix* of the vendor's URL. The researcher registered a short domain under another country-code top-level domain that matched the beginning of the vendor's host name and reused the original proof of concept. Rated Low; disclosed May 2019. This is why test 5 generates lookalikes from the trusted origin instead of trusting that "there is a check". [HackerOne report 499030](https://hackerone.com/reports/499030).
- **One listener, over a million sites (AddThis, 2016).** Mathias Karlsson of Detectify found that the AddThis share widget accepted messages starting with `at-share-bookmarklet:` from any HTTP or HTTPS page and used the rest as the `src` of a new script element. Any site embedding the widget could be made to load an attacker's script. He found it by spotting the listener in DevTools, setting a breakpoint and sending test messages; AddThis added an origin check. [Detectify Labs: postMessage XSS on a million sites](https://labs.detectify.com/writeups/postmessage-xss-on-a-million-sites/), with the companion overview [The pitfalls of postMessage](https://labs.detectify.com/2016/12/08/the-pitfalls-of-postmessage/).
- **postMessage gadgets in OAuth flows (Detectify, 2022).** Frans Rosén showed how to push sign-in flows at major providers onto error paths where a valid code stays in the URL, then leak that URL through postMessage gadgets on the same origin: listeners that answer any origin with `location.href`, storage iframes that sync URLs to any parent, a chat widget exposing an API token. The write-up is the best single explanation of why a harmless-looking "send me the URL" listener is a credential leak (tests 8 and 9). [Account hijacking using "dirty dancing" in sign-in OAuth-flows](https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/); his [postMessage-tracker](https://github.com/fransr/postMessage-tracker) extension came out of the same line of work.
- **Tokens sent with `*` in Microsoft services (MSRC, 2025).** MSRC describes Bing Travel sending authentication tokens with a wildcard target origin, and the Azure Data Explorer web UI sending an access token scoped for user impersonation, plus a cluster URL, to an Azure Marketplace iframe with `*`. It also discusses Teams app manifests whose wildcard trusted domains (`*.azurewebsites.net` and similar) made any host in that space a trusted sender, and XSS cases in Teams-hosted apps, one of which became CVE-2024-49038. The post includes CodeQL queries for both wildcard senders and handlers without origin checks. [postMessaged and Compromised](https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised/).
- **Measurements at scale.** Son and Shmatikov ([NDSS 2013](https://www.ndss-symposium.org/ndss2013/postman-always-rings-twice-attacking-and-defending-postmessage-html5-websites)) found many receivers on the Alexa top 10,000 performing origin checks incorrectly, leading to XSS and localStorage injection. PMForce ([Steffens and Stock, CCS 2020](https://cispa.de/en/research/publications/52660-pmforce-systematically-analyzing-postmessage-handlers-at-scale)) confirmed 111 exploitable handlers automatically across the top 100,000 sites. DISTINCT ([Jannett et al., CCS 2022](https://github.com/RUB-NDS/DISTINCT)) found identity theft or XSS in 31% of self-implemented dual-window SSO flows on top sites.

More write-ups are collected in [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

Rate on what a foreign page achieves in the victim's session and what it takes to get there. The factors that move severity: the **delivery path** (the target can be framed, opened in a popup, or only reached through an opener or child frame; logged in on that path or not), the **victim interaction** (visiting the attacker's page, usually a click to allow a popup), what the **handler does** (script execution, credential or token disclosure, session swap, state-changing action, redirect, cosmetic UI), what is needed to pass a **flawed check** (nothing, a cheaply registered domain, a network position for `http://` origins, or a separate bug on an allow-listed subdomain), and **mitigations** that hold (CSP blocking execution, PKCE making a leaked code useless, COOP severing popups).

**Scope.** Series convention, following the FIRST CVSS v3.1 examples for XSS: message-driven script execution uses **Scope Changed**, because the vulnerable component is the application's client code and the impact lands in the victim's browser session. Disclosure of tokens or data to the attacker's window uses **Scope Unchanged** when the impact is on the same application's data and functions (the token works against the application that leaked it); use Scope Changed if the token grants access to a different system (a partner API, a cloud control plane). Every row has `UI:R`: the victim must open the attacker's page.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| DOM XSS through a listener with no origin check, target framable or openable | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | Same footing as reflected XSS: any site, one visit. Raise C and I to High (9.3) when the session demonstrably controls sensitive data or admin functions |
| DOM XSS through a flawed check that a registered lookalike domain passes | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | Registering a domain is attacker preparation, not a condition outside the attacker's control, so `AC:L` |
| DOM XSS that needs a bug on an allow-listed subdomain | Low to Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N` (4.7) | `AC:H` for a second, unproven flaw; rate the chain if you have it; report the broad allow-list on its own as Low |
| DOM XSS that needs a message from an `http://` origin the listener trusts | Low to Medium | `CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N` (4.3) | Needs a network position to inject into the `http://` page, so `AV:A` with `AC:H`; rate the chain if you have it |
| HTML injection through messages, script blocked by CSP | Low to Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N` (4.7) | One CSP change away from XSS, so it keeps the XSS vector with `AC:H`; HTML injection with no script path is content spoofing, `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` (4.3) |
| Access token, authorisation code or session sent with `*` to a window the attacker controls | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (8.1) | Account takeover within the token's scope; Critical for admin or broad scopes, lower for short-lived, narrow or PKCE-bound codes |
| Same, but the attacker must navigate a child frame at the right moment | High | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N` (6.8) | Timing outside the attacker's full control justifies `AC:H`; impact unchanged |
| Foreign message changes the API base URL so authenticated requests go elsewhere | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (8.1) | Equivalent to handing over the bearer token |
| Personal data (email, name, account identifiers, URLs with personal data) sent with `*` | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N` (4.3) | Lower than a credentialed CORS read (6.5, High) because the attacker receives only the item the page posts, not the whole API on demand. For special-category or financial data, rate Medium to High with `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` (6.5) |
| Foreign message sets the session or token (victim logged into the attacker's account) | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` (5.4) | Login CSRF: the victim's input lands in the attacker's account; higher where that input is sensitive (payment details, documents) |
| Foreign message performs a state-changing action for the victim | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` (6.5) | CSRF by messaging; use `I:L` (4.3) for minor settings |
| Client-side open redirect through a message | Low to Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` (4.3) | Phishing aid; rate as DOM XSS if `javascript:` URLs pass |
| Prototype pollution through a message, no gadget found | Low | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N` (3.1) | Rate as the resulting XSS or logic flaw once a gadget is shown |
| `*` used for sensitive data, but no current path for the attacker to receive it | Low | none | Latent: becomes exploitable if framing, COOP or the opener relationship changes |
| Tokens or personal data on a `BroadcastChannel`; `MessagePort` handshake without origin check but not reachable | Info to Low | none | Same-origin only, or no reachable path; an amplifier for other bugs |
| Listener without origin check whose only effect is cosmetic (iframe height, scroll position) | Info | none | No security effect; recommend the check for hygiene |

When you report, give: the page and frame, the listener or sender (file, line, the exact check or `targetOrigin`), the delivery path you used (frame, popup, opener, child frame) and whether the session was present on it, the marker you sent or the data you received (masked), the origin your PoC ran on (loopback or route-fulfilled lookalike), the mitigations you observed (CSP, COOP, PKCE), and confirmation that tokens you received were revoked.

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 |
|---|---|---|---|---|
| GT-WEB-MSG-1 | WSTG-CLNT-11 | v5.0.0-3.5.5 (context) | CWE-346 (context) | A07:2025 (context) |
| GT-WEB-MSG-2 | WSTG-CLNT-11, WSTG-CLNT-09, WSTG-CLNT-14 | v5.0.0-3.4.6, v5.0.0-3.4.8 | CWE-1021, CWE-1022 | A06:2025 |
| GT-WEB-MSG-3 | WSTG-CLNT-11 | v5.0.0-3.5.5 | CWE-346, CWE-940 | A07:2025 |
| GT-WEB-MSG-4 | WSTG-CLNT-11 | v5.0.0-3.5.5 | CWE-346, CWE-940 | A07:2025 |
| GT-WEB-MSG-5 | WSTG-CLNT-11 | v5.0.0-3.5.5 | CWE-346, CWE-940 | A07:2025 |
| GT-WEB-MSG-6 | WSTG-CLNT-11, WSTG-CLNT-01, WSTG-CLNT-02 | v5.0.0-3.5.5, v5.0.0-3.2.2, v5.0.0-1.3.2, v5.0.0-1.2.2 | CWE-79, CWE-95 | A05:2025 |
| GT-WEB-MSG-7 | WSTG-CLNT-11, WSTG-CLNT-04 | v5.0.0-3.5.5, v5.0.0-2.2.1, v5.0.0-3.7.2, v5.0.0-10.1.2, v5.0.0-15.3.6 | CWE-346, CWE-601, CWE-352, CWE-1321 | A07:2025, A01:2025 |
| GT-WEB-MSG-8 | WSTG-CLNT-11 | v5.0.0-10.1.1, v5.0.0-3.4.8 | CWE-201, CWE-359 | A01:2025 |
| GT-WEB-MSG-9 | WSTG-CLNT-11, WSTG-CLNT-14 | v5.0.0-10.1.1, v5.0.0-10.1.2, v5.0.0-10.2.1, v5.0.0-3.5.5 | CWE-201, CWE-346 | A01:2025, A07:2025 |
| GT-WEB-MSG-10 | WSTG-CLNT-11 | v5.0.0-3.5.5, v5.0.0-3.5.4, v5.0.0-10.1.1 | CWE-201, CWE-346 | A01:2025, A07:2025 |

ASVS levels: `v5.0.0-3.5.5` L2 (discard messages from untrusted origins or with invalid syntax), `v5.0.0-3.2.2` L1 (text-only rendering such as `textContent`), `v5.0.0-1.3.2` L1 (avoid `eval()` and dynamic code execution), `v5.0.0-1.2.2` L1 (safe URL protocols when building URLs), `v5.0.0-2.2.1` L1 (positive validation against expected structure), `v5.0.0-3.7.2` L2 (redirects only to allow-listed destinations), `v5.0.0-3.4.6` L2 (`frame-ancestors`), `v5.0.0-3.4.8` L3 (COOP on document responses), `v5.0.0-3.5.4` L2 (separate applications on separate hostnames), `v5.0.0-10.1.1` L2 (tokens only to components that need them), `v5.0.0-10.1.2` L2 (accept codes and tokens only from flows the same user agent started), `v5.0.0-10.2.1` L2 (PKCE or `state` against forged token requests), `v5.0.0-15.3.6` L2 (prototype-pollution-safe JavaScript).

CWE choice: MITRE has no web-messaging-specific entry. CWE-346 (*Origin Validation Error*) describes the receiver bug exactly but is a class marked *Allowed-with-Review*; CWE-940 (*Improper Verification of Source of a Communication Channel*) is the base-level child that CodeQL's `js/missing-origin-check` uses, and either is defensible. CWE-345 (*Insufficient Verification of Data Authenticity*), which Semgrep's rule uses, is a level-1 class that MITRE marks *Discouraged*. CWE-1385 (*Missing Origin Validation in WebSockets*) is specific to WebSockets and does not fit postMessage. Sender-side leaks map to CWE-201 (*Insertion of Sensitive Information Into Sent Data*), plus CWE-359 for personal data, as in CodeQL's `js/cross-window-information-leak`. Sinks keep their own CWEs: CWE-79, CWE-95 (eval injection), CWE-601 (open redirect), CWE-1321 (prototype pollution); CWE-352 fits message-driven actions taken on the victim's behalf. CWE-1021 (frames) and CWE-1022 (`window.opener` access) cover the reachability side.

Top 10: the official OWASP Top 10:2025 mappings put CWE-346 and CWE-940 under `A07:2025` Authentication Failures, CWE-79 and CWE-95 under `A05:2025` Injection, CWE-201, CWE-359, CWE-352 and CWE-601 under `A01:2025` Broken Access Control, and CWE-1021 and CWE-1022 under `A06:2025` Insecure Design. CWE-1321 has no Top 10:2025 mapping; file it with whatever it leads to. Web messaging is a browser-side issue, so the OWASP API Security Top 10 2023 does not apply.

## References

**OWASP**

- WSTG: [Testing Web Messaging (WSTG-CLNT-11)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/11-Web_Messaging), [DOM-Based Cross Site Scripting (WSTG-CLNT-01)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/01-DOM-based_Cross_Site_Scripting), [JavaScript Execution (WSTG-CLNT-02)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/02-JavaScript_Execution), [Client-side URL Redirect (WSTG-CLNT-04)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/04-Client-side_URL_Redirect), [Clickjacking (WSTG-CLNT-09)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/09-Clickjacking), [Reverse Tabnabbing (WSTG-CLNT-14)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/14-Reverse_Tabnabbing)
- ASVS 5.0: [V3 Web Frontend Security](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md), [V1 Encoding and Sanitization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md), [V2 Validation and Business Logic](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x11-V2-Validation-and-Business-Logic.md), [V10 OAuth and OIDC](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x19-V10-OAuth-and-OIDC.md), [V15 Secure Coding and Architecture](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md)
- Top 10:2025: [A07 Authentication Failures](https://top10.owasp.org/2025/A07_2025-Authentication_Failures/), [A05 Injection](https://top10.owasp.org/2025/A05_2025-Injection/), [A01 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/), [A06 Insecure Design](https://top10.owasp.org/2025/A06_2025-Insecure_Design/)
- Cheat Sheets: [HTML5 Security](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) (Web Messaging section), [DOM based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html), [Cross Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), [OAuth 2.0](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)

**CWE**

- [CWE-346](https://cwe.mitre.org/data/definitions/346.html), [CWE-940](https://cwe.mitre.org/data/definitions/940.html), [CWE-345](https://cwe.mitre.org/data/definitions/345.html), [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html), [CWE-201](https://cwe.mitre.org/data/definitions/201.html), [CWE-359](https://cwe.mitre.org/data/definitions/359.html), [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CWE-95](https://cwe.mitre.org/data/definitions/95.html), [CWE-601](https://cwe.mitre.org/data/definitions/601.html), [CWE-352](https://cwe.mitre.org/data/definitions/352.html), [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html), [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html), [CWE-1022](https://cwe.mitre.org/data/definitions/1022.html)

**Specifications and browser documentation**

- HTML Living Standard: [Communication APIs: web messaging, channel messaging and broadcasting](https://html.spec.whatwg.org/multipage/web-messaging.html) (see the "Security" notes for authors under cross-document messaging)
- MDN: [Window.postMessage()](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage), [Window: message event](https://developer.mozilla.org/en-US/docs/Web/API/Window/message_event), [MessageEvent](https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent), [MessageEvent.origin](https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent/origin), [MessageChannel](https://developer.mozilla.org/en-US/docs/Web/API/MessageChannel), [Using channel messaging](https://developer.mozilla.org/en-US/docs/Web/API/Channel_Messaging_API/Using_channel_messaging), [MessagePort](https://developer.mozilla.org/en-US/docs/Web/API/MessagePort), [BroadcastChannel](https://developer.mozilla.org/en-US/docs/Web/API/BroadcastChannel), [Worker.postMessage()](https://developer.mozilla.org/en-US/docs/Web/API/Worker/postMessage), [ServiceWorker.postMessage()](https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorker/postMessage), [Window.opener](https://developer.mozilla.org/en-US/docs/Web/API/Window/opener), [Window.name](https://developer.mozilla.org/en-US/docs/Web/API/Window/name), [Cross-Origin-Opener-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy), [CSP frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors), [rel=noopener](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Attributes/rel/noopener), [Structured clone algorithm](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Structured_clone_algorithm), [Trusted Types API](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API)
- Chrome DevTools: [Console Utilities API reference](https://developer.chrome.com/docs/devtools/console/utilities) (`getEventListeners`, `monitorEvents`)
- OAuth web message response mode: [IETF Internet-Draft](https://datatracker.ietf.org/doc/draft-meyerzuselha-oauth-web-message-response-mode/); an example provider implementation is described in Auth0's [Configure Silent Authentication](https://auth0.com/docs/authenticate/login/configure-silent-authentication)

**PortSwigger**

- [Controlling the web message source](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source), [DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based), [OAuth 2.0 authentication vulnerabilities](https://portswigger.net/web-security/oauth), [Prototype pollution](https://portswigger.net/web-security/prototype-pollution)
- DOM Invader: [overview](https://portswigger.net/burp/documentation/desktop/tools/dom-invader), [testing for DOM XSS using web messages](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/web-messages), [web message settings](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/settings/web-messages)

**Research**

- Frans Rosén (Detectify Labs), [Account hijacking using "dirty dancing" in sign-in OAuth-flows](https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/) (2022)
- Mathias Karlsson (Detectify Labs), [The pitfalls of postMessage](https://labs.detectify.com/2016/12/08/the-pitfalls-of-postmessage/) and [postMessage XSS on a million sites](https://labs.detectify.com/writeups/postmessage-xss-on-a-million-sites/) (2016)
- MSRC, [postMessaged and Compromised](https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised/) (2025)
- Son and Shmatikov, [The Postman Always Rings Twice: Attacking and Defending postMessage in HTML5 Websites](https://www.ndss-symposium.org/ndss2013/postman-always-rings-twice-attacking-and-defending-postmessage-html5-websites) (NDSS 2013)
- Steffens and Stock, [PMForce: Systematically Analyzing postMessage Handlers at Scale](https://cispa.de/en/research/publications/52660-pmforce-systematically-analyzing-postmessage-handlers-at-scale) (CCS 2020)
- Jannett, Mladenov, Mainka and Schwenk, DISTINCT: Identity Theft using In-Browser Communications in Dual-Window Single Sign-On (CCS 2022), [tool and paper links](https://github.com/RUB-NDS/DISTINCT)
- FIRST, [CVSS v3.1 examples](https://www.first.org/cvss/v3.1/examples) (scope for XSS) and [user guide](https://www.first.org/cvss/v3.1/user-guide)

**Framework documentation**

- React: [useEffect](https://react.dev/reference/react/useEffect), [common components](https://react.dev/reference/react-dom/components/common) (`dangerouslySetInnerHTML`)
- Angular: [Host elements](https://angular.dev/guide/components/host-elements), [HostListener](https://angular.dev/api/core/HostListener), [takeUntilDestroyed](https://angular.dev/api/core/rxjs-interop/takeUntilDestroyed), [Security](https://angular.dev/guide/security), [DomSanitizer](https://angular.dev/api/platform-browser/DomSanitizer)
- Playwright: [Network](https://playwright.dev/docs/network) (`route.fulfill`), [Route](https://playwright.dev/docs/api/class-route), [BrowserContext](https://playwright.dev/docs/api/class-browsercontext), [Frame](https://playwright.dev/docs/api/class-frame)
- Validation: [Zod](https://zod.dev/), [Ajv](https://ajv.js.org/); sanitising: [DOMPurify](https://github.com/cure53/DOMPurify)

**Tools**

- [postMessage-tracker](https://github.com/fransr/postMessage-tracker) (Chrome extension, Frans Rosén)
- [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader) (Burp Suite)
- [DISTINCT](https://github.com/RUB-NDS/DISTINCT) (SSO in-browser communication analysis)
- CodeQL: [js/missing-origin-check](https://codeql.github.com/codeql-query-help/javascript/js-missing-origin-check/), [js/cross-window-information-leak](https://codeql.github.com/codeql-query-help/javascript/js-cross-window-information-leak/), [js/xss](https://codeql.github.com/codeql-query-help/javascript/js-xss/)
- Semgrep: [insufficient-postmessage-origin-validation](https://semgrep.dev/r/javascript.browser.security.insufficient-postmessage-origin-validation.insufficient-postmessage-origin-validation), [wildcard-postmessage-configuration](https://semgrep.dev/r/javascript.browser.security.wildcard-postmessage-configuration.wildcard-postmessage-configuration) ([rule sources](https://github.com/semgrep/semgrep-rules/tree/develop/javascript/browser/security))
- ESLint: [eslint-plugin-no-unsanitized](https://github.com/mozilla/eslint-plugin-no-unsanitized)
