---
title: "CRLF, Email Header, Log and CSV Injection"
date: 2026-11-15 20:12:00 +0000
subcategory: injection
summary: "Testing CRLF and response header injection, email header and IMAP/SMTP injection, log forging and CSV formula injection, with safe proofs and fixes."
refs: [WSTG-INJT-15, WSTG-INJT-10, WSTG-INJT-21, WSTG-INJT-04, v5.0.0-1.2.1, v5.0.0-1.2.2, v5.0.0-1.2.10, v5.0.0-1.3.3, v5.0.0-1.3.9, v5.0.0-1.3.11, v5.0.0-4.2.4, v5.0.0-16.4.1, v5.0.0-16.2.4, "A05:2025", "A09:2025", CWE-93, CWE-113, CWE-117, CWE-1236, CWE-147, CWE-150]
tags: [web, injection, crlf, header-injection, log-injection, csv-injection]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Injection](/web/web-injection-testing-guide/). It covers the injection classes where the interpreter is not a database or a shell but a *line-based format*: HTTP response headers (`WSTG-INJT-15`, HTTP response splitting), mail headers and IMAP/SMTP commands (`WSTG-INJT-10`), log files and the tools that display them, and CSV exports opened in a spreadsheet (`WSTG-INJT-21`, formula injection). They share one root cause: a value that should be data contains a character the next component treats as structure, usually a carriage return and line feed (CR LF, `\r\n`, `%0d%0a`), sometimes a comma, a quote or a leading `=`. You get the model (which delimiter each sink uses and what current frameworks already neutralise, checked against real library versions), the variants that still produce findings in 2026, twelve tests that each stop at a harmless marker (an `X-GT-Test` header, a `Bcc` to your own mailbox, a fake log line with a `GT-` marker, a cell that shows `2` instead of `=1+1`), and fixes for Express, Django, Spring and Laravel with regression tests. Parameter pollution, which often travels with these tests, is covered from the authorisation side in [mass assignment and BOPLA](/web/web-mass-assignment-bopla/) and [IDOR and BOLA](/web/web-idor-bola/). Request smuggling and Host header attacks belong to the HTTP & Infrastructure subcategory, and script execution through a split response or a log viewer to the Client-Side (XSS) notes; neither is published yet, so this note only points at them.

## Contents

- [How it works](#how-it-works)
  - [Line-based protocols and the CRLF delimiter](#line-based-protocols-and-the-crlf-delimiter)
  - [Where untrusted data meets a delimiter](#where-untrusted-data-meets-a-delimiter)
  - [What current frameworks already block](#what-current-frameworks-already-block)
  - [Spreadsheets and logs are interpreters too](#spreadsheets-and-logs-are-interpreters-too)
- [What goes wrong](#what-goes-wrong)
  - [Raw header writing and legacy stacks](#raw-header-writing-and-legacy-stacks)
  - [Redirect targets](#redirect-targets)
  - [Cookies and custom headers set from parameters](#cookies-and-custom-headers-set-from-parameters)
  - [Path-based injection in proxies](#path-based-injection-in-proxies)
  - [Outbound requests and HTTP/2 downgrades](#outbound-requests-and-http2-downgrades)
  - [Email headers and address lists](#email-headers-and-address-lists)
  - [IMAP and SMTP commands](#imap-and-smtp-commands)
  - [Cache and key-value protocols](#cache-and-key-value-protocols)
  - [Log forging, control sequences and log viewers](#log-forging-control-sequences-and-log-viewers)
  - [CSV and formula injection](#csv-and-formula-injection)
  - [Related: HTTP parameter pollution](#related-http-parameter-pollution)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-WEB-CRLF-1: Map where input reaches response headers](#gt-web-crlf-1-map-where-input-reaches-response-headers)
  - [GT-WEB-CRLF-2: CRLF in redirect targets](#gt-web-crlf-2-crlf-in-redirect-targets)
  - [GT-WEB-CRLF-3: CRLF in cookies and custom headers](#gt-web-crlf-3-crlf-in-cookies-and-custom-headers)
  - [GT-WEB-CRLF-4: Encoding, bare LF and path variants](#gt-web-crlf-4-encoding-bare-lf-and-path-variants)
  - [GT-WEB-CRLF-5: Assess the impact of a confirmed header injection](#gt-web-crlf-5-assess-the-impact-of-a-confirmed-header-injection)
  - [GT-WEB-CRLF-6: Header injection in server-side outbound requests](#gt-web-crlf-6-header-injection-in-server-side-outbound-requests)
  - [GT-WEB-CRLF-7: Email header and recipient injection](#gt-web-crlf-7-email-header-and-recipient-injection)
  - [GT-WEB-CRLF-8: IMAP and SMTP command injection](#gt-web-crlf-8-imap-and-smtp-command-injection)
  - [GT-WEB-CRLF-9: Cache and key-value protocol injection](#gt-web-crlf-9-cache-and-key-value-protocol-injection)
  - [GT-WEB-CRLF-10: Log forging with CR and LF](#gt-web-crlf-10-log-forging-with-cr-and-lf)
  - [GT-WEB-CRLF-11: Control sequences, markup and lookups in log pipelines](#gt-web-crlf-11-control-sequences-markup-and-lookups-in-log-pipelines)
  - [GT-WEB-CRLF-12: CSV and formula injection in exports](#gt-web-crlf-12-csv-and-formula-injection-in-exports)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Response headers and redirects](#response-headers-and-redirects)
  - [Email](#email)
  - [Logging](#logging)
  - [CSV and spreadsheet exports](#csv-and-spreadsheet-exports)
  - [Static analysis](#static-analysis)
  - [Regression tests](#regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Line-based protocols and the CRLF delimiter

HTTP/1.1, SMTP, IMAP, the memcached text protocol, most log files and CSV all use a line ending as a record separator. In HTTP/1.1 every header field ends with CR LF, and an empty line (CR LF CR LF) ends the header block and starts the body (RFC 9110 and RFC 9112). In SMTP every command and every header line of the message ends with CR LF (RFC 5321, RFC 5322). In IMAP every tagged command ends with CR LF (RFC 9051). A text log usually means "one line, one event". A CSV file means "one line, one record; commas separate fields; quotes protect commas" (RFC 4180).

So if an application builds any of these by concatenating a string, and the string contains CR LF, the receiver sees a new line it was never meant to see:

```text
Location: /home?lang=en          <- what the developer intended
Location: /home?lang=en
X-GT-Test: crlf-1                <- what the receiver parses when lang = "en\r\nX-GT-Test: crlf-1"
```

That new line is a new header, a new SMTP command, a new log event, a new CSV record. Two CR LF in a row in HTTP end the headers, and what follows becomes the response body, which is where the name "response splitting" comes from: the client or an intermediary cache may read one response as two.

CWE has one entry for the general pattern and specific ones per sink. Use the most specific that fits:

| CWE | Name (short) | Use for |
|---|---|---|
| CWE-93 | Improper Neutralization of CRLF Sequences ('CRLF Injection') | Base entry: CR LF used as a separator in any protocol (SMTP, IMAP, memcached, custom line protocols) |
| CWE-113 | Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting') | Variant: CR LF into HTTP response or request headers |
| CWE-117 | Improper Output Neutralization for Logs | Base entry: log forging and log injection |
| CWE-1236 | Improper Neutralization of Formula Elements in a CSV File | Base entry: CSV and formula injection |
| CWE-147 | Improper Neutralization of Input Terminators | Variant: a terminator other than CR LF (an SMTP `.` line, a NUL, a protocol's end marker) |
| CWE-150 | Improper Neutralization of Escape, Meta, or Control Sequences | Variant: ANSI terminal escape sequences and other control sequences |

All six are marked "Allowed" for vulnerability mapping on cwe.mitre.org at the time of writing. CWE-74 (the injection class parent) is "Discouraged"; use it only as an umbrella.

### Where untrusted data meets a delimiter

| Sink | Delimiter that matters | Typical source of untrusted data |
|---|---|---|
| HTTP response header | CR, LF (and in some stacks a bare LF or bare CR) | Redirect target (`?next=`, `?returnUrl=`), language or theme cookie, file name in `Content-Disposition`, CORS origin echo, custom `X-Request-Id` echo, a value from the path rewritten by a proxy |
| Outbound HTTP request header | CR, LF | A user-supplied value the back end forwards to an upstream API (`X-Customer-Ref`, a host name, a token) |
| Mail header | CR, LF; also `,` and `;` in address fields, quotes and angle brackets in display names | Contact form "your email" and "name", "send to a friend", invitation and sharing emails, subject lines built from ticket titles |
| IMAP or SMTP command | CR, LF; for SMTP data also a line containing only `.` | Webmail parameters (mailbox name, message ID, search term), mail-sending features talking SMTP directly |
| memcached or a custom TCP line protocol | CR, LF, spaces in keys | Cache keys built from user input (`user:<name>`) |
| Log file and log pipeline | CR, LF; ANSI escape (`ESC`, `0x1B`); HTML if a viewer renders it; lookup syntax in some logging libraries | Username on failed login, `User-Agent`, `Referer`, search terms, any request field logged verbatim |
| CSV or spreadsheet export | Leading `=`, `+`, `-`, `@`, tab, CR, LF; `,` or `;` and `"` to start a new cell | Any user-controlled field that ends up in an export: names, comments, ticket subjects, addresses, imported data |

### What current frameworks already block

The good news, and the reason most CRLF findings today come from edges rather than from mainstream code paths: the header APIs of current runtimes refuse or neutralise CR and LF. We checked this at the time of writing against the versions shown, by setting a header from a query parameter containing `%0d%0a` and reading the raw response (Node.js, Express, Django, Python, Go were run locally; Tomcat, Spring Security and PHP were read from source). Outputs are summarised; treat them as illustrative and re-check on the stack you test.

| Stack | Header value containing CR LF | Redirect target containing CR LF | Cookie value containing CR LF |
|---|---|---|---|
| Node.js `http` (v26) | `setHeader` and `writeHead` throw `ERR_INVALID_CHAR` ("Invalid character in header content") | Same, if you set `Location` yourself | Same, if you write `Set-Cookie` yourself |
| Express 5 | Inherits Node's check | `res.location()` and `res.redirect()` pass the URL through `encodeurl`, so CR LF leaves as `%0D%0A` | `res.cookie()` URL-encodes the value by default |
| Django 6.1 | Raises `BadHeaderError` ("Header values can't contain newlines") | `HttpResponseRedirect` percent-encodes it (`/home%0D%0A…`) | `set_cookie` raises `http.cookies.CookieError` |
| Python `http.server` | **No check**: `send_header` writes the value as given | **No check** | **No check** |
| Spring Security (`StrictHttpFirewall` is the default) | The `FirewalledResponse` wrapper throws `IllegalArgumentException` ("Invalid characters (CR/LF) in header") | `sendRedirect` with CR LF is rejected (the source cites SEC-1790) | `addCookie` is checked too |
| Apache Tomcat | Replaces control characters other than tab with spaces when writing header values | Same | Same |
| Go `net/http` (1.27) | Replaces CR and LF with spaces | `http.Redirect` keeps them, the header writer then turns them into spaces | Same writer |
| PHP `header()` (and so Symfony HttpFoundation and Laravel) | Refuses with "Header may not contain more than a single header, new line detected"; also refuses NUL bytes | Same | `setcookie()` URL-encodes the value |

The same holds for mail: Nodemailer, Django's mail functions, Jakarta Mail (Angus Mail) and Symfony Mailer (which Laravel uses) all neutralise CR LF in headers in current versions (details in [email headers and address lists](#email-headers-and-address-lists)). What they do **not** do is stop a comma from adding a recipient when you hand them an address *string*, and they cannot help when the application writes the protocol itself.

What this means for testing: a CRLF probe that fails against a modern framework is the expected result, not a reason to try a hundred encodings. Spend the time on the places the table does not cover: code that writes raw responses or raw protocol lines, old runtimes and appliances, proxies and gateways that build headers from the path, HTTP clients that build outbound requests, mail sent through `mail()` or a raw SMTP socket, logs, and exports. ASVS 5.0 puts the general rule in `v5.0.0-1.2.1` (L1): output encoding for an HTTP response must suit the context, explicitly including HTTP header fields, so the message structure cannot change. `v5.0.0-1.2.2` (L1) adds URL encoding when building URLs, which is exactly what Express and Django do for `Location`.

### Spreadsheets and logs are interpreters too

Two of the sinks here look like plain data files, which is why they are underestimated.

A **spreadsheet** opening a CSV does not see "text". It sees cells, and a cell that starts with `=` (or `+`, `-`, `@` in most products) is a formula. Formulas compute, reference other cells, build hyperlinks and, in some products and configurations, fetch remote data or (historically, through Dynamic Data Exchange) start programs. The victim is not the web application but whoever opens the export: often an administrator, a finance team member or a support agent with more access than the attacker. The vulnerable component and the impacted component are different, which matters for [rating](#rating-findings).

A **log** is read by people and programs: an engineer running `tail -f` in a terminal that interprets escape sequences, a SIEM parsing one event per line, an admin "audit log" page rendering entries as HTML, a log library that (as Log4j 2 did before the Log4Shell fixes) evaluates lookup expressions inside the message. Each reader is an interpreter with its own metacharacters. ASVS 5.0 `v5.0.0-16.4.1` (L2) requires every logging component to encode data to prevent log injection, and `v5.0.0-16.2.4` (L2) asks for a common format the log processor can read, which in practice means structured logs.

## What goes wrong

### Raw header writing and legacy stacks

**What happens:** the response is written without the framework's header API: a CGI script printing `Location: …\r\n`, a custom server on a raw socket, Python's `http.server` used "just for an internal tool", an embedded web server in an appliance or IoT management interface, a serverless adapter that maps a header dictionary to a proxy response without validation, an old runtime that predates the checks in the table above.

**Why it matters:** any header value built from input becomes a header injection, and with two CR LF a body injection.

**Where to look:** responses with unusual `Server` headers, admin consoles of network devices and printers in scope, legacy paths (`/cgi-bin/`, `.pl`, `.cgi`), internal tools exposed on staging hosts, and any endpoint where the framework fingerprint (cookie names, error pages) differs from the rest of the application.

### Redirect targets

**What happens:** `?next=`, `?returnUrl=`, `?redirect_uri=` or a language switcher puts its value into `Location`. On a stack that does not encode or reject CR LF, the value can end the `Location` line and add headers. The WSTG example is exactly this: an interface parameter reflected into a `302`.

**Why it matters:** redirects are the most common header sink, they are usually unauthenticated, and a link containing the payload is easy to deliver. Some platforms URL-encode the path part of `Location` but not the query string, so injection may work only after `?`.

**Where to look:** login and logout flows, language and currency switchers, "continue to" interstitials, SSO and OAuth endpoints, short-link and tracking redirectors, file download endpoints that redirect to storage. An open redirect on the same parameter is a separate finding (in the Client-Side subcategory, not yet published).

### Cookies and custom headers set from parameters

**What happens:** a preference (`?theme=dark`, `?lang=en`, `?campaign=`) is stored by writing `Set-Cookie: lang=<value>` by hand, or a value is echoed in a custom header: `X-Request-Id`, `X-Correlation-Id`, `Content-Disposition: attachment; filename="<name>"`, a CORS `Access-Control-Allow-Origin` that reflects the `Origin` request header, a `Link` header, a `Refresh` header.

**Why it matters:** an injected `Set-Cookie` lets an attacker plant cookies in the victim's browser for the application's domain (session fixation if the application accepts a pre-set session ID and does not rotate it at login, which `v5.0.0-7.2.4` requires; cookie tossing against double-submit CSRF tokens; feature flags). An injected body is reflected content or script. `Content-Disposition` file names are a classic, because developers think of them as file names rather than as header values.

**Where to look:** every `Set-Cookie` whose value you can recognise from your input, every response header that contains a value you sent, download endpoints with user-chosen file names.

### Path-based injection in proxies

**What happens:** a reverse proxy builds a header or a redirect from the *decoded* request path. In nginx the `$uri` and `$document_uri` variables hold the normalised (decoded) URI, so a configuration such as `return 302 https://$host$uri;` or `add_header X-Path $uri;` can write a decoded CR LF from `/%0d%0aX-GT-Test:%20crlf-1` into the response. `$request_uri` holds the original, still-encoded request URI and does not have this problem. Regex captures from a `location` pattern with an exclusive character class (`[^.]*`, which still matches CR and LF) used in `add_header`, `return`, `rewrite` or `proxy_set_header` have the same effect. The nginx configuration analyser gixy has an `http_splitting` check for both patterns, and Semgrep's community rules include an nginx `header-injection` rule for the capture-variable case.

**Why it matters:** the application code is fine and the framework checks never run; the proxy writes the header. HTTP-to-HTTPS redirects on every host are a common place for it.

**Where to look:** plain-HTTP listeners that redirect to HTTPS, trailing-slash redirects, locale redirects done at the edge, and any configuration you can read in a grey-box test (`nginx.conf`, ingress annotations, CDN edge rules).

### Outbound requests and HTTP/2 downgrades

**What happens (outbound):** the server builds a request to another service and puts user input into a header or the request line: a partner reference in `X-Customer-Ref`, a tenant host name, a forwarded token. If the HTTP client does not validate header values, CR LF adds headers to the *outbound* request, for example a trust header the internal service honours (`X-User-Id`, `X-Internal: true`). Clients have had real bugs here: Node.js's `undici` (which backs `fetch` in Node) did not validate the `host` header until the fix for CVE-2023-23936 (see [real-world cases](#real-world-cases)).

**What happens (HTTP/2):** HTTP/2 frames headers in binary, so `\r\n` inside a header *value* is not a delimiter on the wire. RFC 9113 says such values are malformed and must be rejected. A front end that does not reject them and downgrades the request to HTTP/1.1 for the back end turns the bytes back into delimiters, which is the basis of HTTP/2 request smuggling and request splitting via CRLF injection (PortSwigger's "HTTP/2: The Sequel is Always Worse" research and the related Web Security Academy labs). ASVS 5.0 `v5.0.0-4.2.4` (L3) requires accepting HTTP/2 and HTTP/3 requests only when header names and values contain no CR, LF or CRLF.

**Why it matters:** these are request-side injections whose impact is on other users' requests and on internal trust boundaries, not on one response. Request smuggling is covered in the HTTP & Infrastructure subcategory (not yet published); this note only checks whether a CRLF reaches an outbound request ([GT-WEB-CRLF-6](#gt-web-crlf-6-header-injection-in-server-side-outbound-requests)) and stops there.

### Email headers and address lists

**What happens:** a contact form, "share by email", invitation or notification feature builds the message with user input in header fields. Two families:

- **CRLF in a header value.** The old pattern is PHP's `mail($to, $subject, $body, "From: " . $_POST['email'])`: the `additional_headers` argument is raw text with CR LF separating headers, and the PHP manual itself warns that outside data must be sanitised so no unwanted headers can be injected. A value of `user@example.org\r\nBcc: someone@example.net` adds a recipient. The same happens with any code that writes headers to a `sendmail -t` pipe or an SMTP socket.
- **Address syntax injection.** Current libraries neutralise CR LF (below), so the live variant is the comma. If the application passes a *string* such as `"<user name>" <user email>` or `user email` into an address field, the library parses it as an address *list*. A comma, a semicolon, quotes or angle brackets in the user's input can add a recipient or change the address mail is delivered to. Django's 6.1 documentation now warns explicitly against building addresses with string formatting and recommends `email.headerregistry.Address`, and Nodemailer has published a series of address-parser advisories in 2026 where crafted comments, quotes or separators led to delivery to an address the header did not show.

What the libraries do with CR LF today (checked locally at the time of writing, offline, by building messages without sending them):

| Library | CR LF in subject or custom header | CR LF in an address | Comma in an address string |
|---|---|---|---|
| Nodemailer 10.6 | Replaced with a space (`Subject: Hello Bcc: …` stays one header) | Display name is Q-encoded; the address part is parsed, not injected | Parsed as a second recipient and added to the envelope |
| Django 6.1 | `send_mail()` and `EmailMessage` raise `ValueError` (Django 6.0 replaced the older `BadHeaderError` with `ValueError`) | `ValueError` | The SMTP back end rejects a recipient string containing two addresses ("must be a single address"); `Address` objects avoid the question |
| Jakarta Mail (Angus Mail 2.0.5) | Folded: the text after CR LF becomes a continuation line of `Subject`, not a new header | `InternetAddress.parse()` throws `AddressException` ("Domain contains control or whitespace") | `InternetAddress.parse()` returns two addresses |
| Symfony Mime (Laravel Mail) | Header tokens containing CR or LF are encoded | `Address` validates the address with `egulias/email-validator` and strips CR and LF from the display name | Use one `Address` per recipient; Laravel's `to()` accepts arrays and objects |

**Why it matters:** the application becomes a spam or phishing relay with its own domain's reputation (SPF and DKIM pass), confidential messages (password resets, invoices, internal notifications) can be copied to an attacker, and a forged `Reply-To` or body can impersonate staff. Mail libraries also have had their own injection bugs at the SMTP level; Jakarta Mail's CVE-2025-7962 (SMTP injection through CR and LF) is the recent one.

**Where to look:** every form with "email", "name", "subject" or "message" fields that triggers a mail; features that send *to* a user-supplied address (invite, share, "email me this report"); support desks that turn tickets into mail; mail templates whose subject includes a user-controlled title.

### IMAP and SMTP commands

**What happens:** a webmail front end or a mail-integrated feature talks IMAP or SMTP on behalf of the user and concatenates parameters into commands: `SELECT "<mailbox>"`, `FETCH <id> BODY[HEADER]`, `SEARCH TEXT "<term>"`, `RCPT TO:<address>`. A quote breaks the argument; CR LF ends the command and starts a new one (WSTG-INJT-10 gives the structure: finish the expected command, inject a new tagged command, then restart the expected one so the parser stays in sync).

**Why it matters:** the mail server is usually not reachable from the internet, so injection reaches an internal system through the web tier, as the logged-in user or, for features that run before login, as the application's own service account. Typical effects: reading or moving mail in ways the UI does not allow, bypassing per-feature restrictions, using the server as a relay.

**Where to look:** webmail products, "connect your mailbox" features, mailbox import, any parameter named `mailbox`, `folder`, `uid`, `passed_id`, `message_id`. ASVS 5.0 `v5.0.0-1.3.11` (L2) requires sanitising user input before it is passed to mail systems to protect against SMTP or IMAP injection.

A related but different class is **SMTP smuggling** (SEC Consult, 2023): differences between outbound and inbound MTAs in how they treat non-standard end-of-data sequences. That is an MTA configuration issue, not an application injection, and is out of scope here beyond noticing it.

### Cache and key-value protocols

**What happens:** memcached's text protocol and Redis's inline command syntax are line-based. Clients that frame commands properly (Redis's RESP arrays carry explicit byte lengths; memcached `set` carries a byte count for the value) are not affected by CR LF in *values*. Problems appear when keys are built from input and the client does not validate them (a memcached key containing a space or CR LF can add arguments or a second command), or when the application or a script writes raw protocol to a socket.

**Why it matters:** a cache often holds sessions, rate-limit counters, feature flags and serialised objects. Writing another key can mean session poisoning, bypassing rate limits, or feeding data to a deserialiser. ASVS 5.0 `v5.0.0-1.3.9` (L2) names memcache specifically; for Redis and other stores the general rule is `v5.0.0-1.3.3` (L2, sanitise data before passing it to a potentially dangerous context). SSRF into Redis or memcached (for example through a `gopher://` URL) is the bigger cousin and belongs to the Server-Side Request & Files subcategory (not yet published).

**Where to look:** mostly in code review: grep for socket writes, `inline` command helpers, key builders using user names or e-mail addresses, and old or home-grown cache clients. Black-box signs are rare (a `500` for a key with a space when other characters work).

### Log forging, control sequences and log viewers

**What happens:**

- **Forged lines.** `log.info("Login failed for " + username)` in a plain-text format writes whatever the username contains, including `\n` followed by a line that looks like a genuine entry (`2026-11-15T20:00:00Z INFO login ok user=admin`). Anyone reading or parsing the file sees two events.
- **Terminal escape sequences.** An `ESC` character (`0x1B`) followed by `[31m` changes colour; other sequences move the cursor, clear the screen, hide text, set the window title or, in some terminals, write to the clipboard or create hyperlinks. An analyst running `tail -f` or `less -R` sees what the attacker wants (CWE-150).
- **Viewers that render HTML.** An admin "audit log" or a log dashboard that inserts entries into a page without encoding is stored XSS against the people with the most access. The XSS details belong to the Client-Side subcategory (not yet published); here you only detect that markup reaches the viewer unencoded.
- **Logging libraries that interpret the message.** Log4j 2 before the Log4Shell fixes evaluated `${…}` lookups, including JNDI, inside logged data (CVE-2021-44228). That is the extreme case of "the log is an interpreter". ASVS 5.0 `v5.0.0-1.3.8` (L2) covers JNDI injection. This note does not include lookup payloads; see the Apache Log4j security page for affected versions and the [test](#gt-web-crlf-11-control-sequences-markup-and-lookups-in-log-pipelines) for the safe approach.

**Why it matters:** logs are evidence. Forged entries mislead incident response, hide the real event among fakes, frame another user, and break parsers and alert rules that expect one event per line. Escape sequences and HTML attack the reader directly. The OWASP Top 10:2025 lists improper output encoding to logs (CWE-117) under A09:2025 Security Logging and Alerting Failures.

**Where to look:** fields that are logged verbatim: username on failed login, `User-Agent`, `Referer`, `X-Forwarded-For`, search terms, invalid input that triggers a validation error, file names on upload. Admin pages that show activity, audit trails or "recent errors".

The local check below shows the difference in Node.js (illustrative, `cat -v` makes the escape visible as `^[`): a plain-text formatter writes the forged line; JSON loggers escape both the newline and the escape character.

```text
info: login failed for gt-test
2026-11-15T20:00:00Z INFO login ok user=admin^[[31m                        <- winston format.simple()
{"level":30,"username":"gt-test\n2026-11-15T20:00:00Z INFO login ok user=admin\u001b[31m","msg":"login failed"}   <- pino
```

### CSV and formula injection

**What happens:** user-controlled text goes into a CSV, TSV or spreadsheet export. When a cell starts with `=`, `+`, `-` or `@` (and, in various products, a tab, CR or LF, or the full-width forms `＝ ＋ － ＠`), the spreadsheet treats it as a formula. Checking only the *start of the field* is not enough: if the exporter does not quote fields properly, a value containing a separator (`,` or `;`) and a quote can start a new cell that begins with `=`. HackerOne's own export had exactly this bypass after a first fix (see [real-world cases](#real-world-cases)).

**Why it matters:** formulas can show false values (a "total" that is not the total), create links that look legitimate (`HYPERLINK`), and in some products pull data from other cells into a URL when clicked. Historically, Dynamic Data Exchange made command execution possible on the workstation that opened the file, after warnings the user had to accept; current Office versions disable or restrict that by default at the time of writing, which is one reason programmes now rate this lower. Many bug bounty programmes list CSV injection as out of scope or Informative unless you show concrete impact, so check the policy first. In a pentest it is still worth reporting, because the client's own staff open these files.

**Where to look:** "Export to CSV/Excel" on user lists, orders, tickets, audit logs, survey responses, CRM data; scheduled reports sent by mail; imports from partners that are later exported. ASVS 5.0 `v5.0.0-1.2.10` (L3) requires following RFC 4180 sections 2.6 and 2.7 (quote fields containing line breaks, quotes or commas; escape quotes by doubling) and escaping a leading `=`, `+`, `-`, `@`, tab or NUL with a single quote, for CSV and for XLS, XLSX and ODF exports.

### Related: HTTP parameter pollution

HTTP parameter pollution (`WSTG-INJT-04`) is not CRLF injection, but you often find it in the same session because both are about the boundary between "one value" and "several values". Sending `?lang=en&lang=fr` tests which occurrence the application uses, whether a proxy or WAF reads a different one from the back end, and whether duplicates are joined (some stacks join with a comma, which turns two harmless values into one with a separator in it). Where it matters for this note is when a filter checks one occurrence and a header or export is built from another. The authorisation consequences (checking one ID and acting on another, binding extra fields) are tested in [mass assignment and BOPLA](/web/web-mass-assignment-bopla/) (GT-WEB-BOPLA-9) and [IDOR and BOLA](/web/web-idor-bola/) (GT-WEB-IDOR-7). ASVS 5.0 `v5.0.0-15.3.7` (L2) covers it.

## Testing

Every test here assumes an authorised engagement with written scope and rules of engagement, a bug bounty programme whose rules allow this kind of testing, or a lab you run yourself. Responses and outputs shown are illustrative, not captured from a real target.

### Before you start

**Scope and accounts.** Confirm which hosts, which mail-sending features and which export features are in scope. You need at least one normal user account; an admin or support account the client provides is needed for export, audit-log and log-viewer tests, because those are usually where the output is consumed. For grey-box log tests, agree read access to the relevant log files or the log platform (or ask the client to search for your markers and send you the lines).

**Proxy setup.** One Burp project per engagement with the target scope set and Logger on. Useful additions: **Param Miner** (to find unlinked parameters and headers that are reflected), **Hackvertor** (to insert control characters such as `\r`, `\n` or `\x1b` into a request precisely and readably), and **Burp Collaborator** or **interactsh** for out-of-band checks on outbound requests. In Repeater, look at the raw response bytes, not only the parsed header view, and turn off "Update Content-Length" only when you mean to. For HTTP/2 targets, Burp's Inspector lets you put CR LF inside an HTTP/2 header value (drill into the header and press Shift + Return, as PortSwigger's CRLF labs describe); note that this is a request-smuggling technique, so keep it to the single detection step described in [GT-WEB-CRLF-6](#gt-web-crlf-6-header-injection-in-server-side-outbound-requests) unless the scope explicitly covers smuggling.

**Safe proofs only.** Each test stops at the least invasive proof that the delimiter reaches the sink:

| Sink | Proof | Never |
|---|---|---|
| Response header | A new header `X-GT-Test: crlf-1` appears as a separate header in the raw response | Script in a split body, `Set-Cookie` for a real session cookie name, poisoning a shared cache |
| Outbound request | An extra header arrives at **your** Collaborator or interactsh endpoint | Injecting trust headers (`X-User-Id`, `X-Internal`) towards internal services without explicit approval |
| Email | A `Bcc` or extra recipient that is **your own** mailbox receives a copy | Any address you do not control; more than a handful of messages |
| IMAP / SMTP | A syntax error that echoes the command, or a harmless injected `NOOP` / `CAPABILITY` | `DELETE`, `EXPUNGE`, `RENAME`, `COPY`, `STORE` flags, relaying to outside addresses |
| Cache / key-value | An error or a behaviour difference for a key containing a space or CR LF, ideally in code review or staging | Writing or overwriting keys you did not create |
| Logs | A forged line containing the marker `GT-FORGED-LINE`, found by you or the client | Payloads that alter the client's SIEM, alerting or parsers; lookup (JNDI) payloads unless agreed in writing |
| Terminal escapes | One colour sequence (`ESC[31m`) visible as colour in a terminal **you** run, or as `^[` in `cat -v` | Title, clipboard (OSC 52), hyperlink or screen-clearing sequences in logs other people read |
| CSV | A cell showing `2` for `=1+1`, or the value of a cell reference such as `=A1` | DDE, command-launching formulas, `WEBSERVICE`/`IMPORTXML`-style network formulas |

**Email rules.** Tests that send mail only ever send to mailboxes you control: a dedicated test domain or plus-addressed mailbox you own (written as `tester@example.org`, `tester+bcc@example.org` and `tester+cc@example.org` in this note). Warn the client before you submit contact or support forms: they often page a human or open a ticket. Keep the count low (a few messages per feature, not a loop).

**Stop rules.** Stop and report immediately if:

- a probe reaches a shared cache and other users could receive your response (see [GT-WEB-CRLF-5](#gt-web-crlf-5-assess-the-impact-of-a-confirmed-header-injection) on how to avoid that);
- a mail test delivers to an address that is not yours, or the feature sends more mail than you triggered;
- a log or IMAP test shows data from other users' sessions or mailboxes: keep the minimum redacted evidence, do not retrieve more;
- an export contains real customer data: test exports only on data you created, ideally in a test tenant, and delete downloaded files at the end of the engagement.

**Rate limits.** These tests need few requests: a handful of encodings per parameter, sent one at a time. If you use a scanner (Burp Scanner, ZAP's CRLF Injection rule, Nuclei's CRLF templates, CRLFuzz), point it at specific in-scope URLs with a low request rate, never at a crawl of production, and never at mail-sending endpoints.

**A small probe helper.** For one parameter, this sends four harmless variants, one per second, and reports whether the marker header came back as a real header or was only reflected inside another header's value. It uses `http.client` so the path is sent exactly as written, without the client re-encoding it.

```python
#!/usr/bin/env python3
"""Probe one parameter for response header injection with a harmless marker header.
Usage: crlf_probe.py 'https://app.example.com/lang?next=FUZZ' [--cookie 'session=<SESSION_USER_A>']"""
import http.client, ssl, sys, time
from urllib.parse import urlsplit

PROBES = [
    "%0d%0aX-GT-Test:%20crlf-1",        # CR LF
    "%0aX-GT-Test:%20crlf-2",           # bare LF
    "%0dX-GT-Test:%20crlf-3",           # bare CR
    "%250d%250aX-GT-Test:%20crlf-4",    # double-encoded: is the value decoded twice somewhere?
]

def probe(template, cookie=None):
    for p in PROBES:
        u = urlsplit(template.replace("FUZZ", "gt" + p))
        cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        kw = {"context": ssl.create_default_context()} if u.scheme == "https" else {}
        c = cls(u.hostname, u.port, timeout=10, **kw)
        headers = {"User-Agent": "gt-crlf-probe"}
        if cookie:
            headers["Cookie"] = cookie
        c.request("GET", u.path + ("?" + u.query if u.query else ""), headers=headers)
        r = c.getresponse()
        hit = r.getheader("X-GT-Test")
        print(f"{r.status} {'INJECTED ' + hit if hit else 'no marker header'}  <- {p}")
        for name, value in r.getheaders():
            if "GT-Test" in value:
                print(f"    marker reflected inside {name}: {value[:120]}")
        c.close()
        time.sleep(1)

if __name__ == "__main__":
    probe(sys.argv[1], sys.argv[sys.argv.index("--cookie") + 1] if "--cookie" in sys.argv else None)
```

Against a deliberately vulnerable local lab (see [practice labs](#practice-labs)) it prints:

```text
302 INJECTED crlf-1  <- %0d%0aX-GT-Test:%20crlf-1
302 INJECTED crlf-2  <- %0aX-GT-Test:%20crlf-2
302 INJECTED crlf-3  <- %0dX-GT-Test:%20crlf-3
302 no marker header  <- %250d%250aX-GT-Test:%20crlf-4
    marker reflected inside Location: /home?lang=gt%0d%0aX-GT-Test: crlf-4
```

Python's own response parser treats a bare CR or bare LF as a line break, which browsers and caches may not. Treat a bare-CR or bare-LF hit as a lead and confirm it in Burp's raw response view and in a browser before you report it.

### GT-WEB-CRLF-1: Map where input reaches response headers

*Guler Tech methodology.* Implements the discovery step of WSTG-INJT-15 (identify user-controlled input reflected into response headers).

#### What it checks

Which parameters, cookies, headers and path segments are reflected in any response header, and where. The output is the work list for tests 2 to 5.

#### Prerequisites

Burp Logger history from a full walk-through of the application, logged in and logged out; Param Miner installed.

#### Steps

1. Walk every feature, including login, logout, language and theme switches, downloads and every redirect, with Logger on.
2. Search the history for your own input in **response headers**. Use distinctive markers in every field you control (`gtmark01`, `gtmark02`, …) so a search for `gtmark` finds every reflection. Burp's search can be restricted to response headers.
3. For each reflection, record the request location (query, body, path, cookie, request header), the response header, and whether the value is reflected raw, URL-encoded or transformed.
4. Run Param Miner's "Guess headers" and "Guess params" on the redirect and download endpoints you found; it reports unlinked inputs that change the response, including ones reflected in headers.
5. Check the edge: request `http://` versions of hosts, paths without a trailing slash, and paths with a marker (`/gtmark03`) to see whether the proxy echoes the path into `Location` or another header.

```bash
# Is the path echoed into Location by the edge? (illustrative)
curl -s -o /dev/null -D - 'http://app.example.com/gtmark03' | grep -i '^location'
```

#### Observation

A table like this (illustrative):

| Request input | Response header | Reflection | Notes |
|---|---|---|---|
| `?next=` on `/login` | `Location` | Raw in query part | Redirect after login |
| `?lang=` on `/` | `Set-Cookie: lang=…` | Raw | Preference cookie |
| `filename` in `POST /export` | `Content-Disposition` | Inside quotes | User-chosen file name |
| Path on `http://` | `Location` | Decoded | Edge HTTPS redirect |
| `X-Request-Id` request header | `X-Request-Id` | Raw | Echoed by gateway |

#### Evaluation

No finding by itself. Every raw or decoded reflection goes to tests 2 to 4. URL-encoded reflections still go to test 4 (double decoding happens).

#### False positives

Reflections inside the *body* only are not header sinks. A `Location` that contains your value because the server redirected *to a URL you supplied* on another host is an open redirect question, not a CRLF one.

#### Automation

ZAP's passive and active scanners and Burp Scanner both flag input reflected in headers. In CI, an integration test can request each redirecting route with a marker and assert the response's header list has no header named after the marker (see [regression tests](#regression-tests)).

### GT-WEB-CRLF-2: CRLF in redirect targets

*Guler Tech methodology.* Implements WSTG-INJT-15 for the `Location` header.

#### What it checks

Whether CR or LF in a value that ends up in `Location` ends the header line and adds a header.

#### Prerequisites

Redirect inputs from GT-WEB-CRLF-1.

#### Steps

1. Send the redirect with the marker appended to the value, URL-encoded, in the part of the URL where your value lands:

```http
GET /login?next=/home%0d%0aX-GT-Test:%20crlf-1 HTTP/1.1
Host: app.example.com
```

2. If your value lands in the path part of `Location`, try it in a query-string position as well (`/home?x=1%0d%0aX-GT-Test:%20crlf-1`): some platforms encode the path but not the query.
3. Repeat with the parameter in a POST body if the endpoint accepts it (longer values, no URL length limit), and after authentication if the redirect happens post-login.
4. Use the probe helper above for the four standard variants if Repeater shows the value is reflected raw.

```bash
curl -s -o /dev/null -D - 'https://app.example.com/login?next=/home%0d%0aX-GT-Test:%20crlf-1'
```

#### Observation

Vulnerable (illustrative):

```http
HTTP/1.1 302 Found
Location: /home
X-GT-Test: crlf-1
Content-Length: 0
```

Not vulnerable, encoded (Express, Django):

```http
HTTP/1.1 302 Found
Location: /home%0D%0AX-GT-Test:%20crlf-1
```

Not vulnerable, rejected (Node.js `setHeader`, Spring Security): a `500` or `400` with an error such as `ERR_INVALID_CHAR` or "Invalid characters (CR/LF) in header Location". A neutralised value (Tomcat, Go): `Location: /home  X-GT-Test: crlf-1` on one line.

#### Evaluation

- **Fail:** `X-GT-Test` appears as its own header line in the raw response.
- **Pass:** the value is percent-encoded, rejected with an error, or neutralised to spaces on one line.
- A `500` from a rejected header is a robustness issue at most (an unhandled exception on user input); mention it as Info or Low if it leaks a stack trace.

#### False positives

Burp's parsed "Headers" tab can show a header that the raw bytes do not contain, or the reverse, when line endings are unusual. Always read the raw response. A `Location` value with literal `%0d%0a` text is encoded, not injected.

#### Automation

Burp Scanner and ZAP's CRLF Injection active rule test this on crawled parameters; Nuclei's generic CRLF templates and CRLFuzz test lists of URLs. Use them on specific URLs at a low rate. In CI, assert that `GET /login?next=/a%0d%0aX-Test:1` returns no `X-Test` header.

### GT-WEB-CRLF-3: CRLF in cookies and custom headers

*Guler Tech methodology.* Implements WSTG-INJT-15 for `Set-Cookie` and other reflected headers.

#### What it checks

Whether values reflected into `Set-Cookie`, `Content-Disposition`, `X-Request-Id`-style echoes, CORS headers or other custom headers can add a header.

#### Prerequisites

Header reflections from GT-WEB-CRLF-1 other than `Location`.

#### Steps

1. For a preference cookie:

```http
GET /?lang=en%0d%0aX-GT-Test:%20crlf-1 HTTP/1.1
Host: app.example.com
```

2. For a file name reflected into `Content-Disposition` (own export only):

```http
POST /api/export HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
Content-Type: application/json

{"format":"csv","filename":"report\r\nX-GT-Test: crlf-1"}
```

3. For echoed request headers (`X-Request-Id`, `X-Correlation-Id`), send the CR LF inside the request header value. Most HTTP/1.1 servers reject a request header containing a bare CR or LF, and a literal CR LF simply ends your header, so encode the marker the way the application decodes it (some gateways URL-decode or base64-decode IDs) or test whether the application decodes the header value at all.
4. If you need to show cookie impact, inject a cookie with a test-only name the application does not use, in **your own** browser: `%0d%0aSet-Cookie:%20gt_crlf_test=1`. Do not set or overwrite the session cookie or any cookie the application relies on.

#### Observation

Vulnerable (illustrative):

```http
HTTP/1.1 200 OK
Set-Cookie: lang=en
X-GT-Test: crlf-1
Content-Type: text/html; charset=utf-8
```

Not vulnerable (Express `res.cookie`, which URL-encodes the value):

```http
HTTP/1.1 200 OK
Set-Cookie: lang=en%0D%0AX-GT-Test%3A%20crlf-1; Path=/
```

#### Evaluation

- **Fail:** the marker header (or the test cookie) appears as a separate header.
- **Pass:** encoded, rejected or neutralised as in GT-WEB-CRLF-2.

#### False positives

A `Set-Cookie` attribute that *contains* your text (`lang="en X-GT-Test: crlf-1"`) is quoted, not injected. Browsers ignore malformed `Set-Cookie` lines, so confirm a test cookie is actually stored (DevTools, Application tab) before claiming cookie impact.

#### Automation

As GT-WEB-CRLF-2. For `Content-Disposition`, unit-test the download handler with a file name containing CR LF and quotes and assert the header is a single line (or the framework's encoded `filename*=` form).

### GT-WEB-CRLF-4: Encoding, bare LF and path variants

*Guler Tech methodology.* Implements the encoding notes of WSTG-INJT-15 (alternative encodings, components encoded differently). This is a check of the *filter*, not an evasion exercise.

#### What it checks

Whether a CR LF defence that blocked the plain `%0d%0a` is complete: bare LF or bare CR, double decoding, and the path.

#### Prerequisites

A reflection where the plain probe was blocked by application code (a custom filter), not by the framework. If the framework rejected it (an `ERR_INVALID_CHAR`, `BadHeaderError`, encoded `%0D%0A`), stop here: variants do not change the outcome.

#### Steps

1. Bare LF: `%0aX-GT-Test:%20crlf-2`. Many filters strip `\r\n` as a pair but not a lone `\n`; some servers and clients accept a bare LF as a line end.
2. Double encoding: `%250d%250a`, for applications that decode twice (a proxy and the application, or an explicit `urldecode()` after the framework already decoded).
3. Path position, for edge redirects: `GET /%0d%0aX-GT-Test:%20crlf-1 HTTP/1.1` against the `http://` listener and against paths that get a trailing-slash redirect.
4. If the stack is old or exotic, one Unicode variant: characters whose low byte is `0x0a` or `0x0d` (for example U+560A, U+560D) were truncated to LF and CR by some historical Latin-1 header writers. Current Node.js rejects them (we checked: `ERR_INVALID_CHAR`).
5. Stop after these. If none works, the filter is good enough for the purpose of this test.

#### Observation

As GT-WEB-CRLF-2: the marker header appears, or it does not.

#### Evaluation

- **Fail:** any variant produces the marker header. Report the plain probe being blocked and the variant working: the finding is CR LF injection with an incomplete filter.
- **Pass:** all variants are encoded, rejected or neutralised.

#### False positives

Bare-LF hits seen only through tools that split on any line break (Python's `http.client`, some scanners). Check the raw bytes and test in a browser: if the browser does not see a second header, the practical impact is limited to clients that parse like the tool, which you should state.

#### Automation

The probe helper covers steps 1 and 2. For nginx configurations in a grey-box test, run gixy or the Semgrep nginx rules over the configuration files.

### GT-WEB-CRLF-5: Assess the impact of a confirmed header injection

*Guler Tech methodology.* Implements the impact assessment of WSTG-INJT-15 (cache poisoning, XSS, session fixation) with harmless evidence only.

#### What it checks

What a confirmed header injection actually allows on this target, so the report rates it correctly, without performing the attacks.

#### Prerequisites

A confirmed injection from tests 2 to 4.

#### Steps

1. **Body control.** Check whether a second CR LF pair ends the headers and lets you start the body with a plain-text marker: `%0d%0a%0d%0aGT-CRLF-BODY`. If the marker appears at the start of the body as you see it in the browser, script execution in the browser is very likely possible. Do not inject HTML or script; describe the XSS consequence in prose (details in the Client-Side subcategory).
2. **Header precedence.** Note whether your injected header lands before or after the application's own headers. Some impacts depend on it (a `Content-Type` you inject only matters if it wins).
3. **Cookie impact.** Read the session handling: does the application accept a session ID it did not issue, and does it issue a new session ID at login (`v5.0.0-7.2.4`)? If it accepts pre-set IDs and does not rotate, an injected `Set-Cookie` is session fixation. If it uses double-submit CSRF cookies, an injected cookie can defeat them. Evidence: your test-only cookie being stored (GT-WEB-CRLF-3, step 4) plus the documented session behaviour. Do not plant a real session cookie.
4. **Cache exposure.** Without sending any injection to a cached URL, check whether the vulnerable response is cacheable: `Cache-Control`, `Expires`, `Age`, `X-Cache`, `CF-Cache-Status`, `Vary`, and whether the vulnerable parameter is part of the cache key (Param Miner's cache-key checks help here). If the response is cacheable and the parameter is unkeyed or the response could be stored under another URL, describe the cache-poisoning risk in the report; do not try it. If you must confirm cacheability, do it on a URL with a unique cache-buster that only you request, and tell the client to purge it.
5. **Reachability.** Is the injection reachable unauthenticated, by a link (GET), or only by a POST the victim would have to submit? Does it work on the main domain or a sibling the session cookie covers?

#### Observation

A short impact table for the report (illustrative):

| Aspect | Result |
|---|---|
| Header injection | Yes, `Location` on `/login?next=` |
| Body control | Yes, `GT-CRLF-BODY` appears as the body start |
| Cookie impact | Test cookie stored; app accepts pre-set `session` IDs and does not rotate at login |
| Cache | `Cache-Control: no-store`, not cached |
| Delivery | GET link, unauthenticated |

#### Evaluation

The finding is confirmed in tests 2 to 4; this test sets its severity. Use the [rating table](#rating-findings): header-only injection is usually Medium; body control (XSS), working session fixation or a cacheable response raise it.

#### False positives

Body markers that appear only in a raw view but are discarded by browsers (a body after a `Content-Length: 0` the browser respects). Check in a browser, not only in Repeater.

#### Automation

None beyond the regression tests for the original injection. Cacheability checks are manual by design.

### GT-WEB-CRLF-6: Header injection in server-side outbound requests

*Guler Tech methodology.* Extends WSTG-INJT-15 to requests the server makes (CWE-113 covers request splitting), with the HTTP/2 note from WSTG-INJT-16 kept to detection.

#### What it checks

Whether input the server forwards into an outbound HTTP request (to a partner API, a webhook, an internal service) can add a header to that request.

#### Prerequisites

A feature that makes an outbound request with something you control in a header or in the request target: webhooks with custom headers, "test connection" buttons, integrations with a configurable API key or host, link previews. A Burp Collaborator or interactsh endpoint you control, and permission to point the feature at it.

#### Steps

1. Configure the feature to call your collaborator URL and put the CR LF probe into the field that becomes a header, for example a webhook "secret" or "custom header value": `abc\r\nX-GT-Test: crlf-6` (in a JSON body, `\r\n` is the JSON escape).
2. Trigger one request and read what arrived at the collaborator.
3. If the feature uses a host or path you control, put the probe there too (`api.example.com%0d%0aX-GT-Test:%20crlf-6`); HTTP clients have had bugs in host handling.
4. HTTP/2 front ends: send one HTTP/2 request with a CR LF inside a harmless custom header value (Burp Inspector) and note whether the front end rejects it (`RST_STREAM`, `400`) as RFC 9113 requires. If it does not reject it, stop and report the observation; testing what the back end does with it is request smuggling and belongs to that test plan.

```http
POST /api/integrations/webhook HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
Content-Type: application/json

{
  "url": "https://<YOUR_COLLABORATOR_ID>.oastify.com/hook",
  "headers": {
    "X-Partner-Ref": "abc\r\nX-GT-Test: crlf-6"
  }
}
```

#### Observation

Vulnerable (what the collaborator receives, illustrative):

```http
POST /hook HTTP/1.1
Host: <YOUR_COLLABORATOR_ID>.oastify.com
X-Partner-Ref: abc
X-GT-Test: crlf-6
Content-Type: application/json
```

Not vulnerable: the feature returns a validation error, or the collaborator sees `X-Partner-Ref: abc X-GT-Test: crlf-6` on one line, or the request is not sent.

#### Evaluation

- **Fail:** the marker arrives as a separate header.
- **Pass:** rejected, encoded or neutralised.
- For HTTP/2: a front end that accepts CR or LF in header values fails `v5.0.0-4.2.4` (L3) even before any smuggling is shown; report it as a hardening finding and recommend a dedicated smuggling test.

#### False positives

Collaborator interactions caused by other people's tests on a shared collaborator domain: use a fresh payload ID per test. Integrations that deliberately let the customer set arbitrary headers are a feature; the finding is only that a *single* header field can create others.

#### Automation

In CI, unit-test the outbound client wrapper with a header value containing CR LF and assert it throws. Keep HTTP client libraries patched (dependency scanning will flag CVEs such as CVE-2023-23936).

### GT-WEB-CRLF-7: Email header and recipient injection

*Guler Tech methodology.* Implements the SMTP side of WSTG-INJT-10 for application-generated mail.

#### What it checks

Whether input placed into a mail header (sender name, reply-to address, subject, recipient) can add headers or recipients.

#### Prerequisites

A mail-sending feature in scope, at least two mailboxes you control (`tester@example.org` and `tester+bcc@example.org` here), the client warned that test messages will arrive at the receiving end. A local mail catcher such as Mailpit for any lab work.

#### Steps

1. Submit the form normally once, with your own address, and read the delivered message's **full headers** (your mail client's "show original"). Note which header each field lands in: `From`, `Reply-To`, `Subject`, `To`.
2. CR LF in a header field. In the field that becomes `Reply-To` or the display name:

```http
POST /contact HTTP/1.1
Host: app.example.com
Content-Type: application/x-www-form-urlencoded

name=Tester&email=tester%40example.org%0d%0aBcc:%20tester%2Bbcc%40example.org&subject=GT-MAIL-7&message=test
```

3. Repeat in the subject field (`subject=GT-MAIL-7%0d%0aBcc:%20tester%2Bbcc%40example.org`) and, if the API takes JSON, with `\r\n` escapes in the JSON string.
4. Address-list injection. In fields that become recipients (invite, share, "send me a copy"), try a comma and then a semicolon: `tester@example.org,tester+cc@example.org`. In display-name fields, try a quoted comma: `Tester, Second <tester+cc@example.org>`.
5. After each submission, wait for delivery and check **both** mailboxes. Read the full headers of anything that arrives at the second mailbox.

#### Observation

Vulnerable, CR LF (headers of the received message, illustrative):

```text
From: Contact form <noreply@app.example.com>
To: support@app.example.com
Reply-To: tester@example.org
Bcc: tester+bcc@example.org
Subject: GT-MAIL-7
```

(`Bcc` is normally removed before delivery, so the evidence is that `tester+bcc@example.org` received a copy; its own headers show it was not in `To` or `Cc`.)

Vulnerable, address list: `tester+cc@example.org` receives a message intended for one recipient.

Not vulnerable: a validation error; or the subject arrives as `GT-MAIL-7 Bcc: tester+bcc@example.org` on one line (Nodemailer) or folded into the subject (Jakarta Mail); or no second copy arrives.

#### Evaluation

- **Fail:** a mailbox you did not name as the recipient receives the message, or an injected header appears in the delivered message.
- **Pass:** no extra delivery and no extra header.
- A feature that is *designed* to send to an address the user types is not injection by itself; the finding is when one field produces more recipients or headers than intended, or when the feature can be used to send arbitrary content to arbitrary people (that is an abuse and rate-limit question for the Business Logic subcategory).

#### False positives

Mail that arrives at the second mailbox because the plus-addressing routes `tester+bcc@` and `tester@` to the same inbox: check the `Delivered-To` or envelope recipient header of each copy. Messages delayed by greylisting: wait before concluding "no delivery".

#### Automation

None against production; mail tests are manual and few. In CI, unit-test the mail builder with CR LF, commas and quotes in each field and assert the generated message (most libraries can render a message without sending) has exactly the intended headers and envelope recipients.

### GT-WEB-CRLF-8: IMAP and SMTP command injection

*Guler Tech methodology.* Implements WSTG-INJT-10 (identify parameters, understand the command, inject a harmless command).

#### What it checks

Whether parameters a webmail or mail-integrated feature passes to an IMAP or SMTP server can break the command syntax or add a command.

#### Prerequisites

A webmail or mailbox feature in scope, with a test mailbox you own. The mail server's identity if known (error messages often reveal it).

#### Steps

1. List the parameters that obviously map to IMAP arguments: mailbox or folder name, message UID or sequence number, search term, flags.
2. Syntax probes, one at a time, on **your** mailbox (WSTG's list): empty value, a non-existent mailbox (`NOTEXIST`), an extra argument (`INBOX GT`), a stray quote (`INBOX"`), a non-numeric ID (`passed_id=gt`), the parameter removed.

```http
GET /mail/read?mailbox=INBOX%22&uid=4791 HTTP/1.1
Host: webmail.example.com
Cookie: session=<SESSION_USER_A>
```

3. Read the result. An error that echoes the IMAP command and the server's response (`Query: SELECT "INBOX""`, `Unexpected extra arguments`) confirms the value reaches the protocol unescaped.
4. Only if step 3 shows the command: inject one harmless tagged command after a CR LF, keeping the original command intact, and look for its output or for a changed error. `CAPABILITY` and `NOOP` change nothing:

```http
GET /mail/read?mailbox=INBOX&uid=4791%20BODY[HEADER]%0d%0aGT1%20NOOP%0d%0aGT2%20FETCH%204791 HTTP/1.1
Host: webmail.example.com
Cookie: session=<SESSION_USER_A>
```

5. For SMTP features (a web form that talks SMTP directly rather than through a library), the equivalent probe is a CR LF in the sender or recipient field followed by `NOOP`. Do not inject `RCPT TO` for outside addresses or `DATA`.

#### Observation

Vulnerable: the response or error contains the server's reply to your `GT1 NOOP` (`GT1 OK NOOP completed`), or the error changes from "bad syntax" to something that shows two commands were parsed.

Not vulnerable: a generic "invalid mailbox" or "message not found" with no protocol echo, the same for every probe.

#### Evaluation

- **Fail:** a stray quote or CR LF produces a protocol-level error showing your input inside the command (input reaches the protocol unescaped), or an injected harmless command is executed.
- **Pass:** the application validates mailbox names and IDs before using them (generic errors, numeric IDs enforced) and quotes or literal-encodes strings per RFC 9051.
- Rate impact by state: injection only after login runs as your own IMAP user (impact is bypassing application-level restrictions on your own mailbox, or server bugs reachable through commands); injection before authentication, or through a shared service account, is worse.

#### False positives

Verbose IMAP errors without injection: a library that quotes correctly can still show the command in an error. Confirm with step 4 or by reading the code; report verbose errors separately as information disclosure.

#### Automation

None useful against production. In code review, look for string concatenation into IMAP or SMTP commands; maintained IMAP clients (for example ImapFlow for Node, `imaplib` with its quoting helpers in Python, Jakarta Mail's IMAP provider) build commands from structured arguments.

### GT-WEB-CRLF-9: Cache and key-value protocol injection

*Guler Tech methodology.* Implements ASVS `v5.0.0-1.3.9` checks; there is no dedicated WSTG test, so this extends WSTG-INJT-10's protocol-injection approach to memcached and Redis.

#### What it checks

Whether user input becomes part of a cache key or a raw protocol line without validation.

#### Prerequisites

Grey-box access (code, or at least the cache client library and how keys are built) is close to essential. For black-box, a feature that obviously caches by a user-controlled value (profile pages by user name, rate limits by e-mail address, search caches by term).

#### Steps

1. Code review: find where keys are built (`"user:" + username`, `f"rl:{email}"`) and which client is used. Check whether the client rejects keys containing whitespace or control characters (most maintained memcached clients do; check the version in use) or hashes keys.
2. Find any raw protocol writes: socket writes of `set`, `get`, `delete` lines, Redis "inline" commands, home-grown cache wrappers.
3. Black-box, on values you own only: create an object whose cache-key component contains a space, then one containing `%0d%0a`. Compare the behaviour with a normal value: an error only for the space or CR LF, or a cache that never hits for those values, suggests the key reaches the protocol unvalidated.
4. Stop there. Do not try to write or delete other keys.

#### Observation

Code review evidence (illustrative, a vulnerable pattern):

```python
sock.sendall(f"get session:{request.cookies['sid']}\r\n".encode())   # raw memcached text protocol
```

Black-box hint: `500` for a profile name containing a space, while other punctuation works.

#### Evaluation

- **Fail:** keys or commands built from unvalidated input in a line-based protocol (code review), or a reproducible behaviour difference showing the key reaches the protocol raw.
- **Pass:** a client that frames commands (RESP arrays, memcached binary or meta protocol with validated keys), or keys hashed or validated against an allowlist before use.

#### False positives

A `500` for an unusual value caused by something else (database constraint, template error). Without code access, report this at most as a lead.

#### Automation

Semgrep or CodeQL custom rules for socket writes in the cache layer; unit tests that pass a key with a space and CR LF to the cache wrapper and assert it is rejected or hashed.

### GT-WEB-CRLF-10: Log forging with CR and LF

*Guler Tech methodology.* Implements ASVS `v5.0.0-16.4.1`; there is no dedicated current WSTG test (WSTG-INJT-14, Incubated Vulnerability, covers the general idea of a payload stored now and triggered later by another component).

#### What it checks

Whether a request field that is logged can add a line that looks like a separate log event.

#### Prerequisites

Agreement with the client on log access: you read the logs, or they search for your marker and send you the lines. A list of fields that are likely to be logged (failed-login username, `User-Agent`, invalid parameter values).

#### Steps

1. Send one request per candidate field with an injected line that contains a unique marker and is obviously fake:

```http
POST /login HTTP/1.1
Host: app.example.com
Content-Type: application/json
User-Agent: gt-ua%0aGT-FORGED-LINE

{"username":"gt-user\n2026-11-15T20:00:00Z INFO GT-FORGED-LINE login ok user=gt-admin","password":"wrong"}
```

2. The JSON `\n` escape puts a real LF in the username. The `User-Agent` above contains the *text* `%0a`, which most servers do not decode; it tells you whether something downstream URL-decodes before logging.
3. Ask for (or search) the log lines around the request time for `GT-FORGED-LINE`.
4. Note the log format (plain text, JSON, key=value) and where it is shipped (file, SIEM, cloud logging).

#### Observation

Vulnerable (plain-text log, illustrative):

```text
2026-11-15T20:12:03Z WARN auth login failed user=gt-user
2026-11-15T20:00:00Z INFO GT-FORGED-LINE login ok user=gt-admin
```

Not vulnerable (structured log, illustrative):

```json
{"ts":"2026-11-15T20:12:03Z","level":"warn","msg":"login failed","user":"gt-user\n2026-11-15T20:00:00Z INFO GT-FORGED-LINE login ok user=gt-admin"}
```

Also not vulnerable: the LF replaced (`gt-user_2026-…` or `gt-user\\n2026-…` in a text log).

#### Evaluation

- **Fail:** the marker starts a new line in a line-oriented log or appears as a separate event in the log platform.
- **Pass:** CR and LF are escaped or replaced, or the log is structured and the parser keeps the value in one field.
- Note: a log platform that ingests JSON can still *display* the newline as a line break in its UI. That is cosmetic unless analysts or rules treat displayed lines as events.

#### False positives

Your request rejected before logging (validation error, WAF) and therefore not logged: confirm the normal value is logged first. Multi-line stack traces are not forged lines.

#### Automation

CodeQL's log-injection queries (`java/log-injection`, `js/log-injection`, `py/log-injection`, `go/log-injection`) and Semgrep's `crlf-injection-logs` rule for Java find concatenated log messages. In CI, a test that logs a value with CR LF through the application's logger and asserts the captured output is one event.

### GT-WEB-CRLF-11: Control sequences, markup and lookups in log pipelines

*Guler Tech methodology.* Implements ASVS `v5.0.0-16.4.1` for log consumers, with WSTG-INJT-14 (incubated) as the model: the payload is stored by one component and triggered by another.

#### What it checks

Whether logged input is interpreted by whoever reads the logs: a terminal (escape sequences), a web-based log or audit viewer (markup), or the logging library itself (lookups).

#### Prerequisites

As GT-WEB-CRLF-10, plus access to the in-application log or audit viewer with your admin test account, if there is one. Explicit agreement before sending any escape sequence into logs that the client's staff read.

#### Steps

1. **Terminal escapes.** With agreement, send one colour sequence in a logged field, using the JSON `\u001b` escape: `"username":"gt-esc-\u001b[31mRED\u001b[0m"`. Read the line yourself with `cat -v` (shows `^[[31m`, meaning the raw escape is in the file) and, if you can, in a terminal (shows red text). Nothing else: no cursor movement, screen clearing, title, hyperlink or clipboard sequences.
2. **Viewer markup.** Put harmless markup with a marker in a logged field, for example a username of `gt-<b>GT-BOLD</b>`, then open the admin audit or activity view as your admin test account. If the marker renders **bold**, the viewer inserts log data as HTML. Stop there and report it; script execution is the Client-Side (XSS) subcategory's test.
3. **Library lookups.** Identify the logging library and version (dependency manifests in a grey-box test, error pages, `Server` and framework fingerprints). Report vulnerable Log4j 2 versions from the version evidence; the Apache Log4j security page lists affected and fixed releases. Send lookup or JNDI payloads only with explicit written approval and only to an out-of-band endpoint you control; that test belongs with JNDI injection (ASVS `v5.0.0-1.3.8`) in the Server-Side Request & Files subcategory.

#### Observation

Vulnerable viewer (what the admin page's HTML contains, illustrative):

```text
<td class="user">gt-<b>GT-BOLD</b></td>
```

Not vulnerable: the page shows the literal text `gt-<b>GT-BOLD</b>` (HTML-encoded as `&lt;b&gt;` in the source).

#### Evaluation

- **Fail:** raw escape bytes reach a log that people read in terminals (Low; higher if your agreed check shows they render), markup renders in a log viewer (rate as stored XSS against privileged users once confirmed by the XSS test), or a logging library version with known lookup evaluation is in use (rate by that CVE).
- **Pass:** control characters are escaped (`\u001b` in JSON, `\x1b` or replaced in text) and viewers encode output.

#### False positives

A log viewer that renders a fixed set of safe formatting from its own templates (not from your data). Terminals and pagers that strip escapes (`less` without `-R`) hide the problem from you but not from colleagues using other tools: `cat -v` on the raw file is the real check.

#### Automation

Unit-test the log formatter with `\u001b[31m` and assert the output contains no raw `0x1B`. Software composition analysis catches vulnerable logging library versions.

### GT-WEB-CRLF-12: CSV and formula injection in exports

*Guler Tech methodology.* Implements WSTG-INJT-21 (find exports, place benign formula values, test cell breakout, verify in a spreadsheet, re-check after save and re-open).

#### What it checks

Whether user-controlled values in a CSV or spreadsheet export are interpreted as formulas when the file is opened, including after Excel saves and re-opens it.

#### Prerequisites

An export feature in scope and data **you** created that appears in it (a test tenant or your own records). The role that opens exports in real life (admin, finance) noted for the rating. Microsoft Excel and LibreOffice Calc in an isolated test VM, and a text editor.

#### Steps

1. Put benign formula values into fields that end up in the export, one per record so you can tell them apart. Use only harmless formulas: `=1+1`, `+1+1`, `-1+1`, `@SUM(1,1)`, a cell reference such as `=A1`, and one tab-prefixed value (`\t=1+1`, JSON escape) if the API accepts it.
2. Cell breakout: in one field, put a value that closes the quoted field and starts a new cell, adjusted to the separator the export uses: `gt",=1+1,"x` for comma-separated, `gt";=1+1;"x` for semicolon-separated.
3. Export as the role that normally exports (your admin test account), or as yourself if users export their own data.
4. Open the raw file in a text editor first. For each test value, note whether it is quoted, prefixed with `'` or a tab, or written as-is, and whether any cell *starts* with `=`, `+`, `-`, `@`, tab or CR.
5. Open the file in Excel (double-click) and in LibreOffice Calc (note whether the text-import dialog has an option to evaluate formulas and whether it is on, where your version offers one). A cell showing `2`, or the formula bar showing a formula, means evaluation.
6. If the application escapes values, save the file in Excel as CSV, close, re-open, and check again (WSTG's save and re-open step).

```text
id,name,company
1001,"=1+1",GT Ltd                       <- vulnerable: cell starts with =
1002,"'=1+1",GT Ltd                      <- escaped with a leading single quote
1003,"gt"",=1+1,""x",GT Ltd               <- quotes doubled: breakout neutralised
1004,gt",=1+1,"x,GT Ltd                    <- not quoted: breakout creates a cell starting with =
```

#### Observation

Vulnerable: the `name` cell shows `2`; or the breakout row has an extra cell showing `2`.

Not vulnerable: every test value shows as literal text (`=1+1`) in both applications and after save and re-open.

#### Evaluation

- **Fail:** any user-controlled value is evaluated as a formula in a spreadsheet application the client's staff use.
- **Pass:** no evaluation, including after save and re-open in Excel, and the raw file shows RFC 4180 quoting plus an escape for leading formula characters (`v5.0.0-1.2.10`).
- Report the role that opens the export and whether exports leave the organisation, and describe impact in prose (misleading values, links that look trusted, workstation-side risk depending on spreadsheet configuration). Check the programme policy: many bug bounty programmes rate CSV injection as Informative or out of scope without demonstrated impact.

#### False positives

A value that *looks* like a formula in the text editor but is quoted *and* escaped (`"'=1+1"`). Formulas you typed into the spreadsheet yourself while checking. Numeric columns: a negative number (`-5`) displayed as a number is not a formula.

#### Automation

Semgrep's `use-defusedcsv` and `csv-writer-injection` rules flag Python's `csv` module used with user data. In CI, a unit test that exports a record containing each leading character and the breakout value, parses the result with a strict CSV reader, and asserts no field starts with `=`, `+`, `-`, `@`, tab, CR or NUL (see [regression tests](#regression-tests)).

## Secure implementation

### Design rules

- **Never write a protocol by hand.** Use the framework's header, cookie, redirect and download APIs, a maintained mail library with structured address objects, a structured logger and a CSV writer. All of them know the delimiters; string concatenation does not. This is ASVS `v5.0.0-1.2.1` (L1) for HTTP headers.
- **Validate the *shape* of values that go into headers, before encoding.** A language is one of a short list; a redirect target is a local path; a file name matches a conservative pattern; an e-mail address is exactly one addr-spec. Allowlists remove the question of which control character a sink cares about.
- **Encode for the sink when the value is free text.** URL-encode values placed in URLs (`v5.0.0-1.2.2`, L1), RFC 5987-encode file names, JSON-encode log fields, RFC 4180-quote and formula-escape CSV fields (`v5.0.0-1.2.10`, L3).
- **Keep the safety net on.** Do not disable Spring Security's firewall, do not catch and ignore `ERR_INVALID_CHAR` or `BadHeaderError` by stripping the check, keep runtimes, HTTP clients and mail libraries patched. Reject CR, LF and NUL in HTTP/2 and HTTP/3 header values at the edge (`v5.0.0-4.2.4`, L3).
- **Mail:** pass recipients and reply-to as address objects, never formatted strings; fix the recipient of contact forms on the server; validate user addresses as a single address (`v5.0.0-1.3.11`, L2).
- **Logs:** structured logs (JSON) with user data in separate fields, CR, LF and control characters escaped by the encoder (`v5.0.0-16.4.1`, L2, and `v5.0.0-16.2.4`, L2); log viewers encode output as HTML text; no logging library that evaluates expressions in data.
- **Cache keys:** build them from validated or hashed components (`v5.0.0-1.3.9`, L2), use clients that frame commands.
- **Exports:** quote every field, double embedded quotes, prefix a leading formula character with `'`; decide deliberately whether the Excel-resistant tab variant is needed for files that will be re-saved.

### Response headers and redirects

#### Node.js and Express

```javascript
const LANGS = new Set(['en', 'fr', 'de']);
const LOCAL_PATH = /^\/(?!\/)[A-Za-z0-9\/_\-.]*$/;   // a local path, not //evil.example or a scheme

app.get('/lang', (req, res) => {
  const lang = LANGS.has(req.query.lang) ? req.query.lang : 'en';      // allowlist, never the raw value
  res.cookie('lang', lang, { httpOnly: true, secure: true, sameSite: 'lax' });   // res.cookie URL-encodes values
  res.redirect(303, '/');
});

app.get('/login/continue', (req, res) => {
  const next = typeof req.query.next === 'string' && LOCAL_PATH.test(req.query.next) ? req.query.next : '/';
  res.redirect(303, next);                         // res.location() also runs the value through encodeurl
});

app.get('/api/export/:id', requireUser, async (req, res) => {
  const name = `report-${req.params.id}.csv`;      // build file names yourself where you can
  res.attachment(name);                            // uses content-disposition: CR LF ends up percent-encoded in filename*
  res.type('text/csv').send(await buildCsv(req.user, req.params.id));
});
```

Do not wrap `res.setHeader` in a `try`/`catch` that "cleans" the value and retries; let the `ERR_INVALID_CHAR` error surface and fix the input path. Node's `http` module (and so Express) refuses CR and LF in any header value.

#### Django

```python
from django.http import FileResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils.http import url_has_allowed_host_and_scheme

LANGS = {"en", "fr", "de"}

def set_lang(request):
    lang = request.GET.get("lang")
    response = redirect("/")
    response.set_cookie("lang", lang if lang in LANGS else "en", secure=True, httponly=True, samesite="Lax")
    return response

def continue_after_login(request):
    nxt = request.GET.get("next", "/")
    if not url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        nxt = "/"
    return redirect(nxt)        # HttpResponseRedirect percent-encodes CR LF in Location

def download(request, pk):
    report = get_object_or_404(Report, pk=pk, owner=request.user)
    return FileResponse(report.file.open("rb"), as_attachment=True, filename=report.display_name)
    # content_disposition_header() encodes unusual names as filename*=utf-8''…
```

Setting a header with a newline raises `BadHeaderError`; leave it to raise (a `500` in tests tells you an input path is wrong).

#### Spring

```java
@Controller
class PreferenceController {
    private static final Set<String> LANGS = Set.of("en", "fr", "de");
    private static final Pattern LOCAL_PATH = Pattern.compile("^/(?!/)[A-Za-z0-9/_\\-.]*$");

    @GetMapping("/lang")
    ResponseEntity<Void> lang(@RequestParam(defaultValue = "en") String lang) {
        ResponseCookie cookie = ResponseCookie.from("lang", LANGS.contains(lang) ? lang : "en")
                .httpOnly(true).secure(true).sameSite("Lax").path("/").build();
        return ResponseEntity.status(HttpStatus.SEE_OTHER)
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .location(URI.create("/")).build();
    }

    @GetMapping("/login/continue")
    ResponseEntity<Void> next(@RequestParam(defaultValue = "/") String next) {
        String target = LOCAL_PATH.matcher(next).matches() ? next : "/";
        return ResponseEntity.status(HttpStatus.SEE_OTHER).location(URI.create(target)).build();
    }

    @GetMapping("/api/export/{id}")
    ResponseEntity<byte[]> export(@PathVariable long id, Authentication auth) {
        byte[] csv = reports.csvFor(auth, id);
        ContentDisposition cd = ContentDisposition.attachment()
                .filename("report-" + id + ".csv", StandardCharsets.UTF_8).build();   // RFC 5987-encoded
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION, cd.toString())
                .contentType(MediaType.parseMediaType("text/csv")).body(csv);
    }
}
```

`ResponseCookie.from()` validates cookie names and values, and with Spring Security on the classpath the default `StrictHttpFirewall` wraps every response in `FirewalledResponse`, which rejects CR and LF in header names, header values, redirect locations and cookie fields. Keep it as the safety net, not the primary control.

#### Laravel

```php
use Illuminate\Http\Request;

Route::get('/lang', function (Request $request) {
    $lang = in_array($request->query('lang'), ['en', 'fr', 'de'], true) ? $request->query('lang') : 'en';
    return redirect('/')->withCookie(cookie('lang', $lang, 60 * 24 * 365));
});

Route::get('/login/continue', function (Request $request) {
    $next = $request->query('next', '/');
    if (! is_string($next) || ! preg_match('#^/(?!/)[A-Za-z0-9/_\-.]*$#', $next)) {
        $next = '/';
    }
    return redirect()->to($next);
});

Route::get('/api/export/{report}', function (Report $report) {
    Gate::authorize('view', $report);
    return response()->download($report->path(), 'report-'.$report->id.'.csv');
});
```

Laravel sends headers through Symfony HttpFoundation and PHP's `header()`, which refuses a header containing a newline or a NUL byte; Symfony's `HeaderUtils::makeDisposition()` throws for download names whose ASCII fallback contains characters outside printable ASCII, `%`, `/` or `\`. Laravel's cookies are encrypted by default, so the stored value is not your raw input.

#### nginx and other proxies

```text
# Vulnerable: $uri is decoded, so %0d%0a in the path becomes CR LF in Location
return 301 https://$host$uri;

# Fixed: $request_uri is the original, still-encoded request URI
return 301 https://$host$request_uri;

# Captures used in headers: restrict to a safe set, not "anything but a dot"
location ~ ^/v1/(?<action>[a-z0-9_-]+)\.json$ {
    add_header X-Action $action;
}
```

### Email

#### Nodemailer

```javascript
const SINGLE_ADDRESS = /^[^\s@,;<>"()]+@[^\s@,;<>"()]+\.[^\s@,;<>"()]+$/;

async function sendContact(form) {
  if (!SINGLE_ADDRESS.test(form.email) || form.email.length > 254) throw new BadRequest('invalid email');
  await transporter.sendMail({
    from: { name: 'Example support', address: 'noreply@app.example.com' },
    to: 'support@app.example.com',                          // fixed server-side recipient
    replyTo: { name: form.name, address: form.email },      // an address object, never `${name} <${email}>`
    subject: `Contact form: ${form.subject.slice(0, 150)}`,
    text: form.message,
  });
}
```

In our local check, Nodemailer replaced CR LF in the subject and custom headers with spaces and quoted a hostile display name in the object form, but a plain string such as `'a@example.org, b@example.org'` in `to` became two envelope recipients. The object form plus a single-address check closes that.

#### Django

```python
from email.headerregistry import Address
from django.core.exceptions import ValidationError
from django.core.mail import EmailMessage
from django.core.validators import validate_email
from django.http import HttpResponseBadRequest
from django.shortcuts import redirect

def send_contact(data):
    validate_email(data["email"])                 # exactly one valid address, raises ValidationError
    msg = EmailMessage(
        subject="Contact form: " + data["subject"][:150],
        body=data["message"],
        from_email="noreply@app.example.com",
        to=["support@app.example.com"],
        reply_to=[Address(display_name=data["name"], addr_spec=data["email"])],
    )
    msg.send()    # CR or LF in any header raises ValueError (Django 6.0+; BadHeaderError, a ValueError subclass, before)

def contact_view(request):
    form = ContactForm(request.POST)
    if not form.is_valid():
        return HttpResponseBadRequest()
    try:
        send_contact(form.cleaned_data)
    except (ValueError, ValidationError):
        return HttpResponseBadRequest()
    return redirect("/contact/thanks")
```

Catching `ValueError` works on both sides of the Django 6.0 change, because the older `BadHeaderError` subclasses `ValueError`. `Address(addr_spec=…)` itself rejects an addr-spec that contains more than one address.

#### Spring

```java
void sendContact(ContactForm form) throws MessagingException, UnsupportedEncodingException {
    InternetAddress replyTo = new InternetAddress(form.email(), true);   // strict: exactly one address
    replyTo.validate();
    replyTo.setPersonal(form.name(), "UTF-8");

    MimeMessage message = mailSender.createMimeMessage();
    MimeMessageHelper helper = new MimeMessageHelper(message, false, "UTF-8");
    helper.setFrom("noreply@app.example.com");
    helper.setTo("support@app.example.com");
    helper.setReplyTo(replyTo);
    helper.setSubject("Contact form: " + form.subject().replaceAll("[\\r\\n\\x00]", " "));
    helper.setText(form.message());
    mailSender.send(message);
}
```

In our check with Angus Mail 2.0.5, a CR LF in the subject was folded into a continuation line (harmless) and an address with CR LF was rejected, but `InternetAddress.parse("a@example.org, b@example.org")` returns two addresses. The single-address constructor plus `validate()` closes that; replacing control characters in the subject keeps the data clean and protects older mail stacks. Keep `org.eclipse.angus` mail at a version that includes the CVE-2025-7962 fix (check the advisory for the fixed release that applies to your line).

#### Laravel

```php
use Illuminate\Mail\Mailables\Address;
use Illuminate\Mail\Mailables\Envelope;

// Controller
$data = $request->validate([
    'name'    => ['required', 'string', 'max:100', 'regex:/^[^\r\n]*$/'],
    'email'   => ['required', 'email:rfc', 'max:254'],
    'subject' => ['required', 'string', 'max:150', 'regex:/^[^\r\n]*$/'],
    'message' => ['required', 'string', 'max:5000'],
]);
Mail::to('support@app.example.com')->send(new ContactMessage($data));

// App\Mail\ContactMessage
public function envelope(): Envelope
{
    return new Envelope(
        subject: 'Contact form: '.$this->data['subject'],
        replyTo: [new Address($this->data['email'], $this->data['name'])],
    );
}
```

Laravel Mail is built on Symfony Mailer: Symfony's `Address` validates the address with `egulias/email-validator` and strips CR and LF from display names, and header tokens with CR or LF are encoded. The validation rules make the failure a clean `422` instead of an exception. Avoid PHP's `mail()` with a string `additional_headers` built from input anywhere in the code base.

### Logging

The OWASP Logging Cheat Sheet's advice is short: sanitise CR, LF and delimiter characters in event data, encode for the log format, and prefer structured formats such as JSON over unstructured text. It adds a point that surprises many Java developers: parameterised logging (`log.info("user {}", name)`) alone does not prevent CR LF injection; the encoder has to escape the value.

#### Node.js

```javascript
const logger = require('pino')();                  // JSON lines; JSON.stringify escapes \n, \r and \u001b

app.post('/login', async (req, res) => {
  const ok = await auth.check(req.body.username, req.body.password);
  if (!ok) {
    logger.warn({ event: 'login_failed', username: String(req.body.username).slice(0, 128), ip: req.ip }, 'login failed');
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  // …
});
```

If you use winston, use `format.json()` rather than `format.simple()` or a `printf` template that concatenates user data: our local check showed `format.simple()` writing a forged second line, `format.json()` escaping it.

#### Django and Python

```python
# myapp/logging.py
import json, logging
from datetime import datetime, timezone

class JsonFormatter(logging.Formatter):
    def format(self, record):
        event = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            **getattr(record, "fields", {}),
        }
        if record.exc_info:
            event["exc"] = self.formatException(record.exc_info)
        return json.dumps(event, ensure_ascii=True, default=str)   # escapes CR, LF, ESC and other controls

# settings.py
LOGGING = {
    "version": 1,
    "formatters": {
        "json": {"()": "myapp.logging.JsonFormatter"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "json"},
    },
    "root": {"handlers": ["console"], "level": "INFO"},
}

# usage: user data goes in fields, the message stays constant
fields = {"username": username[:128]}
logger.warning("login failed", extra={"fields": fields})
```

Python's default `logging.Formatter` writes messages as given, so `logger.warning("login failed for %s", username)` with a newline in `username` produces a forged line in a text log.

#### Spring

Spring Boot (3.4 and later) has built-in structured logging; one property switches console or file output to JSON:

```yaml
logging:
  structured:
    format:
      console: ecs        # also logstash or gelf
```

If you must keep a text pattern, escape in the pattern itself (Log4j 2's `enc` converter with the `CRLF` option writes `\r` and `\n` as visible escapes):

{% raw %}
```text
Logback:  %d %-5level %logger - %replace(%msg){'[\r\n]', '_'}%n
Log4j 2:  %d %-5level %logger - %enc{%m}{CRLF}%n
```
{% endraw %}

Keep messages constant and pass user data as arguments or structured key-value pairs, never by concatenation. Keep Log4j 2 on a release listed as fixed on the Apache Log4j security page.

#### Laravel

```php
// config/logging.php
'channels' => [
    'stack' => ['driver' => 'stack', 'channels' => ['json']],
    'json' => [
        'driver' => 'monolog',
        'handler' => Monolog\Handler\StreamHandler::class,
        'handler_with' => ['stream' => storage_path('logs/laravel.json')],
        'formatter' => Monolog\Formatter\JsonFormatter::class,
    ],
],

// usage
Log::warning('login failed', ['username' => Str::limit((string) $request->input('username'), 128)]);
```

Laravel's default channels use Monolog's `LineFormatter` with inline line breaks allowed (so stack traces stay readable). Our reading of the Laravel 13 and Monolog sources at the time of writing is that a CR LF in a logged message is then written as a real line break, so the default text log is forgeable; the JSON formatter escapes it.

#### Log viewers

Whatever renders logs in a browser (an admin audit page, an internal dashboard) must treat entries as text: framework auto-escaping in templates, no `innerHTML`, no "render as Markdown". Serve raw log files, if at all, as `text/plain` (the Logging Cheat Sheet makes the same point).

### CSV and spreadsheet exports

The combined rule from RFC 4180, ASVS `v5.0.0-1.2.10` and the OWASP CSV Injection page: quote every field, double embedded quotes, and if a field starts with `=`, `+`, `-`, `@`, tab, CR, LF or NUL (and, for some locales, the full-width `＝ ＋ － ＠`), prefix it with a single quote. Leave typed numbers from your own data alone, so negative amounts stay numbers. Two caveats from the OWASP page and WSTG: Excel can drop the quote escaping when a user saves and re-opens the file, and the Excel-resistant alternative is a tab character at the start of the quoted field, which changes the data for programmatic consumers. Pick one deliberately and test it in the spreadsheet your users have.

#### Node.js

```javascript
const FORMULA_START = /^[=+\-@\t\r\n\0＝＋－＠]/;

function csvCell(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);   // typed numbers stay numbers
  let s = value == null ? '' : String(value);
  if (FORMULA_START.test(s)) s = "'" + s;          // ASVS 1.2.10: escape a leading formula character with '
  return '"' + s.replace(/"/g, '""') + '"';        // RFC 4180 2.6 and 2.7: quote the field, double quotes
}

const csvRow = (cells) => cells.map(csvCell).join(',') + '\r\n';
```

#### Django and Python

```python
import csv
from django.http import HttpResponse

FORMULA_START = ("=", "+", "-", "@", "\t", "\r", "\n", "\0", "＝", "＋", "－", "＠")

def safe_cell(value):
    if value is None or isinstance(value, (int, float)):     # typed numbers from your own data
        return value
    s = str(value)
    return "'" + s if s.startswith(FORMULA_START) else s

def export_customers(request):
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="customers.csv"'
    writer = csv.writer(response, quoting=csv.QUOTE_ALL, lineterminator="\r\n")   # quotes doubled by default
    writer.writerow(["id", "name", "company"])
    for c in Customer.objects.filter(tenant=request.user.tenant):
        writer.writerow([c.id, safe_cell(c.name), safe_cell(c.company)])
    return response
```

The `defusedcsv` package on PyPI is a drop-in wrapper around `csv` that applies formula escaping; Semgrep's `use-defusedcsv` rule points to it.

#### Spring and Java

```java
final class Csv {
    private static final Pattern FORMULA_START = Pattern.compile("^[=+\\-@\\t\\r\\n\\x00\\uFF1D\\uFF0B\\uFF0D\\uFF20]");

    static String cell(Object value) {
        if (value instanceof Number n) return n.toString();
        String s = value == null ? "" : value.toString();
        if (FORMULA_START.matcher(s).find()) s = "'" + s;
        return "\"" + s.replace("\"", "\"\"") + "\"";
    }

    static String row(Object... cells) {
        return Arrays.stream(cells).map(Csv::cell).collect(Collectors.joining(",")) + "\r\n";
    }
}
```

Libraries such as Apache Commons CSV handle RFC 4180 quoting for you; check whether the version you use also escapes formulas, and if not, apply `cell()`-style escaping to values before handing them over.

#### Laravel and PHP

```php
use League\Csv\EscapeFormula;
use League\Csv\Writer;

$writer = Writer::createFromString();
$writer->addFormatter((new EscapeFormula())->escapeRecord(...));   // escapes leading + - = @ \t \r with '
$writer->insertOne(['id', 'name', 'company']);
foreach (Customer::where('tenant_id', $request->user()->tenant_id)->cursor() as $c) {
    $writer->insertOne([$c->id, $c->name, $c->company]);
}

return response($writer->toString(), 200, [
    'Content-Type' => 'text/csv; charset=UTF-8',
    'Content-Disposition' => 'attachment; filename="customers.csv"',
]);
```

`league/csv`'s `EscapeFormula` formatter escapes a leading `+`, `-`, `=`, `@`, tab and CR by default, and its constructor accepts extra characters to escape (for example LF and NUL, to match ASVS fully; check which characters your version accepts). With plain `fputcsv()`, apply the same prefix yourself and pass an empty `escape` argument so quoting follows RFC 4180 rather than PHP's backslash escape.

### Static analysis

| Tool | Rule or query | Finds |
|---|---|---|
| CodeQL | `java/http-response-splitting`, `py/http-response-splitting` | User input flowing into response headers |
| CodeQL | `java/log-injection`, `js/log-injection`, `py/log-injection`, `go/log-injection`, `cs/log-forging` | User input written to logs without neutralisation |
| Semgrep (community rules) | `java/lang/security/audit/http-response-splitting`, `java/lang/security/audit/crlf-injection-logs` | Header and log CRLF in Java |
| Semgrep (community rules) | `generic/nginx/security/header-injection` | nginx `location` captures used in `add_header` |
| Semgrep (community rules) | `python/lang/security/use-defusedcsv`, `python/django/security/injection/csv-writer-injection` | `csv.writer` with user data |
| gixy | `http_splitting` | nginx `$uri`, `$document_uri` and loose captures in `return`, `rewrite`, `add_header`, `proxy_set_header` |

Add a custom rule (Semgrep or a simple grep in CI) for the patterns no general rule knows: PHP `mail(` with a fourth argument built from request data, socket writes in the cache layer, `printf`-style log templates in winston, string-formatted e-mail addresses (`f'"{name}" <{email}>'`).

### Regression tests

Write one test per sink with the probe values from the tests above, and assert on the *structure* of the output, not on a specific error message.

```javascript
// Express, Jest and supertest
const request = require('supertest');

test.each(['%0d%0aX-GT-Test:%201', '%0aX-GT-Test:%201', '%250d%250aX-GT-Test:%201'])(
  'no header injection through next=%s', async (probe) => {
    const res = await request(app).get('/login/continue?next=/home' + probe);
    expect(res.headers['x-gt-test']).toBeUndefined();
  });

test('CSV export neutralises formulas and breakout', async () => {
  await seedCustomer({ name: '=1+1' }, { name: 'gt",=1+1,"x' }, { name: '\t=1+1' });
  const res = await request(app).get('/api/export/customers').set('Cookie', adminCookie);
  const rows = parseCsv(res.text);                     // a strict RFC 4180 parser such as csv-parse
  for (const cell of rows.slice(1).flat()) expect(cell).not.toMatch(/^[=+\-@\t\r\n\0]/);
});
```

```python
# Django
import csv, io
from django.core import mail
from django.test import TestCase
from myapp.logging import JsonFormatter

class InjectionRegressionTests(TestCase):
    def test_redirect_has_no_injected_header(self):
        r = self.client.get("/login/continue", {"next": "/home\r\nX-GT-Test: 1"})
        self.assertNotIn("X-GT-Test", r.headers)

    def test_contact_form_rejects_header_injection(self):
        r = self.client.post("/contact", {"name": "T", "email": "tester@example.org\r\nBcc: tester+bcc@example.org",
                                          "subject": "s", "message": "m"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(len(mail.outbox), 0)

    def test_contact_form_sends_to_one_recipient(self):
        self.client.post("/contact", {"name": "T, X", "email": "tester@example.org", "subject": "s", "message": "m"})
        self.assertEqual(mail.outbox[0].recipients(), ["support@app.example.com"])

    def test_log_line_stays_one_event(self):
        with self.assertLogs("myapp.auth", level="WARNING") as cm:
            self.client.post("/login", {"username": "gt\nGT-FORGED-LINE", "password": "x"})
        self.assertTrue(all("\n" not in JsonFormatter().format(r) for r in cm.records))

    def test_csv_cells_do_not_start_with_formula(self):
        Customer.objects.create(tenant=self.tenant, name="=1+1", company="@SUM(1,1)")
        self.client.force_login(self.admin)
        body = self.client.get("/export/customers.csv").content.decode()
        for row in list(csv.reader(io.StringIO(body)))[1:]:
            for cell in row:
                self.assertFalse(cell.startswith(("=", "+", "-", "@", "\t", "\r", "\n", "\0")), cell)
```

```java
// Spring, MockMvc
@Test
void redirectHasNoInjectedHeader() throws Exception {
    mvc.perform(get("/login/continue").param("next", "/home\r\nX-GT-Test: 1"))
       .andExpect(header().doesNotExist("X-GT-Test"));
}
```

```php
// Laravel, PHPUnit
public function test_lang_cookie_has_no_injected_header(): void
{
    $this->get('/lang?lang='.rawurlencode("en\r\nX-GT-Test: 1"))->assertHeaderMissing('X-GT-Test');
}

public function test_contact_form_rejects_crlf_in_subject(): void
{
    Mail::fake();
    $this->post('/contact', ['name' => 'T', 'email' => 'tester@example.org',
        'subject' => "s\r\nBcc: tester+bcc@example.org", 'message' => 'm'])->assertSessionHasErrors('subject');
    Mail::assertNothingSent();
}
```

If an export has signed numeric columns, run the leading-character assertion on the free-text columns only, since a typed negative number is meant to stay a number.

## Practice labs

**PortSwigger Web Security Academy.** At the time of writing we found no Academy lab dedicated to response header injection, e-mail header injection or CSV injection. The two CRLF labs are HTTP/2 downgrade labs and belong with request smuggling (HTTP & Infrastructure subcategory): [HTTP/2 request smuggling via CRLF injection](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-smuggling-via-crlf-injection) and [HTTP/2 request splitting via CRLF injection](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-splitting-via-crlf-injection). They are useful here to see why a CR LF inside an HTTP/2 header value matters (GT-WEB-CRLF-6).

**OWASP WebGoat.** The *Logging Security* lesson has a [log spoofing task](https://github.com/WebGoat/WebGoat/blob/main/src/main/resources/lessons/logging/documentation/logSpoofing_Task.adoc): make the log show that `admin` logged in successfully, which is GT-WEB-CRLF-10 in a lab.

**Build your own (local only).** These classes are easy to reproduce on your own machine, and doing so is the best way to learn what a real hit looks like in raw bytes:

- *Header injection:* Python's `http.server` does not validate header values, so this deliberately vulnerable server, bound to `127.0.0.1`, reproduces GT-WEB-CRLF-2 and the probe-helper output above. Never expose it.

```python
# lab_crlf.py — deliberately vulnerable, localhost only
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlsplit(self.path).query)
        self.send_response(302)
        self.send_header("Location", "/home?lang=" + q.get("lang", ["en"])[0])   # raw value into a header
        self.end_headers()

HTTPServer(("127.0.0.1", 8081), H).serve_forever()
```

- *E-mail:* run [Mailpit](https://mailpit.axllent.org/) locally as an SMTP catcher, then send to it from a small script that passes a form value as a string in `to` (address-list injection) or builds headers by hand (CRLF injection). Mailpit shows the raw message and every envelope recipient.
- *Logs:* log a value containing `\n` and `\u001b[31m` with your stack's default text formatter and with a JSON formatter, and compare the files with `cat -v`.
- *CSV:* write a CSV with and without the escaping function from [CSV and spreadsheet exports](#csv-and-spreadsheet-exports), open both in Excel and LibreOffice Calc, then save and re-open.

## Real-world cases

- **CSV export without escaping, then a bypass of the fix (HackerOne, 2015 and 2016).** Report 72785 showed that HackerOne's "Download as CSV" let a researcher name a report `=1+1` and have it evaluated when the response team opened the export; it was resolved and disclosed in September 2015. Report 118582 (February 2016, disclosed April 2019, rated Low) bypassed the fix by putting a quote and a semicolon in a title so that a new cell started with a formula, which is why GT-WEB-CRLF-12 tests cell breakout and not only the first character. [HackerOne report 72785](https://hackerone.com/reports/72785), [HackerOne report 118582](https://hackerone.com/reports/118582).
- **CSV injection rated Medium with a bounty (MetaMask programme, 2022).** A report generator on a Consensys asset wrote user input into CSV reports without neutralising formulas; the report is rated Medium and shows a USD 500 bounty, disclosed January 2023. Programmes differ widely on this class, which is why the rating section says to check the policy. [HackerOne report 1748961](https://hackerone.com/reports/1748961).
- **CRLF injection adding `Set-Cookie` (U.S. Department of Defense, 2017).** A CRLF sequence in a request produced an additional `Set-Cookie` header on a redirect; the reporter described XSS through a cookie, bypass of double-submit-cookie CSRF protection and session fixation across the organisation's sibling domains as the consequences. Rated Medium, resolved, disclosed December 2019 (host names redacted). [HackerOne report 245485](https://hackerone.com/reports/245485).
- **CRLF in the `host` header of Node's HTTP client (Internet Bug Bounty, 2023).** `undici`, which backs `fetch` in Node.js, validated header values but not the `host` header passed to `undici.request`, so CR LF there could split the outbound request. Fixed as CVE-2023-23936; rated Medium with a USD 600 bounty. This is the outbound-request variant of GT-WEB-CRLF-6. [HackerOne report 1878489](https://hackerone.com/reports/1878489), [CVE-2023-23936](https://www.cve.org/CVERecord?id=CVE-2023-23936).
- **SMTP injection in Jakarta Mail (2025).** CVE-2025-7962: CR and LF characters in input could be used to inject SMTP commands through Jakarta Mail / Angus Mail. Advisories differ on the exact affected ranges, so check the [GitHub advisory](https://github.com/advisories/GHSA-9342-92gg-6v29) and [NVD entry](https://nvd.nist.gov/vuln/detail/CVE-2025-7962) for the line you use. A reminder that "the library handles it" needs keeping the library current.
- **Log4Shell (2021).** CVE-2021-44228: Log4j 2 evaluated lookup expressions, including JNDI, inside logged data, so any logged request field became a remote code execution vector. It is the reason GT-WEB-CRLF-11 treats the logging library as an interpreter and checks versions rather than sending payloads. [CVE-2021-44228](https://www.cve.org/CVERecord?id=CVE-2021-44228), [Apache Log4j security page](https://logging.apache.org/log4j/2.x/security.html).

More write-ups are collected in [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

Rate on what the injected structure lets an attacker do, who has to interact (a victim clicking a link, an admin opening a file), whether the result is limited to one victim or shared (a cache, a mailing, a log everybody relies on), and what the reader of the output can be made to do. Series convention for Scope: **Changed** when the impact lands in a different security authority from the vulnerable component (script in the user's browser, a spreadsheet on the opener's workstation, a shared cache serving others), **Unchanged** when it stays within the application's own data and functions. The vectors are examples, not fixed answers.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Response header injection, arbitrary header, no body control, delivered by a link | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` (5.4) | The attacker controls headers of a response the victim requests; impact depends on which headers matter (CSP, CORS, `Content-Type`, `Refresh`) |
| Response splitting with body control (script in the victim's browser) | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | Equivalent to reflected XSS; Scope Changed as for XSS. Rate higher where the session reaches sensitive functions |
| `Set-Cookie` injection with working session fixation (pre-set IDs accepted, no rotation at login) | High | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N` (6.8) | Account takeover of the victim after they log in; `AC:H` because the attacker must plant the cookie and wait for a login. Without fixation, cookie tossing only: Medium |
| Split response stored by a shared cache | High | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N` (7.5) | Every user of the cached URL receives attacker content without any interaction; `AC:H` for cache timing and keying. Rate from analysis, not from a poisoning attempt |
| Header injection into an outbound request | Medium; High if it sets a trust header an internal service honours | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` (5.4) | Impact depends entirely on what the upstream does with the extra header; show only the marker reaching your collaborator |
| HTTP/2 front end accepts CR or LF in header values (no smuggling shown) | Low (hardening) | none until impact is shown | Fails `v5.0.0-4.2.4`; recommend a dedicated request-smuggling test |
| E-mail recipient or header injection on an unauthenticated form | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` (5.3) | Relay of messages from the organisation's domain (SPF and DKIM pass), phishing with trusted branding; rate higher if bulk sending is possible |
| E-mail injection that copies another user's sensitive mail (reset links, invoices) to the attacker | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | Only when demonstrated with your own two accounts; a copied reset link is account takeover |
| IMAP command injection after login, own mailbox | Medium | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` (5.4) | Bypasses application restrictions and reaches an internal server, but as your own mail user |
| IMAP or SMTP injection before authentication or via a shared service account | High | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` (7.4) | Reaches other mailboxes or relaying; `AC:H` reflects command-structure constraints |
| Cache-key or protocol injection (memcached, Redis) | Medium to High | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N` (6.8) | Writing other keys can poison sessions or flags; usually found in code review, rate on what the cache holds |
| Log forging in a plain-text log | Low | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` (5.3) | The base score overstates it: the integrity impact is on log evidence only. Rate Low unless logs feed security decisions automatically |
| Raw ANSI escape sequences reach logs read in terminals | Low or Info | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N` (3.1) | Can hide or fake lines for an analyst; needs a terminal that interprets the sequence |
| Markup rendered in an admin log or audit viewer | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | Stored XSS against privileged users once confirmed by the XSS test; rate up when an admin session reaches admin functions |
| Vulnerable Log4j 2 version with lookups reachable from request data | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (10.0, as published for CVE-2021-44228) | Remote code execution; confirm by version evidence or an agreed out-of-band test |
| CSV injection, formula evaluated when staff open the export | Low to Medium; many bug bounty programmes rate it Informative | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` (5.4) | Scope Changed: the spreadsheet on the opener's workstation is a different authority. Rate Low (for example `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N`, 3.5) when only displayed values can be faked and exports stay internal |
| Header reflection that the framework encodes or rejects; incomplete custom filter with no working bypass | Info | none | No structural change possible; mention the filter only if it is the sole control on a stack that would not protect |

When you report, give: the exact input and where it was placed, the raw output showing the new structure (header line, delivered copy, log line, evaluated cell), the stack or library involved if known, the impact assessment from GT-WEB-CRLF-5 or the equivalent, and confirmation that only your own accounts, mailboxes and data were involved.

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 |
|---|---|---|---|---|
| GT-WEB-CRLF-1 | WSTG-INJT-15 | v5.0.0-1.2.1 | CWE-113 (context) | A05:2025 |
| GT-WEB-CRLF-2 | WSTG-INJT-15 | v5.0.0-1.2.1, v5.0.0-1.2.2 | CWE-113 | A05:2025 |
| GT-WEB-CRLF-3 | WSTG-INJT-15 | v5.0.0-1.2.1 | CWE-113 | A05:2025 |
| GT-WEB-CRLF-4 | WSTG-INJT-15 | v5.0.0-1.2.1 | CWE-113 | A05:2025 |
| GT-WEB-CRLF-5 | WSTG-INJT-15 | v5.0.0-1.2.1, v5.0.0-7.2.4 | CWE-113, CWE-384 (fixation) | A05:2025 |
| GT-WEB-CRLF-6 | WSTG-INJT-15, WSTG-INJT-16 (detection only) | v5.0.0-1.2.1, v5.0.0-4.2.4 | CWE-113, CWE-93 | A05:2025 |
| GT-WEB-CRLF-7 | WSTG-INJT-10 | v5.0.0-1.3.11 | CWE-93 | A05:2025 |
| GT-WEB-CRLF-8 | WSTG-INJT-10 | v5.0.0-1.3.11 | CWE-93, CWE-147 | A05:2025 |
| GT-WEB-CRLF-9 | WSTG-INJT-10 (approach) | v5.0.0-1.3.9, v5.0.0-1.3.3 | CWE-93 | A05:2025 |
| GT-WEB-CRLF-10 | WSTG-INJT-14 (model) | v5.0.0-16.4.1, v5.0.0-16.2.4 | CWE-117 | A09:2025 |
| GT-WEB-CRLF-11 | WSTG-INJT-14 (model) | v5.0.0-16.4.1, v5.0.0-1.3.8 | CWE-150, CWE-117; CWE-79 for viewer XSS; CWE-917 for lookups | A09:2025, A05:2025 |
| GT-WEB-CRLF-12 | WSTG-INJT-21 | v5.0.0-1.2.10 | CWE-1236 | A05:2025 |

ASVS levels: `v5.0.0-1.2.1` L1 (context-appropriate output encoding, including HTTP header fields), `v5.0.0-1.2.2` L1 (URL encoding when building URLs), `v5.0.0-1.2.10` L3 (CSV and formula injection, RFC 4180 escaping, single-quote prefix), `v5.0.0-1.3.3` L2 (sanitise data passed to a dangerous context), `v5.0.0-1.3.8` L2 (JNDI), `v5.0.0-1.3.9` L2 (memcache), `v5.0.0-1.3.11` L2 (SMTP and IMAP), `v5.0.0-4.2.4` L3 (no CR or LF in HTTP/2 and HTTP/3 header fields), `v5.0.0-7.2.4` L1 (new session token on authentication), `v5.0.0-15.3.7` L2 (HTTP parameter pollution, for the related checks), `v5.0.0-16.2.4` L2 (log format the processor can read), `v5.0.0-16.4.1` L2 (encode data to prevent log injection).

CWE choice: CWE-113 (a Variant) for anything in HTTP headers; CWE-93 (Base) for CR LF in other protocols; CWE-147 when the terminator is something other than CR LF; CWE-117 for logs and CWE-150 for terminal escape sequences; CWE-1236 for CSV. All are "Allowed" for mapping on cwe.mitre.org at the time of writing. CWE-74 is the "Discouraged" class parent. HTTP parameter pollution, if you report it, maps to `WSTG-INJT-04`, `v5.0.0-15.3.7` and CWE-235. OWASP Top 10: `A05:2025` Injection lists CWE-93 and CWE-113 among its mapped CWEs; `A09:2025` Security Logging and Alerting Failures names CWE-117. CWE-1236 is not in A05's published list, but formula injection is an injection weakness and we file it there.

## References

**OWASP**

- WSTG: [HTTP Response Splitting (WSTG-INJT-15)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/15-HTTP_Response_Splitting), [IMAP SMTP Injection (WSTG-INJT-10)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/10-IMAP_SMTP_Injection), [CSV Injection (WSTG-INJT-21)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/21-CSV_Injection), [HTTP Parameter Pollution (WSTG-INJT-04)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/04-HTTP_Parameter_Pollution), [Incubated Vulnerability (WSTG-INJT-14)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/14-Incubated_Vulnerability), [HTTP Request Smuggling (WSTG-INJT-16)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/16-HTTP_Request_Smuggling)
- ASVS 5.0: [V1 Encoding and Sanitization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md), [V4 API and Web Service](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x13-V4-API-and-Web-Service.md), [V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)
- Top 10:2025: [A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/), [A09:2025 Security Logging and Alerting Failures](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/)
- Community pages: [CSV Injection](https://owasp.org/www-community/attacks/CSV_Injection), [HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting), [Log Injection](https://owasp.org/www-community/attacks/Log_Injection)
- Cheat Sheets: [Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), [Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html), [HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [OWASP WebGoat](https://github.com/WebGoat/WebGoat)

**CWE and standards**

- [CWE-93](https://cwe.mitre.org/data/definitions/93.html), [CWE-113](https://cwe.mitre.org/data/definitions/113.html), [CWE-117](https://cwe.mitre.org/data/definitions/117.html), [CWE-1236](https://cwe.mitre.org/data/definitions/1236.html), [CWE-147](https://cwe.mitre.org/data/definitions/147.html), [CWE-150](https://cwe.mitre.org/data/definitions/150.html), [CWE-74](https://cwe.mitre.org/data/definitions/74.html), [CWE-384](https://cwe.mitre.org/data/definitions/384.html), [CWE-235](https://cwe.mitre.org/data/definitions/235.html)
- [RFC 9110 HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110), [RFC 9112 HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112), [RFC 9113 HTTP/2](https://www.rfc-editor.org/rfc/rfc9113) (field values must not contain CR, LF or NUL)
- [RFC 5321 SMTP](https://www.rfc-editor.org/rfc/rfc5321), [RFC 5322 Internet Message Format](https://www.rfc-editor.org/rfc/rfc5322), [RFC 9051 IMAP4rev2](https://www.rfc-editor.org/rfc/rfc9051)
- [RFC 4180 CSV](https://www.rfc-editor.org/rfc/rfc4180) (sections 2.6 and 2.7 on quoting)
- [memcached protocol](https://github.com/memcached/memcached/blob/master/doc/protocol.txt), [Redis serialization protocol](https://redis.io/docs/latest/develop/reference/protocol-spec/)

**PortSwigger and research**

- [HTTP response header injection](https://portswigger.net/kb/issues/00200200_http-response-header-injection) and [SMTP header injection](https://portswigger.net/kb/issues/00200800_smtp-header-injection) (Burp issue definitions)
- [Advanced request smuggling, including request smuggling via CRLF injection](https://portswigger.net/web-security/request-smuggling/advanced) and [HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2) (James Kettle)
- [Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) and [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [SMTP Smuggling: Spoofing E-Mails Worldwide](https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/) (SEC Consult)
- [Apache Log4j security vulnerabilities](https://logging.apache.org/log4j/2.x/security.html)

**Framework and library documentation**

- Node.js: [`http` module](https://nodejs.org/api/http.html) (`ERR_INVALID_CHAR` on invalid header characters); Express: [API reference](https://expressjs.com/en/5x/api.html) (`res.location`, `res.cookie`, `res.attachment`)
- Django: [request and response objects](https://docs.djangoproject.com/en/6.1/ref/request-response/) (newlines in header values raise `BadHeaderError`) and [sending email](https://docs.djangoproject.com/en/6.1/topics/email/) (formatting addresses, preventing header injection, the 6.0 change to `ValueError`); Python: [`email.headerregistry`](https://docs.python.org/3/library/email.headerregistry.html), [`csv`](https://docs.python.org/3/library/csv.html), [`http.server`](https://docs.python.org/3/library/http.server.html) (not for production)
- Spring: [`MimeMessageHelper`](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/mail/javamail/MimeMessageHelper.html), [Spring Security HTTP firewall](https://docs.spring.io/spring-security/reference/servlet/exploits/firewall.html), [Spring Boot logging](https://docs.spring.io/spring-boot/reference/features/logging.html) (structured logging)
- Laravel: [mail](https://laravel.com/docs/13.x/mail), [logging](https://laravel.com/docs/13.x/logging) (Monolog formatters)
- Nodemailer: [address formats](https://nodemailer.com/message/addresses), [custom headers](https://nodemailer.com/message/custom-headers); [Nodemailer advisories](https://github.com/advisories?query=nodemailer)
- Jakarta Mail / Angus Mail: [CVE-2025-7962 advisory](https://github.com/advisories/GHSA-9342-92gg-6v29)
- Logging: [pino](https://getpino.io/), [Log4j 2 pattern layout](https://logging.apache.org/log4j/2.x/manual/pattern-layout.html) (`%enc{…}{CRLF}`), [Logback layouts](https://logback.qos.ch/manual/layouts.html) (`%replace`)
- CSV: [league/csv EscapeFormula](https://csv.thephpleague.com/9.0/interoperability/escape-formula-injection/), [defusedcsv](https://pypi.org/project/defusedcsv/)
- nginx: [core module variables](https://nginx.org/en/docs/http/ngx_http_core_module.html) (`$uri` is normalised, `$request_uri` is the original); [gixy HTTP splitting check](https://github.com/yandex/gixy/blob/master/docs/en/plugins/httpsplitting.md)

**Tools**

- Burp extensions: [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943), [Hackvertor](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100); [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator); [interactsh](https://github.com/projectdiscovery/interactsh)
- [ZAP CRLF Injection scan rule](https://www.zaproxy.org/docs/alerts/40003/), [Nuclei](https://github.com/projectdiscovery/nuclei), [CRLFuzz](https://github.com/dwisiswant0/crlfuzz)
- Static analysis: CodeQL query help for [`java/http-response-splitting`](https://codeql.github.com/codeql-query-help/java/java-http-response-splitting/), [`py/http-response-splitting`](https://codeql.github.com/codeql-query-help/python/py-http-response-splitting/), [`java/log-injection`](https://codeql.github.com/codeql-query-help/java/java-log-injection/), [`js/log-injection`](https://codeql.github.com/codeql-query-help/javascript/js-log-injection/), [`py/log-injection`](https://codeql.github.com/codeql-query-help/python/py-log-injection/); [Semgrep community rules](https://github.com/semgrep/semgrep-rules)
- [Mailpit](https://mailpit.axllent.org/) (local SMTP catcher for labs)
