---
title: "Injection Testing Guide"
date: 2026-11-15 20:20:00 +0000
subcategory: injection
summary: "Hub for the Injection notes: the interpreter model, the safe-proof ladder, a test plan, all 92 tests, ASVS V1 coverage and rating rules."
refs: [WSTG-INJT, v5.0.0-V1, "A05:2025", "A02:2025", "A08:2025", CWE-74, CWE-89, CWE-943, CWE-78, CWE-1336, CWE-611, CWE-90, CWE-113, CWE-1321]
tags: [web, injection, methodology, wstg, asvs, secure-coding]
---

Injection happens when data supplied by a user crosses into the code of an interpreter. The application builds a SQL statement, a shell command line, a template, an XML document, an LDAP filter, an HTTP header or a spreadsheet cell, and some of the input ends up as syntax rather than as a value. From that point the attacker is writing part of the program that runs. The interpreter does what the combined text says, with the application's privileges, so the outcomes range from a misleading log line to reading the whole database or running commands on the server. OWASP ranks Injection fifth in the [Top 10:2025](https://top10.owasp.org/2025/A05_2025-Injection/) (`A05:2025`), down from third in 2021. The 2025 page maps 37 CWEs to the category and counts more than 62,000 CVEs. It describes cross-site scripting as the high-frequency, low-impact part of the category and SQL injection as the low-frequency, high-impact part. Frameworks have made the common cases rarer, but it has not gone away, and when it is present it is usually the most serious finding of a test. This page is the hub of the Injection subcategory of our [Web Application Security testing guide](/web/web-application-security-testing-guide/). It covers server-side and stored injection into SQL and NoSQL databases, operating-system commands, template engines and expression languages, XML parsers, directories and XPath, line-based protocols, logs and CSV exports, and server-side prototype pollution in Node.js. Related topics live elsewhere. Cross-site scripting and other browser-side injection belong to the Client-Side subcategory. SSRF, file inclusion and insecure deserialisation belong to Server-Side Request & Files, and request smuggling and Host header injection to HTTP & Infrastructure. Those three are not written yet. Mass assignment is already covered in the Access Control subcategory, in [Mass assignment and BOPLA](/web/web-mass-assignment-bopla/). The hub sets out the model, the safe-proof ladder that every note follows, the order we test in, a table of all 92 tests with their WSTG and ASVS 5.0 mapping, ASVS V1 coverage, the rating conventions and a practice path. Rules of engagement, Burp set-up and the severity scale are in the series hub and are not repeated here. Everything assumes an authorised engagement, a bug bounty programme whose rules allow injection testing, or a lab. Outputs shown on this page are illustrative.

## Contents

- [How injection works](#how-injection-works)
  - [The interpreter, the context and the encoding](#the-interpreter-the-context-and-the-encoding)
  - [Interpreters and the notes that test them](#interpreters-and-the-notes-that-test-them)
  - [Why it keeps happening](#why-it-keeps-happening)
- [Safe proofs](#safe-proofs)
  - [The proof ladder](#the-proof-ladder)
  - [The ladder per interpreter](#the-ladder-per-interpreter)
  - [What we never do](#what-we-never-do)
  - [Production cautions](#production-cautions)
- [Test plan](#test-plan)
  - [Finding injection points](#finding-injection-points)
  - [Order of work](#order-of-work)
  - [Prioritisation](#prioritisation)
  - [Triaging scanner output](#triaging-scanner-output)
  - [Where manual work matters](#where-manual-work-matters)
  - [Second-order and asynchronous paths](#second-order-and-asynchronous-paths)
- [Notes in this subcategory](#notes-in-this-subcategory)
  - [SQL injection](#sql-injection)
  - [NoSQL injection](#nosql-injection)
  - [OS command and argument injection](#os-command-and-argument-injection)
  - [Server-side template and code injection](#server-side-template-and-code-injection)
  - [XXE and XML injection](#xxe-and-xml-injection)
  - [LDAP and XPath injection](#ldap-and-xpath-injection)
  - [CRLF, email header, log and CSV injection](#crlf-email-header-log-and-csv-injection)
  - [Server-side prototype pollution](#server-side-prototype-pollution)
- [All tests at a glance](#all-tests-at-a-glance)
- [ASVS 5.0 V1 coverage](#asvs-50-v1-coverage)
- [Rating injection findings](#rating-injection-findings)
  - [Conventions](#conventions)
  - [Typical ratings](#typical-ratings)
- [Prevention patterns](#prevention-patterns)
  - [The patterns](#the-patterns)
  - [Static analysis](#static-analysis)
  - [Regression tests](#regression-tests)
- [Practice path](#practice-path)
- [References](#references)

## How injection works

### The interpreter, the context and the encoding

Every injection finding answers three questions. Describing a finding in these terms makes it reproducible, and it tells the developer exactly where the fix belongs.

- **Which interpreter?** Something downstream parses the string the application built: a database engine, a shell, a template engine, an XML parser, a directory server, an HTTP or SMTP peer, a log viewer, a spreadsheet, or JavaScript's own property lookup. Each has its own grammar and its own idea of what counts as code. A quote character means nothing to a shell running without one. A newline means nothing to SQL but ends a header line, and an equals sign at the start of a CSV cell starts a formula.
- **Which context inside it?** The same interpreter has several places where input can land, and each one breaks differently. In SQL, input can land in a string literal, a number, an identifier (`ORDER BY`), a list or a `LIKE` pattern. In MongoDB it can be a scalar value or an operator object. A command line has the shell grammar and also the target program's options. A template has plain text, an expression and a template name. An XML document has text content, an attribute, a DTD or a fragment the server wraps. An HTTP message has the header value and the line structure around it. Parameterisation protects values; it cannot protect identifiers, operators or option names, which is why so many findings are in those contexts.
- **Which encoding layers on the way?** Between the request and the sink, the input passes through URL decoding, JSON parsing, bracket-notation parsers that turn `a[b]=c` into objects, base64, multipart file names, XML entity decoding, and sometimes storage and a second read. Each layer can turn harmless-looking input into structure (`%0d%0a`, `{"$ne":null}`, `__proto__`). It can also undo an escape applied too early, which is why ASVS `v5.0.0-1.1.1` (L2) asks for decoding once, before validation, and `v5.0.0-1.1.2` (L2) asks for encoding as the last step before the interpreter.

A test is a controlled experiment on those three variables. You hold the interpreter and the encoding fixed, change one character class in one context, and compare the response with a control that should behave identically if the input is treated as data.

### Interpreters and the notes that test them

| Interpreter | Data becomes code when… | Contexts that matter | Note | WSTG | ASVS 5.0 | Default CWE | Top 10:2025 |
|---|---|---|---|---|---|---|---|
| SQL engines and ORMs | Input is concatenated or formatted into a statement, or passed to an ORM's raw escape hatch | String, numeric, identifier, `IN` list, `LIKE`, stored and re-read | [SQL injection](/web/web-sql-injection/) | WSTG-INJT-05 (05.1–05.7), WSTG-INJT-14 | `1.2.4` L1 | CWE-89 (CWE-564 for HQL) | A05 |
| Document stores and search engines | A request object becomes a filter, or input reaches `$where`, a pipeline or a query-string syntax | Scalar versus operator object, bracket-parsed query strings, server-side JavaScript, search DSL | [NoSQL injection](/web/web-nosql-injection/) | WSTG-INJT-05 (05.6), WSTG-INJT-11 | `1.2.4` L1, `1.2.9` L2 | CWE-943 | A05 |
| Shells and the programs they start | Input reaches a shell command line, or becomes an option of a program started without a shell | Shell metacharacters, option-like values, file names, Windows `cmd.exe` rules | [OS command injection](/web/web-os-command-injection/) | WSTG-INJT-12 | `1.2.5` L1 | CWE-78, CWE-88 | A05 |
| Template engines, expression languages, `eval`, SSI, JNDI | Input becomes part of template source, an expression, evaluated code or a lookup string | Plain-text versus code context, template names, second-order rendering in email and PDF | [SSTI and code injection](/web/web-server-side-template-injection/) | WSTG-INJT-18, WSTG-INJT-11, WSTG-INJT-08 | `1.3.7`, `1.3.2`, `1.3.5`, `1.3.8` | CWE-1336, CWE-95, CWE-917, CWE-97 | A05 |
| XML parsers, XSLT processors and XML builders | The parser resolves entities or includes, a stylesheet is user-controlled, or input changes the structure of XML the server builds | DTD, external and parameter entities, XInclude fragments, XML inside uploads, structural injection | [XXE and XML injection](/web/web-xxe-xml-injection/) | WSTG-INJT-07 | `1.5.1` L1, `1.2.1` L1, `1.3.5` L2 | CWE-611 (CWE-91 for structure) | A02 for XXE, A05 for XML injection |
| Directory servers and XPath/XQuery engines | Input is concatenated into a search filter, a DN or an XPath expression | Filter metacharacters, wildcards in login, DN components, XPath 2.0 functions | [LDAP and XPath injection](/web/web-ldap-xpath-injection/) | WSTG-INJT-06, WSTG-INJT-09 | `1.2.6` L2, `1.2.7` L2 | CWE-90, CWE-643, CWE-652 | A05 |
| Line-based protocols, logs and spreadsheets | CR and LF (or a formula prefix) reach a header, a mail command, a log line or a CSV cell | Response and outbound headers, mail headers, IMAP/SMTP, cache protocols, log viewers, exports | [CRLF, header, log and CSV injection](/web/web-crlf-header-log-csv-injection/) | WSTG-INJT-15, WSTG-INJT-10, WSTG-INJT-21 | `1.2.1` L1, `1.3.11` L2, `16.4.1` L2, `1.2.10` L3 | CWE-113, CWE-93, CWE-117, CWE-1236 | A05; A09 for logs |
| The JavaScript object model | A key such as `__proto__` or `constructor.prototype` in input is merged or set on an object | JSON bodies, query strings, path setters, YAML and config imports | [Server-side prototype pollution](/web/web-server-side-prototype-pollution/) | WSTG-INJT-22 | `15.3.6` L2 | CWE-1321 | A08 |

Three of the classes do not sit in `A05:2025`. The 2025 list files CWE-611 and CWE-776 under [A02:2025 Security Misconfiguration](https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/), CWE-117 under [A09:2025 Security Logging and Alerting Failures](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/), and CWE-1321's parent CWE-915 under [A08:2025 Software or Data Integrity Failures](https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/). We test them with injection techniques and keep them in this subcategory, but each note maps them where the Top 10 puts them. The OWASP API Security Top 10 2023 has no injection category; an injection in an API is still `A05:2025`.

On CWE: [CWE-74](https://cwe.mitre.org/data/definitions/74.html) (*Improper Neutralization of Special Elements in Output Used by a Downstream Component*) is the class that sits above all of these. MITRE marks its vulnerability mapping as **Discouraged**, because the entry is high-level and often used where a lower-level weakness fits better. It appears in this hub's front matter only as the umbrella term for the subcategory. Never put it on a finding: use the specific entry from the note's Mapping table.

### Why it keeps happening

Most applications we test use an ORM, a templating engine with auto-escaping and a JSON API. Injection survives in the gaps those tools leave:

- **Places parameters cannot reach.** Sort columns, table names, `LIMIT` values, Mongo operators, program options and template names cannot be bound as parameters. Developers build them as strings, and that is where the injection is.
- **Escape hatches.** `raw()`, `extra()`, `$queryRawUnsafe`, `whereRaw()`, `render_template_string`, `exec()` with a string, `shell=True`, a custom recursive merge. Each one exists for a reason, and each one hands parsing back to the string.
- **Structure arriving as data.** JSON and bracket parsers deliver objects and arrays where the code expects a string. A filter that receives `{"$ne": null}` is not being given a value, it is being given a query.
- **The second reader.** Input that is safe where it is stored is concatenated somewhere else later: in a report query, an email template, a batch job, an export or a log viewer. WSTG calls this an incubated vulnerability (WSTG-INJT-14).
- **Parsers configured for features nobody uses.** XML external entities, XInclude, XSLT extension functions, SSI `#exec`, JNDI lookups in log messages and server-side JavaScript in the database are all on in some default configuration somewhere.

## Safe proofs

An injection test is finished as soon as you can show that input reaches the interpreter as code. Everything after that point is exploitation, and on a client system it adds risk without adding evidence. The client needs the root cause and a credible statement of impact, and both come from the proof plus what you know about the component's privileges. Extracted data is not needed for either. Every note in this subcategory follows the same ladder. Each note's *Before you start* section gives the interpreter-specific details.

### The proof ladder

Climb only as far as you must, and stop at the first rung that proves the point for that input.

1. **Syntax or error difference.** One metacharacter breaks the statement and its repaired twin does not: `'` errors and `''` does not, an unclosed template delimiter errors and plain text does not, a DOCTYPE is accepted or rejected. This shows that the input is parsed. It does not yet show that it is evaluated, so it is a lead until a second signal agrees.
2. **Boolean difference.** Two payloads that differ only in truth value give two different responses, and the true one matches the original. Examples are `AND 1=1` versus `AND 1=2`, a `$ne` filter versus a `$eq` filter on your own record, or an LDAP filter that matches your account versus one that does not. This is the workhorse proof for SQL, NoSQL, LDAP and XPath.
3. **Bounded time delay.** Use this only where nothing else distinguishes the responses. The delay is a few seconds (our notes use 3 s for SQL and at most 5 s for commands). Repeat it three times, interleave it with zero-delay controls, and check that it scales with the value you ask for: 3 s gives about 3 s and 6 s gives about 6 s.
4. **Out-of-band interaction with your own collaborator.** A DNS (or HTTP) lookup of a unique subdomain on Burp Collaborator or a self-hosted interactsh server. Use one subdomain per request so that a hit identifies its source. The label is a static marker you chose and never carries server data, because data in DNS names is exfiltration. Run DNS and HTTP only, with no SMB listener. This is the standard proof for blind and asynchronous sinks: XXE, JNDI lookups, commands run in background jobs, and second-order SQL.
5. **Minimal benign output.** The smallest result that only evaluation could produce:
   - SQL: the database version banner, current user and database name.
   - SSTI: the product `1234*5678 = 7006652` rendered by the template engine, plus the engine's identity.
   - Commands: `hostname` or `id` where the feature echoes output and the client agreed to it.
   - XXE: one agreed harmless file (`/etc/hostname` or a canary file the client placed), read once.
   - CSV: a cell that shows `2` for `=1+1`.
   - Prototype pollution: a reversible canary property or formatting change, undone at once.

   This rung is the ceiling. Anything beyond it needs the client's written approval for that specific finding.

Record the proof with its control. A delay without the zero-delay request, a boolean pair without the original response, or a collaborator hit without the request that carried that subdomain is not evidence. Proxies, mail scanners and security products resolve hostnames they see, so an OOB hit also needs a control: the same hostname sent in a context that is not interpreted.

### The ladder per interpreter

| Note | Syntax or error | Boolean | Bounded time | Out-of-band | Ceiling (minimal benign output) |
|---|---|---|---|---|---|
| [SQL](/web/web-sql-injection/) | Quote breaks, doubled quote repairs; `1003-1` returns 1002 in numeric context | `AND` true/false pairs, `CASE` pairs in `ORDER BY` | Short sleep in a scalar subquery, never `BENCHMARK` | Engine DNS functions to your collaborator | Version, current user, current database name |
| [NoSQL](/web/web-nosql-injection/) | Cast errors, broken JavaScript string syntax | `$ne`/`$eq` or regex pairs on your own records | `sleep()` in `$where` only if agreed, behind a one-document condition | Rarely applicable | A response difference on your own record; no reading of other documents |
| [Command](/web/web-os-command-injection/) | Error or output change from a metacharacter | Rarely useful | `sleep` with a zero-delay control, 5 s at most | One DNS lookup of a unique name | `hostname` or `id` where output is echoed and agreed |
| [SSTI](/web/web-server-side-template-injection/) | Fuzz string or unclosed delimiter error | Engine discriminators | Only where nothing is rendered | DNS lookups for JNDI and blind rendering | Arithmetic result and engine identity; a harmless command only with approval for that finding |
| [XXE](/web/web-xxe-xml-injection/) | Malformed XML errors; DOCTYPE accepted; internal entity expands to your marker | n/a | n/a | External or parameter entity to your collaborator | One agreed harmless file, once |
| [LDAP and XPath](/web/web-ldap-xpath-injection/) | `*`, `(` and `)` errors | Filter or expression true/false pairs on your own account | n/a | XPath 2.0 `doc()` to your collaborator | Login or group check on your own test account |
| [CRLF](/web/web-crlf-header-log-csv-injection/) | Encoded CR LF changes the header or line structure | n/a | n/a | A marker header reaching your collaborator in an outbound request | A marker header, a copy to your own mailbox, a forged marker log line, `=1+1` evaluated |
| [Prototype pollution](/web/web-server-side-prototype-pollution/) | n/a | Status, JSON-spacing or header probes that change and change back | n/a | n/a | A unique canary property, undone immediately; gadgets assessed, not fired |

### What we never do

These limits apply on every client system, whatever a scanner or a cheat sheet suggests:

- **No data extraction.** That means no `UNION` dumps, no blind character-by-character reads of tables, tokens or hashes, no reading of other users' documents, and no `--dump` in sqlmap.
- **No writes or state changes through the interpreter.** That rules out `DROP`, `UPDATE`, `DELETE`, stacked writes, `INTO OUTFILE`, enabling `xp_cmdshell`, configuration changes, `$out` or `$merge` stages, file creation, and edits to a template that real users receive.
- **No shells or persistence.** No reverse or bind shells, web shells, scheduled tasks, privilege escalation after code execution or lateral movement. Describe what an attacker could do from the process's privileges in prose instead.
- **No secrets.** Do not read `/etc/passwd`, configuration files, environment variables, cloud metadata, keys or template context objects that hold secrets. The exception is a step the client has approved in writing for that finding.
- **No denial of service.** No entity-expansion bombs, catastrophic regular expressions, long sleeps, loops in templates or `$where`, or probes against features that fan out to many workers. Missing limits are reported from configuration and version evidence.
- **No evasion catalogues.** One or two encoding variants against a denylist, reported as a finding about the filter, is the limit. We do not use tamper scripts or WAF bypass lists.
- **No third-party collaborators.** Payloads point only at your own collaborator, never at a third party's server or at the target's internal addresses.

### Production cautions

- **Time-based payloads load the database.** Heavy functions (`BENCHMARK`, Cartesian joins) burn CPU on a shared server. A sleep in a `WHERE` or `ORDER BY` clause can run once per row and hold a connection for minutes. In Node.js a delay blocks the event loop for every user of that process. Keep delays short, the requests few, and the condition limited to one row.
- **Stored probes reach other people and later jobs.** Profile names, ticket subjects, file names and template drafts are read by staff, exports, email renderers and batch jobs. Use your own records and an inert payload, keep a list of every stored probe, and remove them when you finish.
- **Asynchronous sinks retry.** A probe in a queued job can fire again on every retry. Once you see one interaction, stop sending to that feature.
- **Prototype pollution persists.** A global pollution changes behaviour for every user until the process restarts. Use only the reversible probes, agree a test window, and have a client contact who can restart the service.
- **Scanners send hundreds of payloads per parameter.** Burp Scanner, sqlmap, commix, SSTImap and NoSQLMap are confirmation and detection aids on agreed hosts, at one thread with a delay, pointed at single requests. Their payload sets include `OR` conditions and stacked statements that are unsafe on production. The SQL note gives the conservative sqlmap settings.
- **Errors page people.** Every malformed document or broken statement can produce a stack trace in the client's monitoring. Agree beforehand whether out-of-band callbacks and error spikes will alert, and tell the client when you start.
- **Prefer staging for confirmation, then check production with one request.** Report the environment in every finding. The series hub's [production or staging](/web/web-application-security-testing-guide/) rules apply.

If a probe ever returns data that is not yours, such as another customer's row, a secret in an error page or a rendered context object, stop that line of testing. Keep only the minimum redacted evidence and report it immediately, as the series hub's stop-on-real-data rule requires.

## Test plan

### Finding injection points

An injection point is any value that reaches an interpreter, not just the visible form fields. Build the inventory before you probe anything. The mapping tests of each note do this work: SQLI-1, NOSQL-1, CMD-1, SSTI-1, XXE-1, LDAP-1, CRLF-1 and PP-1.

- **Every parameter location.** Query strings, form and JSON bodies (including nested keys and arrays), path segments, cookies, and headers the application reads (`User-Agent`, `Referer`, `X-Forwarded-For`, custom tenant or locale headers), plus GraphQL arguments and variables. **Param Miner** finds parameters and headers that no page sends.
- **Structure the parser will accept.** Try a JSON body where a form is expected, a form where JSON is expected, and XML where either is expected. Use bracket notation (`a[b]=c`) where the server uses `qs` or PHP. **Content Type Converter** turns a captured request into XML for XXE-2, and the NoSQL and prototype pollution notes show what bracket parsers produce.
- **Files and their metadata.** File names, archive entry names and EXIF fields, and the content of uploaded SVG, DOCX, XLSX, PDF and image files. These reach converters, image tools and XML parsers (CMD-7, CMD-11, XXE-9).
- **Features that call another interpreter.** Look for search with operators, sort and filter options, reports and exports, PDF and email rendering, "preview" and "test send", network diagnostics (ping, traceroute, DNS lookup), image resizing, document conversion, LDAP or Active Directory login, SSO and SOAP endpoints, webhooks, import and sync jobs, and anything with a template or formula editor.
- **Hidden and legacy surface.** Old API versions, mobile back-ends, admin and support tooling, and the operations behind a GraphQL schema (InQL). The [IDOR and BOLA](/web/web-idor-bola/) and [bypass](/web/web-authorization-bypass-techniques/) notes describe how we find unlinked routes. The same route list feeds this subcategory.
- **Values that come back later.** For every field you control, note where else it is displayed, exported, logged or processed. These are the second-order candidates.

### Order of work

1. **Map and fingerprint.** Run the eight mapping tests together on one pass through the application, recording for each input the likely interpreter and context. Fingerprint the stack (database, template engine, XML library, Node.js or not) from headers, errors and behaviour, and from source if the test is grey-box.
2. **Passive and cheap checks.** Error-handling behaviour (SQLI-2, NOSQL-1, CMD-2, LDAP-2, XXE-3), header reflection (CRLF-1) and arithmetic in rendered fields (SSTI-2). These are low-risk probes that sort inputs into "parsed" and "not parsed".
3. **Confirm the leads by hand, one interpreter at a time,** climbing the ladder: boolean (SQLI-3, NOSQL-7, LDAP-4), time (SQLI-4, CMD-3), OOB (SQLI-5, CMD-4, XXE-5, XXE-6, SSTI-10), benign output (SQLI-6, SSTI-4, XXE-7).
4. **Contexts parameters cannot protect.** Identifiers and lists (SQLI-7, SQLI-8), operators and pipelines (NOSQL-2 to NOSQL-4, NOSQL-9), option injection (CMD-6), template names and code context (SSTI-3), DN injection (LDAP-8), fragments (XXE-8, XXE-10).
5. **Authentication and authorisation paths.** Login and token checks on your own account (NOSQL-5, LDAP-6, LDAP-7). These are high-value, and they are also where `OR`-style payloads cause the most damage, so follow the notes exactly.
6. **Stored and second-order paths** (see below): SQLI-10, SSTI-5, CMD-7, XXE-9, CRLF-10 to CRLF-12, PP-8.
7. **Impact assessment without exploitation.** SSTI-6 (sandbox and context), CMD-12 (execution context), PP-9 (gadgets), CRLF-5 (what a header injection enables), and the client's answer about database account privileges.
8. **Source and configuration review** where you have access: SQLI-11, NOSQL-12, CMD-10, CMD-11, SSTI-12, XXE-12, PP-10. Run these early if source is available from day one, because they turn a black-box search into a list of sinks to confirm.

### Prioritisation

You will not probe every parameter with every interpreter's payloads, and you should not try. Rank inputs by how likely an interpreter sits behind them and by what that interpreter can reach:

| Priority | Feature | Interpreter to suspect first | Tests |
|---|---|---|---|
| 1 | Unauthenticated inputs: login, password reset, search, contact and sign-up forms, public APIs | SQL, NoSQL, LDAP, mail headers | SQLI-2 to SQLI-5, NOSQL-5, LDAP-6, CRLF-7 |
| 1 | Anything that starts a program: diagnostics, conversion, image and PDF processing | Shell, program options, ImageMagick and Ghostscript | CMD-1 to CMD-7, CMD-11 |
| 1 | Template, formula, report or email editors; "preview" and "test send" | Template engine, expression language | SSTI-1 to SSTI-6 |
| 2 | Sort, filter, column selection and advanced search | SQL identifiers, Mongo operators, search DSL | SQLI-7, SQLI-8, NOSQL-3, NOSQL-9, NOSQL-10 |
| 2 | XML anywhere: SOAP, SAML, RSS or sitemap import, office and SVG uploads | XML parser, XSLT | XXE-1, XXE-2, XXE-5, XXE-9, XXE-11 |
| 2 | JSON APIs on Node.js with deep-merge settings or config import | JavaScript object model | PP-1 to PP-4 |
| 3 | Redirects, language and locale cookies, values copied into headers | HTTP header parser | CRLF-2 to CRLF-4 |
| 3 | Exports, audit logs, admin log viewers | Spreadsheet, log viewer | CRLF-10 to CRLF-12 |

Within each band, unauthenticated beats authenticated, and internet-facing beats internal. Hand-built features beat framework defaults: a custom search builder is more likely to concatenate than the framework's model form.

### Triaging scanner output

Burp Scanner's active checks, the BApps listed in the notes (Backslash Powered Scanner, NoSQLi Scanner, Server-Side Prototype Pollution Scanner) and tools such as sqlmap or SSTImap produce leads, not findings. Our triage rules:

- **Reproduce every issue by hand in Repeater with a control** before it goes in the report. A scanner's "SQL injection (time-based)" is a delay; check the zero-delay request, the cache headers and the jitter yourself (the SQL note's *Signals and false positives* table lists the usual impostors).
- **Check what was actually changed.** Scanners report the payload, and the response may differ for reasons unrelated to it: a WAF block page, a validation error that echoes your input, a CDN cache hit, a rate limiter, or lenient type coercion (`parseInt("1002 AND 1=2")` is 1002).
- **Collaborator hits need provenance.** Tie the interaction to the request through the unique subdomain, check the source address belongs to the client's estate, and send a control in a non-interpreted context to rule out a mail scanner or proxy resolving the hostname.
- **Severity in the scanner is not ours.** Re-rate every confirmed issue with the conventions below.
- **Silence is not a pass.** A scanner cannot see second-order sinks or asynchronous jobs, and it does not know which input reaches the PDF renderer or what the sort parameter does. It also stops at its own payload list. A clean scan reduces the search space; it does not close a test.

### Where manual work matters

- **Context recognition.** Telling a numeric context from a string one, an identifier from a value, an option from an argument, a template's code context from its text context. Scanners guess; the notes show how to tell.
- **Structure that is not a string.** JSON operator objects, arrays where scalars are expected, `__proto__` keys and content-type switches. Most scanners send string payloads into string slots.
- **Authentication flows.** Login and token checks need the careful, own-account approach of NOSQL-5 and LDAP-6. A scanner's `OR 1=1` in a login form can sign in as the first account in the table, usually an administrator, which you must not do on a client system.
- **Impact without exploitation.** Deciding whether an engine is sandboxed, what the process can reach, which gadget a pollution would hit and what the database account may read. This is judgement from versions, configuration and the client's answers.
- **Source review.** Where the client gives you code, a grep for sinks (`raw(`, `exec(`, `shell=True`, `render_template_string`, `DocumentBuilderFactory.newInstance()`, `merge(`) finds more in an hour than a day of black-box fuzzing. The static-analysis queries below make that repeatable.

### Second-order and asynchronous paths

A second-order injection is stored safely by one request and used unsafely by another, often in a different component, for a different user, minutes or days later. They are invisible to request-response testing and they are where we most often find injection in otherwise well-built applications. Our approach:

1. **Plant inert, labelled probes** in fields you control, one unique marker per field and per interpreter: a quote-and-marker string for SQL, an arithmetic expression for templates, an OOB hostname for commands and XXE, a CR LF marker for logs, a harmless formula for exports. Keep the list.
2. **Trigger the readers you can reach.** Generate the report, export the CSV, request the PDF, send the test email, run the import or sync, open the admin views your role can open, and ask the client to run the batch job if it is scheduled.
3. **Watch every channel:** the response, your mailbox, downloaded files, your collaborator, and, if the client shares them, application logs.
4. **Remove the probes** when you finish, and tell the client which records held them.

The notes that cover this: SQLI-10 (second-order SQL), SSTI-5 (stored and second-order rendering), CMD-7 (file names, headers and stored values reaching commands), XXE-9 (XML inside uploads and imports), CRLF-10 to CRLF-12 (logs, log viewers and exports) and PP-8 (YAML and config imports). Rating follows the direct case: delay and indirection do not reduce impact, and `UI:R` applies only when a person has to open something.

## Notes in this subcategory

The eight notes, in the order they were written. Each one has its own *Before you start*, tests, secure implementation for Node.js, Django, Spring and Laravel where they apply, practice labs, real-world cases, rating table and mapping.

### SQL injection

[SQL Injection: Detection, Confirmation and Prevention](/web/web-sql-injection/) covers input that changes the structure of a SQL statement. It looks at the places it still turns up in modern code: sort parameters, hand-built `IN` lists, report builders, JSON filters, GraphQL arguments, headers written to analytics tables, and the raw escape hatches of ORMs. Detection runs through error, boolean, time and out-of-band signals, each with a control. The proof stops at the version banner and current user, and sqlmap is used only with conservative settings for confirmation. The fixes cover parameterisation in Node.js, Django, Spring and Laravel, and allow-lists for the identifiers that cannot be bound.

- GT-WEB-SQLI-1: Map database-backed inputs and injection points
- GT-WEB-SQLI-2: Error-based detection with syntax probes
- GT-WEB-SQLI-3: Boolean-based detection with true and false pairs
- GT-WEB-SQLI-4: Time-based detection with bounded delays
- GT-WEB-SQLI-5: Out-of-band detection with a collaborator you control
- GT-WEB-SQLI-6: Fingerprint the database and confirm version and current user
- GT-WEB-SQLI-7: ORDER BY, column, table and LIMIT injection
- GT-WEB-SQLI-8: IN lists, search filters and LIKE wildcards
- GT-WEB-SQLI-9: JSON bodies, encoded payloads, headers, cookies and GraphQL arguments
- GT-WEB-SQLI-10: Second-order injection
- GT-WEB-SQLI-11: ORM, query-builder and stored-procedure review
- GT-WEB-SQLI-12: Confirm with sqlmap on conservative settings

### NoSQL injection

[NoSQL Injection: MongoDB Operators, JavaScript Evaluation and Beyond](/web/web-nosql-injection/) covers operator injection and type confusion, where a JSON object or a bracket-parsed query string arrives where the code expected a string. It also covers syntax injection into string-built queries, server-side JavaScript through `$where` and `$function`, and aggregation pipeline injection. Elasticsearch, CouchDB, DynamoDB, Redis and GraphQL filter APIs get the same treatment. Login and token-check tests run only against your own account. The fixes centre on type validation at the boundary and on never passing request objects into filters.

- GT-WEB-NOSQL-1: Fingerprint the data store and map query inputs
- GT-WEB-NOSQL-2: Type confusion with objects, arrays and non-strings
- GT-WEB-NOSQL-3: Operator injection in JSON bodies
- GT-WEB-NOSQL-4: Operator injection through query-string and form parsers
- GT-WEB-NOSQL-5: Login and token-check bypass on your own account
- GT-WEB-NOSQL-6: Syntax injection into string-built queries
- GT-WEB-NOSQL-7: Boolean and regex response differences
- GT-WEB-NOSQL-8: Server-side JavaScript evaluation
- GT-WEB-NOSQL-9: Aggregation pipeline, sort and projection injection
- GT-WEB-NOSQL-10: Elasticsearch, CouchDB, DynamoDB and Redis
- GT-WEB-NOSQL-11: GraphQL resolvers and generic filter APIs
- GT-WEB-NOSQL-12: Configuration and code review

### OS command and argument injection

[OS Command and Argument Injection](/web/web-os-command-injection/) covers input that reaches a shell and starts new commands (CWE-78). It also covers input that becomes an option of a program started without a shell, where the program's own features do the damage (CWE-88). It maps the features that shell out (diagnostics, converters, image and document tools), confirms blind cases with one bounded delay or one DNS lookup, and covers Windows quoting rules and second-order sources such as file names. It then assesses the execution context instead of exploiting it. The fixes use argument arrays without a shell, an end-of-options marker, allow-lists and sandboxing.

- GT-WEB-CMD-1: Map features that call OS programs
- GT-WEB-CMD-2: Response, timing and error baselines
- GT-WEB-CMD-3: Blind confirmation with bounded time delays
- GT-WEB-CMD-4: Blind confirmation with out-of-band DNS
- GT-WEB-CMD-5: Typed fields and input context
- GT-WEB-CMD-6: Option-like values and argument injection
- GT-WEB-CMD-7: Filenames, headers and second-order sources
- GT-WEB-CMD-8: Windows targets
- GT-WEB-CMD-9: Quality of validation and filtering
- GT-WEB-CMD-10: Source and greybox review
- GT-WEB-CMD-11: Vulnerable wrappers and delegate configuration
- GT-WEB-CMD-12: Execution context, hardening and fix verification

### Server-side template and code injection

[Server-Side Template Injection and Code Injection](/web/web-server-side-template-injection/) covers user input that becomes template source, an expression (SpEL, OGNL, Jakarta EL), an `eval` argument, a JNDI lookup string or a server-side include. Detection uses a fuzz string, an arithmetic result and engine discriminators. Impact is assessed from the engine, its sandbox and the template context, not by running code. It also explains how to rule out client-side template injection and application-side maths. The fixes cover Jinja2, Django, EJS, Handlebars, Thymeleaf, FreeMarker, Blade, Twig, Smarty, ERB and Liquid.

- GT-WEB-SSTI-1: Inventory template sinks and user-controlled template content
- GT-WEB-SSTI-2: Plaintext-context detection with a fuzz string and arithmetic
- GT-WEB-SSTI-3: Code-context detection
- GT-WEB-SSTI-4: Identify the template engine
- GT-WEB-SSTI-5: Stored and second-order template rendering
- GT-WEB-SSTI-6: Assess sandbox and context exposure without exploiting
- GT-WEB-SSTI-7: Expression-language injection in Java applications
- GT-WEB-SSTI-8: eval-style code injection in Node.js, Python, PHP and Ruby
- GT-WEB-SSTI-9: Server-side include injection
- GT-WEB-SSTI-10: JNDI and lookup-string injection with out-of-band detection
- GT-WEB-SSTI-11: Rule out client-side rendering and application-side maths
- GT-WEB-SSTI-12: Source review for template, expression and eval sinks

### XXE and XML injection

[XXE and XML Injection](/web/web-xxe-xml-injection/) covers XML parsers that honour an attacker's DTD and fetch files or URLs (CWE-611) or expand entities without limit (CWE-776). It also covers XInclude, user-controlled XSLT and structural injection into XML the server builds (CWE-91). It finds the hidden XML surface: content-type switching on JSON endpoints, SVG and Office uploads, feeds, SOAP and SAML. Proofs are limited to OOB interactions and one agreed harmless file, and expansion limits are checked from configuration only. The fixes give a hardened parser configuration for each platform.

- GT-WEB-XXE-1: Inventory every XML-consuming code path
- GT-WEB-XXE-2: Content-type switching on JSON and form endpoints
- GT-WEB-XXE-3: Probe XML structure with metacharacters
- GT-WEB-XXE-4: DTD acceptance and internal entity expansion
- GT-WEB-XXE-5: External entity resolution to your collaborator
- GT-WEB-XXE-6: Blind detection with parameter entities
- GT-WEB-XXE-7: Agreed-file read and error-based disclosure
- GT-WEB-XXE-8: XInclude when you control only a fragment
- GT-WEB-XXE-9: XML inside uploads and imports
- GT-WEB-XXE-10: XML injection into server-built documents
- GT-WEB-XXE-11: XSLT processing and user-controlled stylesheets
- GT-WEB-XXE-12: Parser configuration review and expansion limits

### LDAP and XPath injection

[LDAP and XPath Injection](/web/web-ldap-xpath-injection/) covers filter and DN injection into directory queries, and XPath or XQuery injection into lookups over XML documents. Both tend to sit next to authentication: Active Directory logins, people search, group checks and legacy XML user stores. The tests use boolean pairs and wildcard behaviour on your own test accounts. They also cover the empty-password unauthenticated bind and XPath 2.0 functions that reach out of band. The fixes use RFC 4515 and RFC 4514 escaping, parameterised XPath and least-privilege service accounts.

- GT-WEB-LDAP-1: Map directory and XML-backed features
- GT-WEB-LDAP-2: Probe for filter metacharacters and errors
- GT-WEB-LDAP-3: Wildcards in search and lookup features
- GT-WEB-LDAP-4: Boolean filter injection
- GT-WEB-LDAP-5: Blind injection and attribute discovery
- GT-WEB-LDAP-6: Login filters and unauthenticated bind
- GT-WEB-LDAP-7: Group membership and authorisation filters
- GT-WEB-LDAP-8: DN injection
- GT-WEB-LDAP-9: XPath injection in lookups and login
- GT-WEB-LDAP-10: Blind XPath, XPath 2.0 functions and XQuery

### CRLF, email header, log and CSV injection

[CRLF, Email Header, Log and CSV Injection](/web/web-crlf-header-log-csv-injection/) covers interpreters that are line-based formats rather than languages. That means HTTP response and outbound request headers (response splitting), mail headers and IMAP/SMTP commands, cache protocols, logs and the viewers that display them, and CSV exports opened in a spreadsheet. It checks what current frameworks already reject before you spend time on them. It assesses what a confirmed header injection enables (cache, cookies, session fixation) without poisoning anything. Request smuggling stays in the HTTP & Infrastructure subcategory.

- GT-WEB-CRLF-1: Map where input reaches response headers
- GT-WEB-CRLF-2: CRLF in redirect targets
- GT-WEB-CRLF-3: CRLF in cookies and custom headers
- GT-WEB-CRLF-4: Encoding, bare LF and path variants
- GT-WEB-CRLF-5: Assess the impact of a confirmed header injection
- GT-WEB-CRLF-6: Header injection in server-side outbound requests
- GT-WEB-CRLF-7: Email header and recipient injection
- GT-WEB-CRLF-8: IMAP and SMTP command injection
- GT-WEB-CRLF-9: Cache and key-value protocol injection
- GT-WEB-CRLF-10: Log forging with CR and LF
- GT-WEB-CRLF-11: Control sequences, markup and lookups in log pipelines
- GT-WEB-CRLF-12: CSV and formula injection in exports

### Server-side prototype pollution

[Server-Side Prototype Pollution in Node.js](/web/web-server-side-prototype-pollution/) covers keys such as `__proto__` and `constructor.prototype` that a recursive merge, clone or path setter writes onto `Object.prototype`. Every object in the process then inherits the attacker's property until the process restarts. It uses only reversible black-box probes (canary reflection, status, formatting and charset changes), agreed with a client contact who can restart the service. Gadgets are assessed rather than triggered. The fixes cover schema validation, null-prototype objects and `Map`, patched merge libraries and own-property checks. For the related object-level outcome, see [mass assignment and BOPLA](/web/web-mass-assignment-bopla/).

- GT-WEB-PP-1: Fingerprint the runtime and map merge-shaped inputs
- GT-WEB-PP-2: Polluted-property reflection with a unique canary
- GT-WEB-PP-3: Status code override probe
- GT-WEB-PP-4: Formatting and header probes
- GT-WEB-PP-5: Charset override probe on staging
- GT-WEB-PP-6: Constructor route and filter variants
- GT-WEB-PP-7: Query strings, forms and path-setter inputs
- GT-WEB-PP-8: YAML, config import and multipart sources
- GT-WEB-PP-9: Gadget and impact assessment
- GT-WEB-PP-10: Source, dependency and runtime review

## All tests at a glance

Built by script from the Mapping tables of the eight notes. The WSTG column lists the test IDs only; sub-page and scope remarks (for example "DBMS sub-pages" or "detection only") are in each note's Mapping table. The ASVS 5.0 column drops the `v5.0.0-` prefix for space, and each requirement is followed by its level. "(context)" marks a mapping test that gives context for a requirement rather than verifying it. CWE and Top 10 mappings per test are in each note.

| Test | Title | Note | WSTG | ASVS 5.0 |
|---|---|---|---|---|
| GT-WEB-SQLI-1 | Map database-backed inputs and injection points | [SQLi](/web/web-sql-injection/) | WSTG-INJT-05, WSTG-INFO-06, WSTG-APIT-99 | 1.2.4 L1 (context) |
| GT-WEB-SQLI-2 | Error-based detection with syntax probes | [SQLi](/web/web-sql-injection/) | WSTG-INJT-05 | 1.2.4 L1, 16.5.1 L2 |
| GT-WEB-SQLI-3 | Boolean-based detection with true and false pairs | [SQLi](/web/web-sql-injection/) | WSTG-INJT-05 | 1.2.4 L1 |
| GT-WEB-SQLI-4 | Time-based detection with bounded delays | [SQLi](/web/web-sql-injection/) | WSTG-INJT-05 | 1.2.4 L1 |
| GT-WEB-SQLI-5 | Out-of-band detection with a collaborator you control | [SQLi](/web/web-sql-injection/) | WSTG-INJT-05 | 1.2.4 L1, 13.2.2 L2 |
| GT-WEB-SQLI-6 | Fingerprint the database and confirm version and current user | [SQLi](/web/web-sql-injection/) | WSTG-INJT-05 | 1.2.4 L1, 13.2.2 L2 |
| GT-WEB-SQLI-7 | ORDER BY, column, table and LIMIT injection | [SQLi](/web/web-sql-injection/) | WSTG-INJT-05 | 1.2.4 L1, 2.2.1 L1 |
| GT-WEB-SQLI-8 | IN lists, search filters and LIKE wildcards | [SQLi](/web/web-sql-injection/) | WSTG-INJT-05 | 1.2.4 L1, 2.2.1 L1 |
| GT-WEB-SQLI-9 | JSON bodies, encoded payloads, headers, cookies and GraphQL arguments | [SQLi](/web/web-sql-injection/) | WSTG-INJT-05, WSTG-APIT-99 | 1.2.4 L1, 1.1.1 L2 |
| GT-WEB-SQLI-10 | Second-order injection | [SQLi](/web/web-sql-injection/) | WSTG-INJT-14, WSTG-INJT-05 | 1.2.4 L1 |
| GT-WEB-SQLI-11 | ORM, query-builder and stored-procedure review | [SQLi](/web/web-sql-injection/) | WSTG-INJT-05 | 1.2.4 L1 |
| GT-WEB-SQLI-12 | Confirm with sqlmap on conservative settings | [SQLi](/web/web-sql-injection/) | WSTG-INJT-05 | 1.2.4 L1 |
| GT-WEB-NOSQL-1 | Fingerprint the data store and map query inputs | [NoSQL](/web/web-nosql-injection/) | WSTG-INJT-05, WSTG-INFO-06, WSTG-INFO-08, WSTG-ERRH-01 | 16.5.1 L2 |
| GT-WEB-NOSQL-2 | Type confusion with objects, arrays and non-strings | [NoSQL](/web/web-nosql-injection/) | WSTG-INJT-05 | 2.2.1 L1, 15.3.5 L2, 1.2.4 L1 |
| GT-WEB-NOSQL-3 | Operator injection in JSON bodies | [NoSQL](/web/web-nosql-injection/) | WSTG-INJT-05 | 1.2.4 L1, 15.3.5 L2 |
| GT-WEB-NOSQL-4 | Operator injection through query-string and form parsers | [NoSQL](/web/web-nosql-injection/) | WSTG-INJT-05, WSTG-INJT-04 | 1.2.4 L1, 15.3.7 L2, 1.5.3 L3 |
| GT-WEB-NOSQL-5 | Login and token-check bypass on your own account | [NoSQL](/web/web-nosql-injection/) | WSTG-INJT-05, WSTG-ATHN-04 | 1.2.4 L1, 15.3.5 L2 |
| GT-WEB-NOSQL-6 | Syntax injection into string-built queries | [NoSQL](/web/web-nosql-injection/) | WSTG-INJT-05 | 1.2.4 L1 |
| GT-WEB-NOSQL-7 | Boolean and regex response differences | [NoSQL](/web/web-nosql-injection/) | WSTG-INJT-05 | 1.2.4 L1, 1.2.9 L2, 1.3.12 L3 |
| GT-WEB-NOSQL-8 | Server-side JavaScript evaluation | [NoSQL](/web/web-nosql-injection/) | WSTG-INJT-05, WSTG-INJT-11 | 1.3.2 L1, 1.2.4 L1 |
| GT-WEB-NOSQL-9 | Aggregation pipeline, sort and projection injection | [NoSQL](/web/web-nosql-injection/) | WSTG-INJT-05 | 1.2.4 L1, 15.3.1 L1 |
| GT-WEB-NOSQL-10 | Elasticsearch, CouchDB, DynamoDB and Redis | [NoSQL](/web/web-nosql-injection/) | WSTG-INJT-05 | 1.2.4 L1, 1.2.9 L2 |
| GT-WEB-NOSQL-11 | GraphQL resolvers and generic filter APIs | [NoSQL](/web/web-nosql-injection/) | WSTG-INJT-05, WSTG-APIT-99 | 1.2.4 L1, 8.2.2 L1 |
| GT-WEB-NOSQL-12 | Configuration and code review | [NoSQL](/web/web-nosql-injection/) | WSTG-INJT-05, WSTG-INJT-11 | 1.3.2 L1, 13.2.2 L2, 15.2.2 L2 |
| GT-WEB-CMD-1 | Map features that call OS programs | [Command](/web/web-os-command-injection/) | WSTG-INJT-12, WSTG-INFO-06, WSTG-INFO-10, WSTG-INJT-14 | 1.2.5 L1 (context) |
| GT-WEB-CMD-2 | Response, timing and error baselines | [Command](/web/web-os-command-injection/) | WSTG-INJT-12, WSTG-ERRH-01 | 13.4.6 L3 |
| GT-WEB-CMD-3 | Blind confirmation with bounded time delays | [Command](/web/web-os-command-injection/) | WSTG-INJT-12 | 1.2.5 L1 |
| GT-WEB-CMD-4 | Blind confirmation with out-of-band DNS | [Command](/web/web-os-command-injection/) | WSTG-INJT-12, WSTG-INJT-14 | 1.2.5 L1 |
| GT-WEB-CMD-5 | Typed fields and input context | [Command](/web/web-os-command-injection/) | WSTG-INJT-12 | 1.3.3 L2, 1.2.5 L1 |
| GT-WEB-CMD-6 | Option-like values and argument injection | [Command](/web/web-os-command-injection/) | WSTG-INJT-12 | 1.2.5 L1, 1.3.3 L2 |
| GT-WEB-CMD-7 | Filenames, headers and second-order sources | [Command](/web/web-os-command-injection/) | WSTG-INJT-14, WSTG-BUSL-09, WSTG-INJT-12 | 5.3.2 L1, 1.2.5 L1 |
| GT-WEB-CMD-8 | Windows targets | [Command](/web/web-os-command-injection/) | WSTG-INJT-12 | 1.2.5 L1 |
| GT-WEB-CMD-9 | Quality of validation and filtering | [Command](/web/web-os-command-injection/) | WSTG-INJT-12 | 1.2.5 L1, 1.3.3 L2, 1.1.1 L2 |
| GT-WEB-CMD-10 | Source and greybox review | [Command](/web/web-os-command-injection/) | WSTG-INJT-12 | 1.2.5 L1, 1.3.3 L2 |
| GT-WEB-CMD-11 | Vulnerable wrappers and delegate configuration | [Command](/web/web-os-command-injection/) | WSTG-INJT-12, WSTG-BUSL-09 | 1.2.8 L2, 15.2.1 L1, 15.2.5 L3 |
| GT-WEB-CMD-12 | Execution context, hardening and fix verification | [Command](/web/web-os-command-injection/) | WSTG-INJT-12 | 13.2.2 L2, 15.2.5 L3 |
| GT-WEB-SSTI-1 | Inventory template sinks and user-controlled template content | [SSTI](/web/web-server-side-template-injection/) | WSTG-INJT-18, WSTG-INJT-11, WSTG-INJT-08, WSTG-INJT-14 | 1.3.7 L2, 1.3.5 L2 |
| GT-WEB-SSTI-2 | Plaintext-context detection with a fuzz string and arithmetic | [SSTI](/web/web-server-side-template-injection/) | WSTG-INJT-18 | 1.3.7 L2 |
| GT-WEB-SSTI-3 | Code-context detection | [SSTI](/web/web-server-side-template-injection/) | WSTG-INJT-18 | 1.3.7 L2 |
| GT-WEB-SSTI-4 | Identify the template engine | [SSTI](/web/web-server-side-template-injection/) | WSTG-INJT-18 | 1.3.7 L2 |
| GT-WEB-SSTI-5 | Stored and second-order template rendering | [SSTI](/web/web-server-side-template-injection/) | WSTG-INJT-18, WSTG-INJT-14 | 1.3.7 L2, 1.3.5 L2 |
| GT-WEB-SSTI-6 | Assess sandbox and context exposure without exploiting | [SSTI](/web/web-server-side-template-injection/) | WSTG-INJT-18 | 1.3.5 L2, 1.3.7 L2, 15.2.5 L3 |
| GT-WEB-SSTI-7 | Expression-language injection in Java applications | [SSTI](/web/web-server-side-template-injection/) | WSTG-INJT-11, WSTG-INJT-18 | 1.3.2 L1, 1.3.7 L2 |
| GT-WEB-SSTI-8 | eval-style code injection in Node.js, Python, PHP and Ruby | [SSTI](/web/web-server-side-template-injection/) | WSTG-INJT-11 | 1.3.2 L1 |
| GT-WEB-SSTI-9 | Server-side include injection | [SSTI](/web/web-server-side-template-injection/) | WSTG-INJT-08 | 1.3.5 L2, 1.2.1 L1 |
| GT-WEB-SSTI-10 | JNDI and lookup-string injection with out-of-band detection | [SSTI](/web/web-server-side-template-injection/) | WSTG-INJT-11 | 1.3.8 L2 |
| GT-WEB-SSTI-11 | Rule out client-side rendering and application-side maths | [SSTI](/web/web-server-side-template-injection/) | WSTG-INJT-18, WSTG-CLNT-15 | 1.3.7 L2 |
| GT-WEB-SSTI-12 | Source review for template, expression and eval sinks | [SSTI](/web/web-server-side-template-injection/) | WSTG-INJT-18, WSTG-INJT-11, WSTG-INJT-08 | 1.3.7 L2, 1.3.2 L1, 1.3.5 L2, 1.3.8 L2 |
| GT-WEB-XXE-1 | Inventory every XML-consuming code path | [XXE](/web/web-xxe-xml-injection/) | WSTG-INJT-07, WSTG-INFO-06, WSTG-APIT-01 | 1.5.1 L1 (context) |
| GT-WEB-XXE-2 | Content-type switching on JSON and form endpoints | [XXE](/web/web-xxe-xml-injection/) | WSTG-INJT-07 | 1.5.1 L1, 1.5.3 L3 |
| GT-WEB-XXE-3 | Probe XML structure with metacharacters | [XXE](/web/web-xxe-xml-injection/) | WSTG-INJT-07, WSTG-ERRH-01 | 1.2.1 L1, 16.5.1 L2 |
| GT-WEB-XXE-4 | DTD acceptance and internal entity expansion | [XXE](/web/web-xxe-xml-injection/) | WSTG-INJT-07 | 1.5.1 L1 |
| GT-WEB-XXE-5 | External entity resolution to your collaborator | [XXE](/web/web-xxe-xml-injection/) | WSTG-INJT-07 | 1.5.1 L1 |
| GT-WEB-XXE-6 | Blind detection with parameter entities | [XXE](/web/web-xxe-xml-injection/) | WSTG-INJT-07 | 1.5.1 L1 |
| GT-WEB-XXE-7 | Agreed-file read and error-based disclosure | [XXE](/web/web-xxe-xml-injection/) | WSTG-INJT-07, WSTG-ERRH-01 | 1.5.1 L1, 16.5.1 L2 |
| GT-WEB-XXE-8 | XInclude when you control only a fragment | [XXE](/web/web-xxe-xml-injection/) | WSTG-INJT-07 | 1.5.1 L1, 1.2.1 L1 |
| GT-WEB-XXE-9 | XML inside uploads and imports | [XXE](/web/web-xxe-xml-injection/) | WSTG-INJT-07, WSTG-BUSL-08, WSTG-BUSL-09 | 1.5.1 L1, 1.3.4 L2, 5.2.2 L1, 5.2.3 L2 |
| GT-WEB-XXE-10 | XML injection into server-built documents | [XXE](/web/web-xxe-xml-injection/) | WSTG-INJT-07 | 1.2.1 L1 |
| GT-WEB-XXE-11 | XSLT processing and user-controlled stylesheets | [XXE](/web/web-xxe-xml-injection/) | WSTG-INJT-07 | 1.3.5 L2 |
| GT-WEB-XXE-12 | Parser configuration review and expansion limits | [XXE](/web/web-xxe-xml-injection/) | WSTG-INJT-07 | 1.5.1 L1, 15.2.1 L1, 15.2.2 L2, 5.2.3 L2 |
| GT-WEB-LDAP-1 | Map directory and XML-backed features | [LDAP/XPath](/web/web-ldap-xpath-injection/) | WSTG-INJT-06, WSTG-INJT-09, WSTG-INFO-06 | 16.5.1 L2 |
| GT-WEB-LDAP-2 | Probe for filter metacharacters and errors | [LDAP/XPath](/web/web-ldap-xpath-injection/) | WSTG-INJT-06, WSTG-ERRH-01 | 1.2.6 L2, 16.5.1 L2 |
| GT-WEB-LDAP-3 | Wildcards in search and lookup features | [LDAP/XPath](/web/web-ldap-xpath-injection/) | WSTG-INJT-06 | 1.2.6 L2 |
| GT-WEB-LDAP-4 | Boolean filter injection | [LDAP/XPath](/web/web-ldap-xpath-injection/) | WSTG-INJT-06 | 1.2.6 L2, 1.1.2 L2 |
| GT-WEB-LDAP-5 | Blind injection and attribute discovery | [LDAP/XPath](/web/web-ldap-xpath-injection/) | WSTG-INJT-06 | 1.2.6 L2, 6.3.8 L3, 13.2.2 L2 |
| GT-WEB-LDAP-6 | Login filters and unauthenticated bind | [LDAP/XPath](/web/web-ldap-xpath-injection/) | WSTG-INJT-06, WSTG-ATHN-04 | 1.2.6 L2, 6.3.8 L3 |
| GT-WEB-LDAP-7 | Group membership and authorisation filters | [LDAP/XPath](/web/web-ldap-xpath-injection/) | WSTG-INJT-06, WSTG-ATHZ-03 | 1.2.6 L2, 8.2.1 L1 |
| GT-WEB-LDAP-8 | DN injection | [LDAP/XPath](/web/web-ldap-xpath-injection/) | WSTG-INJT-06 | 1.2.6 L2, 1.1.2 L2 |
| GT-WEB-LDAP-9 | XPath injection in lookups and login | [LDAP/XPath](/web/web-ldap-xpath-injection/) | WSTG-INJT-09 | 1.2.7 L2 |
| GT-WEB-LDAP-10 | Blind XPath, XPath 2.0 functions and XQuery | [LDAP/XPath](/web/web-ldap-xpath-injection/) | WSTG-INJT-09 | 1.2.7 L2, 13.2.4 L2 |
| GT-WEB-CRLF-1 | Map where input reaches response headers | [CRLF](/web/web-crlf-header-log-csv-injection/) | WSTG-INJT-15 | 1.2.1 L1 |
| GT-WEB-CRLF-2 | CRLF in redirect targets | [CRLF](/web/web-crlf-header-log-csv-injection/) | WSTG-INJT-15 | 1.2.1 L1, 1.2.2 L1 |
| GT-WEB-CRLF-3 | CRLF in cookies and custom headers | [CRLF](/web/web-crlf-header-log-csv-injection/) | WSTG-INJT-15 | 1.2.1 L1 |
| GT-WEB-CRLF-4 | Encoding, bare LF and path variants | [CRLF](/web/web-crlf-header-log-csv-injection/) | WSTG-INJT-15 | 1.2.1 L1 |
| GT-WEB-CRLF-5 | Assess the impact of a confirmed header injection | [CRLF](/web/web-crlf-header-log-csv-injection/) | WSTG-INJT-15 | 1.2.1 L1, 7.2.4 L1 |
| GT-WEB-CRLF-6 | Header injection in server-side outbound requests | [CRLF](/web/web-crlf-header-log-csv-injection/) | WSTG-INJT-15, WSTG-INJT-16 | 1.2.1 L1, 4.2.4 L3 |
| GT-WEB-CRLF-7 | Email header and recipient injection | [CRLF](/web/web-crlf-header-log-csv-injection/) | WSTG-INJT-10 | 1.3.11 L2 |
| GT-WEB-CRLF-8 | IMAP and SMTP command injection | [CRLF](/web/web-crlf-header-log-csv-injection/) | WSTG-INJT-10 | 1.3.11 L2 |
| GT-WEB-CRLF-9 | Cache and key-value protocol injection | [CRLF](/web/web-crlf-header-log-csv-injection/) | WSTG-INJT-10 | 1.3.9 L2, 1.3.3 L2 |
| GT-WEB-CRLF-10 | Log forging with CR and LF | [CRLF](/web/web-crlf-header-log-csv-injection/) | WSTG-INJT-14 | 16.4.1 L2, 16.2.4 L2 |
| GT-WEB-CRLF-11 | Control sequences, markup and lookups in log pipelines | [CRLF](/web/web-crlf-header-log-csv-injection/) | WSTG-INJT-14 | 16.4.1 L2, 1.3.8 L2 |
| GT-WEB-CRLF-12 | CSV and formula injection in exports | [CRLF](/web/web-crlf-header-log-csv-injection/) | WSTG-INJT-21 | 1.2.10 L3 |
| GT-WEB-PP-1 | Fingerprint the runtime and map merge-shaped inputs | [Prototype pollution](/web/web-server-side-prototype-pollution/) | WSTG-INJT-22, WSTG-INFO-06, WSTG-INFO-08 | 2.2.1 L1 |
| GT-WEB-PP-2 | Polluted-property reflection with a unique canary | [Prototype pollution](/web/web-server-side-prototype-pollution/) | WSTG-INJT-22 | 15.3.6 L2, 2.2.1 L1 |
| GT-WEB-PP-3 | Status code override probe | [Prototype pollution](/web/web-server-side-prototype-pollution/) | WSTG-INJT-22 | 15.3.6 L2 |
| GT-WEB-PP-4 | Formatting and header probes | [Prototype pollution](/web/web-server-side-prototype-pollution/) | WSTG-INJT-22 | 15.3.6 L2, 15.2.1 L1 |
| GT-WEB-PP-5 | Charset override probe on staging | [Prototype pollution](/web/web-server-side-prototype-pollution/) | WSTG-INJT-22 | 15.3.6 L2 |
| GT-WEB-PP-6 | Constructor route and filter variants | [Prototype pollution](/web/web-server-side-prototype-pollution/) | WSTG-INJT-22 | 15.3.6 L2, 2.2.1 L1 |
| GT-WEB-PP-7 | Query strings, forms and path-setter inputs | [Prototype pollution](/web/web-server-side-prototype-pollution/) | WSTG-INJT-22 | 15.3.6 L2, 15.3.7 L2 |
| GT-WEB-PP-8 | YAML, config import and multipart sources | [Prototype pollution](/web/web-server-side-prototype-pollution/) | WSTG-INJT-22 | 15.3.6 L2, 2.2.1 L1, 15.2.1 L1 |
| GT-WEB-PP-9 | Gadget and impact assessment | [Prototype pollution](/web/web-server-side-prototype-pollution/) | WSTG-INJT-22 | 15.3.6 L2, 15.3.3 L2 |
| GT-WEB-PP-10 | Source, dependency and runtime review | [Prototype pollution](/web/web-server-side-prototype-pollution/) | WSTG-INJT-22 | 15.3.6 L2, 15.2.1 L1 |

## ASVS 5.0 V1 coverage

The injection requirements in [ASVS 5.0 V1 Encoding and Sanitization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md) (sections 1.1, 1.2, 1.3 and 1.5), with the tests that produce evidence for each. A requirement is verified at a level only if the application is assessed at that level or higher. An L1 assessment does not fail on `1.2.10`, but we still report what we saw as an observation. Rows marked *later subcategory* are tested elsewhere in the series.

| Requirement | Level | What it asks for (paraphrased) | Verified by |
|---|---|---|---|
| `v5.0.0-1.1.1` | L2 | Decode input into canonical form once, before validation | SQLI-9, CMD-9 |
| `v5.0.0-1.1.2` | L2 | Encode as the final step before the interpreter, or let the interpreter do it | LDAP-4, LDAP-8 |
| `v5.0.0-1.2.1` | L1 | Context-appropriate output encoding for HTTP responses, HTML and XML documents, including header fields | CRLF-1 to CRLF-6; XXE-3, XXE-8, XXE-10; SSTI-9. HTML element, attribute, CSS and comment contexts: *later subcategory* (Client-Side) |
| `v5.0.0-1.2.2` | L1 | Encode untrusted data when building URLs; allow only safe URL schemes | CRLF-2 (redirect targets). Scheme allow-lists (`javascript:`, `data:`): *later subcategory* (Client-Side) |
| `v5.0.0-1.2.3` | L1 | Encode when building JavaScript and JSON content | *Later subcategory* (Client-Side) |
| `v5.0.0-1.2.4` | L1 | Parameterised queries or equivalent protection for SQL, HQL, NoSQL and Cypher, stored procedures included | SQLI-1 to SQLI-12; NOSQL-2 to NOSQL-11 |
| `v5.0.0-1.2.5` | L1 | Protection against OS command injection: parameterised OS calls or contextual command-line encoding | CMD-1, CMD-3 to CMD-10 |
| `v5.0.0-1.2.6` | L2 | Protection against LDAP injection | LDAP-2 to LDAP-8 |
| `v5.0.0-1.2.7` | L2 | Parameterised or precompiled XPath queries | LDAP-9, LDAP-10 |
| `v5.0.0-1.2.8` | L2 | LaTeX processors configured without shell escape, with a command allow-list | CMD-11 |
| `v5.0.0-1.2.9` | L2 | Regex metacharacters escaped | NOSQL-7, NOSQL-10 |
| `v5.0.0-1.2.10` | L3 | CSV and formula injection: RFC 4180 escaping and neutralised formula characters | CRLF-12 |
| `v5.0.0-1.3.1` | L1 | Untrusted HTML from WYSIWYG editors sanitised with a well-known library | *Later subcategory* (Client-Side) |
| `v5.0.0-1.3.2` | L1 | Avoid `eval()` and dynamic code execution such as SpEL; sanitise input where there is no alternative | SSTI-7, SSTI-8, SSTI-12; NOSQL-8, NOSQL-12 |
| `v5.0.0-1.3.3` | L2 | Sanitise data passed to a dangerous context (safe characters, length limits) | CMD-5, CMD-6, CMD-9, CMD-10; CRLF-9 |
| `v5.0.0-1.3.4` | L2 | User-supplied SVG limited to safe tags and attributes | XXE-9 (the XML side of SVG). Script in SVG: *later subcategory* (Client-Side) |
| `v5.0.0-1.3.5` | L2 | Sanitise or disable user-supplied scriptable or template content (Markdown, CSS, XSL, BBCode) | SSTI-1, SSTI-5, SSTI-6, SSTI-9, SSTI-12; XXE-11. Markdown and BBCode rendering into HTML: *later subcategory* (Client-Side) |
| `v5.0.0-1.3.6` | L2 | SSRF protection through allow-lists of protocols, domains, paths and ports | *Later subcategory* (Server-Side Request & Files). XXE-5 and LDAP-10 show outbound reach from a parser but do not verify this requirement |
| `v5.0.0-1.3.7` | L2 | Templates never built from untrusted input; strict validation where there is no alternative | SSTI-1 to SSTI-7, SSTI-11, SSTI-12 |
| `v5.0.0-1.3.8` | L2 | Sanitise input to JNDI queries and configure JNDI securely | SSTI-10, SSTI-12; CRLF-11 (lookups in log pipelines) |
| `v5.0.0-1.3.9` | L2 | Sanitise content sent to memcache | CRLF-9 |
| `v5.0.0-1.3.10` | L2 | Sanitise format strings that could resolve unexpectedly | Not covered by a test in this series at the time of writing (WSTG-INJT-13); flag `printf`-style sinks found in source review |
| `v5.0.0-1.3.11` | L2 | Sanitise input passed to mail systems (SMTP, IMAP) | CRLF-7, CRLF-8 |
| `v5.0.0-1.3.12` | L3 | Regular expressions free of exponential backtracking | NOSQL-7 for database regex; other ReDoS sinks are not tested here |
| `v5.0.0-1.5.1` | L1 | Restrictive XML parser configuration, external entities disabled | XXE-1, XXE-2, XXE-4 to XXE-9, XXE-12 |
| `v5.0.0-1.5.2` | L2 | Safe deserialisation: type allow-lists, no insecure mechanisms with untrusted data | *Later subcategory* (Server-Side Request & Files) |
| `v5.0.0-1.5.3` | L3 | Parsers for the same data type behave consistently | NOSQL-4, XXE-2; URL-parser cases in *later subcategories* |

The memory-safety requirements in 1.4 apply to native code and are out of scope for a web application test. Outside V1, the notes also produce evidence for V2 (`2.2.1` positive validation), V5 (`5.2.2`, `5.2.3`, `5.3.2` file handling), V13 (`13.2.2` least-privilege back-end accounts, `13.2.4`, `13.4.6`), V15 (`15.2.1`, `15.2.2`, `15.2.5` sandboxing, `15.3.5` strict types, `15.3.6` prototype pollution, `15.3.7` parameter pollution) and V16 (`16.2.4`, `16.4.1` log injection, `16.5.1` generic errors). The all-tests table lists them per test.

## Rating injection findings

The series uses one severity scale and one approach to CVSS; both are under *Rating findings* in the [series hub](/web/web-application-security-testing-guide/). Each note has its own rating table. This section collects the conventions those tables share, so that findings from different notes sit in one report without contradicting each other or the [Access Control hub](/web/web-access-control-testing-guide/).

### Conventions

1. **Rate what the interpreter gives the attacker, not the technique.** Blind injection is slower to exploit, but it reads the same data as an in-band one. An `ORDER BY` injection confirmed by `CASE` pairs is still SQL injection. Second-order and asynchronous findings take the rating of the direct case with the same preconditions. Use `UI:R` only when a person has to open something, and `UI:N` when a job triggers it.
2. **Severity is ours; CVSS is an input.** Write every vector with its version prefix (`CVSS:3.1/…`), as the series hub requires. Base metrics cannot express what the database or file system holds. Report the vector honestly and move the severity with a stated reason. The commonest example is blind SQL injection by a read-only account, which scores 6.5 and which we rate High.
3. **Scope Unchanged unless the impact clearly escapes the vulnerable component.** The application, its own database, its own host or container and its own tenants form one security authority, so the baseline is `S:U`. This includes code execution as the application's account, which is 9.8 unauthenticated and 8.8 for any registered user.
   - Use `S:C` only with evidence that the impact lands in a separate authority. Examples are a host shared with other applications, a container with host-level privileges, credentials for systems administered separately (another team's database, a cloud account), requests into other internal services, or a component with its own authority such as the victim's browser, the spreadsheet on the opener's workstation or a cache shared by other users.
   - Other tenants of the same application do not by themselves make `S:C`; raise the severity for scale, as Access Control convention 3 does.
   - An OOB interaction with your own collaborator shows outbound reach, not a change of scope.
   - Say in the report which applies and why.
4. **Published CVEs keep their published vector.** Log4Shell (CVE-2021-44228) is 10.0 as published, and Struts, Confluence or ImageMagick advisories follow the vendor or NVD vector. Our evidence is the version plus a reachable code path. We do not attempt the exploit.
5. **Documented capability counts as impact.** An unsandboxed engine where public research shows code execution, SSI with `#exec` enabled, XSLT with extension functions, or a reachable program option that runs commands is rated as code execution even though you stopped at arithmetic, a delay or a DNS lookup. Say clearly that execution was not demonstrated.
6. **Proof level caps the claim where capability is not documented.** OOB-only XXE is Medium until file read or internal reach is shown. Global prototype pollution without an identified gadget is Medium to High. A filter that is incomplete but has no working probe is Info or Low.
7. **Privileges Required.** Use `PR:N` only when no account is needed. Any registered account is `PR:L`, including a self-service trial and a self-service tenant administrator (Access Control convention 5). `PR:H` is for operator roles that are vetted. Admin-only code execution or SQL injection is Medium to High (7.2). It is High when administrators are not meant to have server access, and Medium where they already deploy code, which you state as an accepted design risk.
8. **Availability follows what the reached interpreter can destroy.** Use `A:H` for code execution and for database accounts that can write. Use `A:N` for read-only accounts and file reads. Denial-of-service potential that comes only from configuration evidence (entity expansion, ReDoS, unlimited template rendering) is Medium. The `A:H` vector describes an outage you did not cause, so rate it below the vector and say why.
9. **Login bypass is rated by whose account you reach.** If an unauthenticated attacker can choose any account, administrators included, it is Critical (9.1). If the bypass is limited to some accounts or needs a known username plus another condition, it is High, with the limits stated. Group or role checks made true by injection are High (8.1).
10. **No reachable interpreter, no vulnerability.** Verbose interpreter errors without confirmed injection are Low. The base score (5.3) overstates them. A vulnerable library that request data cannot reach, a denylist with no working bypass, or a parser feature that is enabled but unused is Info or Low. These items raise the rating of any injection found next to them.

### Typical ratings

Scores are calculated with the FIRST v3.1 formulas; check them in the [calculator](https://www.first.org/cvss/calculator/3.1) if you reuse them. The Note column says which note's rating table has the detailed rows.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning | Note |
|---|---|---|---|---|
| Unauthenticated code execution: command injection, SSTI or EL in an unsandboxed engine, SSI `#exec`, prototype pollution with an RCE gadget | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | Anyone runs code as the application's account | CMD, SSTI, PP |
| As above, impact shown to escape (shared host, privileged container, credentials for separate systems) | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (10.0) | Convention 3; name the shared resource | CMD, SSTI, SQLI, PP |
| Code execution for any registered user (including second-order through email or PDF templates) | Critical; High only if tightly sandboxed | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Registration is a thin barrier; `S:C` (9.9) when convention 3 applies | CMD, SSTI, PP |
| Code execution or SQL injection in an admin-only feature | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (7.2) | Convention 7; a self-service tenant admin is `PR:L` (8.8) | CMD, SSTI, SQLI, PP |
| Unauthenticated SQL injection, account reads and writes application data | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | Whole application database readable and changeable | SQLI |
| Unauthenticated blind SQL injection, read-only account | High or Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | Critical when the readable data is sensitive and at scale | SQLI |
| Authenticated SQL injection reading the database | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Read-only low-privilege account: `C:H/I:N/A:N` (6.5), rated High | SQLI |
| Unauthenticated login as any chosen account (operator injection, LDAP unauthenticated bind, filter bypass) | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | Convention 9; High when limited to some accounts | NOSQL, LDAP |
| Injection makes a group or role check true | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1) | Any user to the application's privileged role | LDAP |
| Operator, filter or search-syntax injection crossing the user or tenant scope | High; Critical for sensitive multi-tenant data at scale | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | An authorisation bypass through the query | NOSQL, LDAP |
| XXE or XInclude with agreed-file read, unauthenticated | High; Critical when secrets were confirmed with approval | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | Any file the process can read is exposed | XXE |
| XXE with internal network reach shown | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` (8.6) | Requests into other internal services are a separate authority | XXE |
| OOB-only interaction from a parser (XXE, XPath 2.0 `doc()`), no read or internal reach | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | Resolution proven, disclosure not; conventions 3 and 6 | XXE, LDAP |
| JNDI lookup expansion confirmed by OOB DNS (Log4Shell pattern) | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (10.0) | Published vector, convention 4 | SSTI, CRLF |
| Sandboxed engine, secrets or other users' data reachable through the template context | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Raise it when the secret signs sessions or unlocks further access | SSTI |
| Global prototype pollution confirmed, no gadget identified | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H` (7.1) | Shared behaviour changed for every user until restart | PP |
| Structural XML injection changing a document a partner trusts | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` (6.5) | Integrity of a trusted business message; Medium with a harmless marker only | XXE |
| Response splitting with body control | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | Equivalent to reflected XSS; `S:C` because the browser is a separate authority | CRLF |
| `Set-Cookie` injection with working session fixation | High | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N` (6.8) | Account takeover after the victim logs in | CRLF |
| Split response stored by a shared cache (from analysis) | High | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N` (7.5) | Every user of the cached URL is affected; not proven by poisoning | CRLF |
| Arbitrary response header injection, no body control | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` (5.4) | Impact depends on which headers matter | CRLF |
| Email header or recipient injection on an unauthenticated form | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` (5.3) | Mail relayed with the organisation's SPF and DKIM; High to Critical if another user's reset mail is copied | CRLF |
| CSV formula evaluated when staff open the export | Low to Medium; many programmes rate it Informative | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` (5.4) | The opener's spreadsheet is a separate authority; Low (3.5, `S:U/C:N/I:L`) when only displayed values change | CRLF |
| Markup rendered in an admin log viewer | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | Stored XSS against privileged users | CRLF |
| Log forging in a plain-text log | Low | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` (5.3) | Base score overstates it; only log evidence is affected | CRLF |
| Missing limits on entity expansion, regex or template rendering (configuration evidence) | Medium | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` (6.5) | Convention 8; never demonstrated | XXE, NOSQL, SSTI |
| Verbose interpreter errors, no confirmed injection | Low | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | Convention 10 | SQLI, CMD, LDAP, XXE |
| Shell-out with a denylist and no working probe; unreachable vulnerable library; risky parser feature unused | Info to Low | none | No reachable interpreter; raises the rating of anything found next to it | CMD, PP, XXE |

## Prevention patterns

Each note gives the fixes in Node.js, Django, Spring and Laravel, with the exact APIs. The patterns behind them are the same across interpreters. When you write recommendations, name the pattern first and the API second, so the client fixes the class and not just the line.

### The patterns

| Pattern | What it means | Where it applies |
|---|---|---|
| **Parameterise** | Send code and data to the interpreter separately, so that data can never change the structure. Use bound SQL parameters, ORM query methods, parameterised XPath and the driver's own query objects | SQL (`1.2.4`), NoSQL with `$eq` or typed values, XPath (`1.2.7`) |
| **Use a structured API instead of a string** | Pass an argument array to a process without a shell (`execFile`/`spawn`, `subprocess.run([...])`, `ProcessBuilder`, Symfony `Process` with an array). Set headers and mail recipients through library calls that reject CR and LF. Build XML with a DOM or serialiser, and logs with a structured (JSON) formatter | Commands (`1.2.5`), headers (`1.2.1`), mail (`1.3.11`), XML building, logs (`16.4.1`) |
| **Allow-list what cannot be bound** | Map sort columns, directions, table names, operators, program options and template names to fixed values on the server. Reject everything else. Put user values after `--` and reject a leading `-` | SQL identifiers, Mongo operators, CMD-6 option injection, view names |
| **Validate type and shape at the boundary** | Use a schema that says "string, 1–64 characters" or "integer". It stops operator objects, arrays and `__proto__` keys before they reach a query or a merge. Validation is a second line, not the fix for string building | NoSQL (`15.3.5`), prototype pollution (`15.3.6`), every interpreter (`2.2.1`) |
| **Escape for the exact context, as the last step** | Where an interpreter has no parameter API, apply its own escaping rules immediately before use: RFC 4515 for LDAP filters, RFC 4514 for DNs, RFC 4180 plus formula neutralisation for CSV, regex quoting for patterns. Escaping for the wrong context, or too early, is a finding | LDAP (`1.2.6`), CSV (`1.2.10`), regex (`1.2.9`), `1.1.2` |
| **Configure parsers and engines safely** | Disallow DOCTYPE or disable external entities and XInclude. Turn off XSLT extension functions, SSI `#exec`, JNDI lookups in log messages and server-side JavaScript in the database. Use null-prototype objects and patched merge libraries | XXE (`1.5.1`), SSI and JNDI (`1.3.8`), PP |
| **Never build templates or code from input** | Pass user data into a fixed template as context variables. Keep `eval`, `Function`, SpEL parsing and `render_template_string` away from request data. Users who must write templates get a logic-less or sandboxed engine with time and size limits | SSTI (`1.3.7`, `1.3.2`, `1.3.5`) |
| **Sandbox and least privilege** | The database account reads only what the feature needs. The process that converts images runs in a container with no credentials, no egress and a hardened ImageMagick or Ghostscript policy. The directory service account cannot read password attributes | `13.2.2`, `15.2.5`; limits the blast radius when the other patterns fail |
| **Keep components current** | Most expression-language, template and XML findings in the wild are known CVEs in products and libraries | `15.2.1` |

### Static analysis

The query and rule names below are the ones the notes use. Check them against your tool version.

- **SQL:** CodeQL `js/sql-injection`, `py/sql-injection`, `java/sql-injection`, `java/concatenated-sql-query`, `cs/sql-injection`. Semgrep `sql-injection-using-raw` (Django), `formatted-sql-string` (Java), `tainted-sql-string` (Express, PHP), `laravel-sql-injection`.
- **NoSQL:** CodeQL `js/sql-injection` (it also covers MongoDB queries, tagged CWE-943) and `py/nosql-injection`. njsscan's `node_nosqli_injection` in the Semgrep registry.
- **Commands:** Semgrep `p/command-injection`, `subprocess-shell-true`, `dangerous-subprocess-use-audit`, `detect-child-process`. CodeQL `js/command-line-injection`, `js/second-order-command-line-injection`, `js/shell-command-constructed-from-input`, `py/command-line-injection`, `java/command-line-injection`.
- **Templates and code:** CodeQL `py/template-injection`, `js/code-injection`, `js/template-object-injection`, `java/server-side-template-injection`, `java/spel-expression-injection`, `java/ognl-injection`. Semgrep `render-template-string`, `spel-injection`, `el-injection`.
- **XML:** CodeQL `java/xxe`, `py/xxe`, `js/xxe`, `js/xml-bomb`, `cs/xml/insecure-dtd-handling`, `java/xslt-injection`. Semgrep `documentbuilderfactory-disallow-doctype-decl-missing`.
- **LDAP and XPath:** CodeQL `java/ldap-injection`, `py/ldap-injection`, `java/xml/xpath-injection`, `py/xpath-injection`, `js/xpath-injection`.
- **Headers and logs:** CodeQL `java/http-response-splitting`, `py/http-response-splitting`, `java/log-injection`, `js/log-injection`, `py/log-injection`. gixy `http_splitting` for nginx.
- **Prototype pollution:** CodeQL `js/prototype-pollution`, `js/prototype-pollution-utility`, `js/prototype-polluting-assignment`. Semgrep `prototype-pollution-loop` and `prototype-pollution-assignment`.

Generic rules do not know the project's own helpers. Each note suggests a cheap custom rule that fails the build on any new use of a project-specific escape hatch (`$queryRawUnsafe`, `orderByRaw(`, `shell=True`, a raw XML factory, a hand-written merge) unless a reviewer has suppressed it.

### Regression tests

Every confirmed finding should leave a test behind. The test sends the malicious-looking input that proved the bug (a quote, an operator object, `; sleep 0`, an arithmetic expression, a DOCTYPE, a CR LF, `__proto__`) through the real request path. It then asserts that the input is treated as data: the stored value equals the input, the response matches the control, no extra header, recipient, log line or cell appears, and the prototype is unchanged. Add cases for the contexts that parameters cannot protect, and run them in CI with the rest of the suite. The notes' *Regression tests* sections give examples for each stack.

## Practice path

A sequence that follows the order of this hub. Labs are where you may extract data and run code, because they are built for it. Keep the client-system habits anyway: one change at a time, and a control for every signal.

1. **SQL injection basics (PortSwigger).** [Retrieval of hidden data](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data), [Login bypass](https://portswigger.net/web-security/sql-injection/lab-login-bypass), [Querying the database version on MySQL and Microsoft](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft), then the blind ladder: [conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses), [time delays](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays), [out-of-band interaction](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band).
2. **NoSQL (PortSwigger).** [Detecting NoSQL injection](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-detection) and [operator injection to bypass authentication](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication).
3. **OS commands (PortSwigger, then DVWA).** [Simple case](https://portswigger.net/web-security/os-command-injection/lab-simple), [blind with time delays](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays), [blind with out-of-band interaction](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band), then the *Command Injection* module of [DVWA](https://github.com/digininja/DVWA) at each security level, reading the Impossible level's source as the model fix.
4. **Templates (PortSwigger).** [Basic SSTI](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic), [code context](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context), [using documentation](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation) and [information disclosure via user-supplied objects](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects), for the identification and context reasoning of SSTI-4 and SSTI-6.
5. **XML (PortSwigger).** [Retrieve files](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files), [blind with out-of-band interaction](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction), [via parameter entities](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities), [XInclude](https://portswigger.net/web-security/xxe/lab-xinclude-attack) and [XXE via image upload](https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload).
6. **Prototype pollution (PortSwigger).** [Detecting server-side prototype pollution without polluted property reflection](https://portswigger.net/web-security/prototype-pollution/server-side/lab-detecting-server-side-prototype-pollution-without-polluted-property-reflection) first, because it is the probe style you use on client systems. Then [privilege escalation](https://portswigger.net/web-security/prototype-pollution/server-side/lab-privilege-escalation-via-server-side-prototype-pollution) and [flawed input filters](https://portswigger.net/web-security/prototype-pollution/server-side/lab-bypassing-flawed-input-filters-for-server-side-prototype-pollution).
7. **OWASP Juice Shop** ([companion guide: Injection](https://pwning.owasp-juice.shop/companion-guide/latest/part2/injection.html)). *Login Admin*, *Login Jim*, *Christmas Special*, *NoSQL Manipulation* and *NoSQL Exfiltration*. The XXE and SSTi challenges are "Danger Zone" and need a from-source local install.
8. **OWASP crAPI** ([challenges](https://github.com/OWASP/crAPI/blob/develop/docs/challenges.md)). Challenge 12 (NoSQL injection in the coupon check) and Challenge 13 (SQL injection in coupon redemption). **VAmPI** ([repository](https://github.com/erev0s/VAmPI)) is useful for practising sqlmap with a saved request and the conservative flags.
9. **The rest, locally.** LDAP and XPath have no Academy labs; use [OWASP Mutillidae II](https://github.com/webpwnized/mutillidae) or the build-your-own lab in the LDAP note. CRLF and logging: WebGoat's [log spoofing task](https://github.com/WebGoat/WebGoat/blob/main/src/main/resources/lessons/logging/documentation/logSpoofing_Task.adoc) and the local servers in the CRLF note. Finish by writing one vulnerable and one fixed endpoint per interpreter and running the static-analysis rules above against both.

## References

**OWASP**

- WSTG Injection chapter: [overview](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/), [WSTG-INJT-04 HTTP Parameter Pollution](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/04-HTTP_Parameter_Pollution), [WSTG-INJT-05 SQL Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection) (with the [NoSQL](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/05.6-NoSQL_Injection) and [ORM](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/05.7-ORM_Injection) sub-pages), [WSTG-INJT-06 LDAP Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/06-LDAP_Injection), [WSTG-INJT-07 XML Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/07-XML_Injection/), [WSTG-INJT-08 SSI Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/08-SSI_Injection), [WSTG-INJT-09 XPath Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/09-XPath_Injection), [WSTG-INJT-10 IMAP/SMTP Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/10-IMAP_SMTP_Injection), [WSTG-INJT-11 Code Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/11-Code_Injection), [WSTG-INJT-12 Command Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/12-Command_Injection), [WSTG-INJT-14 Incubated Vulnerability](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/14-Incubated_Vulnerability), [WSTG-INJT-15 HTTP Response Splitting](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/15-HTTP_Response_Splitting), [WSTG-INJT-18 Server-side Template Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/18-Server-side_Template_Injection), [WSTG-INJT-21 CSV Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/21-CSV_Injection), [WSTG-INJT-22 Prototype Pollution](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/22-Prototype_Pollution)
- ASVS 5.0: [V1 Encoding and Sanitization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md), [V15 Secure Coding and Architecture](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md), [V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)
- OWASP Top 10:2025: [A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/), [A02:2025 Security Misconfiguration](https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/), [A08:2025 Software or Data Integrity Failures](https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/), [A09:2025 Security Logging and Alerting Failures](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/)
- Cheat Sheets: [Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html), [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), [Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html), [NoSQL Security](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html), [OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html), [XML External Entity Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html), [LDAP Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html), [Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), [Prototype Pollution Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html), [Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)

**CWE**

- [CWE-74](https://cwe.mitre.org/data/definitions/74.html) (the injection class; mapping Discouraged by MITRE), [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CWE-564](https://cwe.mitre.org/data/definitions/564.html), [CWE-943](https://cwe.mitre.org/data/definitions/943.html), [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CWE-88](https://cwe.mitre.org/data/definitions/88.html), [CWE-77](https://cwe.mitre.org/data/definitions/77.html), [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html), [CWE-94](https://cwe.mitre.org/data/definitions/94.html), [CWE-95](https://cwe.mitre.org/data/definitions/95.html), [CWE-917](https://cwe.mitre.org/data/definitions/917.html), [CWE-97](https://cwe.mitre.org/data/definitions/97.html), [CWE-611](https://cwe.mitre.org/data/definitions/611.html), [CWE-776](https://cwe.mitre.org/data/definitions/776.html), [CWE-91](https://cwe.mitre.org/data/definitions/91.html), [CWE-90](https://cwe.mitre.org/data/definitions/90.html), [CWE-643](https://cwe.mitre.org/data/definitions/643.html), [CWE-652](https://cwe.mitre.org/data/definitions/652.html), [CWE-113](https://cwe.mitre.org/data/definitions/113.html), [CWE-93](https://cwe.mitre.org/data/definitions/93.html), [CWE-117](https://cwe.mitre.org/data/definitions/117.html), [CWE-1236](https://cwe.mitre.org/data/definitions/1236.html), [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html)

**Scoring**

- FIRST: [CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) (Scope and the security-authority definition), [CVSS v3.1 calculator](https://www.first.org/cvss/calculator/3.1)

**PortSwigger**

- Web Security Academy topics: [SQL injection](https://portswigger.net/web-security/sql-injection) and its [cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet), [NoSQL injection](https://portswigger.net/web-security/nosql-injection), [OS command injection](https://portswigger.net/web-security/os-command-injection), [Server-side template injection](https://portswigger.net/web-security/server-side-template-injection), [XXE](https://portswigger.net/web-security/xxe), [Prototype pollution](https://portswigger.net/web-security/prototype-pollution)
- Research: [Server-side template injection](https://portswigger.net/research/server-side-template-injection), [Server-side prototype pollution](https://portswigger.net/research/server-side-prototype-pollution), [Backslash powered scanning](https://portswigger.net/research/backslash-powered-scanning-hunting-unknown-vulnerability-classes)

**Tools**

- Burp extensions: [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943), [Backslash Powered Scanner](https://portswigger.net/bappstore/9cff8c55432a45808432e26dbb2b41d8), [Content Type Converter](https://portswigger.net/bappstore/db57ecbe2cb7446292a94aa6181c9278), [InQL](https://portswigger.net/bappstore/296e9a0730384be4b2fffef7b4e19b1f), [NoSQLi Scanner](https://portswigger.net/bappstore/605a859f0a814f0cbbdce92bc64233b4), [Server-Side Prototype Pollution Scanner](https://portswigger.net/bappstore/c1d4bd60626d4178a54d36ee802cf7e8)
- [interactsh](https://github.com/projectdiscovery/interactsh) (self-hosted out-of-band listener), [sqlmap](https://github.com/sqlmapproject/sqlmap) (confirmation only, with the settings in the SQL note)

**Labs**

- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), [OWASP crAPI](https://github.com/OWASP/crAPI), [VAmPI](https://github.com/erev0s/VAmPI), [DVWA](https://github.com/digininja/DVWA), [OWASP Mutillidae II](https://github.com/webpwnized/mutillidae)

**Elsewhere on this site**

- [Web Application Security testing guide](/web/web-application-security-testing-guide/) (rules of engagement, set-up, severity scale, reporting)
- [Access Control Testing Guide](/web/web-access-control-testing-guide/) and [Mass assignment and BOPLA](/web/web-mass-assignment-bopla/), for the property-level side of prototype pollution and parameter binding
- [Bug Bounty Writeups](/bug-bounty-writeups/)
