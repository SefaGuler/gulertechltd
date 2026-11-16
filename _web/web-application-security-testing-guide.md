---
title: "Web Application Security Testing Guide"
date: 2026-11-15 18:30:00 +0000
subcategory: methodology
summary: "Hub for our web application series: rules of engagement, set-up, a WSTG-based method, series map, high-value checks, severity and reporting."
refs: [OWASP WSTG, OWASP ASVS 5.0, "OWASP Top 10:2025", OWASP API Security Top 10 2023]
tags: [web, methodology, wstg, asvs, pentest]
---

This is the hub of our web application security series. It is written for people who test web applications and APIs for a living, on client engagements or on bug bounty programmes, and for the AppSec engineers and developers who want to run the same checks before somebody else does. The series is built on two OWASP projects. The [Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) (WSTG) tells you *what to test* and gives every test an ID such as `WSTG-ATHZ-04`. The [Application Security Verification Standard 5.0](https://owasp.org/www-project-application-security-verification-standard/) (ASVS) tells you *what good looks like*, with requirement IDs such as `v5.0.0-8.2.2` and a level (L1, L2 or L3). Each finding is also mapped to the OWASP Top 10:2025, the OWASP API Security Top 10 2023, CWE and an example CVSS vector.

The series is grouped into ten subcategories. Access Control is published first. Every note in it has the same shape: how the mechanism works, what goes wrong, numbered tests with raw HTTP and curl, fixes in Node.js/Express, Django, Spring Security and Laravel, practice labs, public real-world cases, a rating table and a mapping table. Each note has 8–12 tests. The test IDs look like `GT-WEB-<AREA>-n` (for example `GT-WEB-IDOR-1`) and they are stable: an ID always means the same check, so you can cite it in a report and track it from one engagement to the next. This page covers how the pieces fit together and how we run a web assessment from start to finish.

## Contents

- [Rules of engagement](#rules-of-engagement)
  - [Written scope](#written-scope)
  - [Bug bounty programmes](#bug-bounty-programmes)
  - [Accounts and tenants you control](#accounts-and-tenants-you-control)
  - [Stop on real data](#stop-on-real-data)
  - [Rate limits and non-destructive proofs](#rate-limits-and-non-destructive-proofs)
  - [Production or staging](#production-or-staging)
  - [Data handling and evidence redaction](#data-handling-and-evidence-redaction)
- [Setting up](#setting-up)
  - [The role matrix](#the-role-matrix)
  - [Burp Suite project](#burp-suite-project)
  - [One browser profile per user](#one-browser-profile-per-user)
  - [Burp extensions we use](#burp-extensions-we-use)
  - [ZAP as a free alternative](#zap-as-a-free-alternative)
  - [Command-line tools](#command-line-tools)
  - [API clients](#api-clients)
- [Methodology](#methodology)
  - [Keeping coverage with the WSTG checklist](#keeping-coverage-with-the-wstg-checklist)
  - [Habits that matter more than tools](#habits-that-matter-more-than-tools)
- [Series map](#series-map)
- [Where to start: high-value checks](#where-to-start-high-value-checks)
- [Rating findings](#rating-findings)
  - [Our severity scale](#our-severity-scale)
  - [CVSS v3.1 and v4.0](#cvss-v31-and-v40)
  - [How bug bounty platforms rate](#how-bug-bounty-platforms-rate)
  - [Worked examples](#worked-examples)
- [Writing the finding](#writing-the-finding)
- [Framework mapping](#framework-mapping)
- [Practice labs](#practice-labs)
- [References](#references)

## Rules of engagement

Everything in this series assumes one of three situations: an **authorised engagement** with a written scope, a **bug bounty programme** whose rules allow the test, or a **lab** you run yourself. None of the techniques here are acceptable against a system you have not been given permission to test. In the UK, unauthorised access to computer material is an offence under the [Computer Misuse Act 1990](https://www.legislation.gov.uk/ukpga/1990/18/contents); good intentions are not a defence, and written permission is what makes the work lawful. (This is not legal advice. If in doubt, ask the client's legal contact before you start, not after.)

### Written scope

Before the first request, the scope document should answer these questions. If it does not, ask.

- **Targets.** Exact hostnames, base URLs and API versions in scope (`app.example.com`, `api.example.com/v2/`, `admin.example.com`). Wildcards such as `*.example.com` need a clear statement of what they include.
- **Environments.** Production, staging, a dedicated test tenant, or a mix. Which environment holds real customer data.
- **Accounts.** Which test accounts the client provides, for which roles, and whether you may self-register more.
- **Excluded functions.** Typical exclusions are payments, anything that sends email or SMS to real people at volume, data exports of real records, account deletion and third-party integrations.
- **Third parties.** Identity providers, payment gateways, CDNs, analytics and support widgets belong to someone else. They are out of scope unless that party's own policy or a written agreement allows testing. You may *observe* how the client uses them (for example, which OAuth scopes the app requests). You may not attack them.
- **Testing windows and source IPs.** When you may test and from where. Give the client your egress IPs so their monitoring can tell your traffic apart. Do not ask them to allow-list you past the WAF unless the goal is to test the application behind it; if you are allow-listed, say so in the report.
- **Contacts.** A technical contact, an escalation contact for critical findings, and an agreed "stop" signal if the client sees impact on availability.

### Bug bounty programmes

On a bug bounty programme the programme policy *is* your scope document, and it is stricter than most people read it.

- Test only the assets listed as in scope. A host that belongs to the same company but is not listed is out of scope, however tempting it looks.
- Read the prohibited activities. Most programmes ban denial of service, social engineering, physical attacks, spam, and testing that degrades the service for other users. Many restrict or ban automated scanning.
- Follow the identification rules. Many programmes ask for a custom request header or a platform email alias (for example a `@wearehackerone.com` or `@bugcrowdninja.com` address) on test accounts. Add the header with a Burp match-and-replace rule so you never forget it.
- Read the safe harbour wording and the disclosure rules. Report only through the programme, and do not publish anything until the programme allows it.
- A vulnerability disclosure policy (VDP) or a [security.txt](https://www.rfc-editor.org/rfc/rfc9116) file tells you where to *report*. It does not automatically authorise *testing*. Read its terms before you send anything.

### Accounts and tenants you control

Authorisation testing needs at least two users per role, a higher role where the client provides one, and two tenants or organisations for multi-tenant products. We list the full set under [The role matrix](#the-role-matrix). The rule that keeps you safe: **a cross-account proof always targets an object your own second account created**. To prove user B can read user A's invoice, you create the invoice as A and read it as B. You never prove the bug against a real customer's object, even when an ID from a real customer is sitting in front of you.

Seed your test data so it is obviously fake and easy to find: names such as `GT Test A1`, invoice references such as `GT-A1-0001`, a marker string such as `gt-marker-7f3a` in free-text fields. That makes your evidence unambiguous and makes clean-up easy for the client.

### Stop on real data

If a test unexpectedly returns a real third party's data, **stop**. Keep only the minimum evidence needed to prove the issue (one response, with the personal data redacted before it is saved anywhere). Do not download more, do not page through results and do not retain the data. Report it to the client's escalation contact, or to the programme, straight away, even if you are in the middle of a test window. A broken access control that exposes real records is an incident for the client, not just a finding.

### Rate limits and non-destructive proofs

- **No mass enumeration or scraping.** Iterating identifiers with Burp Intruder, ffuf or a script is limited to identifiers you created, a small bounded range agreed with the client, or a lab. Proving that IDs are sequential needs two or three requests, not ten thousand.
- **Keep the rate low.** Our default for anything automated is a single thread and a few requests per second unless the client agrees otherwise. Use a Burp Intruder resource pool with one concurrent request and a delay, `ffuf -rate`, or `nuclei -rl`. Back off as soon as you see `429`, rising latency or `5xx` responses.
- **Do not brute-force production logins.** Test lockout and throttling against your own account with a small, agreed number of attempts.
- **Read before write.** Prove access with a read first. If a write proof is needed, change a harmless field on your own object (a display name, a marker string) before you ever consider a delete.
- **State-changing proofs are for own test objects only.** Update, delete, role change, invitation and transfer proofs target objects and accounts you control. The notes label these steps "**own test objects only**".
- **Payloads must not reach other users.** Stored cross-site scripting proofs belong in your own tenant or a private field, use a harmless marker (`console.log` or a unique string rather than a pop-up on a shared page), and are removed once evidence is captured.
- **Denial of service is out of scope** unless a separate, explicit agreement says otherwise. This includes resource-exhaustion proofs against GraphQL, regular expressions and file processing: show that the limit is missing without exhausting the resource.

### Production or staging

Staging is safer, and it is often different. It may run another build, have debug settings turned on, sit behind a different WAF or none, carry different feature flags and hold synthetic data. Ask the client how closely staging matches production, and write down what you were told.

- On **production**, keep to the non-destructive rules above, avoid payloads that write to the database (no injection tests that insert or update rows), and agree in advance which tools may run at all.
- On **staging**, you can usually go further (sqlmap, heavier fuzzing, upload tests), but report the environment in every finding. A finding that exists only because staging has debug mode on is a configuration finding about staging, not proof that production is vulnerable.
- When an issue depends on configuration (CORS policy, cookie flags, error handling, CSP), confirm it against production with a single read-only request if the scope allows. Otherwise state clearly that it was only observed on staging.

### Data handling and evidence redaction

- **Collect the minimum.** One request and response per finding, plus whatever is needed to reproduce. No bulk exports.
- **Redact before you save.** Mask session cookies, bearer tokens, API keys, passwords and one-time codes in every screenshot, report and ticket. Keep the first and last few characters if you need to show two tokens are different (`sess_7Q…k2`). Mask names, email addresses, phone numbers, addresses and payment data belonging to anyone other than your test accounts.
- **Sanitise HAR files and Burp project files before sharing.** A HAR contains every cookie and `Authorization` header the browser sent. A Burp project contains the whole of your traffic. Share extracts, not the raw file.
- **Keep client data off third-party services.** Do not paste tokens, responses or source code into online decoders, paste sites or public AI tools. Burp Collaborator's public server is a third-party service too: if the client does not want out-of-band interactions leaving their environment, use a private Collaborator server or leave those tests out.
- **Store and delete.** Keep engagement data on encrypted storage for as long as the contract says and no longer. Rotate or ask the client to disable the test accounts at the end.

## Setting up

### The role matrix

Most serious web findings are authorisation findings, and you cannot test authorisation with one account. Ask for, or create, this set before the test starts.

| Label | Role | Tenant / organisation | Used for |
|---|---|---|---|
| A1 | Standard user | Tenant A | Your primary user; owns the test objects |
| A2 | Standard user | Tenant A | Horizontal checks inside one tenant (A2 must not see A1's private objects) |
| AM | Tenant admin / manager | Tenant A | Vertical checks: what admin can do that A1 must not |
| AR | Read-only or restricted role (viewer, billing, support) | Tenant A | Checks that "read-only" really means read-only |
| B1 | Standard user | Tenant B | Cross-tenant checks |
| BM | Tenant admin | Tenant B | Cross-tenant admin checks (an admin of B must not administer A) |
| PS | Platform staff role, if the client provides one | — | Back-office and support tooling |
| U | Unauthenticated | — | Every request replayed with no session at all |

For each role, write down what it *should* be able to do. Ask the client for a permission matrix; if there is none, build one from the user interface, the documentation and the API specification, and get the client to confirm it. A finding is a difference between what the matrix says and what the server does, so the matrix is the most important artefact of the set-up phase. WSTG covers this preparation under role definitions (`WSTG-IDNT-01`), and ASVS 5.0 expects the rules to be documented (`v5.0.0-8.1.1`, L1).

Keep one line per account in your notes: label, login, role, tenant, the IDs of the test objects it owns, and how it authenticates (cookie, bearer token, API key). You will refer to this table hundreds of times.

### Burp Suite project

We use Burp Suite Professional; Community Edition covers most of the manual work. For every engagement:

1. **One project per engagement**, saved to disk, named with the engagement reference and the date. Never mix two clients in one project.
2. **Target scope.** Add the in-scope hosts under Target > Scope. Use advanced scope control (regular expressions) when the scope is "these hosts but not these paths", and add explicit exclusions for logout endpoints and out-of-scope third parties. Filter Proxy history to in-scope items, and set the Proxy history logging and interception settings so out-of-scope traffic is not recorded or intercepted.
3. **Upstream proxy.** If you must reach the target through a client VPN, a jump host or a corporate egress proxy, set it under Settings > Network > Connections > Upstream proxy servers. Rules are matched per destination host, so you can send only the client's hosts through the upstream proxy.
4. **Identification header.** Add a Proxy match-and-replace rule that inserts the header the programme or client asked for (for example `X-Pentest-Ref: GT-<engagement-ref>`). Check in Logger that requests from Repeater and Intruder carry it too; if not, add it there as well.
5. **Session handling rules.** In the Sessions settings (project settings), record a login macro for each account and add a rule that checks whether the session is still valid and runs the macro when it is not. This keeps long Intruder runs and Autorize sessions from silently testing as a logged-out user, which is one of the commonest sources of false negatives.
6. **Logger.** Burp's Logger records traffic from every tool, including requests changed by session handling rules and sent by extensions. Proxy history only shows browser traffic. Keep Logger on: it is your record of what you actually sent, when, and at what rate, which matters if the client ever asks.
7. **Resource pools.** Create a "gentle" Intruder resource pool (one concurrent request, a delay between requests) and make it the default for anything touching production.

### One browser profile per user

Testing several users in one browser leads to mixed cookies and confused evidence. Use one isolated profile or container per account:

- **Firefox Multi-Account Containers**: one container per account (A1, A2, B1, ...), each with its own cookies and storage, all proxied through Burp. Pair it with [PwnFox](https://github.com/yeswehack/PwnFox), which tags each container's requests so Burp highlights them in a different colour.
- **Separate Chrome or Chromium profiles**, each pointed at Burp, or Burp's built-in browser for one account and a second profile for the other.
- A **private window** for the unauthenticated user.

Label everything: name the containers after the matrix labels and give each a colour, so a screenshot shows at a glance which user made the request.

### Burp extensions we use

All of these are in the BApp Store. Install only what you need for the test in hand; extensions add memory and processing overhead.

| Extension | What it does | Where we use it |
|---|---|---|
| [Autorize](https://github.com/PortSwigger/autorize) | You browse as a higher-privileged user; it replays every request with a lower-privileged session and with no session, and marks each as bypassed, enforced or unclear | First pass on every Access Control note |
| [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix) | Define users, roles and requests, then run the whole matrix and see which role got what; handles CSRF tokens and chained values | Repeatable vertical and horizontal checks, retests |
| [Auth Analyzer](https://github.com/PortSwigger/auth-analyzer) | Runs several sessions in parallel as you browse, swapping session tokens and chosen parameters per session and comparing responses | Multi-tenant and multi-role testing |
| [Param Miner](https://github.com/PortSwigger/param-miner) | Guesses hidden parameters and headers; also used for cache-poisoning research | Hidden fields, mass assignment, HTTP and infrastructure |
| [InQL](https://github.com/doyensec/inql) | GraphQL: fetches the schema, generates queries and mutations, helps with batching and field-level checks | GraphQL APIs |
| [Logger++](https://github.com/nccgroup/LoggerPlusPlus) | Logging with filter expressions, colour rules and export | Finding patterns across thousands of requests |
| [JWT Editor](https://github.com/PortSwigger/jwt-editor) | Decodes, edits and re-signs JSON Web Tokens, and manages test keys | Session and authentication notes |

Treat their output as leads. Autorize marks a request "bypassed" when the responses look alike, and two responses can look alike for innocent reasons (both users can see the object by design, or both received an error page with a `200` status). Every lead is confirmed by hand in Repeater before it becomes a finding.

A small helper is sometimes quicker than an extension. This script replays one request as two of your accounts and compares the bodies. It is for your own test objects only.

```bash
#!/usr/bin/env bash
# compare-sessions.sh: replay one GET as users A1 and B1 and diff the JSON bodies.
# Usage: SESSION_A1=<SESSION_USER_A> SESSION_B1=<SESSION_USER_B> ./compare-sessions.sh <url>
set -euo pipefail
url="$1"
for who in A1 B1; do
  var="SESSION_${who}"
  curl -s -o "resp_${who}.json" \
       -w "${who}: HTTP %{http_code}, %{size_download} bytes\n" \
       -H "Cookie: session=${!var}" \
       -H "X-Pentest-Ref: GT-<engagement-ref>" \
       "$url"
  sleep 1
done
if diff <(jq -S . resp_A1.json) <(jq -S . resp_B1.json) >/dev/null; then
  echo "Identical bodies: B1 may be reading A1's object. Confirm by hand."
else
  echo "Bodies differ: check whether B1 got an error, an empty object or its own data."
fi
```

### ZAP as a free alternative

[ZAP](https://www.zaproxy.org/) (Zed Attack Proxy, formerly OWASP ZAP, now maintained by the ZAP team with Checkmarx as sponsor) covers proxying, manual request editing, spidering and scanning at no cost. For authorisation work, its [Access Control Testing add-on](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/) uses ZAP contexts and users: you mark which URLs each user should be allowed or denied, and the add-on requests every URL as every user and reports where the rules were not followed. It needs more set-up than Autorize, but the access rules you define double as documentation of the permission matrix.

### Command-line tools

| Tool | What we use it for | Notes |
|---|---|---|
| curl + [jq](https://jqlang.org/) | Reproducing every finding outside Burp; the curl command goes in the report | Every note shows curl equivalents of the raw requests |
| [ffuf](https://github.com/ffuf/ffuf) | Content discovery and bounded fuzzing | Always with `-rate`; small, targeted wordlists in production |
| [Arjun](https://github.com/s0md3v/Arjun) | Hidden HTTP parameter discovery on a single endpoint | Low thread count; check `arjun -h` for the current delay and thread options |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Known-issue checks: exposed files, default panels, known CVEs in identified components | Pick templates for the stack you fingerprinted, exclude intrusive ones, set `-rl` |
| [sqlmap](https://github.com/sqlmapproject/sqlmap) | Confirming and characterising SQL injection you already found by hand | Only where the scope explicitly allows it, preferably on staging; covered in the Injection note |

Two examples at production-safe settings:

```bash
# Content discovery: five requests a second, show interesting status codes only.
ffuf -u https://app.example.com/FUZZ -w small-wordlist.txt -rate 5 \
     -mc 200,204,301,302,307,401,403 \
     -H "X-Pentest-Ref: GT-<engagement-ref>"

# Known-issue checks: exposure and misconfiguration templates, no intrusive or DoS templates.
nuclei -u https://app.example.com -tags exposure,misconfig -etags intrusive,dos -rl 5 -c 2 \
       -H "X-Pentest-Ref: GT-<engagement-ref>"
```

Scanner output is a list of leads. Nuclei matches on signatures; a match is a reason to look, not a finding, until you have confirmed it by hand and understood the impact.

### API clients

APIs are easier to test from a collection than from the user interface, because you can reach endpoints the front end never calls.

- Import the client's OpenAPI or Postman collection into [Postman](https://www.postman.com/) or [Bruno](https://www.usebruno.com/). Bruno stores collections as plain files, which makes them easy to keep in the engagement folder and share with the client.
- Point the client's HTTP proxy at Burp (`127.0.0.1:8080`) and trust Burp's CA certificate, so every request shows up in Proxy history and Logger.
- Keep one environment per account (A1, B1, AM, ...) holding only that account's token, so swapping identity is a single switch rather than a copy-and-paste.
- Compare the specification with the traffic you see. Endpoints in the specification that the front end never calls, and endpoints the front end calls that are not in the specification, are both worth a closer look.

## Methodology

We run web assessments in phases that follow the WSTG chapters. The phases overlap in practice, but the order matters: the mapping and identity work early on tells you where the later phases should go deep.

| Phase | Goal | WSTG chapter | Series notes |
|---|---|---|---|
| 1. Scope and preparation | Rules of engagement, accounts, role matrix, tooling | [The Testing Framework](https://wstg.owasp.org/latest/3-The_OWASP_Testing_Framework/) | This page |
| 2. Recon and mapping | Hosts, technologies, entry points, every route and parameter, API specifications, roles | [Information Gathering](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/) (`WSTG-INFO`), [API Reconnaissance](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/) (`WSTG-APIT-01`) | Recon & Configuration, API Security (coming next) |
| 3. Configuration and deployment | Platform settings, admin interfaces, HTTP methods, security headers, CSP, cloud storage, subdomain takeover, path confusion | [Configuration and Deployment Management](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/) (`WSTG-CONF`) | Recon & Configuration; HTTP & Infrastructure (coming next) |
| 4. Identity and authentication | Registration, provisioning, enumeration, login, lockout, password reset, MFA, SAML, OAuth | [Identity Management](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/03-Identity_Management/) (`WSTG-IDNT`), [Authentication](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/04-Authentication/) (`WSTG-ATHN`), `WSTG-ATHZ-05` | Authentication (coming next) |
| 5. Authorisation | Object, function and field-level access, tenant isolation, revocation, bypasses | [Authorization](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/) (`WSTG-ATHZ-02` to `-04`), `WSTG-APIT-02` to `-04`, parts of `WSTG-BUSL` | [Access Control](/web/web-access-control-testing-guide/) |
| 6. Session management | Session tokens, cookie attributes, fixation, CSRF, logout, timeouts, JWTs, concurrent sessions | [Session Management](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/06-Session_Management/) (`WSTG-SESS`) | Session Management (coming next) |
| 7. Input handling | Injection of every kind, request smuggling, Host header, SSTI, SSRF, mass assignment, deserialisation | [Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/) (`WSTG-INJT`), `WSTG-ATHZ-01` | Injection; Server-Side Request & Files; HTTP & Infrastructure (coming next) |
| 8. Error handling and cryptography | Stack traces and verbose errors, TLS, padding oracles, weak primitives, sensitive data over plain channels | [Error Handling](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/08-Error_Handling/) (`WSTG-ERRH`), [Weak Cryptography](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/09-Weak_Cryptography/) (`WSTG-CRYP`) | Recon & Configuration (coming next) |
| 9. Business logic | Workflow bypass, limits, timing, integrity, payments, uploads | [Business Logic](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/10-Business_Logic/) (`WSTG-BUSL`) | Business Logic; Server-Side Request & Files (coming next) |
| 10. Client-side | DOM XSS, redirects, CORS, clickjacking, web messaging, browser storage, WebSockets, DOM clobbering | [Client-side](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/) (`WSTG-CLNT`) | Client-Side (coming next) |
| 11. API | REST, GraphQL and gRPC specifics: object and function-level authorisation, data exposure, schema exposure, batching | [API Testing](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/) (`WSTG-APIT`, including `WSTG-APIT-99` for GraphQL) | API Security (coming next); BOLA and BFLA in [Access Control](/web/web-access-control-testing-guide/) |
| 12. Reporting and retest | Findings with evidence, severity, fixes; retest of fixes | [Reporting](https://wstg.owasp.org/latest/5-Reporting/) | [Rating findings](#rating-findings), [Writing the finding](#writing-the-finding) |

A few WSTG tests sit in a different place in our series than in WSTG, because that is where a tester meets them in practice. Directory traversal is `WSTG-ATHZ-01` in WSTG but lives in our Server-Side Request & Files note. HTTP verb tampering (`WSTG-INJT-03`) is covered as an authorisation bypass in the [bypass techniques note](/web/web-authorization-bypass-techniques/). Mass assignment (`WSTG-INJT-20`) is an authorisation problem first, so it is in the [mass assignment and BOPLA note](/web/web-mass-assignment-bopla/). OAuth weaknesses (`WSTG-ATHZ-05`) go to the Authentication note.

Two points about WSTG IDs. First, they are taken from the current WSTG development tree (the version 5.0 work) at the time of writing; the last stable release is [4.2](https://wstg.owasp.org/v4.2/), and some IDs differ between the two. For example, 4.2 numbered the input tests `WSTG-INPV-nn`, while the current tree calls that chapter Injection and uses `WSTG-INJT-nn`. WSTG itself recommends a versioned form such as `WSTG-v42-INFO-02` when you need an ID that will never move, so put the version in your report. Second, WebAssembly testing (`WSTG-WASM`) is a new chapter with a single reconnaissance test so far; we cover it with recon when we meet it.

### Keeping coverage with the WSTG checklist

The WSTG repository ships a testing checklist in its [`checklists` folder](https://github.com/OWASP/wstg/tree/master/checklists): `checklist.md`, `checklist.json` and an Excel workbook, generated from the guide by the project's build workflow (the folder also keeps the old 4.2 workbook). Each row is a WSTG ID and test name with Status and Notes columns.

We keep a copy per engagement and add three columns of our own:

| WSTG ID | Test | Status | Our test IDs | Evidence | Notes |
|---|---|---|---|---|---|
| WSTG-ATHZ-04 | Insecure Direct Object References | Fail | GT-WEB-IDOR-1, GT-WEB-IDOR-3 | F-07 | Invoices and attachments; search endpoint passes |
| WSTG-SESS-02 | Cookies Attributes | Pass | — | Screenshot 14 | `Secure`, `HttpOnly`, `SameSite=Lax` on session cookie |
| WSTG-CONF-11 | Cloud Storage | N/A | — | — | No client-side storage URLs observed |

Every row ends as Pass, Fail or N/A with a reason. "Not tested" is allowed only when the scope excluded it, and then the report says so. The checklist is what turns "we found these bugs" into "we tested these things and found these bugs", which is what a client actually pays for.

### Habits that matter more than tools

- **Map before you attack.** Walk every feature as every role with Burp recording, and build a route list (method, path, parameters, who should be allowed). Most missed findings are endpoints nobody looked at, not payloads nobody tried.
- **Compare, do not guess.** Authorisation bugs show up as the *same* response for two users who should get different ones. Keep requests for A1 and B1 side by side in Repeater or Comparer.
- **Follow the identifier.** Note where each ID is issued, where else it appears (URLs, exports, notifications, WebSocket messages, other users' responses) and which endpoints accept it. A UUID that leaks in a shared-document response is no longer hard to obtain.
- **Test every door to the same room.** The web UI, the mobile API, the public API, GraphQL, the export job and the webhook can all reach the same data. A fix on one route often leaves another open.
- **Chain findings, then rate the chain.** A self-XSS is Low on its own; with a login CSRF it becomes account compromise. An open redirect is Low; in an OAuth `redirect_uri` it can leak authorisation codes. Draw the path and rate what an attacker can actually achieve.
- **Write it up while it is fresh.** Capture the request, the response and the account labels the moment you confirm a finding. Reconstructing evidence a week later is how mistakes get into reports.

## Series map

| Subcategory | Status | Main WSTG chapters | What it covers |
|---|---|---|---|
| [Access Control](/web/web-access-control-testing-guide/) | Published | `WSTG-ATHZ-02` to `-04`, `WSTG-APIT-02` to `-04`, `WSTG-INJT-20`, parts of `WSTG-BUSL` | Hub plus six notes, listed below |
| [Injection](/web/web-injection-testing-guide/) | Published | `WSTG-INJT-05` to `-12`, `-14`, `-15`, `-18`, `-21`, `-22` | Hub plus eight notes, listed below (XSS is covered under Client-Side) |
| Client-Side | Coming next | `WSTG-CLNT` | DOM XSS, CORS, clickjacking, web messaging, browser storage, client-side redirects, CSS injection, DOM clobbering |
| Authentication | Coming next | `WSTG-IDNT`, `WSTG-ATHN`, `WSTG-ATHZ-05` | Registration, enumeration, lockout, password reset, MFA, SAML, OAuth and OIDC |
| Session Management | Coming next | `WSTG-SESS` | Session tokens, cookies, fixation, CSRF, logout, timeouts, JWTs, concurrent sessions |
| Server-Side Request & Files | Coming next | `WSTG-INJT-19`, `WSTG-INJT-23`, `WSTG-ATHZ-01`, `WSTG-BUSL-08`, `WSTG-BUSL-09` | SSRF, file uploads, path traversal and file inclusion, deserialisation |
| HTTP & Infrastructure | Coming next | `WSTG-INJT-16`, `WSTG-INJT-17`, `WSTG-CONF-13`, `WSTG-CLNT-10` | Request smuggling, cache poisoning and cache deception, Host header attacks, WebSockets |
| Business Logic | Coming next | `WSTG-BUSL` | Workflow bypass, limits and race conditions, integrity checks, payments |
| API Security | Coming next | `WSTG-APIT` | REST, GraphQL (`WSTG-APIT-99`) and gRPC: recon, data exposure, schema exposure, batching, resource limits |
| Recon & Configuration | Coming next | `WSTG-INFO`, `WSTG-CONF`, `WSTG-ERRH`, `WSTG-CRYP` | Mapping, fingerprinting, exposed files and panels, headers and CSP, TLS, error handling |

The Access Control subcategory:

| Note | Test IDs | What it covers |
|---|---|---|
| [Web Access Control Testing Guide](/web/web-access-control-testing-guide/) | — | The authorisation model, the role matrix, the session-swap workflow, and how the notes below fit together |
| [IDOR and BOLA](/web/web-idor-bola/) | `GT-WEB-IDOR-n` | Object-level authorisation: swapping identifiers between users, in paths, bodies, headers, batch and nested endpoints |
| [Vertical privilege escalation and BFLA](/web/web-vertical-privilege-escalation-bfla/) | `GT-WEB-PRIV-n` | Function-level authorisation: admin functions, hidden endpoints, role self-assignment |
| [Authorisation bypass techniques](/web/web-authorization-bypass-techniques/) | `GT-WEB-BYP-n` | Forced browsing, unauthenticated access, path normalisation and proxy mismatches, method tampering and override headers, header-based trust, client-side-only checks |
| [Mass assignment and BOPLA](/web/web-mass-assignment-bopla/) | `GT-WEB-BOPLA-n` | Writable fields that should not be, excessive data exposure, field-level authorisation, GraphQL field access |
| [Multi-tenant isolation](/web/web-multi-tenant-isolation/) | `GT-WEB-TEN-n` | Cross-tenant access in SaaS: tenant identifiers, invitations, search, shared infrastructure |
| [Revocation, sharing and asynchronous access](/web/web-access-control-revocation-sharing-async/) | `GT-WEB-CTX-n` | Stale permissions after role changes, share links, exports and downloads, background jobs, webhooks, real-time channels, confused deputies between services |

The Injection subcategory:

| Note | Test IDs | What it covers |
|---|---|---|
| [Injection Testing Guide](/web/web-injection-testing-guide/) | — | The interpreter and context model, the safe-proof ladder, the test plan and how the notes below fit together |
| [SQL injection](/web/web-sql-injection/) | `GT-WEB-SQLI-n` | Error, boolean, time and out-of-band detection, ORDER BY and identifier injection, second-order injection, ORM escape hatches |
| [NoSQL injection](/web/web-nosql-injection/) | `GT-WEB-NOSQL-n` | MongoDB operator injection, type confusion, server-side JavaScript, Elasticsearch, DynamoDB and Redis |
| [OS command and argument injection](/web/web-os-command-injection/) | `GT-WEB-CMD-n` | Features that shell out, blind confirmation with bounded delays and DNS, option injection without a shell |
| [Server-side template and code injection](/web/web-server-side-template-injection/) | `GT-WEB-SSTI-n` | Template engines, expression languages, `eval`, server-side includes and lookup strings |
| [XXE and XML injection](/web/web-xxe-xml-injection/) | `GT-WEB-XXE-n` | External entities, XInclude, XSLT, XML inside uploads, parser hardening per platform |
| [LDAP and XPath injection](/web/web-ldap-xpath-injection/) | `GT-WEB-LDAP-n` | Directory search filters, DN injection, login filters, XPath and XQuery lookups |
| [CRLF, email header, log and CSV injection](/web/web-crlf-header-log-csv-injection/) | `GT-WEB-CRLF-n` | Response header injection, mail headers and recipients, log forging, formula injection in exports |
| [Server-side prototype pollution](/web/web-server-side-prototype-pollution/) | `GT-WEB-PP-n` | Unsafe merges and path setters in Node.js, non-destructive detection, gadgets and fixes |

Each note has 8–12 tests. Later subcategories get their own `AREA` codes when they are published.

Our other series use the same structure. The mobile series follows OWASP MASVS; the [MASVS-AUTH hub](/mobile/masvs-auth-authentication-guide/) is a good entry point, and much of what it says about back-end authorisation applies to the APIs behind web front ends too. The [AWS series hub](/cloud/aws-security-testing-guide/) covers the cloud accounts many of these applications run in, which is where an SSRF finding goes next. Public writeups are collected on the [Bug Bounty Writeups](/bug-bounty-writeups/) page (mobile writeups at the time of writing; web writeups will be added as the series grows).

## Where to start: high-value checks

If you have a day rather than two weeks, these checks find most of the serious issues we see. Published notes are linked; the others are in plain text until their notes are out.

1. **Swap object IDs between two users** on every endpoint that reads or changes an object, including attachments, exports and nested resources. [IDOR and BOLA](/web/web-idor-bola/)
2. **Replay admin requests with a standard user's session**, including requests the user interface never shows to that user. [Vertical privilege escalation and BFLA](/web/web-vertical-privilege-escalation-bfla/)
3. **Drop the session entirely** on every API route and see which ones still answer. [Authorisation bypass techniques](/web/web-authorization-bypass-techniques/)
4. **Try path, method and header variants on blocked routes**: trailing slashes, case changes, encoded characters, method override headers. [Authorisation bypass techniques](/web/web-authorization-bypass-techniques/)
5. **Add `role`, `owner`, `tenant` and `isAdmin`-style fields** to create and update bodies, and read responses for fields the user should not see. [Mass assignment and BOPLA](/web/web-mass-assignment-bopla/)
6. **Use tenant A's identifiers with tenant B's session**, including in search, invitations and reporting. [Multi-tenant isolation](/web/web-multi-tenant-isolation/)
7. **Remove a user or downgrade a role, then reuse the old session, token, share link and export URL.** [Revocation, sharing and asynchronous access](/web/web-access-control-revocation-sharing-async/)
8. **Password reset and email change**: token leakage, tokens tied to the wrong account, reset links built from the `Host` header, email change without re-authentication. Authentication (coming next)
9. **MFA on every login path**: the web form, the API, SSO, the mobile endpoint, the "remember this device" cookie. Authentication (coming next)
10. **Session lifecycle**: cookie attributes, a new session on login, logout that actually ends the session on the server, JWT signature and expiry checks. Session Management (coming next)
11. **Stored and DOM XSS** in rich text, Markdown, file names, display names and anything rendered in an admin panel. Client-Side (coming next)
12. **SQL and NoSQL injection in search, sort and filter parameters**, which are often built by hand even in ORM-based applications. [SQL injection](/web/web-sql-injection/) and [NoSQL injection](/web/web-nosql-injection/)
13. **SSRF wherever the server fetches a URL**: webhooks, "import from URL", PDF and image renderers, link previews. Server-Side Request & Files (coming next)
14. **File uploads**: what types are accepted, where files are stored, and what `Content-Type` they are served back with. Server-Side Request & Files (coming next)
15. **CORS that reflects any origin with credentials**, and cross-origin reads of authenticated JSON. Client-Side (coming next)
16. **Single-use and limited actions under concurrency**: coupons, transfers, invitations and votes sent in parallel. Business Logic (coming next)
17. **Exposed debug pages, admin consoles, `.git` folders, backups and verbose errors.** Recon & Configuration (coming next)

## Rating findings

The series uses one rating model, so findings from different notes sit in the same report without contradicting each other.

### Our severity scale

| Severity | Meaning | Typical examples |
|---|---|---|
| Critical | Direct compromise of many users, the whole tenant base or the platform, with few or no preconditions | Unauthenticated access to admin functions or to all users' sensitive data; any user can take over any account; remote code execution |
| High | Serious compromise with a realistic precondition such as a registered account | Any user reads or changes other users' sensitive objects at scale; cross-tenant read in SaaS; stored XSS that runs in an admin's session |
| Medium | Real impact, limited by scale, data sensitivity or a hard precondition | IDOR with non-guessable identifiers that are not exposed elsewhere; CSRF on a state-changing but low-value action; SSRF limited to blind requests to internal hosts |
| Low | Weakness with little direct impact, or one that needs an unlikely chain | Verbose errors revealing framework versions; missing rate limit on a non-sensitive function; self-XSS |
| Info | Hardening advice or defence in depth, no reachable vulnerability | A hidden admin menu item with server-side checks in place; missing headers with no exploitable effect |

We rate on **impact × likelihood**, and we make both halves explicit in the finding:

- **Impact**: what the attacker gains (read, modify or delete other users' data, act as another user, use admin functions, break out of a tenant, take over accounts, run code), the sensitivity of the data (personal, financial, health, credentials) and the scale (one record, one tenant, everyone).
- **Likelihood**: the precondition (unauthenticated, any registered user, a specific role, an insider), how the attacker obtains what they need (a sequential ID, an ID that leaks in another response, a UUID that is not secret but not guessable either), whether user interaction is needed, and how much effort or luck the attack takes.

A UUID is not an access control. If the server does not check ownership, the bug is there, and the report says so plainly. What the UUID changes is likelihood: an attacker who cannot obtain other users' IDs has a much harder job, so the finding is usually Medium or Low until you find a place where those IDs leak. Then it moves up.

### CVSS v3.1 and v4.0

Every finding carries a CVSS vector so clients can feed it into their own tooling. We give a **CVSS v3.1** vector by default, because in our experience most clients' vulnerability management and most programmes still expect it, and add a **CVSS v4.0** vector when the client or programme uses v4.0. Always write the version in the vector string (`CVSS:3.1/...` or `CVSS:4.0/...`) so nobody mixes the two up.

What changed in [CVSS v4.0](https://www.first.org/cvss/v4.0/specification-document) (published by FIRST in November 2023), in the parts that matter for web findings:

- **Scope is gone.** v3.1's `S:U`/`S:C` is replaced by separate impact metrics for the vulnerable system (`VC`, `VI`, `VA`) and for subsequent systems (`SC`, `SI`, `SA`). A stored XSS that harms the victim's browser session, or an SSRF that reaches an internal service, is expressed through the subsequent-system metrics rather than a scope change.
- **Attack Requirements (`AT`)** is new. It covers conditions outside the attacker's control, such as winning a race or being in a position to intercept traffic. Attack Complexity (`AC`) now covers evading security controls and obtaining target-specific secrets, which is where a secret, non-guessable identifier fits.
- **User Interaction** has three values: None, Passive and Active.
- **Naming.** A score from base metrics alone is CVSS-B; with threat metrics CVSS-BT; with environmental metrics CVSS-BE; with both CVSS-BTE. Supplemental metrics add context without changing the score.

The [CVSS v4.0 user guide](https://www.first.org/cvss/v4.0/user-guide) is explicit that a base score measures severity, not risk, and should not be used on its own to assess risk. The same is true of v3.1. That is why our severity is not simply the CVSS band. The most common example in this series: an IDOR that lets any user read every other user's sensitive records scores `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 6.5, which is Medium in v3.1. The base metrics cannot express "every customer's record", so we rate it High and explain why in the finding. In v4.0 the same vector (`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`) scores 7.1, High. Report the vector honestly and put the business reasoning in the text, rather than inflating metrics to reach the severity you want.

### How bug bounty platforms rate

- **HackerOne** lets each programme choose how severity is set: a severity level picked directly, or a CVSS calculator. At the time of writing its documentation lists a custom CVSS 3.0 implementation and standard CVSS 3.1 and 4.0 implementations, and asset-level environmental settings can change the final score. See [HackerOne's severity documentation](https://docs.hackerone.com/en/articles/8495674-severity).
- **Bugcrowd** uses its [Vulnerability Rating Taxonomy](https://bugcrowd.com/vulnerability-rating-taxonomy) (VRT 1.19 at the time of writing): a baseline priority from P1 (critical) to P5 (informational) per vulnerability type. Some entries are marked "varies" because the impact depends on context; IDOR is the standard example and can land anywhere from P4 to P1. The [VRT repository](https://github.com/bugcrowd/vulnerability-rating-taxonomy) also publishes mappings to CVSS v3, CVSS v4 and CWE.
- **Programme policies override both.** Many programmes publish their own severity tables, out-of-scope finding types and impact requirements. Read them before you rate.

On a programme, the triager decides the final severity. You make your case with a clear statement of impact and a proof against your own accounts. On a client engagement, you decide the severity and own the reasoning.

### Worked examples

Scores below were calculated from the vectors with the FIRST formulas; check them in the [v3.1](https://www.first.org/cvss/calculator/3.1) and [v4.0](https://www.first.org/cvss/calculator/4.0) calculators if you reuse them.

| Finding | Our severity | CVSS v3.1 | CVSS v4.0 | Reasoning |
|---|---|---|---|---|
| Unauthenticated admin API lists and edits all users | Critical | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` (9.3) | No precondition; full read and write of every account |
| Any user reads and edits other users' invoices with sequential IDs | High | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1) | `AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` (8.6) | Any registered user, trivially enumerable, financial data at scale |
| Any user reads other users' sensitive records (read only) | High | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | `AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` (7.1) | We rate above the v3.1 band because the scale and sensitivity are not captured by base metrics; explained in the finding |
| Cross-tenant read and write in a SaaS product | High–Critical | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1) | `AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` (8.6) | Critical when any self-registered tenant can reach every other tenant |
| IDOR on UUIDs that are not exposed anywhere else | Medium | `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N` (5.3) | `AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` (6.0) | The missing check is real; obtaining a victim's ID is the hard part. Re-rate if the IDs leak |
| Stored XSS in a field other users view | Medium–High | `AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` (5.4) | `AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` (5.1) | High when it runs in an admin's session or leads to account takeover; rate the chain |
| SSRF that reaches cloud instance metadata credentials | High–Critical | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` (8.6) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N` (9.2) | Severity follows what the stolen role can do; see the [AWS series](/cloud/aws-security-testing-guide/) |
| Stack trace with framework versions on an error page | Low | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` (6.9) | Both calculators overstate this; we rate Low unless the trace leaks secrets or data |
| Admin menu hidden in the UI, server-side checks in place | Info | — | — | No reachable gap; note it only if the client asked for hardening advice |

Notice the last two rows with a vector: the calculators and our severity disagree in both directions. That is normal. The base score is an input to the rating, not the rating itself.

## Writing the finding

A finding has to let three different people do their jobs: a manager deciding priority, a developer fixing it, and a tester (possibly not you) retesting it. We use this template for every finding in the series.

```text
Title:          <weakness> in <feature> allows <attacker> to <impact>
                e.g. "Missing ownership check on invoice API lets any user read and edit other users' invoices"
ID / test:      F-07 / GT-WEB-IDOR-1 (WSTG-ATHZ-04, WSTG-APIT-02)
Severity:       High
CVSS:           CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N (8.1)
                CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N (8.6)
Environment:    Production, https://api.example.com, build/version if known, tested on <date>
Affected:       GET /api/v1/invoices/{id}
                PUT /api/v1/invoices/{id}
                GET /api/v1/invoices/{id}/pdf
Preconditions:  Any registered user. Invoice IDs are sequential integers.
Summary:        Two or three sentences: what is wrong, why it matters, who is affected.
Steps:          Numbered, with account labels (A1, B1), raw HTTP requests and curl equivalents.
Observed:       What the server returned, and what it should have returned.
Impact:         Business terms: whose data, how much, what an attacker can do with it.
Evidence:       Request/response pairs and screenshots, tokens and personal data redacted.
Remediation:    The fix at the right layer, plus defence in depth. Framework-specific where possible.
References:     WSTG, ASVS 5.0 (v5.0.0-8.2.2, L1), OWASP Top 10 (A01:2025), API Top 10 (API1:2023), CWE-639.
Retest:         Exact requests to replay, the expected result after the fix, and other routes to the same data.
```

The steps are the part most reports get wrong. Use your matrix labels, show the raw request, and say what each step proves. For the example above:

1. As **A1**, create an invoice. The response contains its ID, `10482`.
2. As **B1** (a different user with no relationship to A1), request A1's invoice:

```http
GET /api/v1/invoices/10482 HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_B1>
Accept: application/json
X-Pentest-Ref: GT-<engagement-ref>
```

3. The server returns A1's invoice instead of `403` or `404` (illustrative response, personal data redacted):

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id":10482,"owner_id":"usr_a1","customer_name":"GT Test A1","billing_address":"[REDACTED]","total":"120.00"}
```

4. The same request as curl, for the developer:

```bash
curl -s https://api.example.com/api/v1/invoices/10482 \
     -H "Authorization: Bearer <TOKEN_USER_B1>" \
     -H "Accept: application/json" | jq .
```

5. **Own test objects only:** as B1, change the `reference` field of A1's invoice to `gt-marker-7f3a` with `PUT /api/v1/invoices/10482`, then read it back as A1 to confirm the write. Restore the original value afterwards.

A correct server answers step 2 with `404 Not Found` (preferable, as it does not confirm the object exists) or `403 Forbidden`, and the response body contains none of A1's data.

Some rules for the rest of the template:

- **Impact in business terms.** "Any of the roughly N registered customers can read every other customer's invoices, including billing addresses" is useful. "Confidentiality is compromised" is not. Estimate scale from what you can see (ID ranges, counts in your own tenant) without enumerating real records.
- **Redact evidence** as described under [Data handling and evidence redaction](#data-handling-and-evidence-redaction). Redact *values*, not structure: the developer needs to see which fields came back.
- **Remediation at the right layer.** "Validate the ID" is not a fix. "Load the invoice with a query scoped to the caller's account (`WHERE id = ? AND account_id = ?`) and return 404 when nothing matches; enforce it in the shared data-access layer so every route inherits it" is. Each note's "Secure implementation" section gives the framework-specific version.
- **Retest notes.** List every route to the same data you found (UI, API, export, GraphQL), so the retest checks all of them, not just the one in the report.
- **Mark what you did not prove.** If you stopped at a read because a write proof was not allowed, say "write access was not tested at the client's request". Do not claim impact you have not shown.

## Framework mapping

Every test in the series carries several kinds of reference, and each note ends with a mapping table. They answer different questions, so a finding normally has all of them.

| Reference | Answers | Example | How we cite it |
|---|---|---|---|
| OWASP WSTG | How do I test this? | `WSTG-ATHZ-04` Insecure Direct Object References | Unversioned IDs from the current tree, with the version stated in reports |
| OWASP ASVS 5.0 | What requirement does the application fail? At which level? | `v5.0.0-8.2.2` (L1): data-specific access restricted to consumers with explicit permission | `v5.0.0-<chapter>.<section>.<requirement>` plus the level |
| OWASP Top 10:2025 | Which awareness category is this? | `A01:2025` Broken Access Control | One category per finding |
| OWASP API Security Top 10 2023 | Which API risk is this? | `API1:2023` Broken Object Level Authorization | For API findings |
| CWE | What is the underlying weakness? | `CWE-639` Authorization Bypass Through User-Controlled Key | The most specific CWE that fits |
| CVSS | How severe is it, in a portable format? | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | v3.1 by default, v4.0 on request |

**ASVS 5.0** was released on 30 May 2025. It has around 350 requirements in 17 chapters (V1 Encoding and Sanitization, V2 Validation and Business Logic, V3 Web Frontend Security, V4 API and Web Service, V5 File Handling, V6 Authentication, V7 Session Management, V8 Authorization, V9 Self-contained Tokens, V10 OAuth and OIDC, V11 Cryptography, V12 Secure Communication, V13 Configuration, V14 Data Protection, V15 Secure Coding and Architecture, V16 Security Logging and Error Handling, V17 WebRTC). The levels are cumulative. L1 is the minimum, around a fifth of the requirements, mostly first-line defences against common attacks. L2 adds about half of the requirements again and is what most applications should aim for. L3 adds the remaining defence-in-depth controls for the most sensitive applications. ASVS IDs changed completely between 4.0.3 and 5.0, which is why ASVS asks for the versioned form `v5.0.0-8.2.2`; an unversioned `8.2.2` from an old report may mean something else. Some ASVS requirements are documentation requirements (for example `v5.0.0-8.1.1`, L1: authorisation rules are documented), and they are verified by reviewing the documentation, not by a black-box test. A black-box pentest can show that an L1 requirement fails. It can rarely show that a whole level passes.

**OWASP Top 10:2025** is the current edition. A release candidate was published in November 2025, and the final edition followed (OWASP's site presents 2025 as the current edition at the time of writing). The categories are:

| ID | Category |
|---|---|
| A01:2025 | Broken Access Control |
| A02:2025 | Security Misconfiguration |
| A03:2025 | Software Supply Chain Failures |
| A04:2025 | Cryptographic Failures |
| A05:2025 | Injection |
| A06:2025 | Insecure Design |
| A07:2025 | Authentication Failures |
| A08:2025 | Software or Data Integrity Failures |
| A09:2025 | Security Logging and Alerting Failures |
| A10:2025 | Mishandling of Exceptional Conditions |

Two details matter for this series. SSRF no longer has its own category; CWE-918 is now mapped to A01:2025 Broken Access Control. And the Top 10's own CWE mapping does not always match the way a tester thinks about a bug: CWE-915 (the mass assignment weakness) is mapped to A08:2025 Software or Data Integrity Failures, even though we test and fix it as an authorisation problem. Our mapping tables follow OWASP's CWE mapping and say so where the two differ.

**OWASP API Security Top 10 2023** is used for every finding on an API:

| ID | Category |
|---|---|
| API1:2023 | Broken Object Level Authorization |
| API2:2023 | Broken Authentication |
| API3:2023 | Broken Object Property Level Authorization |
| API4:2023 | Unrestricted Resource Consumption |
| API5:2023 | Broken Function Level Authorization |
| API6:2023 | Unrestricted Access to Sensitive Business Flows |
| API7:2023 | Server Side Request Forgery |
| API8:2023 | Security Misconfiguration |
| API9:2023 | Improper Inventory Management |
| API10:2023 | Unsafe Consumption of APIs |

How the references line up for the Access Control subcategory:

| Weakness | WSTG | ASVS 5.0 | Top 10 / API Top 10 | CWE |
|---|---|---|---|---|
| IDOR / BOLA | `WSTG-ATHZ-04`, `WSTG-APIT-02` | `v5.0.0-8.2.2` (L1) | `A01:2025`, `API1:2023` | CWE-639 |
| Missing function-level authorisation | `WSTG-ATHZ-02`, `WSTG-ATHZ-03`, `WSTG-APIT-04` | `v5.0.0-8.2.1` (L1) | `A01:2025`, `API5:2023` | CWE-862, CWE-285 |
| Authorisation enforced only on the client | `WSTG-ATHZ-02` | `v5.0.0-8.3.1` (L1) | `A01:2025` | CWE-602 |
| Mass assignment, excessive data exposure | `WSTG-INJT-20`, `WSTG-APIT-03` | `v5.0.0-8.2.3` (L2) | `A08:2025` (via CWE-915) or `A01:2025`, `API3:2023` | CWE-915, CWE-213 |
| Cross-tenant access | `WSTG-ATHZ-04`, `WSTG-APIT-02` | `v5.0.0-8.4.1` (L2) | `A01:2025`, `API1:2023` | CWE-639, CWE-863 |
| Permissions not revoked promptly | `WSTG-ATHZ-02`, `WSTG-SESS-06` | `v5.0.0-8.3.2` (L3) | `A01:2025` | CWE-863 |
| Service acting with its own rights instead of the user's | `WSTG-ATHZ-02` | `v5.0.0-8.3.3` (L3) | `A01:2025` | CWE-441 |

Each note refines this table for its own tests.

## Practice labs

Practise anything aggressive or state-changing in a lab you run yourself, never on a client's system or a programme you are not sure about.

- [PortSwigger Web Security Academy](https://portswigger.net/web-security): free, browser-based labs for nearly every topic in this series, including [access control](https://portswigger.net/web-security/access-control), authentication, OAuth, JWT, SSRF, request smuggling, cache poisoning and deception, GraphQL, API testing and race conditions. The [all labs](https://portswigger.net/web-security/all-labs) page lists them by topic. Each note links the labs for its topic.
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/): a deliberately insecure single-page shop with a scoreboard of challenges covering most of the OWASP Top 10. The companion book, [Pwning OWASP Juice Shop](https://pwning.owasp-juice.shop/), explains every challenge. Run it locally from the [GitHub repository](https://github.com/juice-shop/juice-shop) or as a container.
- [OWASP crAPI](https://github.com/OWASP/crAPI) (completely ridiculous API): a microservice-based vehicle-owner application built around the API Security Top 10, good for BOLA, BFLA, mass assignment and excessive data exposure.
- [VAmPI](https://github.com/erev0s/VAmPI): a small vulnerable REST API with a switch to turn the vulnerabilities on and off, handy for testing your own tooling and scripts.
- [DVWA](https://github.com/digininja/DVWA) (Damn Vulnerable Web Application): a classic PHP/MySQL application with security levels, useful for injection, upload and file inclusion basics.
- [WebGoat](https://github.com/WebGoat/WebGoat): OWASP's Java-based teaching application, with guided lessons that explain each weakness before you exploit it.

Run these on your own machine or an isolated lab network. Several are designed to be exploitable from the network, so never expose them to the internet.

## References

- OWASP: [Web Security Testing Guide (project page)](https://owasp.org/www-project-web-security-testing-guide/)
- OWASP: [WSTG latest (development version)](https://wstg.owasp.org/latest/) and [WSTG 4.2 (stable)](https://wstg.owasp.org/v4.2/)
- OWASP: [WSTG web application security testing chapters](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/)
- OWASP: [WSTG reporting chapter](https://wstg.owasp.org/latest/5-Reporting/)
- OWASP: [WSTG repository and checklists](https://github.com/OWASP/wstg/tree/master/checklists)
- OWASP: [Application Security Verification Standard (project page)](https://owasp.org/www-project-application-security-verification-standard/)
- OWASP: [ASVS 5.0 source on GitHub](https://github.com/OWASP/ASVS/tree/master/5.0) and [releases (CSV, JSON, PDF)](https://github.com/OWASP/ASVS/releases)
- OWASP: [Top 10:2025](https://owasp.org/Top10/2025/) and [A01:2025 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/)
- OWASP: [API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- OWASP: [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- OWASP: [Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- OWASP: [Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)
- FIRST: [CVSS v3.1 specification](https://www.first.org/cvss/v3-1/specification-document) and [calculator](https://www.first.org/cvss/calculator/3.1)
- FIRST: [CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document), [user guide](https://www.first.org/cvss/v4.0/user-guide) and [calculator](https://www.first.org/cvss/calculator/4.0)
- MITRE: [CWE](https://cwe.mitre.org/), for example [CWE-639](https://cwe.mitre.org/data/definitions/639.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html), [CWE-863](https://cwe.mitre.org/data/definitions/863.html)
- HackerOne: [Severity](https://docs.hackerone.com/en/articles/8495674-severity)
- Bugcrowd: [Vulnerability Rating Taxonomy](https://bugcrowd.com/vulnerability-rating-taxonomy) and [VRT repository](https://github.com/bugcrowd/vulnerability-rating-taxonomy)
- IETF: [RFC 9116, security.txt](https://www.rfc-editor.org/rfc/rfc9116)
- UK legislation: [Computer Misuse Act 1990](https://www.legislation.gov.uk/ukpga/1990/18/contents)
- PortSwigger: [Burp target scope](https://portswigger.net/burp/documentation/desktop/tools/target/scope), [session handling settings](https://portswigger.net/burp/documentation/desktop/settings/sessions), [Logger](https://portswigger.net/burp/documentation/desktop/tools/logger), [upstream proxy and connection settings](https://portswigger.net/burp/documentation/desktop/settings/network/connections), [BApp Store](https://portswigger.net/bappstore)
- ZAP: [Access Control Testing add-on](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/)
- Tools: [Autorize](https://github.com/PortSwigger/autorize), [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix), [Auth Analyzer](https://github.com/PortSwigger/auth-analyzer), [Param Miner](https://github.com/PortSwigger/param-miner), [InQL](https://github.com/doyensec/inql), [Logger++](https://github.com/nccgroup/LoggerPlusPlus), [JWT Editor](https://github.com/PortSwigger/jwt-editor), [PwnFox](https://github.com/yeswehack/PwnFox), [Firefox Multi-Account Containers](https://addons.mozilla.org/en-GB/firefox/addon/multi-account-containers/), [ffuf](https://github.com/ffuf/ffuf), [Arjun](https://github.com/s0md3v/Arjun), [nuclei](https://github.com/projectdiscovery/nuclei), [sqlmap](https://github.com/sqlmapproject/sqlmap)
