---
title: "Access Control Testing Guide"
date: 2026-11-15 18:20:00 +0000
subcategory: access-control
summary: "Hub for the Access Control notes: how authorisation fails, building the access matrix, a test plan, all 71 tests, ASVS V8 coverage and rating rules."
refs: [WSTG-ATHZ, WSTG-APIT, WSTG-INJT-20, v5.0.0-V8, "A01:2025", "API1:2023", "API3:2023", "API5:2023", CWE-284, CWE-639, CWE-862, CWE-863]
tags: [web, access-control, authorization, methodology, wstg, asvs]
---

Access control decides whether *this* caller may perform *this* operation on *this* object, field or tenant, *right now*. Authentication tells the application who you are; access control decides what that identity is allowed to do. When it fails, users read each other's records, members call admin functions, one customer reaches another customer's data, and people who were removed keep working. OWASP ranks Broken Access Control first in the [Top 10:2025](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) (`A01:2025`), as it did in 2021. The 2025 page says every application in the contributed data had some form of it, and that the category had the highest number of occurrences of any. In our experience it is also where the most serious findings of a web or API test come from, because scanners cannot know your permission model and frameworks do not supply it. This page is the hub of the Access Control subcategory of our [Web Application Security testing guide](/web/web-application-security-testing-guide/). It covers the mental model, how we build the access matrix that every test runs against, the order we run the six notes in, a table of all 71 tests with their WSTG and ASVS 5.0 mapping, ASVS V8 coverage, and the rating conventions shared by the notes. Rules of engagement, account set-up, Burp configuration and the tooling are covered once in the series hub and not repeated here. Everything assumes an authorised engagement, a bug bounty programme whose rules allow the test, or a lab, and uses accounts and tenants you control. Outputs shown on this page are illustrative.

## Contents

- [How access control fails](#how-access-control-fails)
- [Building the access matrix](#building-the-access-matrix)
  - [What goes in the matrix](#what-goes-in-the-matrix)
  - [Capturing it as data](#capturing-it-as-data)
  - [Worked example: an invoicing SaaS](#worked-example-an-invoicing-saas)
- [Test plan](#test-plan)
  - [Order of work](#order-of-work)
  - [Time-boxing](#time-boxing)
  - [What the session-swap tools carry and what they miss](#what-the-session-swap-tools-carry-and-what-they-miss)
- [Notes in this subcategory](#notes-in-this-subcategory)
  - [IDOR and BOLA](#idor-and-bola)
  - [Vertical privilege escalation and BFLA](#vertical-privilege-escalation-and-bfla)
  - [Authorisation bypass techniques](#authorisation-bypass-techniques)
  - [Mass assignment and BOPLA](#mass-assignment-and-bopla)
  - [Multi-tenant isolation](#multi-tenant-isolation)
  - [Revocation, sharing and asynchronous access](#revocation-sharing-and-asynchronous-access)
- [All tests at a glance](#all-tests-at-a-glance)
- [ASVS 5.0 V8 coverage](#asvs-50-v8-coverage)
- [Rating access-control findings](#rating-access-control-findings)
  - [Conventions](#conventions)
  - [Typical ratings](#typical-ratings)
- [Practice path](#practice-path)
- [References](#references)

## How access control fails

Every access-control decision answers the same question with up to six inputs: **who** is asking, for **what** function, on **which object**, touching **which field**, inside **which tenant**, and in **what context or at what time**. An application that gets five right and one wrong is still broken, and each input fails in its own way, so we split the subcategory along those lines.

| Dimension | The question the server must answer | Typical failure | Note | WSTG | ASVS 5.0 |
|---|---|---|---|---|---|
| Who | Is there an authenticated identity at all, and is it the one the request claims? | Routes outside the auth layer; identity taken from a parameter, header or cookie | [Bypass techniques](/web/web-authorization-bypass-techniques/), [IDOR and BOLA](/web/web-idor-bola/) (identity parameters) | WSTG-ATHZ-02, WSTG-ATHN-04 | `8.2.1`, `8.3.1` |
| What | May this role run this function? | Admin endpoints protected only by a hidden menu; sibling verbs unchecked; role values the client sets | [Vertical privilege escalation and BFLA](/web/web-vertical-privilege-escalation-bfla/) | WSTG-ATHZ-03, WSTG-APIT-04 | `8.2.1` |
| Which object | May this identity act on this record? | Lookups by ID without an ownership filter; nested resources where only the parent is checked | [IDOR and BOLA](/web/web-idor-bola/) | WSTG-ATHZ-04, WSTG-APIT-02 | `8.2.2` |
| Which field | May this identity read or write this property? | Mass assignment of `role` or `owner_id`; whole objects serialised to the client | [Mass assignment and BOPLA](/web/web-mass-assignment-bopla/) | WSTG-INJT-20, WSTG-APIT-03 | `8.2.3`, `8.1.2` |
| Which tenant | Does this operation stay inside the caller's organisation? | Tenant taken from a header nobody checks; search, cache and export paths that ignore the tenant | [Multi-tenant isolation](/web/web-multi-tenant-isolation/) | WSTG-ATHZ-02, WSTG-ATHZ-04 | `8.4.1` |
| Context and time | Is the decision still true now, and does it hold on every path the data takes? | Sessions and tokens that outlive a removal; share links that never expire; jobs, sockets and webhooks that were authorised once | [Revocation, sharing and asynchronous access](/web/web-access-control-revocation-sharing-async/) | WSTG-ATHZ-02, WSTG-BUSL-06, WSTG-SESS-06 | `8.3.2`, `8.3.3` |

Two failures cut across all six dimensions, so they are worth keeping in mind from the start.

- **The decision is made in the wrong place.** A check in the SPA, in the API gateway or in a reverse-proxy rule is only as good as the agreement between that layer and the handler behind it. Path normalisation, method overrides, `X-Original-URL` and IP-trust headers all exploit a disagreement about what the request *is*. ASVS `v5.0.0-8.3.1` (L1) says the decision belongs in a trusted service layer. The [bypass techniques note](/web/web-authorization-bypass-techniques/) tests every way of reaching the handler without passing the check.
- **The decision is made once and reused.** Anything that caches authority (a session, a JWT, a socket subscription, a signed URL, a queued job) carries yesterday's decision into today. ASVS `v5.0.0-8.3.2` (L3) asks for changes to be applied immediately, or for compensating controls where they cannot be. The [revocation note](/web/web-access-control-revocation-sharing-async/) tests what happens after the decision changes.

The usual root cause behind all of this is design, not syntax: there is no written policy, so every handler implements its own idea of it. That is why the first thing we do is write the policy down.

## Building the access matrix

You cannot test "should B be able to do this?" until someone has decided the answer. The access matrix records that decision for every role, object, operation, field and tenant relationship. A finding is a cell where the server's behaviour differs from the matrix. ASVS 5.0 expects the client to have this documentation already (`v5.0.0-8.1.1`, L1, for function and data rules; `v5.0.0-8.1.2`, L2, for field rules). In practice we usually reconstruct it from the UI, the API specification and a conversation with the product owner, then ask the client to confirm it. The account set itself (A1, A2, AM, AR, B1, BM, U and, where provided, platform staff) is described under *The role matrix* in the [series hub](/web/web-application-security-testing-guide/).

### What goes in the matrix

- **Roles.** Every role the application has, including the easy-to-forget ones: owner versus admin, billing-only, read-only auditor, support staff, service accounts and API keys, external guests (customers, contractors), and the anonymous visitor.
- **Objects.** Every object type a user can name in a request. Start with the obvious (invoices, users) and keep going until you reach the long tail (attachments, comments, audit entries, saved filters, export jobs, webhook endpoints, API keys). Missing object types are where tests get skipped.
- **Operations.** Function-level operations as method plus path template (`DELETE /api/users/{id}`) or GraphQL operation name, not concrete URLs. Separate read, list, create, update, delete and any domain verbs (send, approve, void, export, impersonate).
- **Relationship to the object.** "Member: allowed" is rarely the real rule. It is usually "own only", "own team", "assigned to me" or "any in own tenant". Record the condition, because the condition is what the object-level tests check.
- **Fields.** For each object, which fields each role may read, which it may write, through which operation, and in which states. Server-only fields (`org_id`, `total`, `paid_at`, `email_verified`) get their own row.
- **Tenants.** The rule for crossing the tenant boundary is almost always "never", with named exceptions (platform support, shared catalogue data). Write the exceptions down; the [tenant note](/web/web-multi-tenant-isolation/) tests everything else.
- **Lifecycle and context.** What happens on downgrade, removal, deactivation, password change and invoice state changes, and how long share links, export links and tokens live.

### Capturing it as data

Keep the matrix as a CSV or YAML file in the engagement folder, not only as a table in a document. As data, it drives AuthMatrix, the comparison helpers in the notes and, later, the client's CI regression tests, and the same file becomes the retest checklist. One row per operation (and per field where field rules differ), one column per role, plus the cross-tenant expectation and the tests that cover the row:

```text
row,method,path,object,op,field,condition,owner,admin,accountant,member,viewer,support,anon,tenant_b,tests
M-01,GET,/api/invoices,invoice,list,,own tenant,allow,allow,allow,allow,allow,deny,deny,deny,IDOR-9;TEN-7
M-02,GET,/api/invoices/{id},invoice,read,,own tenant,allow,allow,allow,allow,allow,audited,deny,deny,IDOR-2;TEN-2
M-03,PATCH,/api/invoices/{id},invoice,update,lines,draft only,allow,allow,allow,own draft,deny,deny,deny,deny,IDOR-3;BOPLA-7
M-04,PATCH,/api/invoices/{id},invoice,update,status,draft->sent,allow,allow,allow,deny,deny,deny,deny,deny,BOPLA-7;BOPLA-12
M-05,PATCH,/api/invoices/{id},invoice,update,total,server only,deny,deny,deny,deny,deny,deny,deny,deny,BOPLA-7
M-06,POST,/api/invoices/{id}/void,invoice,void,,sent only,allow,allow,allow,deny,deny,deny,deny,deny,PRIV-4
M-07,GET,/api/invoices/{id}/pdf,attachment,read,,own tenant,allow,allow,allow,allow,allow,deny,deny,deny,IDOR-11;TEN-8
M-08,PATCH,/api/members/{id},membership,update,role,ceiling: <= own role,allow,not owner,deny,deny,deny,deny,deny,deny,PRIV-6;BOPLA-5
M-09,DELETE,/api/members/{id},membership,delete,,not last owner,allow,allow,deny,deny,deny,deny,deny,deny,PRIV-3;CTX-2
M-10,POST,/api/exports,export,create,,own tenant,allow,allow,allow,deny,deny,deny,deny,deny,PRIV-3;CTX-7
M-11,POST,/api/webhooks,webhook,create,,own tenant,allow,allow,deny,deny,deny,deny,deny,deny,PRIV-3;CTX-11
M-12,GET,/p/{share_token},invoice,read,,valid unexpired link,link,link,link,link,link,link,link,link,CTX-5;CTX-6
M-13,POST,/api/support/impersonate,session,create,,support staff only,deny,deny,deny,deny,deny,allow,deny,deny,PRIV-8;TEN-11
```

Use `deny` for "must be refused", `allow` for "must work", and a short condition where the answer depends on the object. When a cell is unclear, mark it `?` and ask. An unanswered question is itself a documentation finding against `v5.0.0-8.1.1`, and it is usually the root cause of the bugs you find later in that area.

### Worked example: an invoicing SaaS

Take a small invoicing product at `app.example.com`. Organisations (tenants) sign up for a trial, invite colleagues, create customers and invoices, send invoices to their customers through a share link, take payment through a payment provider whose webhook marks invoices as paid, and export data for their accountants. Its roles:

| Role | Who | Intended power |
|---|---|---|
| Owner | Whoever created the organisation | Everything in the organisation, including billing and deleting it |
| Admin | Trusted colleague | Everything except billing, ownership transfer and deleting the organisation; cannot grant Owner |
| Accountant | Finance staff | Create, send and void invoices, record payments, run exports |
| Member | Sales staff | Create and edit their own draft invoices; read all invoices in the organisation |
| Viewer | Auditor | Read-only access to invoices and customers |
| Customer | The invoiced business, external | Reads one invoice through a share link; no account |
| Support | Platform staff | Audited, time-limited impersonation of an organisation on request |
| Anonymous | Anyone | The marketing site, sign-up and share links only |

Function and object rules are in the CSV above. The field rules for the `Invoice` object are where most designs leave gaps, so write them out separately:

| Field | Read | Write | Notes |
|---|---|---|---|
| `id`, `number` | All roles in tenant, share link | Server only | `number` is unique per tenant, a possible side channel (TEN-12) |
| `org_id` | Nobody needs it in responses | Server only, from the session | Any client-supplied value is ignored or rejected (BOPLA-6, TEN-3) |
| `customer_id` | All roles in tenant | Accountant+, Member on own draft | Must reference a customer in the same tenant (IDOR-4) |
| `lines[]` | All roles in tenant, share link | Accountant+, Member on own draft | Draft state only |
| `total`, `tax` | All roles in tenant, share link | Server only (computed) | A writable total is a BOPLA-7 finding |
| `status` | All roles in tenant, share link | `draft → sent`, `sent → void`: Accountant+; `paid`: payment webhook only | State-dependent rule (BOPLA-12) |
| `paid_at` | All roles in tenant | Server only | |
| `internal_note` | Accountant+ | Accountant+ | Must not appear in the share-link view or in exports for Viewer (BOPLA-4, CTX-6) |
| `created_by` | All roles in tenant | Server only | Spoofing it is "acting as another user" (IDOR-5) |

And the lifecycle rules that the [revocation note](/web/web-access-control-revocation-sharing-async/) tests:

- A removed or deactivated member loses access on their next request: sessions, refresh tokens and API keys stop working immediately, open WebSocket connections are closed, and webhooks they registered stop delivering.
- A downgrade from Accountant to Member applies to the next request, not the next login.
- Share links expire after 30 days, stop working when the invoice is voided, and show only the customer-facing fields.
- Export downloads are bound to the requester, expire after 24 hours, and are re-authorised when the job runs, not only when it is queued.

Each row becomes one or more requests. Take M-02 against tenant B's user. Log in as **A1** (Member, tenant A) and note one of **your own** invoices, `inv_7Hq2`. Then replay the read with **B1**'s session (Member, tenant B):

```http
GET /api/invoices/inv_7Hq2 HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_B1>
Accept: application/json
```

```bash
curl -s -i https://app.example.com/api/invoices/inv_7Hq2 \
     -H "Cookie: session=<SESSION_USER_B1>" -H "Accept: application/json"
```

The matrix says `tenant_b: deny`. A correct server answers `404 Not Found`, or `403`, with no invoice data in the body. A vulnerable one answers `200 OK` with A1's invoice. A `200` whose body is an error message, or an empty object, is not a finding; read the body before you trust the status. The same request then goes through the other columns (A2, AR, U) automatically, as described in the test plan.

## Test plan

### Order of work

We run the notes in this order. The early steps produce the inventories the later ones depend on, and the steps that change account state (downgrades, removals) come last so they do not disrupt the rest of the test.

1. **Map and write the matrix.** IDOR-1 (identifiers and where they come from), PRIV-1 and PRIV-2 (functions, including the hidden ones), BOPLA-1 (property inventory per object) and TEN-1 (tenancy model and tenant selectors), with BYP-2 forced browsing feeding the route list. Output: the matrix file and a Burp project in which every feature has been used by the highest-privileged account you have.
2. **Broad session-swap pass.** Replay everything as every lower column with the tools below. This covers most of IDOR-2, IDOR-12, PRIV-3, BYP-1 and TEN-2 in one sweep and gives you a list of leads, not findings.
3. **Object level, by hand.** IDOR-3 to IDOR-11: writes and deletes (verified from the owner's session), nested resources, identity parameters, identifier predictability, parsing variants, alternate routes and versions, lists and exports, GraphQL, files.
4. **Function level, by hand.** PRIV-4 to PRIV-11: sibling verbs, role values in requests, role ceilings, bulk and import paths, impersonation, GraphQL mutations, horizontal-to-vertical chains, admin interface separation.
5. **Property level.** BOPLA-2 to BOPLA-12: what responses expose, then which extra fields writes accept, always on your own objects and always re-reading to see what was stored.
6. **Tenant boundary.** TEN-3 to TEN-12: conflicting tenant selectors, organisation switching, invitations, tenant admin versus platform admin, search, caches, storage, jobs, SSO binding, support consoles, side channels. Skip this step for single-tenant applications, but record the decision.
7. **Bypasses on everything that was denied.** BYP-3 to BYP-12 against the denials from steps 2 to 6: path variants, method tampering and override headers, URL override and forwarding headers, Referer and step-order checks, client-side flags, framework CVEs. A denial at the edge is only as strong as the edge's agreement with the back-end.
8. **Context and time.** CTX-1 to CTX-12. These need state changes: log out, change a password, downgrade A2, remove A2 from the organisation, revoke a share link, then replay the saved requests. Agree the timing with the client if the accounts are shared with their own testers.

### Time-boxing

Access control is the part of a web test that rewards time most, and it is easy to sink the whole budget into step 3 on one rich object type. Our rough split for a mid-sized application (around 100 to 200 API operations, four or five roles, two tenants) on a five-day web test, adjusted per engagement:

| Step | Share of the access-control time | Stop when |
|---|---|---|
| 1. Map and matrix | 15–20% | Every object type and role has a row, and open questions have gone to the client |
| 2. Session-swap pass | 10% | Every captured request has been replayed by every column and the leads are triaged |
| 3–4. Object and function level | 35% | Each object type has had read, write and nested checks; each privileged function has been called by each lower role |
| 5. Property level | 10–15% | Each writable object has had the privilege, ownership and state fields tried |
| 6. Tenant boundary | 10–15% | Every tenant selector and every data path out of the request (search, exports, caches, storage, jobs) has been tried |
| 7–8. Bypasses, context and time | 10–15% | Every denial has had the bypass variants tried, and every revocation event has been replayed |

Two rules keep the time-box honest. First, breadth before depth: one confirmed IDOR on invoices is worth less to the client than knowing that attachments, exports and the GraphQL endpoint were all checked. Second, once a root cause is confirmed (for example, "no handler filters by tenant"), stop proving it on every endpoint. Record the affected routes from the session-swap output and move on.

### What the session-swap tools carry and what they miss

Set-up for all three extensions is in the [series hub](/web/web-application-security-testing-guide/). How we use them in this subcategory:

- **Autorize** is the first pass. Browse as the higher-privileged account (AM, or A1 for horizontal checks) and give Autorize the lower account's cookie or `Authorization` header (A2, AR or B1 in turn) with the unauthenticated check switched on. It replays each request and marks it *Bypassed!*, *Enforced!* or *Is enforced???*. Tune the enforcement detectors to the application's real denial (a status code, a body string such as `"error":"forbidden"`) before you trust the colours.
- **Auth Analyzer** runs several sessions at once (A2, AR, B1 and U side by side). Its parameter extraction and replacement can follow CSRF tokens and swap values such as an `X-Org-Id` header or an `org` body field per session, which makes it our tool for tenant and multi-role sweeps. It tags each replay `SAME`, `SIMILAR` or `DIFFERENT` compared with the original response.
- **AuthMatrix** holds the matrix itself: roles as columns, requests as rows, the expected roles ticked, and a regex that recognises success. Run it after the manual work and again at retest. The saved configuration is the regression artefact you hand to the client, and re-running it after a downgrade or a removal is the quickest way to execute much of CTX-2.
- **ZAP's Access Control Testing add-on** is the free alternative, with allow and deny rules per user and context.

Between them, these tools carry the bulk of the "same request, different identity" checks: reads, lists, most function-level calls and unauthenticated access. Manual work is needed wherever the test changes something other than the session:

- **Writes and deletes.** A `404` or an error to B does not prove the change was refused. Check the object from A's session (IDOR-3; the blind-write case). Keep writes out of automated replays unless they target your own test objects only.
- **Adding or changing request content.** Extra fields (BOPLA), swapped identifiers inside bodies and nested paths (IDOR-4), path, method and header variants (BYP-3 to BYP-8): the tools replay what you sent, they do not invent variants.
- **Responses that look alike for innocent reasons.** GraphQL returns `200` with an `errors` array; lists return the caller's own rows; shared objects are readable by design; a CDN may serve a cached copy. Compare the content, not the status.
- **Anything off the HTTP request path.** WebSocket and SSE messages, GraphQL subscriptions, webhooks, queued exports and emailed links (CTX-7 to CTX-11). The tools see the request that starts these, not the data they deliver later.
- **State and time.** Revocation, organisation switching and multi-step flows need a change between two requests (CTX-1 to CTX-4, TEN-4, CTX-8).

The "stop on real data" rule from the series hub applies to every step. If a replay returns data that does not belong to one of your accounts, stop, keep the minimum redacted evidence and tell the client.

## Notes in this subcategory

### IDOR and BOLA

[IDOR and BOLA: Testing Object-Level Authorization](/web/web-idor-bola/) covers the check that decides whether this user may read, change or delete this record. It follows identifiers from where they are issued to everywhere they are accepted (paths, bodies, headers, GraphQL global IDs, file names) and explains why a UUID is not an access control even though it lowers likelihood. The fixes scope every query by owner or tenant, with regression tests that run each request as a second user.

- GT-WEB-IDOR-1: Inventory object identifiers and where they come from
- GT-WEB-IDOR-2: Swap object IDs between two users on read
- GT-WEB-IDOR-3: Write and delete on the other user's object
- GT-WEB-IDOR-4: Nested resources and references in request bodies
- GT-WEB-IDOR-5: Identity parameters, headers and token claims
- GT-WEB-IDOR-6: Identifier predictability and exposure
- GT-WEB-IDOR-7: Type juggling, arrays, wrapped IDs and parameter pollution
- GT-WEB-IDOR-8: Alternate routes, versions, methods and content types
- GT-WEB-IDOR-9: List, search, bulk and export endpoints
- GT-WEB-IDOR-10: GraphQL object-level authorisation
- GT-WEB-IDOR-11: Files and attachments
- GT-WEB-IDOR-12: Full-coverage session-swap replay

### Vertical privilege escalation and BFLA

[Vertical Privilege Escalation and Function-Level Authorization (BFLA)](/web/web-vertical-privilege-escalation-bfla/) covers a lower role getting the application to run a higher role's function. It builds the role-by-function matrix, finds the admin functions the UI hides, and tests role values in requests, role ceilings, privileged side doors in bulk and import features, impersonation and GraphQL mutations. It also covers chains in which a horizontal bug against an administrator's own record becomes vertical.

- GT-WEB-PRIV-1: Build the role and function matrix
- GT-WEB-PRIV-2: Discover privileged functions the UI hides
- GT-WEB-PRIV-3: Call privileged functions with a lower-privilege session
- GT-WEB-PRIV-4: Sibling operations and verbs on the same resource
- GT-WEB-PRIV-5: Role and permission values in client requests
- GT-WEB-PRIV-6: Role ceilings and self-assignment of roles and groups
- GT-WEB-PRIV-7: Privileged actions inside bulk, import and multi-step features
- GT-WEB-PRIV-8: Impersonation, support tooling and feature flags
- GT-WEB-PRIV-9: GraphQL mutations and privileged queries
- GT-WEB-PRIV-10: Horizontal-to-vertical chains against higher-role accounts
- GT-WEB-PRIV-11: Administrative interface separation and layered controls

### Authorisation bypass techniques

[Bypassing the Authorization Schema: Forced Browsing, Path and Header Tricks](/web/web-authorization-bypass-techniques/) covers checks that exist but sit in the wrong place or read the wrong input. That includes routes outside the auth middleware, proxy and back-end path disagreements, method tampering and override headers, `X-Original-URL`, forwarding headers trusted as client IPs, Referer and step-order checks, role flags the client controls, and checks that exist only in the SPA. Known framework CVEs of this class (Next.js middleware, Spring Security matchers) are handled as version checks plus a harmless confirmation.

- GT-WEB-BYP-1: Strip the session from authenticated requests
- GT-WEB-BYP-2: Forced browsing to unlinked pages and API routes
- GT-WEB-BYP-3: Path normalisation variants against edge rules
- GT-WEB-BYP-4: Path parameters and suffix matching on Java stacks
- GT-WEB-BYP-5: HTTP method tampering
- GT-WEB-BYP-6: Method override headers and parameters
- GT-WEB-BYP-7: URL override headers
- GT-WEB-BYP-8: Client IP trust through forwarding headers
- GT-WEB-BYP-9: Referer checks and multi-step flows
- GT-WEB-BYP-10: Client-controlled role and privilege flags
- GT-WEB-BYP-11: Client-side-only enforcement in SPAs
- GT-WEB-BYP-12: Known framework authorisation bypass CVEs

### Mass assignment and BOPLA

[Mass Assignment and Property-Level Authorization (BOPLA)](/web/web-mass-assignment-bopla/) covers authorisation on a single property: you may edit your own profile but not its `role`, and read your own order but not its `internal_notes`. It tests both directions: binding on the way in (privilege, ownership, tenant and business-state fields, nested objects, alternative content types and PATCH semantics, create paths) and serialisation on the way out (secrets, other users' data in embedded objects, GraphQL fields). Every write test runs against your own object and re-reads it to see what the server stored.

- GT-WEB-BOPLA-1: Build a property inventory for each object
- GT-WEB-BOPLA-2: Compare the raw response with what the UI shows
- GT-WEB-BOPLA-3: Secrets and write-only fields in responses
- GT-WEB-BOPLA-4: Other users' data in embedded objects and lists
- GT-WEB-BOPLA-5: Privilege fields on your own profile update
- GT-WEB-BOPLA-6: Ownership and tenant fields on create and update
- GT-WEB-BOPLA-7: Business state and value fields on your own objects
- GT-WEB-BOPLA-8: Nested objects and bracket notation
- GT-WEB-BOPLA-9: Content types, PATCH semantics and parameter pollution
- GT-WEB-BOPLA-10: Registration, invitation, import and bulk paths
- GT-WEB-BOPLA-11: GraphQL field-level authorization
- GT-WEB-BOPLA-12: Field rules that depend on role and state

### Multi-tenant isolation

[Multi-Tenant Isolation: Testing Cross-Tenant Access in SaaS](/web/web-multi-tenant-isolation/) covers the boundary between one customer's organisation and every other's. It looks at where the tenant is resolved (subdomain, path, header, token claim, session) and what happens when two sources disagree. It then works through organisation switching, invitations, tenant admin versus platform admin, and the paths data takes out of the request: search indexes, caches, object storage, queues, SSO and support consoles. The fixes cover the isolation models from a `tenant_id` column to PostgreSQL row-level security as a backstop.

- GT-WEB-TEN-1: Map the tenancy model and every tenant selector
- GT-WEB-TEN-2: Swap tenant B object IDs into tenant A requests
- GT-WEB-TEN-3: Make the tenant selectors disagree
- GT-WEB-TEN-4: Organisation switching and stale tenant context
- GT-WEB-TEN-5: Invitations and membership lifecycle
- GT-WEB-TEN-6: Tenant admin versus platform admin
- GT-WEB-TEN-7: Search, reporting, exports and caches
- GT-WEB-TEN-8: File and object storage paths
- GT-WEB-TEN-9: Background jobs, integrations and webhooks
- GT-WEB-TEN-10: SSO and identity provider tenant binding
- GT-WEB-TEN-11: Support and impersonation consoles
- GT-WEB-TEN-12: Cross-tenant side channels

### Revocation, sharing and asynchronous access

[Access Control Beyond the Request: Revocation, Share Links, Exports and Async Channels](/web/web-access-control-revocation-sharing-async/) covers failures that a request-by-request check misses. Authority can outlive the decision that granted it: sessions, JWTs, refresh tokens, API keys and OAuth grants after a downgrade or removal. Data can also leave through a side door: share links and pre-signed URLs, exports, multi-step flows checked only at the first step, WebSocket, SSE and GraphQL subscriptions, webhooks, and confused deputies between services. For pre-signed object storage URLs, see also our note on [S3 security](/cloud/aws-s3-security/).

- GT-WEB-CTX-1: Session termination on logout, password change and deactivation
- GT-WEB-CTX-2: Stale authorisation after role downgrade or removal
- GT-WEB-CTX-3: Access and refresh tokens after a revocation event
- GT-WEB-CTX-4: API keys, personal access tokens and OAuth grants
- GT-WEB-CTX-5: Share link token strength, expiry and revocation
- GT-WEB-CTX-6: Share link scope, audience and sharer lifecycle
- GT-WEB-CTX-7: Exports, reports and download links
- GT-WEB-CTX-8: Authorisation on every step of a multi-step process
- GT-WEB-CTX-9: WebSocket and SSE subscriptions and messages
- GT-WEB-CTX-10: GraphQL subscriptions
- GT-WEB-CTX-11: Webhook registration and event scoping
- GT-WEB-CTX-12: Confused deputy between services and workers

## All tests at a glance

Built from the Mapping tables of the six notes. The ASVS 5.0 column drops the `v5.0.0-` prefix for space; each ID is followed by its level. CWE and Top 10 mappings per test are in each note's Mapping table.

| Test | Title | Note | WSTG | ASVS 5.0 |
|---|---|---|---|---|
| GT-WEB-IDOR-1 | Inventory object identifiers and where they come from | [IDOR/BOLA](/web/web-idor-bola/) | WSTG-ATHZ-04, WSTG-APIT-01, WSTG-INFO-06 | 8.1.1 L1 |
| GT-WEB-IDOR-2 | Swap object IDs between two users on read | [IDOR/BOLA](/web/web-idor-bola/) | WSTG-ATHZ-04, WSTG-APIT-02 | 8.2.2 L1, 8.3.1 L1 |
| GT-WEB-IDOR-3 | Write and delete on the other user's object | [IDOR/BOLA](/web/web-idor-bola/) | WSTG-ATHZ-04, WSTG-APIT-02 | 8.2.2 L1, 8.3.1 L1 |
| GT-WEB-IDOR-4 | Nested resources and references in request bodies | [IDOR/BOLA](/web/web-idor-bola/) | WSTG-ATHZ-04, WSTG-APIT-02 | 8.2.2 L1 |
| GT-WEB-IDOR-5 | Identity parameters, headers and token claims | [IDOR/BOLA](/web/web-idor-bola/) | WSTG-ATHZ-04, WSTG-APIT-02 | 8.2.2 L1, 8.3.1 L1, 4.1.3 L2 |
| GT-WEB-IDOR-6 | Identifier predictability and exposure | [IDOR/BOLA](/web/web-idor-bola/) | WSTG-ATHZ-04, WSTG-APIT-02 | 8.2.2 L1 |
| GT-WEB-IDOR-7 | Type juggling, arrays, wrapped IDs and parameter pollution | [IDOR/BOLA](/web/web-idor-bola/) | WSTG-ATHZ-04, WSTG-APIT-02, WSTG-INJT-04 | 8.2.2 L1, 8.3.1 L1 |
| GT-WEB-IDOR-8 | Alternate routes, versions, methods and content types | [IDOR/BOLA](/web/web-idor-bola/) | WSTG-APIT-02, WSTG-ATHZ-04 | 8.2.2 L1, 4.1.4 L3 |
| GT-WEB-IDOR-9 | List, search, bulk and export endpoints | [IDOR/BOLA](/web/web-idor-bola/) | WSTG-APIT-02 | 8.2.2 L1 |
| GT-WEB-IDOR-10 | GraphQL object-level authorisation | [IDOR/BOLA](/web/web-idor-bola/) | WSTG-APIT-99, WSTG-APIT-02 | 8.2.2 L1, 4.3.1 L2 |
| GT-WEB-IDOR-11 | Files and attachments | [IDOR/BOLA](/web/web-idor-bola/) | WSTG-ATHZ-04, WSTG-APIT-02 | 8.2.2 L1 |
| GT-WEB-IDOR-12 | Full-coverage session-swap replay | [IDOR/BOLA](/web/web-idor-bola/) | WSTG-ATHZ-04, WSTG-APIT-02 | 8.2.2 L1, 8.3.1 L1 |
| GT-WEB-PRIV-1 | Build the role and function matrix | [BFLA](/web/web-vertical-privilege-escalation-bfla/) | WSTG-ATHZ-03, WSTG-APIT-04 | 8.1.1 L1 |
| GT-WEB-PRIV-2 | Discover privileged functions the UI hides | [BFLA](/web/web-vertical-privilege-escalation-bfla/) | WSTG-APIT-01, WSTG-APIT-99, WSTG-BUSL-02 | 13.4.5 L2, 4.3.2 L2 |
| GT-WEB-PRIV-3 | Call privileged functions with a lower-privilege session | [BFLA](/web/web-vertical-privilege-escalation-bfla/) | WSTG-ATHZ-03, WSTG-ATHZ-02, WSTG-APIT-04 | 8.2.1 L1, 8.3.1 L1 |
| GT-WEB-PRIV-4 | Sibling operations and verbs on the same resource | [BFLA](/web/web-vertical-privilege-escalation-bfla/) | WSTG-APIT-04, WSTG-ATHZ-03 | 8.2.1 L1 |
| GT-WEB-PRIV-5 | Role and permission values in client requests | [BFLA](/web/web-vertical-privilege-escalation-bfla/) | WSTG-ATHZ-03, WSTG-BUSL-02 | 8.2.1 L1, 8.2.3 L2, 15.3.3 L2 |
| GT-WEB-PRIV-6 | Role ceilings and self-assignment of roles and groups | [BFLA](/web/web-vertical-privilege-escalation-bfla/) | WSTG-ATHZ-03, WSTG-APIT-04 | 8.2.1 L1 |
| GT-WEB-PRIV-7 | Privileged actions inside bulk, import and multi-step features | [BFLA](/web/web-vertical-privilege-escalation-bfla/) | WSTG-ATHZ-03, WSTG-BUSL-06 | 8.2.1 L1, 2.3.1 L1 |
| GT-WEB-PRIV-8 | Impersonation, support tooling and feature flags | [BFLA](/web/web-vertical-privilege-escalation-bfla/) | WSTG-ATHZ-03, WSTG-BUSL-02 | 8.2.1 L1, 8.3.1 L1, 13.4.2 L2 |
| GT-WEB-PRIV-9 | GraphQL mutations and privileged queries | [BFLA](/web/web-vertical-privilege-escalation-bfla/) | WSTG-APIT-04, WSTG-APIT-99 | 8.2.1 L1, 4.3.2 L2 |
| GT-WEB-PRIV-10 | Horizontal-to-vertical chains against higher-role accounts | [BFLA](/web/web-vertical-privilege-escalation-bfla/) | WSTG-ATHZ-02, WSTG-ATHZ-03 | 8.2.2 L1, 8.2.1 L1 |
| GT-WEB-PRIV-11 | Administrative interface separation and layered controls | [BFLA](/web/web-vertical-privilege-escalation-bfla/) | WSTG-ATHZ-03 | 8.4.2 L3, 8.3.1 L1, 16.3.2 L2 |
| GT-WEB-BYP-1 | Strip the session from authenticated requests | [Bypass](/web/web-authorization-bypass-techniques/) | WSTG-ATHZ-02, WSTG-ATHN-04 | 8.2.1 L1, 7.2.1 L1 |
| GT-WEB-BYP-2 | Forced browsing to unlinked pages and API routes | [Bypass](/web/web-authorization-bypass-techniques/) | WSTG-ATHZ-02, WSTG-CONF-05, WSTG-CONF-04, WSTG-APIT-01 | 8.2.1 L1, 13.4.5 L2, 15.2.3 L2 |
| GT-WEB-BYP-3 | Path normalisation variants against edge rules | [Bypass](/web/web-authorization-bypass-techniques/) | WSTG-CONF-13, WSTG-ATHZ-02 | 8.3.1 L1, 8.2.1 L1 |
| GT-WEB-BYP-4 | Path parameters and suffix matching on Java stacks | [Bypass](/web/web-authorization-bypass-techniques/) | WSTG-CONF-13, WSTG-ATHZ-02 | 8.3.1 L1 |
| GT-WEB-BYP-5 | HTTP method tampering | [Bypass](/web/web-authorization-bypass-techniques/) | WSTG-CONF-06 | 4.1.4 L3, 13.4.4 L2, 8.2.1 L1 |
| GT-WEB-BYP-6 | Method override headers and parameters | [Bypass](/web/web-authorization-bypass-techniques/) | WSTG-CONF-06 | 4.1.4 L3, 8.2.1 L1 |
| GT-WEB-BYP-7 | URL override headers | [Bypass](/web/web-authorization-bypass-techniques/) | WSTG-ATHZ-02 | 4.1.3 L2, 8.3.1 L1 |
| GT-WEB-BYP-8 | Client IP trust through forwarding headers | [Bypass](/web/web-authorization-bypass-techniques/) | WSTG-ATHZ-02 | 15.3.4 L2, 4.1.3 L2, 8.4.2 L3 |
| GT-WEB-BYP-9 | Referer checks and multi-step flows | [Bypass](/web/web-authorization-bypass-techniques/) | WSTG-ATHZ-02 | 8.2.1 L1, 8.3.1 L1 |
| GT-WEB-BYP-10 | Client-controlled role and privilege flags | [Bypass](/web/web-authorization-bypass-techniques/) | WSTG-ATHN-04, WSTG-ATHZ-02, WSTG-CLNT-12 | 8.3.1 L1 |
| GT-WEB-BYP-11 | Client-side-only enforcement in SPAs | [Bypass](/web/web-authorization-bypass-techniques/) | WSTG-ATHZ-02, WSTG-APIT-04 | 8.3.1 L1, 8.2.1 L1 |
| GT-WEB-BYP-12 | Known framework authorisation bypass CVEs | [Bypass](/web/web-authorization-bypass-techniques/) | WSTG-ATHZ-02, WSTG-INFO-08 | 15.2.1 L1, 8.3.1 L1 |
| GT-WEB-BOPLA-1 | Build a property inventory for each object | [BOPLA](/web/web-mass-assignment-bopla/) | WSTG-INJT-20, WSTG-APIT-01 | 8.1.2 L2 |
| GT-WEB-BOPLA-2 | Compare the raw response with what the UI shows | [BOPLA](/web/web-mass-assignment-bopla/) | WSTG-APIT-03 | 15.3.1 L1, 8.3.1 L1 |
| GT-WEB-BOPLA-3 | Secrets and write-only fields in responses | [BOPLA](/web/web-mass-assignment-bopla/) | WSTG-APIT-03 | 15.3.1 L1, 14.2.6 L3 |
| GT-WEB-BOPLA-4 | Other users' data in embedded objects and lists | [BOPLA](/web/web-mass-assignment-bopla/) | WSTG-APIT-03 | 8.2.3 L2, 15.3.1 L1 |
| GT-WEB-BOPLA-5 | Privilege fields on your own profile update | [BOPLA](/web/web-mass-assignment-bopla/) | WSTG-INJT-20, WSTG-ATHZ-03 | 15.3.3 L2, 8.2.3 L2 |
| GT-WEB-BOPLA-6 | Ownership and tenant fields on create and update | [BOPLA](/web/web-mass-assignment-bopla/) | WSTG-INJT-20, WSTG-APIT-02 | 15.3.3 L2, 8.2.2 L1 |
| GT-WEB-BOPLA-7 | Business state and value fields on your own objects | [BOPLA](/web/web-mass-assignment-bopla/) | WSTG-INJT-20, WSTG-BUSL-01 | 15.3.3 L2, 8.2.3 L2 |
| GT-WEB-BOPLA-8 | Nested objects and bracket notation | [BOPLA](/web/web-mass-assignment-bopla/) | WSTG-INJT-20 | 15.3.3 L2 |
| GT-WEB-BOPLA-9 | Content types, PATCH semantics and parameter pollution | [BOPLA](/web/web-mass-assignment-bopla/) | WSTG-INJT-20, WSTG-INJT-04 | 15.3.3 L2, 15.3.7 L2 |
| GT-WEB-BOPLA-10 | Registration, invitation, import and bulk paths | [BOPLA](/web/web-mass-assignment-bopla/) | WSTG-INJT-20, WSTG-ATHZ-03 | 15.3.3 L2 |
| GT-WEB-BOPLA-11 | GraphQL field-level authorization | [BOPLA](/web/web-mass-assignment-bopla/) | WSTG-APIT-99, WSTG-APIT-03 | 8.2.3 L2, 4.3.2 L2 |
| GT-WEB-BOPLA-12 | Field rules that depend on role and state | [BOPLA](/web/web-mass-assignment-bopla/) | WSTG-ATHZ-03, WSTG-APIT-03 | 8.1.2 L2, 8.2.3 L2 |
| GT-WEB-TEN-1 | Map the tenancy model and every tenant selector | [Tenant](/web/web-multi-tenant-isolation/) | WSTG-ATHZ-02, WSTG-APIT-02 | 8.4.1 L2, 8.1.1 L1 |
| GT-WEB-TEN-2 | Swap tenant B object IDs into tenant A requests | [Tenant](/web/web-multi-tenant-isolation/) | WSTG-ATHZ-04, WSTG-APIT-02 | 8.4.1 L2, 8.2.2 L1, 8.3.1 L1 |
| GT-WEB-TEN-3 | Make the tenant selectors disagree | [Tenant](/web/web-multi-tenant-isolation/) | WSTG-ATHZ-02 | 8.4.1 L2, 8.3.1 L1, 4.1.3 L2 |
| GT-WEB-TEN-4 | Organisation switching and stale tenant context | [Tenant](/web/web-multi-tenant-isolation/) | WSTG-ATHZ-02 | 8.4.1 L2, 8.3.2 L3 |
| GT-WEB-TEN-5 | Invitations and membership lifecycle | [Tenant](/web/web-multi-tenant-isolation/) | WSTG-ATHZ-02, WSTG-ATHZ-04 | 8.4.1 L2, 8.2.1 L1, 8.3.2 L3, 7.4.2 L1 |
| GT-WEB-TEN-6 | Tenant admin versus platform admin | [Tenant](/web/web-multi-tenant-isolation/) | WSTG-ATHZ-02, WSTG-APIT-04 | 8.4.1 L2, 8.2.1 L1, 8.4.2 L3 |
| GT-WEB-TEN-7 | Search, reporting, exports and caches | [Tenant](/web/web-multi-tenant-isolation/) | WSTG-ATHZ-04, WSTG-APIT-02 | 8.4.1 L2, 8.2.2 L1, 14.2.2 L2 |
| GT-WEB-TEN-8 | File and object storage paths | [Tenant](/web/web-multi-tenant-isolation/) | WSTG-ATHZ-04 | 8.4.1 L2, 8.2.2 L1 |
| GT-WEB-TEN-9 | Background jobs, integrations and webhooks | [Tenant](/web/web-multi-tenant-isolation/) | WSTG-ATHZ-04, WSTG-APIT-02 | 8.4.1 L2, 8.3.3 L3 |
| GT-WEB-TEN-10 | SSO and identity provider tenant binding | [Tenant](/web/web-multi-tenant-isolation/) | WSTG-ATHZ-02, WSTG-SESS-10 | 6.8.1 L2, 10.5.2 L2, 9.2.3 L2, 8.4.1 L2 |
| GT-WEB-TEN-11 | Support and impersonation consoles | [Tenant](/web/web-multi-tenant-isolation/) | WSTG-ATHZ-02 | 8.4.2 L3, 8.2.1 L1, 8.4.1 L2 |
| GT-WEB-TEN-12 | Cross-tenant side channels | [Tenant](/web/web-multi-tenant-isolation/) | WSTG-ATHZ-04, WSTG-ATHZ-02 | 8.4.1 L2 |
| GT-WEB-CTX-1 | Session termination on logout, password change and deactivation | [Revocation](/web/web-access-control-revocation-sharing-async/) | WSTG-SESS-06, WSTG-SESS-07, WSTG-SESS-11 | 7.4.1 L1, 7.4.2 L1, 7.4.3 L2, 7.4.5 L2, 7.3.1 L2, 7.3.2 L2 |
| GT-WEB-CTX-2 | Stale authorisation after role downgrade or removal | [Revocation](/web/web-access-control-revocation-sharing-async/) | WSTG-ATHZ-02 | 8.3.2 L3, 8.2.1 L1, 8.2.2 L1 |
| GT-WEB-CTX-3 | Access and refresh tokens after a revocation event | [Revocation](/web/web-access-control-revocation-sharing-async/) | WSTG-SESS-10, WSTG-SESS-06 | 7.4.1 L1, 7.4.2 L1, 9.2.1 L1, 10.4.8 L2, 10.4.9 L2, 8.3.2 L3 |
| GT-WEB-CTX-4 | API keys, personal access tokens and OAuth grants | [Revocation](/web/web-access-control-revocation-sharing-async/) | WSTG-ATHZ-02, WSTG-ATHZ-05 | 7.4.2 L1, 10.4.9 L2, 10.7.3 L2, 8.3.2 L3 |
| GT-WEB-CTX-5 | Share link token strength, expiry and revocation | [Revocation](/web/web-access-control-revocation-sharing-async/) | WSTG-ATHZ-04, WSTG-ATHZ-02 | 8.2.2 L1, 11.5.1 L2, 14.2.1 L1 |
| GT-WEB-CTX-6 | Share link scope, audience and sharer lifecycle | [Revocation](/web/web-access-control-revocation-sharing-async/) | WSTG-ATHZ-02 | 8.2.2 L1, 8.3.2 L3 |
| GT-WEB-CTX-7 | Exports, reports and download links | [Revocation](/web/web-access-control-revocation-sharing-async/) | WSTG-ATHZ-04, WSTG-ATHZ-02 | 8.2.2 L1, 8.3.2 L3, 14.2.2 L2, 14.3.2 L2 |
| GT-WEB-CTX-8 | Authorisation on every step of a multi-step process | [Revocation](/web/web-access-control-revocation-sharing-async/) | WSTG-BUSL-06, WSTG-ATHZ-02 | 2.3.1 L1, 8.2.1 L1, 2.3.5 L3 |
| GT-WEB-CTX-9 | WebSocket and SSE subscriptions and messages | [Revocation](/web/web-access-control-revocation-sharing-async/) | WSTG-CLNT-10, WSTG-ATHZ-02, WSTG-ATHZ-04 | 4.4.2 L2, 4.4.4 L2, 8.2.2 L1, 8.3.2 L3 |
| GT-WEB-CTX-10 | GraphQL subscriptions | [Revocation](/web/web-access-control-revocation-sharing-async/) | WSTG-APIT-99, WSTG-CLNT-10 | 8.2.2 L1, 8.2.3 L2, 8.3.2 L3 |
| GT-WEB-CTX-11 | Webhook registration and event scoping | [Revocation](/web/web-access-control-revocation-sharing-async/) | WSTG-ATHZ-02, WSTG-ATHZ-03 | 8.2.1 L1, 8.2.2 L1, 8.3.2 L3 |
| GT-WEB-CTX-12 | Confused deputy between services and workers | [Revocation](/web/web-access-control-revocation-sharing-async/) | WSTG-ATHZ-02, WSTG-ATHZ-04 | 8.3.3 L3, 8.3.1 L1 |

## ASVS 5.0 V8 coverage

Every requirement in [ASVS 5.0 V8 Authorization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md), with the tests that produce evidence for it. A requirement is verified at a level only if the application is assessed at that level or higher. An L1 assessment does not fail on `8.3.2`, but we still report what we saw as an observation.

| Requirement | Level | What it asks for (paraphrased) | Verified by |
|---|---|---|---|
| `v5.0.0-8.1.1` | L1 | Documented function-level and data-specific access rules | Documentation review; IDOR-1, PRIV-1 and TEN-1 reconstruct and challenge the rules |
| `v5.0.0-8.1.2` | L2 | Documented field-level read and write rules, including state-dependent ones | Documentation review; BOPLA-1 and BOPLA-12 |
| `v5.0.0-8.1.3` | L3 | Documented environmental and contextual attributes (time, location, IP, device) used in decisions | Documentation review only |
| `v5.0.0-8.1.4` | L3 | Documented use of those attributes in decisions: thresholds and actions (allow, challenge, deny, step-up) | Documentation review only |
| `v5.0.0-8.2.1` | L1 | Function-level access limited to explicit permissions | PRIV-3 to PRIV-10; BYP-1, BYP-2, BYP-3, BYP-5, BYP-6, BYP-9, BYP-11; TEN-5, TEN-6, TEN-11; CTX-2, CTX-8, CTX-11 |
| `v5.0.0-8.2.2` | L1 | Data-specific access limited to explicit permissions (IDOR, BOLA) | IDOR-2 to IDOR-12; PRIV-10; BOPLA-6; TEN-2, TEN-7, TEN-8; CTX-2, CTX-5, CTX-6, CTX-7, CTX-9, CTX-10, CTX-11 |
| `v5.0.0-8.2.3` | L2 | Field-level access limited to explicit permissions (BOPLA) | BOPLA-4, BOPLA-5, BOPLA-7, BOPLA-11, BOPLA-12; PRIV-5; CTX-10 |
| `v5.0.0-8.2.4` | L3 | Adaptive controls on environmental and contextual attributes, at session start and during the session | Not covered by a test in this subcategory; BYP-8 shows whether IP-based trust can be spoofed. Adaptive authentication belongs to the Authentication subcategory (coming next) |
| `v5.0.0-8.3.1` | L1 | Rules enforced in a trusted service layer, not in client-side controls | IDOR-2, IDOR-3, IDOR-5, IDOR-7, IDOR-12; PRIV-3, PRIV-8, PRIV-11; BYP-3, BYP-4, BYP-7, BYP-9 to BYP-12; BOPLA-2; TEN-2, TEN-3; CTX-12 |
| `v5.0.0-8.3.2` | L3 | Changes to authorisation inputs applied immediately, or mitigated where they cannot be | CTX-2, CTX-3, CTX-4, CTX-6, CTX-7, CTX-9, CTX-10, CTX-11; TEN-4, TEN-5 |
| `v5.0.0-8.3.3` | L3 | Decisions based on the originating subject, not an intermediary's permissions | CTX-12; TEN-9 |
| `v5.0.0-8.4.1` | L2 | Cross-tenant controls in multi-tenant applications | TEN-1 to TEN-12 |
| `v5.0.0-8.4.2` | L3 | Layered controls on administrative interfaces; network location never the only factor | PRIV-11; BYP-8; TEN-6, TEN-11 |

Outside V8, the notes also produce evidence for parts of V2 (business logic: `2.3.1`, `2.3.5`), V4 (API and web service: `4.1.3`, `4.1.4`, `4.3.1`, `4.3.2`, `4.4.2`, `4.4.4`), V7 (session management), V9 and V10 (tokens, OAuth), V13 and V15 (configuration and secure coding, including `15.3.3` for mass assignment). The table above lists them per test.

## Rating access-control findings

The series uses one severity scale and one approach to CVSS; both are explained under *Rating findings* in the [series hub](/web/web-application-security-testing-guide/). Each note has its own rating table for its findings. This section collects the conventions those tables share, so that findings from different notes sit in one report without contradicting each other.

### Conventions

1. **Rate the outcome, not the technique.** A trailing slash that reaches the admin panel, a role cookie and a missing middleware registration are all "a member runs admin functions" and get the same rating. Chains are rated by their end result: an IDOR on the administrator's email that leads to admin takeover is rated as admin takeover.
2. **Severity is ours; CVSS is an input.** Base metrics do not capture scale (one record or every record) or sensitivity beyond High and Low. We report the vector honestly and move the severity within or above its band with a stated reason. The commonest case is any user reading every other user's sensitive records: 6.5 in CVSS v3.1, rated High.
3. **Scope Unchanged inside the application.** Horizontal access, vertical escalation, tenant breakout and a tenant user reaching platform administration are all enforced by the same application, so the vulnerable and impacted components share one security authority: `S:U`. We use `S:C` only when the impact lands in a component with its own, separate authority. Examples are a confused deputy that makes a separately authorised downstream service release data, or credentials that reach a cloud account. Tenant breakout is rated High to Critical through the narrative, not through `S:C`. Some teams score tenant breakout as `S:C`; if a client's policy requires it, say so and apply it to every finding in the report.
4. **Availability follows what the reached functions can destroy.** `A:H` when the attacker can delete data, disable accounts or stop the service. Full administrative access normally qualifies, giving 9.8 unauthenticated and 8.8 for any user. When the reached functions only read and edit, use `A:N` (9.1 and 8.1).
5. **Privileges Required.** `PR:N` only when no account is needed. Any registered account is `PR:L`, including one anyone can create by self-registering or starting a trial. We do not lower it to `PR:N`; we raise the severity in the narrative instead. `PR:H` is for roles that require vetting (support staff, an admin role the client grants manually); a self-service tenant administrator is `PR:L`.
6. **Attack Complexity carries identifier and timing difficulty.** `AC:L` for sequential, time-based (UUIDv1) or leaked identifiers. Use `AC:H` for random identifiers that are not exposed anywhere else, for a race against a removal, or for a link someone else must have shared. Re-rate the moment an identifier leak turns up.
7. **Windows are measured.** A documented, short token lifetime after a downgrade is Low; access that never ends is High. State the time you measured.
8. **No reachable server-side gap, no vulnerability.** A hidden menu with correct server checks is Info. Missing authorisation documentation (`8.1.x`) is Low or Info on its own and is cited as the root cause of the findings that follow.

### Typical ratings

Scores calculated with the FIRST v3.1 formulas; check them in the [calculator](https://www.first.org/cvss/calculator/3.1) if you reuse them.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning | Note |
|---|---|---|---|---|
| Unauthenticated access to admin functions that can delete or disable | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | No precondition; full control | PRIV, BYP |
| Unauthenticated read of all users' sensitive data | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | Rated above the band for scale and sensitivity | IDOR, BYP |
| Any user becomes administrator (role field, self-assignment, bypass) | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Critical when self-registration is open and admin reaches all customers' data | PRIV, BOPLA, BYP |
| Tenant user reaches platform administration or a support console | Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Every tenant affected; `S:U` per convention 3, severity raised for scale | PRIV, TEN |
| Tenant selector switches tenant without a membership check | Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Any trial account reaches every tenant without needing IDs | TEN |
| Any user reads and modifies other users' objects, guessable or leaked IDs | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1) | Critical when the whole dataset is reachable and sensitive | IDOR |
| Cross-tenant read and modify by ID | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1) | Breaks the isolation customers pay for | TEN, IDOR |
| Any user reads other users' or tenants' sensitive objects (read only) | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Scale and sensitivity raise it above the base band | IDOR, TEN, BOPLA |
| Ownership, price or status field writable on own objects | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` (6.5) | Integrity of other users' data or direct financial loss | BOPLA |
| Removed or deactivated user keeps read and write access indefinitely | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1) | Former insider; no time limit | CTX, TEN |
| Confused deputy: a separately authorised service releases other users' data | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` (7.7) | `S:C` because the downstream service is a separate authority; `S:U` (6.5) when the worker is part of the same application | CTX |
| IDOR or cross-tenant read with random IDs not exposed anywhere | Medium | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N` (5.3) | The check is missing; obtaining an ID is the hard part | IDOR, TEN |
| Expired or revoked share link still works | Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (5.9) | Needs a link that was once legitimately issued | CTX |
| Delegated admin exceeds their role ceiling | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (7.2) | Privileged precondition, full admin result | PRIV |
| Access token honoured for its documented remaining lifetime after downgrade | Low | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N` (4.2) | Short window the attacker cannot extend | CTX |
| Existence oracle (`403` versus `404`, uniqueness errors across tenants) | Low or Info | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (4.3) | Matters only where existence itself is sensitive | IDOR, TEN |
| Hidden admin UI or client-side route guard, server denies correctly | Info | none | No reachable server-side gap | BYP, PRIV |

## Practice path

A sequence that builds the skills in the order this hub uses them. Run the labs in PortSwigger's hosted environment or locally, never against a shared deployment you do not own.

1. **Function-level basics (PortSwigger).** [Unprotected admin functionality](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality), [Unprotected admin functionality with unpredictable URL](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url), [User role controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter), [User role can be modified in user profile](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile).
2. **Object-level basics (PortSwigger).** [User ID controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter), [with unpredictable user IDs](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids), [with data leakage in redirect](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect), [with password disclosure](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure) (a horizontal-to-vertical chain), [Insecure direct object references](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references).
3. **Bypasses and multi-step flows (PortSwigger).** [URL-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented), [Method-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented), [Multi-step process with no access control on one step](https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step), [Referer-based access control](https://portswigger.net/web-security/access-control/lab-referer-based-access-control), then [Insufficient workflow validation](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation).
4. **APIs and GraphQL (PortSwigger).** [Exploiting an API endpoint using documentation](https://portswigger.net/web-security/api-testing/lab-exploiting-api-endpoint-using-documentation), [Finding and exploiting an unused API endpoint](https://portswigger.net/web-security/api-testing/lab-exploiting-unused-api-endpoint), [Exploiting a mass assignment vulnerability](https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability), [Accessing private GraphQL posts](https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts), [Accidental exposure of private GraphQL fields](https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure), [Finding a hidden GraphQL endpoint](https://portswigger.net/web-security/graphql/lab-graphql-find-the-endpoint).
5. **Real-time channels (PortSwigger).** [Cross-site WebSocket hijacking](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab), as background for CTX-9.
6. **OWASP Juice Shop** ([repository](https://github.com/juice-shop/juice-shop), [companion guide: Broken Access Control](https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html)). Start with *View Basket* and *Admin Section*. Move on to *Five-Star Feedback*, *Forged Feedback*, *Forged Review*, *Manipulate Basket* and *Product Tampering*, then the property-level challenges *Admin Registration* and *Deluxe Fraud* from the [Improper Input Validation chapter](https://pwning.owasp-juice.shop/companion-guide/latest/part2/improper-input-validation.html). Finish with *GDPR Data Theft*, which uses the data export to reach another user's personal data (CTX-7). Juice Shop is a full single-page application, which makes it a good place to practise the Autorize workflow on a real front end.
7. **OWASP crAPI** ([repository](https://github.com/OWASP/crAPI), [challenges](https://github.com/OWASP/crAPI/blob/develop/docs/challenges.md)). An API with GUID identifiers that leak elsewhere. Work through Challenges 1 and 2 (BOLA), 4 and 5 (excessive data exposure), 7 (BFLA), 8 to 10 (mass assignment), 14 (an endpoint without authentication checks) and 18 (a chatbot acting on behalf of another user, a confused deputy).
8. **VAmPI** ([repository](https://github.com/erev0s/VAmPI)). A small REST API with a switch between vulnerable and secure modes. Build an AuthMatrix configuration for it, run it in both modes and compare: BOLA, mass assignment at registration and the `/users/v1/_debug` endpoint should flip from red to green.
9. **Your own two-tenant lab.** None of the common training targets models tenants well. The [multi-tenant isolation note](/web/web-multi-tenant-isolation/) describes a half-day lab with one missing tenant filter, one unchecked tenant header and a row-level security policy that the table owner bypasses. Build it, then run this hub's matrix against it.

## References

**OWASP**

- WSTG Authorization chapter: [overview](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/), [WSTG-ATHZ-02 Bypassing Authorization Schema](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/02-Bypassing_Authorization_Schema/), [WSTG-ATHZ-03 Privilege Escalation](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/03-Privilege_Escalation/), [WSTG-ATHZ-04 Insecure Direct Object References](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/04-Insecure_Direct_Object_References/)
- WSTG API and related tests: [WSTG-APIT-02 API Broken Object Level Authorization](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/02-API_Broken_Object_Level_Authorization/), [WSTG-APIT-03 Excessive Data Exposure](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/03-Excessive_Data_Exposure), [WSTG-APIT-04 API Broken Function Level Authorization](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/04-API_Broken_Function_Level_Authorization/), [WSTG-APIT-99 GraphQL](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/99-GraphQL), [WSTG-INJT-20 Mass Assignment](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/20-Mass_Assignment), [WSTG-BUSL-06 Circumvention of Work Flows](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/10-Business_Logic/06-Circumvention_of_Work_Flows/), [WSTG-CONF-06 HTTP Methods](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/06-HTTP_Methods), [WSTG-CONF-13 Path Confusion](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/13-Path_Confusion)
- ASVS 5.0: [V8 Authorization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md) and the [5.0.0 source tree](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en)
- OWASP Top 10:2025: [A01:2025 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- OWASP API Security Top 10 2023: [API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/), [API5:2023 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- Cheat Sheets: [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [Authorization Testing Automation](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html), [Insecure Direct Object Reference Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html), [Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html), [Multi-Tenant Security](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html)

**CWE**

- [CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html) (the pillar; MITRE discourages it for mapping individual findings), [CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html), [CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html), [CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html), [CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html), [CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

**Scoring**

- FIRST: [CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) (Scope and the security-authority definition), [CVSS v3.1 calculator](https://www.first.org/cvss/calculator/3.1)

**PortSwigger**

- [Access control vulnerabilities and privilege escalation](https://portswigger.net/web-security/access-control), [Insecure direct object references](https://portswigger.net/web-security/access-control/idor)

**Tools**

- Burp extensions: [Autorize](https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f) ([GitHub](https://github.com/PortSwigger/autorize)), [AuthMatrix](https://portswigger.net/bappstore/30d8ee9f40c041b0bfec67441aad158e) ([GitHub](https://github.com/SecurityInnovation/AuthMatrix)), [Auth Analyzer](https://portswigger.net/bappstore/7db49799266c4f85866f54d9eab82c89) ([GitHub](https://github.com/PortSwigger/auth-analyzer))
- [ZAP Access Control Testing add-on](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/)

**Labs**

- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), [OWASP crAPI](https://github.com/OWASP/crAPI), [VAmPI](https://github.com/erev0s/VAmPI)

**Elsewhere on this site**

- [Web Application Security testing guide](/web/web-application-security-testing-guide/) (rules of engagement, set-up, severity scale, reporting)
- [MASVS-AUTH hub](/mobile/masvs-auth-authentication-guide/) and [MASWE-0018 missing authentication on app components](/mobile/maswe-0018-missing-auth-on-app-components/), for the mobile side of the same back-ends
- [AWS Cognito security](/cloud/aws-cognito-security/) and [S3 security](/cloud/aws-s3-security/) (identity pools and pre-signed URLs)
- [Bug Bounty Writeups](/bug-bounty-writeups/)
