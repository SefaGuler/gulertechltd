---
title: "IDOR and BOLA: Testing Object-Level Authorization"
date: 2026-11-15 18:00:00 +0000
subcategory: access-control
summary: "Testing object-level authorisation: where IDs hide, read/write/blind IDOR, ID guessability, GraphQL node IDs, two-account proofs and framework fixes."
refs: [WSTG-ATHZ-04, WSTG-APIT-02, WSTG-APIT-99, v5.0.0-8.2.2, v5.0.0-8.3.1, "API1:2023", "A01:2025", CWE-639, CWE-566, CWE-862, CWE-863]
tags: [web, idor, bola, access-control, api-security, graphql]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Access Control](/web/web-access-control-testing-guide/). It covers object-level authorisation: the check that decides whether *this* user may read, change or delete *this* record. When the check is missing or wrong you get an Insecure Direct Object Reference (IDOR, the WSTG name, `WSTG-ATHZ-04`) or Broken Object Level Authorization (BOLA, the API name, `WSTG-APIT-02` and `API1:2023`). They are the same weakness seen from two angles, and in our experience the single most common high-impact finding in web and API tests. You get the model (where the decision should happen and where identifiers travel), the variants that keep producing findings (nested resources, blind writes, GraphQL global IDs, array-wrapped IDs, legacy API versions, export endpoints), twelve tests that always use two accounts you control, a small replay-and-diff helper, and fixes in Express, Django/DRF, Spring and Laravel with regression tests. Property-level problems (mass assignment, fields you should not see) are in [mass assignment and BOPLA](/web/web-mass-assignment-bopla/); cross-tenant access is in [multi-tenant isolation](/web/web-multi-tenant-isolation/); share links, exports and background jobs are in [revocation, sharing and asynchronous access](/web/web-access-control-revocation-sharing-async/).

## Contents

- [How it works](#how-it-works)
  - [Where the decision belongs](#where-the-decision-belongs)
  - [How a request reaches an object](#how-a-request-reaches-an-object)
  - [Where identifiers live](#where-identifiers-live)
  - [What changes in SPAs, APIs, GraphQL and mobile back-ends](#what-changes-in-spas-apis-graphql-and-mobile-back-ends)
  - [Why an unguessable ID is not authorisation](#why-an-unguessable-id-is-not-authorisation)
- [What goes wrong](#what-goes-wrong)
  - [Unscoped lookups](#unscoped-lookups)
  - [Read, write and delete are checked separately](#read-write-and-delete-are-checked-separately)
  - [Blind IDOR](#blind-idor)
  - [Nested resources where only the parent is checked](#nested-resources-where-only-the-parent-is-checked)
  - [References inside write bodies](#references-inside-write-bodies)
  - [Identity taken from the request](#identity-taken-from-the-request)
  - [Identifier leaks in other responses](#identifier-leaks-in-other-responses)
  - [Parsing and type variants](#parsing-and-type-variants)
  - [Second routes to the same object](#second-routes-to-the-same-object)
  - [GraphQL node queries, batching and aliases](#graphql-node-queries-batching-and-aliases)
  - [Files and attachments](#files-and-attachments)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-WEB-IDOR-1: Inventory object identifiers and where they come from](#gt-web-idor-1-inventory-object-identifiers-and-where-they-come-from)
  - [GT-WEB-IDOR-2: Swap object IDs between two users on read](#gt-web-idor-2-swap-object-ids-between-two-users-on-read)
  - [GT-WEB-IDOR-3: Write and delete on the other user's object](#gt-web-idor-3-write-and-delete-on-the-other-users-object)
  - [GT-WEB-IDOR-4: Nested resources and references in request bodies](#gt-web-idor-4-nested-resources-and-references-in-request-bodies)
  - [GT-WEB-IDOR-5: Identity parameters, headers and token claims](#gt-web-idor-5-identity-parameters-headers-and-token-claims)
  - [GT-WEB-IDOR-6: Identifier predictability and exposure](#gt-web-idor-6-identifier-predictability-and-exposure)
  - [GT-WEB-IDOR-7: Type juggling, arrays, wrapped IDs and parameter pollution](#gt-web-idor-7-type-juggling-arrays-wrapped-ids-and-parameter-pollution)
  - [GT-WEB-IDOR-8: Alternate routes, versions, methods and content types](#gt-web-idor-8-alternate-routes-versions-methods-and-content-types)
  - [GT-WEB-IDOR-9: List, search, bulk and export endpoints](#gt-web-idor-9-list-search-bulk-and-export-endpoints)
  - [GT-WEB-IDOR-10: GraphQL object-level authorisation](#gt-web-idor-10-graphql-object-level-authorisation)
  - [GT-WEB-IDOR-11: Files and attachments](#gt-web-idor-11-files-and-attachments)
  - [GT-WEB-IDOR-12: Full-coverage session-swap replay](#gt-web-idor-12-full-coverage-session-swap-replay)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Node.js and Express](#nodejs-and-express)
  - [Django and Django REST framework](#django-and-django-rest-framework)
  - [Spring Security](#spring-security)
  - [Laravel](#laravel)
  - [GraphQL resolvers](#graphql-resolvers)
  - [Authorisation regression tests](#authorisation-regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Where the decision belongs

Every request that touches stored data answers two questions. **Function level:** may this caller use this operation at all ("may a customer call `PUT /api/orders/{id}`?")? That is covered in [vertical privilege escalation and BFLA](/web/web-vertical-privilege-escalation-bfla/). **Object level:** may this caller use this operation on *this particular record* ("is order 1002 one of hers?")? IDOR and BOLA are failures of the second question. The OWASP API Security Top 10 draws the same line: if the user can reach an endpoint they should not, that is function-level; if they can reach a legitimate endpoint and manipulate the object ID to reach someone else's record, that is object-level.

The object-level decision needs three inputs: the **subject** (who is calling, taken from a server-validated session or token), the **object** (loaded from the database, so you know its real owner, tenant, state and sharing settings), and the **action**. Only the server has all three, which is why ASVS 5.0 puts it in two Level 1 requirements:

- `v5.0.0-8.2.2` (L1): data-specific access is restricted to consumers with explicit permission to the specific data items, explicitly to mitigate IDOR and BOLA.
- `v5.0.0-8.3.1` (L1): authorisation is enforced at a trusted service layer, not by controls the client can manipulate (hiding a button, a client-side route guard, an ID the SPA "would never send").

Function-level checks are usually centralised: a route annotation, a middleware, a gateway rule. Object-level checks cannot be fully centralised in the same way, because they need the object. That is the structural reason this class is so common: the framework gives you `@login_required` or `auth:sanctum` for free, and the per-record check is a line every developer must remember in every handler.

### How a request reaches an object

A typical request goes through the same stages in every framework:

1. **Routing** maps `GET /api/orders/1002` to a handler and extracts `1002` as a path parameter (Express `req.params`, Django URL converters, Spring `@PathVariable`, Laravel route parameters).
2. **Authentication** turns the cookie or bearer token into a user object (`req.user`, `request.user`, the Spring `Authentication`, `$request->user()`).
3. **Function-level authorisation** checks role or scope. This is where most frameworks stop doing anything automatically.
4. **Object loading** runs a query. If the query is `SELECT … WHERE id = 1002`, the ID alone decides what is returned. If it is `WHERE id = 1002 AND owner_id = <current user>`, the query itself is the authorisation check.
5. **Serialisation** returns fields of the object (and sometimes related objects).

Frameworks with "implicit binding" (Laravel route-model binding, Spring Data's domain class converter, DRF's `get_object()`) do step 4 for you, by ID only, before your code runs. Binding is convenient and harmless on its own, but it means the handler receives a fully loaded object of *anyone's*, and the authorisation must come after it (a policy call, `has_object_permission`) or be built into the binding query (DRF `get_queryset`, Laravel scoped bindings).

### Where identifiers live

Treat any value the server uses to pick a record as an object reference, wherever it sits:

| Location | Example | Notes |
|---|---|---|
| Path | `/api/orders/1002`, `/users/77/invoices/9` | The obvious place; nested paths carry two references |
| Query string | `?invoice=12345`, `?accountId=…` | Also in filters: `?owner=`, `?user_id=` on list endpoints |
| JSON or form body | `{"orderId": 1002}`, `{"address_id": 42}` | Including references to *other* objects you attach |
| Headers | `X-Account-Id`, `X-User-Id`, `X-Tenant` | Sometimes set by a gateway and trusted by the back end |
| Cookies | `account=77`, `cart_id=…`, `last_project=…` | Non-session cookies that select an object |
| Token claims | `sub`, `user_id`, `org_id` in a JWT | Safe only when the token is signed, validated and the claim is used as the subject, not as a free choice |
| GraphQL arguments | `order(id: "1002")`, `node(id: "T3JkZXI6MTAwMQ==")` | Global IDs are encoded type-plus-ID |
| Encoded values | base64, hex, Hashids, URL-safe tokens | Encoding is not secrecy; decode and see what is inside |
| File references | `/download?file=inv-1002.pdf`, `/attachments/8f2c…` | Storage keys and pre-signed URLs, see [Files and attachments](#files-and-attachments) |
| WebSocket and SSE messages | `{"subscribe":"order:1002"}` | Subscriptions to another user's channel |

### What changes in SPAs, APIs, GraphQL and mobile back-ends

**SPAs** move rendering to the browser, so the API returns raw objects (often more than the screen shows) and the identifiers are visible in every XHR. The UI usually offers only your own IDs, which tempts developers to treat "the client only sends IDs we gave it" as a control. It is not; `v5.0.0-8.3.1` is the requirement it breaks.

**REST APIs** expose one route per resource, so the number of object-level checks grows with resources × operations. Each `GET`, `PUT`, `PATCH`, `DELETE` and every sub-resource (`/orders/{id}/items`, `/orders/{id}/invoice.pdf`) needs its own check, and they are often written by different people.

**GraphQL** has one endpoint and many resolvers. Authorisation lives in resolvers (or in a layer they call), and GraphQL itself enforces nothing (WSTG-APIT-99 says as much). Relay-style schemas add a `node(id:)` field that can fetch any type by a global ID, which bypasses every type-specific query you thought you had protected.

**Mobile back-ends** are frequently separate API deployments (`/mobile/v3/`, `m-api.example.com`) built by a different team, sometimes with weaker checks because "only our app calls it". They are fully reachable from a proxy once you intercept the app (see [missing authentication on app components](/mobile/maswe-0018-missing-auth-on-app-components/) for the mobile side).

### Why an unguessable ID is not authorisation

Random identifiers lower *exploitability*: an attacker who cannot learn or guess your ID cannot request it. They do not make the endpoint authorised. RFC 9562, the current UUID specification, says implementations should not assume UUIDs are hard to guess and must not use them as security capabilities, that is, identifiers whose possession alone grants access. Identifiers leak constantly: in list and search responses, shared URLs, notification emails, referrer headers, logs, analytics, browser history, other users' screens. The OWASP IDOR Prevention Cheat Sheet and `API1:2023` both treat random IDs as defence in depth next to the per-object check, never as a replacement for it.

Not all "random-looking" IDs are random:

| Identifier | What it encodes | Guessability |
|---|---|---|
| Auto-increment integer | Row number | Trivial; neighbours of your own IDs are other users' objects |
| UUIDv1 (version digit `1`) | 60-bit timestamp, clock sequence, node (often MAC-derived) | Predictable from a nearby sample and a time estimate; see the "sandwich" research in [Real-world cases](#real-world-cases) |
| UUIDv4 (version digit `4`) | 122 random bits | Not guessable if generated with a CSPRNG; still leaks |
| UUIDv7 (version digit `7`) | 48-bit Unix millisecond timestamp, then random bits | Not practically guessable, but reveals creation time and sorts by it |
| MongoDB ObjectId | Timestamp, a per-process random value, an incrementing counter | Neighbours of an ID from the same process are close; treat as weakly predictable |
| Snowflake-style IDs | Timestamp, worker, sequence | Predictable within a time window |
| Hashids / Sqids | An integer, reversibly encoded with a shuffled alphabet | The Sqids FAQ says the IDs are not hashes and can be decoded; the old "salt" was never a security feature |
| base64 or hex of an integer | The integer | Decode, increment, re-encode |
| Hash of an integer (`md5(1002)`) | The integer | Hash candidate integers and compare |
| GraphQL global ID | base64 of `Type:123` or `gid://app/Type/123` | Decode and edit the type or the number |

The useful habit: take one of your own IDs, find out what it really is (decode it, check the UUID version nibble, compare two IDs created a second apart), and only then decide how exploitable a missing check is. The [rating](#rating-findings) depends on it; the finding does not.

## What goes wrong

### Unscoped lookups

**What happens:** the handler loads by ID only (`Order.objects.get(pk=pk)`, `orderRepository.findById(id)`, `Order::findOrFail($id)`, `db.order.findUnique({ where: { id } })`) and returns the result. Authentication worked, the role check passed, and nothing compared the order's owner to the caller.

**Why it matters:** every object of that type is reachable by every authenticated user. With sequential IDs the whole table is reachable.

**Where to look:** detail endpoints (`GET /resource/{id}`), PDF and receipt rendering, "print" and "preview" views, old server-rendered pages kept alongside a new API.

### Read, write and delete are checked separately

**What happens:** the developer protected `GET /api/orders/{id}` after a pentest finding, but `PATCH`, `DELETE`, `POST /api/orders/{id}/cancel` and `POST /api/orders/{id}/refund` are separate handlers and were not touched.

**Why it matters:** write and delete IDOR are usually worse than read: changing another user's delivery address, cancelling their booking, deleting their documents. `API1:2023` scenario 3 is exactly this (a GraphQL delete mutation with no permission check).

**Where to look:** every state-changing operation on an object, especially "action" endpoints (`/approve`, `/cancel`, `/share`, `/transfer`, `/invite`) that are not plain CRUD.

### Blind IDOR

**What happens:** a write succeeds on someone else's object but the response echoes nothing useful: `204 No Content`, `{"ok":true}`, or even an error. HackerOne report 1501611 (see [Real-world cases](#real-world-cases)) is a good example: the server answered that the object was not found, yet the change had been applied.

**Why it matters:** testers who judge by the response miss it, and so do scanners and Autorize-style tools that compare response bodies.

**Where to look:** any write, and any notification-style action (resend invite, add comment, attach a file). You confirm it by looking at the object **from its owner's session**, which is why you need your own second account.

### Nested resources where only the parent is checked

**What happens:** `GET /api/users/{userId}/orders/{orderId}` verifies that `userId` is the caller, then loads `orderId` by ID alone. Or the reverse: `/projects/{projectId}/files/{fileId}` checks membership of `projectId` and never checks that `fileId` belongs to that project. GitLab's external status check IDOR (HackerOne 1372216) had this shape: the project in the path was authorised, the status-check ID in the body was not scoped to it.

**Why it matters:** put your own ID in the parent position and someone else's in the child position, and every child of every parent is reachable.

**Where to look:** any route with two or more IDs; child IDs sent in bodies of nested routes; frameworks where nested routes are declared but not scoped (Laravel without `scopeBindings()`, DRF nested routers with a `get_queryset` that filters only on the parent).

### References inside write bodies

**What happens:** a create or update body references another object: `{"shipping_address_id": 42}`, `{"payment_method_id": "pm_…"}`, `{"folder_id": 9}`, `{"assignee_id": 31}`. The server validates that 42 exists, not that it is yours.

**Why it matters:** you attach another user's object to your own: ship to their saved address and read it back on your order, charge their stored card, move your document into their folder (and then list the folder), or assign work to people outside your organisation. These are easy to miss because the object being written *is* yours.

**Where to look:** every foreign key in a request body; DRF `PrimaryKeyRelatedField` with an unscoped `queryset`; Rails/Laravel `*_id` fields in fillable attributes.

### Identity taken from the request

**What happens:** the request names the user it acts for: `POST /changepassword?user=alice` (the WSTG example), `{"user_id": 77, "email": "…"}` on a profile update, an `X-User-Id` header that a gateway is supposed to set, or a cookie such as `uid=77` next to the real session cookie.

**Why it matters:** this is IDOR on the user object itself, often leading to account takeover (change email or password of another user). Where a header is meant to be set by an intermediary, ASVS `v5.0.0-4.1.3` (L2) requires that the end user cannot override it. Token claims are fine as the subject *if* the token is properly verified; forging or tampering with tokens belongs to the Authentication and Session subcategories (not yet published), and header-based trust is covered in [authorisation bypass techniques](/web/web-authorization-bypass-techniques/).

**Where to look:** profile, settings, password, email, MFA and notification-preference endpoints; any body field or header whose name contains `user`, `account`, `member`, `customer`, `owner`.

### Identifier leaks in other responses

**What happens:** the detail endpoint uses UUIDv4, but another response hands the UUIDs out: a public profile, a comment thread, a search or autocomplete endpoint, an "invite colleague" lookup, a notification feed, a WebSocket broadcast, an email link, a redirect `Location` header, a sitemap, or an error message. crAPI's first BOLA challenge is built around this: vehicle IDs are GUIDs, and you have to find where another user's GUID is exposed first.

**Why it matters:** it turns a "UUIDs, so Low" finding into a practical one. Report the leak and the missing check together, because each makes the other worse.

**Where to look:** everything that shows other users' content to you: social features, shared workspaces, marketplace listings, reviews, chat, collaboration, activity feeds.

### Parsing and type variants

**What happens:** the authorisation code and the data-access code read the same parameter differently:

- **Type juggling.** The check compares `order.owner_id == body.user_id` loosely, or a JSON `true`, `0`, `null` or `"1002abc"` is coerced in one layer and not the other. PHP loose comparison and JavaScript `==` are the classic sources.
- **Arrays and wrapped values.** `{"id": [1001, 1002]}` reaches an ORM that turns arrays into `WHERE id IN (…)`, while the check validated only the first element. `{"id": {"id": 1002} }` or `{"order": {"id": 1002} }` reaches a deserialiser that unwraps it after a check that saw "not an integer" and skipped. Query strings do the same with `?id[]=1001&id[]=1002` or `?id=1001,1002` (the exact behaviour depends on the query parser in use).
- **Parameter pollution.** `?id=1001&id=1002`: the check reads the first value, the handler the last, or a proxy reads one and the back end the other (WSTG-INJT-04 covers HTTP parameter pollution in general).
- **Duplicate sources.** The ID is accepted from path, query and body; the check reads the path, the handler prefers the body.
- **Encoding and normalisation.** `1002` versus `01002`, `1002.0`, `+1002`, `%31%30%30%32`, a different case of a UUID. Usually the database normalises, the check does not.

**Why it matters:** these are not separate vulnerabilities but ways to reach a missing or partial check that the obvious request does not hit. They are worth trying only when the plain swap is blocked.

**Where to look:** JSON APIs in Node.js (body and query parsers that build nested objects), PHP, and anywhere a validation layer sits in front of an ORM.

### Second routes to the same object

**What happens:** the object is reachable by more than one handler and only some of them check:

- **Old API versions.** `/api/v2/orders/{id}` was fixed, `/api/v1/orders/{id}` still runs the old code (`API9:2023` Improper Inventory Management is about exactly this kind of forgotten version).
- **Mobile and partner back-ends.** `/mobile/api/…`, `/partner/…`, `/internal/…` served by the same app with different middleware.
- **Alternate methods and content types.** A `POST` with `X-HTTP-Method-Override: DELETE`, a `PUT` that reaches a legacy form handler, `application/x-www-form-urlencoded` or XML hitting a different controller than JSON. The general technique of method and header tampering is in [authorisation bypass techniques](/web/web-authorization-bypass-techniques/); here you only care whether it reaches an *object* without a check.
- **Export, print and bulk endpoints.** `GET /api/orders/1002/export.csv`, `/reports?ids=…`, `/batch` endpoints that accept many operations in one request and authorise the batch, not each item.
- **Suffixes and formats.** `/orders/1002.json`, `/orders/1002?format=pdf`, `/orders/1002/print`.

**Where to look:** API documentation (OpenAPI, Postman collections), JavaScript bundles, mobile app traffic, `robots.txt` and old documentation that mention earlier versions.

### GraphQL node queries, batching and aliases

**What happens:** the schema protects `order(id:)` but also implements the Relay `Node` interface, so `node(id: "<global ID of someone else's order>")` resolves through a generic loader without the order-specific check. Many schemas also expose `nodes(ids: [...])` (GitHub's public API is one), which fetches many objects in one request. Aliases let one query ask for the same field many times with different arguments, and some servers accept arrays of operations in one HTTP request; both turn a single-object IDOR into many objects per request and defeat per-request rate limits (WSTG-APIT-99 covers batching and aliases).

**Why it matters:** HackerOne report 447930 shows the pattern well: the public identifier was a random UUID, but the `node` interface accepted a global ID built from the sequential primary key, and returned the UUID. One generic resolver undid the protection the UUID was meant to provide.

**Where to look:** introspection or the schema (InQL, clairvoyance if introspection is off), `Node` implementations, mutations taking an `id` input, nested resolvers (`order { customer { addresses } }`) that load related objects without their own check.

### Files and attachments

**What happens:** the download handler serves `/files/{fileId}` or `/download?file=inv-1002.pdf` without checking the file's owning record; files sit in a public bucket under predictable keys; or a pre-signed URL is issued to anyone who asks with an ID.

**Why it matters:** attachments are often the most sensitive data in the application: invoices, identity documents, medical letters, payslips.

**Where to look:** upload responses (they return the new file's ID or URL), message attachments, avatar and document endpoints, CDN or object-storage hostnames in responses. Pre-signed S3 URLs are covered in [S3 security](/cloud/aws-s3-security/); share links and capability URLs are in [revocation, sharing and asynchronous access](/web/web-access-control-revocation-sharing-async/).

## Testing

Every test below assumes an authorised engagement with written scope and rules of engagement, a bug bounty programme whose rules allow this testing, or a deliberately vulnerable lab. Requests and responses are illustrative: hosts, IDs and bodies are made up, and real applications will differ in detail.

### Before you start

**Accounts.** Object-level testing is a comparison between identities, so ask for (or register) at least:

| Identity | Why |
|---|---|
| User A and user B, same role | The core horizontal test: A's session against B's objects and back |
| User C in a different role (for example "viewer" or "manager") | Object rules that depend on role inside the same organisation |
| An admin account, if the client provides one | To see the full set of object types and actions, and to confirm what admin should and should not reach |
| Two tenants or organisations (A1, A2 in tenant 1; B1 in tenant 2) | Same-org sharing hides IDOR; the cross-tenant variant is in [multi-tenant isolation](/web/web-multi-tenant-isolation/) |
| No session | Some object endpoints do not require authentication at all |

Create test objects in each account with recognisable markers so you can spot them anywhere: an order note `GT-A-canary-01`, a document titled `GT-B-canary-01`, an address line `GT-B street`. Record every ID you create, per account, in a small table. Every cross-account proof in this note targets **your own other account's** object from that table, never a real customer's.

**Stop on real data.** If any request returns data that is not from one of your accounts (a real customer's name, address, document), stop that line of testing, keep only the minimum redacted evidence needed to report it (status, endpoint, a masked field), do not download or keep more, and report it to the client or programme immediately. Do not "confirm" by requesting more records.

**No enumeration.** Do not iterate identifiers through ranges you do not own. Iteration in Burp Intruder, ffuf or a script is limited to IDs you created, a small range the client agreed to in writing, or a lab, at a low request rate (one or two requests per second is a sensible default unless the rules say otherwise).

**Burp setup.**

- One Burp project per engagement, target scope set to the in-scope hosts, Logger enabled so you have every request.
- Two browser profiles (or Firefox containers) proxied through Burp, one logged in as A and one as B. Label them clearly; most mistakes in this testing are "I was in the wrong session".
- Install **Autorize**, **AuthMatrix** and **Auth Analyzer** from the BApp Store, plus **InQL** for GraphQL and **Param Miner** for discovering hidden parameters.

**Session-swap workflow (the core loop).**

1. In Autorize, paste B's cookie or `Authorization` header into the low-privilege header box (Autorize replaces the header if present, adds it if missing), tick "Check unauthenticated", set an interception filter to the in-scope host, and switch it on.
2. Browse the application as **A**, using every feature that touches A's objects. Autorize replays each request with B's credentials and without credentials and colours the result: *Bypassed!* (B or anonymous got the same as A), *Enforced!*, or *Is enforced???* (it needs an enforcement fingerprint, such as a body string your app returns on denial).
3. Configure enforcement detectors early (for example "body contains `not_found`" or "status 404"), otherwise Autorize marks many responses as uncertain.
4. Treat Autorize's results as **leads**. Confirm each "Bypassed!" by hand in Repeater, and remember that Autorize only sees reads well; blind writes need a check from the owner's session.
5. For applications with CSRF tokens or per-session parameters, **Auth Analyzer** can extract values (from `Set-Cookie`, HTML inputs or JSON keys) per session and substitute them, and it labels replays as `SAME` or `SIMILAR` to the original. For a documented role × request matrix you can re-run after a fix, use **AuthMatrix**: define users and roles, add requests, mark which roles should succeed, and run the whole matrix.

ZAP users get similar coverage from the **Access Control Testing** add-on, which replays a context's requests as different users and compares the results with rules you define.

**Rate and side effects.** Session-swap tools replay *everything* you do as A, including writes. When you browse as A through Autorize, a `DELETE` you send for A is replayed as B against A's object. That is the point of the test, but it means: only use Autorize on accounts and objects you own, and turn it off before exercising destructive features you have not planned for.

### GT-WEB-IDOR-1: Inventory object identifiers and where they come from

*Guler Tech methodology.* Implements the mapping step of WSTG-ATHZ-04 and WSTG-APIT-02, using WSTG-INFO-06 (entry points) and WSTG-APIT-01 (API reconnaissance).

#### What it checks

Which requests carry object references, of which type, in which location, and where each kind of identifier is disclosed. The output is the work list for tests 2 to 11 and the input to the [rating](#rating-findings).

#### Prerequisites

Accounts A and B with seeded objects; Burp Logger history from a full walk-through as A; API documentation if available (OpenAPI, Postman collection, GraphQL schema).

#### Steps

1. Walk every feature as A with Logger on: create, view, edit, delete, share, export, download, every settings page.
2. Filter Logger (or export it) for requests whose path, query, body, headers or cookies contain any ID from your seed table. Also look for values that *look* like IDs: integers, UUIDs, base64 strings, short alphanumeric codes.
3. For each identifier, record: object type, location, format, operations that use it (read, update, delete, actions), and whether the request also carries a second ID (parent or reference).
4. Classify the format. Check the UUID version nibble (the first character of the third group: `xxxxxxxx-xxxx-1xxx-…` is v1, `4xxx` is v4, `7xxx` is v7). Decode base64 and Hashids-looking values. Create two objects a few seconds apart and compare their IDs.
5. Look for disclosure of **B's** identifiers in responses A can see: lists, search, comments, notifications, WebSocket frames (Burp's WebSockets history), emails sent to A, redirects, error messages.
6. Pull extra endpoints from the JavaScript bundles, the mobile app, and old API versions (`/v1/`, `/api/` without a version). Note which ones you could not reach from the UI.

```bash
# Quick look at what an identifier really is (illustrative values)
echo 'T3JkZXI6MTAwMQ==' | base64 -d; echo         # -> Order:1001
echo 'Z2lkOi8vc2hvcC9PcmRlci8xMDAx' | base64 -d; echo   # -> gid://shop/Order/1001
python3 -c "import uuid; print(uuid.UUID('1b4e28ba-2fa1-11d2-883f-0016d3cca427').version)"   # -> 1
```

#### Observation

A table like this (illustrative):

| Request | Object | Location | Format | Ops | Leaks elsewhere |
|---|---|---|---|---|---|
| `GET /api/orders/1001` | order | path | integer, sequential | R | order list |
| `PATCH /api/orders/1001` | order | path | integer | U | |
| `POST /api/orders/1001/items` | order, product | path, body `product_id` | integer | C | catalogue |
| `PUT /api/me/address` | address | body `address_id` | UUIDv4 | U | none seen |
| `GET /files/8b1c…` | attachment | path | UUIDv1 | R | message thread |
| `POST /graphql` `node(id:)` | any | argument | base64 `Type:id` | R | everywhere |

#### Evaluation

This test produces no finding by itself except disclosure: report identifiers of other users exposed without need (B's UUIDs in a public list, email addresses in an autocomplete) as information exposure, rated by what is disclosed. Weak identifier formats (sequential, UUIDv1) are not findings on their own; they raise the severity of any missing check found later.

#### False positives

IDs that are public by design (product IDs, public post IDs, usernames on a social site). Disclosure of an ID the other user deliberately shared with you.

#### Automation

Param Miner and Arjun can discover unlinked parameters (`user_id`, `account`) on endpoints you found. For CI, keep an inventory of routes from the framework (`php artisan route:list`, Spring Actuator `mappings` in a test profile, DRF schema generation, Express route introspection in tests) and fail the build when a route that takes an object ID has no registered authorisation test (see [regression tests](#authorisation-regression-tests)).

### GT-WEB-IDOR-2: Swap object IDs between two users on read

*Guler Tech methodology.* Implements WSTG-ATHZ-04 and WSTG-APIT-02 for read operations.

#### What it checks

Whether B, authenticated normally, can read A's object by putting A's identifier into a request B is allowed to make, and the same in reverse.

#### Prerequisites

Accounts A and B; at least one object of each type per account; the inventory from GT-WEB-IDOR-1.

#### Steps

1. As A, capture a read of A's object:

```http
GET /api/orders/1001 HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
Accept: application/json
```

2. Send it to Repeater and replace the credential with **B's**, leaving A's ID in place:

```http
GET /api/orders/1001 HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_B>
Accept: application/json
```

3. Repeat in the other direction (A's session, B's ID), then without any credential.
4. Repeat for every location where the identifier appears: query (`?orderId=1001`), body, custom header, non-session cookie.
5. Repeat for every object type in the inventory, and for sub-resources (`/orders/1001/items`, `/orders/1001/invoice`).

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
  -H 'Authorization: Bearer <TOKEN_USER_B>' https://api.example.com/api/orders/1001
```

#### Observation

Vulnerable (B reads A's order, illustrative):

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id":1001,"owner":"user-a@example.org","note":"GT-A-canary-01","address":"1 Test Road","total":"42.00"}
```

Correct:

```http
HTTP/1.1 404 Not Found
Content-Type: application/json

{"error":"not_found"}
```

#### Evaluation

- **Fail:** B receives any part of A's object (the canary marker, A's address, A's email), or the response for A's ID differs from the response for a non-existent ID in a way that reveals the object exists and returns its data.
- **Pass:** `403` or `404` (or the application's normal denial body) for B and for the anonymous request, while A still gets `200`.
- A `403` for A's ID and a `404` for a non-existent ID is not IDOR, but it confirms existence; mention it as Low where the existence of an object is itself sensitive. The IDOR Prevention Cheat Sheet suggests answering both cases the same way when that matters.

#### False positives

- **Public by design:** published posts, public profiles, shared catalogue items. Check the business rule before reporting.
- **Same organisation:** A and B can legitimately see each other's objects because they share a workspace. Repeat with B in a different organisation before you call it.
- **Cached responses:** a CDN or reverse proxy served A's cached response to B. Look for `Age`, `X-Cache: HIT` or `CF-Cache-Status: HIT`, and repeat with a cache-busting query parameter. If it really is the cache, that is a different finding (web cache deception or poisoning, in the HTTP & infrastructure subcategory, not yet published).
- **`200 OK` with an error body:** `{"success":false,"error":"forbidden"}` is a denial. Read the body, not just the status.
- **Your own data shape:** an endpoint that ignores the ID and always returns the caller's own object (B gets B's order whatever ID it sends). Compare the canary, not the status.

#### Automation

Autorize or Auth Analyzer flag candidates during browsing; AuthMatrix or the helper in [GT-WEB-IDOR-12](#gt-web-idor-12-full-coverage-session-swap-replay) re-runs them. In CI, every detail endpoint gets a test that requests a fixture object owned by another user and asserts `404` (see [regression tests](#authorisation-regression-tests)).

### GT-WEB-IDOR-3: Write and delete on the other user's object

*Guler Tech methodology.* Implements WSTG-ATHZ-04 ("parameter used to perform an operation") and the method coverage of WSTG-APIT-02. **Own test objects only.**

#### What it checks

Whether B can update, perform actions on, or delete A's object, including writes that return no data (blind IDOR).

#### Prerequisites

Accounts A and B; dedicated test objects in A's account created for this test; agreement with the client on which destructive actions you may exercise.

#### Steps

1. Start with the least destructive write: a harmless field on A's object, such as a note or a display name. As B (**own test objects only**):

```http
PATCH /api/orders/1001 HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_B>
Content-Type: application/json

{"note":"GT-B-was-here-01"}
```

2. **Verify from A's session**, whatever B's response said:

```bash
curl -s -H 'Authorization: Bearer <TOKEN_USER_A>' https://api.example.com/api/orders/1001 | jq .note
```

3. Repeat for `PUT`, every action endpoint (`POST /api/orders/1001/cancel`, `/share`, `/approve`), and only then `DELETE`, against an object in A's account that you created to be deleted.
4. For actions with side effects outside the app (emails, payments, shipping), agree with the client first and prefer a staging environment.
5. Restore A's object afterwards (set the note back, recreate the deleted object) and record what you changed.

#### Observation

A blind write looks like this from B's side (illustrative):

```http
HTTP/1.1 404 Not Found
Content-Type: application/json

{"error":"not_found"}
```

and like this from A's side a moment later:

```json
"GT-B-was-here-01"
```

#### Evaluation

- **Fail:** the change is visible from A's session, regardless of the status code B received. For deletes, A's object is gone or marked deleted.
- **Pass:** B's request is denied and A's object is unchanged when re-read by A.
- Note which operations fail separately; read protected and write unprotected (or the reverse) is common and the fix must cover each handler.

#### False positives

- Writes that are queued and rejected later by a worker (check again after the queue runs before you call it).
- Collaborative objects where B is a legitimate editor (shared document, same project).
- A response that echoes B's input without persisting it; always verify by re-reading as A.

#### Automation

Autorize replays writes but judges by the response, so it misses blind writes; add a "read back as owner" step to your manual checklist. In CI, write tests that perform the write as a non-owner and then assert both the denial *and* that the stored object is unchanged.

### GT-WEB-IDOR-4: Nested resources and references in request bodies

*Guler Tech methodology.* Implements WSTG-ATHZ-04 (references split across several parameters) and WSTG-APIT-02.

#### What it checks

Whether every identifier in a request is checked, not just the first: child IDs under a parent you own, and references to other objects inside write bodies.

#### Prerequisites

Accounts A and B with parent-child objects (A's project with A's file; B's project with B's file); write endpoints that reference other objects (addresses, payment methods, folders, assignees).

#### Steps

1. **Parent yours, child theirs.** As B, keep B's parent and put A's child:

```http
GET /api/users/2002/orders/1001 HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_B>
```

(`2002` is B's own user ID, `1001` is A's order.)

2. **Parent theirs, child theirs.** `GET /api/users/2001/orders/1001` as B. If this is blocked but step 1 works, the check is on the parent only.
3. **Mismatched pairs.** Combine A's project with B's file and B's project with A's file in both sessions; some code checks "the user can see the project" and "the file exists" but never "the file belongs to the project".
4. **References in bodies.** As B, create or update B's own object referencing A's related object (**own test objects only**):

```http
POST /api/orders HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_B>
Content-Type: application/json

{"items":[{"product_id":17,"qty":1}],"shipping_address_id":"7d3f0c1e-9a51-4c0e-8f7b-3b2a9e6c1d40"}
```

where the address ID is one of A's saved addresses. Then read B's new order and check whether A's address appears in it.

5. Do the same for every `*_id` field you saw in the inventory: `payment_method_id`, `folder_id`, `parent_id`, `template_id`, `assignee_id`, `attachment_ids`.

#### Observation

Vulnerable reference (illustrative): B's new order comes back with `"shipping_address": {"line1": "GT-A street", "postcode": "…"}`, A's address, readable by B on B's own order.

#### Evaluation

- **Fail:** any combination returns or acts on an object not owned by (or shared with) the caller; any write accepts a reference to another user's object and either discloses it or links it.
- **Pass:** every mismatched combination is denied, and references to objects the caller cannot see are rejected (`400` or `404`).

#### False positives

References to objects that are meant to be shared (public product IDs, a team member you may assign). Check what "assignable" means in the business rules: assigning a ticket to a user in another organisation is usually a finding; assigning it to a colleague is not.

#### Automation

AuthMatrix handles multi-ID requests if you add them manually per role. In CI, add a test per nested route with a mixed fixture (caller's parent, other user's child) and a test per foreign-key field that references another user's object.

### GT-WEB-IDOR-5: Identity parameters, headers and token claims

*Guler Tech methodology.* Implements WSTG-ATHZ-04 (the `changepassword?user=` scenario) and WSTG-APIT-02.

#### What it checks

Whether the server takes "who is acting" or "whose account" from a request value the client controls, instead of from the authenticated session.

#### Prerequisites

Accounts A and B; profile, settings, password, email and preferences endpoints from the inventory; A's and B's user IDs (both are yours).

#### Steps

1. Look for user identifiers in requests that operate on "me": body fields (`user_id`, `account_id`, `customer`), query (`?user=`), custom headers (`X-User-Id`, `X-Account-Id`), non-session cookies (`uid`, `account`).
2. As B, change the value to A's ID on a **read** first (**own test objects only**):

```http
GET /api/profile?user_id=2001 HTTP/1.1
Host: api.example.com
Cookie: session=<SESSION_USER_B>
```

3. Then on a harmless **write** (a display-name or preference change), and verify from A's session.
4. Add identity headers that the front end never sends but an internal gateway might (`X-User-Id: 2001`, `X-Forwarded-User: user-a`) and see whether the answer changes. If it does, the full technique is in [authorisation bypass techniques](/web/web-authorization-bypass-techniques/).
5. If the session is a JWT, decode it (do not paste real tokens into online decoders) and note which claims identify the user and tenant. Check whether the API also accepts those values as parameters, and which one wins when they disagree. Do not attempt signature attacks under this test; they belong to the Authentication and Session subcategories.
6. Only with explicit client approval and on A's test account: try the sensitive variants (email change, password change, MFA reset) on A's account from B's session. These are account takeover if they work.

#### Observation

Vulnerable (illustrative): `GET /api/profile?user_id=2001` as B returns A's profile; or `PUT /api/profile` with `{"user_id":2001,"display_name":"GT-B-01"}` as B changes A's display name.

#### Evaluation

- **Fail:** any request acts on or returns another user's account when the client changes an identity value.
- **Pass:** the server ignores identity values in the request (always uses the session) or rejects them when they differ from the session.

#### False positives

Admin or support endpoints where acting on other users is the intended function (test those as function-level in [vertical privilege escalation](/web/web-vertical-privilege-escalation-bfla/)). Parameters that are accepted but ignored: always check *whose* data came back.

#### Automation

Param Miner's header guessing can find identity headers the back end reads. In CI, test that "me" endpoints ignore or reject a foreign `user_id`, and that the API gateway strips identity headers sent by clients.

### GT-WEB-IDOR-6: Identifier predictability and exposure

*Guler Tech methodology.* Supports WSTG-ATHZ-04 and WSTG-APIT-02 (collecting third-party identifiers); it does not replace the authorisation tests.

#### What it checks

How an attacker would obtain another user's identifier in practice: by guessing it (format) or by finding it (disclosure). The result sets the exploitability part of every IDOR finding.

#### Prerequisites

Inventory from GT-WEB-IDOR-1; the ability to create several objects in A's and B's accounts.

#### Steps

1. Create five objects in A's account, then five in B's, then five more in A's, a few seconds apart. Compare all fifteen IDs.
   - Integers interleaving between A and B mean a shared sequence: B's IDs sit between A's.
   - UUIDv1 or time-based IDs created by B between two of A's are bounded by A's IDs (the "sandwich" idea). Note the timestamp portion and how far apart they are; do not try to brute-force the space outside a lab.
   - For Hashids/Sqids-style codes, check whether they are short, change by one character between neighbours, and decode consistently; the Sqids FAQ is explicit that these are encodings, not hashes.
2. Check where **B's** identifiers appear to A without any attack: B's public profile, shared spaces, comments, search, autocomplete ("invite a colleague"), activity feeds, notifications, WebSocket broadcasts, emails A receives, `Location` headers, error messages.
3. Search the client-side code and responses for embedded ID lists (initial state JSON in the page, `__NEXT_DATA__`, GraphQL caches).
4. If the client has agreed a small range for iteration, run it only over IDs between your own objects, slowly:

```bash
# Bounded check over IDs between your own objects 1001..1015 only, 1 request per second.
seq 1001 1015 > own-range.txt
ffuf -u https://api.example.com/api/orders/FUZZ -w own-range.txt \
     -H 'Authorization: Bearer <TOKEN_USER_B>' -rate 1 -mc all -o ffuf-own-range.json
```

#### Observation

Illustrative: A's orders are 1001, 1002, 1003, 1011…; B's are 1004 to 1008. The sequence is global and shared between customers, so any customer's neighbours are other customers' orders. Attachment IDs are UUIDv1 and appear in message threads visible to all participants.

#### Evaluation

This test does not produce an IDOR finding by itself. It produces:
- an exploitability statement per object type for the [rating](#rating-findings) ("sequential, shared across customers", "UUIDv4, not exposed elsewhere", "UUIDv4, exposed in search results");
- separate findings for disclosure of other users' identifiers or personal data in responses that should not carry them (rated by sensitivity, often Low or Medium);
- an informational note where security-relevant tokens (reset tokens, invite codes, share links) use UUIDv1 or other predictable formats; that is a finding in its own right for those flows.

#### False positives

Sequential IDs on public objects. Disclosure that is intended (a teammate list in a shared workspace). Do not report "uses integers" as a vulnerability without a missing check.

#### Automation

Not much beyond scripts that collect your own IDs and classify them. A unit test that asserts new objects get UUIDv4 or v7 IDs is reasonable defence in depth, but the authorisation tests matter more.

### GT-WEB-IDOR-7: Type juggling, arrays, wrapped IDs and parameter pollution

*Guler Tech methodology.* Extends WSTG-ATHZ-04 and WSTG-APIT-02 with input-format variants; parameter pollution is WSTG-INJT-04.

#### What it checks

Whether a check that blocks the plain swap can be bypassed by sending the identifier in a form the check and the data layer interpret differently.

#### Prerequisites

An endpoint where the plain swap from GT-WEB-IDOR-2 or GT-WEB-IDOR-3 is denied; A's and B's IDs of the same type.

#### Steps

As B, against A's object (and, for writes, **own test objects only**), try one variant at a time and compare with the denied baseline:

1. **Arrays:** `{"id":[1001]}`, `{"id":[2005,1001]}` (B's own ID first, A's second), `?id[]=2005&id[]=1001`, `?id=2005,1001`.
2. **Wrapped objects:** `{"id": {"id": 1001} }`, `{"order": {"id": 1001} }`, `{"id": {"$eq": 1001} }` (the last one only where a document database is in use; operator injection proper belongs to Injection, not yet published).
3. **Types:** `{"id":"1001"}` versus `{"id":1001}`, `1001.0`, `"01001"`, `true`, `null`, and for UUIDs a different case.
4. **Parameter pollution:** `?id=2005&id=1001` and `?id=1001&id=2005`; the same ID in path and body with different values; the same JSON key twice in one body (`{"id":2005,"id":1001}`; parsers usually keep the last).
5. **Location:** the ID the check reads (path) set to B's, and a second copy in query or body set to A's.

```http
POST /api/orders/lookup HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_B>
Content-Type: application/json

{"id":[2005,1001]}
```

#### Observation

Vulnerable (illustrative): the response is an array that contains B's order 2005 *and* A's order 1001, because the check validated the first element and the ORM loaded both.

#### Evaluation

- **Fail:** any variant returns or acts on A's object while the plain request is denied. Report the root cause (the check and the lookup read different values) as well as the payload.
- **Pass:** all variants are rejected with `400` (strict input validation) or denied like the baseline.

#### False positives

A `500` error is not a bypass, although it can point to type confusion worth a closer look. Arrays that return only B's own objects are fine.

#### Automation

These are hand-crafted in Repeater. In CI, parameter validation tests (the ID must be a single integer or a single UUID string) catch most of the class: reject anything else before it reaches the lookup.

### GT-WEB-IDOR-8: Alternate routes, versions, methods and content types

*Guler Tech methodology.* Implements WSTG-APIT-02 (different HTTP methods) and WSTG-ATHZ-04 across every route that reaches the same object.

#### What it checks

Whether the object-level check exists on *every* handler that reaches the object, not only the one the current UI uses.

#### Prerequisites

Inventory with all versions and back-ends found (web API, mobile API, partner API, legacy pages); A's and B's objects.

#### Steps

1. **Versions.** If the UI calls `/api/v3/orders/1001`, try `/api/v2/…`, `/api/v1/…`, `/api/…` and `/v1/…` with B's session and A's ID. Old versions often still answer.
2. **Other back-ends.** Repeat against the mobile API (`/mobile/api/…`, `m-api.example.com`), partner or integration APIs, and server-rendered pages (`/orders/1001`, `/orders/1001/print`).
3. **Formats and suffixes.** `/orders/1001.json`, `/orders/1001.xml`, `?format=csv`, `/orders/1001/export`, `/orders/1001/pdf`.
4. **Methods.** If `GET` is checked, try `POST` with the same parameters, `HEAD`, and the override headers (`X-HTTP-Method-Override`, `_method=`), since some frameworks route an overridden method to a different handler. The general bypass technique is in [authorisation bypass techniques](/web/web-authorization-bypass-techniques/); here you record only whether the alternate route reaches A's object.
5. **Content types.** Send the write as `application/x-www-form-urlencoded`, `multipart/form-data` or XML instead of JSON; a different parser or a legacy controller may handle it.

```bash
for v in v3 v2 v1; do
  printf '%s ' "$v"
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
    -H 'Authorization: Bearer <TOKEN_USER_B>' "https://api.example.com/api/$v/orders/1001"
  sleep 1
done
```

#### Observation

Illustrative:

```text
v3 404 21
v2 404 21
v1 200 412
```

#### Evaluation

- **Fail:** any route, version, method or content type returns or acts on A's object for B.
- **Pass:** all routes deny consistently. Old versions that return `410 Gone` or are not routed at all are a pass.

#### False positives

Old versions that are deliberately public for public objects. A `200` with the same small body as the denial (check the length and body). Versions that answer only in a non-production environment that is out of scope.

#### Automation

AuthMatrix or the helper below can carry several URL variants per request. In CI, generate authorisation tests from the route table so a new or legacy route without a test fails the build; decommission old versions in the gateway rather than leaving them routed.

### GT-WEB-IDOR-9: List, search, bulk and export endpoints

*Guler Tech methodology.* Implements the bulk-access part of WSTG-APIT-02.

#### What it checks

Whether endpoints that return or act on many objects scope their results to the caller, and whether filter parameters can widen that scope.

#### Prerequisites

Accounts A and B with several objects each; list, search, report, export and batch endpoints from the inventory.

#### Steps

1. As B, call each list endpoint plainly and check for any A canary in the result.
2. Add or change filters that name an owner: `?user_id=2001`, `?owner=user-a@example.org`, `?account=`, `?customer_id=`, and try removing the filter the UI always sends (`GET /api/orders` instead of `GET /api/orders?mine=true`).
3. Try `?ids=1001,1002`, `?id[]=1001` and similar on list endpoints that accept explicit IDs.
4. Search and autocomplete: search for A's canary string as B.
5. Exports and reports: request a CSV or PDF export as B with A's IDs or A's filter. Batch endpoints: put one operation on B's object and one on A's object in the same batch (**own test objects only**):

```http
POST /api/batch HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_B>
Content-Type: application/json

{"operations":[{"method":"GET","path":"/orders/2005"},{"method":"GET","path":"/orders/1001"}]}
```

6. Check pagination parameters too: some APIs scope the first page and not the "cursor" or `offset` path.

#### Observation

Vulnerable (illustrative): `GET /api/orders?user_id=2001` as B returns A's orders; the batch response contains a `200` result for `/orders/1001`.

#### Evaluation

- **Fail:** any list, search, export or batch result contains objects the caller may not see, or a filter parameter changes the owner scope beyond the caller's.
- **Pass:** results are always scoped to the caller (filters can narrow, never widen), and each batch item is authorised individually.
- Scale matters here: a list endpoint that returns *all* users' records is usually rated higher than a single-object IDOR, because no identifier is needed.

#### False positives

Lists that are meant to show other users' objects (a public feed, a team's shared board). Aggregate statistics without per-user data.

#### Automation

The helper in GT-WEB-IDOR-12 can compare list sizes and a canary field across sessions. In CI, seed fixtures for two users and assert that every list endpoint returns only the caller's fixtures, with and without owner filters.

### GT-WEB-IDOR-10: GraphQL object-level authorisation

*Guler Tech methodology.* Implements the authorisation part of WSTG-APIT-99 and the GraphQL case of WSTG-APIT-02.

#### What it checks

Whether every resolver that returns or mutates an object checks access to it: type-specific queries, the generic `node`/`nodes` fields, nested fields, and mutations, including when requests are batched or aliased.

#### Prerequisites

Accounts A and B; the schema (introspection if enabled; otherwise InQL's schema work or clairvoyance to reconstruct it from suggestions); global IDs of A's objects.

#### Steps

1. Load the schema into InQL and list queries and mutations that take an `id`, `ID!` or input object containing IDs. Check whether `Query` has `node(id: ID!)` and `nodes(ids: [ID!]!)`.
2. Decode A's global IDs (base64 `Order:1001`, `gid://shop/Order/1001`, or a custom format).
3. As B, request A's object through the type-specific query:

```http
POST /graphql HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_B>
Content-Type: application/json

{"query":"query { order(id: \"T3JkZXI6MTAwMQ==\") { id note total } }"}
```

4. Then through the generic node interface, and with a type swap (a global ID re-encoded with a different type name, such as `Invoice:1001`, if invoices share the numbering):

```graphql
query {
  node(id: "T3JkZXI6MTAwMQ==") {
    id
    ... on Order { note total shippingAddress { line1 } }
  }
}
```

5. Through nested fields: request B's own object and walk into relations that may reach A's objects (`me { team { members { orders { id note } } } }`).
6. Mutations (**own test objects only**): update a harmless field of A's object as B, and verify the change from A's session, because GraphQL servers frequently return errors or `null` while the mutation has run.
7. Batching and aliases: confirm whether one request can fetch several of **your own** objects through aliases or an array of operations, and that each is authorised. Keep the count small; you are checking per-item authorisation, not throughput.

```graphql
query {
  mine: order(id: "T3JkZXI6MjAwNQ==") { id note }
  other: order(id: "T3JkZXI6MTAwMQ==") { id note }
}
```

#### Observation

Vulnerable (illustrative): `order(id:)` returns `null` with an authorisation error for A's ID, but `node(id:)` with the same ID returns A's note and shipping address. Or, in the alias query, `mine` and `other` both resolve.

```json
{
  "data": {
    "node": {
      "id": "T3JkZXI6MTAwMQ==",
      "note": "GT-A-canary-01",
      "total": "42.00",
      "shippingAddress": { "line1": "1 Test Road" }
    }
  }
}
```

Correct:

```json
{"data":{"node":null},"errors":[{"message":"Not found","path":["node"]}]}
```

#### Evaluation

- **Fail:** any query path (type-specific, `node`, `nodes`, nested, alias, batch) returns A's object or fields to B; any mutation changes A's object as verified from A's session.
- **Pass:** all paths deny consistently (a `null` with an error is the usual GraphQL shape); nested resolvers apply the same rule as the top-level ones.

#### False positives

- GraphQL usually answers `200 OK` even when denying; read `errors` and the data, not the status.
- Fields that are public by design on a shared type (a product's name).
- `null` results because the global ID was mis-encoded; check that your encoding works for your own objects first.

#### Automation

InQL generates queries for every field; graphql-cop flags batching and alias support (useful context, not object-level findings). Autorize works on GraphQL if you replay each operation separately. In CI, write resolver-level tests per type and per mutation, plus one test that calls `node` with every type's fixture owned by another user.

### GT-WEB-IDOR-11: Files and attachments

*Guler Tech methodology.* Implements WSTG-ATHZ-04 (file system resources) and WSTG-APIT-02 for file objects.

#### What it checks

Whether file downloads, previews and deletions check the caller's access to the file's owning record, and whether files are reachable outside the application's checks (public storage, long-lived pre-signed URLs).

#### Prerequisites

Accounts A and B; at least one upload in each account (attachment, avatar, document, export); the download requests for them.

#### Steps

1. As A, upload a file with a canary name and content (`GT-A-canary-01.pdf`) and record the upload response: file ID, storage key, URL.
2. As B, request A's file by ID through every route: `/api/files/{id}`, `/api/files/{id}/download`, `/api/files/{id}/preview`, `/download?file=`, thumbnails.
3. Open A's file URL with no session at all. If it is a direct storage URL (bucket or CDN), check whether it is pre-signed (an expiring signature in the query) or plainly public, and note any expiry time.
4. As B, try to delete or replace A's file (**own test objects only**), and verify from A's session.
5. Where filenames are predictable (`inv-1001.pdf`), try B's neighbour only within your own range; if the path is used to build a filesystem path, path traversal is a separate test (WSTG-ATHZ-01, not covered here).

```bash
curl -s -o /dev/null -w '%{http_code} %{content_type} %{size_download}\n' \
  -H 'Cookie: session=<SESSION_USER_B>' 'https://app.example.com/api/files/5c9e2f04-1a7b-4e33-9d0a-6f2b8c1e4a77/download'
```

#### Observation

Vulnerable (illustrative): B's request returns `200 application/pdf 48213`, A's canary document. Or the download endpoint denies B correctly but redirects A to a storage URL that works for anyone and never expires.

#### Evaluation

- **Fail:** B (or no session) can read, replace or delete A's file through any route; storage URLs for private files are public or effectively permanent.
- **Pass:** every route checks access to the owning record; direct storage URLs are short-lived, issued only after the check, and scoped to one object.

#### False positives

Public assets (product images, published avatars). Pre-signed URLs used within their short expiry by the person they were issued to: that is the design; whether such links should be shareable is covered in [revocation, sharing and asynchronous access](/web/web-access-control-revocation-sharing-async/).

#### Automation

Autorize catches download routes during browsing. In CI, add a test that downloads another user's fixture file and expects `404`, and a configuration test that the storage bucket blocks public access (see [S3 security](/cloud/aws-s3-security/) for AWS).

### GT-WEB-IDOR-12: Full-coverage session-swap replay

*Guler Tech methodology.* Implements the two-account method of WSTG-ATHZ-04 and WSTG-APIT-02 across the whole captured API surface.

#### What it checks

That every captured request touching A's objects has been replayed as B (and without a session) and compared, so nothing in the inventory is left untested, and gives the client a repeatable artefact for retesting.

#### Prerequisites

Captured requests for A's objects (from Burp, exported as JSON in the format below or hand-written); B's credentials; Python 3 with `requests`.

#### Steps

1. Export or write the requests you want to check into `requests.json`. Only include requests that reference **your own** objects. Leave writes out on the first run.

```json
[
  {"name": "order detail", "method": "GET", "url": "https://api.example.com/api/orders/1001",
   "headers": {"Accept": "application/json"} },
  {"name": "order invoice", "method": "GET", "url": "https://api.example.com/api/orders/1001/invoice",
   "headers": {"Accept": "application/json"} },
  {"name": "graphql node", "method": "POST", "url": "https://api.example.com/graphql",
   "headers": {"Content-Type": "application/json"},
   "body": "{\"query\":\"query { node(id: \\\"T3JkZXI6MTAwMQ==\\\") { id ... on Order { note } } }\"}"}
]
```

2. Run the helper below with A's and B's credentials in environment variables. It replays each request three times (as A, as B, without credentials), at most one request per second by default, refuses hosts outside the scope you pass, skips non-read methods unless you add `--allow-writes`, and does not store response bodies: it prints status, length, a short hash and the key fields you name.

```python
#!/usr/bin/env python3
"""authz_diff.py: replay captured requests as user A, user B and anonymous, and diff the results.

For authorised testing against your own test accounts only. It does not generate or iterate
identifiers: it replays exactly the requests in the input file.

  export AUTH_A='Bearer <TOKEN_USER_A>'      # or a cookie: 'session=<SESSION_USER_A>'
  export AUTH_B='Bearer <TOKEN_USER_B>'
  python3 authz_diff.py requests.json --scope api.example.com --fields id,note,owner
"""
import argparse
import hashlib
import json
import os
import sys
import time
from urllib.parse import urlsplit

import requests

READ_METHODS = {"GET", "HEAD", "OPTIONS"}
DENY_STATUSES = {401, 403, 404}


def auth_headers(value):
    if not value:
        return {}
    if value.lower().startswith("bearer "):
        return {"Authorization": value}
    return {"Cookie": value}


def pick(obj, path):
    """Return obj['a']['b'] for path 'a.b'; list indexes allowed ('items.0.id')."""
    for part in path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif isinstance(obj, list) and part.isdigit() and int(part) < len(obj):
            obj = obj[int(part)]
        else:
            return None
    return obj


def send(session, req, identity):
    headers = {k: v for k, v in req.get("headers", {}).items()
               if k.lower() not in ("cookie", "authorization")}
    headers.update(auth_headers(identity))
    resp = session.request(req["method"], req["url"], headers=headers,
                           data=req.get("body"), allow_redirects=False, timeout=15)
    try:
        body = resp.json()
    except ValueError:
        body = None
    digest = hashlib.sha256(resp.content).hexdigest()[:10]
    return {"status": resp.status_code, "length": len(resp.content), "hash": digest, "body": body}


def verdict(a, other, fields):
    if other["status"] in DENY_STATUSES:
        return "enforced"
    if not 200 <= other["status"] < 300:
        return "review"
    if other["hash"] == a["hash"]:
        return "BYPASS? identical to owner"
    if fields and a["body"] is not None and other["body"] is not None:
        if all(pick(a["body"], f) == pick(other["body"], f) for f in fields) \
                and any(pick(a["body"], f) is not None for f in fields):
            return "BYPASS? key fields match owner"
    return "review (2xx, different body)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("requests_file")
    ap.add_argument("--scope", required=True, action="append", help="allowed host, repeatable")
    ap.add_argument("--fields", default="", help="comma-separated JSON paths to compare")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between requests")
    ap.add_argument("--allow-writes", action="store_true",
                    help="also replay non-read methods (own test objects only)")
    args = ap.parse_args()

    auth_a, auth_b = os.environ.get("AUTH_A"), os.environ.get("AUTH_B")
    if not auth_a or not auth_b:
        sys.exit("Set AUTH_A and AUTH_B")
    fields = [f for f in args.fields.split(",") if f]
    with open(args.requests_file, encoding="utf-8") as fh:
        captured = json.load(fh)

    session = requests.Session()
    print("name\tmethod\tA\tB\tanon\tB verdict\tanon verdict\tfields(A | B)")
    for req in captured:
        method = req["method"].upper()
        host = urlsplit(req["url"]).hostname
        if host not in args.scope:
            print(f"{req['name']}\tSKIPPED: {host} not in scope")
            continue
        if method not in READ_METHODS and not args.allow_writes:
            print(f"{req['name']}\tSKIPPED: {method} needs --allow-writes")
            continue
        results = {}
        for label, identity in (("A", auth_a), ("B", auth_b), ("anon", None)):
            results[label] = send(session, req, identity)
            time.sleep(args.delay)
        a, b, anon = results["A"], results["B"], results["anon"]
        shown = " | ".join(
            f"{[pick(r['body'], f) for f in fields] if r['body'] is not None else '-'}" for r in (a, b))
        print("\t".join([
            req["name"], method,
            f"{a['status']}/{a['length']}/{a['hash']}",
            f"{b['status']}/{b['length']}/{b['hash']}",
            f"{anon['status']}/{anon['length']}",
            verdict(a, b, fields), verdict(a, anon, fields), shown,
        ]))


if __name__ == "__main__":
    main()
```

3. Confirm every `BYPASS?` and `review` line by hand in Repeater. For writes, run with `--allow-writes` only against test objects you created for the purpose, and verify each from A's session as in GT-WEB-IDOR-3, because the helper, like Autorize, cannot see blind writes.
4. Keep `requests.json` and the output with the evidence: after the client fixes the issues, the same run is the retest.

#### Observation

Illustrative output:

```text
name           method  A               B               anon    B verdict                       anon verdict  fields(A | B)
order detail   GET     200/412/9c1e0a  200/412/9c1e0a  401/27  BYPASS? identical to owner     enforced      [1001, 'GT-A-canary-01'] | [1001, 'GT-A-canary-01']
order invoice  GET     200/980/51d3aa  404/21/77b0c2   401/27  enforced                        enforced      - | [None, None]
graphql node   POST    200/96/0e44f1   200/58/a1c9d2   200/58  review (2xx, different body)    review (2xx, different body)  [None, None] | [None, None]
```

The third line is typical GraphQL: `200` for everyone, with the denial inside the body. Use `--fields data.node.note` to make the comparison meaningful.

#### Evaluation

- **Fail:** any confirmed line where B or the anonymous request obtained A's object or changed it.
- **Pass:** every request in the inventory has been replayed, and every replay is denied or returns only the caller's own data.
- Coverage is part of the result: report which object types and operations were tested and which were not (for example "refund was not exercised: no test payment method").

#### False positives

As in GT-WEB-IDOR-2: public objects, shared workspaces, cached responses, `200` with an error body, endpoints that ignore the ID and return the caller's own data. Responses with timestamps or nonces never hash the same; rely on `--fields` for those.

#### Automation

The helper is the bridge to CI: the same idea, written as framework tests against fixtures instead of live sessions, is the [authorisation regression test](#authorisation-regression-tests) suite. AuthMatrix saves its configuration and can be re-run after a fix; Autorize can export its results table.

## Secure implementation

### Design rules

- **Deny by default.** An object is invisible unless a rule grants access: ownership, membership, an explicit share, a role that covers it. Unknown is "no".
- **Take the subject from the session, never from the request.** The current user and tenant come from the validated session or token; request parameters say *which* object, never *who is asking*.
- **Make the query the check.** Load objects through a query scoped to what the caller may see (`WHERE id = ? AND owner_id = ?`, `request.user.orders`, a repository method that takes the user). A forgotten "if" is the usual bug; a lookup that cannot return someone else's row cannot be forgotten.
- **Centralise the rule, call it everywhere.** One policy per object type (Laravel Policy, a Spring bean used by `@PreAuthorize`, a DRF permission plus `get_queryset`, an Express loader middleware) used by every handler: REST, GraphQL, export, batch, background jobs.
- **Check every ID in the request.** Parent, child and every referenced object in a body. Scope nested lookups to the parent, and the parent to the caller.
- **Check each operation.** Read, update, delete and each action are separate rules; "can read" is not "can cancel".
- **Answer the same for "not yours" and "does not exist"** where existence is sensitive (usually `404`).
- **Validate identifier types strictly** at the edge: one integer or one UUID string, not arrays, objects or mixed types.
- **Use non-sequential IDs (UUIDv4 or v7) as defence in depth,** and stop leaking other users' IDs where they are not needed. Neither replaces the check.
- **Retire old versions and parallel back-ends,** or route them through the same authorisation layer.

### Node.js and Express

Load the object by ID *and* owner in a middleware, and make handlers use only `req.order`:

```javascript
// orders.routes.js (Express 5, Prisma used as the example data layer)
const express = require('express');
const { prisma } = require('./db');
const { requireAuth } = require('./auth'); // sets req.user from a verified session or token

const router = express.Router();

function parseId(value) {
  // Exactly one positive integer: rejects arrays, objects, "1002abc", "1e3", "-1"
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,17}$/.test(value)) return null;
  const id = Number(value);
  return Number.isSafeInteger(id) ? id : null;
}

async function loadOwnedOrder(req, res, next) {
  const id = parseId(req.params.orderId);
  if (id === null) return res.status(404).json({ error: 'not_found' });
  const order = await prisma.order.findFirst({ where: { id, ownerId: req.user.id } });
  if (!order) return res.status(404).json({ error: 'not_found' }); // same answer for "not yours"
  req.order = order;
  return next();
}

router.get('/orders/:orderId', requireAuth, loadOwnedOrder, (req, res) => {
  res.json({ id: req.order.id, note: req.order.note, total: req.order.total });
});

router.patch('/orders/:orderId', requireAuth, loadOwnedOrder, async (req, res) => {
  const updated = await prisma.order.update({
    where: { id: req.order.id },
    data: { note: String(req.body.note ?? '') },
  });
  res.json({ id: updated.id, note: updated.note });
});

// Lists are scoped too: filters can narrow, never widen
router.get('/orders', requireAuth, async (req, res) => {
  const orders = await prisma.order.findMany({ where: { ownerId: req.user.id } });
  res.json(orders.map((o) => ({ id: o.id, note: o.note, total: o.total })));
});

module.exports = router;
```

For references in bodies, resolve each referenced ID with the same kind of scoped query before using it (`prisma.address.findFirst({ where: { id: body.shippingAddressId, ownerId: req.user.id } })`), and reject the request if it returns nothing. In Express 5 a rejected promise in async middleware is passed to the error handler; on Express 4, wrap async middleware or catch errors yourself.

### Django and Django REST framework

Plain Django: put the owner into the lookup.

```python
# views.py
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render

from .models import Order


@login_required
def order_detail(request, pk):
    # 404 for "does not exist" and for "not yours" alike
    order = get_object_or_404(Order, pk=pk, owner=request.user)
    return render(request, "orders/detail.html", {"order": order})
```

DRF: scope `get_queryset()`. It is used by `get_object()` for detail, update and delete, *and* by the list action, so one method covers every route of the viewset. Object permissions (`has_object_permission`) are useful for finer rules, but the DRF docs point out that they are not applied to each instance of a list and not applied on create, so they cannot be the only control.

```python
# views.py
from rest_framework import permissions, serializers, viewsets

from .models import Address, Order


class OrderSerializer(serializers.ModelSerializer):
    shipping_address = serializers.PrimaryKeyRelatedField(queryset=Address.objects.none())

    class Meta:
        model = Order
        fields = ["id", "note", "shipping_address", "total"]
        read_only_fields = ["id", "total"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get("request")
        if request is not None and request.user.is_authenticated:
            # A referenced address must also belong to the caller
            self.fields["shipping_address"].queryset = Address.objects.filter(owner=request.user)


class OrderViewSet(viewsets.ModelViewSet):
    serializer_class = OrderSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Order.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)  # owner from the session, not the body
```

For nested routes (`/users/{user_pk}/orders/{pk}`), filter on the caller, not just on the URL parent: `Order.objects.filter(owner=self.request.user, owner_id=self.kwargs["user_pk"])` returns nothing when the URL names someone else.

### Spring Security

Make the repository method take the user, so the query is the check:

```java
// OrderRepository.java
public interface OrderRepository extends JpaRepository<Order, Long> {
    Optional<Order> findByIdAndOwnerUsername(Long id, String username);
    List<Order> findAllByOwnerUsername(String username);
}
```

```java
// OrderController.java
@RestController
@RequestMapping("/api/orders")
class OrderController {
    private final OrderRepository orders;

    OrderController(OrderRepository orders) { this.orders = orders; }

    @GetMapping("/{id}")
    OrderDto get(@PathVariable Long id, @AuthenticationPrincipal UserDetails user) {
        return orders.findByIdAndOwnerUsername(id, user.getUsername())
                .map(OrderDto::from)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    @PatchMapping("/{id}")
    OrderDto updateNote(@PathVariable Long id, @RequestBody NoteUpdate body,
                        @AuthenticationPrincipal UserDetails user) {
        Order order = orders.findByIdAndOwnerUsername(id, user.getUsername())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        order.setNote(body.note());
        return OrderDto.from(orders.save(order));
    }
}
```

Where the rule is more than ownership (team membership, shares), method security keeps it in one place. Enable it with `@EnableMethodSecurity`, then use `@PostAuthorize` for reads (it checks the returned object) and `@PreAuthorize` with a policy bean for writes (it checks before the method runs):

```java
@Service
class OrderService {
    @PostAuthorize("returnObject.owner.username == authentication.name")
    public Order read(Long id) {
        return orders.findById(id).orElseThrow();
    }

    @PreAuthorize("@orderPolicy.canEdit(#id, authentication)")
    public Order updateNote(Long id, String note) { /* ... */ }
}

@Component("orderPolicy")
class OrderPolicy {
    private final OrderRepository orders;

    OrderPolicy(OrderRepository orders) { this.orders = orders; }

    public boolean canEdit(Long id, Authentication auth) {
        return orders.findByIdAndOwnerUsername(id, auth.getName()).isPresent();
    }
}
```

`@PostAuthorize` denies with `403` after loading the object, so prefer the scoped repository where you want a uniform `404`, and never use `@PostAuthorize` alone on a method that changes data (the change has already happened when it runs). `#id` resolves from the parameter name, which needs the `-parameters` compiler flag; Spring Boot's build plugins set it, plain builds may not.

### Laravel

Write a Policy per model and call it from every controller action. Laravel discovers `App\Policies\OrderPolicy` for `App\Models\Order` by convention.

```php
<?php
// app/Policies/OrderPolicy.php
namespace App\Policies;

use App\Models\Order;
use App\Models\User;
use Illuminate\Auth\Access\Response;

class OrderPolicy
{
    public function view(User $user, Order $order): Response
    {
        return $user->id === $order->user_id ? Response::allow() : Response::denyAsNotFound();
    }

    public function update(User $user, Order $order): Response
    {
        return $user->id === $order->user_id ? Response::allow() : Response::denyAsNotFound();
    }

    public function delete(User $user, Order $order): Response
    {
        return $this->update($user, $order);
    }
}
```

```php
<?php
// app/Http/Controllers/OrderController.php
namespace App\Http\Controllers;

use App\Http\Resources\OrderResource;
use App\Models\Order;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class OrderController extends Controller
{
    public function index(Request $request)
    {
        return OrderResource::collection($request->user()->orders()->paginate());
    }

    public function show(Order $order)
    {
        Gate::authorize('view', $order);
        return new OrderResource($order);
    }

    public function update(Request $request, Order $order)
    {
        Gate::authorize('update', $order);
        $order->update($request->validate(['note' => ['nullable', 'string', 'max:500']]));
        return new OrderResource($order);
    }
}
```

`$this->authorize('update', $order)` does the same where the base controller uses the `AuthorizesRequests` trait; at the time of writing, new Laravel 11 and later applications ship a base controller without it, so `Gate::authorize()` (or the `can:update,order` route middleware) is the portable form. Alternatively scope the lookup itself: `$request->user()->orders()->findOrFail($id)`. For nested routes, use scoped bindings so the child must belong to the parent, and still authorise the parent:

```php
<?php
// routes/api.php
use App\Http\Controllers\ProjectFileController;
use Illuminate\Support\Facades\Route;

Route::middleware('auth:sanctum')->scopeBindings()->group(function () {
    Route::get('/projects/{project}/files/{file}', [ProjectFileController::class, 'show'])
        ->middleware('can:view,project');
});
```

### GraphQL resolvers

Put the rule in the data layer every resolver uses, including `node`, so there is no generic path around it:

```javascript
// Loaders take the viewer and return null for objects the viewer may not see
const loaders = {
  Order: (viewer, id) => prisma.order.findFirst({ where: { id, ownerId: viewer.id } }),
  Invoice: (viewer, id) => prisma.invoice.findFirst({ where: { id, order: { ownerId: viewer.id } } }),
};

function decodeGlobalId(globalId) {
  const [type, raw] = Buffer.from(String(globalId), 'base64').toString('utf8').split(':');
  const id = /^[1-9][0-9]{0,17}$/.test(raw ?? '') ? Number(raw) : null;
  return { type, id };
}

const resolvers = {
  Query: {
    order: (_parent, { id }, ctx) => loaders.Order(ctx.viewer, decodeGlobalId(id).id),
    node: async (_parent, { id }, ctx) => {
      const { type, id: dbId } = decodeGlobalId(id);
      const load = Object.hasOwn(loaders, type) ? loaders[type] : null;
      if (!load || dbId === null) return null;
      const obj = await load(ctx.viewer, dbId);
      return obj ? { ...obj, __typename: type } : null;
    },
  },
  Mutation: {
    updateOrderNote: async (_parent, { id, note }, ctx) => {
      const order = await loaders.Order(ctx.viewer, decodeGlobalId(id).id);
      if (!order) throw new Error('Not found'); // checked before writing
      return prisma.order.update({ where: { id: order.id }, data: { note } });
    },
  },
};
```

Apply the same loaders to nested field resolvers (`Order.invoice`, `User.orders`). Limit batching and aliases as ASVS `v5.0.0-4.3.1` (L2) describes for cost, but do not rely on those limits for authorisation.

### Authorisation regression tests

A pentest finds a sample; tests keep the fix. Build a matrix per object type: **identities** (owner, another user with the same role, another tenant, anonymous, and admin where relevant) × **operations** (read, list, update, delete, each action, export) × **routes** (every version and back-end). For each cell, assert the expected status *and*, for writes, that the stored object did not change. Seed two users' fixtures in every test run, and make "a route that takes an object ID has no authorisation test" a failing check.

Django REST framework:

```python
from rest_framework.test import APITestCase

from accounts.models import User
from orders.models import Order


class OrderObjectAuthorizationTests(APITestCase):
    def setUp(self):
        self.alice = User.objects.create_user("alice", password="unused-in-tests")
        self.bob = User.objects.create_user("bob", password="unused-in-tests")
        self.order = Order.objects.create(owner=self.alice, note="alice-only")
        self.url = f"/api/orders/{self.order.pk}/"

    def test_other_user_cannot_read(self):
        self.client.force_authenticate(self.bob)
        self.assertEqual(self.client.get(self.url).status_code, 404)

    def test_other_user_cannot_update(self):
        self.client.force_authenticate(self.bob)
        response = self.client.patch(self.url, {"note": "bob"}, format="json")
        self.assertEqual(response.status_code, 404)
        self.order.refresh_from_db()
        self.assertEqual(self.order.note, "alice-only")

    def test_list_contains_only_own_orders(self):
        self.client.force_authenticate(self.bob)
        response = self.client.get("/api/orders/")
        self.assertNotIn(self.order.pk, [o["id"] for o in response.json()])
```

Spring (MockMvc, with a fixture order owned by `alice`):

```java
@SpringBootTest
@AutoConfigureMockMvc
class OrderObjectAuthorizationTest {
    @Autowired MockMvc mvc;

    @Test
    @WithMockUser(username = "bob")
    void otherUserCannotReadOrUpdate() throws Exception {
        mvc.perform(get("/api/orders/{id}", TestData.ALICE_ORDER_ID))
           .andExpect(status().isNotFound());
        mvc.perform(patch("/api/orders/{id}", TestData.ALICE_ORDER_ID)
                .contentType(MediaType.APPLICATION_JSON).content("{\"note\":\"bob\"}").with(csrf()))
           .andExpect(status().isNotFound());
    }
}
```

Laravel:

```php
public function test_other_user_cannot_view_or_update_order(): void
{
    $alice = User::factory()->create();
    $bob = User::factory()->create();
    $order = Order::factory()->for($alice)->create(['note' => 'alice-only']);

    $this->actingAs($bob)->getJson("/api/orders/{$order->id}")->assertNotFound();
    $this->actingAs($bob)->patchJson("/api/orders/{$order->id}", ['note' => 'bob'])->assertNotFound();
    $this->assertSame('alice-only', $order->fresh()->note);
}
```

Express (Jest and supertest):

```javascript
const request = require('supertest');
const app = require('../app');
const { seedTwoUsers } = require('./fixtures');

test('user B cannot read or update user A order', async () => {
  const { orderA, tokenB } = await seedTwoUsers();
  const auth = { Authorization: `Bearer ${tokenB}` };
  await request(app).get(`/api/orders/${orderA.id}`).set(auth).expect(404);
  await request(app).patch(`/api/orders/${orderA.id}`).set(auth).send({ note: 'bob' }).expect(404);
  const again = await request(app).get(`/api/orders/${orderA.id}`).set({ Authorization: `Bearer ${orderA.ownerToken}` });
  expect(again.body.note).toBe(orderA.note);
});
```

## Practice labs

**PortSwigger Web Security Academy** (free, browser-based):

- [User ID controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter): the basic swap.
- [User ID controlled by request parameter, with unpredictable user IDs](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids): GUIDs, and finding where another user's GUID leaks.
- [User ID controlled by request parameter with data leakage in redirect](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect): the denial redirects, but the redirect body carries the data.
- [User ID controlled by request parameter with password disclosure](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure): IDOR on an account page that pre-fills a password.
- [Insecure direct object references](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references): static files with incrementing names.
- [Accessing private GraphQL posts](https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts) and [Accidental exposure of private GraphQL fields](https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure): GraphQL object and field access.

**OWASP Juice Shop** ([companion guide, Broken Access Control](https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html)): *View Basket* (view another user's basket), *Manipulate Basket* (put a product into another user's basket, a write IDOR with a parameter-pollution twist), *Forged Feedback* and *Forged Review* (act in another user's name).

**OWASP crAPI** ([challenges](https://github.com/OWASP/crAPI/blob/develop/docs/challenges.md)): Challenge 1, *access details of another user's vehicle* (vehicle IDs are GUIDs, so you first find where they leak), and Challenge 2, *access mechanic reports of other users* (a hidden endpoint with a report ID).

**VAmPI** ([repository](https://github.com/erev0s/VAmPI)): a deliberately vulnerable REST API that lists BOLA among its vulnerabilities, with endpoints such as `GET /books/v1/{book}` (returns a book's secret) and `PUT /users/v1/{username}/email`. Run it locally in its vulnerable mode.

## Real-world cases

- **GraphQL `node` interface undoes random UUIDs (HackerOne, 2018).** Embedded submission forms were addressed by random UUIDs, but the model still had a sequential primary key. Encoding `gid://hackerone/EmbeddedSubmissionForm/<n>` as a global ID and querying it through `node` returned the form's UUID, which granted the same access as an invited reporter. Disclosed January 2019. [HackerOne report 447930](https://hackerone.com/reports/447930).
- **Blind write IDOR through a GraphQL mutation (HackerOne, 2022).** A mutation taking a `StructuredScope` global ID let any user archive or unarchive assets on any programme. HackerOne's summary notes that the server responded that the object was not found, yet the change was applied: the reason GT-WEB-IDOR-3 verifies from the owner's session. [HackerOne report 1501611](https://hackerone.com/reports/1501611).
- **Child ID not scoped to the parent (GitLab, 2021).** `POST /projects/:id/merge_requests/:iid/status_check_responses` authorised the project in the path, but the `external_status_check_id` parameter was not scoped to it, so changing it returned the configuration of status checks in any project on the instance, private ones included. Disclosed February 2022. [HackerOne report 1372216](https://hackerone.com/reports/1372216).
- **IDOR on a user-management API (PayPal, 2018).** According to PayPal's published summary, a business account owner could assign secondary users from other accounts through `/businessmanage/users/api/v1/users`, giving those logins access to the account's functions; PayPal states it found no evidence of abuse. The report shows a USD 10,500 bounty. Only the summary is public. [HackerOne report 415081](https://hackerone.com/reports/415081).
- **Incrementing document numbers, no authentication (First American Financial, 2019).** KrebsOnSecurity reported that roughly 885 million title-insurance records dating back to 2003 were viewable by anyone with a link to one document, by changing a single digit in the URL. The case is the extreme of the rating scale: unauthenticated, enumerable, highly sensitive. [KrebsOnSecurity](https://krebsonsecurity.com/2019/05/first-american-financial-corp-leaked-hundreds-of-millions-of-title-insurance-records/).
- **UUIDv1 is predictable (research, 2022 to 2023).** Daniel Thatcher's [In GUID We Trust](https://www.intruder.io/research/in-guid-we-trust) (Intruder) shows how version 1 GUIDs used as password-reset tokens can be predicted from a sample and a time estimate; VerSprite's [write-up on UUIDs](https://versprite.com/blog/universally-unique-identifiers/) and Roni Carta's [sandwich attack](https://depi.security/blog/20230811-sandwich-attack/) bracket a victim's UUIDv1 between two of the attacker's own. These are token attacks, but the same reasoning applies to UUIDv1 object IDs.

More write-ups are collected in [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

Rate on what the attacker gains, the preconditions, how the identifier is obtained, the scale and the sensitivity of the data. CVSS v3.1 base scores do not capture scale (one record versus every record) or sensitivity beyond High/Low, so state those in the reasoning and adjust the final severity; the vectors below are examples, not fixed answers.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Unauthenticated read of other users' sensitive objects, sequential or leaked IDs | Critical | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | Anyone on the internet can read every record; the base score understates the scale, so rate above it |
| Any registered user reads other users' sensitive objects (PII, financial, health), sequential or leaked IDs | High; Critical when the whole dataset is reachable and highly sensitive | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Registration is free, so `PR:L` is barely a barrier; scale and sensitivity raise the severity above the base score |
| Any user modifies other users' objects (address, bank details, booking) | High | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` (6.5) | Integrity of other users' data; rises further when the change redirects money or goods |
| Any user deletes other users' objects | High | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` (8.1) | Data loss for the victim; scale and recoverability (soft delete, backups) decide between High and Critical |
| IDOR on the user object leading to account takeover (change another user's email or password) | Critical | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Full control of any account; for admin accounts, of the application |
| Cross-tenant read in SaaS | High to Critical | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Breaks the isolation customers pay for; see [multi-tenant isolation](/web/web-multi-tenant-isolation/) |
| List or filter endpoint returns all users' records | High to Critical | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | No identifier needed at all; one request exposes everything |
| IDOR with UUIDv4 IDs not exposed anywhere else | Medium, sometimes Low | `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N` (5.3) | The check is missing, but the attacker needs an ID they cannot guess or find; `AC:H` reflects that. Rate up as soon as any leak is found |
| IDOR with UUIDv1 or other time-based IDs | Medium to High | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Predictable within a time window; treat close to sequential |
| Write IDOR on a low-impact field (display name of a draft, a preference) | Low to Medium | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` (4.3) | Real but limited integrity impact |
| Existence oracle (`403` for others' objects, `404` for missing ones) | Low or Info | `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (4.3) | Only matters where existence is sensitive (for example "this person has an account at this clinic") |
| Hidden UI element or client-side route guard, with the server correctly denying | Info | none | No server-side gap; mention only to explain the test |

When you report, give: the request as B with A's ID, the response, the proof from A's session for writes, how an attacker obtains the ID (format and where it leaks), the operations affected, and confirmation that only your own test accounts were involved.

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 / API Top 10 |
|---|---|---|---|---|
| GT-WEB-IDOR-1 | WSTG-ATHZ-04, WSTG-APIT-01, WSTG-INFO-06 | v5.0.0-8.1.1 | CWE-639 (context) | A01:2025; API1:2023, API9:2023 |
| GT-WEB-IDOR-2 | WSTG-ATHZ-04, WSTG-APIT-02 | v5.0.0-8.2.2, v5.0.0-8.3.1 | CWE-639, CWE-566, CWE-862 | A01:2025; API1:2023 |
| GT-WEB-IDOR-3 | WSTG-ATHZ-04, WSTG-APIT-02 | v5.0.0-8.2.2, v5.0.0-8.3.1 | CWE-639, CWE-862 | A01:2025; API1:2023 |
| GT-WEB-IDOR-4 | WSTG-ATHZ-04, WSTG-APIT-02 | v5.0.0-8.2.2 | CWE-639, CWE-863 | A01:2025; API1:2023 |
| GT-WEB-IDOR-5 | WSTG-ATHZ-04, WSTG-APIT-02 | v5.0.0-8.2.2, v5.0.0-8.3.1, v5.0.0-4.1.3 | CWE-639 | A01:2025; API1:2023 |
| GT-WEB-IDOR-6 | WSTG-ATHZ-04, WSTG-APIT-02 | v5.0.0-8.2.2 (exploitability) | CWE-639 (context) | A01:2025; API1:2023 |
| GT-WEB-IDOR-7 | WSTG-ATHZ-04, WSTG-APIT-02, WSTG-INJT-04 | v5.0.0-8.2.2, v5.0.0-8.3.1 | CWE-863, CWE-639 | A01:2025; API1:2023 |
| GT-WEB-IDOR-8 | WSTG-APIT-02, WSTG-ATHZ-04 | v5.0.0-8.2.2, v5.0.0-4.1.4 | CWE-862, CWE-639 | A01:2025; API1:2023, API9:2023 |
| GT-WEB-IDOR-9 | WSTG-APIT-02 | v5.0.0-8.2.2 | CWE-639, CWE-862 | A01:2025; API1:2023 |
| GT-WEB-IDOR-10 | WSTG-APIT-99, WSTG-APIT-02 | v5.0.0-8.2.2, v5.0.0-4.3.1 | CWE-639, CWE-862 | A01:2025; API1:2023 |
| GT-WEB-IDOR-11 | WSTG-ATHZ-04, WSTG-APIT-02 | v5.0.0-8.2.2 | CWE-639, CWE-862 | A01:2025; API1:2023 |
| GT-WEB-IDOR-12 | WSTG-ATHZ-04, WSTG-APIT-02 | v5.0.0-8.2.2, v5.0.0-8.3.1 | CWE-639 | A01:2025; API1:2023 |

ASVS levels: `v5.0.0-8.1.1` L1 (authorisation documentation covers data-specific access), `v5.0.0-8.2.2` L1, `v5.0.0-8.3.1` L1, `v5.0.0-4.1.3` L2 (intermediary-set headers cannot be overridden by the end user), `v5.0.0-4.1.4` L3 (only supported HTTP methods are accepted), `v5.0.0-4.3.1` L2 (GraphQL query cost and amount limits). CWE choice: CWE-639 (Authorization Bypass Through User-Controlled Key) is the base-level entry for this class and the one to use by default; CWE-566 is its child for a user-controlled SQL primary key; CWE-862 (Missing Authorization) and CWE-863 (Incorrect Authorization) are class-level entries that MITRE allows for mapping with review, so use them when the defect is a missing check or a wrong check rather than a user-controlled key. CWE-284 (Improper Access Control) is a pillar that MITRE marks as discouraged for mapping; it is the umbrella, not a finding's CWE. `A01:2025` is Broken Access Control in the OWASP Top 10:2025 (it lists CWE-639 among its mapped CWEs).

## References

**OWASP**

- WSTG: [Testing for Insecure Direct Object References (WSTG-ATHZ-04)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/04-Insecure_Direct_Object_References), [API Broken Object Level Authorization (WSTG-APIT-02)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/02-API_Broken_Object_Level_Authorization), [Testing GraphQL (WSTG-APIT-99)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/99-GraphQL)
- ASVS 5.0: [V8 Authorization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md) and the [5.0 source tree](https://github.com/OWASP/ASVS/tree/master/5.0)
- [API1:2023 Broken Object Level Authorization](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/), [API9:2023 Improper Inventory Management](https://api-security.owasp.org/editions/2023/en/0xa9-improper-inventory-management/)
- [A01:2025 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/)
- Cheat Sheets: [Insecure Direct Object Reference Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html), [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [Authorization Testing Automation](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html), [Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html), [GraphQL](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)

**CWE and standards**

- [CWE-639](https://cwe.mitre.org/data/definitions/639.html), [CWE-566](https://cwe.mitre.org/data/definitions/566.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html), [CWE-863](https://cwe.mitre.org/data/definitions/863.html), [CWE-284](https://cwe.mitre.org/data/definitions/284.html)
- [RFC 9562, Universally Unique IDentifiers](https://www.rfc-editor.org/rfc/rfc9562) (UUID versions; security considerations on guessability)
- [GraphQL Global Object Identification](https://graphql.org/learn/global-object-identification/) and the [Relay object identification specification](https://relay.dev/graphql/objectidentification.htm)
- [Sqids FAQ](https://sqids.org/faq) (Hashids' successor; not a security feature)

**PortSwigger**

- [Access control vulnerabilities](https://portswigger.net/web-security/access-control) and [IDOR](https://portswigger.net/web-security/access-control/idor)
- [GraphQL API vulnerabilities](https://portswigger.net/web-security/graphql), [API testing](https://portswigger.net/web-security/api-testing)

**Framework documentation**

- Django: [`get_object_or_404`](https://docs.djangoproject.com/en/5.2/topics/http/shortcuts/); DRF: [permissions](https://www.django-rest-framework.org/api-guide/permissions/) (limits of object-level permissions) and [filtering](https://www.django-rest-framework.org/api-guide/filtering/) (`get_queryset`)
- Spring Security: [method security](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html) (`@EnableMethodSecurity`, `@PreAuthorize`, `@PostAuthorize`); Spring Data JPA: [query methods](https://docs.spring.io/spring-data/jpa/reference/jpa/query-methods.html)
- Laravel: [authorisation](https://laravel.com/docs/12.x/authorization) (policies, `Gate::authorize`, `denyAsNotFound`) and [routing](https://laravel.com/docs/12.x/routing) (`scopeBindings`)
- Express: [API reference](https://expressjs.com/en/5x/api.html)

**Tools**

- Burp extensions: [Autorize](https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f) ([GitHub](https://github.com/Quitten/Autorize)), [AuthMatrix](https://portswigger.net/bappstore/30d8ee9f40c041b0bfec67441aad158e) ([GitHub](https://github.com/SecurityInnovation/AuthMatrix)), [Auth Analyzer](https://portswigger.net/bappstore/7db49799266c4f85866f54d9eab82c89) ([GitHub](https://github.com/simioni87/auth_analyzer)), [InQL](https://portswigger.net/bappstore/296e9a0730384be4b2fffef7b4e19b1f) ([GitHub](https://github.com/doyensec/inql))
- [ZAP Access Control Testing add-on](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/)
- [ffuf](https://github.com/ffuf/ffuf), [Arjun](https://github.com/s0md3v/Arjun), [graphql-cop](https://github.com/dolevf/graphql-cop), [clairvoyance](https://github.com/nikitastupin/clairvoyance)
- Labs: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), [OWASP crAPI](https://github.com/OWASP/crAPI), [VAmPI](https://github.com/erev0s/VAmPI)
