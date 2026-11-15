---
title: "Mass Assignment and Property-Level Authorization (BOPLA)"
date: 2026-11-15 18:06:00 +0000
subcategory: access-control
summary: "Property-level authorization: mass assignment of privileged fields, excessive data exposure, GraphQL field access, own-account checks and framework fixes."
refs: [WSTG-INJT-20, WSTG-APIT-03, WSTG-APIT-01, WSTG-APIT-99, WSTG-ATHZ-03, WSTG-INJT-04, WSTG-BUSL-01, v5.0.0-8.1.2, v5.0.0-8.2.3, v5.0.0-8.3.1, v5.0.0-15.3.1, v5.0.0-15.3.3, v5.0.0-15.3.7, v5.0.0-14.2.6, v5.0.0-4.3.2, "API3:2023", "A01:2025", "A08:2025", CWE-915, CWE-213, CWE-200, CWE-201]
tags: [web, mass-assignment, bopla, access-control, api-security, graphql]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Access Control](/web/web-access-control-testing-guide/). It covers authorization at the level of a single *property* of an object: you may be allowed to read and edit your own profile, but not to set its `role`, see its `password_hash`, or read the `internal_notes` field on an order that is legitimately yours. The OWASP API Security Top 10 calls this Broken Object Property Level Authorization (BOPLA, `API3:2023`), which merges the 2019 entries Excessive Data Exposure (the read side) and Mass Assignment (the write side). The WSTG tests are `WSTG-INJT-20` (Mass Assignment) and `WSTG-APIT-03` (Excessive Data Exposure), with GraphQL in `WSTG-APIT-99`. You get the model (binding on the way in, serialisation on the way out), the variants that keep producing findings, twelve tests that each add a candidate field to a request on **your own** object and then re-read it to see what the server actually stored, and the fixes in Express, Django/DRF, Spring and Laravel with regression tests. The emphasis is on the fix and on how to verify it. Role-by-role testing of whole functions is in [vertical privilege escalation and BFLA](/web/web-vertical-privilege-escalation-bfla/); swapping object IDs is in [IDOR and BOLA](/web/web-idor-bola/); cross-tenant leaks are in [multi-tenant isolation](/web/web-multi-tenant-isolation/).

## Contents

- [How it works](#how-it-works)
  - [Properties, not objects](#properties-not-objects)
  - [Binding: how request fields reach the model](#binding-how-request-fields-reach-the-model)
  - [Serialisation: how model fields reach the response](#serialisation-how-model-fields-reach-the-response)
  - [What changes in SPAs, APIs, GraphQL and mobile back-ends](#what-changes-in-spas-apis-graphql-and-mobile-back-ends)
- [What goes wrong](#what-goes-wrong)
  - [Privilege and identity fields accepted on write](#privilege-and-identity-fields-accepted-on-write)
  - [Ownership and tenant references accepted on write](#ownership-and-tenant-references-accepted-on-write)
  - [Business state and value fields accepted on write](#business-state-and-value-fields-accepted-on-write)
  - [Nested objects and relations](#nested-objects-and-relations)
  - [Second binders and patch semantics](#second-binders-and-patch-semantics)
  - [Create paths that skip the edit rules](#create-paths-that-skip-the-edit-rules)
  - [Whole objects serialised to the client](#whole-objects-serialised-to-the-client)
  - [Secrets and write-only fields in responses](#secrets-and-write-only-fields-in-responses)
  - [Other users' data inside your own responses](#other-users-data-inside-your-own-responses)
  - [List, search and export endpoints](#list-search-and-export-endpoints)
  - [GraphQL fields without field-level authorization](#graphql-fields-without-field-level-authorization)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-WEB-BOPLA-1: Build a property inventory for each object](#gt-web-bopla-1-build-a-property-inventory-for-each-object)
  - [GT-WEB-BOPLA-2: Compare the raw response with what the UI shows](#gt-web-bopla-2-compare-the-raw-response-with-what-the-ui-shows)
  - [GT-WEB-BOPLA-3: Secrets and write-only fields in responses](#gt-web-bopla-3-secrets-and-write-only-fields-in-responses)
  - [GT-WEB-BOPLA-4: Other users' data in embedded objects and lists](#gt-web-bopla-4-other-users-data-in-embedded-objects-and-lists)
  - [GT-WEB-BOPLA-5: Privilege fields on your own profile update](#gt-web-bopla-5-privilege-fields-on-your-own-profile-update)
  - [GT-WEB-BOPLA-6: Ownership and tenant fields on create and update](#gt-web-bopla-6-ownership-and-tenant-fields-on-create-and-update)
  - [GT-WEB-BOPLA-7: Business state and value fields on your own objects](#gt-web-bopla-7-business-state-and-value-fields-on-your-own-objects)
  - [GT-WEB-BOPLA-8: Nested objects and bracket notation](#gt-web-bopla-8-nested-objects-and-bracket-notation)
  - [GT-WEB-BOPLA-9: Content types, PATCH semantics and parameter pollution](#gt-web-bopla-9-content-types-patch-semantics-and-parameter-pollution)
  - [GT-WEB-BOPLA-10: Registration, invitation, import and bulk paths](#gt-web-bopla-10-registration-invitation-import-and-bulk-paths)
  - [GT-WEB-BOPLA-11: GraphQL field-level authorization](#gt-web-bopla-11-graphql-field-level-authorization)
  - [GT-WEB-BOPLA-12: Field rules that depend on role and state](#gt-web-bopla-12-field-rules-that-depend-on-role-and-state)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Node.js and Express](#nodejs-and-express)
  - [Django and Django REST framework](#django-and-django-rest-framework)
  - [Spring and Spring Security](#spring-and-spring-security)
  - [Laravel](#laravel)
  - [GraphQL resolvers](#graphql-resolvers)
  - [Property-level regression tests](#property-level-regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Properties, not objects

Access control has three layers. **Function level** asks whether this caller may use the operation at all (may a customer call `PATCH /api/users/{id}`?). **Object level** asks whether this caller may use it on *this* record (is user 1002 the caller?). **Property level** asks, for an object the caller is allowed to touch, which of its fields they may read and which they may write. A user who may edit her own profile should be able to change `display_name` and `phone`, and should not be able to change `role`, `email_verified`, `credit_limit` or `tenant_id`, even though all of them are columns of the same row she legitimately owns.

The OWASP API Security Top 10 2023 makes this its own category, [API3:2023 Broken Object Property Level Authorization](https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/), and maps it to CWE-213 (Exposure of Sensitive Information Due to Incompatible Policies) and CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes). ASVS 5.0 states the requirements directly:

- `v5.0.0-8.1.2` (L2): the authorization documentation defines field-level read and write rules, which may depend on the user's permissions and on the object's own attributes such as its state.
- `v5.0.0-8.2.3` (L2): field-level access is restricted to consumers with explicit permission to those fields, explicitly to mitigate BOPLA.
- `v5.0.0-8.3.1` (L1): rules are enforced at a trusted service layer, not by the client choosing which fields to send or show.
- `v5.0.0-15.3.1` (L1): the application returns only the required subset of an object's fields, not the whole object.
- `v5.0.0-15.3.3` (L2): mass assignment is prevented by limiting the allowed fields per controller and action.
- `v5.0.0-15.3.7` (L2): defences against HTTP parameter pollution, particularly where the framework merges parameters from several sources.
- `v5.0.0-14.2.6` (L3): only the minimum sensitive data is returned (partial card numbers rather than full ones, for example).

Note that `8.1.2` comes first for a reason. You cannot test "may this user write `status`?" unless someone has decided the answer. On most engagements nobody has written it down, so part of your job is to reconstruct the field policy from the UI, the documentation and the admin role's traffic, and to report the gaps where the server's behaviour and the obvious intent disagree.

### Binding: how request fields reach the model

Every modern framework will turn a request body into an object for you. Express gives you `req.body`; Django forms and DRF serializers build validated data from `request.data`; Spring MVC binds form parameters onto a `@ModelAttribute` object through `WebDataBinder` and deserialises JSON onto a `@RequestBody` type through Jackson; Laravel hands you `$request->all()` and Eloquent accepts arrays in `create()`, `fill()` and `update()`. The convenience is the risk: whatever names the client sends are matched against the target object's properties, and if the target is the persistence entity itself, every column is a candidate.

Mass assignment (also called auto-binding or object injection) therefore needs three things:

1. **A binder** that copies client-supplied names onto an object without a per-action list of allowed names. `Object.assign(user, req.body)`, `User.update(req.body)`, a DRF `ModelSerializer` with `fields = "__all__"`, a JPA entity as `@RequestBody`, `$user->update($request->all())` on an unguarded model.
2. **A sensitive property** on that object: a privilege flag, an identity or ownership reference, a workflow state, a monetary value, an audit timestamp.
3. **Persistence** of the bound object, so the change survives the request.

The UI is irrelevant to all three. The form shows four inputs; the binder accepts whatever the request contains. That is why the WSTG test description (`WSTG-INJT-20`) tells you to look at what the *server* returns for an object and then try those names on the handlers that modify it.

Two framework behaviours confuse testers and developers alike, and you will see them in almost every test:

- **Silently ignored unknown fields.** DRF serializers ignore keys they do not declare; Mongoose drops paths that are not in the schema (its default `strict` mode); Spring Boot configures Jackson not to fail on unknown properties; Laravel's mass-assignment guard discards unfillable attributes without an error unless you ask it to throw. A `200 OK` after adding `"role": "admin"` proves nothing in either direction. Only re-reading the object tells you whether the field was stored.
- **Strict schemas do not protect known fields.** Zod's `strictObject`, Mongoose `strict: "throw"` and Jackson's `FAIL_ON_UNKNOWN_PROPERTIES` reject fields the schema does not know. If the schema or entity *does* have a `role` property, strictness does nothing for you. The protection is a separate input type per action that simply does not contain `role`.

### Serialisation: how model fields reach the response

The read side mirrors the write side. Express `res.json(user)`, a DRF `ModelSerializer` with every field, Spring returning a JPA entity (Jackson serialises every getter), Laravel returning a model from a route (it is converted to JSON with every attribute not marked hidden). If the handler returns the persistence object, the response contains every column the ORM loaded, plus every relation that happens to be loaded. The SPA then picks the three fields it displays, and the remaining forty are visible to anyone who opens the network tab.

This is what the API Top 10 2019 called Excessive Data Exposure and what WSTG now tests as `WSTG-APIT-03`. The decision about what to return has moved to the client, and the client is not a security boundary (`v5.0.0-8.3.1`). The fix is to decide on the server, per endpoint and per audience, which fields leave.

Field-level read rules are often conditional, which is where real findings hide:

- **Relationship-dependent.** You may see your own email and phone; another member of your team may see your name but not your phone; a stranger may see only a display name.
- **Role-dependent.** A support agent sees `last_login_ip`; a customer does not.
- **State-dependent.** A reviewer's identity on a submission is hidden until the review is published; a redacted report field stays redacted on every path that can return it.

### What changes in SPAs, APIs, GraphQL and mobile back-ends

- **SPAs and mobile apps** are built against generous APIs. The front end receives full objects and filters them for display, and the same API serves the admin console, so the user's response often contains admin-only fields. Mobile back-ends are worse because nobody looks at them in a browser.
- **JSON APIs** make mass assignment easier to try than HTML forms did: you just add a key. They also add patch formats (JSON Merge Patch, [RFC 7396](https://www.rfc-editor.org/rfc/rfc7396), and JSON Patch, [RFC 6902](https://www.rfc-editor.org/rfc/rfc6902)) whose `path` can point at any property, including nested ones.
- **GraphQL** inverts the read side. The client chooses fields, so "the front end never asks for `passwordHash`" means nothing if the type exposes it. Authorization has to sit on the type's field resolvers, because the same type is reachable through many query paths (a `user` query, a `node(id:)` lookup, `viewer.team.members`, and the payload of every mutation that returns a `User`). On the write side, a mutation's input type is the allowlist: if `UpdateProfileInput` contains `role`, the schema advertises the mass assignment for you.
- **API gateways and BFFs** sometimes filter responses (stripping fields at the edge). That helps only if every route goes through the filter. Internal or legacy routes, alternative versions and GraphQL endpoints behind the same gateway often do not.
- **OpenAPI and generated clients** are a gift to testers. A shared `User` schema reused for request and response bodies tells you that the request accepts the same properties the response returns, unless the spec marks them `readOnly`.

## What goes wrong

### Privilege and identity fields accepted on write

**What:** the profile or account update handler binds the full user entity, so `role`, `is_admin`, `permissions`, `groups`, `email_verified`, `mfa_enabled` or `email` (where email is an identity attribute that should go through a verification flow) are writable by the account owner.

**Why it matters:** a role or admin flag is vertical privilege escalation with one request. `email_verified` skips a verification step that other controls (SSO account linking, invitation domains, "verified users only" features) rely on. Changing `email` without re-verification can become account takeover when the email is also the login or recovery identifier. Disabling `mfa_enabled` on your own account is harmless; that the server accepts it from the profile endpoint without step-up is the finding.

**Where to look:** `PATCH /api/me`, `PUT /api/users/{id}`, account settings forms, the admin console's user edit request (which shows you the privileged field names), and any endpoint whose response contains a privilege field. The role matrix itself (who may grant which role through the proper admin function) is tested in [vertical privilege escalation and BFLA](/web/web-vertical-privilege-escalation-bfla/); here you only care whether the *wrong* handler accepts the field.

### Ownership and tenant references accepted on write

**What:** `owner_id`, `user_id`, `author_id`, `created_by`, `organisation_id`, `tenant_id`, `team_id` or `account_id` are taken from the request body instead of from the authenticated context.

**Why it matters:** on create, you can file a record under somebody else (forged feedback, a review in another user's name, an invoice in another tenant). On update, you can move an object out of reach of its rightful owner or into a tenant you control. This is where BOPLA and BOLA meet: the property is a reference to another object, and the server should check both "may you set this field?" and "may you reference that object?". The second half belongs to [IDOR and BOLA](/web/web-idor-bola/) and, across tenants, to [multi-tenant isolation](/web/web-multi-tenant-isolation/).

**Where to look:** create endpoints (`POST /api/comments`, `POST /api/reviews`, `POST /api/projects`), any body containing an ID that is the same as your own user or tenant ID, and responses that echo `owner_id` back.

### Business state and value fields accepted on write

**What:** fields that the application should set as the *result* of a process are writable directly: `status`, `approved`, `paid`, `plan`, `subscription_tier`, `balance`, `credit`, `price`, `discount`, `quantity_shipped`, `trial_ends_at`, `created_at`, `deleted_at`.

**Why it matters:** this is how you get a premium plan without paying, an order marked `paid`, a refund marked `approved`, a wallet balance increase, or an audit trail with a forged timestamp. WSTG's Mass Assignment test calls these *process-dependent* and *internal* properties; WSTG-BUSL-01 asks you to add parameters the interface never sends for the same reason.

**Where to look:** order, cart, subscription, wallet, invoice and workflow objects; any field the UI shows as read-only text rather than an input; any field whose value changes after a background process (payment webhook, approval, KYC check) completes.

### Nested objects and relations

**What:** the binder walks into nested objects. A body like `{"profile": {"display_name": "x"} }` reaches a related `Profile` row, and so does `{"account": {"plan": "enterprise"} }` if the serializer or ORM supports nested writes. Form binders do the same with bracket notation (`user[role]`, `address[user_id]`) or dotted paths (`account.plan` in Spring property paths).

**Why it matters:** developers who protect the top-level entity often forget that a nested update writes a *different* entity with its own sensitive fields, or that a nested object can carry an ID that re-parents a related row (`{"addresses": [{"id": 77, "user_id": 2}]}`).

**Where to look:** responses with embedded objects (the shape you can read is usually the shape you can try to write), Rails-style and PHP-style bracketed form names, Prisma-style nested `connect` / `update` objects, DRF writable nested serializers, Mongoose sub-documents.

### Second binders and patch semantics

**What:** the same handler accepts more than one input format, and only one of them is restricted. Typical shapes:

- JSON body is mapped through a DTO, but `application/x-www-form-urlencoded` or `multipart/form-data` reaches a binder that maps onto the entity (Spring `@ModelAttribute` versus `@RequestBody` on separate handler methods for the same path).
- `PUT` goes through a validated input type; `PATCH` applies the body field by field onto the entity.
- JSON Patch or JSON Merge Patch is applied to the full entity with a generic library, so any `path` is writable.
- Parameter names are normalised (`isAdmin`, `is_admin`, `IsAdmin`) or duplicated (`role=user&role=admin`, two `"role"` keys in one JSON object), and the allowlist check and the binder disagree about which one wins.

**Why it matters:** you can have a perfect allowlist on the code path the front end uses and full mass assignment on a code path nobody tested. ASVS `v5.0.0-15.3.7` (parameter pollution) exists for the frameworks that merge query, body and cookie parameters into one map.

### Create paths that skip the edit rules

**What:** the edit endpoint is locked down, but registration, invitation acceptance, CSV import, bulk create, "duplicate", or SCIM-style provisioning endpoints bind more fields. CVE-2024-0404 in AnythingLLM is the canonical recent example: the invitation-acceptance endpoint accepted a `role` property.

**Why it matters:** registration is unauthenticated. A role or verified flag accepted there needs no account at all, which moves the finding to the top of the severity range.

### Whole objects serialised to the client

**What:** handlers return the entity or a full model dump, and the client filters. Fields you will see: `role`, `permissions`, internal flags (`is_staff`, `fraud_score`, `kyc_status`, `beta_features`), internal IDs, `created_by`, IP addresses, soft-delete flags, debug structures.

**Why it matters:** internal flags rarely hurt on their own; they give you the field names for the write-side tests and tell you how the application models privilege. The findings are fields that are sensitive in themselves (below) or that belong to someone else.

### Secrets and write-only fields in responses

**What:** fields that should never leave the server, or should only ever be written, appear in a response: `password` or `password_hash`, `reset_token`, `email_verification_token`, `otp_secret` / `totp_seed`, `mfa_backup_codes`, `api_key` in full, `session_id`, OAuth refresh tokens, webhook signing secrets, full card numbers or bank details.

**Why it matters:** a password reset token in a profile or user-lookup response is account takeover if the response can be obtained for another user. A TOTP seed defeats the second factor. A password hash invites offline cracking. Even on your own account, a secret returned in a response gets logged by proxies, browser caches and APM tools; ASVS `v5.0.0-14.2.6` and `v5.0.0-15.3.1` both apply.

### Other users' data inside your own responses

**What:** you request something you are entitled to, and it embeds another user with too many fields: an order that embeds the seller with phone and home address, a comment that embeds the author's email, a team listing that returns every member's full user object, a ride that embeds the driver's full profile.

**Why it matters:** this is the most common way excessive data exposure turns into a reportable privacy issue. There is no IDOR involved: the object is yours, the embedded person is not, and the serializer did not switch to a public view of them.

**Where to look:** embedded `user`, `author`, `owner`, `assignee`, `customer`, `driver`, `seller`, `members[]`, `participants[]` objects; activity feeds; notification payloads; WebSocket messages.

### List, search and export endpoints

**What:** the detail endpoint uses a careful serializer, but list, search, autocomplete, "mentions" pickers and export endpoints serialise the full object for every row. The Peloton research by Pen Test Partners (below) is a good illustration: a user search response and a class-statistics response returned profile data even for accounts set to private.

**Why it matters:** scale. One extra field on a detail endpoint is one record; the same field on a search endpoint is every record that matches a two-letter query. You do not need to prove scale by harvesting: one response on your own two test accounts and a description of the query semantics is enough.

### GraphQL fields without field-level authorization

**What:** sensitive fields exist on a type and are resolved for anyone who can reach the type. Mutation input types include privileged fields. Redaction or masking is applied in one query's resolver instead of on the type, so the same field leaks through another path (a mutation payload, a `node` lookup, a nested connection).

**Why it matters:** HackerOne's own programme has two public examples: a 2019 report where the `users` connection exposed emails, OTP backup codes and other private fields, and a 2024 report where a mutation's returned `report` object included an `impact` field that the redaction feature was meant to hide. Both are in [Real-world cases](#real-world-cases).

## Testing

### Before you start

**Authorisation.** Run these tests only inside an authorised engagement with written scope and rules of engagement, inside a bug bounty programme whose rules allow it, or against a deliberately vulnerable lab. All requests, responses and outputs in this note are illustrative, written for fictional hosts (`app.example.com`, `api.example.com`, `admin.example.com`); nothing here was run against a real target.

**Accounts.** You need:

- **User A** and **user B** in the same role, both yours. User A is the account you modify; user B is the "other user" whose data you look for in A's responses and whose ID you use when testing ownership fields.
- An **admin** or higher role if the client provides one. Its traffic is the best source of privileged field names: record the admin's user-edit, order-approval and plan-change requests and note every field that the ordinary user's requests never contain.
- **Two tenants** (organisations, workspaces) for multi-tenant apps, each with at least one of your users.
- Where state matters (orders, subscriptions, invoices), a few **objects you created for testing** in each relevant state, so that every write is against your own test objects.

**The own-object rule.** Every write test in this note adds a candidate field to a request on **your own** profile or **your own** test object and then re-reads that object. You never send a candidate field to someone else's object. Where a test uses user B, it only places B's ID into A's object (GT-WEB-BOPLA-6), or reads A's responses for data about B (GT-WEB-BOPLA-4). Prefer the least destructive candidate value: set `display_name`-style canaries first, flip a boolean you can flip back, use the lowest privileged role above your own before trying `admin`, and never touch real money flows unless the client has given you a sandbox payment provider. Record the original value of everything you change and restore it.

**Stop on real data.** If any response contains a real third party's data (an embedded user who is not one of your accounts, a list row from a real customer, a secret belonging to someone else): stop that line of testing, keep only the minimum redacted evidence (field names and one masked value, the request that produced it, a timestamp), do not download, page through or retain more, and report it to the client contact immediately.

**No harvesting.** Parameter discovery (Param Miner, Arjun, a wordlist in Intruder) sends many requests to one endpoint; that is fine at a low rate against your own object. It is not fine to iterate user IDs or search terms to collect other users' records. To show the scale of a list-endpoint exposure, describe the query semantics and show one page with your own accounts in it.

**Burp setup.**

1. One Burp project per engagement, scope set to the in-scope hosts. Turn on Logger so you have every response body for later field diffs.
2. Log in as user A in one browser profile and user B in another (or use Burp's built-in browser plus a second container), so both sessions are live.
3. Install **Autorize** or **Auth Analyzer** with user B's session as the replay identity. For property-level work its main value is the side-by-side response for A and B on the same request: the field sets often differ even when the status codes match.
4. Install **Param Miner** for hidden-parameter discovery and, for GraphQL, **InQL**.
5. Set a project-level rate limit (a resource pool in Repeater/Intruder with one concurrent request and a delay) and respect any limit in the rules of engagement.

**A key-diff helper.** Most of the read-side work is comparing *which fields* come back, not their values. This small script fetches one URL with two sessions and prints the flattened key paths present in each response, so you can see extra fields and fields that differ by caller. It sends one GET per session and nothing else.

```python
#!/usr/bin/env python3
"""Compare the JSON key paths returned to two sessions for the same URL.
Usage: keydiff.py URL  (sessions come from env vars SESSION_A, SESSION_B)"""
import json, os, sys, urllib.request

def keys(node, prefix=""):
    out = set()
    if isinstance(node, dict):
        for k, v in node.items():
            path = f"{prefix}.{k}" if prefix else k
            out.add(path)
            out |= keys(v, path)
    elif isinstance(node, list):
        for item in node[:3]:              # first few items show the row shape
            out |= keys(item, prefix + "[]")
    return out

def fetch(url, session):
    req = urllib.request.Request(url, headers={
        "Cookie": f"session={session}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)

url = sys.argv[1]
a = keys(fetch(url, os.environ["SESSION_A"]))
b = keys(fetch(url, os.environ["SESSION_B"]))
for label, s in (("both", a & b), ("only A", a - b), ("only B", b - a)):
    print(f"== {label}")
    for k in sorted(s):
        print("  ", k)
```

Point it only at endpoints in scope, and only at objects that both of your accounts may legitimately read (a shared project, a team listing, each user's own `/api/me`). For CI, the same `keys()` function is the core of a response-shape test (see [Property-level regression tests](#property-level-regression-tests)).

### GT-WEB-BOPLA-1: Build a property inventory for each object

*Guler Tech methodology.* Implements the reconnaissance parts of `WSTG-INJT-20` (identify sensitive fields) and `WSTG-APIT-01` (API reconnaissance).

#### What it checks

Which properties each important object has, where each name comes from, and which of them *should* be writable by whom. Every later test uses this inventory; without it you are guessing field names.

#### Prerequisites

User A, user B and (ideally) admin sessions; a crawl of the application in Burp with Logger on.

#### Steps

1. **List the objects that matter:** user/account, profile, membership, organisation/tenant, subscription/plan, order/cart, invoice/payment, wallet, and the core business object of the app (ticket, document, project).
2. **Collect names from responses.** For each object, take the richest response you can legitimately get (your own `GET /api/me`, your own order) and flatten its keys with `jq`:

   ```bash
   curl -s https://api.example.com/api/me \
     -H 'Authorization: Bearer <TOKEN_USER_A>' | jq '[paths | map(tostring) | join(".")]'
   ```

3. **Collect names from the front end.** Search the JavaScript bundles and any public source maps for the object's type definitions, form models and admin-only screens (`isAdmin`, `role`, `plan`, `tenantId`, `emailVerified`). Admin pages are often in the same bundle as the user pages, behind a client-side route guard.
4. **Collect names from the API description.** If an OpenAPI document is published or in scope (`/openapi.json`, `/v3/api-docs`, `/swagger.json`), read the request schemas for create and update operations. Note request schemas that `$ref` the same component as the response, and properties marked `readOnly: true` (the documented intent that the server must enforce).
5. **Collect names from GraphQL.** If introspection is enabled (InQL loads it into Burp), read the `input` types used by mutations (`UpdateUserInput`, `CreateOrderInput`) and the fields of the matching output types. If introspection is disabled, field suggestions in error messages can still reveal names; clairvoyance automates that, at a pace the rules of engagement allow.
6. **Collect names from privileged traffic.** Compare the admin's update request for a user with user A's own profile update. Every extra field in the admin's request is a candidate.
7. **Write the inventory** as a table per object: property, type, source(s), who should read it, who should write it, through which endpoint. Mark the expected answer "server-set" for ownership, timestamps and state.

#### Observation

An inventory such as:

| Object | Property | Seen in | Expected write | Expected read |
|---|---|---|---|---|
| User | `display_name` | `GET /api/me`, form | owner | team |
| User | `role` | `GET /api/me`, admin request | admin function only | owner, admin |
| User | `email_verified` | bundle (`emailVerified`) | server only | owner |
| User | `tenant_id` | `GET /api/me` | server only | owner |
| Order | `status` | `GET /api/orders/{id}` | server (payment webhook) | owner |
| Order | `unit_price` | OpenAPI `OrderLine` | server only | owner |

#### Evaluation

This test produces no finding on its own. A **finding candidate** is any property whose "expected write" is not the owner but which appears in a request schema, a mutation input type or an admin-only request. An OpenAPI request schema that lists `role` or `tenant_id` without `readOnly` is worth an informational note even before you confirm behaviour, because it documents the wrong contract.

#### False positives

- A property in a response is not necessarily bindable. Many teams already use separate input DTOs; treat the inventory as a list of candidates, not results.
- Bundle code for admin screens is not a vulnerability: it only tells you what exists (hidden-UI-only defects without a reachable server gap are informational).

#### Automation

Keep the inventory as a machine-readable file (YAML or JSON) alongside the report; it becomes the expected-field list for the regression tests in [Secure implementation](#secure-implementation). Burp's Logger export plus `jq` gives you the union of response keys per endpoint.

### GT-WEB-BOPLA-2: Compare the raw response with what the UI shows

*Guler Tech methodology.* Implements `WSTG-APIT-03` (compare API responses against displayed data).

#### What it checks

Whether endpoints return whole objects and rely on the client to filter (`v5.0.0-15.3.1`, `v5.0.0-8.3.1`).

#### Prerequisites

User A session; the property inventory from GT-WEB-BOPLA-1.

#### Steps

1. Open a screen (profile page, order summary, team page) and note exactly which fields it displays.
2. Find the API calls that populate it in Burp's HTTP history.
3. List the fields in the response that the screen does not display. Use the inventory's "expected read" column to mark each extra field as harmless, internal, or sensitive.
4. Repeat for the same object type through every endpoint that returns it: detail, list, search, embedded in another object, and the payload returned by create and update calls (these often serialise the full entity after saving).

#### Observation

A vulnerable profile response for user A might look like this (illustrative):

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 1001,
  "display_name": "Alex A",
  "email": "user-a@example.org",
  "role": "member",
  "is_staff": false,
  "tenant_id": 40,
  "fraud_score": 12,
  "last_login_ip": "203.0.113.24",
  "password_hash": "<REDACTED_HASH>"
}
```

A correct response returns what the screen and the user's own legitimate needs require:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 1001,
  "display_name": "Alex A",
  "email": "user-a@example.org",
  "role": "member"
}
```

#### Evaluation

- **Pass:** each endpoint returns a defined field set; no internal-only or sensitive fields; different endpoints for the same type return consistent, minimal views.
- **Fail (finding):** sensitive fields (see GT-WEB-BOPLA-3) or internal fields with a privacy or security impact (`fraud_score`, risk flags, internal notes, staff comments, IP addresses) are returned to a user who should not see them.
- **Fail (low or informational):** internal but harmless fields (`is_staff: false`, internal numeric IDs). Report them as evidence of whole-object serialisation and as the source of the field names you used for the write tests.

#### False positives

- Fields the UI does not *currently* display but the user is entitled to see (their own `role`, their own `created_at`). Extra is not automatically wrong; check against the expected-read column.
- Sparse fieldsets or `?fields=` parameters that the client chose to widen. That is by design if the server still enforces what each caller may request.

#### Automation

Run `keydiff.py` against your own endpoints and keep its output per release. Burp's Comparer on the raw response and the rendered page text is a quick manual check. In CI, assert the exact key set of each response (see [Property-level regression tests](#property-level-regression-tests)).

### GT-WEB-BOPLA-3: Secrets and write-only fields in responses

*Guler Tech methodology.* Implements `WSTG-APIT-03` (sensitive fields in responses) and supports `WSTG-ATHZ-03` where a leaked secret enables escalation.

#### What it checks

That credentials, tokens and other write-only values never appear in any response (`v5.0.0-15.3.1`, `v5.0.0-14.2.6`).

#### Prerequisites

User A; the ability to trigger flows that create secrets on your own account (request a password reset, enrol in TOTP, create an API key, set up a webhook).

#### Steps

1. Trigger each secret-creating flow **on user A only**: request a password reset, start an email change, enrol a TOTP authenticator, generate backup codes, create an API key, register a webhook with a signing secret.
2. After each flow, re-read every endpoint that returns user A (profile, `/api/me`, team listing, admin views available to A) and every endpoint that returns the related object (API key list, webhook list).
3. Search the responses for the secret value you just received by email or on screen, and for field names such as `password`, `hash`, `token`, `secret`, `seed`, `otp`, `backup`, `recovery`, `key`, `signature`.
4. Check the responses to the *write* calls themselves: an update to the profile often returns the full saved entity, including fields the read endpoint hides.
5. Check error responses and debug endpoints for the same values.

#### Observation

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 1001,
  "display_name": "Alex A",
  "reset_token": "<REDACTED_RESET_TOKEN>",
  "reset_token_expires": "2026-11-15T19:00:00Z",
  "totp_secret": "<REDACTED_TOTP_SEED>"
}
```

#### Evaluation

- **Fail (High–Critical):** a password reset token, email verification token, TOTP seed, backup codes, session identifier or full API key is returned in a response that **another user** can obtain (embedded in a team listing, returned by a user lookup, visible to a lower role). Confirm with user B reading user A's data through a legitimate path, never by fetching a real user's record.
- **Fail (Medium):** a password hash, or any of the above, returned only to the owner. The owner already controls the account, but the value now lives in browser caches, proxy logs and client-side error reporting, and any IDOR or cross-site leak elsewhere becomes account takeover.
- **Pass:** secrets are shown once at creation (API keys), masked thereafter (`****abcd`), and never serialised by read endpoints.

#### False positives

- An API key shown in full immediately after creation, once, is the normal pattern.
- A hash-looking value that is an avatar checksum, ETag or cache key. Check what the field is before you call it a password hash.

#### Automation

Add a denylist check to your response-shape tests: fail the build if any response body contains a key matching the secret-name pattern, or the literal value of a secret created in the test fixture. Burp's search across Logger history for the fixture secret is the manual equivalent.

### GT-WEB-BOPLA-4: Other users' data in embedded objects and lists

*Guler Tech methodology.* Implements `WSTG-APIT-03` (related objects, list and search endpoints, different privilege levels).

#### What it checks

Whether responses you are entitled to embed other people with more fields than you are entitled to see, and whether list and search endpoints return full objects per row.

#### Prerequisites

User A and user B, set up so that A has a legitimate relationship with B: the same team, a shared project, a conversation, B as the seller of an item A bought, B as the author of a comment A can read. Set B's privacy settings to the most restrictive option the app offers.

#### Steps

1. As user A, load every screen where B appears and capture the API responses.
2. Find B's embedded object in each response and list its fields. Compare them with what A should see about B (usually: display name, avatar, perhaps a work email in a team context).
3. Use user lookup, mention pickers, autocomplete, search and directory endpoints with a query that matches **B's name or handle only**. Inspect the fields per row.
4. Repeat after B changes a privacy setting (private profile, hide email). Check whether the server honours it in every endpoint, not just on B's profile page.
5. If the app exports lists (CSV, PDF), export a list that contains only A and B and inspect the columns.

#### Observation

A comment list on a document that A and B share (illustrative):

```json
{
  "comments": [
    {
      "id": 501,
      "body": "Looks good",
      "author": {
        "id": 1002,
        "display_name": "Blair B",
        "email": "user-b@example.org",
        "phone": "+44 7700 900123",
        "home_address": "1 Example Street",
        "role": "member"
      }
    }
  ]
}
```

#### Evaluation

- **Pass:** embedded users are serialised through a public or relationship-scoped view; privacy settings are applied wherever the user is serialised.
- **Fail:** contact details, addresses, dates of birth, location, security fields or private-profile data of B appear in A's responses. Severity depends on the data and on reach: a team member's phone number in a small B2B app is Low–Medium; any user's address through a public search endpoint is High.

#### False positives

- Both accounts are in the same organisation where the directory is meant to show contact details. Ask what the organisation's policy is; the same response may be fine for colleagues and a finding for strangers.
- Data B chose to make public.
- A cached CDN response for the wrong session: confirm with `Cache-Control` and by repeating with a cache-busting parameter before reporting.

#### Automation

Autorize or Auth Analyzer show A's and B's views of the same request side by side. `keydiff.py` on a list endpoint shows the row shape. In CI, seed two users with a relationship and assert the exact key set of the embedded object.

### GT-WEB-BOPLA-5: Privilege fields on your own profile update

*Guler Tech methodology.* Implements `WSTG-INJT-20` (mass assignment) and the role-manipulation part of `WSTG-ATHZ-03`.

#### What it checks

Whether the owner of an account can set privilege or verification fields on **their own** account through the ordinary update endpoint (`v5.0.0-15.3.3`, `v5.0.0-8.2.3`).

#### Prerequisites

User A, with a known baseline (`GET /api/me` saved). Candidate field names from GT-WEB-BOPLA-1. The client's agreement on which role values you may try; a role one step above yours is the least intrusive first choice.

#### Steps

All steps: **own test objects only** (user A's own account).

1. Send the normal profile update the UI sends, unchanged, and confirm it works. This is your control request.
2. Add **one** candidate field with a harmless-but-detectable value. Start with a field whose effect is easy to undo, such as a verification flag or a lower role:

   ```http
   PATCH /api/me HTTP/1.1
   Host: api.example.com
   Authorization: Bearer <TOKEN_USER_A>
   Content-Type: application/json

   {"display_name": "Alex A", "email_verified": true}
   ```

3. **Re-read the object** through a different endpoint from the one you wrote to (`GET /api/me`, the admin view if you have one, the session's user info). The write response alone can echo your input without storing it.
4. Repeat with each candidate field separately (`role`, `is_admin`, `permissions`, `groups`, `mfa_enabled`), and with naming variants the inventory suggests (`isAdmin`, `is_admin`, `admin`). One field per request keeps the evidence unambiguous.
5. If a role change sticks, log out, log in again and check what the new session can actually do: one admin-only read is enough as proof. Then **restore the original role** (through the same request with the original value, or by asking the client).
6. If the endpoint rejects the field, note *how*: `400` with a validation error naming the field is the best outcome; `200` with the field silently ignored is acceptable; `500` suggests the binder reached the entity and failed later, which deserves a closer look.

The curl equivalent, followed by the re-read:

```bash
curl -s -X PATCH https://api.example.com/api/me \
  -H 'Authorization: Bearer <TOKEN_USER_A>' \
  -H 'Content-Type: application/json' \
  -d '{"display_name":"Alex A","email_verified":true}'

curl -s https://api.example.com/api/me \
  -H 'Authorization: Bearer <TOKEN_USER_A>' | jq '{email_verified, role}'
```

#### Observation

Vulnerable: the re-read shows the value you sent.

```json
{"email_verified": true, "role": "member"}
```

Correct: either a rejection that names the field, or a re-read that still shows the server's value.

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"error": "unrecognised_field", "field": "email_verified"}
```

#### Evaluation

- **Fail (Critical/High):** `role`, `is_admin` or an equivalent sticks and the new session gains privileged functions. Rate by what the role grants (tenant admin versus platform admin).
- **Fail (Medium–High):** `email_verified` or an identity attribute changes without the verification flow; rate by what relies on it (SSO linking, domain-based auto-join, invitations).
- **Fail (Low–Medium):** a security setting that should require step-up (disabling MFA, changing recovery email) changes through the plain profile endpoint without re-authentication. Cross-check with the Authentication notes of this series once they are published.
- **Pass:** every candidate is rejected or ignored, and the re-read shows the original value.

#### False positives

- The write response echoes the field but the re-read shows the old value: the field was not stored.
- The user is genuinely allowed to change it (some apps let the owner choose between two non-privileged profile types).
- A role displayed in the UI changes but the server-side permissions do not (the field is cosmetic, or permissions come from a separate table). Prove impact with an action, not with the field value.

#### Automation

Param Miner can discover unlinked body parameters; Arjun does the same from the command line. Both detect a parameter by a **change in the response**, so they find fields that alter the reply and can miss fields that are silently stored. Keep their rate low against your own object, for example:

```bash
arjun -u https://api.example.com/api/me -m JSON \
  --headers 'Authorization: Bearer <TOKEN_USER_A>' \
  --include '{"display_name":"Alex A"}' -d 1 --rate-limit 2
```

Arjun's methods are GET, POST, JSON and XML; if the update endpoint accepts only `PATCH` or `PUT`, use Param Miner from Repeater or a short Intruder run with your inventory as the payload list, one field per request, followed by a re-read. In CI, write one test per privileged field that sends it on the owner's update and asserts the stored value did not change.

### GT-WEB-BOPLA-6: Ownership and tenant fields on create and update

*Guler Tech methodology.* Implements `WSTG-INJT-20` and the cross-reference part of `WSTG-APIT-02` (references in request bodies).

#### What it checks

Whether `owner_id`, `user_id`, `author_id`, `created_by`, `tenant_id`, `organisation_id` and similar references are taken from the authenticated context, or whether the client can set them.

#### Prerequisites

User A and user B (B's user ID known from a legitimate shared context); two tenants you control for the tenant variant. A create endpoint and an update endpoint for an object type A owns.

#### Steps

All steps: **own test objects only**. The only foreign value you use is **your own user B's or your own second tenant's ID**.

1. **Create as A, attributed to B.** Create a harmless object (a comment, a review, a feedback entry, a draft) as A and add one ownership field with B's ID:

   ```http
   POST /api/reviews HTTP/1.1
   Host: api.example.com
   Authorization: Bearer <TOKEN_USER_A>
   Content-Type: application/json

   {"product_id": 3001, "text": "bopla-test-6a", "author_id": 1002}
   ```

2. **Re-read** the new object as A and as B. Check the author shown to each, and whether it appears in B's own list of reviews.
3. **Move A's object.** On an existing object A owns, add `owner_id` set to B's ID, or `tenant_id` set to your second tenant's ID. Re-read as both users and in both tenants.
4. Try the same on nested ownership (`project.owner_id`, `{"owner": {"id": 1002} }`) where the inventory shows that shape.
5. Delete the test objects afterwards.

#### Observation

Vulnerable: B's review list now contains `bopla-test-6a` written by A, or A's project appears in tenant 2's listing.

#### Evaluation

- **Fail (High):** objects can be created in another user's name. This is the shape of Juice Shop's Forged Feedback and Forged Review: impersonation, reputation damage and repudiation, and in workflows (approvals, signatures, payments) it can be much worse.
- **Fail (High–Critical):** objects can be moved into another tenant or re-parented away from their owner, which is a tenant-isolation break; continue in [multi-tenant isolation](/web/web-multi-tenant-isolation/).
- **Pass:** the server ignores or rejects the field and sets the owner from the session and the tenant from the server-side context.

#### False positives

- Admin or delegate roles that are explicitly allowed to create on behalf of others. Check the role you used.
- Fields that look like ownership but are a legitimate reference the user chooses (`assignee_id` within the same team, `recipient_id` on a message). Those need an object-level check on the referenced ID, which is a BOLA question.

#### Automation

A CI test that creates as user A with `owner_id` set to a second fixture user and asserts that the stored owner is A. Autorize does not help here; it is a single-session write check.

### GT-WEB-BOPLA-7: Business state and value fields on your own objects

*Guler Tech methodology.* Implements `WSTG-INJT-20` (process-dependent and internal properties) and `WSTG-BUSL-01` (additional parameters the interface never sends).

#### What it checks

Whether fields that should change only as the result of a process (payment, approval, verification, time) can be set directly.

#### Prerequisites

User A with test objects in a known state: an unpaid order or cart, a free-tier subscription, a draft document, a pending refund request. A sandbox payment provider if anything touches payment.

#### Steps

All steps: **own test objects only**, never against real money.

1. Identify process fields from the inventory: `status`, `paid`, `approved`, `plan`, `tier`, `balance`, `credit`, `price`, `unit_price`, `discount`, `trial_ends_at`, `created_at`.
2. On your own object, add **one** field at a time with a value that is detectable and cheap to undo. For a subscription, try the plan identifier one tier up; for an order line, a price one penny lower; for a timestamp, a date one day earlier:

   ```http
   PATCH /api/subscriptions/me HTTP/1.1
   Host: api.example.com
   Authorization: Bearer <TOKEN_USER_A>
   Content-Type: application/json

   {"billing_email": "user-a@example.org", "plan": "pro"}
   ```

3. Re-read the object and, where it matters, check the effect elsewhere: does the feature unlock, does the invoice total change, does an approver queue still show the item?
4. Restore the original state, cancel the test order, or ask the client to reset the object.

#### Observation

Vulnerable: `GET /api/subscriptions/me` now reports `"plan": "pro"` and pro features work, with no payment event. This is the shape of crAPI's "Get an item for free" and "Increase your balance" challenges and Juice Shop's Deluxe Fraud.

#### Evaluation

- **Fail (High–Critical):** monetary values, balances, plan tiers or payment/approval status can be set by the user. Rate by direct financial impact and whether it scales.
- **Fail (Medium):** workflow or audit fields (timestamps, `reviewed_by`) can be forged, undermining integrity of records.
- **Pass:** process fields are server-set only; the API rejects or ignores them.

#### False positives

- The field changes but the server recomputes the effective value from a trusted source at checkout (the stored `price` is a display cache). Prove impact by completing the cheapest possible flow in a sandbox, or describe the gap as defence in depth.
- Fields the user may legitimately set (a requested plan that goes to a payment step before taking effect).

#### Automation

One negative test per process field in CI, asserting the field is unchanged after an owner update. Business-logic flows themselves (coupon stacking, race conditions on balance) are part of the Business Logic subcategory of this series, not yet published.

### GT-WEB-BOPLA-8: Nested objects and bracket notation

*Guler Tech methodology.* Implements `WSTG-INJT-20` (bracket syntax for input parameter names, nested attributes).

#### What it checks

Whether binders walk into related objects, and whether the related object's sensitive fields are protected.

#### Prerequisites

User A; responses that embed related objects (profile inside user, account inside membership, lines inside order); form parameter names that use brackets or dots.

#### Steps

All steps: **own test objects only**.

1. For JSON APIs, take the nested shape you read (for example `{"profile": {...}, "account": {...} }`) and send a normal update that includes the nested object with one harmless field changed. If the nested write is accepted at all, the binder walks into it.
2. Then add **one** sensitive field inside the nested object:

   ```json
   {"display_name": "Alex A", "account": {"plan": "pro"} }
   ```

3. For HTML forms, add bracketed names next to the existing ones (`user[display_name]` is present, so try `user[role]`, or `profile[account][plan]`). As WSTG notes, a non-existent bracketed attribute that produces a different error from an existing one also tells you which names the model has.
4. For nested collections, check whether you can attach a related row by ID (`{"addresses": [{"id": 77}]}` where address 77 is **your own user B's**) or re-parent your own row. That is a BOLA check on the nested reference.
5. Re-read every affected object, including the nested one through its own endpoint.

#### Observation

Vulnerable: the nested `account.plan` is stored even though `plan` is rejected at the top level. Or user B's address now appears under user A.

#### Evaluation

- **Fail:** any sensitive nested property is writable, or nested references can be re-pointed to objects the caller does not own. Rate as for the equivalent top-level field.
- **Pass:** nested input is either not accepted, or accepted through a dedicated nested input type with its own allowlist and object-level checks.

#### False positives

- Nested writes that are supported but go through the same allowlist (the server returns a field-level validation error for the nested sensitive field).

#### Automation

Include nested paths in the inventory (`account.plan`) and in CI negative tests. Param Miner guesses top-level names; nested candidates need a hand-built payload list in Intruder or Repeater.

### GT-WEB-BOPLA-9: Content types, PATCH semantics and parameter pollution

*Guler Tech methodology.* Implements `WSTG-INJT-20` across binders and `WSTG-INJT-04` (HTTP parameter pollution).

#### What it checks

Whether the field allowlist holds on every way the same handler can receive input (`v5.0.0-15.3.3`, `v5.0.0-15.3.7`).

#### Prerequisites

User A; a field that GT-WEB-BOPLA-5 to 8 showed is **correctly rejected** on the main path. This test looks for a second path around that rejection.

#### Steps

All steps: **own test objects only**, one candidate field per request, re-read after each.

1. **Content type.** Send the same update as `application/x-www-form-urlencoded` and as `multipart/form-data` instead of JSON (rewrite the body by hand in Repeater; Burp's "Change body encoding" then switches between URL-encoded and multipart). Then XML if the stack might accept it. A different content type can reach a different binder.

   ```http
   PATCH /api/me HTTP/1.1
   Host: api.example.com
   Authorization: Bearer <TOKEN_USER_A>
   Content-Type: application/x-www-form-urlencoded

   display_name=Alex+A&email_verified=true
   ```

2. **Verb.** If `PATCH` rejects the field, try `PUT` and `POST` on the same path (and method-override headers where the framework honours them; those are covered in more depth in [authorization bypass techniques](/web/web-authorization-bypass-techniques/)).
3. **Patch formats.** If the API accepts `application/merge-patch+json` or `application/json-patch+json`, send one operation on a candidate path:

   ```http
   PATCH /api/me HTTP/1.1
   Host: api.example.com
   Authorization: Bearer <TOKEN_USER_A>
   Content-Type: application/json-patch+json

   [{"op": "replace", "path": "/email_verified", "value": true}]
   ```

4. **Naming variants.** Try the inventory's alternative spellings (`emailVerified`, `email_verified`, `EmailVerified`). Some stacks normalise case or style in the binder but not in the allowlist check.
5. **Duplicates.** Send the candidate twice: in query string and body, or as two keys in one JSON object (`{"role": "member", "role": "admin"}`). Different JSON parsers keep the first or the last; a validator and a binder that disagree let one value pass validation and the other be stored.
6. **Version and alias routes.** Repeat the rejected request against `/api/v1/` if the app uses `/api/v2/`, and against mobile or partner API hosts in scope.

#### Observation

Vulnerable: the JSON request is rejected with `400`, but the form-encoded request returns `200` and the re-read shows the new value.

#### Evaluation

- **Fail:** any alternative path stores a field that the main path rejects. Rate as for the field itself; note in the report that the main-path control exists, because the fix is usually to route the second binder through the same input type.
- **Pass:** every content type, verb and patch format yields the same field set, and unsupported content types get `415 Unsupported Media Type`.

#### False positives

- A different content type that is rejected with `415` or a generic error is a pass.
- Duplicate keys where the stored value is the one that passed validation.

#### Automation

A Repeater tab per variant (Burp's "Change body encoding" covers the URL-encoded and multipart pair). In CI, parametrise the negative tests over content type and verb; it is one extra loop per test.

### GT-WEB-BOPLA-10: Registration, invitation, import and bulk paths

*Guler Tech methodology.* Implements `WSTG-INJT-20` on create paths and `WSTG-ATHZ-03` where the result is a privileged account.

#### What it checks

Whether endpoints that create accounts or objects in bulk bind more fields than the edit endpoint.

#### Prerequisites

A fresh email address you control per registration attempt (plus-addressing or a test domain); an invitation from user A's tenant to a new address you control; a small import file containing only your own test data.

#### Steps

All steps: **own test objects only**. Each new account is one you create and then delete.

1. **Registration.** Register a new account and add **one** candidate field from the inventory (`role`, `email_verified`, `tenant_id`, `plan`):

   ```json
   {"email": "bopla-10a@example.org", "password": "<TEST_PASSWORD>", "email_verified": true}
   ```

   Log in and re-read the new account.
2. **Invitation acceptance.** Accept an invitation that A sent to a new address you control, adding one field (`role`, a different `tenant_id` that belongs to your second tenant). This is the CVE-2024-0404 shape.
3. **Import.** Import a CSV or JSON file with an extra column named after a candidate field (`role`) for a row that represents a new test user or a test object. Check what was stored.
4. **Bulk and duplicate endpoints.** Create two objects through a bulk endpoint, or duplicate one of your objects, with a process field added. Compare the stored objects with the single-create result.
5. **SSO and SCIM provisioning** (if in scope and you control the IdP test tenant): check whether attributes from the IdP assertion or SCIM payload map onto privileged fields without an allowlist.

#### Observation

Vulnerable: the new account logs in with `email_verified: true` without clicking the link, or the invited user lands as `admin` instead of `member`.

#### Evaluation

- **Fail (Critical):** an unauthenticated registration creates an admin, staff or verified account, or joins an arbitrary tenant.
- **Fail (High):** invitation acceptance or import lets the invited or imported user choose a higher role than the inviter granted.
- **Pass:** creation paths use their own input types with the same or stricter allowlists as edit paths.

#### False positives

- Registration that lets you choose between equal-privilege account types (personal and business) by design.
- An import performed by an admin who may legitimately set roles in the file; then the question is whether a non-admin can reach the import.

#### Automation

Negative tests for each create path in CI, including the invitation flow (create an invite for `member`, accept with `role: admin`, assert `member`).

### GT-WEB-BOPLA-11: GraphQL field-level authorization

*Guler Tech methodology.* Implements `WSTG-APIT-99` (GraphQL) with `WSTG-APIT-03` and `WSTG-INJT-20` applied to GraphQL types.

#### What it checks

Whether sensitive fields on GraphQL types are authorised on every path that reaches them, and whether mutation input types accept privileged fields (`v5.0.0-8.2.3`, `v5.0.0-4.3.2`).

#### Prerequisites

User A and user B in a shared context; the schema (InQL or the introspection result; clairvoyance if introspection is off and the rules of engagement allow it).

#### Steps

1. **Read the schema.** In InQL, list the fields of each sensitive type (`User`, `Account`, `Report`) and every place the type is returned: root queries, `node`, nested connections (`team.members`), and mutation payloads. Note whether introspection is enabled in production for an API that is not meant to be public (`v5.0.0-4.3.2`).
2. **Your own object first.** As user A, request the sensitive fields on `viewer` or `me` (A's own record). Note which resolve and which return an authorization error.
3. **Another user through a legitimate path.** Request **user B's** record through each path where A can legitimately reach B (shared team, comment author), asking for one sensitive field at a time:

   ```graphql
   query {
     team(id: "T-40") {
       members { id displayName email }
     }
   }
   ```

   ```http
   POST /graphql HTTP/1.1
   Host: api.example.com
   Authorization: Bearer <TOKEN_USER_A>
   Content-Type: application/json

   {"query": "query { team(id: \"T-40\") { members { id displayName email } } }"}
   ```

4. **Mutation payloads.** For mutations A may legitimately call on A's own objects, add sensitive fields of the returned object to the selection set. A payload often returns the full type, and redaction applied in the query resolver may not apply here.
5. **Input types.** For each mutation A may call, compare its input type with the inventory. If `UpdateUserInput` has `role`, call it on A's own user with a one-step-higher role and re-read (as GT-WEB-BOPLA-5).
6. **Errors and suggestions.** Request a field that does not exist and see whether the server suggests real names ("Did you mean …"). That is how clairvoyance rebuilds schemas.

#### Observation

Vulnerable: `team.members.email` resolves for B even though B's profile page hides it, or a mutation payload returns a field that the corresponding query redacts.

#### Evaluation

- **Fail:** a sensitive field resolves for a caller who should not see it on any path; a mutation input type accepts a privileged field that sticks. Rate as for the REST equivalent; GraphQL makes scale easier (one query can return many nodes), so check whether the path is a list.
- **Fail (Low/Info):** introspection enabled in production for a private API, without a field-level issue. It is a recon aid, not an exposure on its own.
- **Pass:** sensitive fields are authorised in their type's field resolvers (or by a directive that is enforced on every path), and input types contain only fields the caller may write.

#### False positives

- A field that resolves to `null` for unauthorised callers with an error entry is a pass, provided the `null` is the result of an authorization check and not merely missing data.
- Persisted-query-only APIs where the server rejects arbitrary queries. Confirm that rejection before you call the schema unreachable.

#### Automation

InQL generates queries per type and sends them to Repeater. graphql-cop checks common GraphQL misconfigurations (introspection, field suggestions, batching). For CI, a schema test that lists sensitive fields and asserts each has an authorization directive or a resolver-level check, plus query tests that request them as an unauthorised fixture user.

### GT-WEB-BOPLA-12: Field rules that depend on role and state

*Guler Tech methodology.* Implements `WSTG-ATHZ-03` and `WSTG-APIT-03` (different privilege levels) for field-level rules.

#### What it checks

That field-level read and write rules change correctly with the caller's role and the object's state (`v5.0.0-8.1.2`, `v5.0.0-8.2.3`). Full role-by-function matrices live in [vertical privilege escalation and BFLA](/web/web-vertical-privilege-escalation-bfla/); this test covers only the field dimension.

#### Prerequisites

Accounts in each role (at least member and a manager or tenant admin); test objects you own in each relevant state (draft, submitted, approved, closed).

#### Steps

All steps: **own test objects only**.

1. **Read by role.** For the same object, compare the field sets returned to each role with `keydiff.py` or Auth Analyzer. Mark fields that a lower role sees and should not.
2. **Write by role.** Take a field that only the higher role may edit (a manager's approval note, a team's billing contact) and send it from the lower role on an object both roles can reach, then re-read.
3. **Write by state.** Fields that should freeze after a transition (an order's `shipping_address` after dispatch, a submitted expense's `amount`, a published post's `author_id`): move your own object into the later state, then try the update the UI allowed in the earlier state.
4. **Read by state.** Fields that should appear only after a transition (a reviewer's name after publication, a prize after a draw): read them before the transition through every endpoint that returns the object.

#### Observation

Vulnerable: a submitted expense's `amount` can still be changed by its owner after approval, or a member sees a field the manager view is meant to restrict.

#### Evaluation

- **Fail:** any field rule that holds in the UI is not enforced on the server for some role or state. State-dependent writes on financial or approval objects are usually High.
- **Pass:** the server applies the field policy based on the caller and the stored state of the object, not on what the client sends as the state.

#### False positives

- Roles that legitimately overlap. Check the documented policy, or confirm the intent with the client, before reporting a "lower role sees field X" difference.

#### Automation

AuthMatrix lets you define roles, requests and expected outcomes, which maps well to a field-level matrix. In CI, a table-driven test over (role, state, field) with the expected read and write result.

## Secure implementation

### Design rules

1. **Write the field policy down** (`v5.0.0-8.1.2`). For each object: which fields each role may read, which it may write, through which action, and in which states. The inventory from GT-WEB-BOPLA-1 is a good first draft.
2. **One input type per action, never the entity.** `UpdateProfileInput` contains `display_name` and `phone`. Role changes go through a separate admin action with its own function-level check. This is the allowlist `v5.0.0-15.3.3` asks for, and it is the only control that protects *known* sensitive fields.
3. **Server-set fields come from the server.** Owner and author from the session, tenant from the server-side tenant context, state from the workflow, prices from the catalogue, timestamps from the clock. Assign them *after* the client's data so that a stray client value cannot overwrite them.
4. **Reject unknown fields on security-relevant endpoints.** Silently ignoring them is safe as long as the input type is right, but rejecting with a `400` that names the field makes mistakes visible in testing and in logs. Either way, test with a re-read.
5. **One output type per audience.** A self view, a teammate view, a public view, an admin view. Embedded users always use the public or relationship view. Never return the persistence object (`v5.0.0-15.3.1`).
6. **Secrets are write-only.** Passwords, reset and verification tokens, TOTP seeds, backup codes and signing secrets never appear in an output type. API keys are shown once and masked afterwards.
7. **Every binder goes through the same input type.** JSON, form and multipart; `PUT`, `PATCH` and JSON Patch. If you support JSON Patch, apply it to the input DTO, not to the entity, and reject paths outside the allowlist.
8. **GraphQL authorises fields on the type**, so every path that returns the type gets the same rule, and mutation input types are allowlists.
9. **Test the policy**, both directions, per field (see [Property-level regression tests](#property-level-regression-tests)).

### Node.js and Express

Validate the body with a strict schema that contains only the writable fields, then build the database update from the parsed result plus server-set values. [Zod](https://zod.dev/api)'s `z.object` strips unknown keys and `z.strictObject` rejects them; [Joi](https://github.com/hapijs/joi/blob/master/API.md) rejects unknown keys unless you allow them.

```javascript
import { z } from "zod";

const UpdateProfile = z.strictObject({
  display_name: z.string().min(1).max(80).optional(),
  phone: z.string().max(32).optional(),
});

const CreateReview = z.strictObject({
  product_id: z.number().int().positive(),
  text: z.string().min(1).max(2000),
});

// What the owner sees about themselves, and what anyone else sees.
const selfSelect = { id: true, display_name: true, email: true, role: true };
const publicSelect = { id: true, display_name: true };

app.patch("/api/me", requireAuth, async (req, res) => {
  const parsed = UpdateProfile.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid_body", issues: parsed.error.issues });
  }
  const user = await prisma.user.update({
    where: { id: req.user.id },        // object from the session, not the body
    data: parsed.data,                 // only the allowlisted fields
    select: selfSelect,
  });
  res.json(user);
});

app.post("/api/reviews", requireAuth, async (req, res) => {
  const parsed = CreateReview.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_body" });
  const review = await prisma.review.create({
    data: {
      ...parsed.data,
      author_id: req.user.id,          // server-set, after the client data
      tenant_id: req.user.tenant_id,
    },
    select: { id: true, text: true, author: { select: publicSelect } },
  });
  res.status(201).json(review);
});
```

The anti-patterns to grep for: `Object.assign(entity, req.body)`, `{ ...req.body }` passed to an ORM, `Model.update(req.body)`, `findByIdAndUpdate(id, req.body)`, `res.json(entity)` on an ORM object. Recursive merge helpers on `req.body` also bring prototype pollution, which the Injection part of this series will cover.

ORM-level defence in depth:

- **Prisma:** prefer explicit `select` on every query that feeds a response. `omit` removes named fields per query, or globally when set in the `PrismaClient` constructor (`new PrismaClient({ omit: { user: { password_hash: true } } })`); it left Preview and became generally available in Prisma ORM 6.2.0 according to Prisma's changelog. `omit` is a denylist, so treat it as a safety net for secrets, not as your output type.
- **Mongoose:** the schema's `strict` option (on by default) drops paths that are not in the schema, and `strict: "throw"` makes that an error. Mark secrets `select: false` so queries do not load them unless asked, and mark server-set paths such as `tenant_id` and `created_by` `immutable: true` so they cannot change after creation. None of these stop a client from writing a field that *is* in the schema, such as `role`; that still needs the input schema above.

```javascript
const userSchema = new mongoose.Schema({
  display_name: String,
  email: String,
  role: { type: String, enum: ["member", "manager", "admin"], default: "member" },
  tenant_id: { type: mongoose.Schema.Types.ObjectId, required: true, immutable: true },
  password_hash: { type: String, select: false },
  totp_secret: { type: String, select: false },
}, { strict: "throw" });
```

### Django and Django REST framework

**Forms.** A `ModelForm` should list its `fields` explicitly. Django's documentation strongly recommends this and warns that `fields = "__all__"` and `exclude` can lead to security problems when new fields are added to the model, citing GitHub as an example of a major site that was exploited that way ([ModelForm docs](https://docs.djangoproject.com/en/stable/topics/forms/modelforms/)).

```python
class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["display_name", "phone"]   # never "__all__" or exclude
```

**DRF.** Use separate serializers for input and for each output audience. DRF ignores input keys a serializer does not declare and ignores read-only fields on input, which is safe but silent; the mixin below turns unknown keys into a `400`.

```python
from rest_framework import serializers, viewsets, permissions


class RejectUnknownFieldsMixin:
    def validate(self, attrs):
        writable = {name for name, f in self.fields.items() if not f.read_only}
        unknown = set(self.initial_data) - writable
        if unknown:
            raise serializers.ValidationError(
                {name: "This field is not allowed." for name in sorted(unknown)})
        return super().validate(attrs)


class ProfileUpdateSerializer(RejectUnknownFieldsMixin, serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["display_name", "phone"]


class SelfSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "display_name", "email", "phone", "role"]
        read_only_fields = fields


class PublicUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "display_name"]


class ReviewSerializer(RejectUnknownFieldsMixin, serializers.ModelSerializer):
    author = PublicUserSerializer(read_only=True)

    class Meta:
        model = Review
        fields = ["id", "product", "text", "author"]
        read_only_fields = ["id", "author"]


class ReviewViewSet(viewsets.ModelViewSet):
    serializer_class = ReviewSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Review.objects.filter(tenant=self.request.user.tenant)

    def perform_create(self, serializer):
        # Server-set ownership and tenant: never from request.data.
        serializer.save(author=self.request.user, tenant=self.request.user.tenant)
```

Where admins may edit more fields, choose the serializer by role in `get_serializer_class()` rather than adding conditional fields to one serializer. Writable nested serializers need explicit `create()` and `update()` methods in DRF, which is a natural place to apply the nested allowlist; do not accept nested input you did not design for. For relationship-dependent reads (a teammate sees an email, a stranger does not), branch in the view on the relationship and pick `SelfSerializer`, a `TeammateSerializer` or `PublicUserSerializer`.

### Spring and Spring Security

**JSON bodies.** Bind `@RequestBody` to a record that contains only the writable fields, copy them onto the entity explicitly, and return a view record. Never bind or return the JPA entity.

```java
public record UpdateProfileRequest(
        @Size(min = 1, max = 80) String displayName,
        @Size(max = 32) String phone) {}

public record SelfView(Long id, String displayName, String email, String role) {
    static SelfView of(User u) {
        return new SelfView(u.getId(), u.getDisplayName(), u.getEmail(), u.getRole().name());
    }
}

@RestController
@RequestMapping("/api/me")
class ProfileController {

    private final UserRepository users;

    ProfileController(UserRepository users) { this.users = users; }

    @PatchMapping
    SelfView update(@AuthenticationPrincipal AppUser principal,
                    @Valid @RequestBody UpdateProfileRequest body) {
        User u = users.findById(principal.id()).orElseThrow();
        if (body.displayName() != null) u.setDisplayName(body.displayName());
        if (body.phone() != null) u.setPhone(body.phone());
        return SelfView.of(users.save(u));
    }
}

@RestController
@RequestMapping("/admin/users")
class AdminUserController {

    // Role changes are a separate, function-level-checked action.
    @PreAuthorize("hasRole('ADMIN')")
    @PatchMapping("/{id}/role")
    void changeRole(@PathVariable Long id, @Valid @RequestBody ChangeRoleRequest body) {
        // ...
    }
}
```

Spring Boot's auto-configured Jackson `ObjectMapper` does not fail on unknown properties, so an extra `"role"` on the record above is silently ignored. That is safe with a record that has no `role`, but if you want unknown keys rejected, set `spring.jackson.deserialization.fail-on-unknown-properties=true` (property name as in Spring Boot 3.x; Spring Boot 4 moves to Jackson 3, so confirm the property and the default for your version). As defence in depth on classes that must be both read and written, Jackson's `@JsonProperty(access = JsonProperty.Access.READ_ONLY)` stops a property being deserialised and `WRITE_ONLY` stops it being serialised (use it for a password field on an input class).

**Form binding.** `@ModelAttribute` binding goes through `WebDataBinder`. Spring's [data binding guidance](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-data-binding.html) recommends records or dedicated input objects, says domain entities are generally not safe for web binding, and offers `setAllowedFields` and declarative binding; it calls `disallowedFields` fragile and says it is due to be deprecated in Spring Framework 7.1. `@InitBinder` configuration applies to data binding, not to `@RequestBody` JSON, which Jackson deserialises separately.

```java
@ControllerAdvice
class BindingConfig {
    @InitBinder
    void initBinder(WebDataBinder binder) {
        // Constructor binding always; setter binding only where allowedFields is set.
        binder.setDeclarativeBinding(true);
    }
}

@Controller
class ProfileFormController {
    @InitBinder("profileForm")
    void allow(WebDataBinder binder) {
        binder.setAllowedFields("displayName", "phone");
    }
}
```

**Field-level read rules.** Separate view records per audience are the simplest answer. Where one object must be shown to different roles, Spring Security's method security can authorise individual getters: annotate the getter with `@PreAuthorize`, mark the repository or service method that returns the object with `@AuthorizeReturnObject`, and use `@HandleAuthorizationDenied` with a `MethodAuthorizationDeniedHandler` to return `null` or a masked value instead of throwing ([method security docs](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html); the annotations arrived in Spring Security 6.3 and are documented in the current 7.x reference).

```java
@Component
public class MaskingHandler implements MethodAuthorizationDeniedHandler {
    @Override
    public Object handleDeniedInvocation(MethodInvocation invocation, AuthorizationResult result) {
        return "***";
    }
}

public class Member {
    // ...
    @PreAuthorize("hasAuthority('member:contact:read')")
    @HandleAuthorizationDenied(handlerClass = MaskingHandler.class)
    public String getPhone() { return phone; }
}

public interface MemberService {
    @AuthorizeReturnObject
    List<Member> teamMembers(Long teamId);
}
```

The handler must be registered as a bean (a `@Bean` method or `@Component`). `@AuthorizeReturnObject` in Spring Security 6.3.0 and 6.3.1 could leave wrapped objects without security advice in some configurations ([CVE-2024-38810](https://spring.io/security/cve-2024-38810)), so use 6.3.2 or later, and cover the masking with a test. Keep this for genuinely shared objects; it is easier to reason about a `TeammateView` record than about proxies on getters.

### Laravel

Validate with a Form Request and pass only `validated()` (or `safe()->only([...])`) to Eloquent. Never `$request->all()`.

```php
<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class UpdateProfileRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user() !== null;
    }

    public function rules(): array
    {
        return [
            'display_name' => ['sometimes', 'string', 'max:80'],
            'phone'        => ['sometimes', 'nullable', 'string', 'max:32'],
        ];
    }
}
```

```php
public function update(UpdateProfileRequest $request): SelfResource
{
    $user = $request->user();
    $user->update($request->validated());   // only keys that have rules
    return new SelfResource($user);
}

public function storeReview(StoreReviewRequest $request): PublicReviewResource
{
    // Ownership through the relationship; tenant from server-side context.
    $review = $request->user()->reviews()->create(
        $request->validated() + ['tenant_id' => $request->user()->tenant_id]
    );
    return new PublicReviewResource($review);
}
```

On the model, declare what may be mass-assigned and what is hidden from serialisation. Laravel 13 documents PHP attributes for this ([Eloquent docs](https://laravel.com/docs/13.x/eloquent#mass-assignment)); Laravel 12 and earlier use the `$fillable`, `$guarded` and `$hidden` properties. Check whether your version still honours the property form before mixing the two styles.

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Foundation\Auth\User as Authenticatable;

#[Fillable(['display_name', 'phone'])]
#[Hidden(['password', 'remember_token', 'two_factor_secret', 'two_factor_recovery_codes'])]
class User extends Authenticatable
{
    // Laravel 12 equivalent:
    // protected $fillable = ['display_name', 'phone'];
    // protected $hidden = ['password', 'remember_token'];
}
```

Avoid `#[Unguarded]` (or `$guarded = []`) on models that contain privileged columns. In local and test environments, `Model::preventSilentlyDiscardingAttributes($this->app->isLocal())` in `AppServiceProvider::boot()` turns a discarded unfillable attribute into an exception, which surfaces handlers that pass more than they should.

For output, return [API Resources](https://laravel.com/docs/13.x/eloquent-resources) rather than models, and use conditional attributes for relationship-dependent fields:

```php
class PublicUserResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id'           => $this->id,
            'display_name' => $this->display_name,
            'email'        => $this->when(
                $request->user()?->can('viewContact', $this->resource),
                $this->email
            ),
        ];
    }
}
```

### GraphQL resolvers

- **Schema:** do not put secrets on output types at all. Mutation input types contain only the fields the caller may write; privileged changes get their own mutation with a function-level check.
- **Resolvers:** authorise sensitive fields in the type's field resolver (or a schema directive enforced by the server), never in the root query resolver, so `user`, `node`, `team.members` and every mutation payload apply the same rule.
- **Introspection:** disable it in production for APIs not meant for third parties (`v5.0.0-4.3.2`), and turn off field suggestions where your server supports that. Neither is an authorization control; they only slow down reconnaissance.

```graphql
type User {
  id: ID!
  displayName: String!
  email: String        # resolver-authorised; null for callers without access
}

input UpdateProfileInput {
  displayName: String
  phone: String
}
```

```javascript
const resolvers = {
  User: {
    email: (user, _args, ctx) =>
      ctx.viewer && (ctx.viewer.id === user.id || ctx.policy.canSeeContact(ctx.viewer, user))
        ? user.email
        : null,
  },
  Mutation: {
    updateProfile: async (_parent, { input }, ctx) => {
      // input already limited by UpdateProfileInput; identity from context
      return ctx.users.update(ctx.viewer.id, {
        display_name: input.displayName,
        phone: input.phone,
      });
    },
  },
};
```

Note that the resolver maps input fields explicitly instead of spreading `input` into the update. If the input type later grows, the database call does not silently follow.

### Property-level regression tests

Property-level rules regress quietly: someone adds a column, the serializer is `__all__`, and nothing fails. Two kinds of tests catch that.

**Write side: privileged fields are not stored.** One test per field in the inventory whose expected writer is not the owner, sending it on the owner's own update and comparing before and after:

```javascript
// Jest + supertest; userA is a fixture account
const PROTECTED = {
  role: "admin",
  is_admin: true,
  email_verified: true,
  tenant_id: 999,
  plan: "pro",
};

describe.each(["application/json", "application/x-www-form-urlencoded"])("%s", (type) => {
  test.each(Object.entries(PROTECTED))("owner cannot set %s", async (field, value) => {
    const before = await db.users.findRaw(userA.id);   // reads the stored row
    const res = await api.patch("/api/me").set(auth(userA)).type(type)
      .send({ display_name: "fixture", [field]: value });
    expect([200, 400, 415]).toContain(res.status);
    const after = await db.users.findRaw(userA.id);
    expect(after[field]).toEqual(before[field]);
  });
});
```

`db.users.findRaw` stands for whatever reads the stored row directly in your stack (a repository call or a database query); the point is to check storage, not the response. Add create-path variants (registration, invitation acceptance, import) and nested variants (`account.plan`).

**Read side: response shapes are exact.** Assert the key set per endpoint and per audience, and fail on any secret-looking key anywhere in the body:

```javascript
const SECRET_KEY = /(password|hash|token|secret|seed|otp|backup|recovery)/i;

function keyPaths(node, prefix = "") {
  if (Array.isArray(node)) return node.slice(0, 3).flatMap((n) => keyPaths(n, `${prefix}[]`));
  if (node && typeof node === "object") {
    return Object.entries(node).flatMap(([k, v]) => {
      const p = prefix ? `${prefix}.${k}` : k;
      return [p, ...keyPaths(v, p)];
    });
  }
  return [];
}

test("teammate view of a comment author is the public view", async () => {
  const res = await api.get(`/api/documents/${sharedDoc.id}/comments`).set(auth(userA));
  const author = res.body.comments.find((c) => c.author.id === userB.id).author;
  expect(Object.keys(author).sort()).toEqual(["display_name", "id"]);
});

test("no endpoint in the smoke set returns secret-looking keys", async () => {
  for (const path of SMOKE_PATHS) {
    const res = await api.get(path).set(auth(userA));
    expect(keyPaths(res.body).filter((k) => SECRET_KEY.test(k))).toEqual([]);
  }
});
```

**Contract:** in your OpenAPI document, give request bodies their own schemas with `additionalProperties: false`, and mark server-set response properties `readOnly: true`. Contract-testing tools can then fail a build when the implementation accepts or returns more than the contract says. In GraphQL, a schema test that lists every field tagged sensitive and asserts it has an authorization rule serves the same purpose.

## Practice labs

**PortSwigger Web Security Academy**

- [Exploiting a mass assignment vulnerability](https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability): a checkout request accepts a hidden discount property you find in the matching GET response (GT-WEB-BOPLA-1, 7).
- [User role can be modified in user profile](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile): a role ID added to the email-change JSON body is stored (GT-WEB-BOPLA-5).
- [User ID controlled by request parameter with password disclosure](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure): an account page that pre-fills the password, combined with an IDOR (GT-WEB-BOPLA-3).
- [Accidental exposure of private GraphQL fields](https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure): a `User` type exposes a password field (GT-WEB-BOPLA-11).
- [Accessing private GraphQL posts](https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts): a field that the front end never requests is queryable (GT-WEB-BOPLA-11).

**OWASP Juice Shop** (challenge names as in the [companion guide](https://pwning.owasp-juice.shop/companion-guide/latest/part2/improper-input-validation.html))

- *Admin Registration* (Improper Input Validation): register with an admin role (GT-WEB-BOPLA-10).
- *Deluxe Fraud* (Improper Input Validation): obtain a deluxe membership without paying (GT-WEB-BOPLA-7).
- *Forged Feedback* and *Forged Review* (Broken Access Control): post as another user (GT-WEB-BOPLA-6).
- *Password Hash Leak* (Sensitive Data Exposure): a response carries a password hash (GT-WEB-BOPLA-3).

**OWASP crAPI** ([challenges](https://github.com/OWASP/crAPI/blob/develop/docs/challenges.md))

- Excessive Data Exposure: Challenge 4 (an endpoint that leaks sensitive information of other users) and Challenge 5 (an internal property of a video).
- Mass Assignment: Challenge 8 (get an item for free), Challenge 9 (increase your balance by $1,000 or more) and Challenge 10 (update internal video properties).

**VAmPI** ([repo](https://github.com/erev0s/VAmPI)): its vulnerability list includes Mass Assignment (on registration) and "Excessive Data Exposure through debug endpoint", where `GET /users/v1/_debug` returns all details for all users.

## Real-world cases

| Case | What happened | Lesson |
|---|---|---|
| GitHub public-key incident, 2012 ([GitHub blog](https://github.blog/2012-03-04-public-key-security-vulnerability-and-mitigation/), [CVE-2012-2055](https://www.cve.org/CVERecord?id=CVE-2012-2055)) | A user exploited the public key update form to add his key to the `rails` organisation and pushed a commit as a demonstration. GitHub attributed it to a failure to check incoming form parameters (mass assignment). The CVE record for GitHub Enterprise describes the attacker setting `public_key[user_id]`. | The ownership reference was bindable on an update form. This incident is why Rails moved to strong parameters and why Django's ModelForm documentation warns against `__all__`. |
| Uber partners.uber.com, [HackerOne #99424](https://hackerone.com/reports/99424) (disclosed 2016, bounty $1,000) | After acceptance into the driver programme, the name fields were locked in the UI. Adding `first_name` and `last_name` inputs back into the form let a driver change their name anyway. | A field locked in the UI was still writable on the server: the client was the only control (GT-WEB-BOPLA-5). |
| HackerOne GraphQL, [HackerOne #489146](https://hackerone.com/reports/489146) (disclosed 2019, rated critical) | The `users` connection in HackerOne's GraphQL API returned private fields of other users, including email addresses, OTP backup codes and account recovery phone data. | Sensitive fields on a type with no field-level authorization, reachable through a list (GT-WEB-BOPLA-3, 11). |
| HackerOne `ShareReportViaEmail`, [HackerOne #2357012](https://hackerone.com/reports/2357012) (disclosed 2024, rated medium) | A mutation's payload returned the report object, including its `impact` field, without the redaction that was meant to hide parts of it. | Redaction applied on one path does not cover mutation payloads; authorise and redact on the type (GT-WEB-BOPLA-11). |
| AnythingLLM, CVE-2024-0404 ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-0404), [huntr report](https://huntr.com/bounties/b4355bae-766a-4bb0-942b-607bc491b23d), [fix commit](https://github.com/mintplex-labs/anything-llm/commit/8cd3a92c660b202655d99bee90b2864694c99946)) | The invitation-acceptance endpoint `/api/invite/:code` accepted a `role` property, so an invited user could create an admin account (CWE-915). The fix takes only the username and password from the body and sets the role to `default` on the server. | A textbook create-path mass assignment and a textbook fix: pick the allowed fields and set the privileged one server-side (GT-WEB-BOPLA-10). |
| Peloton, "Tour de Peloton" by Pen Test Partners, 2021 ([write-up](https://www.pentestpartners.com/security-blog/tour-de-peloton-exposed-user-data/)) | API endpoints for class statistics and user search, and GraphQL endpoints, returned profile data (including age, gender, location and workout statistics) even for accounts set to private; initially without authentication, and after a partial fix to any authenticated user. | A privacy setting enforced in the UI but not in list and search serialisers; requiring login is not a fix when anyone can register (GT-WEB-BOPLA-4). |

## Rating findings

Rate by what the field gives the attacker, who can reach it, and how many records it affects. Mass assignment is usually rated by its *outcome* (a role change is privilege escalation); excessive data exposure by the *sensitivity* of what leaks and to whom.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Role or admin flag set at unauthenticated registration | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | No account needed; full application compromise. |
| Any user sets own role to platform admin through profile update | Critical/High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Low privilege required (self-registration often enough); full admin. Use `S:C` only if the admin role controls a separately authorised system (another tenant in the same application stays `S:U`, per the series convention). |
| Reset token, TOTP seed or session ID of other users in a response | High–Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1) | Direct account takeover of the users whose data you can reach; Critical when the endpoint is a list or unauthenticated. |
| Ownership or tenant field writable (objects created as, or moved to, another user or tenant) | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` (6.5) | Integrity impact on other users; raise confidentiality to `C:H` when moving an object into your tenant exposes it, and treat cross-tenant moves as High–Critical. |
| Price, balance, plan or payment status writable | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` (6.5) | CVSS under-scores direct financial loss; state the business impact (free goods, credit) and rate High in the report. |
| `email_verified` writable, bypassing verification | Medium–High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` (5.4) | Depends on what trusts the flag: domain auto-join, SSO linking or invitations push it up. |
| Other users' contact details or address in embedded objects or search | Medium–High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Sensitive PII of other users; High when a search endpoint makes it reachable for any user at scale, Low–Medium for colleagues' work details. |
| Password hash returned to the owner only | Medium | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N` (3.1) | Owner already controls the account; the risk is leakage through logs and caches and chaining with another bug. Many programmes rate this Medium by policy. |
| Internal flags or IDs in responses (no sensitive value) | Low/Info | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (4.3), or none | Evidence of whole-object serialisation; useful for the write tests. Info if nothing in it is sensitive. |
| GraphQL introspection enabled on a private API, no field-level issue | Info/Low | none | Reconnaissance aid (`v5.0.0-4.3.2`), not an exposure by itself. |
| Privileged field visible in OpenAPI request schema but rejected by the server | Info | none | Documentation defect only; report so the contract matches the implementation. |

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 / API Top 10 |
|---|---|---|---|---|
| GT-WEB-BOPLA-1 | WSTG-INJT-20, WSTG-APIT-01 | v5.0.0-8.1.2 | CWE-915 | A08:2025, API3:2023 |
| GT-WEB-BOPLA-2 | WSTG-APIT-03 | v5.0.0-15.3.1, v5.0.0-8.3.1 | CWE-213, CWE-200 | A01:2025, API3:2023 |
| GT-WEB-BOPLA-3 | WSTG-APIT-03 | v5.0.0-15.3.1, v5.0.0-14.2.6 | CWE-200, CWE-201 | A01:2025, API3:2023 |
| GT-WEB-BOPLA-4 | WSTG-APIT-03 | v5.0.0-8.2.3, v5.0.0-15.3.1 | CWE-213, CWE-200 | A01:2025, API3:2023 |
| GT-WEB-BOPLA-5 | WSTG-INJT-20, WSTG-ATHZ-03 | v5.0.0-15.3.3, v5.0.0-8.2.3 | CWE-915 | A08:2025, A01:2025, API3:2023 |
| GT-WEB-BOPLA-6 | WSTG-INJT-20, WSTG-APIT-02 | v5.0.0-15.3.3, v5.0.0-8.2.2 | CWE-915, CWE-639 | A08:2025, A01:2025, API3:2023, API1:2023 |
| GT-WEB-BOPLA-7 | WSTG-INJT-20, WSTG-BUSL-01 | v5.0.0-15.3.3, v5.0.0-8.2.3 | CWE-915 | A08:2025, API3:2023 |
| GT-WEB-BOPLA-8 | WSTG-INJT-20 | v5.0.0-15.3.3 | CWE-915 | A08:2025, API3:2023 |
| GT-WEB-BOPLA-9 | WSTG-INJT-20, WSTG-INJT-04 | v5.0.0-15.3.3, v5.0.0-15.3.7 | CWE-915, CWE-235 | A08:2025, API3:2023 |
| GT-WEB-BOPLA-10 | WSTG-INJT-20, WSTG-ATHZ-03 | v5.0.0-15.3.3 | CWE-915 | A08:2025, A01:2025, API3:2023 |
| GT-WEB-BOPLA-11 | WSTG-APIT-99, WSTG-APIT-03 | v5.0.0-8.2.3, v5.0.0-4.3.2 | CWE-213, CWE-200, CWE-915 | A01:2025, API3:2023 |
| GT-WEB-BOPLA-12 | WSTG-ATHZ-03, WSTG-APIT-03 | v5.0.0-8.1.2, v5.0.0-8.2.3 | CWE-213, CWE-863 | A01:2025, API3:2023 |

API3:2023 lists CWE-213 and CWE-915. In the OWASP Top 10 2025, CWE-200 and CWE-201 map to A01:2025 Broken Access Control and CWE-915 maps to A08:2025 Software or Data Integrity Failures; where a mass assignment results in privilege escalation, we also cite A01:2025.

## References

**OWASP**

- WSTG: [Mass Assignment (WSTG-INJT-20)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/20-Mass_Assignment), [Excessive Data Exposure (WSTG-APIT-03)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/03-Excessive_Data_Exposure), [GraphQL (WSTG-APIT-99)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/99-GraphQL), [API Reconnaissance (WSTG-APIT-01)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/01-API_Reconnaissance), [Privilege Escalation (WSTG-ATHZ-03)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/03-Privilege_Escalation), [HTTP Parameter Pollution (WSTG-INJT-04)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/04-HTTP_Parameter_Pollution)
- [ASVS 5.0 on GitHub](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en): V8 Authorization, V15 Secure Coding and Architecture, V14 Data Protection, V4 API and Web Service
- [API3:2023 Broken Object Property Level Authorization](https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- OWASP Top 10 2025: [A01:2025 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/), [A08:2025 Software or Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)
- Cheat Sheets: [Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html), [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [GraphQL](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)

**CWE and standards**

- [CWE-915](https://cwe.mitre.org/data/definitions/915.html), [CWE-213](https://cwe.mitre.org/data/definitions/213.html), [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-201](https://cwe.mitre.org/data/definitions/201.html), [CWE-235](https://cwe.mitre.org/data/definitions/235.html)
- [RFC 6902 JSON Patch](https://www.rfc-editor.org/rfc/rfc6902), [RFC 7396 JSON Merge Patch](https://www.rfc-editor.org/rfc/rfc7396)

**PortSwigger**

- [API testing](https://portswigger.net/web-security/api-testing) (includes mass assignment), [GraphQL API vulnerabilities](https://portswigger.net/web-security/graphql), [Access control](https://portswigger.net/web-security/access-control)

**Framework documentation**

- [Zod API](https://zod.dev/api), [Joi API reference](https://github.com/hapijs/joi/blob/master/API.md), [Mongoose schemas (`strict`)](https://mongoosejs.com/docs/guide.html), [Mongoose SchemaTypes (`select`, `immutable`)](https://mongoosejs.com/docs/schematypes.html), [Prisma: excluding fields](https://www.prisma.io/docs/orm/prisma-client/queries/excluding-fields)
- [Django ModelForm: selecting the fields to use](https://docs.djangoproject.com/en/stable/topics/forms/modelforms/), [DRF serializers](https://www.django-rest-framework.org/api-guide/serializers/)
- [Spring MVC data binding and model design](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-data-binding.html), [Spring Security method security](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html), [CVE-2024-38810](https://spring.io/security/cve-2024-38810)
- [Laravel Eloquent: mass assignment](https://laravel.com/docs/13.x/eloquent#mass-assignment), [Eloquent serialization](https://laravel.com/docs/13.x/eloquent-serialization), [Eloquent API resources](https://laravel.com/docs/13.x/eloquent-resources)

**Tools**

- [Param Miner](https://github.com/PortSwigger/param-miner), [Arjun](https://github.com/s0md3v/Arjun), [Autorize](https://github.com/PortSwigger/autorize), [Auth Analyzer](https://github.com/simioni87/auth_analyzer), [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix), [InQL](https://github.com/doyensec/inql), [clairvoyance](https://github.com/nikitastupin/clairvoyance), [graphql-cop](https://github.com/dolevf/graphql-cop)
- Labs: [OWASP crAPI](https://github.com/OWASP/crAPI), [VAmPI](https://github.com/erev0s/VAmPI), [OWASP Juice Shop companion guide](https://pwning.owasp-juice.shop/companion-guide/latest/part2/improper-input-validation.html)
