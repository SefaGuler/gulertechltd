---
title: "Vertical Privilege Escalation and Function-Level Authorization (BFLA)"
date: 2026-11-15 18:02:00 +0000
subcategory: access-control
summary: "Testing function-level authorisation: role matrices, finding admin functions, role self-assignment, GraphQL mutations, chains and framework fixes."
refs: [WSTG-ATHZ-03, WSTG-ATHZ-02, WSTG-APIT-04, WSTG-APIT-01, WSTG-APIT-99, WSTG-BUSL-02, WSTG-BUSL-06, v5.0.0-8.1.1, v5.0.0-8.2.1, v5.0.0-8.3.1, v5.0.0-8.4.2, v5.0.0-15.3.3, v5.0.0-4.3.2, v5.0.0-13.4.5, v5.0.0-16.3.2, "API5:2023", "API3:2023", "A01:2025", CWE-269, CWE-285, CWE-862, CWE-863, CWE-266, CWE-915, CWE-602]
tags: [web, access-control, bfla, privilege-escalation, rbac, graphql]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and the [Access Control testing guide](/web/web-access-control-testing-guide/). It covers **vertical privilege escalation**: a user with a lower role (a member, a viewer, a customer, sometimes nobody at all) gets the application to run a function that only a higher role (manager, admin, support, owner) should be able to run. In API terms this is **Broken Function Level Authorization** (BFLA, [API5:2023](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)), and the OWASP tests are WSTG-ATHZ-03 (Privilege Escalation) and WSTG-APIT-04 (API Broken Function Level Authorization). The note covers role models and where function-level checks go wrong, how to build a role-by-function matrix, how to find privileged functions the UI hides, how to call them with a low-privilege session, role and permission values the client controls, role self-assignment and role ceilings, privileged actions hidden inside ordinary features (bulk operations, import, impersonation, feature flags), GraphQL mutations without resolver-level checks, and chains where a horizontal bug against an administrator's own record becomes vertical. The fixes are shown for Express, Django and DRF, Spring Security and Laravel, together with regression tests that iterate the role matrix. Object-level access (user A reading user B's invoice) is covered in [IDOR and BOLA](/web/web-idor-bola/). Tricks that get a request *past* a check that does exist (path normalisation, `X-Original-URL`, method override headers, IP allowlists) are in [Authorisation bypass techniques](/web/web-authorization-bypass-techniques/). Mass assignment as a general technique is in [Mass assignment and BOPLA](/web/web-mass-assignment-bopla/).

## Contents

- [How it works](#how-it-works)
  - [Vertical, horizontal, function and object](#vertical-horizontal-function-and-object)
  - [Role models: RBAC, ABAC and ReBAC](#role-models-rbac-abac-and-rebac)
  - [Where the function-level decision belongs](#where-the-function-level-decision-belongs)
  - [How privileged functions reach the client](#how-privileged-functions-reach-the-client)
- [What goes wrong](#what-goes-wrong)
  - [The UI is the only gate](#the-ui-is-the-only-gate)
  - [Allow by default and forgotten routes](#allow-by-default-and-forgotten-routes)
  - [Admin operations on user resources](#admin-operations-on-user-resources)
  - [Role values the client controls](#role-values-the-client-controls)
  - [No role ceiling when roles are granted](#no-role-ceiling-when-roles-are-granted)
  - [Privileged side doors in ordinary features](#privileged-side-doors-in-ordinary-features)
  - [GraphQL resolvers without checks](#graphql-resolvers-without-checks)
  - [Horizontal bugs that become vertical](#horizontal-bugs-that-become-vertical)
  - [Checks that trust the wrong signal](#checks-that-trust-the-wrong-signal)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-WEB-PRIV-1: Build the role and function matrix](#gt-web-priv-1-build-the-role-and-function-matrix)
  - [GT-WEB-PRIV-2: Discover privileged functions the UI hides](#gt-web-priv-2-discover-privileged-functions-the-ui-hides)
  - [GT-WEB-PRIV-3: Call privileged functions with a lower-privilege session](#gt-web-priv-3-call-privileged-functions-with-a-lower-privilege-session)
  - [GT-WEB-PRIV-4: Sibling operations and verbs on the same resource](#gt-web-priv-4-sibling-operations-and-verbs-on-the-same-resource)
  - [GT-WEB-PRIV-5: Role and permission values in client requests](#gt-web-priv-5-role-and-permission-values-in-client-requests)
  - [GT-WEB-PRIV-6: Role ceilings and self-assignment of roles and groups](#gt-web-priv-6-role-ceilings-and-self-assignment-of-roles-and-groups)
  - [GT-WEB-PRIV-7: Privileged actions inside bulk, import and multi-step features](#gt-web-priv-7-privileged-actions-inside-bulk-import-and-multi-step-features)
  - [GT-WEB-PRIV-8: Impersonation, support tooling and feature flags](#gt-web-priv-8-impersonation-support-tooling-and-feature-flags)
  - [GT-WEB-PRIV-9: GraphQL mutations and privileged queries](#gt-web-priv-9-graphql-mutations-and-privileged-queries)
  - [GT-WEB-PRIV-10: Horizontal-to-vertical chains against higher-role accounts](#gt-web-priv-10-horizontal-to-vertical-chains-against-higher-role-accounts)
  - [GT-WEB-PRIV-11: Administrative interface separation and layered controls](#gt-web-priv-11-administrative-interface-separation-and-layered-controls)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Node.js and Express](#nodejs-and-express)
  - [Django and Django REST framework](#django-and-django-rest-framework)
  - [Spring Security](#spring-security)
  - [Laravel](#laravel)
  - [GraphQL resolvers](#graphql-resolvers)
  - [Separating administrative interfaces](#separating-administrative-interfaces)
  - [Authorisation regression tests](#authorisation-regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Vertical, horizontal, function and object

WSTG-ATHZ-03 separates two directions of escalation. **Horizontal** escalation is reaching resources that belong to a peer with the same role: user A reads user B's order. **Vertical** escalation is reaching what a higher role can do: a customer runs a staff function, a staff user runs an administrator function. The API Security Top 10 slices the same space along a different axis. **BOLA** (API1:2023) is about *which object* a function is applied to. **BFLA** (API5:2023) is about *which function* the caller may invoke at all. **BOPLA** (API3:2023) is about *which properties* of an object the caller may read or write.

In practice the three overlap, and a good finding names the one that was actually missing:

| Question the server should ask | Missing check | Typical name | Where we cover it |
|---|---|---|---|
| May this caller run `DELETE /api/users/{id}` at all? | Function-level | BFLA, vertical escalation | This note |
| May this caller delete *this* user? | Object-level | IDOR, BOLA, horizontal escalation | [IDOR and BOLA](/web/web-idor-bola/) |
| May this caller set `role` on this user? | Property-level | Mass assignment, BOPLA | [Mass assignment and BOPLA](/web/web-mass-assignment-bopla/) |
| May this caller act in *this* organisation? | Tenant-level | Cross-tenant access | [Multi-tenant isolation](/web/web-multi-tenant-isolation/) |

A role change through a `role` field in a profile update is *both* a property-level flaw and a vertical escalation. We test it here (because the result is a role you were not given) and point to the mass-assignment note for the technique.

ASVS 5.0 states the function-level requirement directly. `v5.0.0-8.2.1` (L1) requires that function-level access is restricted to consumers with explicit permissions. `v5.0.0-8.1.1` (L1) requires the authorisation rules to be *documented*, which is what makes a role matrix testable. `v5.0.0-8.3.1` (L1) requires enforcement at a trusted service layer, not in client-side code.

### Role models: RBAC, ABAC and ReBAC

Function-level checks are expressed in one of three models, and each fails in its own way.

**Role-based access control (RBAC).** Users hold roles; roles hold permissions; a function requires a permission or a role. This is the model most applications start with (`hasRole('ADMIN')`, `is_staff`, `user.role === 'admin'`). It is easy to reason about, and it is the model a role matrix maps onto. Its typical failures are:

- **Checks on the role name rather than a permission.** Code that asks `role == 'admin'` breaks the day someone adds `super_admin` or `billing_admin`: either the new role cannot do what it should (and someone loosens the check), or a role hierarchy is implemented as string comparison (`role >= 'manager'`) and orders alphabetically.
- **Role sprawl.** A product with 30 custom roles nobody can enumerate has no reviewable matrix. The OWASP [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) recommends attribute- or relationship-based models for applications for this reason.
- **Global roles in a scoped world.** "Admin" means admin of *which* organisation, project or workspace? A role held in tenant A must not authorise functions in tenant B. That is a [multi-tenant](/web/web-multi-tenant-isolation/) problem, but it often shows up first as a vertical one.

**Attribute-based access control (ABAC).** The decision uses attributes of the subject (role, department, clearance), the resource (owner, state, classification), the action and the environment (time, network, device). "A manager may approve expenses under 5,000 for their own cost centre" is ABAC. Function-level and object-level checks merge here: the function "approve" is allowed only for certain objects. The typical failure is a policy that evaluates attributes **the client supplied** (a `department` field in the request body) instead of attributes the server loaded.

**Relationship-based access control (ReBAC).** The decision follows relationships in a graph: "user is an *owner* of *workspace*; owners of a workspace may *manage members* of that workspace". Google's Zanzibar paper popularised it; OpenFGA, SpiceDB and similar engines implement it. The typical failures are relationship writes that are not themselves authorised (anyone who can write the tuple "user X is owner of workspace W" is an owner), and relations inherited too broadly (a *viewer* of a parent folder becomes an *editor* of a child).

Whatever the model, a vertical escalation test asks the same thing: for each function, which subjects should be allowed, and does the server agree?

### Where the function-level decision belongs

Trace a request through a typical stack and note every place a check *could* sit:

1. **Edge** (CDN, WAF, API gateway, ingress). Can block whole path prefixes (`/admin/*`) or require a token scope. It sees only the URL, method and headers, and it often parses the path differently from the application. Useful as a second layer; never the only one.
2. **Router and middleware** (Express middleware, Spring Security's filter chain, Django middleware, Laravel route middleware). The first place that knows which handler will run. This is where *deny-by-default* is cheapest to implement: any route without a declared rule is refused.
3. **Controller or handler** (`@PreAuthorize` on a controller method, DRF `permission_classes`, `Gate::authorize()` in a controller). Knows the operation and its parameters.
4. **Service or domain layer** (method security on a service, a policy call inside `UserService.setRole()`). Knows the business meaning. This is the layer every entry point (REST, GraphQL, a background job, an admin CLI) shares, which is why the graphql.org guidance on [authorisation](https://graphql.org/learn/authorization/) puts the check there.
5. **Data layer** (query scoping, row-level security). Best for object-level and tenant-level filtering; weak for "may this role call this function at all".

Function-level flaws happen when the check lives only in a layer that some entry point skips: the admin SPA hides the button (no server check), the REST controller checks but the GraphQL resolver calling the same repository does not, the `v2` route has middleware but `v1` was never retired, the gateway blocks `/admin` but the same handler is also mounted at `/internal`.

How routing works matters for testing. Frameworks map a method plus a path template (`DELETE /api/users/:id`) to a handler. A check attached to a *router* or *prefix* covers what is mounted under it, and nothing else. A check attached to a *handler* covers that handler only. A check attached to a *service method* covers every handler that calls it. When you find one unprotected function, ask which of these the team used; it tells you where the siblings are.

**What changes by client type:**

- **Server-rendered apps** tend to put admin pages under one prefix with one guard, and to forget the form-post targets (`POST /admin/users/delete`) or the AJAX endpoints those pages call.
- **SPAs** ship the whole route table, sometimes including the admin area, to every browser. The client-side route guard (`canActivate`, a React `<ProtectedRoute>`) is a UX feature; the API behind it must refuse on its own.
- **Public and partner APIs** have documentation that lists every operation, including administrative ones, and often a single API serving several roles.
- **GraphQL** has one HTTP endpoint and many operations. A check "on the endpoint" means nothing; each query field and mutation is a function.
- **Mobile back-ends** often expose operations the web client never calls, older API versions kept for app versions still in the field, and support or debug operations used by internal builds.

### How privileged functions reach the client

An attacker does not need to guess most admin functions. They leak through:

| Source | What you find | Notes |
|---|---|---|
| JavaScript bundles | Route tables, API client methods, GraphQL documents, role names, feature-flag keys | Code splitting may put admin code in a separate chunk that is still publicly downloadable |
| Source maps (`*.js.map`) | Original source, comments, file layout (`src/admin/...`) | Referenced by a `sourceMappingURL` comment, or present at a predictable path even when not referenced |
| OpenAPI / Swagger documents | Every operation, parameter and schema, including `admin` tags | Common defaults include `/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/swagger-ui/`, `/docs`; check rather than assume |
| GraphQL introspection | Every query, mutation, type and argument | When disabled, field suggestions in error messages and tools such as clairvoyance can rebuild much of it |
| Mobile apps | Endpoint strings, older API versions, debug menus | Decompiling is in the mobile series; the endpoints you find are tested here |
| Naming conventions | `/api/admin/*`, `/internal/*`, `/manage/*`, `/staff/*`, `/support/*`, `/ops/*` | API5:2023 warns not to assume a function is user-level just because of its path |
| REST conventions | A `GET /api/users/{id}` implies `PUT`, `PATCH` and `DELETE` on the same path | The most common BFLA in practice |
| Higher-role traffic | Requests you capture while logged in as the client's admin test account | The best source by far; this is why you ask for an admin account |

ASVS treats exposure as its own control. `v5.0.0-13.4.5` (L2) asks that documentation for internal APIs and monitoring endpoints is not exposed unless intended, and `v5.0.0-4.3.2` (L2) that GraphQL introspection is disabled in production unless the API is meant for other parties. These are worth recording, but they are not the vulnerability: a function that is properly protected stays protected when everyone knows its name.

## What goes wrong

### The UI is the only gate

The front end renders the "Admin" menu only for admins, and the developers treat that as the access control. The API endpoints the admin pages call have no role check. WSTG-ATHZ-03 calls this out explicitly ("authorization validation at the GUI level only"), and it is CWE-602, Client-Side Enforcement of Server-Side Security.

**Why it matters:** anyone who can read the JavaScript, or who has seen one admin request, can call the function. **Where to look:** admin SPA routes and the API client methods they import; any API whose OpenAPI document has an `admin` tag.

### Allow by default and forgotten routes

The framework allows any route that does not opt in to a check. Each new endpoint needs a developer to remember a decorator, middleware or annotation. Most do; one does not. Typical leftovers: an endpoint added for a migration or a one-off support task, a health or metrics endpoint that also exposes a "flush cache" or "reindex" action, an old API version (`/api/v1/`) still routed, a debug controller (`/debug/`, `/_debug`) enabled in production.

**Why it matters:** one forgotten route is enough, and the omission is invisible in code review unless the reviewer checks every route. **Where to look:** routes that appear in the bundle, docs or mobile app but not in the UI; endpoints whose names do not match the rest of the API's style.

### Admin operations on user resources

The resource `/api/users/{id}` serves both the user ("read my profile", "update my display name") and the administrator ("disable this user", "change this user's role", "delete this user"). The handler checks that the caller is authenticated and that `id` is accessible (or not even that), and the *operation* is never checked against the caller's role. API5:2023's guidance is blunt about this: administrative functions often sit under the same paths as regular ones.

**Why it matters:** `DELETE` or `PATCH` on a resource you can `GET` is the cheapest BFLA test there is, and it finds real bugs. **Where to look:** every resource the user can read; extra path segments (`/users/{id}/role`, `/users/{id}/disable`, `/users/{id}/impersonate`); RPC-style actions (`POST /api/users/{id}:suspend`, `?action=delete`).

### Role values the client controls

The server takes the caller's role, group or permission set from somewhere the caller controls:

- a field in the registration, invitation-acceptance or profile-update body (`"role": "admin"`, `"isAdmin": true`, `"groups": ["staff"]`), accepted through mass assignment;
- a cookie or hidden form field (`role=user`, `<input type="hidden" name="profile" value="SysGuest">`, the WSTG-ATHZ-03 example);
- a request header set by the front end (`X-User-Role: member`), trusted because "only our gateway sets it" (see [bypass techniques](/web/web-authorization-bypass-techniques/) for header trust);
- a claim in a token the server does not verify properly. Token forgery belongs to the Authentication and Session Management subcategories (not yet published); here you only note whether the role comes from the token and whether changing the stored role takes effect.

**Why it matters:** any registered user, often any visitor who can register, becomes an administrator in one request. CVE-2024-0404 and CVE-2023-3460 in [Real-world cases](#real-world-cases) are both this. **Where to look:** sign-up, invitation acceptance, "complete your profile" and organisation-creation flows; any response that echoes a `role`, `permissions` or `groups` property (the property exists in the model, so it may be writable).

### No role ceiling when roles are granted

A role that may grant roles (a manager who invites members, an admin of one project) is allowed to grant **any** role, including one above its own. Or a user may edit their *own* membership record. Or a custom-role builder lets a delegated administrator create a role with permissions they do not hold. Or an API key or personal access token can be created with scopes the user's role does not have.

**Why it matters:** the caller does not escalate directly; they invite a second account (or themselves) at a higher role. The OWASP API5:2023 first scenario is exactly this, an invitation endpoint that accepts an admin role from a non-admin. **Where to look:** invite, member management, group membership, role editor, API key and token creation, ownership transfer.

### Privileged side doors in ordinary features

The headline admin functions are checked, but the same effect is reachable through a feature that a lower role is allowed to use:

- **Bulk operations.** `POST /api/users/bulk` accepts a list of IDs and an `action`. The handler checks the role for `deactivate` (which managers may do) but executes `delete` or `set_role` with the same check.
- **Import.** A CSV import of team members accepts a `role` column. Each row is created through an internal function that does not check the importer's role ceiling.
- **Multi-step flows.** The first step of a sensitive admin flow checks the role; the confirmation step does not (the PortSwigger lab "Multi-step process with no access control on one step" models this, and WSTG-BUSL-06 covers workflow circumvention in general).
- **Impersonation and support tooling.** An "act as user" function for support staff. Questions: who can call it, can it target administrators (impersonating an admin is an escalation for a support agent), is it logged, and does the impersonated session keep a marker that blocks the most sensitive actions?
- **Feature flags and hidden options.** A flag turns on a beta admin console, or a debug parameter (WSTG-BUSL-02 calls these hidden features) enables an operation. The flag is evaluated only in the client, or the flag value can be set by the user.

**Why it matters:** these paths are rarely in the role matrix the developers tested, because nobody thinks of "import" as an admin function. **Where to look:** anything that accepts many items, a file, or a target user other than the caller.

### GraphQL resolvers without checks

GraphQL has one endpoint and many fields. A team that protects the endpoint (authentication required) and then checks roles in *some* resolvers has a function-level gap in every resolver it forgot. Typical misses: mutations added after the initial security review, mutations used only by the admin UI (`setUserRole`, `deleteUser`, `updateFeatureFlags`), queries that return admin-only data (`auditLog`, `allUsers`), and nested fields that expose an admin function through a type (`organization { billingSettings }`). Directive-based checks (`@auth(requires: ADMIN)`) help, but only if a missing directive fails closed. WSTG-APIT-99 notes that GraphQL itself enforces no permissions; that job is entirely the application's.

**Why it matters:** introspection or a leaked schema gives you a complete list of functions, and each one is a separate test. **Where to look:** the `Mutation` type, any query whose name suggests listing or administration, and operations in the bundle that the current role's UI never sends.

### Horizontal bugs that become vertical

An object-level bug becomes a vertical one when the object belongs to a higher role:

- an IDOR on `PUT /api/users/{id}/email` lets you change *an administrator's* e-mail address, then reset their password;
- an IDOR on `POST /api/groups/{id}/members` lets you add yourself to the administrators group;
- an IDOR on `DELETE /api/users/{id}/mfa` removes an administrator's second factor;
- an IDOR on `GET /api/users/{id}/api-keys` returns an administrator's API key.

**Why it matters:** the same bug with a peer as the target is a Medium; with an administrator as the target, it is account takeover of the most privileged account. **Where to look:** every object-level finding from [IDOR and BOLA](/web/web-idor-bola/) whose object type is "user", "membership", "group", "credential" or "session".

### Checks that trust the wrong signal

The function is protected, but the protection can be steered: the proxy blocks `/admin` and the application also answers `/ADMIN` or `/admin;/`; the check reads `X-Original-URL`; the check allows `GET` and the framework honours `X-HTTP-Method-Override: DELETE`; admin access is granted to "internal" IP addresses taken from `X-Forwarded-For`. All of these are in [Authorisation bypass techniques](/web/web-authorization-bypass-techniques/). In this note you establish that the function is privileged and that the direct request is refused; that note tests whether the refusal holds under those tricks.

## Testing

Every test here assumes an **authorised** engagement with written scope and rules of engagement, a bug bounty programme whose rules allow this testing, or a deliberately vulnerable lab. All requests and responses below are **illustrative**: hosts are fictional and we ran nothing against a real target for this note.

### Before you start

**Accounts and roles.** Vertical testing needs one account per role, and preferably two for the roles you test from:

| Account | Why you need it |
|---|---|
| Anonymous (no session) | Catches functions with no authentication at all |
| `member_a`, `member_b` (lowest role, two accounts) | Your low-privilege sessions; B is the target for any state-changing proof |
| `manager_a` (each intermediate role) | Tests role ceilings and delegated administration |
| `admin_test` (client-provided administrator) | Captures privileged traffic and is the *only* higher-role account you ever target in a chain test |
| Second organisation (`tenant-b`) with its own admin | Only for multi-tenant products; see [Multi-tenant isolation](/web/web-multi-tenant-isolation/) |

If the client cannot give you an administrator account, ask for the role documentation and an OpenAPI document instead, and say in the report that vertical coverage is limited to what you could discover.

**Rules that apply to every test:**

- **Own test objects only** for anything that changes state. A cross-account or cross-role proof targets `member_b`, `manager_a` or `admin_test`, never a real user.
- **Least destructive proof first.** Read before write. A harmless change (a display name, a label) before a role change. A role change on `member_b` before any delete. Never a delete of something you did not create.
- **Stop on real data.** If a request returns a real customer's or employee's data, stop that line of testing, keep only the minimum redacted evidence (status, a few field names, a truncated identifier), do not download or keep more, and tell the client contact immediately.
- **No mass enumeration.** Identifier iteration is limited to objects you created or a small range agreed with the client, at a low rate (a few requests per second at most). Listing endpoints such as "all users" are proved with one request and a redacted count, not by paging through them.
- **Admin functions are dangerous by nature.** "Delete all", "reindex", "send newsletter", "rotate keys" and similar functions are proved by showing that the server *accepted the authorisation* (for example a validation error that only appears after the role check) or by running them against a scope that contains only your test objects. Agree the approach with the client for anything irreversible.

**Burp project setup.**

1. Scope the target hosts (`app.example.com`, `api.example.com`, `admin.example.com`) and exclude third parties.
2. Log in as each account in a separate browser profile or Burp's embedded browser with a separate cookie jar, and note how the session travels (cookie, `Authorization: Bearer`, a CSRF token that must be refreshed).
3. Browse the application *as the administrator first*, using every admin screen. That traffic is the list of privileged functions you will replay.
4. Use Logger (or Proxy history with a filter on `api.example.com`) to export the unique method-plus-path pairs.

**Session-swap workflow.** The core move of every test in this note is "take a request the higher role made, send it with the lower role's credentials, compare". Do it three ways:

- **Manually in Repeater**, for anything state-changing: duplicate the tab, replace `Cookie`/`Authorization` with the lower role's value, send, compare with Comparer.
- **Autorize** ([GitHub](https://github.com/PortSwigger/autorize)): paste the lower-privilege cookie or header, browse as the admin, and Autorize replays each request with the low-privilege session and (optionally) with none, flagging responses that look the same. **Configure its interception filters to skip state-changing methods** (or restrict it to your test objects): it replays *everything* the admin does, so an admin "delete" you click becomes a low-privilege delete if the bug exists.
- **AuthMatrix** ([GitHub](https://github.com/SecurityInnovation/AuthMatrix)) or **Auth Analyzer** ([GitHub](https://github.com/PortSwigger/auth-analyzer)): define users and roles, mark which roles each request should succeed for, and run the whole matrix. AuthMatrix saves the configuration, which gives you a regression run for the retest. Auth Analyzer is good at extracting and replacing CSRF tokens per session. ZAP's [Access Control Testing add-on](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/) does the same from a context with users and access rules; note that it requests every URL as every user, so scope it carefully.

**A small comparison helper.** For APIs, a script that replays a fixed list of requests as each role and prints a matrix is often clearer than any extension. This one refuses hosts outside an allowlist, sends only `GET`/`HEAD` unless told otherwise, waits between requests, and prints status, length and a body hash so you can see when a low-privilege response matches the admin's:

```python
#!/usr/bin/env python3
"""Replay a small fixed list of requests as each test role and print a matrix.
Own test objects only. GET/HEAD by default; writes need --allow-write."""
import argparse, hashlib, json, sys, time
from urllib.parse import urlparse
import requests

ALLOWED_HOSTS = {"api.example.com", "app.example.com"}   # edit to your written scope

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("roles", help="JSON: {role: header-value or null}, highest role first")
    ap.add_argument("reqs", help="JSON list: [{method, url, body?}]")
    ap.add_argument("--allow-write", action="store_true")
    ap.add_argument("--delay", type=float, default=1.0)
    a = ap.parse_args()
    roles = json.load(open(a.roles))
    reqs = json.load(open(a.reqs))
    baseline_role = next(iter(roles))
    for r in reqs:
        method = r["method"].upper()
        if urlparse(r["url"]).hostname not in ALLOWED_HOSTS:
            sys.exit(f"refusing out-of-scope host: {r['url']}")
        if method not in ("GET", "HEAD") and not a.allow_write:
            print(f"skip {method} {r['url']} (use --allow-write, own test objects only)")
            continue
        results = {}
        for role, auth in roles.items():
            headers = {"Authorization": auth} if auth else {}
            resp = requests.request(method, r["url"], headers=headers,
                                    json=r.get("body"), allow_redirects=False, timeout=15)
            digest = hashlib.sha256(resp.content).hexdigest()[:10]
            results[role] = (resp.status_code, len(resp.content), digest)
            time.sleep(a.delay)
        base = results[baseline_role]
        print(f"\n{method} {r['url']}")
        for role, (code, length, digest) in results.items():
            same = " SAME-AS-" + baseline_role if role != baseline_role and digest == base[2] and code < 300 else ""
            print(f"  {role:<10} {code}  {length:>7}  {digest}{same}")

if __name__ == "__main__":
    main()
```

`roles.json` holds placeholders you fill locally, for example `{"admin_test": "Bearer <TOKEN_ADMIN_TEST>", "manager_a": "Bearer <TOKEN_MANAGER_A>", "member_a": "Bearer <TOKEN_MEMBER_A>", "anon": null}`. Keep the file out of any repository.

**Rate limits and noise.** Admin endpoints are often monitored. Tell the client's security team your source IP addresses and test accounts before you start, keep request rates low, and expect some accounts to be locked by anomaly detection; that is a good sign, and worth a line in the report.

### GT-WEB-PRIV-1: Build the role and function matrix

*Guler Tech methodology.* Implements the "Role/Privilege Manipulation" and "Vertical Bypass" preparation of WSTG-ATHZ-03 and the "Identify Function-Level Endpoints" step of WSTG-APIT-04.

#### What it checks

That every privileged function is known, that the intended set of roles for each one is written down, and that you have a list to test against. It also checks ASVS `v5.0.0-8.1.1` (L1): whether the client's authorisation documentation defines function-level rules at all.

#### Prerequisites

The client's role documentation (or a walkthrough with a product owner), an admin test account, and Burp traffic captured while using every admin screen.

#### Steps

1. Collect the roles and what each is meant to do. Ask specifically about roles that are easy to forget: support or customer-success staff, billing-only admins, read-only auditors, partner or reseller accounts, service accounts and API keys, and "owner" versus "admin".
2. From the admin traffic, list each **function** as method plus path template (`DELETE /api/users/{id}`), not each URL. Add GraphQL operations by name (`mutation setUserRole`).
3. Group functions by area (user management, billing, organisation settings, content moderation, integrations, support tooling).
4. For each function and role, record the *expected* result: allowed, denied, or allowed with a condition ("manager: only for members of own team"; "admin: not on the last owner").
5. Add the functions found in [GT-WEB-PRIV-2](#gt-web-priv-2-discover-privileged-functions-the-ui-hides) as you find them.
6. Load the matrix into AuthMatrix (requests as rows, roles as columns) or into your own script's input files.

#### Observation

An illustrative matrix for a SaaS product with four roles:

| Function | Anonymous | Member | Manager | Admin | Notes |
|---|---|---|---|---|---|
| `GET /api/me` | deny | allow | allow | allow | |
| `GET /api/admin/users` | deny | deny | deny | allow | Lists every user in the org |
| `POST /api/orgs/{org}/invitations` | deny | deny | allow (role ≤ manager) | allow | Role ceiling |
| `PATCH /api/users/{id}` (`displayName`) | deny | own only | own team | allow | Object-level condition |
| `PATCH /api/users/{id}` (`role`) | deny | deny | member ↔ manager, own team | allow | Property plus ceiling |
| `DELETE /api/users/{id}` | deny | deny | deny | allow (not self) | |
| `POST /api/support/impersonate` | deny | deny | deny | allow (not other admins) | Plus support role |
| `mutation updateFeatureFlags` | deny | deny | deny | allow | GraphQL |

#### Evaluation

- **Fail (documentation finding, ASVS `v5.0.0-8.1.1`):** the client cannot say which roles may run a privileged function, or two people give different answers. Report it as Low or Info; it is also the root cause of most of the findings that follow.
- **Pass:** every privileged function has an agreed expected result per role. The matrix itself is the input for tests 3 to 10, not a pass of them.

#### False positives

Do not report a function as "undocumented" when it is legitimately available to everyone (public catalogue, status page). Mark it "public by design" in the matrix so the later tests do not flag it.

#### Automation

Keep the matrix as data (YAML or JSON) in the client's repository, and drive both AuthMatrix and the CI tests in [Authorisation regression tests](#authorisation-regression-tests) from the same file. When the matrix and the route table disagree, the build should fail.

### GT-WEB-PRIV-2: Discover privileged functions the UI hides

*Guler Tech methodology.* Implements WSTG-APIT-01 (API Reconnaissance) as input to WSTG-ATHZ-03 and WSTG-APIT-04, plus the hidden-feature part of WSTG-BUSL-02.

#### What it checks

Which privileged functions exist beyond those your admin account showed you: functions referenced in client code, documentation, schemas and mobile apps, or implied by naming and REST conventions. Discovery is not itself a vulnerability; its output feeds [GT-WEB-PRIV-3](#gt-web-priv-3-call-privileged-functions-with-a-lower-privilege-session).

#### Prerequisites

A member session; the admin traffic from test 1 for comparison.

#### Steps

1. **JavaScript bundles.** Load the app as a member and save every script. Pull out path-like strings and look for admin areas, role names and flag keys:

```bash
mkdir -p recon/js && cd recon/js
curl -s https://app.example.com/ | grep -oE 'src="[^"]+\.js"' | cut -d'"' -f2 | sort -u > scripts.txt
while read -r p; do curl -s "https://app.example.com${p}" -o "$(basename "$p")"; sleep 1; done < scripts.txt
grep -ohE '"/(api|internal|admin|manage|support|ops)/[A-Za-z0-9_/{}:.-]+"' ./*.js | sort -u > paths.txt
grep -ohiE '(isAdmin|hasRole|role ?===? ?"[a-z_]+"|permissions?\.[a-z_]+|featureFlags?\.[A-Za-z_]+)' ./*.js | sort | uniq -c | sort -rn | head -50
```

Modern bundlers split code by route, so the admin area may live in its own chunk that the member UI never loads. Look for a chunk manifest (`asset-manifest.json`, `manifest.json`, a `webpack` runtime with a chunk map) and fetch the chunks it names. [LinkFinder](https://github.com/GerbenJavado/LinkFinder) automates the extraction.

2. **Source maps.** Check each bundle for a `sourceMappingURL` comment and also request `<bundle>.map` directly. If maps are served, rebuild the source tree with [sourcemapper](https://github.com/denandz/sourcemapper) and read the admin API client and route guards:

```bash
tail -c 300 main.3f2a1c.js | grep -o 'sourceMappingURL=.*'
curl -s -o /dev/null -w '%{http_code}\n' https://app.example.com/static/js/main.3f2a1c.js.map
sourcemapper -url https://app.example.com/static/js/main.3f2a1c.js.map -output ./src-recovered
grep -rn -iE "admin|impersonat|role|permission" ./src-recovered | head -50
```

3. **API documentation.** Request the common OpenAPI locations on each API host and list operations tagged or named as administrative:

```bash
for p in /openapi.json /swagger.json /v3/api-docs /v2/api-docs /api-docs /swagger-ui/ /docs; do
  printf '%s %s\n' "$(curl -s -o /dev/null -w '%{http_code}' "https://api.example.com$p")" "$p"; sleep 1
done
curl -s https://api.example.com/v3/api-docs \
  | jq -r '.paths | to_entries[] | .key as $p | .value | to_entries[]
           | select(.key | test("get|post|put|patch|delete"))
           | "\(.key | ascii_upcase) \($p)  tags=\(.value.tags // [] | join(","))"' \
  | grep -iE 'admin|internal|role|permission|impersonat|bulk|import|flag' 
```

4. **GraphQL schema.** Try introspection with a member token. If it is disabled, look for field suggestions in error messages ("Did you mean ...?") and use [clairvoyance](https://github.com/nikitastupin/clairvoyance) or InQL's schema brute-forcer, seeded with names from the bundles. Extract all mutations:

```bash
curl -s https://api.example.com/graphql \
  -H 'Authorization: Bearer <TOKEN_MEMBER_A>' -H 'Content-Type: application/json' \
  -d '{"query":"query { __schema { mutationType { fields { name args { name } } } } }"}' \
  | jq -r '.data.__schema.mutationType.fields[].name' | sort
```

Also grep the bundles for GraphQL documents (`mutation `, `gql\``) to find operations the member UI never sends.

5. **Mobile apps.** If the product has a mobile app in scope, extract endpoint strings from it (the method is in our mobile series) and add any API versions or operations the web client does not use.

6. **Conventions and naming.** For every resource the member can read, add the sibling verbs and sub-resources (`PUT`, `PATCH`, `DELETE`, `/role`, `/disable`, `/impersonate`, `/export`). For every user-level path, try the admin twin (`/api/users` and `/api/admin/users`, `/api/v2/...` and `/api/v1/...`). A small, hand-built wordlist from the app's own vocabulary beats a generic one. If you fuzz, do it slowly and with the member's session:

```bash
ffuf -u https://api.example.com/api/FUZZ -w admin-words.txt \
     -H 'Authorization: Bearer <TOKEN_MEMBER_A>' -mc all -fc 404 -rate 5
```

7. **Other leaks.** `robots.txt`, error pages that list routes (framework debug pages), `OPTIONS` responses with an `Allow` header, admin subdomains (`admin.example.com`), and older documentation versions. [Arjun](https://github.com/s0md3v/Arjun) and Param Miner find hidden parameters on endpoints you already know.

#### Observation

Illustrative output from step 1:

```text
"/api/admin/users"
"/api/admin/users/{id}/role"
"/api/internal/reindex"
"/api/support/impersonate"
"/api/users/bulk"
```

#### Evaluation

- **Record, not rate:** each discovered privileged function goes into the matrix with its expected roles.
- **Separate findings, usually Low or Info:** production source maps (exposure of source, CWE-540) where they reveal sensitive logic; internal API documentation served to anyone (ASVS `v5.0.0-13.4.5`, L2); introspection enabled on an API not meant for third parties (ASVS `v5.0.0-4.3.2`, L2). Rate them higher only when they expose secrets or directly enable a vertical finding, and then rate the vertical finding.

#### False positives

Strings in bundles are not proof that an endpoint exists or is reachable: dead code, other environments' URLs and third-party libraries all leave paths behind. A documented `admin` operation that returns 403 to members is a well-behaved application.

#### Automation

Run the bundle and OpenAPI extraction on each deployment and diff it. A new privileged path that does not appear in the role matrix is a test gap, whatever the server does with it.

### GT-WEB-PRIV-3: Call privileged functions with a lower-privilege session

*Guler Tech methodology.* Implements the "Vertical Bypass" and "Administrator Page Access" procedures of WSTG-ATHZ-03, "Access to Administrative Functions" in WSTG-ATHZ-02, and "Manipulate Role-Based Access Controls" in WSTG-APIT-04.

#### What it checks

Whether the server enforces the role matrix: each privileged function, called directly with a lower role's credentials (and with none), is refused, and nothing happens.

#### Prerequisites

The matrix from test 1; sessions for every role; an admin test account to confirm state afterwards.

#### Steps

1. Take each privileged function from the matrix and capture a working request from the admin session.
2. Replay it with each lower role, starting with the lowest, and with no credentials. Change only the credentials. For CSRF-protected forms, use the lower role's own CSRF token.
3. Read-only functions first. For state-changing functions, point the request at **own test objects only** (for example `member_b`) and choose the mildest effect.
4. After any 2xx response to a state-changing request, confirm the effect from the admin session (did `member_b` really become disabled?), then revert it.
5. Note functions where the response *differs* between "denied" and "not found" and between roles; inconsistent enforcement across a family of endpoints (APIT-04's third indicator) is a lead for the rest of that family.

The admin's request, captured in step 1:

```http
GET /api/admin/users?limit=5 HTTP/2
Host: api.example.com
Authorization: Bearer <TOKEN_ADMIN_TEST>
Accept: application/json
```

The same request as `member_a`:

```http
GET /api/admin/users?limit=5 HTTP/2
Host: api.example.com
Authorization: Bearer <TOKEN_MEMBER_A>
Accept: application/json
```

```bash
curl -s -i 'https://api.example.com/api/admin/users?limit=5' \
  -H 'Authorization: Bearer <TOKEN_MEMBER_A>' -H 'Accept: application/json'
```

A state-changing function against your own second account:

```http
POST /api/admin/users/usr_b_7f3c/disable HTTP/2
Host: api.example.com
Authorization: Bearer <TOKEN_MEMBER_A>
Content-Type: application/json

{"reason": "gt-test"}
```

#### Observation

Vulnerable (the member gets the admin listing; redact it in evidence):

```http
HTTP/2 200 OK
Content-Type: application/json

{"total": 1873, "users": [{"id": "usr_9a1e", "email": "r***@example.org", "role": "admin"}, "..."]}
```

Correct:

```http
HTTP/2 403 Forbidden
Content-Type: application/json

{"error": "forbidden", "message": "admin role required"}
```

A `404 Not Found` for members is also acceptable if the application deliberately hides admin routes; what matters is that it is consistent and that nothing executes.

#### Evaluation

- **Fail:** a lower role (or anonymous) receives data that only a higher role should see, or a state change happens (confirmed from the admin session) for a function the matrix reserves for a higher role. Unauthenticated success is a separate, more severe finding (CWE-306 alongside CWE-862).
- **Fail (partial):** the function is refused but leaks something on the way (the count of users in an error, the admin's validation messages that reveal internal fields).
- **Pass:** every lower role and the anonymous session receive 401, 403 or a consistent 404 for every privileged function, and no state changes.

#### False positives

- **200 OK with an error body.** Many APIs answer `200` with `{"success": false, "error": "not allowed"}`. Read the body.
- **The SPA shell.** `GET /admin/users` returning `200` and `index.html` is the front end's catch-all route. The question is what the *API* behind it returns.
- **Cached responses.** A CDN or reverse proxy may serve the admin's cached response to anyone. Look at `Age`, `X-Cache`, `CF-Cache-Status` or `Via`, and repeat with a cache-busting query parameter. If it really is a cache leak, it is still a finding, but a different one (cache configuration rather than function-level authorisation).
- **Same data by design.** Both roles may legitimately see the same list (an org directory visible to all members). Check the matrix, and compare fields: admins often get extra properties, which is a [BOPLA](/web/web-mass-assignment-bopla/) question, not a vertical one.
- **Same organisation.** If `member_a` and `admin_test` are in the same organisation and the function is "list my organisation's users", the member may be entitled to a reduced version of it.

#### Automation

Autorize, Auth Analyzer or AuthMatrix over the full admin traffic, with state-changing requests excluded or pointed at test objects. In CI, the role-matrix test in [Authorisation regression tests](#authorisation-regression-tests) calls every privileged route as every role and fails on any unexpected allow.

### GT-WEB-PRIV-4: Sibling operations and verbs on the same resource

*Guler Tech methodology.* Implements "Test Function-Level Access with Different HTTP Methods" in WSTG-APIT-04 and the role/privilege manipulation step of WSTG-ATHZ-03.

#### What it checks

Whether operations that a lower role is *not* meant to perform on a resource it *can* read are refused: write and delete verbs, sub-resource actions, older API versions and alternative clients' endpoints.

#### Prerequisites

Resources the member can read (its own profile, a team, a project); `member_b` and objects you created as targets.

#### Steps

1. For each readable resource, send `OPTIONS` and note the `Allow` header, if any. It is a hint, not a statement of what is authorised.
2. Try each verb the matrix reserves for higher roles, against **own test objects only**:

```http
PATCH /api/users/usr_b_7f3c HTTP/2
Host: api.example.com
Authorization: Bearer <TOKEN_MEMBER_A>
Content-Type: application/json

{"status": "suspended"}
```

```bash
curl -s -i -X DELETE https://api.example.com/api/projects/prj_gt_test_01 \
  -H 'Authorization: Bearer <TOKEN_MEMBER_A>'
```

3. Try the action sub-resources you discovered in test 2 (`/role`, `/disable`, `/restore`, `/transfer-ownership`, `:suspend`) and RPC-style variants (`POST /api/users/usr_b_7f3c?action=delete`).
4. Repeat the most sensitive calls against older or parallel API surfaces: `/api/v1/` if the app uses `/api/v2/`, the mobile prefix (`/m/api/`, `/mobile/v3/`), and a legacy server-rendered form post if one exists.
5. Do **not** use method override headers or path tricks here. If a verb is refused directly, record it and test the override variants in [Authorisation bypass techniques](/web/web-authorization-bypass-techniques/).

#### Observation

Vulnerable: `GET /api/users/usr_b_7f3c` is correctly scoped to members of the same team, but `DELETE` on the same path returns `204 No Content` and `member_b` is gone when the admin looks. Correct: `403` for `PATCH status` and `DELETE`, with `member_b` unchanged.

#### Evaluation

- **Fail:** a verb or action reserved for a higher role succeeds for a lower role on any API surface, confirmed by reading the object afterwards.
- **Pass:** each reserved operation is refused on every surface (current version, older versions, mobile prefix), and the object is unchanged.
- **Note separately:** an old API version that is still routed but unused (ASVS `v5.0.0-13.4.5` territory if it is undocumented) even when it enforces correctly.

#### False positives

`405 Method Not Allowed` means the route does not support the verb, not that authorisation worked; that is fine. A `204` for a `DELETE` that the application implements as idempotent "already deleted" needs the follow-up read to tell you whether anything happened. A member may legitimately delete *their own* objects; target `member_b`'s or the admin's test objects instead.

#### Automation

Generate the verb variants for every path in the OpenAPI document and add them to the role matrix as expected denies. In CI, test at least one write verb per resource as the lowest role.

### GT-WEB-PRIV-5: Role and permission values in client requests

*Guler Tech methodology.* Implements "Manipulation of User Group" and "Manipulation of User Profile" in WSTG-ATHZ-03, and the hidden-field part of WSTG-BUSL-02. The general mass-assignment technique is in [Mass assignment and BOPLA](/web/web-mass-assignment-bopla/); this test focuses on properties that grant a role.

#### What it checks

Whether any request that creates or updates a user, membership or session lets the client choose its own role, group, permission set or administrative flag, and whether the server ever reads the caller's role from something the caller sends.

#### Prerequisites

Fresh test accounts (registration is the most common place for this flaw); an invitation you sent from `manager_a` to an address you control.

#### Steps

1. **Read before write.** Note every property in `GET /api/me`, the registration response and the user objects you can see: `role`, `roles`, `isAdmin`, `is_staff`, `groups`, `permissions`, `scopes`, `accountType`, `tier`, `plan`, `level`, `access_level`. A property the server returns is a property the model has.
2. **Registration.** Register a new account and add the role properties to the body:

```http
POST /api/auth/register HTTP/2
Host: api.example.com
Content-Type: application/json

{
  "email": "gt-test+priv5@example.org",
  "password": "<TEST_PASSWORD>",
  "displayName": "GT priv5",
  "role": "admin",
  "isAdmin": true,
  "groups": ["administrators"]
}
```

3. **Invitation acceptance.** Accept the invitation from `manager_a` and add `"role": "admin"` (or change the existing role value) in the acceptance request. Also check whether the invitation token itself carries the role (a signed token is fine; a readable, unsigned role parameter in the link is not).
4. **Profile update.** Send `PATCH /api/me` (or `PUT /api/users/{own-id}`) with the role properties, then with variants: nested (`"user": {"role": "admin"}`), array (`"roles": ["admin"]`), different case (`"Role"`), framework-specific keys (`"is_superuser"`, `"wp_capabilities"`-style meta keys for CMS plugins).
5. **Cookies, hidden fields and headers.** Look for role values in cookies (`role=user`, `admin=false`), hidden inputs and custom headers set by the front end (`X-User-Role`). Change them on a request to a privileged function.
6. **Token claims.** Decode the session token if it is self-contained. If it carries a role claim, note it and move the forgery question to the authentication and session tests; here, change the role *server-side* (with the client's help) and check whether the old token keeps its old role, which is a revocation issue covered in [Revocation, sharing and async access](/web/web-access-control-revocation-sharing-async/).
7. For each attempt, verify the result **twice**: re-read `GET /api/me`, and call one admin function from [GT-WEB-PRIV-3](#gt-web-priv-3-call-privileged-functions-with-a-lower-privilege-session). An echoed `"role": "admin"` in the response is not proof.

```bash
curl -s https://api.example.com/api/me -H 'Authorization: Bearer <TOKEN_GT_PRIV5>' | jq '{role, isAdmin, groups}'
curl -s -o /dev/null -w '%{http_code}\n' 'https://api.example.com/api/admin/users?limit=1' \
  -H 'Authorization: Bearer <TOKEN_GT_PRIV5>'
```

#### Observation

Vulnerable: registration returns `201` with `"role": "admin"`, `/api/me` agrees, and `/api/admin/users` returns `200`. Correct: the server ignores or rejects the extra properties (`400` with "unknown field" is the best behaviour; silent ignore is acceptable), `/api/me` shows the default role, and the admin function returns `403`.

#### Evaluation

- **Fail:** the new or updated account holds a higher role, group or permission than the flow is meant to grant, confirmed by a privileged function succeeding. Any visitor who can self-register and then do this is the worst case.
- **Fail:** the server decides the caller's role from a cookie, hidden field or header value the caller can change.
- **Pass:** role-granting properties are not accepted from the client in any of these flows, and the role is always loaded server-side from the session's user record.

#### False positives

- The response echoes your input but the stored record is unchanged (check `/api/me` from a fresh session).
- The application legitimately lets the first user of a new organisation become its owner. That is by design; the test is whether you can become owner or admin of an *existing* organisation or of the platform.
- A `role` value that only changes display (a job title field called `role`). Read the matrix.

#### Automation

Param Miner and Arjun can guess hidden body properties. In CI, add a test per user-creating endpoint that posts `role`/`isAdmin` and asserts the stored role is the default; frameworks with allowlisted serializers make this a one-line assertion.

### GT-WEB-PRIV-6: Role ceilings and self-assignment of roles and groups

*Guler Tech methodology.* Implements the role manipulation part of WSTG-ATHZ-03 and the role-based operations in WSTG-APIT-04, for functions that grant privileges. It checks ASVS `v5.0.0-8.2.1` for privilege-granting functions (CWE-269, CWE-266).

#### What it checks

Whether a role that is allowed to grant roles (invite, add to group, edit members, create custom roles, issue API keys) can grant only what it holds itself, and whether any user can modify their own role or membership.

#### Prerequisites

`manager_a` (or any delegated administrator role); `member_a`; an e-mail address you control for invitations; `member_b` as a target.

#### Steps

1. **Invite above your own role.** As `manager_a`, send an invitation to your own address with the highest role:

```http
POST /api/orgs/org_gt_a/invitations HTTP/2
Host: api.example.com
Authorization: Bearer <TOKEN_MANAGER_A>
Content-Type: application/json

{"email": "gt-test+invite-admin@example.org", "role": "admin"}
```

2. **Change a member's role above your own.** As `manager_a`, set `member_b` to `admin` or `owner` through the member-management endpoint. As `member_a`, try the same on `member_b` (that is a plain BFLA if it works).
3. **Self-assignment.** As `member_a`, modify your *own* membership or group record:

```http
PUT /api/orgs/org_gt_a/members/usr_a_31d0 HTTP/2
Host: api.example.com
Authorization: Bearer <TOKEN_MEMBER_A>
Content-Type: application/json

{"role": "owner"}
```

```bash
curl -s -i -X POST https://api.example.com/api/groups/grp_admins/members \
  -H 'Authorization: Bearer <TOKEN_MEMBER_A>' -H 'Content-Type: application/json' \
  -d '{"userId": "usr_a_31d0"}'
```

4. **Custom roles.** If the product has a role editor, as a delegated admin create a role that includes a permission you do not hold (for example `billing:manage` or `users:delete`), then assign it to `member_b`.
5. **Tokens and keys.** Create an API key or personal access token as `member_a` and request scopes beyond the member role (`admin`, `users:write`). Then use the key against an admin function.
6. **Ownership transfer and last-owner rules.** Transfer ownership to yourself from a non-owner role; demote the last owner.
7. Revert every change from `admin_test` when you are done.

#### Observation

Vulnerable: the manager's invitation for `admin` is created, and the account that accepts it can call admin functions. Correct: `403` with a message such as "cannot grant a role higher than your own", or the role list offered to managers simply does not include `admin` *and* the server enforces the same rule.

#### Evaluation

- **Fail:** any grantor can grant a role or permission it does not hold; any user can change their own role or add themselves to a group they were not given; a token can carry scopes beyond its owner's role.
- **Pass:** the server compares the requested grant with the grantor's own permissions on every granting path (invite, edit, bulk, import, role editor, token creation), and self-modification of role is refused.

#### False positives

Some products deliberately let managers invite admins with a second approval step. If the invite is created as "pending approval" and the account gets the admin role only after an admin approves, the ceiling is enforced by the workflow. Check that the pending state really cannot be used.

#### Automation

Encode ceilings as test data: for every granting endpoint, every grantor role and every target role above it, expect a deny. This is a short loop and catches regressions when someone adds a role.

### GT-WEB-PRIV-7: Privileged actions inside bulk, import and multi-step features

*Guler Tech methodology.* Implements the role/privilege manipulation step of WSTG-ATHZ-03 for indirect entry points, and the workflow part of WSTG-BUSL-06 (Circumvention of Work Flows) where an admin flow has several steps.

#### What it checks

Whether functions reserved for higher roles can be reached through a feature the lower role may use: a bulk endpoint with a selectable action, an import that creates or updates users, or a later step of a multi-step admin flow.

#### Prerequisites

The member or manager role that has access to the bulk or import feature; test objects only (a CSV that names only your test accounts).

#### Steps

1. **Bulk actions.** Capture an allowed bulk request (for example a manager deactivating two of their own test members) and change the action to one reserved for admins:

```http
POST /api/users/bulk HTTP/2
Host: api.example.com
Authorization: Bearer <TOKEN_MANAGER_A>
Content-Type: application/json

{"ids": ["usr_b_7f3c"], "action": "set_role", "value": "admin"}
```

Try the action names you found in the bundle (`delete`, `set_role`, `impersonate`, `export`, `reset_mfa`) and include an ID outside the manager's scope that you control (`admin_test` is a good target for a harmless action such as "add label").

2. **Import.** Export the import template, add columns the UI does not offer (`role`, `is_admin`, `group`) and import a file containing only your own test addresses:

```text
email,display_name,role
gt-test+import1@example.org,GT import 1,admin
```

Check the created accounts' roles from `admin_test`.

3. **Multi-step flows.** Walk an admin flow as `admin_test` (for example "change user role": select user, choose role, confirm) and record each request. Replay the *last* step with the member's session, then the middle steps. The PortSwigger lab "Multi-step process with no access control on one step" is the reference case.
4. **Asynchronous variants.** If the bulk or import feature queues a job, check the result of the job, not just the `202 Accepted`. Whether the job runs with the caller's permissions or a service identity's is a [confused-deputy question](/web/web-access-control-revocation-sharing-async/).

#### Observation

Vulnerable: the manager's bulk request with `"action": "set_role"` returns `200 {"updated": 1}` and `member_b` is an admin. Correct: `403` for the action, or a per-item result that marks the item as denied.

#### Evaluation

- **Fail:** a bulk, import or later-step request performs an operation, or reaches an object, that the caller's role could not reach through the direct function.
- **Pass:** each item and each step is authorised as if it were a single direct call by the same user.

#### False positives

A bulk endpoint that silently skips forbidden items and reports `200` may look vulnerable; check the objects. A `202` for a queued job is not success until the job's effect is visible.

#### Automation

In CI, test bulk endpoints with each action name and the lowest role that can reach the endpoint, and test the import with a role column. In code review, look for loops that call repository methods directly instead of the same service method the single-item endpoint uses.

### GT-WEB-PRIV-8: Impersonation, support tooling and feature flags

*Guler Tech methodology.* Implements the vertical bypass procedure of WSTG-ATHZ-03 for support functions and the "hidden options" part of WSTG-BUSL-02.

#### What it checks

Who can use "act as" or impersonation functions and on whom; whether support tooling exposes admin functions to support roles or to everyone; and whether feature flags or hidden options enable privileged functions without a server-side check.

#### Prerequisites

A support-role account if the product has one; the flag keys and impersonation endpoints found in [GT-WEB-PRIV-2](#gt-web-priv-2-discover-privileged-functions-the-ui-hides).

#### Steps

1. **Impersonation entry points.** Look for endpoints and parameters such as `/api/support/impersonate`, `/admin/login-as/{id}`, `?act_as=`, `?switch_user=` and application-specific headers that select a target user. Call them as `member_a` targeting `member_b`:

```http
POST /api/support/impersonate HTTP/2
Host: api.example.com
Authorization: Bearer <TOKEN_MEMBER_A>
Content-Type: application/json

{"targetUserId": "usr_b_7f3c", "reason": "gt-test"}
```

2. **Impersonation ceilings.** As the support role (or `admin_test` if impersonation is admin-only), try to impersonate an account with a *higher* role than the impersonator (`admin_test` impersonating another admin you control, support impersonating an admin). Impersonating up is an escalation.
3. **Impersonated session limits.** In an impersonated session, try the most sensitive actions (change e-mail, change password, create API key, change roles, view secrets). Many products block these during impersonation; if they are allowed, record it.
4. **Audit.** Ask the client to confirm that each impersonation you performed is in the audit log with the real actor's identity.
5. **Feature flags.** Find the flag source (a `/api/flags` or `/api/me/features` response, a third-party flag SDK in the bundle, a cookie or local storage key). Turn on a flag that unlocks an admin feature, in the client (local override) and, if the API allows it, through a preference update:

```http
PATCH /api/me/preferences HTTP/2
Host: api.example.com
Authorization: Bearer <TOKEN_MEMBER_A>
Content-Type: application/json

{
  "features": {
    "adminConsoleBeta": true
  }
}
```

Then call the functions the flag reveals with the member's session.
6. **Debug and hidden options.** Try the debug parameters and hidden fields you found (`debug=true`, `internal=1`, `?preview=admin`). WSTG-BUSL-02 describes these as hidden features left in from development.

#### Observation

Vulnerable: `member_a` receives a session for `member_b`; or a support agent can impersonate an admin and change roles in that session; or the beta admin console's API calls work for any member once the client-side flag is set. Correct: impersonation is refused to roles without the support permission, refused for targets above the impersonator's role, logged, and sensitive actions are blocked in impersonated sessions; flagged features are checked server-side against the caller's role.

#### Evaluation

- **Fail:** any role can impersonate a user it should not, including any user above its own role; or a privileged function becomes usable because a flag or hidden option was set by the client.
- **Pass:** impersonation and flag-gated functions are authorised on the server against the real actor's role, with a ceiling and an audit trail.
- **Info:** a flag that changes only the UI (the admin menu appears, every API call behind it returns `403`) is a hidden-UI-only defect, not a vertical finding.

#### False positives

Some products let any user "view as" a lower-privilege preview of their own account (a "see what members see" mode). That is a de-escalation and not a finding, provided it cannot target another user.

#### Automation

Add impersonation endpoints to the role matrix with explicit target rules (`support → member: allow`, `support → admin: deny`). For flags, keep a list of flag-gated routes and test them in CI with the flag on and the lowest role.

### GT-WEB-PRIV-9: GraphQL mutations and privileged queries

*Guler Tech methodology.* Implements "Test for BFLA in GraphQL APIs" in WSTG-APIT-04 and the authorisation section of WSTG-APIT-99.

#### What it checks

Whether each GraphQL mutation and each privileged query field enforces the caller's role in its resolver (or in the business layer it calls), independently of the other operations in the same request.

#### Prerequisites

The schema (from introspection, clairvoyance or InQL); member and admin tokens; [InQL](https://github.com/doyensec/inql) in Burp to generate operations.

#### Steps

1. From the schema, list all mutations and the query fields that return admin-level data. Mark those the member UI never sends (compare with the member's Proxy history).
2. Generate each operation with InQL's Scanner and send it with the member token. Start with read-only queries, then mutations against **own test objects only**:

```http
POST /graphql HTTP/2
Host: api.example.com
Authorization: Bearer <TOKEN_MEMBER_A>
Content-Type: application/json

{
  "query": "mutation SetRole($id: ID!, $role: Role!) { setUserRole(userId: $id, role: $role) { id role } }",
  "variables": { "id": "usr_b_7f3c", "role": "MANAGER" }
}
```

3. **One request, several operations.** Send an allowed query and a privileged mutation in the same document using aliases, and as a batched array if the server accepts arrays. A check performed once per HTTP request (for the first operation) instead of per field shows up here:

```json
{
  "query": "mutation { a: updateMyProfile(displayName: \"gt\") { id } b: deleteUser(id: \"usr_b_7f3c\") { success } }"
}
```

4. **Nested paths.** Check whether a privileged object is reachable through a nested field a member can query (`me { organization { auditLog { ... } } }`, `project(id) { owner { apiKeys } }`). Field-level exposure is the [BOPLA](/web/web-mass-assignment-bopla/) note's subject; here you note when the nested field is effectively an admin function.
5. **Persisted queries.** If the client sends only persisted query hashes, check whether the server also accepts an arbitrary `query` string. If it does, every operation in the schema is callable, not just the ones the client ships.
6. Run [graphql-cop](https://github.com/dolevf/graphql-cop) once for configuration issues (introspection, field suggestions, GET-based mutations), and record them separately.

#### Observation

Vulnerable:

```json
{
  "data": {
    "setUserRole": { "id": "usr_b_7f3c", "role": "MANAGER" }
  }
}
```

Correct (the error is per field, and `data` for that field is `null`):

```json
{
  "errors": [
    { "message": "Forbidden", "path": ["setUserRole"], "extensions": { "code": "FORBIDDEN" } }
  ],
  "data": { "setUserRole": null }
}
```

#### Evaluation

- **Fail:** any mutation or privileged query field succeeds for a role the matrix does not allow, alone or alongside an allowed operation.
- **Pass:** each field returns a per-field authorisation error for unauthorised roles, and the effect does not happen (check from the admin session).

#### False positives

GraphQL servers return HTTP `200` for most errors; read `errors` and `data`. A `null` field with no error may be a resolver that found no object, not a denial. Introspection that *shows* an admin mutation is not a finding by itself.

#### Automation

A schema-driven CI test (see [GraphQL resolvers](#graphql-resolvers)) fails the build when a mutation has no policy entry. InQL's generated operations can be loaded into AuthMatrix for the manual retest.

### GT-WEB-PRIV-10: Horizontal-to-vertical chains against higher-role accounts

*Guler Tech methodology.* Combines the horizontal bypass procedure of WSTG-ATHZ-02 with the vertical objective of WSTG-ATHZ-03. Object-level techniques are in [IDOR and BOLA](/web/web-idor-bola/).

#### What it checks

Whether an object-level weakness that a lower role can use on peers also works on **higher-role accounts' own objects** (their user record, credentials, MFA, sessions, group memberships), which turns it into control of the higher role.

#### Prerequisites

The object-level findings (or candidates) from the IDOR tests; `admin_test` as the **only** higher-role target. Never target a real administrator.

#### Steps

1. List object types where control equals the owner's privilege: user profile (e-mail, phone, password), MFA devices, recovery codes, API keys and tokens, sessions, OAuth grants, group and membership records, notification or webhook settings that receive password-reset links.
2. For each, take the request a member uses on their own object and point it at `admin_test`'s object, starting with the least harmful property. A display name change proves write access without locking anyone out:

```http
PATCH /api/users/usr_admin_test_02/profile HTTP/2
Host: api.example.com
Authorization: Bearer <TOKEN_MEMBER_A>
Content-Type: application/json

{"displayName": "GT test - changed by member_a"}
```

3. Only if the client agrees in writing, demonstrate the full chain on `admin_test` (for example change its e-mail to an address you control and complete a password reset), then hand the account back. Otherwise, stop at the harmless write and describe the chain.
4. Membership objects: try adding your own user to the admin group by ID (`POST /api/groups/grp_admins/members`) when the endpoint authorises only "can see the group".
5. Credential reads: request `admin_test`'s API keys or session list. If anything secret comes back, note its presence, redact it, and ask the client to rotate it.

#### Observation

Vulnerable: `member_a` changes `admin_test`'s display name, and the same endpoint accepts `email`. Correct: `403` or `404`, and `admin_test`'s record is unchanged.

#### Evaluation

- **Fail:** a lower role can modify or read an object whose control gives a higher role's privileges. Rate it as the privilege it yields (usually admin account takeover), not as the underlying IDOR.
- **Pass:** object-level checks hold for higher-role targets; a peer-only IDOR stays a peer-only finding.

#### False positives

An endpoint that lets members see a *public* profile of admins (name, avatar) is not a chain. A "request access" or "suggest change" function that creates a pending request for the admin to approve is not a write.

#### Automation

In regression tests, include a higher-role account as the target in every object-level test for user, credential and membership objects, not only a peer.

### GT-WEB-PRIV-11: Administrative interface separation and layered controls

*Guler Tech methodology.* Covers the "Administrator Page Access" part of WSTG-ATHZ-03 and checks ASVS `v5.0.0-8.4.2` (L3), `v5.0.0-8.3.1` (L1) and `v5.0.0-16.3.2` (L2).

#### What it checks

How the administrative interface is separated from the user application and what protects it beyond the role check: separate origin or application, separate session or token audience, step-up authentication for sensitive actions, and logging of denied attempts. ASVS `v5.0.0-8.4.2` asks for multiple layers (continuous identity verification, device posture, contextual risk) and says network location must not be the only factor.

#### Prerequisites

`admin_test`; a member session; information from the client about how admin access is meant to be protected.

#### Steps

1. Map where the admin interface lives: a path on the main app (`app.example.com/admin`), a separate host (`admin.example.com`), a separate API (`api.example.com/admin/*` versus `admin-api.example.com`).
2. **Session reuse.** Send a member's cookie or token to the admin host and admin API. A user session that is accepted by the admin application (even if role-checked afterwards) means the admin interface relies on a single check; a separate audience or session that the user app cannot mint is a stronger design.
3. **Network-only protection.** If the admin host is "internal only", confirm from an external address that it is unreachable, and record that the only factor is network location. Bypassing the allowlist is a test in [Authorisation bypass techniques](/web/web-authorization-bypass-techniques/).
4. **Step-up.** As `admin_test`, perform a sensitive admin action (role change, impersonation, export of all users) with an old session. Is re-authentication or MFA required at that point?
5. **Logging.** Ask the client to show the log entries for the denied attempts you made in tests 3 to 9. ASVS `v5.0.0-16.3.2` (L2) requires failed authorisation attempts to be logged.

#### Observation

Illustrative weak setup: the admin SPA is served at `app.example.com/admin`, uses the same session cookie as the user app, has no MFA requirement beyond login, and denied admin calls do not appear in the logs. Stronger setup: `admin.example.com` with its own SSO application and MFA policy, tokens with an admin audience that the user API does not accept, step-up for role changes, and alerts on denied admin calls.

#### Evaluation

- **Fail (L3 hardening):** network location is the only extra control for the admin interface, or there is no step-up for the most sensitive admin actions, against an L3 target. Usually Low or Medium; it raises the impact of any vertical or session finding.
- **Fail (L2):** denied authorisation attempts are not logged.
- **Pass:** the admin interface has at least one control beyond the role check that does not depend on network location, and denied attempts are logged.

#### False positives

A small internal tool with an L1 or L2 target is not expected to meet `v5.0.0-8.4.2`; state the level you assessed against.

#### Automation

Infrastructure tests can assert that the admin host is not resolvable or reachable from the internet and that its identity-provider application requires MFA. Log-based tests can assert that a denied call produces an event.

## Secure implementation

### Design rules

- **Deny by default.** A route, controller method, resolver or job with no declared rule is refused. The OWASP Authorization Cheat Sheet, API5:2023 and Spring Security's own documentation all say this; in practice it means the framework configuration has a final "deny everything else" rule, and adding an endpoint without a policy breaks a test.
- **One policy module.** Express the matrix once (a CASL ability, a Django permission class, a Spring bean, a Laravel policy) and call it from every entry point. API5:2023 suggests administrative controllers inherit from a base controller that enforces the admin check.
- **Check permissions, not role names.** `can('users:delete')` survives new roles; `role === 'admin'` does not.
- **Load the subject server-side.** The caller's role comes from the session's user record (or a verified token whose role is re-checked for sensitive functions), never from the request body, a cookie value or a front-end header.
- **Role ceilings everywhere roles are granted.** A grantor may grant only permissions it holds. Users never edit their own role or memberships.
- **Put the decision in the service layer** for anything reachable from more than one interface (REST, GraphQL, jobs, CLI), and keep route-level checks as a coarse first layer.
- **Separate the admin surface** (see [Separating administrative interfaces](#separating-administrative-interfaces)).
- **Log denials** (`v5.0.0-16.3.2`) and alert on repeated denied admin calls from one account.
- **Treat the matrix as code** and test it (see [Authorisation regression tests](#authorisation-regression-tests)).

### Node.js and Express

Express has no built-in authorisation, so the risk is the default: a route without middleware is open. Make the safe path the only path. The pattern below uses [CASL](https://casl.js.org/v6/en/guide/intro/) for the policy and a small registration helper that refuses to register a route without a guard.

The vulnerable pattern, for comparison:

```javascript
// Admin router mounted without any role check: the SPA hides it, nothing else does
app.use('/api/admin', adminRouter);
adminRouter.delete('/users/:id', async (req, res) => {
  await users.delete(req.params.id);
  res.sendStatus(204);
});
```

The policy (one place, permission-based, with a role ceiling for invitations):

```javascript
// policy.js
const { AbilityBuilder, createMongoAbility } = require('@casl/ability');

const GRANTABLE = { member: ['member'], manager: ['member', 'manager'], admin: ['member', 'manager', 'admin'] };

function defineAbilityFor(user) {
  const { can, build } = new AbilityBuilder(createMongoAbility);
  if (!user) return build();                       // anonymous: no rules, every check fails

  can('read', 'Profile', { userId: user.id });
  can('update', 'Profile', { userId: user.id });

  if (user.role === 'manager' || user.role === 'admin') {
    // may invite or set roles only up to their own level, only in their own org
    can('assignRole', 'Membership', { orgId: user.orgId, role: { $in: GRANTABLE[user.role] } });
  }
  if (user.role === 'admin') {
    can('access', 'AdminConsole');
    can(['read', 'disable', 'delete'], 'User', { orgId: user.orgId });
  }
  return build();
}

module.exports = { defineAbilityFor };
```

The middleware and a registration helper that makes "forgot the check" impossible:

```javascript
// authz.js
const { subject } = require('@casl/ability');
const { defineAbilityFor } = require('./policy');

// type-level check (no object) or object-level check with attributes loaded server-side
function authorize(action, type, loadAttrs) {
  return async (req, res, next) => {
    try {
      const ability = defineAbilityFor(req.user);        // req.user set by authentication middleware
      const target = loadAttrs ? subject(type, await loadAttrs(req)) : type;
      if (ability.can(action, target)) return next();
      req.log?.warn({ action, type, user: req.user?.id }, 'authorization denied');
      return res.status(403).json({ error: 'forbidden' });
    } catch (err) {
      return next(err);
    }
  };
}

const PUBLIC = (req, res, next) => next();               // explicit, greppable opt-out

function secured(router, method, path, guard, ...handlers) {
  if (typeof guard !== 'function') {
    throw new Error(`No authorisation guard declared for ${method.toUpperCase()} ${path}`);
  }
  router[method](path, guard, ...handlers);
}

module.exports = { authorize, secured, PUBLIC };
```

Routes, with a coarse guard on the whole admin router and a specific guard per operation:

```javascript
// routes.js
const express = require('express');
const { authorize, secured } = require('./authz');

const admin = express.Router();
admin.use(authorize('access', 'AdminConsole'));           // first layer for everything mounted here

secured(admin, 'delete', '/users/:id',
  authorize('delete', 'User', async (req) => {
    const u = await users.get(req.params.id);             // attributes from the database, not the request
    return { orgId: u.orgId };
  }),
  async (req, res) => { await users.delete(req.params.id); res.sendStatus(204); });

const api = express.Router();
secured(api, 'post', '/orgs/:orgId/invitations',
  authorize('assignRole', 'Membership', (req) => ({ orgId: req.params.orgId, role: req.body.role })),
  createInvitation);

app.use('/api', requireAuthentication);                   // every /api route needs a session
app.use('/api/admin', admin);
app.use('/api', api);
```

Notes:

- `req.params.orgId` is safe as an attribute here only because the CASL rule compares it with `user.orgId` from the server-side user record; never take the *caller's* attributes from the request.
- `role: req.body.role` is the role being *granted*, which is exactly what the ceiling rule must see.
- Attach the guard to the same router that holds the handlers, so path matching for the guard and the handler is the same; guards in a reverse proxy or a separate prefix match can disagree with Express's routing (see [Authorisation bypass techniques](/web/web-authorization-bypass-techniques/)).
- Express 5 forwards rejected promises from async middleware to the error handler; the `try/catch` keeps the example correct on Express 4 as well.

### Django and Django REST framework

**Django views.** Since Django 5.1, `django.contrib.auth.middleware.LoginRequiredMiddleware` makes authentication the default for every view, with `@login_not_required` as the explicit opt-out. That covers *authentication*; function-level *authorisation* still needs a permission check per view. Use `permission_required` with `raise_exception=True` so a logged-in user without the permission gets a 403 rather than a redirect:

```python
# settings.py
MIDDLEWARE = [
    # ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.auth.middleware.LoginRequiredMiddleware",   # Django 5.1+
    # ...
]
```

```python
# billing/views.py
from django.contrib.auth.decorators import permission_required
from django.views.decorators.http import require_POST

@require_POST
@permission_required("billing.issue_refund", raise_exception=True)
def issue_refund(request, invoice_id):
    ...
```

`PermissionRequiredMixin` does the same for class-based views (`permission_required = "accounts.change_user"`). Note that these check model-level permission names (`"app_label.codename"`); the object-level part ("this refund, in this organisation") still belongs in the view or in a scoped queryset.

**DRF.** If `DEFAULT_PERMISSION_CLASSES` is not set, DRF allows everything (`AllowAny`). Set a default that denies unless the view declares what it needs, so a new view or a new `@action` is closed until someone adds a rule:

```python
# accounts/permissions.py
from rest_framework.permissions import BasePermission

class DeclaredPermissions(BasePermission):
    """Default for every view: deny unless the view maps the current action to permissions."""

    def has_permission(self, request, view):
        mapping = getattr(view, "required_permissions", None)
        if mapping is None:
            return False                                    # view declared nothing: deny
        action = getattr(view, "action", None) or request.method.lower()
        needed = mapping.get(action)
        if needed is None:
            return False                                    # action not in the map: deny
        if needed == "public":
            return True
        return bool(request.user and request.user.is_authenticated and request.user.has_perms(needed))
```

```python
# settings.py
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["accounts.permissions.DeclaredPermissions"],
}
```

```python
# accounts/views.py
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

class UserAdminViewSet(viewsets.ModelViewSet):
    serializer_class = AdminUserSerializer
    required_permissions = {
        "list": ["accounts.view_user"],
        "retrieve": ["accounts.view_user"],
        "create": ["accounts.add_user"],
        "update": ["accounts.change_user"],
        "partial_update": ["accounts.change_user"],
        "destroy": ["accounts.delete_user"],
        "set_role": ["accounts.change_user", "accounts.assign_role"],
    }

    def get_queryset(self):
        return User.objects.filter(organisation=self.request.user.organisation)

    @action(detail=True, methods=["post"])
    def set_role(self, request, pk=None):
        target = self.get_object()
        new_role = request.data.get("role")
        if not can_grant(request.user, new_role):           # role ceiling, server-side
            return Response({"detail": "cannot grant this role"}, status=403)
        target.role = new_role
        target.save(update_fields=["role"])
        return Response({"id": target.pk, "role": target.role})
```

Points worth knowing from the DRF documentation: a view's `permission_classes` replaces the default rather than adding to it, so a view that sets `permission_classes = [IsAuthenticated]` silently drops your default; `IsAdminUser` means `is_staff`; `DjangoModelPermissions` maps `POST`, `PUT`/`PATCH` and `DELETE` to add, change and delete permissions but does not check anything for `GET` unless you extend `perms_map`; and `has_object_permission` runs only when the view calls `get_object()`, so it never protects list or create actions. Keep the user's own profile serializer free of `role`, `is_staff` and `is_superuser` (see [Mass assignment and BOPLA](/web/web-mass-assignment-bopla/)).

### Spring Security

Use both layers. `authorizeHttpRequests` gives a coarse URL policy that ends in `denyAll()`, and method security on the service layer gives the precise rule that every entry point shares. Rules are evaluated in order and the first match wins, so put specific rules first. The Spring Security reference suggests permitting `FORWARD` and `ERROR` dispatches so that error pages render under a deny-by-default policy.

```java
import static jakarta.servlet.DispatcherType.ERROR;
import static jakarta.servlet.DispatcherType.FORWARD;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .dispatcherTypeMatchers(FORWARD, ERROR).permitAll()
                .requestMatchers(HttpMethod.GET, "/api/catalogue/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/users/**").hasRole("ADMIN")
                .requestMatchers("/api/**").authenticated()
                .anyRequest().denyAll()
            )
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }
}
```

```java
@Service
public class UserAdminService {

    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(UUID userId) {
        // ...
    }

    // Role ceiling: a bean decides whether the caller may grant the requested role
    @PreAuthorize("hasAuthority('members:invite') and @roleCeiling.canGrant(authentication, #role)")
    public Invitation invite(String email, @P("role") Role role) {
        // ...
    }
}
```

Notes:

- `@EnableMethodSecurity` turns on `@PreAuthorize`, `@PostAuthorize`, `@PreFilter` and `@PostFilter` by default; `@Secured` and JSR-250 annotations need `securedEnabled` or `jsr250Enabled`.
- `hasRole('ADMIN')` matches the authority `ROLE_ADMIN`; `hasAuthority` takes the full string. Mixing them up is a common reason a check never passes and someone removes it.
- A `@PreAuthorize` on a class applies to every method in it; a method-level annotation overrides it. Annotating the admin controller class gives the API5:2023 "admin base controller" behaviour.
- Method security is proxy-based (Spring AOP), so a call from one method to another inside the same bean does not go through the check (the Spring Framework documentation on [AOP proxies](https://docs.spring.io/spring-framework/reference/core/aop/proxying.html) explains self-invocation). Put the annotated methods on the service that controllers and resolvers call.
- `@P("role")` names the parameter for the expression without relying on compiler flags.

### Laravel

Laravel's authorisation is built on gates (closures for actions not tied to a model) and policies (classes per model). Define the admin gate and the policies once, attach them as route middleware for the coarse layer, and call them again in the controller or service for the precise layer:

```php
// app/Providers/AppServiceProvider.php
use App\Models\User;
use Illuminate\Support\Facades\Gate;

public function boot(): void
{
    // hasPermission() is your own method on User, backed by the role-permission table
    Gate::define('access-admin', fn (User $user) => $user->hasPermission('admin.access'));
}
```

```php
// app/Policies/UserPolicy.php
class UserPolicy
{
    public function delete(User $actor, User $target): bool
    {
        return $actor->hasPermission('users.delete')
            && $actor->organisation_id === $target->organisation_id
            && $actor->isNot($target);
    }

    public function assignRole(User $actor, User $target, string $role): bool
    {
        return $actor->hasPermission('members.manage')
            && $actor->organisation_id === $target->organisation_id
            && $actor->isNot($target)                          // no self-assignment
            && Role::rank($role) <= Role::rank($actor->role);  // role ceiling
    }
}
```

```php
// routes/web.php (or routes/api.php)
use App\Http\Controllers\Admin\UserController;
use App\Models\User;

Route::middleware(['auth', 'can:access-admin'])
    ->prefix('admin')
    ->group(function () {
        Route::get('/users', [UserController::class, 'index']);
        Route::delete('/users/{user}', [UserController::class, 'destroy'])->can('delete', 'user');
        Route::post('/users/{user}/role', [UserController::class, 'setRole']);
    });
```

```php
// app/Http/Controllers/Admin/UserController.php
use Illuminate\Support\Facades\Gate;

public function setRole(SetRoleRequest $request, User $user)
{
    $role = $request->validated('role');
    Gate::authorize('assignRole', [$user, $role]);          // throws AuthorizationException -> 403
    $user->forceFill(['role' => $role])->save();             // role is never in $fillable
    return response()->json(['id' => $user->id, 'role' => $user->role]);
}
```

Notes:

- The `can` middleware returns a 403 when the check fails; `->can('delete', 'user')` is shorthand for `->middleware('can:delete,user')` and uses route model binding.
- `Gate::before` runs before every check, and a non-null return decides the result. A `before` hook that returns `true` for administrators is common; make sure it tests a server-side permission, and return `null` (not `false`) for everyone else so normal policies still run.
- Keep `role` and similar columns out of `$fillable` and set them only through the policy-checked path, as above.
- `Response::denyAsNotFound()` lets a gate answer with 404 instead of 403 when you prefer to hide admin routes.

### GraphQL resolvers

Put the check where every resolver path meets: the service function that performs the action. The resolver only passes the authenticated user along.

```javascript
// Vulnerable: one resolver checks, its sibling does not
const resolvers = {
  Query: {
    adminUsers: (_, __, ctx) => { requireRole(ctx.user, 'admin'); return users.list(); },
  },
  Mutation: {
    setUserRole: (_, { userId, role }) => users.update(userId, { role }),   // no check at all
  },
};
```

```javascript
// Fixed: the service is the only code path that changes roles, and it always authorises
const { ForbiddenError, subject } = require('@casl/ability');
const { defineAbilityFor } = require('./policy');

async function setUserRole(actor, userId, role) {
  const target = await users.get(userId);
  const ability = defineAbilityFor(actor);
  ForbiddenError.from(ability).throwUnlessCan('assignRole', subject('Membership', { orgId: target.orgId, role }));
  return users.update(userId, { role });
}

const resolvers = {
  Mutation: {
    setUserRole: (_, { userId, role }, ctx) => usersService.setUserRole(ctx.user, userId, role),
  },
};
```

Map `ForbiddenError` to a GraphQL error with a `FORBIDDEN` code in your server's error formatter, so the client receives a per-field error and `null` data for that field. If you use schema directives for authorisation, make the absence of a directive on a `Mutation` field a startup error, not an implicit allow. A schema-driven test that enforces this is in [Authorisation regression tests](#authorisation-regression-tests).

### Separating administrative interfaces

- **Separate origin, ideally a separate deployment.** `admin.example.com` with its own session cookie (or token audience) means a user session cannot even be presented to the admin application, and a front-end bug in the user app does not ship admin code to users.
- **Separate identity policy.** Admin sign-in through the company IdP with phishing-resistant MFA and device checks, as ASVS `v5.0.0-8.4.2` (L3) describes; network restrictions are a useful extra layer but not the only one.
- **No admin code in the user bundle.** Build the admin SPA separately; do not rely on lazy-loaded chunks being "hard to find".
- **Step-up for the dangerous few.** Role changes, impersonation, exports of all users and key rotation ask for re-authentication.
- **Narrow, logged support tooling.** Impersonation needs a permission, a reason, a ceiling (never impersonate up), a visible banner, a time limit and an audit event naming the real actor.

### Authorisation regression tests

The best fix for function-level flaws is a test that fails when someone adds an endpoint without a rule, or changes a rule without updating the matrix. Two kinds of test do most of the work.

**1. The role matrix, as data.** One file, used by AuthMatrix in testing and by CI:

```yaml
# authz-matrix.yaml  (expected: allow | deny)
- { method: GET,    path: /api/admin/users,              anon: deny, member: deny, manager: deny,  admin: allow }
- { method: POST,   path: /api/orgs/org_t/invitations,    anon: deny, member: deny, manager: allow, admin: allow, body: { email: t@example.org, role: member } }
- { method: POST,   path: /api/orgs/org_t/invitations,    anon: deny, member: deny, manager: deny,  admin: allow, body: { email: t@example.org, role: admin } }
- { method: DELETE, path: /api/users/usr_target,          anon: deny, member: deny, manager: deny,  admin: allow }
- { method: POST,   path: /api/support/impersonate,       anon: deny, member: deny, manager: deny,  admin: allow, body: { targetUserId: usr_target } }
```

A pytest runner for a DRF API (adapt the fixtures to your factories; `deny` accepts 401, 403 or 404 because unauthenticated responses depend on the authentication class):

```python
# tests/test_authz_matrix.py
import pytest, yaml
from rest_framework.test import APIClient

MATRIX = yaml.safe_load(open("authz-matrix.yaml"))
ROLES = ["anon", "member", "manager", "admin"]
DENY = {401, 403, 404}

@pytest.mark.django_db
@pytest.mark.parametrize("row", MATRIX, ids=lambda r: f"{r['method']} {r['path']}")
@pytest.mark.parametrize("role", ROLES)
def test_role_matrix(row, role, make_user, seed_targets):
    client = APIClient()
    if role != "anon":
        client.force_authenticate(user=make_user(role=role, org="org_t"))
    call = getattr(client, row["method"].lower())          # client.get, client.post, ...
    kwargs = {} if row["method"] == "GET" else {"format": "json"}
    resp = call(row["path"], row.get("body"), **kwargs)
    if row[role] == "deny":
        assert resp.status_code in DENY, f"{role} was allowed: {resp.status_code}"
    else:
        assert resp.status_code not in DENY, f"{role} was denied: {resp.status_code}"
```

The same loop in JUnit 5 with MockMvc, for Spring:

```java
@SpringBootTest
@AutoConfigureMockMvc
class RoleMatrixTest {

    @Autowired MockMvc mvc;

    @ParameterizedTest(name = "{0} {1} as {2} -> {3}")
    @CsvSource({
        "GET,    /api/admin/users,     MEMBER,  deny",
        "GET,    /api/admin/users,     ADMIN,   allow",
        "DELETE, /api/users/usr_t,     MANAGER, deny",
        "DELETE, /api/users/usr_t,     ADMIN,   allow",
    })
    void roleMatrix(String method, String path, String role, String expected) throws Exception {
        int status = mvc.perform(request(HttpMethod.valueOf(method), path)
                        .with(user("matrix-" + role.toLowerCase()).roles(role))
                        .with(csrf()))
                .andReturn().getResponse().getStatus();
        if (expected.equals("deny")) {
            assertThat(status).isIn(401, 403, 404);
        } else {
            assertThat(status).isNotIn(401, 403);
        }
    }
}
```

Laravel follows the same pattern with a PHPUnit `#[DataProvider]` that yields role, method, URI and expected status, and `$this->actingAs($user)->json($method, $uri)->assertStatus($expected)`.

**2. The inventory test: every route has a policy.** This is the deny-by-default guarantee in test form. It enumerates the framework's routes and fails for any route that is neither in the matrix nor explicitly public.

Spring (every handler method in your packages must carry `@PreAuthorize`, on the method or the class, or a custom `@PublicEndpoint` marker):

```java
@SpringBootTest
class EveryEndpointHasAPolicyTest {

    @Autowired @Qualifier("requestMappingHandlerMapping")
    RequestMappingHandlerMapping mapping;

    @Test
    void everyEndpointDeclaresAPolicy() {
        List<String> missing = mapping.getHandlerMethods().entrySet().stream()
            .filter(e -> e.getValue().getBeanType().getPackageName().startsWith("com.example"))
            .filter(e -> !hasPolicy(e.getValue()))
            .map(e -> e.getKey().toString())
            .toList();
        assertThat(missing).isEmpty();
    }

    static boolean hasPolicy(HandlerMethod hm) {
        return AnnotatedElementUtils.hasAnnotation(hm.getMethod(), PreAuthorize.class)
            || AnnotatedElementUtils.hasAnnotation(hm.getBeanType(), PreAuthorize.class)
            || AnnotatedElementUtils.hasAnnotation(hm.getMethod(), PublicEndpoint.class);
    }
}
```

Laravel (every route needs `auth` plus a `can:` middleware, or a place on an explicit public list):

```php
public function test_every_route_has_an_authorisation_rule(): void
{
    $public = ['login', 'register', 'password.request', 'up'];
    $missing = collect(Route::getRoutes()->getRoutes())
        ->reject(fn ($r) => in_array($r->getName(), $public, true))   // also filter vendor routes you accept
        ->filter(function ($r) {
            $mw = $r->gatherMiddleware();
            return ! in_array('auth', $mw, true)
                || ! collect($mw)->contains(fn ($m) => is_string($m) && str_starts_with($m, 'can:'));
        })
        ->map(fn ($r) => implode('|', $r->methods()).' '.$r->uri())
        ->values()->all();

    $this->assertSame([], $missing);
}
```

GraphQL (every mutation must have an entry in the policy map that the service layer uses):

```javascript
// test/schema-policy.test.js
const { schema } = require('../src/schema');
const { MUTATION_POLICIES } = require('../src/policy');

test('every mutation has a policy entry', () => {
  const mutations = Object.keys(schema.getMutationType()?.getFields() ?? {});
  const missing = mutations.filter((name) => !(name in MUTATION_POLICIES));
  expect(missing).toEqual([]);
});
```

Django has the same capability through `django.urls.get_resolver()`: walk its `url_patterns` (recursing into `URLResolver` entries) and compare each pattern with your matrix and a public list. The OWASP [Authorization Testing Automation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html) describes the matrix-as-data approach in more detail.

Keep two habits: add a higher-role account as a *target* in object-level tests (that catches [GT-WEB-PRIV-10](#gt-web-priv-10-horizontal-to-vertical-chains-against-higher-role-accounts) chains), and add a row to the matrix in the same pull request that adds the endpoint.

## Practice labs

**PortSwigger Web Security Academy** ([access control topic](https://portswigger.net/web-security/access-control)):

| Lab | What it practises | Test |
|---|---|---|
| [Unprotected admin functionality](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality) | Finding an admin panel from a public hint and using it without a role | PRIV-2, PRIV-3 |
| [Unprotected admin functionality with unpredictable URL](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url) | Admin URL leaked in client-side JavaScript | PRIV-2, PRIV-3 |
| [User role controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter) | Role taken from a cookie the client controls | PRIV-5 |
| [User role can be modified in user profile](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile) | Role property accepted in a profile update | PRIV-5 |
| [Multi-step process with no access control on one step](https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step) | A later step of an admin flow without a check | PRIV-7 |
| [User ID controlled by request parameter with password disclosure](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure) | An IDOR on the administrator's own account leading to admin access | PRIV-10 |
| [Exploiting an API endpoint using documentation](https://portswigger.net/web-security/api-testing/lab-exploiting-api-endpoint-using-documentation) | Using exposed API documentation to find and call a privileged operation | PRIV-2, PRIV-4 |
| [Finding and exploiting an unused API endpoint](https://portswigger.net/web-security/api-testing/lab-exploiting-unused-api-endpoint) | Verbs the UI never uses on a known resource | PRIV-4 |
| [Finding a hidden GraphQL endpoint](https://portswigger.net/web-security/graphql/lab-graphql-find-the-endpoint) | Locating a GraphQL endpoint and using an administrative mutation | PRIV-2, PRIV-9 |
| [Accidental exposure of private GraphQL fields](https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure) | Using the schema to reach data that leads to an administrator's credentials | PRIV-9, PRIV-10 |

The routing and header labs in the same topic ("URL-based access control can be circumvented", "Method-based access control can be circumvented", "Referer-based access control") belong to [Authorisation bypass techniques](/web/web-authorization-bypass-techniques/).

**OWASP Juice Shop** ([GitHub](https://github.com/juice-shop/juice-shop), [companion guide: Broken Access Control](https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html)): *Admin Section* (find and open the administration section), *Five-Star Feedback* (use an admin function to remove feedback), *Product Tampering* (change a product description through the REST API instead of an admin screen), *Web3 Sandbox* (find an accidentally deployed route), and from the Improper Input Validation category *Admin Registration* (register as a user with administrator privileges, a role property at sign-up).

**OWASP crAPI** ([GitHub](https://github.com/OWASP/crAPI), [challenges](https://github.com/OWASP/crAPI/blob/main/docs/challenges.md)): Challenge 7, "Delete a video of another user", is the BFLA challenge: infer an admin endpoint from the predictable structure of the REST API and call it as an ordinary user.

**VAmPI** ([GitHub](https://github.com/erev0s/VAmPI)): the `DELETE /users/v1/{username}` operation is documented as admin-only, and in vulnerable mode the registration endpoint accepts an `admin` property. Register with it, then use the admin-only delete against a user you created; `/users/v1/_debug` is a debug endpoint to find in [GT-WEB-PRIV-2](#gt-web-priv-2-discover-privileged-functions-the-ui-hides).

Run all of these locally or in the vendor's hosted lab, never against a shared deployment you do not own.

## Real-world cases

| Case | What happened | Lesson | Test |
|---|---|---|---|
| Shopify, Stocky app, [HackerOne report 1245736](https://hackerone.com/reports/1245736) (reported 2021, disclosed 2021, rated Medium) | A non-privileged Stocky user captured an ordinary authenticated request, changed it to `POST /users/create_admin`, and the endpoint created an administrator with the low-privilege session. The [HackerOne write-up](https://www.hackerone.com/blog/how-privilege-escalation-led-unrestricted-admin-account-creation-shopify) explains the flow. | Admin functions that the UI hides still need a role check; a session valid for one endpoint was valid for all. | PRIV-3 |
| GitLab, [HackerOne report 762271](https://hackerone.com/reports/762271) (reported 2019, disclosed 2020, rated Low, bounty USD 100) | A user with no role in a project could call the `issueSetConfidential` GraphQL mutation on issues assigned to them. Changing confidentiality is reserved for Reporter and above. | Each GraphQL mutation is a function and needs its own role check, including for users with *some* relationship to the object. | PRIV-9 |
| AnythingLLM, [CVE-2024-0404](https://nvd.nist.gov/vuln/detail/CVE-2024-0404) ([huntr report](https://huntr.com/bounties/b4355bae-766a-4bb0-942b-607bc491b23d), [fix commit](https://github.com/mintplex-labs/anything-llm/commit/8cd3a92c660b202655d99bee90b2864694c99946)) | The invitation-acceptance endpoint `/api/invite/:code` accepted a `role` property, so an invited user could create their account as an admin. NVD lists CWE-915. | Invitation acceptance must take the role from the server-side invitation record, never from the request. | PRIV-5, PRIV-6 |
| Ultimate Member WordPress plugin, [CVE-2023-3460](https://nvd.nist.gov/vuln/detail/CVE-2023-3460) | Before 2.6.7, visitors could register accounts with arbitrary capabilities, which means administrator accounts; NVD notes active exploitation. Public analyses attribute it to user meta (including the WordPress capabilities key) being settable during registration despite a blocklist. | Blocklists of "dangerous" properties fail; registration must use an allowlist and a fixed default role. | PRIV-5 |
| Atlassian Confluence Data Center and Server, [CVE-2023-22515](https://confluence.atlassian.com/security/cve-2023-22515-broken-access-control-vulnerability-in-confluence-data-center-and-server-1295682276.html) ([Rapid7 analysis](https://www.rapid7.com/blog/post/ra-cve-2023-22515-analysis/)) | Exploited as a zero-day in 2023. Rapid7's analysis shows an unauthenticated request to `/server-info.action` setting `bootstrapStatusProvider.applicationConfig.setupComplete=false`, which reopened the setup flow, after which `/setup/setupadministrator.action` created a new administrator. | A privileged flow (first-run setup) guarded only by application state that a request could change; the setup functions themselves had no role check. Unauthenticated to administrator is the top of the severity scale. | PRIV-3, PRIV-7 |

## Rating findings

Rate by what the attacker gains, the role they start from, how they learn the function exists, and how much it affects. A function-level flaw is rated by the **highest privilege it yields**, not by the request that triggers it.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Unauthenticated call to an admin function with full control (create admin, change any role) | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | No account needed; complete control of the application. The Confluence case. |
| Any registered user becomes administrator (role property at registration or invitation, self-assignment) | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Low privileges required. Rate Critical in the narrative when anyone can self-register and the admin role controls all customers' data. |
| Platform-level admin reached by a tenant user in a multi-tenant SaaS (controls other tenants) | Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Scope stays Unchanged because the same application enforces every tenant boundary (the series convention, see the [Access Control hub](/web/web-access-control-testing-guide/)); rate it Critical in the narrative because one account reaches every tenant. |
| Lower role runs an admin-only write or delete (delete users, disable accounts) | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` (8.1) | Integrity and availability of other users' accounts; one request per victim. |
| Lower role reads an admin-only listing of all users' PII | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | CVSS gives Medium; we rate High for all-users scale and PII, and say why. Lower it if the data is not sensitive. |
| Horizontal-to-vertical chain: IDOR on an admin's e-mail or credentials leading to admin takeover | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Rated as admin account takeover. If the admin's identifier is a non-guessable value not exposed elsewhere, consider `AC:H` (7.5) and explain. |
| Role-ceiling failure: a delegated admin or manager grants admin | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (7.2) | Requires an already-privileged role, which lowers likelihood; the result is full admin. |
| Support role impersonates an administrator | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (7.2) | Insider-level precondition; impact is admin. Worse if impersonation is not logged. |
| GraphQL mutation reserved for a higher role, limited effect (change a flag on an object the user is linked to) | Low to Medium | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` (4.3) | The GitLab case; limited integrity impact on specific objects. |
| Admin function refused, but the error leaks admin-only data (counts, internal fields) | Low | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (4.3) | Minor confidentiality impact. |
| Admin interface protected only by network location, no step-up (L3 target) | Low | n/a (hardening) | ASVS `v5.0.0-8.4.2` gap; raises the impact of other findings. |
| Admin menu, routes or source maps visible to members, every API call returns 403 | Info | n/a | Hidden-UI-only defect with no server-side gap. Report source maps or docs exposure separately if they reveal sensitive logic. |

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 / API Top 10 |
|---|---|---|---|---|
| [GT-WEB-PRIV-1](#gt-web-priv-1-build-the-role-and-function-matrix) | WSTG-ATHZ-03, WSTG-APIT-04 | v5.0.0-8.1.1 (L1) | CWE-285 | A01:2025, API5:2023 |
| [GT-WEB-PRIV-2](#gt-web-priv-2-discover-privileged-functions-the-ui-hides) | WSTG-APIT-01, WSTG-APIT-99, WSTG-BUSL-02 | v5.0.0-13.4.5 (L2), v5.0.0-4.3.2 (L2) | CWE-540 | A01:2025, API5:2023 |
| [GT-WEB-PRIV-3](#gt-web-priv-3-call-privileged-functions-with-a-lower-privilege-session) | WSTG-ATHZ-03, WSTG-ATHZ-02, WSTG-APIT-04 | v5.0.0-8.2.1 (L1), v5.0.0-8.3.1 (L1) | CWE-862, CWE-602, CWE-306 | A01:2025, API5:2023 |
| [GT-WEB-PRIV-4](#gt-web-priv-4-sibling-operations-and-verbs-on-the-same-resource) | WSTG-APIT-04, WSTG-ATHZ-03 | v5.0.0-8.2.1 (L1) | CWE-862, CWE-863 | A01:2025, API5:2023 |
| [GT-WEB-PRIV-5](#gt-web-priv-5-role-and-permission-values-in-client-requests) | WSTG-ATHZ-03, WSTG-BUSL-02 | v5.0.0-8.2.1 (L1), v5.0.0-8.2.3 (L2), v5.0.0-15.3.3 (L2) | CWE-915, CWE-269, CWE-602 | A01:2025, API3:2023, API5:2023 |
| [GT-WEB-PRIV-6](#gt-web-priv-6-role-ceilings-and-self-assignment-of-roles-and-groups) | WSTG-ATHZ-03, WSTG-APIT-04 | v5.0.0-8.2.1 (L1) | CWE-269, CWE-266 | A01:2025, API5:2023 |
| [GT-WEB-PRIV-7](#gt-web-priv-7-privileged-actions-inside-bulk-import-and-multi-step-features) | WSTG-ATHZ-03, WSTG-BUSL-06 | v5.0.0-8.2.1 (L1), v5.0.0-2.3.1 (L1) | CWE-863, CWE-862 | A01:2025, API5:2023 |
| [GT-WEB-PRIV-8](#gt-web-priv-8-impersonation-support-tooling-and-feature-flags) | WSTG-ATHZ-03, WSTG-BUSL-02 | v5.0.0-8.2.1 (L1), v5.0.0-8.3.1 (L1), v5.0.0-13.4.2 (L2) | CWE-269, CWE-602 | A01:2025, API5:2023 |
| [GT-WEB-PRIV-9](#gt-web-priv-9-graphql-mutations-and-privileged-queries) | WSTG-APIT-04, WSTG-APIT-99 | v5.0.0-8.2.1 (L1), v5.0.0-4.3.2 (L2) | CWE-862, CWE-285 | A01:2025, API5:2023 |
| [GT-WEB-PRIV-10](#gt-web-priv-10-horizontal-to-vertical-chains-against-higher-role-accounts) | WSTG-ATHZ-02, WSTG-ATHZ-03 | v5.0.0-8.2.2 (L1), v5.0.0-8.2.1 (L1) | CWE-639, CWE-269 | A01:2025, API1:2023, API5:2023 |
| [GT-WEB-PRIV-11](#gt-web-priv-11-administrative-interface-separation-and-layered-controls) | WSTG-ATHZ-03 | v5.0.0-8.4.2 (L3), v5.0.0-8.3.1 (L1), v5.0.0-16.3.2 (L2) | CWE-285 | A01:2025 |

## References

**OWASP testing guide and standards**

- WSTG-ATHZ-03, [Privilege Escalation](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/03-Privilege_Escalation/)
- WSTG-ATHZ-02, [Bypassing Authorization Schema](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/02-Bypassing_Authorization_Schema/)
- WSTG-APIT-04, [API Broken Function Level Authorization](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/04-API_Broken_Function_Level_Authorization/)
- WSTG-APIT-01, [API Reconnaissance](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/01-API_Reconnaissance/)
- WSTG-APIT-99, [GraphQL](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/99-GraphQL/)
- WSTG-BUSL-02, [Ability to Forge Requests](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/10-Business_Logic/02-Ability_to_Forge_Requests/)
- WSTG-BUSL-06, [Circumvention of Work Flows](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/10-Business_Logic/06-Circumvention_of_Work_Flows/)
- OWASP ASVS 5.0, [V8 Authorization](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x17-V8-Authorization.md) and the [full 5.0 source](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0)
- OWASP API Security Top 10 2023, [API5:2023 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/) and [API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- OWASP Top 10:2025, [A01:2025 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)

**OWASP Cheat Sheets**

- [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [Authorization Testing Automation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html)
- [Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)

**CWE**

- [CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html), [CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)
- [CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html), [CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html), [CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)
- [CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html), [CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
- [CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html), [CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html), [CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

**PortSwigger**

- [Access control vulnerabilities and privilege escalation](https://portswigger.net/web-security/access-control)
- [API testing](https://portswigger.net/web-security/api-testing)
- [GraphQL API vulnerabilities](https://portswigger.net/web-security/graphql)

**Framework documentation**

- Express, [Using middleware](https://expressjs.com/en/guide/using-middleware.html) and [Routing](https://expressjs.com/en/guide/routing.html); CASL, [Introduction](https://casl.js.org/v6/en/guide/intro/)
- Django, [Using the Django authentication system](https://docs.djangoproject.com/en/5.2/topics/auth/default/) (`permission_required`, `PermissionRequiredMixin`) and [Middleware](https://docs.djangoproject.com/en/5.2/ref/middleware/) (`LoginRequiredMiddleware`)
- Django REST framework, [Permissions](https://www.django-rest-framework.org/api-guide/permissions/)
- Spring Security, [Authorize HttpServletRequests](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html) and [Method Security](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html); Spring Framework, [Proxying mechanisms](https://docs.spring.io/spring-framework/reference/core/aop/proxying.html)
- Laravel, [Authorization](https://laravel.com/docs/13.x/authorization)
- GraphQL Foundation, [Authorization](https://graphql.org/learn/authorization/)

**Tools**

- Burp extensions: [Autorize](https://github.com/PortSwigger/autorize), [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix), [Auth Analyzer](https://github.com/PortSwigger/auth-analyzer), [InQL](https://github.com/doyensec/inql)
- [ZAP Access Control Testing add-on](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/)
- [clairvoyance](https://github.com/nikitastupin/clairvoyance), [graphql-cop](https://github.com/dolevf/graphql-cop)
- [ffuf](https://github.com/ffuf/ffuf), [Arjun](https://github.com/s0md3v/Arjun), [Kiterunner](https://github.com/assetnote/kiterunner), [LinkFinder](https://github.com/GerbenJavado/LinkFinder), [sourcemapper](https://github.com/denandz/sourcemapper) (background: [JavaScript from source maps](https://pulsesecurity.co.nz/articles/javascript-from-sourcemaps))

**Labs**

- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), [OWASP crAPI](https://github.com/OWASP/crAPI), [VAmPI](https://github.com/erev0s/VAmPI)
