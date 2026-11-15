---
title: "Multi-Tenant Isolation: Testing Cross-Tenant Access in SaaS"
date: 2026-11-15 18:08:00 +0000
subcategory: access-control
summary: "Testing SaaS tenant isolation: tenant resolution, cross-tenant IDs, invitations, SSO binding, caches, storage, jobs, RLS and per-framework fixes."
refs: [WSTG-ATHZ-02, WSTG-ATHZ-04, WSTG-APIT-02, WSTG-APIT-04, WSTG-SESS-10, v5.0.0-8.4.1, v5.0.0-8.2.2, v5.0.0-8.3.1, v5.0.0-8.2.1, v5.0.0-6.8.1, v5.0.0-4.1.3, "API1:2023", "API5:2023", "A01:2025", CWE-639, CWE-863, CWE-862, CWE-284, CWE-668]
tags: [web, access-control, multi-tenant, saas, row-level-security, sso]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and the [Access Control testing guide](/web/web-access-control-testing-guide/). It covers the boundary that matters most in a SaaS product: the line between one customer's organisation (the *tenant*) and every other customer's. Most of what goes wrong is still ordinary object-level authorisation, as in [IDOR / BOLA](/web/web-idor-bola/), but a tenant boundary has its own shape. The tenant is resolved from somewhere (a subdomain, a path, a header, a token claim, a session), one user can belong to several tenants, tenant administrators are powerful but must not be platform administrators, and the data leaves the request path through search indexes, exports, caches, object storage, queues and identity federation. We cover the isolation models (shared tables with a `tenant_id` column, schema per tenant, database per tenant, PostgreSQL row-level security) and how each one fails, where the tenant is resolved and what happens when two sources disagree, organisation switching, invitations and membership, the long tail of object types, SSO binding, support consoles, and side channels. Then come twelve tests (`GT-WEB-TEN-1` to `GT-WEB-TEN-12`) that you run with two tenants you control, fixes for Express/Prisma, Django/DRF, Spring and Laravel plus PostgreSQL RLS, and how to rate what you find. The primary requirement is ASVS 5.0 `v5.0.0-8.4.1`; the tests implement WSTG-ATHZ-02 and WSTG-ATHZ-04 and their API counterparts.

## Contents

- [How it works](#how-it-works)
  - [What a tenant is](#what-a-tenant-is)
  - [Isolation models](#isolation-models)
  - [Where the tenant comes from](#where-the-tenant-comes-from)
  - [The request path, done properly](#the-request-path-done-properly)
  - [SPAs, APIs, GraphQL and mobile back-ends](#spas-apis-graphql-and-mobile-back-ends)
- [What goes wrong](#what-goes-wrong)
  - [The tenant is a client-supplied value nobody checks](#the-tenant-is-a-client-supplied-value-nobody-checks)
  - [Two tenant sources that disagree](#two-tenant-sources-that-disagree)
  - [The long tail of object types](#the-long-tail-of-object-types)
  - [Cross-tenant references](#cross-tenant-references)
  - [Membership, invitations and switching](#membership-invitations-and-switching)
  - [Tenant admin treated as platform admin](#tenant-admin-treated-as-platform-admin)
  - [Search, reporting, exports and caches](#search-reporting-exports-and-caches)
  - [File and object storage](#file-and-object-storage)
  - [Background jobs and queues](#background-jobs-and-queues)
  - [SSO and identity provider binding](#sso-and-identity-provider-binding)
  - [Support and impersonation consoles](#support-and-impersonation-consoles)
  - [Side channels: uniqueness, errors, rate limits and quotas](#side-channels-uniqueness-errors-rate-limits-and-quotas)
  - [Database-level isolation that does not hold](#database-level-isolation-that-does-not-hold)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-WEB-TEN-1: Map the tenancy model and every tenant selector](#gt-web-ten-1-map-the-tenancy-model-and-every-tenant-selector)
  - [GT-WEB-TEN-2: Swap tenant B object IDs into tenant A requests](#gt-web-ten-2-swap-tenant-b-object-ids-into-tenant-a-requests)
  - [GT-WEB-TEN-3: Make the tenant selectors disagree](#gt-web-ten-3-make-the-tenant-selectors-disagree)
  - [GT-WEB-TEN-4: Organisation switching and stale tenant context](#gt-web-ten-4-organisation-switching-and-stale-tenant-context)
  - [GT-WEB-TEN-5: Invitations and membership lifecycle](#gt-web-ten-5-invitations-and-membership-lifecycle)
  - [GT-WEB-TEN-6: Tenant admin versus platform admin](#gt-web-ten-6-tenant-admin-versus-platform-admin)
  - [GT-WEB-TEN-7: Search, reporting, exports and caches](#gt-web-ten-7-search-reporting-exports-and-caches)
  - [GT-WEB-TEN-8: File and object storage paths](#gt-web-ten-8-file-and-object-storage-paths)
  - [GT-WEB-TEN-9: Background jobs, integrations and webhooks](#gt-web-ten-9-background-jobs-integrations-and-webhooks)
  - [GT-WEB-TEN-10: SSO and identity provider tenant binding](#gt-web-ten-10-sso-and-identity-provider-tenant-binding)
  - [GT-WEB-TEN-11: Support and impersonation consoles](#gt-web-ten-11-support-and-impersonation-consoles)
  - [GT-WEB-TEN-12: Cross-tenant side channels](#gt-web-ten-12-cross-tenant-side-channels)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Node.js: Express with Prisma](#nodejs-express-with-prisma)
  - [Django and Django REST framework](#django-and-django-rest-framework)
  - [Spring Security with Hibernate 6](#spring-security-with-hibernate-6)
  - [Laravel](#laravel)
  - [PostgreSQL row-level security as a backstop](#postgresql-row-level-security-as-a-backstop)
  - [Caches, storage, jobs and identity](#caches-storage-jobs-and-identity)
  - [Cross-tenant regression tests](#cross-tenant-regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### What a tenant is

A tenant is the unit a SaaS product sells to and isolates: an organisation, workspace, account, team, company or project, depending on the product's vocabulary. Users are not tenants. A user is an identity that holds a **membership** in one or more tenants, and each membership carries a role (owner, admin, member, viewer, guest) that is only meaningful inside that tenant. So almost every authorisation question in a SaaS product has three parts:

1. **Is this caller a member of tenant T?** (membership, current and not revoked)
2. **Does the caller's role in T allow this action?** (function-level, see [vertical escalation and BFLA](/web/web-vertical-privilege-escalation-bfla/))
3. **Does this object belong to T, and may this caller touch it?** (object-level, see [IDOR / BOLA](/web/web-idor-bola/))

Part 1 is the one generic access-control testing tends to skip, because a single-tenant app does not have it. ASVS 5.0 states the outcome in `v5.0.0-8.4.1` (L2): a multi-tenant application uses cross-tenant controls so that an operation never affects a tenant the caller has no permission to interact with. The OWASP [Multi-Tenant Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html) puts the rule for implementers well: a tenant identifier that the client sends is a *selector*, never proof of membership.

Two further facts shape testing. A **platform** sits above the tenants: the vendor's own staff, support tooling, billing, and anything marked "super admin" or "root". And tenants are often **cheap to create**: if anyone can start a free trial, "attacker with a tenant-admin role" means "anyone on the internet", which matters for rating.

### Isolation models

Where the data is separated decides which mistakes are possible. You rarely see the model from outside, but error messages, IDs, latency and the client's architecture documents tell you, and you should ask.

| Model | How tenants are separated | Typical failure modes |
|---|---|---|
| **Shared tables, `tenant_id` column** (pool) | Every tenant-owned row has `tenant_id`/`org_id`; every query must filter by it | One query, endpoint or object type that forgets the filter; filtering on a `tenant_id` taken from the request; joins that filter the parent but not the child; raw SQL and reporting queries outside the ORM scope; unique indexes that span tenants and leak existence |
| **Schema per tenant** | One schema per tenant in the same database; the connection's `search_path` (or a schema prefix) selects it, as in [django-tenants](https://django-tenants.readthedocs.io/en/latest/) | The schema is chosen from an attacker-influenced value (hostname, header); a pooled connection keeps the previous request's `search_path`; shared ("public") tables that hold tenant data; background jobs that run in the default schema |
| **Database per tenant** (silo) | Separate database or cluster per tenant; a router picks the connection string | The router trusts a request value; a shared cache, search cluster, object store or analytics warehouse re-merges the data; the control-plane database (users, memberships, billing) is shared anyway |
| **Row-level security** (PostgreSQL RLS, or the equivalent in other databases) | The database adds a policy predicate to every query, usually comparing `tenant_id` to a per-transaction setting | The application connects as the table owner, a superuser or a `BYPASSRLS` role; the setting leaks across pooled connections; views and `SECURITY DEFINER` functions run with the owner's rights; the setting can be changed by SQL the user influences |
| **Hybrid** (AWS calls it the *bridge* model) | Large customers in silos, small ones pooled; or pooled data plus per-tenant encryption keys | Code paths that differ per tier, so you must test both a pooled and a siloed tenant if you can |

The models are not alternatives to application authorisation. Even database-per-tenant needs the application to pick the right database for a caller who is a member of that tenant, and RLS protects only the tables it is enabled on, only for the roles it applies to. The cheat sheet treats ORM-level filtering as defence in depth for the same reason: raw queries and some write paths go around it.

### Where the tenant comes from

A request can name its tenant in many places at once. List every one the application reads before you test anything:

| Source | Example | Who controls it |
|---|---|---|
| Subdomain | `https://tenant-a.example.com/` | The client (any `Host` header the edge forwards) |
| Custom domain | `https://docs.example.org/` mapped to tenant A | The client sends it; the mapping is tenant configuration (verified or not) |
| Path segment | `/orgs/tenant-a/projects/42`, `/api/v2/workspaces/7f3c…/` | The client |
| Header | `X-Tenant-ID`, `X-Org-Id`, `X-Workspace`, `X-Account-Id` | The client, unless an intermediary sets it and strips client values (`v5.0.0-4.1.3`) |
| Query or body field | `?org_id=…`, `"organizationId": "…"` | The client |
| Token claim | `org_id`, `tid`, `tenant`, `https://example.com/org` in a JWT | The issuer, if the signature, issuer and audience are validated |
| Session | `session.current_org_id` set by an org switcher | The server, but set by a client request |
| API key or service token | A key that belongs to tenant A | The server, if the key record carries its tenant |
| Object itself | The tenant of `document 42` looked up from the database | The server |

The safe pattern is to derive the tenant from one trusted source (the membership record behind the authenticated session, a validated token claim, or the API key record), treat any client-supplied selector as a request to act in that tenant, and confirm the caller is an active member before binding it. The unsafe pattern, which is common, is a middleware that resolves the tenant from one source (say, the subdomain) while the handler or the data layer uses another (say, the `X-Org-Id` header, a body field, or the object's own `org_id`). Then the check and the action can be about two different tenants.

### The request path, done properly

```text
request ──► authenticate (who is the caller?)
        ──► resolve tenant ONCE: selector from path/subdomain/header/claim
              └─ confirm active membership of caller in that tenant, load role
        ──► bind {tenant, membership} to the request context (immutable for the request)
        ──► function check: does the role allow this action?
        ──► data access through tenant-scoped repositories only
              └─ every read/write includes the bound tenant; new rows get it from context
        ──► object check where needed (owner, sharing, field-level)
        ──► response; cache keys, logs, metrics and enqueued jobs carry the bound tenant
```

Everything after "bind" uses the bound tenant, never a fresh value from the request. That one rule removes most cross-tenant bugs, because it makes "the tenant I checked" and "the tenant I acted on" the same variable. ASVS `v5.0.0-8.3.1` (L1) says the enforcement belongs in a trusted service layer, not in client code; `v5.0.0-8.2.2` (L1) says data-specific access is limited to consumers with permission to those data items. For tenant isolation the "data item" check is nearly free once the data layer is scoped: an object from tenant B is simply not found when the bound tenant is A.

### SPAs, APIs, GraphQL and mobile back-ends

- **SPAs** typically keep the "current organisation" in the URL (`/app/acme/…`) or local storage and send it as a header or path segment on every API call. The UI's org switcher lists only your memberships, which tells you nothing about what the API will accept.
- **Public and partner APIs** often authenticate with tenant-scoped API keys. Check whether the key's tenant or a request parameter decides the tenant, and whether keys from one tenant work on routes that take a tenant in the path.
- **GraphQL** resolvers fetch by global ID (`node(id:)`), and nested resolvers (`organization { members { … } }`) each need their own scoping. Batch queries and aliases let you test many object types in one request. Object-level GraphQL testing is in [IDOR / BOLA](/web/web-idor-bola/) and field-level access in [mass assignment and BOPLA](/web/web-mass-assignment-bopla/).
- **Mobile back-ends** frequently reuse the web API with an extra header for the selected workspace, and older app versions may call deprecated endpoints that predate the tenant scoping.
- **Microservices** pass the tenant between services in headers or message attributes. A downstream service that trusts an `X-Tenant-ID` header from "inside" is only as safe as every path by which a client value can reach it (see [authorization bypass techniques](/web/web-authorization-bypass-techniques/) for header trust and proxy mismatches).

## What goes wrong

### The tenant is a client-supplied value nobody checks

The middleware reads `X-Org-Id` (or the subdomain, or `/orgs/:orgId/`) and sets the tenant context, and nothing confirms that the caller is a member of that organisation. Every endpoint is then "correctly" scoped to whichever tenant the caller names. This is the worst variant because it is systematic: one change of a header gives you a different customer's entire workspace, and IDs do not matter. **Where to look:** any tenant selector in the request, especially headers that the web UI never sends but the mobile app or public API does, and path segments that look like slugs (`acme`, `globex`) because slugs are guessable and often public.

### Two tenant sources that disagree

The authorisation step and the data step read the tenant from different places. Typical pairs:

- Middleware checks membership for the tenant in the **path**; the handler loads the object by ID without a tenant filter, so `/orgs/A/documents/<id-in-B>` passes the check for A and returns B's document.
- Middleware validates the tenant in the **JWT claim**; the handler reads `organizationId` from the **body** when creating or moving an object.
- The **subdomain** decides branding and the login page; the **session** holds the tenant the user last switched to; the API uses the session, so `tenant-a.example.com` shows tenant B's data after a switch and the reverse.
- A permission check runs against the **query string** org ID; the handler acts on the **active organisation in the session** when the body has none. This exact split was the cause of the `@better-auth/stripe` advisory in [Real-world cases](#real-world-cases).

**Why it matters:** each check looks right in code review, because each one is right about the value it reads. **Where to look:** routes that take the tenant in more than one place, nested routes (`/orgs/:org/projects/:project/…`) where the child is loaded by its own ID, and "move", "copy", "duplicate" and "transfer" operations that take a destination tenant.

### The long tail of object types

The core objects (projects, documents, tickets) are usually scoped because they were built first and tested most. The bugs live in the objects added later or built by another team: comments and attachments, saved views and filters, dashboards, custom fields, tags and labels, integrations and OAuth connections, API keys and personal access tokens, webhooks and their delivery logs, audit logs, invoices and billing contacts, notification settings, export jobs, import mappings, templates, AI assistants and their conversation history, and user objects themselves (`/users/:id` returning a user from another organisation, with email and role). **Where to look:** list the object types in the API schema, OpenAPI document, GraphQL introspection or JavaScript bundle and test each one, not a sample.

### Cross-tenant references

Write operations often take IDs of *other* objects: "attach file 77 to ticket 12", "add user 9 to project 4", "use integration 5 for this automation", "copy template 31". If the handler checks the main object's tenant but not the referenced one, you can pull an object from tenant B into a resource in tenant A, where you can read it, or push data from tenant A into tenant B's objects. Django's related-object access and most ORMs' relation loading do not re-apply your tenant filter when they follow a foreign key (see [Django and Django REST framework](#django-and-django-rest-framework)), so once the reference is stored the leak is permanent. **Where to look:** every ID in a request body that is not the object being written; bulk operations that take arrays of IDs.

### Membership, invitations and switching

Membership is itself an object with a lifecycle, and each step is a place to cross a tenant boundary:

- **Invitations.** An invite created in tenant A for an email address; an invite token in a link; acceptance by whoever is logged in. Bugs: the token is accepted by a session whose verified email does not match the invite (so a forwarded or leaked link joins the wrong identity, or an attacker's account joins with the role intended for someone else); the invite endpoint lets a tenant-A admin set the target organisation or role in the body; invite tokens are reusable after acceptance or after the invite is revoked; inviting a user who belongs to tenant B exposes B's profile data to A; "request to join" flows that auto-approve by email domain.
- **Removal and downgrade.** After a member is removed or downgraded, existing sessions, refresh tokens, cached permissions, API keys and personal access tokens they created keep working. Stale access after removal is in the [revocation note](/web/web-access-control-revocation-sharing-async/) in general; for tenants the specific question is whether the *membership* is re-checked on each request or only at login. The Stripe Atlas report in [Real-world cases](#real-world-cases) involved someone with *prior* admin access to an account.
- **Switching.** A user in tenants A and C switches between them. Bugs: the switch endpoint accepts any organisation ID (including B, where you are not a member); the access token keeps the old tenant claim while the session has the new one; client-side state (cached lists, websockets, service workers) keeps showing the previous tenant's data; a role you hold in C is applied while acting in A.

### Tenant admin treated as platform admin

Tenant administrators can manage users, roles, SSO settings, integrations, billing and data retention for *their* tenant. If those admin endpoints take a tenant or user ID and check only "is the caller an admin?", a tenant admin of a free trial is an admin of everyone. The ZITADEL advisory [GHSA-cpf4-pmr4-w6cx](https://github.com/zitadel/zitadel/security/advisories/GHSA-cpf4-pmr4-w6cx) (CVE-2025-64431) is a public example: an administrator in one organisation could read, modify and delete other organisations through the organisation API. The other direction matters too: platform-level functions (feature flags, tenant creation, plan changes, global settings, "all tenants" reports) must not be reachable with a tenant-level admin role, and a role name like `admin` shared between the two levels is a red flag. **Where to look:** `/admin`, `/settings`, `/manage`, user-management APIs that take a user ID (a user ID is global even when the user is in another tenant), and any role check that tests a string without the tenant.

### Search, reporting, exports and caches

Aggregating features read many rows at once and are often built on a different store from the main database:

- **Search** in Elasticsearch/OpenSearch, Algolia, Typesense or a vector store for AI features. The tenant filter must be applied on the server side query; a filter the client sends (`filters: "org_id:A"`) or a search-only API key that is not scoped per tenant lets you remove it. Autocomplete and "mention a user" endpoints are frequent offenders.
- **Reporting and analytics**: dashboards with a `tenant` parameter, embedded BI tools with signed embed URLs where the tenant is a parameter, data warehouse exports.
- **Exports**: an export job that takes an organisation ID, stores the file under a guessable key, and serves it without checking that the requester is in that organisation.
- **Caches**: a response cache or application cache keyed by path or object ID only. If `/api/dashboard` is cached per user ID but user IDs collide across tenants (per-tenant sequences), or a CDN caches `/api/org/settings` without varying on the tenant header or cookie, the next tenant gets the previous tenant's data. ASVS `v5.0.0-14.2.2` (L2) covers sensitive data in server-side caches; web cache deception is a separate class that PortSwigger documents in its [web cache deception](https://portswigger.net/web-security/web-cache-deception) topic.

### File and object storage

Files usually live in S3, GCS or Azure Blob under a key such as `tenants/<tenant_id>/files/<file_id>/<name>`. Failures: the download endpoint builds the key from request parameters (`?tenant=B&file=…`) after checking membership of a different tenant; the key prefix is the only control and the bucket allows listing; pre-signed URLs are long-lived and handed out without a tenant check; image resizing or preview services fetch any key they are given; and prefix matching treats `tenants/acme` as also covering `tenants/acme-west` (the cheat sheet's deletion example). Storage specifics for AWS are in [S3 security](/cloud/aws-s3-security/).

### Background jobs and queues

A job enqueued by a request often carries IDs but not the tenant, and the worker has no request context, so it runs unscoped (or in a default tenant, or in whichever tenant the previous job on that worker set in a thread-local). Webhook deliveries, scheduled reports, email digests, imports, AI summarisation jobs and data syncs are all jobs. The cheat sheet's advice is to carry the verified tenant in the message and re-authorise at the consumer. The general async patterns (webhooks, subscriptions, confused deputies between services) are in the [revocation, sharing and async note](/web/web-access-control-revocation-sharing-async/).

### SSO and identity provider binding

Enterprise tenants bring their own identity provider (SAML 2.0 or OIDC). The SaaS product must bind each IdP configuration to exactly one tenant and accept from it only users of that tenant. Failures:

- **An IdP configured by tenant A asserts users of tenant B.** If the application looks up the user by email from the assertion and logs them in wherever that email lives, the admin of tenant A (who controls their own IdP and can put any email in an assertion) can log in as any user of tenant B. ASVS `v5.0.0-6.8.1` (L2) addresses this: with several IdPs, identify users by the IdP's ID plus the user's ID at that IdP, so one IdP cannot speak for another's users.
- **Domain claims without verification.** "Users with `@example.org` addresses join tenant A automatically" or "SSO is enforced for `example.org`" is only safe if tenant A proved control of `example.org`. Unverified domain claims let one tenant capture another's sign-ups or redirect their logins. Domains also change hands: Truffle Security showed that buying the domain of a defunct start-up let them recreate former employees' Google accounts and sign in to SaaS tools that trusted the domain and email claims ([write-up](https://trufflesecurity.com/blog/millions-at-risk-due-to-google-s-oauth-flaw)).
- **Multi-tenant OIDC apps that accept any tenant's tokens.** An app registered as multi-tenant in Microsoft Entra ID signs in users from *any* Entra tenant. Microsoft's guidance is that the application must check the issuer and tenant itself. The tenant-independent metadata publishes a templated issuer (`https://login.microsoftonline.com/{tenantid}/v2.0`); the application substitutes the token's tenant ID (`tid`), requires an exact match with `iss`, checks the signing key's issuer, and uses `tid` as part of the key for the user's data. An API should also check that `tid` matches the tenant whose data it stores ([multi-tenant apps](https://learn.microsoft.com/en-us/entra/identity-platform/howto-convert-app-to-be-multi-tenant), [access tokens](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens), [claims validation](https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation)). The same `sub` in two Entra tenants is two different people. Microsoft also warns against using `email`, `preferred_username` or `unique_name` for authorisation and recommends the immutable `tid` plus `oid` as the key. Wiz's BingBang and Descope's nOAuth research (both in [Real-world cases](#real-world-cases)) are what happens when these checks are missing.
- **JIT provisioning into the wrong tenant.** Just-in-time provisioning that creates the user in the tenant named by a `RelayState`, query parameter or the subdomain rather than the tenant that owns the IdP configuration.
- **Token audience and issuer confusion between tenants.** WSTG-SESS-10 includes replaying a token from a lower-trust tenant against a service that shares the same signing keys; ASVS `v5.0.0-9.2.3` (L2) and `v5.0.0-10.3.1` (L2) require audience checks. SAML and OIDC protocol attacks (signature wrapping and the like) belong in the Authentication subcategory, which is not written yet.

### Support and impersonation consoles

The vendor's staff need to help customers, so most SaaS products have a support console ("log in as", "view as", "impersonate") and an internal admin API. These are cross-tenant by design, which makes them the highest-value target in the product. Failures: the console is reachable from the internet with ordinary customer sessions (a role check that a tenant admin passes); impersonation is not limited to tenants that opened a ticket or granted access; impersonated sessions can do everything the user can (change passwords, export data, create API keys) instead of a read-only or limited set; the impersonation is not visible to the tenant in its audit log; and impersonation tokens are long-lived or reusable. You usually test this with a support account the client gives you, or by reviewing the design with the client.

### Side channels: uniqueness, errors, rate limits and quotas

Small leaks across the boundary, usually Low on their own but useful for chaining and sometimes sensitive by themselves:

- **Global uniqueness.** Workspace slugs, custom domains, SSO domains and sometimes email addresses are unique across the platform. "This domain is already claimed" tells tenant A that some tenant uses `example.org` for SSO. PostgreSQL's documentation notes that unique and foreign-key checks bypass RLS, which is the database version of the same leak ([row security docs](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)).
- **Different errors.** `403 Forbidden` for another tenant's real object versus `404 Not Found` for a non-existent one turns any endpoint into an existence oracle for IDs.
- **Shared rate limits and quotas.** A rate limit keyed by IP or by a global resource (an API key prefix, an endpoint) lets one tenant exhaust another's allowance; quota counters shared across tenants reveal another tenant's activity. The cheat sheet recommends tenant-aware rate limits. Keep testing of this light: confirm the key from response headers and documentation, do not try to exhaust anything.

### Database-level isolation that does not hold

RLS and schema-per-tenant are strong when they apply, and silently absent when they do not. PostgreSQL documents the edges: superusers and roles with `BYPASSRLS` always bypass row security; the table owner normally bypasses it unless the table has `FORCE ROW LEVEL SECURITY`; a table with RLS enabled and no policy is default-deny; and a policy without `WITH CHECK` uses its `USING` expression for new rows. In practice the failures are: the application connects as the role that owns the tables (because migrations run as it); the per-request tenant is set with session-level `SET` on a pooled connection, so the next request on that connection inherits it (PgBouncer's [feature table](https://www.pgbouncer.org/features.html) lists `SET`/`RESET` as not supported in transaction pooling); a view created by the owner exposes the table without the policy (by default a view accesses its base tables, and applies their RLS policies, as the view owner; `security_invoker = true`, added in PostgreSQL 15, makes it use the querying role; see [CREATE VIEW](https://www.postgresql.org/docs/current/sql-createview.html)); and a reporting feature that runs user-influenced SQL can call `set_config` itself. In schema-per-tenant, the same pooling issue applies to `search_path`.

## Testing

Every test here assumes an **authorised** engagement (written scope and rules of engagement), a bug bounty programme whose rules allow cross-tenant testing with your own tenants, or a deliberately vulnerable lab. The requests and responses below are **illustrative**: hosts are fictional and we ran nothing against a real target for this note.

### Before you start

**Tenants and accounts.** You need two tenants you control, each with at least an administrator and a normal member. If the product has more roles (owner, billing admin, guest, viewer), add them to tenant A; tenant B mainly needs to own objects.

| Account | Tenant | Role | Used for |
|---|---|---|---|
| `a-admin@` | A | Tenant admin | Attacker with the strongest tenant role, admin endpoints |
| `a-user@` | A | Member | Attacker with an ordinary role (the realistic case) |
| `b-admin@` | B | Tenant admin | Creates and owns the target objects, controls B's settings |
| `b-user@` | B | Member | Target of user-level operations, invitation tests |
| `ab-user@` | A **and** B (or a third tenant C you control) | Member in both | Organisation switching ([GT-WEB-TEN-4](#gt-web-ten-4-organisation-switching-and-stale-tenant-context)) |

Use separate email addresses per account (a domain or plus-addressing you control), and if SSO is in scope, an IdP tenant for A that you control (a free developer tenant of the IdP, or a lab IdP such as a local Keycloak) and, ideally, a separate one for B. If the client provides the tenants, ask for them on different plans if plans change code paths (pooled versus dedicated, SSO only on enterprise).

**Seed tenant B with canaries.** As `b-admin`, create one object of every type you can find (project, document, comment, attachment, saved view, dashboard, integration, API key, webhook, export, invitation, custom field, tag) and give each a recognisable marker in a text field: `GTCANARY-B-<type>-<date>`. Record each object's ID and URL. These markers let you prove a cross-tenant read by searching responses for a string you planted, and they keep every proof on your own data.

**Burp project.** Use one Burp project per engagement, scope limited to the in-scope hosts. Log in as each account in a separate browser profile (or Burp's embedded browser with separate sessions) and capture the session cookie or bearer token for each. Then:

- **Autorize**: paste `a-user`'s cookie or `Authorization` header as the low-privileged user, browse the app as `b-admin` and `b-user`, and Autorize replays each request with `a-user`'s credentials. Headers you define there replace the original ones if present and are added otherwise, which gives you two passes for tenants: with only A's credentials defined, B's `X-Org-Id`/`X-Tenant-ID` stays in the request ("A's credentials, B's selector"); with A's `X-Org-Id` defined as well, it is replaced ("A's credentials and selector, B's object ID"). Configure an enforcement detector (a string or status that your 403/404 responses contain) so the results table is reliable.
- **AuthMatrix**: define roles per tenant (`A-admin`, `A-user`, `B-admin`, `B-user`), add one request per object type, and mark which roles should succeed. Re-run the matrix after each deployment the client makes during the test.
- **Auth Analyzer** repeats your requests for each defined session and can extract and replace parameter values per session, which helps when the tenant or a CSRF token sits in a body field or has to be picked up from responses.

**A two-session comparison helper.** For the object list you seeded, a small script that requests each of *your own* tenant-B objects with tenant-A credentials and flags any response containing B's canary is often faster than clicking. It only touches the IDs you recorded, at a low rate:

```python
#!/usr/bin/env python3
"""Replay tenant-B object URLs (created by us) with tenant-A credentials; flag canary leaks."""
import json, sys, time, requests

BASE = "https://api.example.com"
TOKENS = {
    "B-owner": "Bearer <TOKEN_B_ADMIN>",   # baseline: should succeed
    "A-user":  "Bearer <TOKEN_A_USER>",    # attacker: should fail
}
# objects.json: [{"type": "document", "method": "GET", "path": "/v1/documents/<id>", "canary": "GTCANARY-B-document-20261115"}, ...]
targets = json.load(open(sys.argv[1]))

for t in targets:
    row = [t["type"], t["method"], t["path"]]
    for who, tok in TOKENS.items():
        r = requests.request(t["method"], BASE + t["path"],
                             headers={"Authorization": tok, "Accept": "application/json"},
                             timeout=15, allow_redirects=False)
        leaked = t["canary"] in r.text
        row.append(f"{who}:{r.status_code}{'!LEAK' if leaked and who != 'B-owner' else ''}")
        time.sleep(1)                      # stay slow; this is a comparison, not a scan
    print("\t".join(row))
```

Keep `objects.json` to IDs you created. Do not feed it ranges or IDs harvested from other customers.

**Stop on real data.** If any test returns data that is not from your tenants (names, emails, documents you did not plant), stop that line of testing, keep only the minimum evidence needed to show the issue (one redacted response, the request that produced it), do not download, page through or retain more, and report it to the client or programme immediately. This happens more often in multi-tenant testing than anywhere else, because a missing tenant filter on a list endpoint returns *everyone's* rows, not just tenant B's.

**Rate and volume.** No enumeration of IDs, slugs or subdomains beyond your own objects and a small range agreed with the client. Throttle tools to a few requests per second at most, and do not run search, export or reporting tests that would pull large data sets; one page is enough to prove the filter is missing.

### GT-WEB-TEN-1: Map the tenancy model and every tenant selector

*Guler Tech methodology.* Implements the reconnaissance part of WSTG-ATHZ-02 and WSTG-APIT-02 for tenants.

#### What it checks

Where the application gets the tenant for each request (subdomain, custom domain, path, header, body, token claim, session, API key), whether more than one source is present, which isolation model the back end uses, and which object types exist. It does not produce findings by itself; it produces the test list for the others.

#### Prerequisites

All accounts from [Before you start](#before-you-start); Burp history from browsing every feature as `a-admin` and `b-admin`; API documentation, OpenAPI files, GraphQL schema or the JavaScript bundle if available.

#### Steps

1. Browse every feature as `a-admin`, then search Burp's HTTP history for tenant selectors. Useful Burp search terms: `org`, `tenant`, `workspace`, `account`, `team`, `company`, `X-Org`, `X-Tenant`, and the tenant's slug and ID.
2. Decode any bearer tokens (locally; never paste client tokens into online decoders) and note tenant claims (`org_id`, `tid`, `tenant`, namespaced custom claims). Note whether the token changes when you switch organisation.
3. Note how the tenant appears in object IDs: per-tenant sequences (`/tickets/14` in both tenants) suggest a pooled table with composite keys or separate databases; global UUIDs suggest a shared table.
4. List every object type and endpoint from the API schema or bundle. With GraphQL, if introspection is enabled in scope, export the schema with InQL and list every type that has an `id` and every query that takes one.
5. Ask the client (or read the architecture documents) for the isolation model, the data stores beyond the main database (search, cache, object storage, warehouse, queues) and how each is partitioned.
6. Build a table: endpoint → tenant source(s) read → object types touched → isolation layer.

#### Observation

Illustrative: one API call that names its tenant three ways.

```http
GET /api/v2/orgs/tenant-a/projects/9f1e2b44-0000-4000-8000-00000000a001 HTTP/2
Host: tenant-a.example.com
Authorization: Bearer <TOKEN_A_USER>
X-Org-Id: 2c71d0a6-0000-4000-8000-0000000000aa
Accept: application/json
```

#### Evaluation

Not pass/fail. Every endpoint that reads the tenant from a client-controlled source goes to [GT-WEB-TEN-3](#gt-web-ten-3-make-the-tenant-selectors-disagree); every object type goes to [GT-WEB-TEN-2](#gt-web-ten-2-swap-tenant-b-object-ids-into-tenant-a-requests). A tenant source that the web UI never sends but the server honours (found in the bundle or mobile traffic) is a priority.

#### False positives

A tenant slug in the URL used only for routing and display, with the server ignoring it and using the session's tenant, is not a selector; [GT-WEB-TEN-3](#gt-web-ten-3-make-the-tenant-selectors-disagree) will show that.

#### Automation

Burp's Logger and search, Param Miner ("Guess headers") to find tenant headers the server reacts to but the client never sends (keep the request rate low), Arjun for hidden parameters such as `org_id`. In CI, the equivalent is a route inventory that records each route's tenant source and fails the build when a new route reads a tenant from a header or body without going through the tenant resolver.

### GT-WEB-TEN-2: Swap tenant B object IDs into tenant A requests

*Guler Tech methodology.* Implements WSTG-ATHZ-04 and WSTG-APIT-02 across the tenant boundary.

#### What it checks

Whether a member of tenant A can read, modify or delete an object belonging to tenant B by putting B's object ID into a request made with A's credentials and A's tenant selector. This is the core test, repeated for every object type from [GT-WEB-TEN-1](#gt-web-ten-1-map-the-tenancy-model-and-every-tenant-selector), including the ones nobody thinks of: users, files, comments, integrations, API keys, webhooks and their delivery logs, audit log entries, invoices, saved views, exports.

#### Prerequisites

Canary objects in tenant B, their IDs, and `a-user`'s session.

#### Steps

1. As `b-admin`, capture a read request for a canary object and note the response.
2. Replay it in Repeater with `a-user`'s credentials. Keep A's tenant selector (A's subdomain, A's path segment, A's `X-Org-Id`) and change only the object ID to B's.

```http
GET /api/v2/orgs/tenant-a/documents/5d0c7a31-0000-4000-8000-00000000b001 HTTP/2
Host: tenant-a.example.com
Authorization: Bearer <TOKEN_A_USER>
X-Org-Id: 2c71d0a6-0000-4000-8000-0000000000aa
```

```bash
curl -s https://tenant-a.example.com/api/v2/orgs/tenant-a/documents/5d0c7a31-0000-4000-8000-00000000b001 \
  -H 'Authorization: Bearer <TOKEN_A_USER>' \
  -H 'X-Org-Id: 2c71d0a6-0000-4000-8000-0000000000aa' | jq '.title'
```

3. Repeat for list endpoints with filters that take IDs (`?project_id=<B's project>`), for nested routes (`/projects/<A's>/comments/<B's>`), and for every HTTP method the route supports. For writes, use **own test objects only** and the least destructive change first: a `PATCH` of B's canary's description to `GTCANARY-B-edited-by-A`, checked afterwards as `b-admin`, before you consider a `DELETE` (usually unnecessary).
4. Test references in write bodies: create an object in A that points at B's object (`{"attachment_id": "<B's file>"}`, `{"assignee_id": "<b-user's id>"}`, `{"template_id": "<B's template>"}`), then read the A object back and see whether B's data is now embedded.
5. Test the user object itself: `GET /users/<b-user's id>`, `GET /orgs/tenant-a/members/<b-user's id>`, and user search or mention endpoints with B's user names.
6. In GraphQL, request B's object through every path: `node(id:)`, the type's own query, and nested fields of A's objects that accept an ID argument.

#### Observation

Vulnerable (illustrative):

```http
HTTP/2 200 OK
Content-Type: application/json

{
  "id": "5d0c7a31-0000-4000-8000-00000000b001",
  "org_id": "8e44f1b9-0000-4000-8000-0000000000bb",
  "title": "GTCANARY-B-document-20261115",
  "body": "…"
}
```

Correct: `404 Not Found` (preferred, because it does not confirm the object exists) or `403 Forbidden`, with no B data in the body.

#### Evaluation

- **Fail:** any response with A's credentials returns B's canary, changes a B object (confirmed as `b-admin`), or stores a reference to a B object inside an A object that A can then read. One object type failing is a finding even if the others pass.
- **Pass:** every object type and method returns 404/403 (or an empty list) for B's IDs, and reference fields reject B's IDs.

#### False positives

Objects that are public by design (a published help-centre article, a public share link, a marketplace template). `200 OK` with an error body (`{"error":"not found"}`). Data that is identical because both tenants see a shared global catalogue (countries, plan names). A cached CDN response from your own earlier B session: add a cache-busting query string and check `Age`/`X-Cache` headers. And the classic: `ab-user` being in both tenants, so access is legitimate.

#### Automation

Autorize or Auth Analyzer while you browse as `b-admin`; AuthMatrix with one row per object type; the comparison helper from [Before you start](#before-you-start). In CI, write one cross-tenant test per resource (see [Cross-tenant regression tests](#cross-tenant-regression-tests)) and generate the resource list from the router, so a new resource without a test fails the build.

### GT-WEB-TEN-3: Make the tenant selectors disagree

*Guler Tech methodology.* Implements WSTG-ATHZ-02 (horizontal bypass and special header handling) for tenant selectors.

#### What it checks

Whether the tenant used for authorisation and the tenant used for data access can come from different sources, and whether a selector alone (without a matching membership) switches tenant. Covers subdomain/custom domain versus path versus header versus token claim versus session, and the `Host` and forwarding headers that decide the subdomain.

#### Prerequisites

The selector map from [GT-WEB-TEN-1](#gt-web-ten-1-map-the-tenancy-model-and-every-tenant-selector); `a-user`'s session; B's tenant ID, slug and subdomain.

#### Steps

For each endpoint, change **one** selector at a time to B's value with A's credentials, then combinations:

| Variant | Change | What a failure means |
|---|---|---|
| Header only | `X-Org-Id: <B>` | Header trusted without membership |
| Path only | `/orgs/tenant-b/…` | Path tenant not checked against membership |
| Subdomain only | `Host: tenant-b.example.com` (A's token) | Subdomain picks the tenant; the token is not tied to it |
| Path A, header B | `/orgs/tenant-a/…` + `X-Org-Id: <B>` | Check reads the path, data layer reads the header (or the reverse) |
| Body tenant | `"organizationId": "<B>"` in create/update/move | Write lands in B |
| Query and body | `?org=<A>` with `{"org": "<B>"}` | Middleware and handler parse different locations |
| Duplicates | `X-Org-Id` twice, or `org_id` in both query and body, or `org_id[]=` | Parser differences between layers |
| Forwarded host | `X-Forwarded-Host: tenant-b.example.com` | A proxy or framework resolves the tenant from a forwarding header |
| Custom domain | B's custom domain as `Host` with A's token | Custom-domain routing ignores the token's tenant |
| API key | A's API key with B's tenant in the path | The key's tenant is not enforced |

```http
GET /api/v2/projects HTTP/2
Host: tenant-a.example.com
Authorization: Bearer <TOKEN_A_USER>
X-Org-Id: 8e44f1b9-0000-4000-8000-0000000000bb
```

```bash
for h in tenant-a.example.com tenant-b.example.com; do
  printf '%s ' "$h"
  curl -s -o /dev/null -w '%{http_code}\n' "https://$h/api/v2/projects" \
    -H 'Authorization: Bearer <TOKEN_A_USER>'
done
```

Host-header and forwarding-header manipulation more broadly (routing, cache poisoning) belongs to the HTTP and infrastructure subcategory; here you only test whether it moves the tenant.

#### Observation

A failure is usually obvious: the list endpoint returns B's canaries. Subtler failures: the response is A's data but a write in the same request lands in B (check as `b-admin`), or the response contains B's name or settings in a header or banner.

#### Evaluation

- **Fail:** any single changed selector gives A's credentials access to B's data or writes into B; or two selectors with different values produce a response that mixes tenants.
- **Pass:** a selector naming a tenant you are not a member of returns 403/404 (or is ignored in favour of the bound tenant), consistently on every endpoint, and conflicting selectors are rejected.

#### False positives

A subdomain that only changes branding and login page while the API correctly uses the token's tenant. A platform-wide public endpoint (status, pricing) that ignores the tenant. A `302` redirect to B's login page is not access.

#### Automation

Autorize with A's credentials and B's selector (the first pass above); Burp Intruder with a two-item payload list (A's and B's selector) per position, sniper mode, low rate; a CI test that sends each tenant-scoped route with a foreign selector and expects 403/404.

### GT-WEB-TEN-4: Organisation switching and stale tenant context

*Guler Tech methodology.* Implements WSTG-ATHZ-02 for the tenant-switch function and stale context.

#### What it checks

Whether the organisation switcher lets you switch into a tenant you are not a member of, and whether, after a legitimate switch, any layer (token claim, session, cache, websocket, client state) still acts on the previous tenant.

#### Prerequisites

`ab-user` (member of A and C, or A and B); `a-user` (member of A only).

#### Steps

1. As `ab-user`, switch from A to B in the UI and capture the switch request (`POST /api/session/org`, `PUT /me/current_org`, a token refresh with an `org_id` parameter, or a new token request with an `organization` parameter).
2. Replay the switch request as `a-user` with B's org ID. If it succeeds, call a tenant-scoped list endpoint.
3. As `ab-user`, after switching to B, replay a request captured while in A (A's object ID, A's selector). Does it still work? It should only if you are still a member of A and the request names A explicitly.
4. As `ab-user`, switch to B and check whether the access token's tenant claim changed. If the token still says A while the session says B, send a request that relies on each.
5. Have `b-admin` remove `ab-user` from B, then, as `ab-user`, use the B context you already had (open tab, existing token, websocket) and try to switch to B again.
6. Check that roles do not carry over: give `ab-user` admin in C and member in A, switch to A, and try an admin action.

```http
POST /api/session/switch-organization HTTP/2
Host: app.example.com
Cookie: session=<SESSION_A_USER>
Content-Type: application/json

{"organizationId": "8e44f1b9-0000-4000-8000-0000000000bb"}
```

#### Observation

Vulnerable: `200 OK` with `{"currentOrganization": {"id": "8e44f1b9-…", "name": "Tenant B"} }` for `a-user`, followed by B's data on list endpoints. Also vulnerable: after removal from B, `ab-user`'s existing token still returns B's data until it expires.

#### Evaluation

- **Fail:** switching into a non-member tenant succeeds; a role from one tenant is applied in another; a removed member keeps access through an existing session, token or websocket beyond the documented, short token lifetime (and the client has not accepted that window).
- **Pass:** the switch endpoint checks membership; every request re-derives tenant and role from current membership (or the token is short-lived and re-issued on switch); removal takes effect on the next request or within an accepted window.

#### False positives

A UI that briefly shows the previous tenant's cached list after a switch but the API refuses to serve it again: report as Low/Info for client-side state, not as cross-tenant access. Tokens that stay valid for a few minutes after removal by documented design (ASVS `v5.0.0-8.3.2` at L3 asks for immediate effect or compensating controls).

#### Automation

AuthMatrix with `ab-user` before and after removal; a CI test that removes a membership and asserts the next request with the old token returns 403/404.

### GT-WEB-TEN-5: Invitations and membership lifecycle

*Guler Tech methodology.* Implements WSTG-ATHZ-02 and WSTG-ATHZ-04 for membership objects.

#### What it checks

Whether invitations and membership changes can cross tenants: inviting into a tenant you do not administer, accepting an invitation with a different identity, reusing an invite token, setting your own role, exposing another tenant's user data through invitations, and keeping access after removal.

#### Prerequisites

`a-admin`, `a-user`, `b-admin`, `b-user`; email inboxes for all of them.

#### Steps

All steps change membership, so: **own test objects only**, and record every membership change so you can revert it.

1. **Invite into another tenant.** As `a-admin`, capture the invite request. Replay it with B's org ID in the path or body (`POST /orgs/<B>/invitations`). Then try with `a-user` (non-admin) into A.
2. **Role in the invite.** Change the role in A's invite to `owner` or a platform role (`super_admin`, `staff`) and see what the invitee receives.
3. **Mismatched identity.** As `a-admin`, invite `b-user@`'s email to A. Before accepting, log in as a different account (`a-user`) and open the invite link. A correct implementation refuses because the logged-in identity's verified email does not match the invite, or makes you sign in as the invitee.
4. **Token reuse and revocation.** Accept an invite, then open the same link with another account. Revoke a pending invite as `a-admin`, then try the link.
5. **Information exposure.** Inviting `b-user@` to A: does A's admin now see B's data about the user (other memberships, B's name, B's role, profile fields that B's admin set)?
6. **Join by domain.** If "anyone with an `@example.org` email can join", check that the domain was verified by the tenant and that the joining email is verified ([GT-WEB-TEN-10](#gt-web-ten-10-sso-and-identity-provider-tenant-binding) covers SSO domains).
7. **Removal.** `b-admin` removes `b-user` from B. As `b-user`, with the session, refresh token and any API key or personal access token they created while a member, call B's endpoints.

```http
POST /api/v2/invitations/accept HTTP/2
Host: app.example.com
Cookie: session=<SESSION_A_USER>
Content-Type: application/json

{"token": "<INVITE_TOKEN_FOR_B_USER_EMAIL>"}
```

#### Observation

Vulnerable: `a-user` (logged in) accepts an invite addressed to `b-user@` and becomes a member of A with the invited role; or the invite endpoint creates a pending membership in B when called by `a-admin`. After removal, `b-user`'s personal access token still lists B's projects.

#### Evaluation

- **Fail:** an admin of A can create memberships or invitations in B; an invite can be accepted by an identity other than the invited one without an explicit, documented "anyone with the link" design; tokens are reusable after use or revocation; the inviter can choose a role above their own; removed members keep access through any credential.
- **Pass:** invitation creation is scoped to the bound tenant and the inviter's role; acceptance binds to the invited, verified email; tokens are single-use and expire; removal revokes sessions, tokens and member-owned keys (or the keys are owned by the tenant and survive by design, which you note).

#### False positives

"Invite links" that are deliberately shareable (Slack-style join links), with the risk documented and the link revocable. API keys that belong to the tenant rather than the user, which correctly survive the user's removal. An email-mismatch acceptance that is blocked later by a verification step you had not reached.

#### Automation

Mostly manual. A CI test suite should include: invite into another tenant (expect 403/404), accept with a mismatched user (expect 403), reuse a token (expect 410/400), remove a member and call with their old credentials (expect 401/403).

### GT-WEB-TEN-6: Tenant admin versus platform admin

*Guler Tech methodology.* Implements WSTG-ATHZ-02 (access to administrative functions) and WSTG-APIT-04 across tenants.

#### What it checks

Whether tenant-admin functions are bound to the admin's own tenant (user management, role changes, SSO settings, integrations, billing, data retention, audit log export), and whether platform-level functions are unreachable with a tenant-admin role.

#### Prerequisites

`a-admin`, `b-admin`; a list of admin endpoints (from the UI, bundle, API docs, and any `/admin`, `/internal`, `/staff`, `/support` paths found during recon).

#### Steps

1. As `a-admin`, replay `b-admin`'s admin requests with B's IDs: change `b-user`'s role, deactivate `b-user`, read B's SSO configuration, list B's API keys, export B's audit log, change B's billing contact. Use **own test objects only**, read requests first, and the least destructive write (role change on `b-user`, reverted by `b-admin`).
2. User-management endpoints that take a global user ID: `PATCH /admin/users/<b-user's id>` with A's selector.
3. Platform functions: try `/admin/tenants`, `/internal/feature-flags`, plan changes (`PATCH /orgs/<A>/plan` with `{"plan":"enterprise"}`), tenant creation and deletion, as `a-admin`. Role names are a hint: if the API returns `"role": "admin"` both for tenant admins and for staff, test what a tenant admin's token can do on staff endpoints.
4. Role self-assignment across levels: in A's member update, set your role to a platform role (`"role": "super_admin"`, `"is_staff": true`). Field-level aspects of this are in [mass assignment and BOPLA](/web/web-mass-assignment-bopla/); vertical escalation in general is in [vertical escalation and BFLA](/web/web-vertical-privilege-escalation-bfla/).

#### Observation

Vulnerable (illustrative): `a-admin` sends `PATCH /api/v2/orgs/8e44f1b9-…/members/<b-user's id>` with `{"role":"viewer"}` and gets `200 OK`; `b-admin` sees `b-user` downgraded.

#### Evaluation

- **Fail:** any tenant-admin function works on another tenant; any platform function works with a tenant-admin or member role.
- **Pass:** all admin functions resolve the tenant from the bound context and verify the target belongs to it; platform functions require a separate staff identity, ideally on a separate host or audience.

#### False positives

Partner or reseller models where one tenant legitimately administers child tenants: confirm the relationship and test that the parent can only reach *its* children.

#### Automation

AuthMatrix with roles `A-admin` and `B-admin` across every admin endpoint; CI tests that call each admin route with a foreign tenant's admin and expect 403/404.

### GT-WEB-TEN-7: Search, reporting, exports and caches

*Guler Tech methodology.* Implements WSTG-ATHZ-04 and WSTG-APIT-02 (bulk object access) for aggregating features.

#### What it checks

Whether search, autocomplete, mentions, dashboards, analytics, embedded reports, exports and cached responses are filtered by the bound tenant on the server, and whether any cache can serve one tenant's response to another.

#### Prerequisites

B's canaries (with distinctive words to search for); `a-user` and `a-admin` sessions.

#### Steps

1. **Search.** As `a-user`, search for `GTCANARY-B`. Then inspect the search request: if the client sends a filter (`"filters": "org_id:2c71…"`, `"tenant": "…"`, an Algolia or Typesense search key with embedded restrictions), remove or change it to B's value. Try autocomplete, mention (`@b-user`), "recent items", "related items" and AI assistants that search ("summarise documents about GTCANARY-B").
2. **Reports.** Change the tenant or object filters in dashboard and report requests to B's IDs. For embedded BI, check whether the embed URL or token carries the tenant as a parameter you can change.
3. **Exports.** As `a-admin`, start an export and capture the request and the download URL. Replay the start request with B's tenant or B's project ID; download B's export (created by `b-admin`) with A's session; check whether the export file key is guessable.
4. **Caches.** Request a tenant-dependent endpoint as `b-admin` (for example `/api/v2/org/settings`), then immediately request the same URL as `a-user`. Repeat with a header-selected tenant (same path, different `X-Org-Id`). Watch `Age`, `X-Cache`, `CF-Cache-Status`, `Vary` and `Cache-Control`. If tenants share numeric user IDs, repeat with the same numeric ID in both tenants.
5. **GraphQL batching.** One query with aliases for search across types, to check that every resolver applies the tenant.

```http
POST /search/v1/indexes/documents/query HTTP/2
Host: api.example.com
X-Search-Api-Key: <SEARCH_KEY_FROM_A_SESSION>
Content-Type: application/json

{"query": "GTCANARY-B", "filters": ""}
```

#### Observation

Vulnerable: search results or autocomplete entries include B's canary titles; an export started for A contains B rows; the second request in step 4 is a cache hit (`Age: 3`, `X-Cache: HIT`) returning B's settings.

#### Evaluation

- **Fail:** any aggregating feature returns B's data (even titles, counts or snippets) to A; a cache serves B's tenant-specific response to A; a search key from A's session can be used with a different or empty tenant filter.
- **Pass:** results are tenant-filtered server-side (or the search key is scoped per tenant and cannot be widened); exports are bound to the tenant and requester; tenant-specific responses are `Cache-Control: private`/`no-store` or cached with the tenant in the key.

#### False positives

Global content in search (help articles, public templates). Analytics that are deliberately platform-wide benchmarks ("teams like yours"), if anonymised and aggregated: check with the client. Cache hits on static assets.

#### Automation

Search with Autorize running; a CI test that indexes a canary in tenant B and asserts that tenant A's search and autocomplete return nothing; cache-key unit tests that assert the tenant is part of every key for tenant-scoped values.

### GT-WEB-TEN-8: File and object storage paths

*Guler Tech methodology.* Implements WSTG-ATHZ-04 (file system resources) across tenants.

#### What it checks

Whether files belonging to B (attachments, avatars, exports, imports, generated PDFs) can be fetched, listed, overwritten or deleted with A's session, and whether storage keys and pre-signed URLs carry a tenant check.

#### Prerequisites

Files uploaded by `b-admin` with canary content; A's session.

#### Steps

1. As `b-admin`, upload a file and capture the upload and download flow: is the key server-generated? Does the download go through the app (`/files/<id>/download`) or straight to storage (pre-signed URL, public URL, CDN)?
2. As `a-user`, request B's file through the app route with B's file ID, and with A's tenant in the path.
3. If the app builds keys from parameters (`?path=tenants/<tenant>/files/<name>`), change the tenant segment to B's. Traversal-style manipulation of the path (`../`) is covered in WSTG-ATHZ-01; here change only the tenant segment.
4. Check pre-signed URL lifetime and whether the app issues them for B's file IDs to A.
5. Uploads: as `a-user`, upload with a key or folder parameter set to B's prefix (**own test objects only**; use a new file name so you do not overwrite anything).
6. If the bucket name and prefix are visible, check whether unauthenticated listing works (only for buckets in scope, one request).

#### Observation

Vulnerable: `GET /api/v2/files/<B's file id>/download` as `a-user` returns `302` to a pre-signed URL for `tenants/8e44f1b9-…/files/…`; or a key parameter changed to B's prefix returns B's file.

#### Evaluation

- **Fail:** A can read, list or write any object under B's prefix by any route; pre-signed URLs are issued for B's files to A.
- **Pass:** the app resolves the key from the file record after a tenant-scoped lookup; storage keys are not client-controlled; URLs are short-lived and issued only after the check.

#### False positives

Files deliberately shared publicly (a public link that B created). Avatars served from a public CDN by design, which you may note as a privacy observation rather than tenant breakout.

#### Automation

Autorize on download routes; CI tests that upload to B and fetch with A; storage policy checks per [S3 security](/cloud/aws-s3-security/) when the client is on AWS.

### GT-WEB-TEN-9: Background jobs, integrations and webhooks

*Guler Tech methodology.* Implements WSTG-ATHZ-04 for asynchronous operations; the wider async model is in the [revocation, sharing and async note](/web/web-access-control-revocation-sharing-async/).

#### What it checks

Whether work that runs outside the request (imports, exports, scheduled reports, notifications, webhooks, integration syncs, AI jobs) keeps the tenant of the user who triggered it, and whether job, integration and webhook objects are scoped like everything else.

#### Prerequisites

A's and B's admin sessions; a webhook receiver you run yourself, so that deliveries (which contain only your tenants' test data) do not go to a third-party service.

#### Steps

1. **Job parameters.** Start an import, export or report job as `a-admin` and look for IDs in the request (`project_id`, `org_id`, `report_id`). Replay with B's IDs. Check the job status endpoint (`/jobs/<id>`) with B's job IDs.
2. **Integrations.** Create an automation in A that uses B's integration ID (`"integration_id": "<B's Slack/GitHub connection>"`). If accepted, the job may act with B's OAuth token.
3. **Webhooks.** As `a-admin`, create a webhook with B's event source or B's project ID; read B's webhook delivery logs (`/webhooks/<B's id>/deliveries`), which often contain full payloads.
4. **Notifications.** Mention `b-user` from A, assign A's task to `b-user`: does B's user receive A's data (data leaving the tenant) or does A learn about B's user?
5. **Scheduled work.** Ask the client how workers set the tenant (message attribute, job argument, thread-local) and whether the consumer re-checks membership. This is usually a design review item.

#### Observation

Vulnerable: `POST /api/v2/exports` with `{"project_id": "<B's project>"}` as `a-admin` returns a job whose output contains B's canaries; `GET /webhooks/<B's id>/deliveries` returns B's payloads.

#### Evaluation

- **Fail:** any job, integration, webhook or delivery log can be created for, read from or bound to B by A.
- **Pass:** job inputs are validated against the bound tenant at enqueue time, the tenant travels with the job, and the worker re-checks it before reading data.

#### False positives

Jobs that accept B's ID but fail at the worker with a tenant check (the request returned `202 Accepted` but the job failed): confirm the job's result, not the enqueue response. Note it as hardening if the job status leaks B's metadata.

#### Automation

CI tests at the service layer: enqueue a job with a foreign tenant's object ID and assert it is rejected before enqueueing; worker unit tests that assert the job refuses to run without a tenant.

### GT-WEB-TEN-10: SSO and identity provider tenant binding

*Guler Tech methodology.* Implements WSTG-ATHZ-02 and the issuer-confusion check in WSTG-SESS-10, for federated sign-in.

#### What it checks

Whether an IdP configured for tenant A can sign in users of tenant B; whether SSO and auto-join domains must be verified; whether JIT provisioning puts users into the IdP's own tenant only; and, for multi-tenant OIDC apps (Microsoft Entra ID "accounts in any organizational directory", Google, other multi-tenant IdPs), whether the application validates the issuer and tenant claims.

#### Prerequisites

An IdP you control configured as tenant A's SSO (SAML or OIDC); `b-user@` exists in tenant B with a known email; for Entra tests, a separate Entra tenant you control. Do this only with tenants and IdPs you own; never assert identities of real users.

#### Steps

1. **Cross-tenant assertion.** In your IdP for A, create a user whose email (or NameID, or `email` claim) is `b-user@`'s address. Sign in through A's SSO. A correct application either rejects the login (the user is not in A's directory) or creates a *new*, separate identity in A; it must never log you in as tenant B's `b-user`.
2. **SSO entry points.** Many apps start SSO from an email-first page that looks up the tenant by email domain. Start SSO for `b-user@`'s email but complete it with A's IdP (alter `RelayState`, the `tenant` parameter or the ACS URL path if it contains the tenant).
3. **Domain claims.** As `a-admin`, try to claim B's domain for SSO enforcement or auto-join (`example.org` used by your B accounts). If the app requires DNS or email verification, check that the verification is per tenant and cannot be satisfied by a domain verified in another tenant.
4. **JIT provisioning.** Sign in through A's IdP with a `RelayState` or query parameter naming tenant B. Check where the new user lands.
5. **Multi-tenant OIDC.** If the app offers "Sign in with Microsoft" for any organisation, sign in with a user from your own separate Entra tenant that is not a customer of the app. Then check whether the app maps that login to an existing account by `email` or `preferred_username`. Set the email attribute of your Entra test user to `b-user@`'s address (an attribute you can change in a tenant you administer) and see whether you are logged in as `b-user`. This is the nOAuth pattern.
6. **Token replay.** Take an access token that the app's IdP issued for tenant A (or for another application using the same IdP) and send it to an API that should only serve tenant B or another audience.

#### Observation

Vulnerable: after step 1, the app greets you as `b-user` with tenant B's workspace. After step 5, an unrelated Entra tenant's user is logged in to an existing account because the email matched.

#### Evaluation

- **Fail:** any IdP can authenticate users outside its own tenant; domain claims work without verification or across tenants; JIT provisioning follows a client-supplied tenant; a multi-tenant OIDC app accepts tokens from arbitrary issuers or keys accounts by mutable claims (`email`, `preferred_username`, `upn`).
- **Pass:** each IdP configuration is bound to one tenant, users are keyed by (IdP, subject) as ASVS `v5.0.0-6.8.1` describes, and for Entra by (`tid`, `oid`) or (`tid`, `sub`); the issuer is checked exactly (with `{tenantid}` substituted from `tid` for tenant-independent metadata); only allowed tenants are admitted; domains are verified.

#### False positives

A login with a matching email that creates a *new* account in A (no access to B) is correct behaviour, though it may confuse users. "Account linking" that requires the existing B user to confirm (log in with their own credentials) is not a takeover.

#### Automation

Mostly manual. In CI, unit-test the token validator with tokens from a foreign issuer, a foreign `tid`, a mismatched `iss`/`tid` pair and an unexpected audience; test the SAML handler with an assertion from tenant A's IdP for an email that exists only in B.

### GT-WEB-TEN-11: Support and impersonation consoles

*Guler Tech methodology.* Implements WSTG-ATHZ-02 (access to administrative functions) for the vendor's own cross-tenant tooling.

#### What it checks

Whether support, impersonation and internal admin functions are unreachable for customers, limited for staff, and visible to tenants.

#### Prerequisites

Ideally a support or staff account provided by the client (scoped to your test tenants), and the client's description of the impersonation process. Without it, you can test only reachability.

#### Steps

1. **Reachability.** From recon, list internal hosts and paths (`admin.example.com`, `/support`, `/staff`, `/internal`, `/impersonate`, `/sudo`). Request them with `a-admin`'s session and anonymously. Test the bypass techniques from [authorization bypass techniques](/web/web-authorization-bypass-techniques/) only within the rules of engagement.
2. **Impersonation scope.** With the support account, impersonate `a-user`. What can the impersonated session do? Password and MFA changes, API key creation, data export and billing changes should be blocked or require extra approval.
3. **Consent and audit.** Does tenant A see the impersonation in its audit log? Can staff impersonate users of a tenant that has not granted support access (if the product offers that setting, try with B where you have not granted it)?
4. **Token handling.** Is the impersonation session short-lived, tied to the staff identity, and ended when the staff session ends? Can the impersonation token be replayed from another browser?

#### Observation

Vulnerable: `GET https://admin.example.com/api/tenants` returns `200 OK` with `a-admin`'s cookie; or an impersonated session can create a personal access token that keeps working after the support session ends.

#### Evaluation

- **Fail:** any customer session reaches internal functions; impersonation is unrestricted (any tenant, any action) or invisible to the tenant; impersonation artefacts outlive the support session.
- **Pass:** internal tools use a separate identity, audience and host; impersonation is scoped, consented or ticket-bound, limited in actions, time-boxed and logged in the tenant's audit trail.

#### False positives

Internal hosts that respond with a login page or SSO redirect only. A support role that can *see* all tenants' metadata by design (tenant name, plan) but not their data.

#### Automation

Unauthenticated and customer-session checks of internal routes in CI; for the rest, a design review checklist.

### GT-WEB-TEN-12: Cross-tenant side channels

*Guler Tech methodology.* Implements WSTG-ATHZ-04 (existence disclosure) and the business-logic angle of WSTG-ATHZ-02; keep it light.

#### What it checks

Whether tenant A can learn about tenant B (existence of objects, users, domains, activity) through uniqueness checks, different error codes, rate limits or quotas, without reading B's data directly.

#### Prerequisites

B's IDs, slug, custom domain and SSO domain; A's sessions.

#### Steps

1. **404 versus 403.** Request B's real object ID and a random non-existent ID with A's session. Different status codes or bodies are an existence oracle.
2. **Uniqueness.** As `a-admin`, try to create a slug, custom domain, SSO domain, integration name or member email that B already uses. Note the error text.
3. **Invites.** Invite `b-user@` to A: does the response reveal that the address already belongs to another tenant, or B's name?
4. **Rate limits and quotas.** Read `RateLimit-*`/`X-RateLimit-*` headers on A and B: do they move together (a shared counter)? Do not try to exhaust the limit; a handful of requests from each tenant is enough to see whether the remaining count is shared.

#### Observation

Illustrative: `GET /documents/<B's id>` → `403 {"error":"forbidden"}`; `GET /documents/<random id>` → `404 {"error":"not found"}`. Creating custom domain `docs.example.org` → `409 "Domain already in use by Tenant B Ltd"`.

#### Evaluation

- **Fail (Low, sometimes Medium):** responses distinguish B's existing objects from non-existent ones; uniqueness errors reveal another tenant's name or details; rate-limit counters are shared so one tenant's usage is visible to or can exhaust another's.
- **Pass:** uniform 404 for objects outside the bound tenant; uniqueness errors that say only "unavailable"; tenant-keyed rate limits.

#### False positives

Uniqueness that is inherent (a custom domain can only map to one tenant): the existence leak is unavoidable, only the detail in the error is a finding. Global rate limits that protect the platform and are documented.

#### Automation

A CI test asserting identical status and body for "other tenant's object" and "no such object" on every route.

## Secure implementation

### Design rules

1. **Resolve the tenant once, from a trusted source, and bind it.** Authenticate first. Then take the selector (path, subdomain, header or token claim, ideally exactly one per API), confirm an active membership for the caller in that tenant, and bind `{tenant, membership, role}` to an immutable request context. Reject requests where two selectors disagree. Everything downstream reads the bound context, never the request.
2. **Make the data layer tenant-scoped by default.** Repositories, managers or global scopes add the tenant to every read and stamp it on every insert. The unscoped path exists, is named something obvious (`all_tenants`, `withoutTenantScope`) and is rare enough to review every use.
3. **Fail closed.** No bound tenant means no rows and no writes, not "all tenants". This matters for background jobs, management commands and scripts.
4. **Enforce same-tenant references in the schema.** Put the tenant in foreign keys (`FOREIGN KEY (org_id, document_id) REFERENCES documents (org_id, id)`, with a unique constraint on `(org_id, id)` in the parent) so a row in A cannot point at a row in B even if the application forgets to check.
5. **Return 404 for objects outside the tenant**, the same response as for a non-existent ID.
6. **Keep the tenant on everything that leaves the request**: cache keys, search queries, storage keys, job payloads, log lines, metrics labels, outbound webhooks.
7. **Separate platform administration** (different identity, audience, ideally host) from tenant administration, and make impersonation scoped, time-boxed, consented where possible and visible in the tenant's audit log.
8. **Bind every IdP configuration to one tenant**, key federated users by (IdP, subject), verify domains before using them for routing or auto-join, and validate issuer and tenant claims exactly.
9. **Add a database backstop** (RLS or schema/database separation) for the most sensitive tables, and test it, rather than relying on it alone.

### Node.js: Express with Prisma

Bind the tenant after authentication, using `AsyncLocalStorage` so that the data layer can read it without passing it through every call:

```javascript
// tenant.js
const { AsyncLocalStorage } = require('node:async_hooks');
const { prisma } = require('./db');            // the base PrismaClient

const tenantStore = new AsyncLocalStorage();

// Mounted on tenant routes after authenticate(), which sets req.user from a verified session or token.
async function bindTenant(req, res, next) {
  const fromPath = req.params.orgId;
  const fromHeader = req.get('X-Org-Id');
  if (fromPath && fromHeader && fromPath !== fromHeader) {
    return res.status(400).json({ error: 'conflicting organisation selectors' });
  }
  const selector = fromPath || fromHeader;     // a request to act in this tenant, not proof
  if (!selector) return res.status(400).json({ error: 'organisation required' });

  const membership = await prisma.membership.findFirst({
    where: { userId: req.user.id, orgId: selector, status: 'ACTIVE' },
    select: { orgId: true, role: true },
  });
  if (!membership) return res.status(404).json({ error: 'not found' });

  const ctx = Object.freeze({ orgId: membership.orgId, role: membership.role, userId: req.user.id });
  req.tenant = ctx;
  tenantStore.run(ctx, () => next());
}

module.exports = { tenantStore, bindTenant };
```

Then a Prisma Client query extension adds the tenant to every operation on tenant-owned models and refuses to run without one. Prisma documents `$allModels` / `$allOperations` query extensions ([docs](https://www.prisma.io/docs/orm/prisma-client/client-extensions/query)):

```javascript
// db-scoped.js
const { prisma } = require('./db');
const { tenantStore } = require('./tenant');

const TENANT_MODELS = new Set(['Project', 'Document', 'Comment', 'File', 'ApiKey', 'Webhook', 'AuditLog']);
const WHERE_OPS = new Set([
  'findUnique', 'findUniqueOrThrow', 'findFirst', 'findFirstOrThrow', 'findMany',
  'count', 'aggregate', 'groupBy', 'update', 'updateMany', 'delete', 'deleteMany', 'upsert',
]);

const db = prisma.$extends({
  query: {
    $allModels: {
      async $allOperations({ model, operation, args, query }) {
        if (!TENANT_MODELS.has(model)) return query(args);
        const orgId = tenantStore.getStore()?.orgId;
        if (!orgId) throw new Error(`no tenant bound for ${model}.${operation}`);   // fail closed

        if (WHERE_OPS.has(operation)) args.where = { ...args.where, orgId };
        if (operation === 'create') args.data = { ...args.data, orgId };
        if (operation === 'createMany') args.data = [].concat(args.data).map((d) => ({ ...d, orgId }));
        if (operation === 'upsert') args.create = { ...args.create, orgId };

        const changes = operation === 'upsert' ? args.update : args.data;
        if (['update', 'updateMany', 'upsert'].includes(operation) && changes && 'orgId' in changes) {
          throw new Error('orgId cannot be changed');
        }
        return query(args);
      },
    },
  },
});

module.exports = { db };
```

```javascript
// routes.js
const express = require('express');
const { db } = require('./db-scoped');
const { bindTenant } = require('./tenant');

const app = express();
const orgRouter = express.Router();

app.use('/api/v2/orgs/:orgId', authenticate, bindTenant, orgRouter);

orgRouter.get('/documents/:id', async (req, res) => {
  const doc = await db.document.findFirst({ where: { id: req.params.id } });   // orgId added by the extension
  if (!doc) return res.status(404).json({ error: 'not found' });
  res.json(doc);
});

orgRouter.post('/documents/:id/attachments', async (req, res) => {
  // The referenced file must be in the same tenant: look it up through the scoped client.
  const file = await db.file.findFirst({ where: { id: req.body.fileId } });
  if (!file) return res.status(404).json({ error: 'not found' });
  // ... create the attachment; the composite foreign key (org_id, file_id) is the backstop
});
```

Pitfalls: adding a non-unique field (`orgId`) to a `findUnique`/`update` `where` needs Prisma 5 or later (or the older `extendedWhereUnique` preview); nested writes (`connect: { id }`) and relation filters are not rewritten by the extension, so validate referenced IDs as above; newer operations (`createManyAndReturn`, `updateManyAndReturn` in recent versions) need adding to the lists; `$queryRaw` and `$executeRaw` run through `$allOperations` with `model` undefined, so they pass through unscoped and should be banned on tenant tables or wrapped in RLS ([below](#postgresql-row-level-security-as-a-backstop)). In Express 5, a rejected promise from async middleware reaches the error handler automatically; in Express 4, wrap `bindTenant` so a database error does not hang the request.

### Django and Django REST framework

In DRF, authentication happens inside the view, so bind the tenant in the view's `initial()` (after authentication and permission checks), and derive every queryset from it:

```python
# tenancy/views.py
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated

from .models import Membership


class OrgScopedViewSet(viewsets.ModelViewSet):
    """Base class for every /api/v2/orgs/<org_slug>/... endpoint."""
    permission_classes = [IsAuthenticated]
    model = None  # set by subclasses

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)          # authentication, permissions, throttling
        membership = (Membership.objects.select_related("org")
                      .filter(user=request.user, org__slug=kwargs["org_slug"], is_active=True)
                      .first())
        if membership is None:
            raise NotFound()                                # same as a missing object
        request.org, request.membership = membership.org, membership

    def get_queryset(self):
        return self.model.all_tenants.filter(org=self.request.org)

    def perform_create(self, serializer):
        serializer.save(org=self.request.org)               # never from the request body
```

Validate references in serializers against the same tenant. DRF's related fields call `get_queryset()` per request, so a small subclass scopes every `PrimaryKeyRelatedField`:

```python
# tenancy/serializers.py
from rest_framework import serializers


class OrgScopedPrimaryKeyRelatedField(serializers.PrimaryKeyRelatedField):
    def get_queryset(self):
        return super().get_queryset().filter(org=self.context["request"].org)


class AttachmentSerializer(serializers.ModelSerializer):
    file = OrgScopedPrimaryKeyRelatedField(queryset=File.all_tenants.all())

    class Meta:
        model = Attachment
        fields = ["id", "file", "note"]
        read_only_fields = ["id"]      # org is set in perform_create, not a field at all
```

For code outside views (Celery tasks, management commands, signals), a fail-closed default manager reads the tenant from a `contextvars.ContextVar` that the task sets explicitly:

```python
# tenancy/models.py
import contextvars
from contextlib import contextmanager
from django.db import models

current_org_id = contextvars.ContextVar("current_org_id", default=None)


@contextmanager
def tenant_bound(org_id):
    token = current_org_id.set(org_id)
    try:
        yield
    finally:
        current_org_id.reset(token)


class TenantManager(models.Manager):
    def get_queryset(self):
        org_id = current_org_id.get()
        qs = super().get_queryset()
        return qs.filter(org_id=org_id) if org_id is not None else qs.none()   # fail closed


class TenantModel(models.Model):
    org = models.ForeignKey("tenancy.Organisation", on_delete=models.CASCADE, editable=False)

    objects = TenantManager()          # first manager declared = default manager
    all_tenants = models.Manager()     # explicit, greppable escape hatch

    class Meta:
        abstract = True
```

Set `current_org_id` in tasks and commands with `tenant_bound()`. If you also set it in `initial()` so that `objects` works inside views, reset it when the response is finalised: under WSGI, threads are reused between requests and a value left in the context carries over. Django caveats, from the [managers documentation](https://docs.djangoproject.com/en/5.2/topics/db/managers/): following a foreign key (`comment.document`) uses the model's base manager, not your filtered default manager, so a stored cross-tenant reference is followed without a tenant check; and you should not filter in a base manager. That is why reference validation (and composite foreign keys) matters more than the manager. For schema-per-tenant, [django-tenants](https://django-tenants.readthedocs.io/en/latest/) uses `TenantMainMiddleware` to pick the schema from the request's domain; test that the domain-to-tenant mapping cannot be influenced (forwarded host headers, unverified custom domains) and that `SHARED_APPS` hold no tenant data.

### Spring Security with Hibernate 6

Bind the tenant in a filter that runs after bearer-token authentication, from the validated token and a membership lookup:

```java
public record BoundTenant(String orgId, String role) {}

public final class TenantContext {
    private static final ThreadLocal<BoundTenant> CURRENT = new ThreadLocal<>();
    private TenantContext() {}
    static void set(BoundTenant tenant) { CURRENT.set(tenant); }
    public static BoundTenant get() { return CURRENT.get(); }
    static void clear() { CURRENT.remove(); }
}

public class TenantBindingFilter extends OncePerRequestFilter {
    private final MembershipRepository memberships;

    public TenantBindingFilter(MembershipRepository memberships) { this.memberships = memberships; }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String selector = request.getHeader("X-Org-Id");
        if (selector == null || !(auth instanceof JwtAuthenticationToken jwtAuth)) {
            chain.doFilter(request, response);       // tenant routes then fail closed (see resolver)
            return;
        }
        Jwt jwt = jwtAuth.getToken();
        Optional<Membership> m = memberships.findActive(jwt.getClaimAsString("iss"), jwt.getSubject(), selector);
        if (m.isEmpty()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        try {
            TenantContext.set(new BoundTenant(m.get().getOrgId(), m.get().getRole()));
            chain.doFilter(request, response);
        } finally {
            TenantContext.clear();                   // threads are pooled: always clear
        }
    }
}

// In the SecurityFilterChain bean:
// http.addFilterAfter(new TenantBindingFilter(memberships), BearerTokenAuthenticationFilter.class);
```

Hibernate 6 supports discriminator-based multitenancy with `@TenantId`: the field is populated automatically on persist, and Hibernate takes the current tenant from a `CurrentTenantIdentifierResolver` configured with `hibernate.tenant_identifier_resolver` ([user guide, multitenancy](https://docs.hibernate.org/orm/6.6/userguide/html_single/Hibernate_User_Guide.html)):

```java
@Entity
public class Document {
    @Id @GeneratedValue
    private Long id;

    @TenantId
    @Column(name = "org_id", nullable = false, updatable = false)
    private String orgId;

    private String title;
    // ...
}

@Component
public class OrgTenantResolver implements CurrentTenantIdentifierResolver<String>, HibernatePropertiesCustomizer {
    static final String NO_TENANT = "00000000-0000-0000-0000-000000000000";   // matches no rows

    @Override
    public String resolveCurrentTenantIdentifier() {
        BoundTenant t = TenantContext.get();
        return t != null ? t.orgId() : NO_TENANT;   // fail closed; inserts also fail the FK to organisations
    }

    @Override
    public boolean validateExistingCurrentSessions() { return true; }

    @Override
    public boolean isRoot(String tenantId) { return false; }   // no "sees all partitions" tenant here

    @Override
    public void customize(Map<String, Object> hibernateProperties) {
        hibernateProperties.put("hibernate.tenant_identifier_resolver", this);
    }
}
```

Function-level checks use the bound membership through method security and a small bean of your own:

```java
@Component("tenantAccess")
public class TenantAccess {
    public boolean hasRole(String role) {
        BoundTenant t = TenantContext.get();
        return t != null && t.role().equals(role);
    }
}

@PreAuthorize("@tenantAccess.hasRole('ADMIN')")
@PatchMapping("/api/v2/members/{memberId}")
public MemberDto updateMember(@PathVariable Long memberId, @RequestBody UpdateMemberRequest body) {
    Member member = members.findById(memberId)                       // tenant-filtered (test it)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    return MemberDto.from(memberService.update(member, body));
}
```

Pitfalls: `isRoot` returning `true` gives that tenant access to all partitions, so never derive it from request data. If you use the older `@FilterDef`/`@Filter` approach instead of `@TenantId`, the guide states that filters apply to entity queries but not to direct fetching (`find()` by ID) unless `applyToLoadByKey = true`; write a test that `find()` of a tenant-B ID returns nothing while tenant A is bound, whichever mechanism you use. Native SQL queries are outside both mechanisms. `ThreadLocal` context does not follow `@Async` methods, `CompletableFuture` pools or message listeners: pass the tenant explicitly and set it in the worker. For multiple IdPs, Spring Security's `JwtIssuerAuthenticationManagerResolver.fromTrustedIssuers(...)` selects the decoder by `iss` from a fixed allow-list; its documentation warns that building a decoder for any presented issuer is unsafe ([multitenancy](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/multitenancy.html)). The membership lookup above keys users by issuer and subject for the same reason.

### Laravel

A scoped container binding holds the current organisation for the request (and is reset between queue jobs and Octane requests), a middleware fills it after checking membership, and a global scope plus a model trait apply it ([global scopes](https://laravel.com/docs/12.x/eloquent#global-scopes)):

```php
<?php
// app/Support/CurrentOrganisation.php
namespace App\Support;

final class CurrentOrganisation
{
    private ?int $id = null;

    public function set(int $id): void
    {
        if ($this->id !== null && $this->id !== $id) {
            throw new \LogicException('Tenant already bound for this request');
        }
        $this->id = $id;
    }

    public function id(): ?int
    {
        return $this->id;
    }
}

// AppServiceProvider::register():
// $this->app->scoped(CurrentOrganisation::class);
```

```php
<?php
// app/Http/Middleware/BindOrganisation.php
namespace App\Http\Middleware;

use App\Support\CurrentOrganisation;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class BindOrganisation
{
    public function __construct(private CurrentOrganisation $current) {}

    public function handle(Request $request, Closure $next): Response
    {
        // Routes look like /orgs/{organisationId}/documents/{document}
        $membership = $request->user()
            ->memberships()
            ->where('organisation_id', $request->route('organisationId'))
            ->where('active', true)
            ->first();

        abort_if($membership === null, 404);

        $this->current->set($membership->organisation_id);
        $request->attributes->set('membership', $membership);

        return $next($request);
    }
}
```

```php
<?php
// app/Models/Scopes/OrganisationScope.php
namespace App\Models\Scopes;

use App\Support\CurrentOrganisation;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;

class OrganisationScope implements Scope
{
    public function apply(Builder $builder, Model $model): void
    {
        $orgId = app(CurrentOrganisation::class)->id();
        if ($orgId === null) {
            $builder->whereRaw('1 = 0');          // fail closed
            return;
        }
        $builder->where($model->qualifyColumn('organisation_id'), $orgId);
    }
}

// app/Models/Concerns/BelongsToOrganisation.php
namespace App\Models\Concerns;

use App\Models\Scopes\OrganisationScope;
use App\Support\CurrentOrganisation;
use Illuminate\Database\Eloquent\Model;

trait BelongsToOrganisation
{
    public static function bootBelongsToOrganisation(): void
    {
        static::addGlobalScope(new OrganisationScope);

        static::creating(function (Model $model) {
            $orgId = app(CurrentOrganisation::class)->id() ?? throw new \LogicException('No tenant bound');
            if ($model->organisation_id !== null && (int) $model->organisation_id !== $orgId) {
                throw new \LogicException('Cross-tenant create');
            }
            $model->organisation_id = $orgId;
        });

        static::updating(function (Model $model) {
            if ($model->isDirty('organisation_id')) {
                throw new \LogicException('organisation_id cannot change');
            }
        });
    }
}
```

Validate referenced IDs against the tenant in form requests:

```php
use Illuminate\Validation\Rule;

public function rules(): array
{
    $orgId = app(\App\Support\CurrentOrganisation::class)->id();

    return [
        'file_id' => ['required', Rule::exists('files', 'id')->where('organisation_id', $orgId)],
    ];
}
```

Pitfalls: global scopes apply to Eloquent queries only, so `DB::table()` and raw queries bypass them; `withoutGlobalScope(s)` removes them, so treat every call as a review item; run `BindOrganisation` before `SubstituteBindings` in the middleware priority, otherwise route-model binding resolves `{document}` before a tenant is bound (with the fail-closed scope that is a 404, not a leak, but it breaks the feature); use `Route::scopeBindings()` on nested routes so a child is resolved through its parent; keep `organisation_id` out of `$fillable`. Policies (`Gate`/`Policy` classes) handle role checks within the tenant, using the membership from the request attributes.

### PostgreSQL row-level security as a backstop

RLS makes the database enforce the tenant even when an application query forgets to. Set it up so that the runtime role is subject to it:

```sql
-- Owner role for migrations; runtime role for the application. Neither is a superuser.
CREATE ROLE app_owner NOLOGIN;
CREATE ROLE app_runtime LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '<FROM_SECRET_STORE>';
GRANT SELECT, INSERT, UPDATE, DELETE ON documents TO app_runtime;

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;      -- the owner is subject to it too

CREATE POLICY documents_tenant_isolation ON documents
  USING      (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
```

Set the tenant per **transaction**, with a bound parameter, from the bound request context:

```javascript
// node-postgres
async function withTenant(orgId, fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('app.org_id', $1, true)", [orgId]);   // true = transaction-local
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}
```

Why each piece is there, per the PostgreSQL docs ([row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html), [`set_config`](https://www.postgresql.org/docs/current/functions-admin.html)):

- `current_setting(name, true)` returns NULL instead of raising an error when the setting does not exist, and `org_id = NULL` matches nothing, so a request without a tenant sees no rows. The `NULLIF(…, '')` is there because a custom setting that was once set on a connection can read back as an empty string, rather than NULL, after a transaction-local value has ended; check the behaviour on your PostgreSQL version and keep the `NULLIF` either way.
- `set_config(…, true)` applies only until the end of the transaction, so a pooled connection does not carry tenant A into the next request. Plain `SET` (or `is_local = false`) lasts for the session: on a pooled connection that is a cross-tenant leak waiting for an error path that skips the reset. PgBouncer in transaction pooling mode does not support session `SET` at all.
- Superusers and `BYPASSRLS` roles always bypass RLS, and table owners do unless `FORCE ROW LEVEL SECURITY` is set. Applications that connect as the migration role are the most common way RLS is silently off.
- Without `WITH CHECK`, the `USING` expression is applied to new rows as well; we spell it out so changes to one do not silently change the other.
- Views access their tables as the view owner unless they are created with `security_invoker = true`; `SECURITY DEFINER` functions run as their owner. Audit both.
- Unique and foreign-key checks bypass RLS, so a unique index on `(slug)` across tenants leaks existence; prefer `(org_id, slug)` unless global uniqueness is a product requirement.
- If any feature lets users influence SQL (custom reports, query builders), they can call `set_config` themselves; such features need a separate role and their own isolation.

Prisma publishes a [row-level security example extension](https://github.com/prisma/prisma-client-extensions/tree/main/row-level-security) that uses `set_config('app.current_company_id', …, TRUE)` inside a batch transaction; its README says it is not intended for production and that explicit `$transaction` calls may not behave as expected, so treat it as a pattern, not a library. For schema-per-tenant, the equivalent rule is `SET LOCAL search_path` per transaction (or schema-qualified names), never a session-level `search_path` on a pooled connection.

### Caches, storage, jobs and identity

**Cache keys.** Build every key for tenant-dependent data from the bound tenant, through one helper, so nobody hand-writes a key:

```python
def cache_key(org_id: str, *parts: str) -> str:
    """All tenant-scoped cache keys go through here: v1:org:<org_id>:<parts...>"""
    if not org_id:
        raise ValueError("tenant required for cache key")
    return ":".join(["v1", "org", org_id, *parts])
```

At the HTTP layer, mark tenant-specific responses `Cache-Control: private, no-store` unless you deliberately cache them with the tenant in the cache key (and `Vary` on the header that selects the tenant, if a header does).

**Search.** Apply the tenant filter on the server, or issue per-tenant search keys whose restrictions the client cannot remove. Use a separate index per tenant for the most sensitive data.

**Object storage.** Generate keys server-side (`tenants/<org_id>/files/<random_id>`), resolve them from the database record after a tenant-scoped lookup, issue short-lived pre-signed URLs only after that lookup, match prefixes with the trailing slash, and keep buckets private. Per-tenant prefixes plus IAM conditions (or per-tenant buckets for silos) are a second layer.

**Jobs.** Put `org_id` and the requesting user in the job payload, set the tenant context in the worker before any data access, and re-check membership at the consumer, as the OWASP cheat sheet recommends:

```python
@app.task
def export_project(org_id: str, requested_by: int, project_id: int) -> None:
    with tenant_bound(org_id):
        if not Membership.objects.filter(user_id=requested_by, org_id=org_id, is_active=True).exists():
            return                                     # membership revoked since enqueue
        project = Project.objects.get(id=project_id)   # scoped manager: DoesNotExist for other tenants
        build_export(project)
```

**Identity.** One IdP configuration per tenant; users keyed by `(idp_id, subject)` (and for Entra, `(tid, oid)`); issuer validated exactly against an allow-list; no authorisation on `email`, `preferred_username` or `upn`; domain verification (DNS TXT or similar) before a domain can route SSO or auto-join; JIT provisioning only into the tenant that owns the IdP configuration.

### Cross-tenant regression tests

Cross-tenant bugs come back whenever someone adds an endpoint, so the test has to be generated from the route list, not written once. A pattern that works in any stack:

1. A fixture creates tenants A and B, a member of each, and one object of every tenant-owned type in B, each with a canary string.
2. A table lists every tenant-scoped route with the object type it needs. A separate test fails if the router has a tenant-scoped route that is missing from the table.
3. For each route and method, call it as A's member with A's selector and B's object ID; assert `404` (or your chosen uniform status), that the canary is absent from the body, and, for writes, that B's object is unchanged.
4. Repeat with B's selector and A's credentials (expect 403/404), and with conflicting selectors (expect 400).

```python
# tests/test_tenant_isolation.py  (pytest + DRF APIClient)
import pytest

ROUTES = [
    ("get",    "/api/v2/orgs/{org}/documents/{document}/"),
    ("patch",  "/api/v2/orgs/{org}/documents/{document}/"),
    ("get",    "/api/v2/orgs/{org}/files/{file}/download/"),
    ("get",    "/api/v2/orgs/{org}/webhooks/{webhook}/deliveries/"),
    ("get",    "/api/v2/orgs/{org}/members/{member}/"),
    ("post",   "/api/v2/orgs/{org}/exports/"),
]


@pytest.mark.django_db
@pytest.mark.parametrize("method,template", ROUTES)
def test_member_of_a_cannot_reach_b(api_client_a, tenant_a, tenant_b_objects, method, template):
    url = template.format(org=tenant_a.slug, **{k: v.pk for k, v in tenant_b_objects.items()})
    body = {"title": "changed-by-a", "document": tenant_b_objects["document"].pk}
    resp = getattr(api_client_a, method)(url, body, format="json")

    assert resp.status_code == 404
    assert b"GTCANARY-B" not in resp.content
    tenant_b_objects["document"].refresh_from_db()
    assert tenant_b_objects["document"].title != "changed-by-a"
```

Add the database-level test as well: connect as the runtime role, and assert that with no tenant set a tenant table returns zero rows, with tenant A set it returns only A's rows, and an insert of a B row under tenant A fails with PostgreSQL's "new row violates row-level security policy" error.

## Practice labs

At the time of writing, none of the well-known training targets models tenants as such; their object-level labs are the closest match, and the best tenant practice is a small lab of your own.

| Lab | What to practise | Link |
|---|---|---|
| PortSwigger: Insecure direct object references | Swapping identifiers to reach another user's resource (the mechanics of [GT-WEB-TEN-2](#gt-web-ten-2-swap-tenant-b-object-ids-into-tenant-a-requests)) | [lab](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references) |
| PortSwigger: User ID controlled by request parameter, with unpredictable user IDs | Finding a non-guessable ID leaked elsewhere in the application, as tenant-B IDs often are (mentions, shared links, audit logs) | [lab](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids) |
| PortSwigger: User ID controlled by request parameter with data leakage in redirect | Data in a redirect body, the "302 with content" false negative | [lab](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect) |
| PortSwigger: Host header authentication bypass | An application that trusts the `Host` header, the same trust that subdomain tenant routing relies on | [lab](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-authentication-bypass) |
| PortSwigger: Exploiting path mapping for web cache deception | A cache that stores one user's private response for others, as a tenant-unaware cache does ([GT-WEB-TEN-7](#gt-web-ten-7-search-reporting-exports-and-caches)) | [lab](https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-path-mapping) |
| OWASP Juice Shop: "View Basket", "Manipulate Basket" | Reading and changing another user's basket by ID | [Juice Shop](https://github.com/juice-shop/juice-shop), [companion guide](https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html) |
| OWASP crAPI: Challenge 1 (another user's vehicle), Challenge 2 (other users' mechanic reports) | BOLA in an API where IDs leak through other endpoints | [crAPI](https://github.com/OWASP/crAPI) |
| VAmPI | BOLA and broken authorisation in a small REST API you can run locally | [VAmPI](https://github.com/erev0s/VAmPI) |

**Build a two-tenant lab.** Half a day gets you a better tenant lab than any of the above: a small API with organisations, memberships and two object types, written in the stack you test most. Implement it once with a tenant filter that is deliberately missing on one endpoint, once with a header selector that is not checked against membership, and once with PostgreSQL RLS connected as the table owner. Then run the tests in this note against it, including Autorize and the comparison helper, until you can find each bug in minutes. [django-tenants](https://django-tenants.readthedocs.io/en/latest/) gives you schema-per-tenant in Django with little code if you want to see that model's failure modes.

## Real-world cases

| Case | What happened | Lesson |
|---|---|---|
| Enjin Platform, HackerOne [#2327238](https://hackerone.com/reports/2327238), disclosed January 2024 | "Lack of Tenant Scoping Enables Limited Cross-Tenant Data Querying and Mutation". The team's summary says certain queries and mutations let one tenant query and mutate another tenant's data, while noting that many other queries are cross-tenant by design. The report shows severity Critical; no bounty amount is shown. | When some operations are meant to cross tenants, the ones that are not need an explicit list and tests ([GT-WEB-TEN-2](#gt-web-ten-2-swap-tenant-b-object-ids-into-tenant-a-requests)). |
| TikTok Ads, HackerOne [#984965](https://hackerone.com/reports/984965), disclosed 2021 | A cross-tenant IDOR in the `AddRulesToPixelEvents` GraphQL operation let one advertiser add, update and delete rules on any other advertiser's pixel events. Severity High; no bounty shown. | Secondary object types (pixel rules, not campaigns) are where scoping is missed; one GraphQL mutation often touches several object types. |
| Stripe, HackerOne [#1066203](https://hackerone.com/reports/1066203), disclosed 2022 | A GraphQL cross-tenant IDOR (`UpdateAtlasApplicationPerson`). Stripe's summary says someone with *prior* admin access to a Stripe account could add a co-founder to an Atlas application belonging to that merchant account. Severity High; no bounty shown. | Former members are attackers too: re-check membership at the object, not just at login ([GT-WEB-TEN-5](#gt-web-ten-5-invitations-and-membership-lifecycle)). |
| `@better-auth/stripe`, GitHub advisory [GHSA-h3rm-78g3-j7cp](https://github.com/advisories/GHSA-h3rm-78g3-j7cp), 2026 | The plugin's middleware authorised the organisation ID from the request query string, but the route handler acted on the organisation from the body, falling back to the session's active organisation, so subscription actions (cancel, change plan, restore, billing portal) ran against a different organisation from the one checked. Rated High, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N` (7.1); fixed in 1.6.21 by resolving the organisation once and passing it to the handler. | The textbook "two sources disagree" bug, and the textbook fix ([GT-WEB-TEN-3](#gt-web-ten-3-make-the-tenant-selectors-disagree)). |
| Microsoft "BingBang", [Wiz Research](https://www.wiz.io/blog/azure-active-directory-bing-misconfiguration), 2023 | Several Microsoft internal applications were registered as multi-tenant in Azure AD (now Entra ID) without checking which tenant the signed-in user came from, so any Azure user could sign in. One was a Bing content-management app that could change Bing search results. Wiz reports a USD 40,000 bounty and fixes by MSRC. | A multi-tenant IdP registration means "any tenant"; the application must check `iss`/`tid` and who is allowed ([GT-WEB-TEN-10](#gt-web-ten-10-sso-and-identity-provider-tenant-binding)). |
| "nOAuth", [Descope](https://www.descope.com/blog/post/noauth), 2023 | Applications using "Log in with Microsoft" in multi-tenant mode merged accounts on the `email` claim, which an administrator of any Entra tenant could set to a victim's address without verification. Descope recommends `sub` as the identifier; Microsoft added the `xms_edov` claim and an option to remove unverified email claims. | Key federated users by immutable (tenant, subject) claims, never by email ([GT-WEB-TEN-10](#gt-web-ten-10-sso-and-identity-provider-tenant-binding)). |

Two more worth reading: the ZITADEL organisation API advisory ([GHSA-cpf4-pmr4-w6cx](https://github.com/zitadel/zitadel/security/advisories/GHSA-cpf4-pmr4-w6cx)), where an organisation admin could act on other organisations ([GT-WEB-TEN-6](#gt-web-ten-6-tenant-admin-versus-platform-admin)), and Truffle Security's [domain-ownership research](https://trufflesecurity.com/blog/millions-at-risk-due-to-google-s-oauth-flaw) on SaaS tools that trust the email domain of a Google login.

## Rating findings

Cross-tenant findings rate higher than the same bug inside one tenant, because the attacker is any customer (often anyone who signs up for a trial) and the victim is every other customer. We score CVSS v3.1 with **Scope Unchanged** for application-level tenant breakout: the same application enforces both tenants' authorisation, so the vulnerable and impacted components share a security authority. Some teams score Scope Changed for tenant breakout; whichever you choose, state it and apply it consistently. CVSS also does not capture scale (one record versus every tenant) or sensitivity, so state those in the report and let them move the severity within the band.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Tenant selector (header, path, subdomain) switches tenant without a membership check | Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Any registered user, or anyone with a free trial, gets full member or admin access to every tenant; no IDs needed. Rate Critical despite the 8.8 score because of scale. |
| Unauthenticated cross-tenant read/write (public API route that takes a tenant) | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | No account needed. |
| Cross-tenant read/modify of sensitive objects by ID, IDs guessable or leaked elsewhere | High–Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1) | Any member of any tenant; Critical when the object types hold PII, financial or health data across all tenants. |
| Cross-tenant read only, IDs guessable or leaked | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Raise to High for sensitive data at scale; the vector understates breadth. |
| Cross-tenant read with random UUIDs not exposed anywhere | Medium | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N` (5.3) | UUIDs are not access control, but the attacker needs an ID from elsewhere (AC:H). Re-rate if any endpoint, export, webhook or log exposes them. |
| SSO or IdP of one tenant can sign in users of another (including admins) | Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Account takeover in any tenant; PR:L because creating your own tenant and IdP is self-service. |
| Tenant admin can administer other tenants (users, roles, SSO, billing) | High–Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) with self-service tenants; `PR:H` (7.2) if tenant admin requires vetting | A tenant admin of a free trial is PR:L in practice. |
| Search, export or cache leaks other tenants' records | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Usually returns many tenants' data at once; raise for sensitive data. |
| Search/autocomplete leaks titles or names only | Medium | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (4.3) | Limited data, but often user names and emails of other customers. |
| Removed member keeps access through existing session, token or key | Medium–High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N` (7.1) | Attacker is a former insider; severity depends on how long access persists and what the role allowed. |
| Invitation accepted by a different identity, or reusable invite token | Medium | `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:N` (6.4) | Needs a leaked or forwarded invite link (AC:H, UI:R); gives membership with the invited role. |
| Invite or member endpoint lets tenant A create memberships in tenant B | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1) | Self-join to any tenant is equivalent to tenant breakout. |
| Support or impersonation console reachable with a customer session | Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Platform-wide access by design of the tool. |
| Impersonation unscoped, unlogged or able to mint lasting credentials (staff only) | Medium | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N` (6.5) | Insider precondition; the finding is the missing limits and audit. |
| Cross-tenant existence oracle (403 vs 404, uniqueness errors naming the other tenant, shared rate-limit counters) | Low | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (4.3) | Information only; useful for chaining. |
| RLS configured but bypassed (owner or `BYPASSRLS` role), no reachable application gap | Low / hardening | n/a | A defence-in-depth gap; rate the application bug separately if one exists. |
| Org switcher hides other tenants in the UI only, API correctly refuses | Info | n/a | No reachable server-side gap. |

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 / API Top 10 |
|---|---|---|---|---|
| [GT-WEB-TEN-1](#gt-web-ten-1-map-the-tenancy-model-and-every-tenant-selector) | WSTG-ATHZ-02, WSTG-APIT-02 | `v5.0.0-8.4.1` (L2), `v5.0.0-8.1.1` (L1) | — (reconnaissance) | A01:2025 |
| [GT-WEB-TEN-2](#gt-web-ten-2-swap-tenant-b-object-ids-into-tenant-a-requests) | WSTG-ATHZ-04, WSTG-APIT-02 | `v5.0.0-8.4.1` (L2), `v5.0.0-8.2.2` (L1), `v5.0.0-8.3.1` (L1) | CWE-639, CWE-863 | A01:2025, API1:2023 |
| [GT-WEB-TEN-3](#gt-web-ten-3-make-the-tenant-selectors-disagree) | WSTG-ATHZ-02 | `v5.0.0-8.4.1` (L2), `v5.0.0-8.3.1` (L1), `v5.0.0-4.1.3` (L2) | CWE-639, CWE-863 | A01:2025, API1:2023 |
| [GT-WEB-TEN-4](#gt-web-ten-4-organisation-switching-and-stale-tenant-context) | WSTG-ATHZ-02 | `v5.0.0-8.4.1` (L2), `v5.0.0-8.3.2` (L3) | CWE-863 | A01:2025, API1:2023 |
| [GT-WEB-TEN-5](#gt-web-ten-5-invitations-and-membership-lifecycle) | WSTG-ATHZ-02, WSTG-ATHZ-04 | `v5.0.0-8.4.1` (L2), `v5.0.0-8.2.1` (L1), `v5.0.0-8.3.2` (L3), `v5.0.0-7.4.2` (L1) | CWE-863, CWE-639 | A01:2025, API1:2023, API5:2023 |
| [GT-WEB-TEN-6](#gt-web-ten-6-tenant-admin-versus-platform-admin) | WSTG-ATHZ-02, WSTG-APIT-04 | `v5.0.0-8.4.1` (L2), `v5.0.0-8.2.1` (L1), `v5.0.0-8.4.2` (L3) | CWE-863, CWE-862 | A01:2025, API5:2023 |
| [GT-WEB-TEN-7](#gt-web-ten-7-search-reporting-exports-and-caches) | WSTG-ATHZ-04, WSTG-APIT-02 | `v5.0.0-8.4.1` (L2), `v5.0.0-8.2.2` (L1), `v5.0.0-14.2.2` (L2) | CWE-639, CWE-524 | A01:2025, API1:2023 |
| [GT-WEB-TEN-8](#gt-web-ten-8-file-and-object-storage-paths) | WSTG-ATHZ-04 | `v5.0.0-8.4.1` (L2), `v5.0.0-8.2.2` (L1) | CWE-639, CWE-862 | A01:2025, API1:2023 |
| [GT-WEB-TEN-9](#gt-web-ten-9-background-jobs-integrations-and-webhooks) | WSTG-ATHZ-04, WSTG-APIT-02 | `v5.0.0-8.4.1` (L2), `v5.0.0-8.3.3` (L3) | CWE-639, CWE-863 | A01:2025, API1:2023 |
| [GT-WEB-TEN-10](#gt-web-ten-10-sso-and-identity-provider-tenant-binding) | WSTG-ATHZ-02, WSTG-SESS-10 | `v5.0.0-6.8.1` (L2), `v5.0.0-10.5.2` (L2), `v5.0.0-9.2.3` (L2), `v5.0.0-8.4.1` (L2) | CWE-290, CWE-863 | A07:2025, A01:2025 |
| [GT-WEB-TEN-11](#gt-web-ten-11-support-and-impersonation-consoles) | WSTG-ATHZ-02 | `v5.0.0-8.4.2` (L3), `v5.0.0-8.2.1` (L1), `v5.0.0-8.4.1` (L2) | CWE-862, CWE-863 | A01:2025, API5:2023 |
| [GT-WEB-TEN-12](#gt-web-ten-12-cross-tenant-side-channels) | WSTG-ATHZ-04, WSTG-ATHZ-02 | `v5.0.0-8.4.1` (L2) | CWE-203 | A01:2025 |

CWE-284 (Improper Access Control) and CWE-668 (Exposure of Resource to Wrong Sphere) describe tenant breakout in general and appear in many write-ups, but MITRE marks both as discouraged for mapping real vulnerabilities (CWE-284 is a pillar, CWE-668 a class); use the more specific entries above in reports.

## References

**OWASP**

- WSTG: [Bypassing Authorization Schema (WSTG-ATHZ-02)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/02-Bypassing_Authorization_Schema), [Insecure Direct Object References (WSTG-ATHZ-04)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/04-Insecure_Direct_Object_References), [API Broken Object Level Authorization (WSTG-APIT-02)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/02-API_Broken_Object_Level_Authorization), [API Broken Function Level Authorization (WSTG-APIT-04)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/04-API_Broken_Function_Level_Authorization), [JSON Web Tokens (WSTG-SESS-10)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/06-Session_Management/10-JSON_Web_Tokens)
- ASVS 5.0: [V8 Authorization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md) (`v5.0.0-8.4.1`, `8.2.1`, `8.2.2`, `8.3.1`, `8.3.2`); V6 Authentication (`6.8.1`), V9 Self-contained Tokens (`9.2.3`), V10 OAuth and OIDC (`10.5.2`), V14 Data Protection (`14.2.2`), V4 API and Web Service (`4.1.3`) in the [ASVS 5.0 repository](https://github.com/OWASP/ASVS/tree/master/5.0/en)
- [OWASP Top 10:2025 A01 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- API Security Top 10 2023: [API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [API5:2023 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- Cheat sheets: [Multi-Tenant Security](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html), [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [Insecure Direct Object Reference Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html), [SAML Security](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)

**CWE**

- [CWE-639](https://cwe.mitre.org/data/definitions/639.html) Authorization Bypass Through User-Controlled Key; [CWE-863](https://cwe.mitre.org/data/definitions/863.html) Incorrect Authorization; [CWE-862](https://cwe.mitre.org/data/definitions/862.html) Missing Authorization; [CWE-524](https://cwe.mitre.org/data/definitions/524.html) Use of Cache Containing Sensitive Information; [CWE-290](https://cwe.mitre.org/data/definitions/290.html) Authentication Bypass by Spoofing; [CWE-203](https://cwe.mitre.org/data/definitions/203.html) Observable Discrepancy; [CWE-284](https://cwe.mitre.org/data/definitions/284.html) Improper Access Control; [CWE-668](https://cwe.mitre.org/data/definitions/668.html) Exposure of Resource to Wrong Sphere

**PortSwigger Web Security Academy**

- [Access control vulnerabilities](https://portswigger.net/web-security/access-control), [IDOR](https://portswigger.net/web-security/access-control/idor), [HTTP Host header attacks](https://portswigger.net/web-security/host-header), [Web cache deception](https://portswigger.net/web-security/web-cache-deception)

**Databases and frameworks**

- PostgreSQL: [Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html), [CREATE POLICY](https://www.postgresql.org/docs/current/sql-createpolicy.html), [CREATE VIEW (`security_invoker`)](https://www.postgresql.org/docs/current/sql-createview.html), [`set_config` and `current_setting`](https://www.postgresql.org/docs/current/functions-admin.html), [SET](https://www.postgresql.org/docs/current/sql-set.html); PgBouncer [features by pooling mode](https://www.pgbouncer.org/features.html)
- Node.js: [AsyncLocalStorage](https://nodejs.org/api/async_context.html); Prisma: [query extensions](https://www.prisma.io/docs/orm/prisma-client/client-extensions/query), [row-level security example](https://github.com/prisma/prisma-client-extensions/tree/main/row-level-security)
- Django: [Managers](https://docs.djangoproject.com/en/5.2/topics/db/managers/); [django-tenants](https://django-tenants.readthedocs.io/en/latest/)
- Spring Security: [OAuth 2.0 resource server multitenancy](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/multitenancy.html), [method security](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html); Hibernate ORM 6.6: [User Guide (multitenancy, filters)](https://docs.hibernate.org/orm/6.6/userguide/html_single/Hibernate_User_Guide.html), [CurrentTenantIdentifierResolver](https://docs.hibernate.org/orm/6.6/javadocs/org/hibernate/context/spi/CurrentTenantIdentifierResolver.html)
- Laravel 12: [Eloquent global scopes](https://laravel.com/docs/12.x/eloquent#global-scopes), [Authorization](https://laravel.com/docs/12.x/authorization)
- Microsoft Entra ID: [convert an app to multitenant](https://learn.microsoft.com/en-us/entra/identity-platform/howto-convert-app-to-be-multi-tenant), [access tokens (issuer and `tid` validation)](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens), [claims validation](https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation)
- AWS Well-Architected SaaS Lens: [overview](https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/saas-lens.html), [silo, pool and bridge models](https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/silo-pool-and-bridge-models.html); AWS whitepaper [SaaS tenant isolation strategies](https://docs.aws.amazon.com/whitepapers/latest/saas-tenant-isolation-strategies/saas-tenant-isolation-strategies.html)

**Tools**

- [Autorize](https://github.com/Quitten/Autorize), [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix), [Auth Analyzer](https://github.com/portswigger/auth-analyzer), [ZAP Access Control Testing add-on](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/)

**Research and cases**

- [Enjin #2327238](https://hackerone.com/reports/2327238), [TikTok #984965](https://hackerone.com/reports/984965), [Stripe #1066203](https://hackerone.com/reports/1066203), [GHSA-h3rm-78g3-j7cp](https://github.com/advisories/GHSA-h3rm-78g3-j7cp), [GHSA-cpf4-pmr4-w6cx](https://github.com/zitadel/zitadel/security/advisories/GHSA-cpf4-pmr4-w6cx), [Wiz: BingBang](https://www.wiz.io/blog/azure-active-directory-bing-misconfiguration), [Descope: nOAuth](https://www.descope.com/blog/post/noauth), [Truffle Security: Google OAuth and domain ownership](https://trufflesecurity.com/blog/millions-at-risk-due-to-google-s-oauth-flaw)
