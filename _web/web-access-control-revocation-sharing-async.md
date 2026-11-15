---
title: "Access Control Beyond the Request: Revocation, Share Links, Exports and Async Channels"
date: 2026-11-15 18:10:00 +0000
subcategory: access-control
summary: "Testing stale permissions after revocation, share links, exports, multi-step flows, real-time subscriptions, webhooks and confused deputies."
refs: [WSTG-ATHZ-02, WSTG-ATHZ-04, WSTG-BUSL-06, WSTG-SESS-06, WSTG-SESS-07, WSTG-SESS-10, WSTG-SESS-11, WSTG-CLNT-10, WSTG-APIT-99, v5.0.0-8.3.2, v5.0.0-8.3.3, v5.0.0-8.2.2, v5.0.0-7.4.1, v5.0.0-7.4.2, v5.0.0-7.4.3, v5.0.0-9.2.1, v5.0.0-10.4.9, v5.0.0-4.4.4, v5.0.0-2.3.1, v5.0.0-11.5.1, "API1:2023", "API2:2023", "API5:2023", "A01:2025", CWE-284, CWE-441, CWE-639, CWE-200, CWE-1464, CWE-1469, CWE-841, CWE-862]
tags: [web, access-control, revocation, websocket, webhooks, share-links]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and its [Access Control testing guide](/web/web-access-control-testing-guide/). It covers the access-control failures that a request-by-request check does not catch: authority that outlives the decision that granted it, and data that leaves through a side door. That means stale permissions after a role downgrade, removal from a team or organisation, deactivation or a password change (server-side sessions, JWT access tokens, refresh tokens, API keys and personal access tokens, OAuth grants, mobile sessions, open WebSocket connections and permission caches); share links and capability URLs, including pre-signed object-storage URLs; exports, reports and downloads produced by background jobs; multi-step processes that check only the first step; WebSocket, SSE and GraphQL subscriptions and webhooks; and confused deputies, where a back-end service or worker acts with its own privilege instead of the user's. Object-level checks on ordinary requests live in [IDOR and BOLA](/web/web-idor-bola/), function-level checks in [vertical privilege escalation and BFLA](/web/web-vertical-privilege-escalation-bfla/), field-level checks in [mass assignment and BOPLA](/web/web-mass-assignment-bopla/), and tenant boundaries in [multi-tenant isolation](/web/web-multi-tenant-isolation/).

## Contents

- [How it works](#how-it-works)
  - [Authorisation is a decision at a point in time](#authorisation-is-a-decision-at-a-point-in-time)
  - [Where cached authority lives](#where-cached-authority-lives)
  - [Capability URLs and bearer links](#capability-urls-and-bearer-links)
  - [Work that happens after the request](#work-that-happens-after-the-request)
  - [Long-lived channels](#long-lived-channels)
  - [Identity across service hops](#identity-across-service-hops)
- [What goes wrong](#what-goes-wrong)
  - [Stale sessions and cached permissions](#stale-sessions-and-cached-permissions)
  - [Self-contained tokens that outlive the decision](#self-contained-tokens-that-outlive-the-decision)
  - [Long-lived credentials nobody revokes](#long-lived-credentials-nobody-revokes)
  - [Share links that leak, linger or widen](#share-links-that-leak-linger-or-widen)
  - [Exports and downloads detached from the requester](#exports-and-downloads-detached-from-the-requester)
  - [Checks only on the first step](#checks-only-on-the-first-step)
  - [Subscriptions authorised once](#subscriptions-authorised-once)
  - [Webhooks that receive too much](#webhooks-that-receive-too-much)
  - [Confused deputies](#confused-deputies)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-WEB-CTX-1: Session termination on logout, password change and deactivation](#gt-web-ctx-1-session-termination-on-logout-password-change-and-deactivation)
  - [GT-WEB-CTX-2: Stale authorisation after role downgrade or removal](#gt-web-ctx-2-stale-authorisation-after-role-downgrade-or-removal)
  - [GT-WEB-CTX-3: Access and refresh tokens after a revocation event](#gt-web-ctx-3-access-and-refresh-tokens-after-a-revocation-event)
  - [GT-WEB-CTX-4: API keys, personal access tokens and OAuth grants](#gt-web-ctx-4-api-keys-personal-access-tokens-and-oauth-grants)
  - [GT-WEB-CTX-5: Share link token strength, expiry and revocation](#gt-web-ctx-5-share-link-token-strength-expiry-and-revocation)
  - [GT-WEB-CTX-6: Share link scope, audience and sharer lifecycle](#gt-web-ctx-6-share-link-scope-audience-and-sharer-lifecycle)
  - [GT-WEB-CTX-7: Exports, reports and download links](#gt-web-ctx-7-exports-reports-and-download-links)
  - [GT-WEB-CTX-8: Authorisation on every step of a multi-step process](#gt-web-ctx-8-authorisation-on-every-step-of-a-multi-step-process)
  - [GT-WEB-CTX-9: WebSocket and SSE subscriptions and messages](#gt-web-ctx-9-websocket-and-sse-subscriptions-and-messages)
  - [GT-WEB-CTX-10: GraphQL subscriptions](#gt-web-ctx-10-graphql-subscriptions)
  - [GT-WEB-CTX-11: Webhook registration and event scoping](#gt-web-ctx-11-webhook-registration-and-event-scoping)
  - [GT-WEB-CTX-12: Confused deputy between services and workers](#gt-web-ctx-12-confused-deputy-between-services-and-workers)
- [Secure implementation](#secure-implementation)
  - [Design principles](#design-principles)
  - [Node.js and Express](#nodejs-and-express)
  - [Django and Channels](#django-and-channels)
  - [Spring Security](#spring-security)
  - [Laravel](#laravel)
  - [Authorisation regression tests for revocation](#authorisation-regression-tests-for-revocation)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Authorisation is a decision at a point in time

Every access check answers one question: may subject S perform action A on object O *now*? The inputs are the subject's identity, its roles and memberships, the object's attributes and state, and sometimes context (tenant, device, time). This note is about the word "now". Each input can change after a decision has been made: an administrator demotes a user, an employee leaves, a project is moved into a restricted space, an owner revokes a link, an account is disabled after a compromise. If something that was decided earlier keeps being honoured after one of those changes, the application is enforcing an old policy.

ASVS 5.0 states the requirement directly. v5.0.0-8.3.2 (L3) asks that changes to the values authorisation decisions depend on take effect immediately; where that is not possible, for example because the decision is baked into a self-contained token, there must be controls that alert on, and revert, actions taken by a consumer who is no longer authorised. The requirement itself points out that reverting does not undo a disclosure. The session requirements in V7 set a lower bar that every application has to meet:

| Requirement | Level | What it demands |
|---|---|---|
| v5.0.0-7.4.1 | L1 | Once a session is terminated (logout, expiry), it cannot be used again; for self-contained tokens this needs a deny list, a per-user "not before" time or a per-user signing key |
| v5.0.0-7.4.2 | L1 | All active sessions end when the account is disabled or deleted |
| v5.0.0-7.4.3 | L2 | After a password or MFA change the user can end all other sessions |
| v5.0.0-7.4.5 | L2 | Administrators can end the sessions of one user or of all users |
| v5.0.0-8.3.2 | L3 | Any change to authorisation-relevant values applies immediately, or is detected and reverted |

So even an L1 application must kill sessions when an account is disabled. Stale *role* or *membership* data inside a live session is formally an L3 requirement, but it is where most real findings sit, and the impact (a former employee still reading customer data) is the same whatever level the client targets.

For every artefact that carries authority, ask three questions: where is the decision made (when the artefact is issued, or each time it is used)? What does the artefact or its surrounding cache remember (a role in a claim, a membership list in Redis, a room subscription on a socket)? Which event invalidates it, and does that event actually reach it?

### Where cached authority lives

| Artefact | What it carries | Typically checked | What should invalidate it |
|---|---|---|---|
| Server-side session (cookie) | User ID; sometimes roles, org list or feature flags copied in at login | Session lookup on every request, but copied roles are rarely refreshed | Session deletion; a per-user auth version compared on each request |
| JWT access token | `sub`, scopes, roles, tenant, `exp` | Signature and `exp` only | Expiry; a `jti` deny list; a `ver` or `iat` check against per-user state |
| Refresh token | The right to mint new access tokens | At the token endpoint | Revocation at the authorisation server ([RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)); rotation; account state |
| API key, personal access token, deploy key | Long-lived bearer authority, often scoped | Lookup on every request, but rarely tied to membership | Deletion; owner lifecycle hooks; expiry |
| OAuth grant to a third-party client | Consent plus a refresh token held by someone else | At refresh time | User or admin revocation (v5.0.0-10.4.9, v5.0.0-10.7.3); account state |
| Mobile session | Long-lived refresh token, device binding | At refresh | Server-side device list; account state |
| WebSocket or SSE connection | Identity resolved at the handshake; room or topic memberships | Often never again | Explicit disconnect or unsubscribe |
| Permission cache (Redis, in-process, gateway) | A computed decision or role set | At TTL | TTL plus purge on change events |
| Share link, signed URL, pre-signed object URL | The capability itself | Signature and expiry at use | Expiry; server-side revocation record; the signer's credentials |
| Queued job | Requester ID and parameters captured at enqueue | At enqueue only | Re-check when the job runs and when its output is fetched |

The table is also your test plan: every row is a place where a revocation event can fail to arrive.

### Capability URLs and bearer links

A capability URL is a link whose possession is the authorisation. "Anyone with the link", password-reset links, unsubscribe links, invitation links, signed download URLs and pre-signed object-storage URLs all work this way. The W3C TAG's [Good Practices for Capability URLs](https://www.w3.org/TR/capability-urls/) draft describes the trade-off: they are convenient precisely because no login is needed, and dangerous for the same reason. A sound one has five properties:

1. **Unguessable.** The secret part comes from a CSPRNG with at least 128 bits of entropy. ASVS v5.0.0-11.5.1 (L2) asks exactly that for any value meant to be non-guessable and notes that UUIDs do not satisfy it.
2. **Narrow.** It grants one action (view, comment, download) on one object, not on the folder, project or account around it.
3. **Expiring.** Expiry is enforced on the server at every use, not just shown in the UI.
4. **Revocable.** That requires a server-side record. A purely stateless signed URL can only be revoked by rotating the key or waiting for expiry.
5. **Leak-aware.** URLs end up in browser history, `Referer` headers, proxy and CDN logs, chat previews, analytics tools, and in email security scanners that "click" every link. ASVS v5.0.0-14.2.1 (L1) says URLs should not carry secrets such as API keys or session tokens; a share link is a deliberate exception, so the compensating controls (short expiry, narrow scope, `Referrer-Policy: no-referrer`, no third-party scripts on the shared page) matter.

Pre-signed object-storage URLs are the same thing at the storage layer. Per the AWS documentation, an S3 pre-signed URL is a bearer token that can be used repeatedly until it expires (up to seven days when signed with IAM user credentials and SigV4), it expires earlier if the signing credentials expire or are revoked, and there is no way to revoke one URL on its own. Our [S3 security note](/cloud/aws-s3-security/) covers the bucket side.

### Work that happens after the request

Exports, reports, invoice PDFs, thumbnails, previews, search indexing, email digests and webhook deliveries all run *after* the request that started them, usually in a worker with a service identity and broad database access. The request that enqueued the job was authorised. The questions are whether anyone checks again when the job runs (the requester may have lost access in the meantime), whether the job's output is filtered through the same policy as the UI, and whether the result is bound to the requester or just to a URL. GitLab's `ProjectExportWorker` case, described under [Real-world cases](#real-world-cases), is the textbook example of the first question.

### Long-lived channels

A WebSocket starts as an HTTP `GET` with `Upgrade: websocket`. The browser sends cookies and an `Origin` header, the server answers `101 Switching Protocols`, and from then on there are only messages. Frameworks resolve the user once, at the handshake, and keep that identity for the life of the connection. Spring's documentation says WebSockets reuse the authentication found on the HTTP request when the connection was made; Django Channels' `AuthMiddleware` puts a read-only user object into the connection scope. WSTG-CLNT-10 puts it bluntly: WebSockets do not handle authentication or authorisation themselves.

That leaves three layers the application has to build:

- **Handshake.** Is the client authenticated, and is the `Origin` allowed (v5.0.0-4.4.2, L2)? Are dedicated WebSocket tokens obtained through the authenticated HTTPS session (v5.0.0-4.4.4, L2)?
- **Subscription.** May this user join room, channel or topic X? A topic name such as `project.42` is an object reference, and subscribing is the real-time equivalent of `GET /projects/42`.
- **Message.** May this user send action Y on object Z, and may *this recipient* receive *this* event?

Nothing in that list runs again when a user is demoted or removed unless the application makes it. Server-Sent Events (a long-lived `GET` with `Content-Type: text/event-stream`) and GraphQL subscriptions (usually over WebSocket with the `graphql-transport-ws` subprotocol) have the same shape.

### Identity across service hops

A gateway authenticates the user and calls service A; A calls service B. There are three ways to carry identity on the second hop:

1. **Forward the user's token.** B validates it and checks the user's permissions. Simple, but B must accept tokens issued for A's audience, which conflicts with audience restriction (v5.0.0-9.2.3).
2. **Token exchange.** A swaps the user's token for a new one scoped to B's audience that still names the user as subject and A as the actor (`act` claim), using OAuth 2.0 Token Exchange ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)).
3. **A's own service token.** A calls B with client credentials. B sees only "service A", which is typically allowed to read everything.

Option 3 is the confused deputy: CWE-441 (Unintended Proxy or Intermediary, alternate term "Confused Deputy") describes a component that forwards a request without preserving where it came from. ASVS v5.0.0-8.3.3 (L3) requires access to be based on the originating subject's permissions rather than on those of an intermediary, and gives this exact example. The same pattern appears inside a monolith: a PDF worker that loads "invoice 9001" with a database connection that sees every tenant is a deputy, whatever the network diagram looks like.

## What goes wrong

### Stale sessions and cached permissions

**What happens.** The session survives logout because the server only clears the cookie in the browser. Deactivating an account sets `active = false` but nothing looks at that flag for existing sessions. Roles, organisation lists or "is admin" flags are copied into the session at login and never refreshed, so a demoted user keeps admin rights until they log out. A permission service caches "user 17 may write project 42" for an hour. A revocation runs as a background job that sometimes fails, and nobody notices because the UI already shows the user as removed.

**Why it matters.** The people most likely to use stale access are exactly the ones who have just lost it: a leaver, a contractor at the end of an engagement, a compromised account that was disabled. Their access is already authenticated and looks legitimate in the logs.

**Where to look.** Logout, password change and reset, "sign out everywhere", admin deactivation, removal from team, project or organisation, role edits, SSO deprovisioning (SCIM), and every place that caches permissions: session payloads, Redis keys named like `perm:*` or `acl:*`, gateway authorisers with a result TTL.

### Self-contained tokens that outlive the decision

**What happens.** A JWT access token carries `roles: ["admin"]` and `org: "o_1"` and is valid for 24 hours; the API trusts those claims and never asks the database. Logout deletes the token from `localStorage` but the token itself is still valid. The refresh token keeps working after the account is disabled, or the token endpoint copies the old claims from the refresh token into every new access token, so a downgrade never takes effect. Mobile apps get refresh tokens valid for months.

**Why it matters.** Signature validity is not authorisation. A token is a snapshot of authority at issue time, and its lifetime is the minimum window in which revocation cannot work unless the server checks something per request. WSTG-SESS-10 asks you to review the lifetime from `iat`, `nbf` and `exp`; ASVS v5.0.0-9.2.1 (L1) requires the validity time span to be enforced, and v5.0.0-7.4.1 (L1) requires terminated sessions to stop working even for self-contained tokens.

**Where to look.** The token response (`expires_in`), the decoded claims, the refresh endpoint, the logout handler (does it call a revocation endpoint at all?), and the API's authorisation layer (does it read roles from the token or from the database?).

### Long-lived credentials nobody revokes

**What happens.** API keys, personal access tokens (PATs), deploy keys, SSH keys, OAuth grants to third-party integrations, "app passwords" for legacy protocols, and mobile device sessions are created by a user and tied to that user, but removing the user from an organisation only deletes the membership row. The key still authenticates, and the authorisation check asks "is this key valid?" rather than "is the key's owner still a member with this role?". Laravel Sanctum's documentation, for example, notes that its tokens never expire by default and are invalidated only by revocation, so an application has to wire revocation into its own lifecycle events.

**Why it matters.** These credentials are designed to outlive sessions; they are also the ones the user can copy to a personal machine before leaving. GitLab's demoted-member deploy-key report below shows the second half of the problem: the owner could not even see the key that kept the access alive.

**Where to look.** Settings pages for tokens and keys, OAuth "authorised applications", integration marketplaces, admin views of member credentials, and SCIM or offboarding handlers.

### Share links that leak, linger or widen

**What happens.** Tokens are short, sequential, timestamp-based, a hash of the file ID, or a base64-encoded object ID. Expiry is shown in the UI but not checked on the server. Revoking a link hides it from the owner's list but the token still resolves. A link to one file accepts a different file ID in a parameter, exposes the containing folder through a listing or "download all" endpoint, or reveals version history and comments. An "organisation only" link works anonymously. The link keeps working after its creator has been removed from the project, so the creator can still read the document through their own link. Changing a link password does not reset recipients who already entered the old one.

**Why it matters.** A share link is an access-control decision that has been handed to whoever holds the URL. It must therefore be at least as narrow, short-lived and revocable as the policy it replaces. When it widens (one file becomes a folder) or lingers (removal does not end it), it becomes a bypass for every other control in this guide.

**Where to look.** Share dialogs, public link endpoints (often a separate route tree such as `/s/<token>` or `/public/...`), preview and thumbnail routes for shared items, invitation links, and pre-signed URLs returned by the API (`X-Amz-Expires`, `X-Amz-Credential` and `X-Amz-Date` in the query string).

### Exports and downloads detached from the requester

**What happens.** The export job runs as a service and builds the file from everything in the project, including items the requester cannot see in the UI. The job ID or filename is sequential (`/exports/10452/download`, `report_2026-11-15_17.csv`). The download endpoint checks only that the job exists, not that the caller requested it or still has access. A completed export can be downloaded weeks later by a user who has since been removed. The notification email contains a link that works without login and can be forwarded. The file is served with cacheable headers and a CDN keeps it under a URL that anyone can request.

**Why it matters.** Exports are bulk data by design. A single broken check yields every record in scope rather than one, and the output often lands in places (email, CDN, object storage) that the application's access control does not govern.

**Where to look.** CSV and XLSX export, "download my data" (GDPR), audit-log export, invoices, report builders, backups, "email me this report", and the storage URLs that come back.

### Checks only on the first step

**What happens.** A multi-step process (role change with confirmation, approval workflow, checkout, onboarding wizard, data deletion with confirmation) checks permissions on the page that starts the flow and assumes that anyone who reaches step two came through step one. The confirmation request is accepted from any authenticated user. Status fields such as `step=4` or `approved=true` come from the client. A request can be approved by the person who submitted it, or approved after the approver lost the role. An approved item can be edited afterwards without fresh approval, which is the workflow-circumvention pattern in WSTG-BUSL-06.

**Why it matters.** The privileged action usually happens on the last step, not the first. PortSwigger's "Multi-step process with no access control on one step" lab is the minimal version: the admin role-change confirmation lacks the check that the first step has.

**Where to look.** Any feature with "confirm", "review", "approve", "next", or a wizard; forms that post hidden state; flows spanning several API calls with a shared flow or transaction ID.

### Subscriptions authorised once

**What happens.** The WebSocket handshake checks the session, but subscribing to `project.42` or `orders.9001` only checks that the user is logged in. Inbound messages (`{"action":"delete","id":"..."}`) are dispatched without a per-object check because "the HTTP API does that". Broadcasts go to everyone in a room, including users who should see only part of the event. A user removed from a project keeps receiving its events until they reload, or indefinitely if the client reconnects automatically with a cached token. Subscriptions use a different code path from queries or controllers, so a check implemented in one (blocked users, suspended tenants) never runs in the other, as in GitLab's GraphQL-subscription report.

**Why it matters.** Real-time channels often carry the same data as the REST API, sometimes more (presence, typing indicators, draft content), without any of its checks. Revocation is harder, because there is no next request on which to fail.

**Where to look.** Burp's WebSockets history, Socket.IO frames (`42["event",...]`), STOMP frames (`SUBSCRIBE`, `destination:`), Laravel Echo `private-` and `presence-` channels and the `/broadcasting/auth` request, Pusher or Ably channel auth endpoints, GraphQL `Subscription` types, and `text/event-stream` responses.

### Webhooks that receive too much

**What happens.** Any member can register a webhook, not just administrators. A webhook created at organisation level receives events about private projects its creator cannot read. The payload includes full objects (confidential issues, private comments, customer PII) rather than IDs. Deliveries continue after the creator leaves, because the webhook belongs to the organisation but its authority came from the creator. Delivery logs and "redeliver" endpoints take a delivery ID without an ownership check.

**Why it matters.** A webhook is a standing, outbound subscription: once registered, data flows to an endpoint outside the application with no further requests by the attacker. It is the asynchronous form of a stale session.

Webhook target URLs pointing at internal addresses are a server-side request forgery problem; they belong to the later SSRF and files note and are out of scope here.

**Where to look.** Organisation, project and repository settings; integration APIs (`POST /hooks`, `POST /webhooks`); event catalogues; delivery history pages.

### Confused deputies

**What happens.** The public API checks that user A may read invoice 9001, then calls the billing service with its own service token; the billing service, which trusts that token, returns any invoice. A "generate PDF" or "preview" endpoint takes an object ID and hands it to a worker that loads it with full database rights. An AI assistant or automation feature performs actions with the platform's credentials rather than the user's (crAPI's chatbot challenges are a lab version). An internal API meant only for services is routed through the public gateway, and it trusts the gateway. Downstream services accept an `X-User-Id` header from anything that can reach them (header trust is covered in [authorisation bypass techniques](/web/web-authorization-bypass-techniques/)).

**Why it matters.** The check that matters, at the service holding the data, is made against the wrong subject. Every endpoint that reaches the deputy inherits its privilege, and front-end checks give a false sense of safety because the direct route is correctly blocked.

**Where to look.** PDF, image, thumbnail and document-preview features, import-from-URL, report builders, search, AI or automation features, internal hostnames and `/internal/` paths in JavaScript bundles or API specifications, and service-to-service tokens in grey-box reviews (`azp`, `client_id` or `act` claims).

## Testing

### Before you start

**Authorisation.** Run these tests only in an authorised engagement with written scope and rules of engagement, in a bug bounty programme whose rules allow them, or in a lab you run yourself. Revocation tests need an administrator to demote, remove and deactivate accounts, so they are usually done in a staging environment or in an organisation you own on a SaaS product. HTTP and message outputs in this note are illustrative.

**Accounts.** You need more accounts here than in most access-control tests, because one of them is going to lose access:

| Account | Role | Used for |
|---|---|---|
| O | Owner or administrator of organisation 1 | Performing the revocation events: demote, remove, deactivate, revoke links |
| A | Member (or project admin) in organisation 1 | The subject who loses access; logged in on two browsers and, if in scope, the mobile app |
| B | Member in organisation 1 | Second user of the same role, for cross-user checks and as a "recipient" |
| C | Member of organisation 2 | Cross-tenant checks |
| Anonymous | none | Share links, download URLs, handshake without credentials |

Every object you test against (projects, files, invoices, exports, webhooks) is one you created for the test. A cross-account proof always targets your own second account's object, never a real customer's.

**Stop on real data.** If any request returns data that belongs to a real third party (a customer name you did not create, another tenant's records), stop. Keep only the minimum redacted evidence needed to report it, do not download or retain anything more, and report it to the client or programme immediately.

**No enumeration.** Do not iterate share tokens, export IDs, job IDs or channel names. Compare tokens you generated yourself; if an identifier looks sequential, prove it by creating two of your own in a row and requesting the one in between only if it is also yours, or within a small bounded range the client has agreed. Keep request rates low.

**Ask the client for:** documented session idle and absolute timeouts (v5.0.0-7.1.1), access and refresh token lifetimes, any permission-cache TTLs, the list of events that are supposed to revoke access, and whether a staging queue can be paused (useful for [GT-WEB-CTX-7](#gt-web-ctx-7-exports-reports-and-download-links)).

**Burp setup.** One project file per engagement, with Logger on. Configure [Autorize](https://github.com/Quitten/Autorize) or [Auth Analyzer](https://github.com/portswigger/auth-analyzer) with A's captured session as the "low-privileged" identity while you browse as O; after a revocation event their output tells you, request by request, which of A's old credentials still work. [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix) is useful for keeping a before-and-after role matrix. These extensions work on HTTP; for WebSocket traffic use Burp's WebSockets history and Repeater (which can send WebSocket messages), or a command-line client such as `websocat`. ZAP's [Access Control Testing add-on](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/) offers a similar role-based comparison.

**Revocation timeline.** Each revocation test follows the same rhythm:

1. **Snapshot** everything A holds before the event: session cookies for each browser, access and refresh tokens, API keys, share links, pre-signed URLs, an open WebSocket connection, a queued export.
2. **Trigger** the event as O (or as A for logout and password change), and note the exact UTC time.
3. **Replay** a fixed list of read-only requests with each snapshot at T+0, T+1 min, T+5 min, T+15 min, T+60 min, and after one token refresh cycle.
4. **Record** status, size and a body hash for each replay. A response that stops working at T+15 min tells you the cache or token lifetime; one that never stops is the finding.

This small script does steps 3 and 4 for one credential. It refuses anything other than `GET` and `HEAD`, so it cannot change state:

```bash
#!/usr/bin/env bash
# revoke-replay.sh: replay a fixed list of read-only requests with one captured credential.
# Usage: AUTH_HEADER='Authorization: Bearer <TOKEN_USER_A>' ./revoke-replay.sh requests.txt t+5m
set -euo pipefail
list="$1"; label="${2:-run}"; body="$(mktemp)"
while read -r method url; do
  [[ -z "${method:-}" || "$method" == \#* ]] && continue
  case "$method" in GET|HEAD) ;; *) echo "skip $method $url (read-only script)"; continue ;; esac
  result=$(curl -s -o "$body" -w '%{http_code} %{size_download}' -X "$method" -H "$AUTH_HEADER" "$url")
  printf '%s\t%s\t%s\t%s\t%s\n' "$(date -u +%H:%M:%S)" "$label" "$result" \
    "$(shasum -a 256 "$body" | cut -c1-12)" "$url"
  sleep 1
done < "$list"
rm -f "$body"
```

```text
# requests.txt: only objects created for the test
GET https://api.example.com/v1/projects/p_7Hq2
GET https://api.example.com/v1/projects/p_7Hq2/members
GET https://api.example.com/v1/projects/p_7Hq2/documents/d_test01
GET https://api.example.com/v1/org/o_1/settings
```

To read a JWT's timing and authority claims without pasting the token anywhere (requires jq 1.6 or later):

```bash
jq -R 'split(".")[1] | gsub("-";"+") | gsub("_";"/") | @base64d | fromjson
       | {sub, iat, exp, scope, roles, org, ver, jti}' <<<"$TOKEN_USER_A"
```

### GT-WEB-CTX-1: Session termination on logout, password change and deactivation

*Guler Tech methodology.* Implements WSTG-SESS-06 (logout), WSTG-SESS-07 (session timeout) and WSTG-SESS-11 (concurrent sessions), applied to the account lifecycle events that should end access.

#### What it checks

Whether server-side sessions actually end when they should: on logout (that session), on password change or reset (other sessions, when offered or required), on deactivation or deletion (all sessions), on an administrator's "terminate sessions" action, and at the documented idle and absolute timeouts.

#### Prerequisites

Accounts O and A; A logged in on two browsers (and the mobile app if in scope); the cookies of each session captured in Burp; the documented timeouts.

#### Steps

1. Log in as A in browser 1 and browser 2. In Burp, send an authenticated read request from each browser (for example `GET /api/v1/me` and `GET /api/v1/projects/p_7Hq2`) to Repeater and label the tabs.
2. **Logout.** Log out in browser 1. Replay browser 1's old request. If the logout response set a new cookie, put the old value back manually, as WSTG-SESS-06 describes.
3. **Password change.** As A in browser 2, change the password. If the application offers "sign out of other sessions", select it. Replay the browser 1 session from a fresh login, the mobile session and any other captured session.
4. **Deactivation.** As O, deactivate A (or suspend, block, or remove from the IdP if SSO with SCIM is used). Replay every session you hold for A at T+0 and T+5 min.
5. **Admin termination.** If the admin UI has "sign out user" or "revoke sessions", use it on a fresh A session and replay.
6. **Timeouts.** Leave one session idle beyond the documented idle timeout and replay; keep another active (a request every few minutes) beyond the documented absolute lifetime and replay.
7. **SSO.** Where an IdP is involved, also log out at the IdP and check whether the application session survives (WSTG-SESS-06, single sign-off).

#### Observation

After deactivation, replaying browser 2's cookie:

```http
GET /api/v1/projects/p_7Hq2 HTTP/1.1
Host: api.example.com
Cookie: session=<SESSION_USER_A_BROWSER2>
Accept: application/json
```

Vulnerable (illustrative):

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id":"p_7Hq2","name":"GT test project","role":"admin","documents":12}
```

Expected:

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"error":"session_expired"}
```

#### Evaluation

- **Fail:** a logged-out session still works (v5.0.0-7.4.1, L1); any session works after deactivation or deletion (v5.0.0-7.4.2, L1); the application offers to end other sessions after a password change but they keep working (v5.0.0-7.4.3, L2); sessions live longer than the documented idle or absolute timeout (v5.0.0-7.3.1, v5.0.0-7.3.2, L2); the admin "terminate" control does not terminate (v5.0.0-7.4.5, L2).
- **Pass:** every replay returns 401, 403 or a redirect to login, and the old cookie remains dead even if the browser is given a new one.
- Report the measured window. "Works for 4 minutes after deactivation" and "works until the user logs out" are different findings.

#### False positives

- The browser shows a cached authenticated page after logout (back button); reload from the server before you conclude anything.
- `200 OK` whose body is the login page or a generic error. Compare bodies, not status codes.
- The IdP silently signs the user back in. That is a single sign-off issue, report it separately from session invalidation.
- Concurrent sessions allowed by design are not a finding in themselves (WSTG-SESS-11); failing to end them on deactivation is.

#### Automation

Run `revoke-replay.sh` once per captured session after each event. In CI, write an integration test that logs in twice, deactivates the user through the admin API and asserts 401 on both sessions (see [Authorisation regression tests for revocation](#authorisation-regression-tests-for-revocation)).

### GT-WEB-CTX-2: Stale authorisation after role downgrade or removal

*Guler Tech methodology.* Implements WSTG-ATHZ-02 (horizontal and vertical bypass), extended along the time axis required by ASVS v5.0.0-8.3.2.

#### What it checks

Whether role changes and removal from a team, project or organisation take effect on sessions and tokens that already exist, and how long any permission cache delays them.

#### Prerequisites

O owns organisation 1 and project P; A is a project admin in P. A's session (and token, if the SPA uses one) captured in Burp before the change. Autorize or Auth Analyzer configured with A's session as the low-privileged identity.

#### Steps

1. As A, capture requests that need A's current role: read project settings, list members, read a private document in P, and one harmless write on your own test object (rename a test label). Note the responses.
2. **Downgrade.** As O, change A from admin to viewer. Without logging A out, replay the admin reads first, then the harmless write (**own test objects only**). Repeat at the timeline intervals.
3. **Removal.** As O, remove A from P. Replay A's read of P's documents and members.
4. **Organisation removal.** As O, remove A from organisation 1. Replay organisation-level reads (settings, member directory, billing summary).
5. **Compare with a fresh login.** Log A in again in a third browser and send the same requests. If a fresh login is denied but the old session is allowed, roles or memberships are cached in the session or token.
6. **Check other paths.** Confirm that A has no remaining legitimate access through another team, an organisation-wide role, a guest link or a public project. Otherwise you are testing a different policy.
7. While browsing the project as O after the change, watch Autorize: any request where A's old session gets the same response as O's is a candidate.

#### Observation

```http
GET /api/v1/projects/p_7Hq2/members HTTP/1.1
Host: api.example.com
Cookie: session=<SESSION_USER_A>
```

Vulnerable (illustrative), 20 minutes after A was removed from the project:

```http
HTTP/1.1 200 OK
Content-Type: application/json

[{"user":"O","role":"owner"},{"user":"B","role":"member"}]
```

Expected: `404 Not Found` (or `403`) as soon as the removal is saved.

#### Evaluation

- **Fail:** A keeps any permission beyond the documented propagation window; for an L3 target, any window without the detect-and-revert control v5.0.0-8.3.2 asks for. Write access surviving a downgrade or removal is more serious than read access.
- **Fail (design):** access stops only when A logs out, which means authority is copied into the session at login.
- **Pass:** denial at T+0, or within a short documented window (seconds) caused by replication.

#### False positives

- A has access through another membership, an organisation-wide role, or a public-by-design project.
- Eventual consistency of a few seconds across regions. Repeat at T+1 min before reporting.
- A `200` with an empty list. The policy may be applied as a filter rather than a denial, which is acceptable if nothing leaks.

#### Automation

Autorize or Auth Analyzer with A's pre-change session; `revoke-replay.sh` at each interval. In CI, test each role change against each sensitive endpoint: change the role through the service layer, then call the endpoint with a session created *before* the change.

### GT-WEB-CTX-3: Access and refresh tokens after a revocation event

*Guler Tech methodology.* Implements WSTG-SESS-10 (JWT lifetime review) and WSTG-SESS-06 (logout), for applications that use bearer tokens.

#### What it checks

What authority A's access token carries, how long it stays usable after logout, a password change, a downgrade, removal and deactivation, and whether the refresh token stops minting new tokens, or keeps minting them with old claims.

#### Prerequisites

A logged in to the SPA or mobile app; the token response captured (`access_token`, `refresh_token`, `expires_in`); the refresh request captured.

#### Steps

1. Decode the access token's claims with the jq one-liner above. Record `exp - iat` (the lifetime) and any authority-bearing claims: roles, groups, scopes, organisation or tenant IDs, plan, feature flags.
2. Determine whether the API reads authority from the token or from the server: after a downgrade (step 3), call an admin endpoint with the *old* token and with a *freshly issued* token. If the old token works and the new one does not, the API trusts the claims.
3. For each event (logout, password change, downgrade, removal, deactivation), with a fresh token pair each time:
   - replay API calls with the old access token at the timeline intervals until `exp`;
   - call the refresh endpoint with the old refresh token;
   - if the refresh succeeds, decode the new access token and compare its claims with the new state.
4. Check whether logout calls a revocation endpoint ([RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)) or only deletes the token client-side (watch the network tab during logout).
5. Check other services that accept the same token (another API host, a file service): revocation that works on one service and not on another is common.

#### Observation

```http
POST /oauth/token HTTP/1.1
Host: app.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=<REFRESH_TOKEN_USER_A>&client_id=web-spa
```

Vulnerable (illustrative), one hour after A was deactivated:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"access_token":"<NEW_TOKEN_USER_A>","token_type":"Bearer","expires_in":3600,"refresh_token":"<NEW_REFRESH_USER_A>"}
```

Expected:

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"error":"invalid_grant"}
```

#### Evaluation

- **Fail:** the refresh token works after logout, deactivation or a password change that should end other sessions (v5.0.0-7.4.1, v5.0.0-7.4.2, v5.0.0-10.4.9).
- **Fail:** the API makes authorisation decisions from role or tenant claims in a token whose lifetime is long (hours or days) and there is no server-side version or deny-list check (v5.0.0-8.3.2), or a newly refreshed token still carries the old roles.
- **Fail:** tokens without `exp`, or `exp` not enforced (v5.0.0-9.2.1).
- **Pass:** short-lived access tokens (minutes) whose remaining validity is documented and accepted, plus refresh tokens revoked on every event, plus a server-side check (`ver`, `iat` against a per-user "not before", or `jti` deny list) for high-risk events such as deactivation.
- An access token that keeps working for its last few minutes after a downgrade, with a documented short lifetime, is usually a Low or informational observation; say how long the window was.

#### False positives

- The refresh succeeds but the new token has reduced scopes or roles. That is correct behaviour.
- `offline_access` grants to an integration that the user explicitly approved and that are supposed to survive a browser logout. Test them in [GT-WEB-CTX-4](#gt-web-ctx-4-api-keys-personal-access-tokens-and-oauth-grants), not here.
- A `401` caused by your clock skew or a replayed `DPoP` proof rather than by revocation.

#### Automation

Script the refresh call after each event and assert `invalid_grant`. In CI, issue a token pair, deactivate the user, and assert that both the refresh and a protected API call fail; if the design accepts a short window, assert the window explicitly.

### GT-WEB-CTX-4: API keys, personal access tokens and OAuth grants

*Guler Tech methodology.* Implements WSTG-ATHZ-02 for non-session credentials, with the grant-revocation aspects of WSTG-ATHZ-05 (OAuth weaknesses).

#### What it checks

Whether long-lived credentials created by or for A (API keys, PATs, deploy and SSH keys, OAuth grants to third-party clients, app passwords, mobile device sessions) stop authorising organisation resources when A is removed, demoted or deactivated, and whether owners can see and revoke them.

#### Prerequisites

As A: one PAT or API key with read scope; one OAuth authorisation to a client you control (a test client the client provides, or one registered in your own organisation); a deploy key or SSH key if the product has them. O's admin view of members and credentials.

#### Steps

1. Confirm that each credential works: `GET` an organisation resource with it.
2. As O, remove A from organisation 1. Replay each credential against organisation resources at the timeline intervals.
3. Repeat with a downgrade (does a key created with admin rights keep admin rights?) and with deactivation.
4. For the OAuth client, call the token endpoint with the client's refresh token after each event; also test after A revokes the grant in "authorised applications" (v5.0.0-10.7.3).
5. As O, look for the credentials A created: can the owner see them, attribute them to A, and revoke them? Check the API as well as the UI.
6. Check expiry: can keys be created without one, and does the configured maximum hold?

#### Observation

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Authorization: Bearer <PAT_USER_A>' \
  https://api.example.com/v1/org/o_1/projects
# 200 two days after A was removed from organisation 1 (vulnerable, illustrative)
# 401 or 403 expected
```

#### Evaluation

- **Fail:** any user-owned credential still authorises access to the organisation after the owner lost membership or was deactivated (v5.0.0-7.4.2, v5.0.0-8.3.2); a key keeps rights from a role the owner no longer has; an OAuth refresh still works after deactivation or revocation (v5.0.0-10.4.9).
- **Fail (visibility):** owners cannot see or revoke credentials created by a member or former member. Report it even if the key happens to be blocked, because offboarding depends on it.
- **Observation:** no expiry on PATs, or no maximum lifetime. Not a vulnerability alone, but it multiplies every other failure here.

#### False positives

- Organisation-owned service accounts or bot tokens, which are intended to survive a person's departure. Verify that they are organisation-owned, visible and documented.
- After organisation removal the key still authenticates, but returns only A's personal resources. A still exists as a user, so this is correct.

#### Automation

Add a "leaver" scenario to the CI suite: create a member, issue each credential type, remove the member, and assert 401 or 403 for every credential on organisation endpoints.

### GT-WEB-CTX-5: Share link token strength, expiry and revocation

*Guler Tech methodology.* Implements WSTG-ATHZ-04 (direct references) and WSTG-ATHZ-02 for capability URLs.

#### What it checks

Whether share-link and signed-URL tokens are unguessable, expire on the server, stop working when revoked, and reset access when their password changes; and whether the shared page leaks the token to third parties.

#### Prerequisites

A test file owned by A; the ability to create, expire and revoke links; B and an anonymous browser as recipients.

#### Steps

1. Create five links in a row for the same file and two for different files. Compare the tokens: length, alphabet, any visible structure (a counter, a timestamp, an encoded object ID, a hash of the file name). Base64-decode anything that looks encoded. Do not request tokens you did not create.
2. Check whether the object ID travels next to the token (`/s/<token>?file=f_123`, or a JSON body with both). If so, swap the file ID for another of *your* files: the token should be bound to one object.
3. Set the shortest expiry available, wait for it to pass, and open the link in a fresh browser and with curl. Then test an expired link in a browser that had opened it before expiry (a cookie set by the share page may keep it alive).
4. Revoke a link and replay it immediately and after five minutes.
5. Protect a link with a password, open it as B, change the password as A, and reload as B. B should be asked again (the Nextcloud report below).
6. On the shared page, check the response headers (`Referrer-Policy`, `Cache-Control`, `X-Robots-Tag`) and the third-party requests in Burp's HTTP history: does the full URL with the token go to an analytics or CDN host in the `Referer` header?
7. For pre-signed object URLs returned by the API, read `X-Amz-Expires` (seconds), and check whether the API issues a fresh, short URL per request or a long-lived one that is stored and reused.

#### Observation

```http
GET /s/3f9c2a7d1e HTTP/1.1
Host: app.example.com
```

Illustrative weak tokens from five consecutive shares: `3f9c2a7d1e`, `3f9c2a7d1f`, `3f9c2a7d20`... (a hex counter). A sound token looks like 43 characters of base64url from 32 random bytes and shows no relation between consecutive values. An expired or revoked link should return `404` or `410` with no content.

#### Evaluation

- **Fail:** tokens predictable or derived from object data, or shorter than 128 bits of randomness (v5.0.0-11.5.1, L2; CWE-340); the token not bound to one object (CWE-639); expiry or revocation not enforced on the server (CWE-1469, Improper Check for Credential Expiration); a password change not resetting existing recipients; the token leaking in `Referer` to third parties (v5.0.0-14.2.1).
- **Pass:** random, object-bound tokens; server-side expiry and revocation effective at T+0; `Referrer-Policy: no-referrer` or equivalent; no third-party requests from the shared page.

#### False positives

- A revoked link still serves content from a CDN for the cache TTL. It is still a finding if the TTL is long, but the fix is a purge on revocation, not the token logic.
- Expiry dates displayed in one time zone and enforced in another. Allow for the offset before you report.
- Content that is public by design (a published page that also has a share link).

#### Automation

A unit test that generates 1,000 tokens and checks length, alphabet and uniqueness is cheap. Integration tests should assert that expired, revoked and password-changed links return `404` or `410`.

### GT-WEB-CTX-6: Share link scope, audience and sharer lifecycle

*Guler Tech methodology.* Implements WSTG-ATHZ-02 for shared resources, and the v5.0.0-8.3.2 question of what happens to a link when its creator's authority changes.

#### What it checks

Whether a link to one object exposes more than that object; whether "organisation only" really excludes outsiders; whether re-shares and expiry interact safely; and whether a link outlives its creator's access.

#### Prerequisites

Project P with a folder containing two test files; A as a member who shares one file; B, C (other tenant) and anonymous as recipients; O to remove A.

#### Steps

1. **Scope.** Share one file. With the share token, try the API routes the shared page uses with sibling or parent IDs (your own files): folder listing, "download all as zip", previews, thumbnails, version history, comments, activity. If the share token travels as a header (for example `X-Share-Token`), try it on ordinary API routes too.
2. **Permissions.** For a "view" link, try a comment, an edit and a re-share (**own test objects only**; read before write). For an "edit" link, check that it cannot delete, change sharing, or reach other files.
3. **Re-share and expiry.** Share a folder with B; as B, re-share a subfolder with an expiry; after expiry, open the re-share link. It should show "expired", not the parent folder (the Nextcloud report below).
4. **Audience.** Create an "organisation only" or "specific people" link and open it as C and anonymously.
5. **Sharer lifecycle.** As A, create an "anyone with the link" share. As O, remove A from P (then, separately, deactivate A). Open the link in a fresh browser, and as A. Check the product's documentation first: some products keep links alive by design, but A still being able to read *updated* content through their own link after removal is a revocation bypass whatever the documentation says.
6. **Moved content.** Move the shared file into a folder with stricter permissions and reopen the link.

#### Observation

```http
GET /api/v1/shares/<SHARE_TOKEN_FILE_1>/folder/items HTTP/1.1
Host: api.example.com
```

Vulnerable (illustrative): `200 OK` with a listing of every file in the folder, although the link was created for `file_1` only. Expected: `404 Not Found`.

#### Evaluation

- **Fail:** the token reaches objects or actions beyond the one shared (CWE-639, CWE-863); "organisation only" links open for outsiders; an expired re-share exposes the parent; the creator keeps access to the content through their own link after removal or deactivation (v5.0.0-8.3.2); a link keeps exposing content after it was moved somewhere more restricted, unless that is documented and the owner was warned.
- **Pass:** each token resolves to one object and one permission set, audience restrictions are enforced, and lifecycle events either kill the creator's links or re-check the creator's authority at use time.

#### False positives

- Folder shares, which are meant to expose the folder.
- Products that document "links survive the creator's removal" for public links. Report the creator's own continued access, not the public link itself.
- B seeing sibling files because B is a member of the folder anyway.

#### Automation

Feature tests that create a share for one object and assert `404` for each sibling route with that token; a lifecycle test that removes the creator and asserts the configured behaviour.

### GT-WEB-CTX-7: Exports, reports and download links

*Guler Tech methodology.* Implements WSTG-ATHZ-04 and WSTG-ATHZ-02 for asynchronous outputs, plus the cache checks behind v5.0.0-14.2.2.

#### What it checks

Whether export and report outputs are bound to the requester, re-authorised when the job runs and again at download, filtered through the same policy as the UI, and kept out of shared caches and forwardable links.

#### Prerequisites

Every export-like feature mapped (CSV or XLSX export, "download my data", audit-log export, invoices, report builders, backups, "email me the report"). A, B, C and anonymous sessions. Ideally a staging environment where the queue can be paused or where a large export takes minutes.

#### Steps

1. As A, request each export. Capture the job-creation response, any polling endpoint and the final download URL.
2. **Identifier.** Look at the job ID and file name: sequential, timestamp-based, or random? Create two exports in a row to see the pattern (your own jobs only).
3. **Binding.** Request A's download URL and polling endpoint as B, as C and anonymously.
4. **Re-authorisation at download.** Remove A from the project after the export completes; request the download as A.
5. **Re-authorisation at execution.** Request a large export as A, then remove A from the project before the job finishes (pause the queue if the client can). Does the job complete, and can A download the result? This is the GitLab `ProjectExportWorker` pattern.
6. **Content.** Compare the export with what A can see in the UI: private items, other users' fields, hidden columns, other tenants' rows. A difference means the export does not use the UI's policy.
7. **Links.** If the export is emailed, open the link in a browser where nobody is logged in, and in B's browser. Check the link's expiry.
8. **Caching.** Look at the download response headers (`Cache-Control`, `Age`, `X-Cache`, `CF-Cache-Status`, `Vary`). Request the same URL from another session and anonymously: a `HIT` for a different user means the CDN is serving A's file. Web cache deception through path tricks belongs to the later HTTP and infrastructure note.
9. **Pre-signed URLs.** If the download redirects to object storage, note the URL's lifetime and whether a new one is issued after an authorisation check on each request.

#### Observation

```http
GET /api/v1/exports/10452/download HTTP/1.1
Host: api.example.com
Cookie: session=<SESSION_USER_B>
```

Vulnerable (illustrative):

```http
HTTP/1.1 200 OK
Content-Type: text/csv
Content-Disposition: attachment; filename="p_7Hq2-members.csv"
Cache-Control: public, max-age=86400

email,role,last_login
...
```

Expected: `404 Not Found` for B, and `Cache-Control: private, no-store` for A.

#### Evaluation

- **Fail:** another user or an anonymous client can fetch the output (CWE-639, CWE-862); the job runs or the download works after the requester lost access (v5.0.0-8.3.2); the export contains data the requester cannot see in the UI (CWE-200); a shared cache serves one user's export to another (CWE-524, v5.0.0-14.2.2); emailed links work for anyone, indefinitely.
- **Pass:** the job record holds the requester; the worker checks the requester's current permissions before it runs and filters content with the same policy; the download endpoint requires authentication and the same check, then issues a short-lived storage URL; responses are `private, no-store`.

#### False positives

- B is a legitimate member who can see the same data, so the identical content is not a leak (check whether B could *list* the export as well).
- A short-lived pre-signed URL that B can open only because you copied it to B. It is a bearer capability by design; judge its lifetime and scope.
- A CDN `HIT` on a static asset rather than on the export.

#### Automation

Integration tests for each export type: create as A, assert `404` as B and anonymous, remove A and assert `404` at download; a worker test that removes the requester between enqueue and execution and asserts that the job is cancelled.

### GT-WEB-CTX-8: Authorisation on every step of a multi-step process

*Guler Tech methodology.* Implements WSTG-BUSL-06 (circumvention of workflows, Method 3: multi-step workflow and state transition abuse) together with WSTG-ATHZ-02.

#### What it checks

Whether every request in a multi-step process enforces the permission the process requires, whether steps can be skipped, reordered or replayed, and whether approvals are bound to the approver's current role and to the approved content.

#### Prerequisites

The privileged flows mapped as O (role changes with confirmation, approval workflows, deletion with confirmation, checkout, onboarding wizards); every step captured in Burp; A's lower-privileged session in Autorize.

#### Steps

1. As O, walk the flow and send each step to Repeater. Note the state each step carries: flow or transaction IDs, hidden fields, `step`, `status`, `approved`.
2. Replay **each step individually** with A's session, not just the first. The interesting one is usually the confirmation.
3. **Skip.** As A, call the final step directly without the earlier ones.
4. **Reorder and replay.** Send step 3 before step 2; replay a completed step 3.
5. **Swap state.** Use a flow ID from a flow your second account B started.
6. **Tamper.** Change client-supplied state (`status=approved`, `step=4`, `amount`) on intermediate steps.
7. **Approvals.** Submit as A and approve as A; approve after O has removed A's approver role (combine with [GT-WEB-CTX-2](#gt-web-ctx-2-stale-authorisation-after-role-downgrade-or-removal)); edit an approved request (**own test objects only**) and check whether the approval survives the edit.

#### Observation

The confirmation step of an admin role change, replayed with A's session (compare the PortSwigger lab):

```http
POST /admin/roles/confirm HTTP/1.1
Host: admin.example.com
Cookie: session=<SESSION_USER_A>
Content-Type: application/x-www-form-urlencoded

action=upgrade&username=gt-user-a&confirmed=true
```

Vulnerable (illustrative): `302 Found` to `/admin` and A is now an administrator. Expected: `403 Forbidden`, with no state change.

#### Evaluation

- **Fail:** any state-changing step accepts a session without the required permission (v5.0.0-8.2.1, CWE-862); the final step runs without the earlier steps having been completed for the same user and flow (v5.0.0-2.3.1, CWE-841); client-supplied state is trusted; self-approval is possible where the policy requires a second person (v5.0.0-2.3.5 for high-value flows); approvals survive edits or the approver's loss of role.
- **Pass:** every step authorises independently, and the server holds the flow state and re-validates it at the final step.

#### False positives

- A `200 OK` on the confirmation step without any state change. Always verify the resulting state (role, order, approval) from O's view.
- Steps that are deliberately public (address lookup in a checkout).

#### Automation

Autorize catches the per-step check automatically if you walk the flow as O. In CI, test the final endpoint directly with a low-privileged user and with a flow ID that belongs to someone else.

### GT-WEB-CTX-9: WebSocket and SSE subscriptions and messages

*Guler Tech methodology.* Implements WSTG-CLNT-10 (WebSockets) with the authorisation tests of WSTG-ATHZ-02 and WSTG-ATHZ-04 applied to handshakes, subscriptions, messages and live revocation.

#### What it checks

Whether real-time channels authorise the handshake, every subscription, every inbound message and every outbound event, and whether revocation reaches connections that are already open.

#### Prerequisites

WebSocket or SSE endpoints identified (Burp Proxy WebSockets history; `Upgrade: websocket`; `Content-Type: text/event-stream`); the client's subscription protocol understood (Socket.IO, STOMP, Laravel Echo with Pusher-protocol servers, GraphQL, custom JSON). A and B in project P1, B alone in project P2 (both your test projects), C in another tenant.

#### Steps

1. **Handshake.** Connect without cookies or token; with an expired session; and with a foreign `Origin` header (cross-site WebSocket hijacking, v5.0.0-4.4.2). Note whether the connection is accepted and what it receives.
2. **Subscription.** As A, subscribe to P1 (legitimate), then send a subscription for P2's room or topic using Burp Repeater's WebSocket support. With Laravel Echo, watch the `POST /broadcasting/auth` request that authorises `private-` channels and change its `channel_name`.
3. **Inbound messages.** As A, send read-type actions that reference P2's objects (`get`, `history`, `typing`), then a harmless write on your own P2 object (**own test objects only**).
4. **Outbound filtering.** Generate events in P1 that only some members should see (a private comment, an admin-only field). Watch what B's connection receives.
5. **Live revocation.** Keep A's connection open (in Burp, or `websocat` in a terminal). As O, remove A from P1, then create an event in P1. Does A's connection still receive it? Can A still send? Repeat with deactivation, and check whether the client reconnects automatically with a cached token.
6. **SSE.** For `text/event-stream` endpoints, repeat steps 2 and 5: open the stream as A with a P2 parameter, and keep a P1 stream open across A's removal.

#### Observation

Socket.IO frames in Burp's WebSocket history (illustrative). A asks to join B's project room, and the server acknowledges and starts streaming:

```text
→ 421["project:subscribe",{"projectId":"p_B9x1"}]
← 431[{"ok":true}]
← 42["project:event",{"type":"document.updated","id":"d_b01","title":"B test doc v2"}]
```

The equivalent STOMP subscription (the trailing `^@` is the NUL frame terminator):

```text
SUBSCRIBE
id:sub-1
destination:/topic/projects/p_B9x1

^@
```

Expected: an error acknowledgement or `ERROR` frame, and no events for P2. After A is removed from P1, A's connection should be closed, or should stop receiving P1 events, within the documented window.

#### Evaluation

- **Fail:** subscriptions or messages referencing objects A cannot access are accepted (CWE-862, CWE-639); recipients receive event fields they could not read through the API (CWE-200); unauthenticated or cross-origin handshakes receive private data (v5.0.0-4.4.2); open connections keep receiving or sending after removal or deactivation (v5.0.0-8.3.2, v5.0.0-7.4.2).
- **Pass:** each subscription and message is checked against the object; events are filtered per recipient or carry only identifiers; revocation closes connections or removes them from rooms.

#### False positives

- Events that are content-free pings ("project changed") after which the client re-fetches over the authorised API. A removed user then only learns *that* something changed. Note it, at most Low.
- Public channels by design (status pages, public chat rooms).
- The connection is closed at the next heartbeat or token-refresh interval, and that interval is short and documented.

#### Automation

`websocat` or a short script with the client library (for example `socket.io-client`) that subscribes as A to B's room and asserts an error. In CI, a test that removes a member while their socket is connected and asserts disconnection.

### GT-WEB-CTX-10: GraphQL subscriptions

*Guler Tech methodology.* Implements WSTG-APIT-99 (GraphQL) for the `Subscription` type, together with WSTG-CLNT-10 for the transport.

#### What it checks

Whether GraphQL subscription resolvers apply the same object-level, field-level and account-state checks as queries and mutations, at subscription time and for each event delivered.

#### Prerequisites

The schema (introspection, the client bundle, or recovered with clairvoyance when introspection is off; [InQL](https://github.com/doyensec/inql) in Burp helps); the subscription endpoint and subprotocol (`Sec-WebSocket-Protocol: graphql-transport-ws` for the `graphql-ws` library, or the legacy `subscriptions-transport-ws`); test objects for A and B.

#### Steps

1. List the subscription fields and their arguments.
2. Connect as A. Check how the `connection_init` payload carries credentials, and whether an expired or revoked token is accepted there.
3. Subscribe to an event for one of B's objects (your own second account).
4. Subscribe without the scoping argument, or with a wildcard, if the schema allows it: does it stream everyone's events?
5. Request fields in the subscription selection that queries refuse (confidential or admin-only fields). Subscription payload types often reuse object types whose field-level checks live elsewhere (see [mass assignment and BOPLA](/web/web-mass-assignment-bopla/)).
6. Keep a subscription open while O blocks, deactivates or removes A (GitLab's report below is exactly this case).

#### Observation

```json
{"type": "connection_init", "payload": {"authorization": "Bearer <TOKEN_USER_A>"} }
{"id": "1", "type": "subscribe", "payload": {"query": "subscription { issueUpdated(issueId: \"gid://app/Issue/9002\") { id title confidentialNotes } }"} }
```

Vulnerable (illustrative): `next` frames for `id` 1 whose `payload.data` carries B's issue. Expected: an `error` message for `id` 1, and no `next` frames.

#### Evaluation

- **Fail:** subscribing to another user's object succeeds; wildcard subscriptions stream unscoped events; restricted fields are returned in subscription payloads; blocked, deactivated or removed users keep receiving events (v5.0.0-8.2.2, v5.0.0-8.2.3, v5.0.0-8.3.2).
- **Pass:** the resolver authorises the subscription and filters every event for the subscriber; account-state checks run on the subscription path, not only in the HTTP controller.

#### False positives

- Subscriptions that deliver only IDs, after which the client queries with its own checks.
- An `error` frame that arrives after a first `next`. Read the first frame: if it contained data, that is still a leak.

#### Automation

A schema-driven test that, for each subscription field, subscribes as an unrelated user and asserts an error; InQL to generate the templates during the test.

### GT-WEB-CTX-11: Webhook registration and event scoping

*Guler Tech methodology.* Implements WSTG-ATHZ-02 (and the function-level angle of WSTG-ATHZ-03) for webhooks and similar outbound notifications.

#### What it checks

Who can register a webhook, which events and objects it receives relative to its creator's permissions, whether deliveries stop when the creator loses access, and whether delivery logs are scoped.

#### Prerequisites

An endpoint you control to receive deliveries (Burp Collaborator, or a receiver you run); project P1 that A can access and P2 that A cannot (both your test projects); items in P1 that A cannot see (a confidential issue created by O).

#### Steps

1. As A (a member, not an administrator), try to register organisation-level and project-level webhooks. Compare with the documented role requirements (function-level checks are covered in [vertical privilege escalation and BFLA](/web/web-vertical-privilege-escalation-bfla/)).
2. Register a webhook as A on P1, and one at organisation level if allowed.
3. As O, create events in P2, and confidential items in P1. Check which deliveries arrive at your receiver and what their payloads contain.
4. As O, remove A from P1 and from the organisation. Trigger events again: do deliveries continue?
5. Check the webhook's attribution: can O see that A created it, and is it disabled or flagged after A's removal?
6. As B, request the delivery log or "redeliver" endpoint for A's webhook by its ID (your own second account), and look for payloads or signing secrets shown again in the UI or API.

Do not point webhook URLs at internal or third-party hosts; that SSRF angle is tested in the later SSRF and files note.

#### Observation

```http
POST /api/v1/org/o_1/webhooks HTTP/1.1
Host: api.example.com
Cookie: session=<SESSION_USER_A>
Content-Type: application/json

{"url":"https://<YOUR_COLLABORATOR_HOST>/hook","events":["issue.created","issue.updated"],"scope":"organisation"}
```

Vulnerable (illustrative): `201 Created` for a plain member, followed by deliveries for P2 and for confidential P1 issues, still arriving a day after A's removal.

#### Evaluation

- **Fail:** members can register webhooks that the policy reserves for administrators (CWE-862); deliveries include objects or fields the creator cannot read (CWE-200); deliveries continue after the creator lost access with no re-attestation by an administrator (v5.0.0-8.3.2); delivery logs or secrets are readable by other users.
- **Pass:** registration requires the documented role; each delivery is filtered by the webhook's effective permissions at delivery time; removal of the creator disables or re-scopes their webhooks, and administrators can see them all.

#### False positives

- Organisation webhooks created by an administrator for organisation-wide events, which are meant to receive everything.
- Payloads that contain only IDs and event types.

#### Automation

A CI test that registers a webhook as a member of P1, emits events in P2, and asserts that nothing is queued for delivery; and one that removes the creator and asserts the webhook is disabled.

### GT-WEB-CTX-12: Confused deputy between services and workers

*Guler Tech methodology.* Implements WSTG-ATHZ-02 and WSTG-ATHZ-04 against components that act on the user's behalf, which is the property v5.0.0-8.3.3 asks for.

#### What it checks

Whether services, workers and internal APIs that act on a user's behalf make their decisions with the user's identity and permissions, or with their own.

#### Prerequisites

The features where the server does something with an object on the user's behalf: PDF or report rendering, previews and thumbnails, import or "fetch from URL", search, AI assistant or automation features, integrations. A and B each own a test object of the relevant type. Grey-box: the service-to-service authentication design, if the client shares it.

#### Steps

1. Confirm the direct route is protected: `GET` B's invoice as A returns `404`.
2. Ask the deputy for the same object: render a PDF, request a preview or thumbnail, run a report or search that targets B's object ID, or ask the assistant to "summarise invoice inv_B_0042". Use only B's test objects.
3. Compare: if the direct route is denied but the deputy's output contains B's data, the deputy decided with its own privilege.
4. Look for internal APIs reachable through the public gateway: hostnames and paths such as `/internal/`, `/svc/` or `/admin-api/` in JavaScript bundles, OpenAPI files and error messages. Try them with A's token (read-only), and see whether they trust the gateway rather than the user. Header-trust variants (`X-User-Id`, `X-Forwarded-User`) and proxy and back-end path mismatches are covered in [authorisation bypass techniques](/web/web-authorization-bypass-techniques/).
5. Grey-box: inspect a downstream call in logs or traces. Does it carry the user's token, an exchanged token with the user as subject (`sub`) and the service as actor (`act`), or only a client-credentials token?

#### Observation

```http
POST /api/v1/documents/render-pdf HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
Content-Type: application/json

{"invoiceId":"inv_B_0042","template":"default"}
```

Vulnerable (illustrative): `200 OK`, `Content-Type: application/pdf`, showing B's invoice, while `GET /api/v1/invoices/inv_B_0042` with the same token returns `404`. Expected: `404` from both.

#### Evaluation

- **Fail:** any deputy returns or acts on data that the user cannot reach directly (CWE-441, CWE-639); an internal API accepts calls routed from the public edge and trusts the service identity; downstream services make decisions without the originating user's identity (v5.0.0-8.3.3, L3).
- **Pass:** the deputy re-authorises with the user's identity (it receives the user ID and calls the same policy, or it calls downstream with a user-bound exchanged token), and internal APIs are not routable from the edge.

#### False positives

- The output contains only data A can see anyway (a template, A's own invoice).
- The deputy returns a generic error document with `200 OK`. Read the PDF.

#### Automation

For each deputy endpoint, a CI test that asks it to process another user's object and asserts denial. In service code, make the user identity a required argument of the worker interface, so a job without one cannot be enqueued.

## Secure implementation

### Design principles

- **Decide at use time.** Tokens and sessions carry identity; authority (roles, memberships, tenant) is looked up on the server for each request, from a store that revocation events update. If you must put authority in a token for performance, keep the token short-lived (minutes) and add a per-user version check for high-risk events.
- **One revocation path for every event.** Removal from a team, project or organisation, role change, deactivation, password or MFA change and link revocation should all go through one handler that: bumps the user's auth version; deletes server-side sessions; revokes refresh tokens and OAuth grants; disables or re-scopes API keys and PATs; purges permission caches; disconnects sockets or removes them from rooms; cancels queued jobs; disables or flags the user's webhooks and, where the policy says so, their share links; and writes an audit event. Make the handler idempotent and alert when it fails, because GitHub's case below shows what a silently failing background revocation looks like.
- **Short-lived bearer tokens plus a server-side check.** Access tokens for 5 to 15 minutes; refresh tokens rotated, with an absolute lifetime (v5.0.0-10.4.8) and revoked server-side; a `ver` claim compared with the user's current version, or an `iat` compared with a per-user "not valid before" time, which are the options v5.0.0-7.4.1 lists. A `jti` deny list is the targeted alternative for single-token logout.
- **Permission caches with short TTLs and explicit purge.** Never copy roles into a session at login without a version that is checked on each request.
- **Capabilities that are narrow and recorded.** Share tokens with 256 bits from a CSPRNG, stored as a SHA-256 hash (so a database leak does not leak working links), bound to one object and one permission, with a mandatory expiry, a revocation record, and a re-check of the sharer's authority at use time if your policy says links die with the sharer's access. Serve shared content with `Referrer-Policy: no-referrer`, `Cache-Control: private, no-store` and `X-Robots-Tag: noindex`.
- **Exports bound to a person.** The job record holds the requester; the worker re-authorises the requester before it runs and filters content with the same policy as the UI; the result is stored privately; the download endpoint requires authentication and the same policy check, then issues a storage URL that lives for seconds or minutes.
- **Every step authorises.** Multi-step processes keep their state on the server and re-validate at the final step.
- **Real-time channels authorise three times.** At the handshake (session plus `Origin`), at each subscription, and at each inbound message. Filter outbound events per recipient, or send only identifiers and let clients re-fetch through the API. Disconnect or unsubscribe on revocation.
- **Webhooks owned by the organisation, scoped by a person.** Registration is an administrator function; each delivery is filtered by the webhook's effective permissions at delivery time; removing the creator disables or re-attests their webhooks.
- **Propagate the user's identity across hops.** Downstream services decide with the user's identity (a forwarded token, or an exchanged token with `sub` = user and `act` = calling service); service tokens get narrow audiences; internal APIs are not routable from the public edge.

### Node.js and Express

Authentication with [jose](https://github.com/panva/jose), with authority read from the server and a per-user version check:

```javascript
// auth.js
import { createRemoteJWKSet, jwtVerify } from "jose";

const JWKS = createRemoteJWKSet(new URL("https://app.example.com/auth/.well-known/jwks.json"));

export async function authenticate(req, res, next) {
  try {
    const token = (req.get("authorization") || "").replace(/^Bearer /, "");
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: "https://app.example.com/auth",
      audience: "https://api.example.com",
      algorithms: ["RS256"],
    });
    // Per-user state: { active, tokenVersion, notBefore }, cached for seconds and purged on revocation
    const state = await authState.get(payload.sub);
    if (!state || !state.active || payload.ver !== state.tokenVersion || payload.iat < state.notBefore) {
      return res.status(401).json({ error: "token_revoked" });
    }
    req.user = { id: payload.sub };
    return next();
  } catch {
    return res.status(401).json({ error: "invalid_token" });
  }
}

// Membership is read from the database on every request, never from the token
export const can = (action) => async (req, res, next) =>
  (await policy.check(req.user.id, action, req.params.projectId))
    ? next()
    : res.status(404).json({ error: "not_found" });

app.get("/v1/projects/:projectId/members", authenticate, can("project:members:read"), listMembers);
```

Socket.IO: share the session with the handshake, authenticate in `io.use`, authorise each subscription, re-check on each packet with `socket.use`, and act on revocation events. `io.engine.use()`, `socket.use()`, `socketsLeave()` and `disconnectSockets()` are part of the Socket.IO 4 server API; the [express-session how-to](https://socket.io/how-to/use-with-express-session) shows the session-sharing and logout-disconnect pattern this builds on.

```javascript
// realtime.js
import { Server } from "socket.io";

const io = new Server(httpServer, { cors: { origin: ["https://app.example.com"], credentials: true } });
io.engine.use(sessionMiddleware); // the same express-session middleware as the HTTP app

io.use(async (socket, next) => {
  const sess = socket.request.session;
  const state = sess?.userId && (await authState.get(sess.userId));
  if (!state || !state.active || state.tokenVersion !== sess.authVersion) return next(new Error("unauthorised"));
  socket.data.userId = sess.userId;
  socket.data.authVersion = sess.authVersion;
  socket.join(`user:${sess.userId}`); // lets revocation handlers find this user's sockets
  return next();
});

io.on("connection", (socket) => {
  // Cheap per-packet re-check of account state
  socket.use(async (_packet, next) => {
    const state = await authState.get(socket.data.userId);
    if (!state || !state.active || state.tokenVersion !== socket.data.authVersion) return socket.disconnect(true);
    return next();
  });

  socket.on("project:subscribe", async ({ projectId }, ack) => {
    if (!(await policy.check(socket.data.userId, "project:read", projectId))) return ack?.({ error: "forbidden" });
    socket.join(`project:${projectId}`);
    return ack?.({ ok: true });
  });
});

// Called by the single revocation handler
export function onMembershipRemoved(userId, projectId) {
  io.in(`user:${userId}`).socketsLeave(`project:${projectId}`);
}
export function onUserRevoked(userId) {
  io.in(`user:${userId}`).disconnectSockets(true);
}
```

In a cluster, these server-side helpers work across nodes only with an adapter (for example the Redis adapter). Broadcast minimal events to rooms (`{ type, id }`), so that a recipient whose access is in doubt still has to fetch details through the HTTP API.

Share links stored as hashes and re-checked at use:

```javascript
import crypto from "node:crypto";
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");

export async function createShare(req, res) {
  // policy.check(req.user.id, "file:share", req.params.fileId) has already run
  const token = crypto.randomBytes(32).toString("base64url"); // 256 bits
  await shares.insert({
    tokenHash: sha256(token), fileId: req.params.fileId, permission: "view",
    createdBy: req.user.id, expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000), revokedAt: null,
  });
  res.status(201).json({ url: `https://app.example.com/s/${token}` });
}

export async function openShare(req, res) {
  const share = await shares.findByTokenHash(sha256(req.params.token));
  if (!share || share.revokedAt || share.expiresAt <= new Date()) return res.status(404).end();
  if (!(await policy.check(share.createdBy, "file:share", share.fileId))) return res.status(404).end();
  res.set({ "Referrer-Policy": "no-referrer", "Cache-Control": "private, no-store", "X-Robots-Tag": "noindex" });
  return streamFile(res, share.fileId, share.permission); // this file, this permission, nothing else
}
```

### Django and Channels

Django already covers two events if you let it. With `ModelBackend`, the user is reloaded for each request and an inactive user is rejected, which ends sessions on deactivation; and for users based on `AbstractBaseUser`, the session stores a hash derived from the password and Django checks it on each request, so a password change logs out other sessions ([docs](https://docs.djangoproject.com/en/6.0/topics/auth/default/)). The documentation explicitly supports a custom `get_session_auth_hash()`, which you can use to add an auth version, so that one counter also kills sessions on role or membership changes:

```python
# accounts/models.py
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.crypto import salted_hmac

class User(AbstractUser):
    auth_version = models.PositiveIntegerField(default=0)

    def get_session_auth_hash(self):
        # Bumping auth_version invalidates every existing session on its next request
        return salted_hmac(
            "accounts.User.get_session_auth_hash",
            f"{self.password}:{self.auth_version}",
            algorithm="sha256",
        ).hexdigest()
```

Remember `update_session_auth_hash(request, user)` after a self-service change you do not want to log the current session out of. For DRF with [Simple JWT](https://django-rest-framework-simplejwt.readthedocs.io/en/latest/blacklist_app.html), keep access tokens short, rotate and blacklist refresh tokens, and check the same version:

```python
# settings.py
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=10),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,   # needs "rest_framework_simplejwt.token_blacklist" in INSTALLED_APPS
    "CHECK_USER_IS_ACTIVE": True,       # the default: inactive users get 401
}

# accounts/auth.py
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class VersionedTokenSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["ver"] = user.auth_version
        return token

class VersionedJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        user = super().get_user(validated_token)
        if validated_token.get("ver") != user.auth_version:
            raise AuthenticationFailed("Token revoked", code="token_revoked")
        return user
```

Blacklisting covers refresh and sliding tokens only, which is why the version check is needed for access tokens. Scope querysets by current membership, so a removal applies on the next request:

```python
class DocumentViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Document.objects.filter(
            project__memberships__user=self.request.user,
            project__memberships__active=True,
        ).distinct()
```

Channels resolves the user once, when the connection opens (`AuthMiddlewareStack` puts it in `self.scope["user"]`). Authorise in `connect`, again for each message and event, and give the revocation handler a group to close the connection:

```python
# projects/consumers.py
from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer

@database_sync_to_async
def can_read(user_id, project_id):
    return Membership.objects.filter(
        user_id=user_id, project_id=project_id, active=True, user__is_active=True
    ).exists()

class ProjectConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        self.user = self.scope["user"]
        self.project_id = int(self.scope["url_route"]["kwargs"]["project_id"])
        if not self.user.is_authenticated or not await can_read(self.user.pk, self.project_id):
            await self.close()  # before accept(): the handshake is rejected
            return
        self.group = f"project_{self.project_id}"
        await self.channel_layer.group_add(self.group, self.channel_name)
        await self.channel_layer.group_add(f"user_{self.user.pk}", self.channel_name)
        await self.accept()

    async def disconnect(self, code):
        if hasattr(self, "group"):
            await self.channel_layer.group_discard(self.group, self.channel_name)
            await self.channel_layer.group_discard(f"user_{self.user.pk}", self.channel_name)

    async def receive_json(self, content, **kwargs):
        if not await can_read(self.user.pk, self.project_id):  # re-check on every inbound message
            await self.close(code=4403)
            return
        ...  # per-action object checks go here

    async def project_event(self, event):  # group_send(..., {"type": "project.event", ...})
        if not await can_read(self.user.pk, self.project_id):  # re-check before every delivery
            await self.close(code=4403)
            return
        await self.send_json(event["payload"])

    async def access_revoked(self, event):  # sent by the revocation handler to group f"user_{pk}"
        await self.close(code=4401)
```

Exports with Celery: re-authorise when the task runs, use the same policy as the UI, and re-authorise at download:

```python
@shared_task
def build_export(export_id):
    export = Export.objects.select_related("requested_by", "project").get(pk=export_id)
    if not can_export(export.requested_by, export.project):  # current permissions, not enqueue-time ones
        Export.objects.filter(pk=export_id).update(status="cancelled")
        return
    rows = Document.objects.visible_to(export.requested_by).filter(project=export.project)
    ...

@login_required
def download_export(request, export_id):
    export = get_object_or_404(Export, pk=export_id, requested_by=request.user, status="done")
    if not can_export(request.user, export.project):
        raise Http404
    # django-storages S3 backend: a pre-signed URL that lives for 60 seconds
    return redirect(default_storage.url(export.file.name, expire=60))
```

### Spring Security

Add a revocation validator to the resource server's `JwtDecoder` next to the default issuer and timestamp checks ([JWT resource server docs](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html)):

```java
@Bean
JwtDecoder jwtDecoder(AuthStateRepository authState) {
    NimbusJwtDecoder decoder = NimbusJwtDecoder
        .withJwkSetUri("https://app.example.com/auth/.well-known/jwks.json").build();

    OAuth2TokenValidator<Jwt> audience = new JwtClaimValidator<List<String>>(
        JwtClaimNames.AUD, aud -> aud != null && aud.contains("https://api.example.com"));

    OAuth2TokenValidator<Jwt> notRevoked = jwt -> {
        AuthState s = authState.find(jwt.getSubject());   // cached for seconds, purged on revocation
        boolean ok = s != null && s.active()
            && Objects.equals(jwt.getClaimAsString("ver"), s.tokenVersion())
            && jwt.getIssuedAt() != null && !jwt.getIssuedAt().isBefore(s.notBefore());
        return ok ? OAuth2TokenValidatorResult.success()
                  : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Token revoked", null));
    };

    decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
        JwtValidators.createDefaultWithIssuer("https://app.example.com/auth"), audience, notRevoked));
    return decoder;
}
```

Make object decisions from current data with method security, not from token authorities:

```java
@PreAuthorize("@projectAuthz.canRead(authentication, #projectId)")
@GetMapping("/v1/projects/{projectId}/members")
public List<MemberDto> members(@PathVariable String projectId) { ... }
```

For server-side sessions, Spring Session's `FindByIndexNameSessionRepository` can find and delete a user's sessions from the revocation handler:

```java
public void endAllSessions(String username) {
    sessions.findByPrincipalName(username).keySet().forEach(sessions::deleteById);
}
```

WebSocket message security with `@EnableWebSocketSecurity` authorises each inbound message, including `SUBSCRIBE` frames, through an `AuthorizationManager<Message<?>>` ([WebSocket docs](https://docs.spring.io/spring-security/reference/servlet/integrations/websocket.html)). Path variables in destination patterns are available to a custom manager through `MessageAuthorizationContext.getVariables()`:

```java
@Configuration
@EnableWebSocketSecurity
public class WebSocketSecurityConfig {

    @Bean
    AuthorizationManager<Message<?>> messageAuthorizationManager(
            MessageMatcherDelegatingAuthorizationManager.Builder messages, ProjectAuthz projectAuthz) {
        messages
            .nullDestMatcher().authenticated()
            .simpSubscribeDestMatchers("/user/queue/**").authenticated()
            .simpSubscribeDestMatchers("/topic/projects/{projectId}").access((authentication, ctx) ->
                new AuthorizationDecision(projectAuthz.canRead(authentication.get(), ctx.getVariables().get("projectId"))))
            .simpDestMatchers("/app/projects/{projectId}/**").access((authentication, ctx) ->
                new AuthorizationDecision(projectAuthz.canWrite(authentication.get(), ctx.getVariables().get("projectId"))))
            .simpTypeMatchers(SimpMessageType.MESSAGE, SimpMessageType.SUBSCRIBE).denyAll()
            .anyMessage().denyAll();
        return messages.build();
    }
}
```

That check runs when the client subscribes. Messages the broker later sends to `/topic/projects/42` go to every existing subscriber, so either send per-user (`SimpMessagingTemplate.convertAndSendToUser`) after checking each recipient, or keep topic payloads to identifiers, and close a removed user's WebSocket sessions from the revocation handler. Spring's docs also note that the WebSocket `Principal` is the one from the HTTP request that opened the connection, which is why the HTTP session's revocation has to reach the socket too.

For service-to-service calls, use the token exchange grant so the downstream service still sees the user. Spring Security's OAuth2 client supports `urn:ietf:params:oauth:grant-type:token-exchange` through `TokenExchangeOAuth2AuthorizedClientProvider` ([authorisation grants docs](https://docs.spring.io/spring-security/reference/servlet/oauth2/client/authorization-grants.html)):

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          documents-service:
            client-id: reports-service
            client-secret: "<CLIENT_SECRET>"
            authorization-grant-type: urn:ietf:params:oauth:grant-type:token-exchange
            scope: documents.read
        provider:
          documents-service:
            token-uri: https://app.example.com/auth/oauth/token
```

```java
OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
    .withClientRegistrationId("documents-service")
    .principal(jwtAuthentication)          // the end user's JwtAuthenticationToken
    .build();
OAuth2AccessToken userBoundToken = authorizedClientManager.authorize(authorizeRequest).getAccessToken();
// call the documents service with userBoundToken; it checks the user's permissions, not "reports-service"
```

On the wire, the exchange looks like this ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)):

```http
POST /auth/oauth/token HTTP/1.1
Host: app.example.com
Authorization: Basic <CLIENT_CREDENTIALS_REPORTS_SERVICE>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=<TOKEN_USER_A>&subject_token_type=urn:ietf:params:oauth:token-type:access_token&audience=documents-service&scope=documents.read
```

### Laravel

One listener for the lifecycle events, using Sanctum's token relationship and the database session driver's `user_id` column ([Sanctum docs](https://laravel.com/docs/13.x/sanctum): tokens never expire by default and are revoked by deleting them):

```php
class RevokeUserAccess
{
    public function handle(UserDeactivated|MemberRemoved $event): void
    {
        $user = $event->user;

        $user->tokens()->delete();                                  // Sanctum API and mobile tokens
        DB::table('sessions')->where('user_id', $user->id)->delete(); // database session driver
        Cache::forget("permissions:{$user->id}");
        $user->webhooks()->update(['active' => false]);            // re-attest before re-enabling
        Export::where('requested_by', $user->id)->where('status', 'queued')->update(['status' => 'cancelled']);
    }
}
```

For password changes, put the `auth.session` middleware (`AuthenticateSession`) on authenticated routes and call `Auth::logoutOtherDevices($currentPassword)`, as the [authentication docs](https://laravel.com/docs/13.x/authentication) describe.

Broadcast channel authorisation in `routes/channels.php` runs when the client subscribes (Echo calls `/broadcasting/auth`); delegate to the same policy as the HTTP routes and keep payloads to identifiers so a stale subscriber learns nothing useful ([broadcasting docs](https://laravel.com/docs/13.x/broadcasting)):

```php
// routes/channels.php
use App\Models\Project;
use App\Models\User;
use Illuminate\Support\Facades\Broadcast;

Broadcast::channel('projects.{project}', function (User $user, Project $project) {
    return $user->can('view', $project);
});
```

```php
// app/Events/DocumentUpdated.php
public function broadcastOn(): array
{
    return [new PrivateChannel('projects.'.$this->document->project_id)];
}

public function broadcastWith(): array
{
    return ['documentId' => $this->document->id, 'event' => 'updated']; // clients re-fetch via the API
}
```

Exports: a temporary signed URL limits lifetime and tampering, but it is still a bearer link, so combine `signed` with `auth` and a policy that checks the requester and their current access, then redirect to a short-lived storage URL ([URL generation docs](https://laravel.com/docs/13.x/urls)):

```php
// routes/web.php
Route::get('/exports/{export}/download', [ExportController::class, 'download'])
    ->name('exports.download')
    ->middleware(['auth', 'signed']);

// ExportController
public function download(Export $export)
{
    Gate::authorize('download', $export);
    return redirect()->away(Storage::disk('s3')->temporaryUrl($export->path, now()->addMinute()));
}

// ExportPolicy
public function download(User $user, Export $export): bool
{
    return $export->requested_by === $user->id && $user->can('export', $export->project);
}

// Sending the link: URL::temporarySignedRoute('exports.download', now()->addMinutes(30), ['export' => $export])
```

Queued jobs that receive Eloquent models re-retrieve them from the database when they run, per the [queue docs](https://laravel.com/docs/13.x/queues), so a check inside `handle()` sees current permissions:

```php
class BuildExport implements ShouldQueue
{
    use Queueable;

    public function __construct(public Export $export) {}

    public function handle(): void
    {
        $user = $this->export->requester;
        if (! $user->can('export', $this->export->project)) {
            $this->export->update(['status' => 'cancelled']);
            return;
        }
        // build rows with the same scopes the UI uses, e.g. Document::visibleTo($user)
    }
}
```

### Authorisation regression tests for revocation

Revocation bugs come back because the tests that would catch them need a second step: create a credential, change something, then use the old credential. Write that sequence once as a helper and run it for every sensitive endpoint and every credential type:

1. Arrange: create the owner, a member, a project and a test object.
2. Capture every credential the member can hold: a session, an access and refresh token pair, a PAT, an open socket, a share link, a completed export.
3. Act: apply one revocation event (role downgrade, removal, deactivation, password change, link revocation) through the real service layer, not by editing the database.
4. Assert: every old credential is refused on every endpoint in the matrix, the refresh fails, the socket is closed, the link returns `404`, the export download returns `403` or `404`, and the revocation handler emitted its audit event.

Express with Jest and supertest:

```javascript
test("removed member loses access on an existing token", async () => {
  const { accessToken } = await loginAs(member);
  const get = () => request(app).get(`/v1/projects/${project.id}/members`).set("Authorization", `Bearer ${accessToken}`);
  await get().expect(200);
  await projects.removeMember(owner, project.id, member.id); // service layer, emits the revocation event
  await get().expect(404);
});
```

Django:

```python
def test_deactivation_ends_existing_session(self):
    self.client.force_login(self.member)
    self.assertEqual(self.client.get(f"/projects/{self.project.pk}/").status_code, 200)
    deactivate_user(self.member)  # service function that runs the revocation handler
    self.assertIn(self.client.get(f"/projects/{self.project.pk}/").status_code, (302, 401, 403))
```

Laravel (Pest):

```php
it('refuses an export download after the requester leaves the project', function () {
    [$owner, $member, $project] = projectWithMember();
    $export = Export::factory()->for($project)->create(['requested_by' => $member->id, 'status' => 'done']);
    $url = URL::temporarySignedRoute('exports.download', now()->addMinutes(5), ['export' => $export]);

    app(ProjectMembers::class)->remove($project, $member);

    $this->actingAs($member)->get($url)->assertForbidden();
});
```

Spring (MockMvc with a JWT built by the test support, plus the real decoder in an integration profile):

```java
@Test
void downgradedUserCannotUseOldToken() throws Exception {
    String token = tokens.issueFor(member);                 // real issuer in the test profile
    mvc.perform(get("/v1/org/settings").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
    roles.downgrade(owner, member, Role.VIEWER);            // bumps the user's token version
    mvc.perform(get("/v1/org/settings").header("Authorization", "Bearer " + token)).andExpect(status().isUnauthorized());
}
```

## Practice labs

| Lab | What to practise | Tests |
|---|---|---|
| PortSwigger, [Multi-step process with no access control on one step](https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step) | Replaying the unprotected confirmation step of an admin role change with a normal user's session | GT-WEB-CTX-8 |
| PortSwigger, [Insufficient workflow validation](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation) | Reaching the final step of a checkout without the earlier ones | GT-WEB-CTX-8 |
| PortSwigger, [Authentication bypass via flawed state machine](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-flawed-state-machine) | Dropping a step to land in a privileged default state | GT-WEB-CTX-8 |
| PortSwigger, [Insecure direct object references](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references) | Chat transcripts served from static, incrementing file names: a download URL not bound to its owner | GT-WEB-CTX-7 |
| PortSwigger, [Cross-site WebSocket hijacking](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab) | A handshake authenticated only by cookies, without an `Origin` check | GT-WEB-CTX-9 |
| PortSwigger, [Exploiting path mapping for web cache deception](https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-path-mapping) | How a cache ends up storing one user's private response | GT-WEB-CTX-7 (cache step) |
| OWASP Juice Shop, "GDPR Data Erasure" | Logging in to an account that was supposedly erased: the deactivation case | GT-WEB-CTX-1 |
| OWASP Juice Shop, "GDPR Data Theft" | Abusing the data export to obtain another user's personal data | GT-WEB-CTX-7 |
| OWASP Juice Shop, "Deluxe Fraud" | Obtaining a paid membership by skipping the payment step | GT-WEB-CTX-8 |
| [OWASP crAPI](https://github.com/OWASP/crAPI), challenge 2 "Access mechanic reports of other users" | A report endpoint keyed only by report ID | GT-WEB-CTX-7 |
| OWASP crAPI, challenge 18 "Make the chatbot do an action on behalf of another user" | An assistant acting with more authority than the requester: a confused deputy | GT-WEB-CTX-12 |
| [VAmPI](https://github.com/erev0s/VAmPI) | A small JWT API you run locally: practise `revoke-replay.sh` and token-lifetime checks | GT-WEB-CTX-3 |

Juice Shop solutions are in the [companion guide](https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-authentication.html) (the Broken Authentication, Sensitive Data Exposure and Improper Input Validation chapters). The PortSwigger [access control](https://portswigger.net/web-security/access-control) and [WebSockets](https://portswigger.net/web-security/websockets) topic pages explain the background for each lab.

## Real-world cases

- **GitHub: removed users kept organisation access (2023).** GitHub's [changelog](https://github.blog/changelog/2023-03-16-fixed-bug-that-allowed-removed-users-to-retain-access-to-the-organization) reported that, in some cases, permissions were not fully removed when a team was deleted or when a user who was on a team was removed from the organisation. GitHub attributed it to background job and permissions issues, had applied a manual fix since October 2022, and cleaned up affected users. The lesson for testers: revocation that runs as an asynchronous job is code that can fail silently, so test the *effect* (the old credential is refused), not the UI ([GT-WEB-CTX-2](#gt-web-ctx-2-stale-authorisation-after-role-downgrade-or-removal)).
- **GitLab: `ProjectExportWorker` ignored the requester's current permissions (CVE-2020-8114).** [Issue 37468](https://gitlab.com/gitlab-org/gitlab/-/issues/37468) describes how an export scheduled by a user who then lost access to the project was still processed, because the worker did not check permissions when it ran. GitLab fixed it in its January 2020 security release; the CVE record lists GitLab EE 8.9 through 12.7.2 as affected. This is the re-authorise-at-execution case ([GT-WEB-CTX-7](#gt-web-ctx-7-exports-reports-and-download-links)).
- **GitLab: blocked user kept receiving data through GraphQL subscriptions.** [Issue 526360](https://gitlab.com/gitlab-org/gitlab/-/issues/526360), reported through HackerOne in March 2025, describes a blocked user with a personal access token who could still receive issue, merge request and pipeline updates through GraphQL subscriptions over ActionCable (`/cable`), because the blocked-user check lived in the GraphQL HTTP controller that subscriptions do not pass through. The HackerOne report itself was not public when we checked; the GitLab issue is ([GT-WEB-CTX-10](#gt-web-ctx-10-graphql-subscriptions)).
- **GitLab: demoted member kept access through a deploy key.** [Issue 416958](https://gitlab.com/gitlab-org/gitlab/-/issues/416958), reported through HackerOne in June 2023, describes a member who added a deploy key while a maintainer and kept read and write access through it after being demoted, while the owner's API view of that user's deploy keys came back empty. It combines both halves of [GT-WEB-CTX-4](#gt-web-ctx-4-api-keys-personal-access-tokens-and-oauth-grants): the credential outlived the role, and the owner could not see it.
- **AutoGPT: WebSocket subscriptions without an ownership check (CVE-2025-31494).** The [advisory GHSA-958f-37vw-jx8f](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-958f-37vw-jx8f) explains that the platform's WebSocket API sent node execution updates to whoever subscribed with a given graph ID and version, with nothing stopping a user from subscribing with another user's values; it was fixed in 0.6.1. The CNA scored it `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N` (3.5, Low) with CWE-200 and CWE-284, which shows how the exposure of the data, not the bug class, drives the rating ([GT-WEB-CTX-9](#gt-web-ctx-9-websocket-and-sse-subscriptions-and-messages)).
- **Nextcloud: share links that widened or lingered.** HackerOne report [452854](https://hackerone.com/reports/452854) (disclosed 2019) showed that after a re-shared subfolder link with an expiry date had expired, it gave access to the whole parent folder. An earlier report, [146133](https://hackerone.com/reports/146133) (disclosed 2018, a $50 bounty according to the report data), showed that changing a password-protected share's password did not force recipients who had already entered it to authenticate again ([GT-WEB-CTX-5](#gt-web-ctx-5-share-link-token-strength-expiry-and-revocation), [GT-WEB-CTX-6](#gt-web-ctx-6-share-link-scope-audience-and-sharer-lifecycle)).

More write-ups are collected in our [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

Rate on what the stale or side-door access yields, who can use it, and for how long. A revocation failure is exploitable mainly by insiders and former insiders (`PR:L`, because they once held a legitimate account), which is exactly the population that revocation exists for. Measure and state the window: a few minutes of a documented token lifetime is a different finding from access that never ends. Where exploiting a finding needs a race (removing the user while a job runs) or possession of a link someone else must have shared, raise `AC` to `H`.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Deactivated or removed user keeps read and write access indefinitely (sessions, refresh tokens or API keys) | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1) | Former insider retains full use of the account's authority; no time limit |
| Removed member keeps read access to project or organisation data | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | High confidentiality impact for sensitive data; raise to High for PII, financial or health data at scale |
| Role downgrade not applied until logout; admin functions still usable | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Admin functions include destructive actions; window is unbounded |
| Access token honoured for its remaining lifetime (minutes, documented) after downgrade | Low | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N` (4.2) | Short window that the attacker cannot extend; report the measured time |
| Share tokens predictable (sequential, timestamp, encoded ID) | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | Unauthenticated access to every shared file; severity follows the content |
| Expired or revoked share link still works | Medium | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (5.9) | Needs a link that was legitimately issued; owner believes access ended |
| Link to one file exposes the folder or other files | Medium to High | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (5.9) | Link holder reaches unshared content; `AC:L` (7.5) if links are routinely public |
| Export or report download not bound to the requester, guessable ID | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Any user obtains bulk data; unauthenticated variant is 7.5 |
| Queued export completes after the requester lost access | Medium | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N` (5.3) | Needs timing around removal; yields a full export |
| Unprivileged user completes a privileged step of a multi-step process | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Typically self-promotion to administrator, as in the PortSwigger lab |
| WebSocket or GraphQL subscription to other users' objects | Medium | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Live stream of others' data; Low if events carry only IDs, cross-tenant raises it |
| Open socket keeps receiving events after removal | Low to Medium | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N` (5.3) | Limited to connections opened before removal; content decides |
| Member-registered webhook receives events for objects the member cannot read, continuing after removal | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Standing outbound feed; High when payloads carry full sensitive objects |
| Confused deputy: worker or internal service returns other users' or tenants' data | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Scope Unchanged when the worker is part of the same application, even if the data belongs to another tenant (series convention). Use `S:C` (7.7) only when the data is governed by a separately authorised downstream service. Rate High in the narrative when the data is sensitive or the reach is broad. |
| Owner cannot see or revoke credentials created by former members, with no working bypass shown | Low or Informational | none | Offboarding weakness; rate higher only with a demonstrated stale credential |
| Share or revoke button hidden in the UI, but the server enforces correctly | Informational | none | No reachable server-side gap |

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 / API Top 10 |
|---|---|---|---|---|
| GT-WEB-CTX-1 | WSTG-SESS-06, WSTG-SESS-07, WSTG-SESS-11 | v5.0.0-7.4.1 (L1), v5.0.0-7.4.2 (L1), v5.0.0-7.4.3 (L2), v5.0.0-7.4.5 (L2), v5.0.0-7.3.1 (L2), v5.0.0-7.3.2 (L2) | CWE-1464, CWE-1465, CWE-1466, CWE-1463 | A07:2025; API2:2023 |
| GT-WEB-CTX-2 | WSTG-ATHZ-02 | v5.0.0-8.3.2 (L3), v5.0.0-8.2.1 (L1), v5.0.0-8.2.2 (L1) | CWE-284, CWE-863 | A01:2025; API1:2023, API5:2023 |
| GT-WEB-CTX-3 | WSTG-SESS-10, WSTG-SESS-06 | v5.0.0-7.4.1 (L1), v5.0.0-7.4.2 (L1), v5.0.0-9.2.1 (L1), v5.0.0-10.4.8 (L2), v5.0.0-10.4.9 (L2), v5.0.0-8.3.2 (L3) | CWE-1464, CWE-863 | A07:2025, A01:2025; API2:2023 |
| GT-WEB-CTX-4 | WSTG-ATHZ-02, WSTG-ATHZ-05 | v5.0.0-7.4.2 (L1), v5.0.0-10.4.9 (L2), v5.0.0-10.7.3 (L2), v5.0.0-8.3.2 (L3) | CWE-1464, CWE-284 | A01:2025, A07:2025; API2:2023 |
| GT-WEB-CTX-5 | WSTG-ATHZ-04, WSTG-ATHZ-02 | v5.0.0-8.2.2 (L1), v5.0.0-11.5.1 (L2), v5.0.0-14.2.1 (L1) | CWE-639, CWE-340, CWE-1469 | A01:2025, A04:2025; API1:2023 |
| GT-WEB-CTX-6 | WSTG-ATHZ-02 | v5.0.0-8.2.2 (L1), v5.0.0-8.3.2 (L3) | CWE-863, CWE-639, CWE-1469 | A01:2025; API1:2023 |
| GT-WEB-CTX-7 | WSTG-ATHZ-04, WSTG-ATHZ-02 | v5.0.0-8.2.2 (L1), v5.0.0-8.3.2 (L3), v5.0.0-14.2.2 (L2), v5.0.0-14.3.2 (L2) | CWE-639, CWE-862, CWE-200, CWE-524 | A01:2025; API1:2023 |
| GT-WEB-CTX-8 | WSTG-BUSL-06, WSTG-ATHZ-02 | v5.0.0-2.3.1 (L1), v5.0.0-8.2.1 (L1), v5.0.0-2.3.5 (L3) | CWE-841, CWE-862 | A01:2025, A06:2025; API5:2023 |
| GT-WEB-CTX-9 | WSTG-CLNT-10, WSTG-ATHZ-02, WSTG-ATHZ-04 | v5.0.0-4.4.2 (L2), v5.0.0-4.4.4 (L2), v5.0.0-8.2.2 (L1), v5.0.0-8.3.2 (L3) | CWE-862, CWE-639, CWE-200 | A01:2025; API1:2023 |
| GT-WEB-CTX-10 | WSTG-APIT-99, WSTG-CLNT-10 | v5.0.0-8.2.2 (L1), v5.0.0-8.2.3 (L2), v5.0.0-8.3.2 (L3) | CWE-862, CWE-200 | A01:2025; API1:2023, API3:2023 |
| GT-WEB-CTX-11 | WSTG-ATHZ-02, WSTG-ATHZ-03 | v5.0.0-8.2.1 (L1), v5.0.0-8.2.2 (L1), v5.0.0-8.3.2 (L3) | CWE-862, CWE-200 | A01:2025; API1:2023, API5:2023 |
| GT-WEB-CTX-12 | WSTG-ATHZ-02, WSTG-ATHZ-04 | v5.0.0-8.3.3 (L3), v5.0.0-8.3.1 (L1) | CWE-441, CWE-639 | A01:2025; API1:2023 |

A note on CWE-613 (Insufficient Session Expiration): older reports, scanners and the OWASP Top 10:2025 mapping for A07 still use it, but CWE 5.0 (October 2026) deprecated it and marked it prohibited for mapping, suggesting CWE-1462 (Improper Session Management) and its children, CWE-1463 (Insufficient Session Timeout Value) and CWE-1464 (Improper Session Invalidation), instead. CWE-1465 and CWE-1466 cover invalidation after logout and after a credential change. We map to the new entries above.

## References

**OWASP Web Security Testing Guide**

- [WSTG-ATHZ-02 Testing for Bypassing Authorization Schema](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/02-Bypassing_Authorization_Schema/)
- [WSTG-ATHZ-04 Testing for Insecure Direct Object References](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/04-Insecure_Direct_Object_References/)
- [WSTG-BUSL-06 Testing for the Circumvention of Work Flows](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/10-Business_Logic/06-Circumvention_of_Work_Flows/)
- [WSTG-SESS-06 Testing for Logout Functionality](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/06-Session_Management/06-Logout_Functionality/)
- [WSTG-SESS-07 Testing Session Timeout](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/06-Session_Management/07-Session_Timeout/)
- [WSTG-SESS-10 Testing JSON Web Tokens](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/06-Session_Management/10-JSON_Web_Tokens/)
- [WSTG-SESS-11 Testing for Concurrent Sessions](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/06-Session_Management/11-Concurrent_Sessions/)
- [WSTG-CLNT-10 Testing WebSockets](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/10-WebSockets/)
- [WSTG-APIT-99 Testing GraphQL](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/99-GraphQL/)

**OWASP ASVS 5.0, Top 10 and API Security Top 10**

- [ASVS 5.0 source (GitHub)](https://github.com/OWASP/ASVS/tree/master/5.0/en): [V8 Authorization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md), [V7 Session Management](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x16-V7-Session-Management.md), [V9 Self-contained Tokens](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x18-V9-Self-contained-Tokens.md), [V4 API and Web Service](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x13-V4-API-and-Web-Service.md), [V10 OAuth and OIDC](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x19-V10-OAuth-and-OIDC.md)
- [OWASP Top 10:2025](https://top10.owasp.org/2025/) and [A01:2025 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control)
- OWASP API Security Top 10 2023: [API1 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [API2 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [API5 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)

**OWASP Cheat Sheets**

- [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [Insecure Direct Object Reference Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html), [Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html), [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [WebSocket Security](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html), [Microservices Security](https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html)

**CWE**

- [CWE-284](https://cwe.mitre.org/data/definitions/284.html), [CWE-441](https://cwe.mitre.org/data/definitions/441.html), [CWE-639](https://cwe.mitre.org/data/definitions/639.html), [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html), [CWE-863](https://cwe.mitre.org/data/definitions/863.html), [CWE-841](https://cwe.mitre.org/data/definitions/841.html), [CWE-340](https://cwe.mitre.org/data/definitions/340.html), [CWE-524](https://cwe.mitre.org/data/definitions/524.html), [CWE-1463](https://cwe.mitre.org/data/definitions/1463.html), [CWE-1464](https://cwe.mitre.org/data/definitions/1464.html), [CWE-1465](https://cwe.mitre.org/data/definitions/1465.html), [CWE-1466](https://cwe.mitre.org/data/definitions/1466.html), [CWE-1469](https://cwe.mitre.org/data/definitions/1469.html), [CWE-613 (deprecated)](https://cwe.mitre.org/data/definitions/613.html)

**Standards and specifications**

- [RFC 7009 OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009), [RFC 7662 OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662), [RFC 8693 OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [OpenID Continuous Access Evaluation Profile 1.0](https://openid.net/specs/openid-caep-1_0.html) (a `session-revoked` event for pushing revocations between providers and relying parties) and the [Shared Signals Framework](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)
- [W3C TAG: Good Practices for Capability URLs](https://www.w3.org/TR/capability-urls/)
- [GraphQL subscriptions](https://graphql.org/learn/subscriptions/)
- [AWS: Download and upload objects with presigned URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html)

**PortSwigger Web Security Academy**

- [Access control](https://portswigger.net/web-security/access-control), [WebSockets](https://portswigger.net/web-security/websockets), [Cross-site WebSocket hijacking](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking), [JWT attacks](https://portswigger.net/web-security/jwt), [Web cache deception](https://portswigger.net/web-security/web-cache-deception)

**Framework documentation**

- Express and Socket.IO: [express-session](https://expressjs.com/en/resources/middleware/session.html), [Socket.IO middlewares](https://socket.io/docs/v4/middlewares/), [Socket.IO rooms](https://socket.io/docs/v4/rooms/), [Socket.IO with express-session](https://socket.io/how-to/use-with-express-session), [jose](https://github.com/panva/jose)
- Django: [Using the authentication system](https://docs.djangoproject.com/en/6.0/topics/auth/default/), [Cryptographic signing](https://docs.djangoproject.com/en/6.0/topics/signing/), [Channels authentication](https://channels.readthedocs.io/en/latest/topics/authentication.html), [Channels consumers](https://channels.readthedocs.io/en/latest/topics/consumers.html), [Simple JWT blacklist app](https://django-rest-framework-simplejwt.readthedocs.io/en/latest/blacklist_app.html), [django-storages S3 backend](https://django-storages.readthedocs.io/en/latest/backends/amazon-S3.html)
- Spring Security: [WebSocket security](https://docs.spring.io/spring-security/reference/servlet/integrations/websocket.html), [OAuth2 resource server JWT](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html), [OAuth2 client authorisation grants (token exchange)](https://docs.spring.io/spring-security/reference/servlet/oauth2/client/authorization-grants.html), [Session management](https://docs.spring.io/spring-security/reference/servlet/authentication/session-management.html)
- Laravel: [Broadcasting](https://laravel.com/docs/13.x/broadcasting), [URL generation and signed URLs](https://laravel.com/docs/13.x/urls), [Authentication](https://laravel.com/docs/13.x/authentication), [Authorization](https://laravel.com/docs/13.x/authorization), [Sanctum](https://laravel.com/docs/13.x/sanctum), [Queues](https://laravel.com/docs/13.x/queues)

**Tools**

- [Autorize](https://github.com/Quitten/Autorize), [Auth Analyzer](https://github.com/portswigger/auth-analyzer), [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix), [InQL](https://github.com/doyensec/inql), [clairvoyance](https://github.com/nikitastupin/clairvoyance), [websocat](https://github.com/vi/websocat), [ZAP Access Control Testing add-on](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/)
