---
title: "NoSQL Injection: MongoDB Operators, JavaScript Evaluation and Beyond"
date: 2026-11-15 20:02:00 +0000
subcategory: injection
summary: "Testing NoSQL injection: MongoDB operator and type confusion, query-string parsers, $where and server-side JS, pipelines, Elasticsearch and safe fixes."
refs: [WSTG-INJT-05, WSTG-INJT-04, WSTG-INJT-11, WSTG-ATHN-04, v5.0.0-1.2.4, v5.0.0-1.2.9, v5.0.0-1.3.2, v5.0.0-15.3.5, v5.0.0-2.2.1, "A05:2025", CWE-943, CWE-1287, CWE-95]
tags: [web, injection, nosql-injection, mongodb, api-security, elasticsearch]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Injection](/web/web-injection-testing-guide/). It covers injection into non-relational data stores, with MongoDB as the main case because it is where most findings come from: **operator injection** (a JSON object such as `{"$ne": null}` arriving where the code expected a string), **type confusion** introduced by JSON bodies and bracket-style query-string parsers, **syntax injection** into queries built as strings, **server-side JavaScript** through `$where`, `$function`, `$accumulator` and map-reduce, and **aggregation pipeline** injection. It then covers the same ideas in Elasticsearch, CouchDB Mango, DynamoDB and Redis, and GraphQL resolvers that forward filters to the database. In WSTG this is the NoSQL Injection sub-page of `WSTG-INJT-05` (section 4.7.5.6; the sub-page has no test ID of its own). You get the model, the variants, twelve tests that stop at the least invasive proof, and fixes in Node.js (Mongoose and the MongoDB driver), Django and PyMongo, Spring Data MongoDB and Laravel MongoDB. The relational side is in [SQL injection](/web/web-sql-injection/); `__proto__` keys arriving through the same JSON bodies are in [server-side prototype pollution](/web/web-server-side-prototype-pollution/); JavaScript or expression-language evaluation outside the database is in [server-side template injection](/web/web-server-side-template-injection/).

## Contents

- [How it works](#how-it-works)
  - [Queries are data structures, not strings](#queries-are-data-structures-not-strings)
  - [How a request value becomes a filter](#how-a-request-value-becomes-a-filter)
  - [Operators that matter to a tester](#operators-that-matter-to-a-tester)
  - [Where JavaScript runs](#where-javascript-runs)
  - [Other stores in one table](#other-stores-in-one-table)
- [What goes wrong](#what-goes-wrong)
  - [Request objects passed straight into filters](#request-objects-passed-straight-into-filters)
  - [Bracket parsers turn query strings into objects](#bracket-parsers-turn-query-strings-into-objects)
  - [Type confusion in authentication and token checks](#type-confusion-in-authentication-and-token-checks)
  - [Queries built as strings](#queries-built-as-strings)
  - [User input inside server-side JavaScript](#user-input-inside-server-side-javascript)
  - [User-controlled regular expressions](#user-controlled-regular-expressions)
  - [Client-supplied pipelines, sorts and projections](#client-supplied-pipelines-sorts-and-projections)
  - [Denylist sanitisers with gaps](#denylist-sanitisers-with-gaps)
  - [Search query syntax exposed to users](#search-query-syntax-exposed-to-users)
  - [GraphQL and generic filter APIs](#graphql-and-generic-filter-apis)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-WEB-NOSQL-1: Fingerprint the data store and map query inputs](#gt-web-nosql-1-fingerprint-the-data-store-and-map-query-inputs)
  - [GT-WEB-NOSQL-2: Type confusion with objects, arrays and non-strings](#gt-web-nosql-2-type-confusion-with-objects-arrays-and-non-strings)
  - [GT-WEB-NOSQL-3: Operator injection in JSON bodies](#gt-web-nosql-3-operator-injection-in-json-bodies)
  - [GT-WEB-NOSQL-4: Operator injection through query-string and form parsers](#gt-web-nosql-4-operator-injection-through-query-string-and-form-parsers)
  - [GT-WEB-NOSQL-5: Login and token-check bypass on your own account](#gt-web-nosql-5-login-and-token-check-bypass-on-your-own-account)
  - [GT-WEB-NOSQL-6: Syntax injection into string-built queries](#gt-web-nosql-6-syntax-injection-into-string-built-queries)
  - [GT-WEB-NOSQL-7: Boolean and regex response differences](#gt-web-nosql-7-boolean-and-regex-response-differences)
  - [GT-WEB-NOSQL-8: Server-side JavaScript evaluation](#gt-web-nosql-8-server-side-javascript-evaluation)
  - [GT-WEB-NOSQL-9: Aggregation pipeline, sort and projection injection](#gt-web-nosql-9-aggregation-pipeline-sort-and-projection-injection)
  - [GT-WEB-NOSQL-10: Elasticsearch, CouchDB, DynamoDB and Redis](#gt-web-nosql-10-elasticsearch-couchdb-dynamodb-and-redis)
  - [GT-WEB-NOSQL-11: GraphQL resolvers and generic filter APIs](#gt-web-nosql-11-graphql-resolvers-and-generic-filter-apis)
  - [GT-WEB-NOSQL-12: Configuration and code review](#gt-web-nosql-12-configuration-and-code-review)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Node.js with Mongoose and the MongoDB driver](#nodejs-with-mongoose-and-the-mongodb-driver)
  - [Elasticsearch from Node.js](#elasticsearch-from-nodejs)
  - [Django and PyMongo](#django-and-pymongo)
  - [Spring Data MongoDB](#spring-data-mongodb)
  - [Laravel MongoDB](#laravel-mongodb)
  - [Database configuration](#database-configuration)
  - [Static analysis](#static-analysis)
  - [Regression tests with malicious-looking input](#regression-tests-with-malicious-looking-input)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Queries are data structures, not strings

In SQL the application usually sends the database a *string*, and injection means changing the grammar of that string. MongoDB drivers send a *document*: a nested map of field names, values and operators, serialised as BSON. The query "find the user called alice" is the object `{ "username": "alice" }`, and the query "find any user whose name is not alice" is `{ "username": { "$ne": "alice" } }`. Nothing in the protocol distinguishes a value from an operator except its **type**: a string is a value, an object whose keys start with `$` is an operator expression.

That is why MongoDB injection is mostly not about quotes. The driver escapes strings correctly; the problem is that the application lets the *client* decide whether a field holds a string or an object. If the code does `users.findOne({ username: body.username, password: body.password })` and `body.password` is `{"$ne": null}`, the driver faithfully sends an operator, and the database answers "a user called alice whose password is not null". In SQL terms that is `WHERE username = 'alice' AND password IS NOT NULL`, produced without a single quote character in the input. The WSTG NoSQL page makes the same point from the other side: filters for HTML special characters do nothing against a JSON API, where the special characters are `{ } : $`.

Two families follow from this, and PortSwigger's Web Security Academy uses the same split:

- **Operator injection.** The client supplies a structure (an object, an array, a `$`-prefixed key) where the application expected a scalar. It needs no syntax breaking and is by far the most common real finding.
- **Syntax injection.** The application builds the query *text* itself: a JSON template filled by string interpolation and then parsed, a JavaScript string for `$where`, an Elasticsearch `query_string`, a PartiQL statement, a Redis Lua script. This is classic injection: quotes, brackets and operators in the input change the grammar.

### How a request value becomes a filter

Follow one value from the wire to the database and you know where to test:

1. **Parsing.** The framework turns the HTTP request into a native structure. A JSON body can carry any type (string, number, boolean, null, array, object). URL-encoded bodies and query strings carry strings *unless* the parser supports bracket syntax: PHP, Ruby's Rack and the `qs` library used by Express's "extended" parser turn `user[$ne]=x` into `{ user: { "$ne": "x" } }`. Repeated keys (`?id=1&id=2`) become arrays in many parsers, including Node's built-in `querystring`.
2. **Validation.** A schema validator (zod, joi, a DRF serializer, a Spring DTO, Laravel validation) either rejects the unexpected type or lets it through. Code that only checks "is present" or "matches a regex" often coerces or skips objects.
3. **Query building.** The handler either assembles a new filter from known fields (`{ username: String(u) }`), or forwards a request object (`Model.find(req.query)`, `collection.find(req.body.filter)`), or builds a string.
4. **ODM casting.** Mongoose casts filter values to the schema type, but casting keeps operators: `{ password: { $ne: null } }` is a valid filter on a `String` field. Mongoose does **not** cast aggregation pipelines at all (its query documentation says so), so `Model.aggregate(userInput)` gets no help.
5. **Execution.** The server evaluates the filter, and for `$where`, `$function`, `$accumulator` and map-reduce, runs JavaScript.

Most frameworks with typed request binding (Spring DTOs with `String` fields, DRF `CharField`, Laravel's `string` validation rule) stop the object at step 2. Dynamic stacks (Express, Koa, Flask, Meteor methods, PHP without validation) carry it all the way through. Note also the Express 5 change: the default query parser moved from "extended" (`qs`) to "simple" (Node's `querystring`), and `express.urlencoded()` now defaults to `extended: false`. A fresh Express 5 app therefore does not parse `user[$ne]=` in the query string into an object, while an Express 4 app, or an Express 5 app that set `app.set('query parser', 'extended')`, does. JSON bodies are unaffected by either setting.

### Operators that matter to a tester

| Operator | What it does | Why it matters in injection |
|---|---|---|
| `$ne`, `$gt`, `$gte`, `$lt` | Comparison | `{"$ne": null}` or `{"$gt": ""}` matches almost any string: the classic login and token bypass |
| `$in`, `$nin` | Set membership | `{"$in": ["admin", "root"]}` tries several values in one request |
| `$exists`, `$type` | Field presence and BSON type | Probes for fields that are not in the API at all (`resetToken`, `isAdmin`) |
| `$regex` (with `$options`) | Regular-expression match | Boolean oracle character by character; also a CPU cost when patterns are unanchored |
| `$or`, `$and`, `$nor` | Logical combination | Widens a query that was meant to be scoped, if the client controls a top-level key |
| `$where` | JavaScript expression evaluated per document | Code evaluation in the database; reads any field of the current document |
| `$expr` | Aggregation expressions inside a find | Cross-field comparisons, and a route to `$function` |
| `$function`, `$accumulator` | JavaScript in aggregation expressions | Server-side JavaScript, like `$where` |
| `$lookup`, `$unionWith` | Join another collection in a pipeline | Reads collections the endpoint never meant to expose |
| `$out`, `$merge` | Write pipeline results to a collection | State-changing; never use in testing |

### Where JavaScript runs

MongoDB evaluates JavaScript for four features: the `$where` query operator, the `$function` and `$accumulator` aggregation operators, and map-reduce (deprecated since MongoDB 5.0). Server-side scripting is **enabled by default**. MongoDB's documentation says to disable it when you do not use those features, with `security.javascriptEnabled: false` in the configuration file or the `--noscripting` command-line option, for both `mongod` and `mongos`. Inside `$where`, the code sees the current document as `this` (or `obj`) and a small set of helpers (`sleep()`, `hex_md5()`, `tojson()`, `ObjectId()` and a few others), but not the `db` object that `mongosh` offers. MongoDB's own `$where` page recommends `$expr` with ordinary aggregation operators instead, and `$function` over `$where` when custom logic is unavoidable.

So the database-side impact of `$where` injection is usually: read any field of every document the query touches (through a boolean or error oracle), and burn CPU per document. It is not, by itself, operating-system command execution on the database host. The picture changes when the **application** evaluates query-like objects in its own process: Mongoose's `populate()` match filters were also evaluated in Node.js by the `sift` library, and that is how CVE-2024-53900 and CVE-2025-23061 became code execution on the application server (see [Real-world cases](#real-world-cases)). Ask where each filter is *evaluated*, not just where it is sent.

### Other stores in one table

| Store | Query form | Typical injection shape | Safe form |
|---|---|---|---|
| MongoDB | BSON documents, `$` operators; JavaScript in four features | Object instead of scalar; string-built JSON; `$where` strings; client pipelines | Build filters from validated scalars; `$eq` for literals; scripting off |
| Elasticsearch / OpenSearch | Query DSL (JSON); `query_string` mini-language | User text in `query_string` reaches field selection, `OR`, wildcards and regex; JSON built by concatenation; client-supplied query objects | `match` or `simple_query_string` with user text as a value; fixed fields; filters for scoping |
| CouchDB | Mango selectors (`$eq`, `$gt`, `$regex`, `$or`, `$exists`) | Same operator injection as MongoDB when request values are placed in a selector | Scalar validation; selectors built server-side |
| DynamoDB | Expressions with `:value` and `#name` placeholders; PartiQL | Expression fragments or attribute names concatenated from input; PartiQL statements built as strings | `ExpressionAttributeValues`, `ExpressionAttributeNames`, PartiQL `Parameters` |
| Redis | Binary-safe commands; Lua via `EVAL` | Lua script bodies built from strings; user strings split into extra command arguments; key and glob-pattern injection; raw protocol written by hand | Client library calls with each argument separate; fixed scripts with `KEYS`/`ARGV` |

Redis's own security page states the baseline: the protocol has no concept of string escaping and uses length-prefixed, binary-safe strings, so injection is impossible under normal circumstances with a normal client library, and Lua scripts should not be composed from untrusted strings. When you find Redis injection, it is almost always because the application stepped outside the normal library call.

## What goes wrong

### Request objects passed straight into filters

**What happens:** the handler uses a parsed request structure as the filter, or as one value inside it: `User.findOne({ email: req.body.email, password: req.body.password })`, `Product.find(req.query)`, `collection.find({ owner: user.id, ...req.body.filter })`. The developer thinks of `req.body.email` as a string because the front end always sends one.

**Why it matters:** the client chooses the type. An object value becomes an operator expression; an object as the *whole* filter lets the client add any field and any top-level operator (`$or`, `$where`, `$expr`). Spread syntax is particularly bad: `{ owner: user.id, ...req.body.filter }` lets the client overwrite `owner` itself.

**Where to look:** login, password reset, invitation and email-verification handlers; search and list endpoints with filters; "advanced search" features; admin grids that pass column filters through; Meteor methods and other RPC-style APIs whose arguments are arbitrary JSON.

### Bracket parsers turn query strings into objects

**What happens:** an endpoint that only ever receives `GET /api/users?role=editor` also accepts `GET /api/users?role[$ne]=editor`, because the query-string parser (PHP natively, Rack, `qs`) built a nested object. The same applies to `application/x-www-form-urlencoded` login forms parsed with an extended parser.

**Why it matters:** testers who only try JSON bodies miss it, and so do applications that validated "the JSON API" but not the classic form post. It is also where WSTG's PHP note comes in: in PHP, `$where` and other operators are written in single quotes in code precisely because a double-quoted `"$where"` would be interpolated as a PHP variable.

**Where to look:** server-rendered login forms, legacy `GET` search pages, PHP and Ruby applications on MongoDB, Express 4 apps (default "extended" parser) and any Express 5 app with `app.set('query parser', 'extended')` or `express.urlencoded({ extended: true })`.

### Type confusion in authentication and token checks

**What happens:** a lookup that should match exactly one secret value is made with a client-typed value: `{ email, password }`, `{ resetToken: body.token }`, `{ apiKey: req.headers['x-api-key'] }` (headers are strings, so this one is usually safe), `{ inviteCode: body.code, used: false }`, `{ otp: body.otp, userId }`. An operator such as `$ne`, `$gt`, `$regex` or `$exists` turns "equals this secret" into "matches any secret".

**Why it matters:** this is the textbook NoSQL authentication bypass. It ranges from logging in as the first user in the collection (often an administrator, because the first account created is the admin), to redeeming any reset token or coupon, to leaking a token character by character with `$regex` (the Rocket.Chat case in [Real-world cases](#real-world-cases)). Applications that hash passwords and compare in code (`bcrypt.compare(body.password, user.hash)`) are not vulnerable on the password field, but are still vulnerable on the *username* field if it accepts `{"$ne": null}` or `{"$regex": "^adm"}`.

**Where to look:** login, MFA verification, password reset confirmation, email verification, invite acceptance, coupon and voucher redemption (crAPI's NoSQL challenge is a coupon), API-key lookups taken from bodies or cookies rather than headers.

### Queries built as strings

**What happens:** the code builds query text and parses it: `JSON.parse('{"name":"' + q + '"}')`, `new BasicQuery("{ name: '" + q + "' }")` in Spring, a Handlebars or Mustache template with escaping turned off that fills a stored MongoDB query (the Budibase advisories in [Real-world cases](#real-world-cases)), a `$where` string with user text in it, an Elasticsearch body assembled with template literals, a PartiQL statement concatenated in DynamoDB.

**Why it matters:** now quotes and braces matter again. A `"` in the input closes the string and lets the attacker add keys or operators, even if the code later uses safe driver calls. The detection looks like SQL injection: a syntax error on `"` or `'`, then a working query when the character is escaped or balanced.

**Where to look:** low-code platforms and "saved query" features with variable substitution, reporting modules, code that reads queries from configuration and fills placeholders, and anything that calls `JSON.parse` or `eval` on a string containing request data.

### User input inside server-side JavaScript

**What happens:** user input is placed in a `$where` expression (`{ $where: "this.category == '" + c + "'" }`), in the body of a `$function`, or the client may supply `$where` directly through an object filter. WSTG's examples are this shape: an expression such as `this.credits - this.debits < $userInput`.

**Why it matters:** the input becomes code. Within the database's JavaScript context it can read every field of each document, return `true` for every document, and run loops or `sleep()` per document. WSTG notes that a crafted loop can keep the whole MongoDB instance busy, which is why the safe proof in [GT-WEB-NOSQL-8](#gt-web-nosql-8-server-side-javascript-evaluation) avoids delays. Where the same filter is also evaluated in the application process (the Mongoose `populate()` case), the impact becomes application-server code execution.

**Where to look:** older MongoDB code (`$where` was a common way to express cross-field conditions before `$expr` existed), dynamic report builders, and any filter object that reaches the database without a key allowlist.

### User-controlled regular expressions

**What happens:** a "starts with" or "contains" search is written as `{ name: { $regex: q } }` or `{ name: new RegExp(q, 'i') }` without escaping. Or the client may send `$regex` itself through operator injection.

**Why it matters:** two separate problems. First, metacharacters change the match (`.*` matches everything, `^` anchors), which is a boolean oracle against fields you cannot see. ASVS `v5.0.0-1.2.9` (L2) requires escaping regex metacharacters for this reason. Second, an attacker-chosen pattern applied to many documents costs CPU, and pathological patterns cost far more (`v5.0.0-1.3.12`, L3, covers ReDoS). Regex queries generally cannot use indexes efficiently unless they are case-sensitive prefix expressions, so an unanchored pattern often means a full collection scan.

**Where to look:** search boxes, autocomplete, admin user lookups, "filter by email domain" features.

### Client-supplied pipelines, sorts and projections

**What happens:** the API accepts more than filter values: a `sort` object (`?sort[password]=1`), a projection (`fields=password,resetToken`), a `pipeline` array for an analytics endpoint, or a `$match` stage built from the request. The client then adds stages: `$lookup` into the `users` collection, `$unionWith` another collection, `$project` of hidden fields, `$function` with JavaScript, or `$out` and `$merge` that write.

**Why it matters:** a pipeline is a small program. With `$lookup` or `$unionWith` it reads any collection the database user can read; with `$out` or `$merge` it writes. Sort-only control is weaker but still an oracle: sorting by a hidden field reveals its order. Projection control is a property-level authorisation problem as much as injection (see [mass assignment and BOPLA](/web/web-mass-assignment-bopla/)).

**Where to look:** dashboards, reporting and export endpoints, "charts" features, admin data grids, APIs that advertise a MongoDB-like query language to their clients.

### Denylist sanitisers with gaps

**What happens:** the application relies on removing dangerous keys instead of enforcing types: a middleware that deletes keys starting with `$`, a recursive "strip operators" helper, a check that `JSON.stringify(body)` does not contain `"$`. The OWASP NoSQL Security Cheat Sheet discusses the last one and points out it is a denylist that also blocks legitimate `$` strings.

**Why it matters:** denylists miss things. They may run on `req.body` but not on `req.query`, on parsed bodies but not on GraphQL variables or WebSocket messages, on keys but not on dotted paths, or not at all after a framework upgrade. `express-mongo-sanitize`, the best-known Express middleware for this, describes itself as Express 4.x middleware; at the time of writing its last npm release (2.2.0) dates from January 2022 and open issues report that it fails on Express 5, where `req.query` became a read-only getter. An open issue also reports bypasses in 2.2.0 itself. A sanitiser like this is defence in depth at best, and a gap in one is a finding about the control, separate from whether a query is actually injectable.

**Where to look:** `package.json` and middleware setup in greybox tests; behaviour differences between JSON, form and query-string inputs in black-box tests.

### Search query syntax exposed to users

**What happens:** a search box value is passed to Elasticsearch or OpenSearch as a `query_string` query, often wrapped in an application filter: `"query": "tenant_id:42 AND (" + q + ")"`. The `query_string` mini-language supports field selection (`status:active`), boolean operators, wildcards and `/regex/`.

**Why it matters:** the user can address fields the UI never exposes, widen the query past a scoping clause written in the same string, and run expensive wildcard or regex terms. Elastic's own documentation recommends against `query_string` for search boxes because it returns an error for any invalid syntax, and suggests `match` (no syntax) or `simple_query_string` (limited syntax) instead.

**Where to look:** site search, log and ticket search, any API that returns Elasticsearch-style errors (`query_shard_exception`, `parse_exception`), and multi-tenant search where tenancy is a clause inside the query text rather than a separate filter.

### GraphQL and generic filter APIs

**What happens:** a GraphQL field takes a `filter` or `where` argument typed as a JSON scalar (or a loosely typed input object), and the resolver forwards it: `resolve: (_, { filter }) => Order.find({ ...filter, owner: ctx.user.id })`. REST equivalents accept `?filter={"status":"open"}` and `JSON.parse` it into the query.

**Why it matters:** GraphQL's type system protects you only if the schema actually types the argument. A JSON scalar is a hole straight to the database, and the spread order decides whether the owner scope survives. Prisma's MongoDB support has typed filters, but its raw methods (`findRaw`, `aggregateRaw`) take MongoDB documents and need the same care.

**Where to look:** InQL or introspection output for arguments typed `JSON`, `JSONObject`, `Any` or `Object`; REST parameters whose values are JSON.

## Testing

Every test here assumes an authorised engagement with written scope and rules of engagement, a bug bounty programme whose rules allow injection testing, or a deliberately vulnerable lab. The requests and responses shown are illustrative, written for this note against fictional hosts; they are not captured from a real system.

### Before you start

**Scope.** Before the first payload, agree in writing:

- which hosts and endpoints are in scope, and whether testing happens against production, a staging copy or both. Ask for staging with production-like data volumes if you need to test server-side JavaScript or regex behaviour, because both scale with collection size;
- whether **time-based or CPU-costing proofs** are allowed at all. Our default is no: NoSQL injection can almost always be confirmed with a boolean difference or an error, and `$where` runs once per scanned document, so a two-second delay can become minutes on a large collection;
- which **accounts** you may use. For login and token checks you need your own test account (and ideally a second one) with a known email and password, and a way to trigger your own reset tokens, invites and coupons;
- who to call if something looks wrong (slow responses, errors that continue after you stop).

**Proxy.** One Burp project per engagement with the target scope set and Logger on. Useful additions: **Content Type Converter** (BApp) to turn a form or query-string request into JSON and back, because the same endpoint often behaves differently per content type; **NoSQLi Scanner** (BApp) as a passive and active detection aid; Repeater tabs grouped per endpoint so you can compare baseline, true and false variants side by side; Comparer for response diffs. Prefer manual Repeater work over Intruder for this class. If you use Intruder, cap it at a handful of payloads per parameter and one or two requests per second.

**Collaborator.** Out-of-band interaction is rarely the right proof here: MongoDB's `$where` context has no network functions, and most stores in this note have no built-in way to call out. Keep Burp Collaborator or interactsh for the cases where the injected value flows into something that does fetch (a webhook URL stored by the query, an Elasticsearch ingest pipeline, a templating step), and treat any unexpected callback as a different finding (server-side request forgery belongs to a later subcategory).

**Safe proofs.** Each test ends at the least invasive proof that your input reaches the query interpreter:

| Proof | Example | Use when |
|---|---|---|
| Type error or cast error | A `400` or `500` mentioning a cast or BSON type when you send an object | Showing the value reached the data layer untyped |
| Syntax error | A parser error on a single `"` in a string-built query | Syntax injection |
| Boolean difference | `{"$ne": "x"}` returns your record, `{"$eq": "x"}` does not | Operator injection |
| Regex difference | `{"$regex": "^."}` matches, `{"$regex": "^NOMATCH_GT"}` does not | Regex reaching the database |
| JavaScript boolean | `$where` returning `true` versus `false` | Server-side JavaScript, without delays |
| Bounded delay (only if agreed) | One short `sleep()` behind a condition that matches one document, repeated three times | When nothing else distinguishes the responses |

**Stop rules.**

- **Never extract data that is not yours.** A boolean or regex oracle is enough to prove the finding. If the client wants a demonstration of extraction, extract a canary value you planted in **your own** test account (for example a profile field set to `GT-canary-7f3a`), never a real user's field, token or hash.
- **No writes.** No `$out`, `$merge`, update operators, `deleteMany`-style endpoints or JavaScript that changes state. If a test would send a filter to an update or delete endpoint, use a filter that can only match your own test objects, or skip it.
- **No resource exhaustion.** No loops in `$where`, no unanchored regex over large collections in production, no `sleep()` without agreement. If response times rise and stay high, stop and tell the client.
- **Stop on real data.** If a request returns another person's data (a login bypass lands you in a real user's session, a widened search lists real customers), stop that line of testing, log out, keep only minimal redacted evidence (endpoint, status, a masked identifier), do not browse or download more, and report it immediately.
- **Login bypass is proven on your own account only.** Combine the operator with **your own** username or email. If the only way to show the bypass would be to log in as whoever the database returns first, stop at the response difference and report that.

**Rate limits.** Keep to the programme's or client's limit, and in any case a few requests per second at most. Login and reset endpoints often have lockout or alerting; tell the client in advance so a burst of failed logins on your test account is expected.

### GT-WEB-NOSQL-1: Fingerprint the data store and map query inputs

*Guler Tech methodology.* Implements the reconnaissance part of WSTG-INJT-05 (NoSQL Injection sub-page), using WSTG-INFO-06 (entry points), WSTG-INFO-08 (framework fingerprinting) and WSTG-ERRH-01 (error handling).

#### What it checks

Which data stores sit behind the application, which framework and parser handle requests, and which parameters reach a query. The output is the work list for the other tests.

#### Prerequisites

Your test accounts; Burp Logger history from a full walk-through; API documentation if available (OpenAPI, GraphQL schema).

#### Steps

1. Walk every feature with Logger on. Mark requests that look up or filter records: login, reset, search, list with filters, sort and paging parameters, "advanced search", export, dashboards.
2. Look for store fingerprints in responses and headers:
   - MongoDB: 24-hex-character IDs (`64b7f0c2e13a5d2f9c1a0b3e`, an ObjectId), `_id` fields, `$oid` in extended JSON, error strings with `MongoServerError`, `CastError` or `BSON`;
   - Elasticsearch or OpenSearch: `_source`, `_score`, `hits.total`, errors such as `search_phase_execution_exception`;
   - CouchDB: `_rev` fields such as `1-…`, `Server: CouchDB` headers;
   - DynamoDB: attribute-value shapes such as `{"S": "…"}` leaking through, `ValidationException` messages;
   - framework hints: `X-Powered-By: Express`, `connect.sid` cookies, PHP or Rack parameter behaviour.
3. Check how the server parses each input type. Send a harmless bracket parameter that cannot touch a query, for example `?gt_probe[a]=1` on a page that reflects parameters or logs them in a debug view, and compare with JSON bodies.
4. Record, per parameter: endpoint, location (JSON, form, query, path, header, GraphQL variable), the type the client normally sends, and what the response depends on (a match count, a single record, a login result).
5. In greybox tests, grep the code for query sinks: `find(`, `findOne(`, `aggregate(`, `$where`, `$regex`, `new RegExp(`, `JSON.parse(`, `query_string`, `BasicQuery(`, `whereRaw(`, `raw_aggregate(`, `findRaw(`, `EVAL`.

#### Observation

A table like this (illustrative):

| Request | Parameter | Normal type | Store | Response depends on |
|---|---|---|---|---|
| `POST /api/login` | `email`, `password` | string | MongoDB (ObjectIds) | Login success |
| `POST /api/password/reset/confirm` | `token` | string | MongoDB | Token match |
| `GET /api/products?category=shoes&sort=price` | `category`, `sort` | string | MongoDB | Result list |
| `GET /search?q=red+shoes` | `q` | string | Elasticsearch (`_score`) | Hit list |
| `POST /graphql` `orders(filter:)` | `filter` | JSON scalar | MongoDB | Result list |

#### Evaluation

No finding on its own, except verbose errors: database error messages, query fragments or stack traces returned to the client are a separate low-severity finding under ASVS `v5.0.0-16.5.1` (L2), and they make every later test easier.

#### False positives

24-hex IDs are not proof of MongoDB (some systems generate similar IDs). Elasticsearch-style response shapes may come from a SaaS search provider you cannot test.

#### Automation

Arjun and Param Miner find unlinked parameters (`filter`, `where`, `sort`, `fields`, `pipeline`). In CI, keep a list of endpoints that accept filter-like parameters and require a schema for each (see [regression tests](#regression-tests-with-malicious-looking-input)).

### GT-WEB-NOSQL-2: Type confusion with objects, arrays and non-strings

*Guler Tech methodology.* Implements WSTG-INJT-05 (NoSQL Injection sub-page): the first step of operator injection, without operators.

#### What it checks

Whether parameters that should be strings accept other JSON types and pass them, untyped, to the data layer. It is the cheapest and safest NoSQL test, and a positive result tells you which parameters deserve the operator tests.

#### Prerequisites

The inventory from GT-WEB-NOSQL-1; a JSON request per parameter (convert form requests with Content Type Converter if the endpoint also accepts JSON).

#### Steps

1. Baseline: send the normal request with a normal value and note status, length and body.
2. Replace the string value with each of these, one at a time:

```text
{"a": "b"}           an object with no operator
["value"]            an array with the normal value inside
123                  a number
true                 a boolean
null                 null
```

3. For an object, a typical request:

```http
POST /api/products/search HTTP/1.1
Host: api.example.com
Content-Type: application/json
Cookie: session=<SESSION_TEST_USER>

{"category": {"a": "b"} }
```

4. Note which variants produce a different status, a different error message, or a different result than an invalid string (`"zzzz-no-such-category"`).

#### Observation

Typical answers (illustrative):

| Variant | Strongly typed endpoint | Untyped endpoint |
|---|---|---|
| `{"a": "b"}` | `400 {"error":"category must be a string"}` | `500` with `Cast to string failed for value` or `200` with zero results |
| `["shoes"]` | `400` | `200` with the same results as `"shoes"`, or a cast error |
| `true`, `123`, `null` | `400` | `200` with zero results or all results |

#### Evaluation

- **Pass:** every non-string is rejected with a validation error before any query runs (a `400` that names the type).
- **Fail (lead):** non-strings reach the data layer (cast errors, database errors, or results that change with the type). This is not yet injection: it shows missing type validation (ASVS `v5.0.0-15.3.5`, L2, and `v5.0.0-2.2.1`, L1), and CWE-1287 (Improper Validation of Specified Type of Input) fits if it is reported alone. Continue with GT-WEB-NOSQL-3.
- **Fail (finding):** a non-string changes the query's meaning, for example `null` or `true` returning all records, or an array returning the union of several values.

#### False positives

Frameworks that coerce numbers to strings (`123` becomes `"123"`) and give the same result are fine. A `500` caused by the application's own code (`toLowerCase is not a function`) shows missing validation but not that the value reached a query; note it as a robustness issue unless other evidence follows.

#### Automation

A short Repeater or Bruno collection with these five variants per parameter. In CI, contract tests that post each variant to every JSON endpoint and assert a `400` (see [regression tests](#regression-tests-with-malicious-looking-input)).

### GT-WEB-NOSQL-3: Operator injection in JSON bodies

*Guler Tech methodology.* Implements WSTG-INJT-05 (NoSQL Injection sub-page) for MongoDB-style operators in JSON.

#### What it checks

Whether a `$`-prefixed key inside a value is interpreted as an operator by the database.

#### Prerequisites

A parameter that failed GT-WEB-NOSQL-2, or any JSON parameter you want to test directly. A known value that matches your own data (your own category, your own order reference) and a known value that matches nothing.

#### Steps

1. Use a pair of operators that should give **opposite** answers if they are interpreted, and the same answer if they are treated as literal values:

```http
POST /api/orders/search HTTP/1.1
Host: api.example.com
Content-Type: application/json
Cookie: session=<SESSION_TEST_USER>

{"reference": {"$ne": "GT-no-such-ref"} }
```

```http
POST /api/orders/search HTTP/1.1
Host: api.example.com
Content-Type: application/json
Cookie: session=<SESSION_TEST_USER>

{"reference": {"$eq": "GT-no-such-ref"} }
```

2. Confirm with a second pair that does not rely on `$ne`, for example `{"$in": ["GT-ORDER-0001", "GT-ORDER-0002"]}` (your own two references) against `{"$in": ["GT-no-such-ref"]}`, or `{"$exists": true}` against `{"$exists": false}`.
3. If the endpoint scopes results to the caller (it should), check whether the operator can widen the scope. Do this with **two accounts you control**: does a widened query from account A return account B's orders? Stop at the first record from B; that is the proof.
4. Try a top-level operator if the whole body looks like a filter: `{"$or": [{"reference": "GT-ORDER-0001"}, {"reference": "GT-ORDER-0002"}]}`.

#### Observation

Vulnerable (illustrative): `$ne` with a non-existent value returns all your orders, `$eq` with the same value returns none, and the `$in` pair behaves as set membership. Not vulnerable: both return the same thing (usually nothing, or a `400`).

#### Evaluation

- **Pass:** operator objects are rejected (`400`), or treated as literal values (both members of each pair give the same result).
- **Fail:** the pairs give opposite results. This is operator injection (CWE-943). Severity depends on what the query protects: within your own data it is a low-impact defect with high potential; if it crosses the user or tenant scope, it is an authorisation bypass and rates like the corresponding [IDOR](/web/web-idor-bola/) or [multi-tenant](/web/web-multi-tenant-isolation/) finding; on login or token fields, continue with GT-WEB-NOSQL-5.

#### False positives

Some APIs deliberately expose a MongoDB-like filter language (documented, scoped server-side, operators allowlisted). Operator behaviour there is a feature; test instead whether the server-side scope can be escaped and whether dangerous operators (`$where`, `$function`, `$expr`, `$lookup`) are blocked. A search endpoint that already returns everything you own for an empty string will not show a difference with `$ne`; use `$in` or `$exists` pairs instead.

#### Automation

The NoSQLi Scanner extension adds active checks for common operator payloads; treat its results as leads. NoSQLMap and `nosqli` (a Go command-line scanner) automate detection for MongoDB; run them only against labs or with the client's agreement, with low rates, and never in extraction modes on client systems.

### GT-WEB-NOSQL-4: Operator injection through query-string and form parsers

*Guler Tech methodology.* Implements WSTG-INJT-05 (NoSQL Injection sub-page) together with WSTG-INJT-04 (HTTP Parameter Pollution), which covers the parser behaviour.

#### What it checks

Whether bracket syntax in query strings or URL-encoded bodies creates operator objects, and whether duplicated parameters become arrays.

#### Prerequisites

`GET` endpoints with filter parameters and `POST` forms that use `application/x-www-form-urlencoded`.

#### Steps

1. Baseline with a normal value, then the bracket variant (the brackets and `$` may be URL-encoded as `%5B`, `%5D`, `%24`; send both forms):

```http
GET /api/products?category[$ne]=GT-no-such-category HTTP/1.1
Host: api.example.com
Cookie: session=<SESSION_TEST_USER>
```

```bash
curl -s -g 'https://api.example.com/api/products?category[$ne]=GT-no-such-category' \
  -H 'Cookie: session=<SESSION_TEST_USER>' | jq '.items | length'
curl -s -g 'https://api.example.com/api/products?category[$eq]=GT-no-such-category' \
  -H 'Cookie: session=<SESSION_TEST_USER>' | jq '.items | length'
```

(`-g` stops curl from treating the brackets as its own globbing syntax.)

2. Repeat for form posts, for example a login form on your own account (detailed in GT-WEB-NOSQL-5):

```http
POST /login HTTP/1.1
Host: app.example.com
Content-Type: application/x-www-form-urlencoded

email=gt-tester%40example.org&password[$ne]=GT-wrong-password
```

3. Test duplicates: `?category=shoes&category=hats`. If the result is the union, the value became an array and reached the query as one.
4. Note the framework: Express 4 or `app.set('query parser', 'extended')`, PHP and Rack parse brackets natively; Express 5 defaults and Django's `QueryDict` do not (Django's `request.GET.get()` always returns a string; JSON bodies are a different story).

#### Observation

Vulnerable (illustrative): `category[$ne]=…` returns every product while `category[$eq]=…` returns none; the bracket form behaves exactly like the JSON operator. Not vulnerable: the bracket parameter is ignored, treated as a literal key `category[$ne]`, or rejected.

#### Evaluation

- **Pass:** brackets do not create objects for query parameters, or the handler rejects non-strings.
- **Fail:** bracket syntax yields operator behaviour. Report it with the parser behaviour (which parser, which setting) because the fix may be in configuration as well as in code. Duplicated parameters reaching a query as arrays are a lower-impact variant of the same type failure (ASVS `v5.0.0-15.3.7`, L2, for parameter pollution).

#### False positives

A CDN or WAF that strips or blocks `$` in URLs can hide the issue from the outside while the JSON path stays vulnerable; test both. Front-end code that builds the same request from a dropdown proves nothing; send requests directly.

#### Automation

Param Miner's "guess params" can surface hidden filter parameters; Burp's active scan includes some NoSQL checks. In CI, a test that requests each list endpoint with `field[$ne]=x` and asserts the response is a `400` or equal to the `field=x` response.

### GT-WEB-NOSQL-5: Login and token-check bypass on your own account

*Guler Tech methodology.* Implements WSTG-INJT-05 (NoSQL Injection sub-page) applied to WSTG-ATHN-04 (Bypassing Authentication Schema).

#### What it checks

Whether the secret part of an authentication or one-time-token check (password, OTP, reset token, invite code, coupon code) can be replaced with an operator so that it matches without knowing the secret.

#### Prerequisites

**Your own** test account with a known email or username; the ability to trigger **your own** reset token, invite or coupon; agreement on lockout behaviour. Never combine the operator with someone else's username, and never leave the username open (`{"$ne": null}` on both fields logs you in as whoever the database returns first, which is usually a real person or an administrator).

#### Steps

1. Baseline, wrong password on your own account:

```http
POST /api/login HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"email": "gt-tester@example.org", "password": "GT-wrong-password"}
```

2. Same account, operator in the secret field:

```http
POST /api/login HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"email": "gt-tester@example.org", "password": {"$ne": "GT-wrong-password"} }
```

3. If that fails, try one or two other shapes before concluding: `{"$gt": ""}` (matches any non-empty string), `{"$regex": "^"}`, and the form-encoded variant from GT-WEB-NOSQL-4 (`password[$ne]=…`).
4. If the login succeeds, check that the session is **your** account (profile shows `gt-tester@example.org`), capture the evidence, then log out.
5. Repeat for token checks on your own tokens: request a password reset for your own account, then submit the confirmation with an operator instead of the token:

```http
POST /api/password/reset/confirm HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"email": "gt-tester@example.org", "token": {"$ne": "GT-not-the-token"}, "newPassword": "<NEW_TEST_PASSWORD>"}
```

   If the endpoint takes only a token and no email, do **not** send an operator token: it would match some other user's pending reset. Stop at GT-WEB-NOSQL-2's type check and report the risk from the code path or error behaviour.
6. Check the username or email field separately, but only with operators that cannot match anyone except you, for example `{"$eq": "gt-tester@example.org"}` versus `{"$in": ["gt-tester@example.org"]}`: if both log you in with the right password while a plain string also does, the field accepts operators. Do not use `$ne`, `$gt` or `$regex` on the identity field.

#### Observation

Vulnerable (illustrative):

```http
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: session=<NEW_SESSION>; HttpOnly; Secure; SameSite=Lax

{"user": {"email": "gt-tester@example.org", "role": "user"} }
```

Not vulnerable: `400 {"error":"invalid_request"}` (type rejected) or `401` identical to the wrong-password baseline.

#### Evaluation

- **Pass:** operator values are rejected or treated as literal strings; the response equals the wrong-password baseline.
- **Fail:** your own account is authenticated, or your own token accepted, without the secret. Report it as an authentication bypass: the same request with another person's email logs in as them, and the variant with an open identity field logs in as the first account in the collection. You do not need to demonstrate either.
- **Fail (identity field only):** the identity field accepts operators but the password is compared in code. Still a finding, because operators such as `$regex` on the identity field let an attacker discover usernames and target accounts; rate it lower unless it chains.

#### False positives

Applications that compare password hashes in code (`bcrypt.compare`) reject the object at comparison time even though it reached the query; the login fails, but GT-WEB-NOSQL-2 may still show the type problem. Rate-limited or locked accounts give misleading `401`s; check your account state first.

#### Automation

A regression test per authentication endpoint that posts object, array and operator values for every credential field and asserts a `400` or the baseline `401` (see [regression tests](#regression-tests-with-malicious-looking-input)). Scanners should not be pointed at login endpoints in production: they will try open identity fields.

### GT-WEB-NOSQL-6: Syntax injection into string-built queries

*Guler Tech methodology.* Implements WSTG-INJT-05 (NoSQL Injection sub-page); the special-character probe follows the WSTG page, which lists `' " \ ; { }` as characters that break MongoDB queries built from strings.

#### What it checks

Whether input is concatenated into query text (JSON, JavaScript, a search mini-language, PartiQL) and parsed, so that quotes and brackets change the structure.

#### Prerequisites

String parameters, especially in search, filter and saved-query features; GT-WEB-NOSQL-2 results (string-built queries often survive type checks, because the input *is* a string).

#### Steps

1. Send a value with one special character at a time and compare with the baseline: `GT"`, `GT'`, `GT\`, `GT}`, `GT{`.
2. If one character produces an error, check that **balancing** or **escaping** it removes the error: `GT\"` or `GT""`. An error that comes and goes with the grammar is the strongest syntax signal.
3. Build a true/false pair that is valid in the suspected grammar. For a JSON template filled by string substitution (`{"category": "<input>"}`), an input that closes the string and adds a key is enough, and it only needs to change *your* result set. Two short examples, used as a pair:

```text
shoes", "category": "shoes
shoes", "category": "GT-no-such-category
```

   The first should return the same as `shoes` (the duplicate key repeats the value), the second should return nothing if the later key wins. A difference proves the input is parsed as JSON structure.
4. For JavaScript-built `$where` strings, the PortSwigger-style pair is `GT' && '1'=='1` against `GT' && '1'=='2`, adjusted to the quoting you see in errors.
5. For Elasticsearch `query_string` and DynamoDB PartiQL, see GT-WEB-NOSQL-10.

#### Observation

Vulnerable (illustrative): `GT"` gives `500 {"error":"Unexpected token in JSON at position 17"}` or `SyntaxError`, `GT\"` gives `200`, and the pair in step 3 gives different results. Not vulnerable: all variants return the same "no results" response.

#### Evaluation

- **Pass:** special characters are searched for literally.
- **Fail:** the error tracks the grammar and a true/false pair differs. Report as NoSQL injection (CWE-943), noting the grammar (JSON template, JavaScript, search syntax). Impact follows from what the grammar allows: in a JSON template the attacker can add any operator, which brings in everything in GT-WEB-NOSQL-3, 7, 8 and 9.

#### False positives

Input validation that rejects `"` with a generic `500` (poor error handling, not injection). Search engines that tokenise punctuation away give identical results for `GT"` and `GT`, which is correct behaviour.

#### Automation

Burp Scanner's injection checks and the NoSQLi Scanner extension flag syntax errors; confirm by hand. In code review, search for `JSON.parse` on strings containing request data, template literals that produce query text, `new BasicQuery(` with concatenation, and template engines with escaping disabled in query features.

### GT-WEB-NOSQL-7: Boolean and regex response differences

*Guler Tech methodology.* Implements WSTG-INJT-05 (NoSQL Injection sub-page): blind confirmation with `$regex` and other operators.

#### What it checks

Whether an injected condition changes the response in a way that works as a true/false oracle, which is how blind NoSQL injection reads fields the API never returns. You prove the oracle exists; you do not use it on other people's data.

#### Prerequisites

A parameter where operator or syntax injection works (GT-WEB-NOSQL-3, 4 or 6), or a field that is already documented as a regex search. A canary value in your own test account if you need to demonstrate extraction.

#### Steps

1. Pick a true/false pair that touches only your own record. If the endpoint looks up your own account by email (a "forgot password" form is typical, and often unauthenticated), keep the email fixed and vary a condition on another field:

```http
POST /api/password/forgot HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"email": "gt-tester@example.org", "displayName": {"$regex": "^GT-canary"} }
```

   Then the same with `{"$regex": "^NOMATCH-GT"}`. If the first response says "reset email sent" and the second says "no such account" (or the status, length or timing differs consistently), you have an oracle that reads `displayName` without the API ever returning it. This shape needs a handler that uses the body (or a client object) as the filter; if only the `email` value is injectable, use an anchored, escaped pattern for your own address (`{"$regex": "^gt-tester@example\\.org$"}`) against one that cannot match, never an open pattern that could match other accounts.
2. Check whether the oracle could reach fields that should be secret, using **field existence**, not content: `{"$exists": true}` against `{"$exists": false}` on a field name such as `resetToken` or `passwordHash`, still pinned to your own email. A difference shows the field exists and is reachable by the oracle.
3. If the client wants a demonstration of extraction, read **your own canary** a few characters at a time (`^G`, `^GT`, `^GT-`), and stop after three or four characters. Do not run the oracle against tokens, hashes or another user's fields.
4. For regex search fields, test escaping: search for `.` and for `.*`. If `.` matches every record, metacharacters are not escaped (ASVS `v5.0.0-1.2.9`).

#### Observation

Vulnerable (illustrative):

| Condition on your own record | Response |
|---|---|
| `displayName` `$regex` `^GT-canary` | `200 {"status":"sent"}` |
| `displayName` `$regex` `^NOMATCH-GT` | `404 {"error":"unknown_account"}` |
| `resetToken` `$exists` `true` (after requesting your own reset) | `200 {"status":"sent"}` |
| `resetToken` `$exists` `false` | `404 {"error":"unknown_account"}` |

#### Evaluation

- **Pass:** operators are rejected or literal, so all variants give the same response.
- **Fail:** a consistent true/false difference. Report it as blind NoSQL injection with the fields shown to be reachable. Reachability of a token or hash field by an oracle means an attacker can read it character by character for **any** account they can name; that is how Rocket.Chat's reset tokens leaked. The impact rating follows what the reachable fields allow (token theft means account takeover).
- Unescaped metacharacters in a documented regex search are a separate, lower finding unless they cross a scope.

#### False positives

Rate limiting or caching can produce differences unrelated to the condition: repeat each pair three times and swap the order. Enumeration-safe forgot-password flows that always say "if the account exists, we sent an email" give no visible oracle, but may still differ in timing or in whether the email arrives (check your own inbox).

#### Automation

A small script that sends each pair a few times and compares status and length is fine and useful; keep it to your own record and a handful of requests. Character-by-character extraction loops do not belong in client testing.

### GT-WEB-NOSQL-8: Server-side JavaScript evaluation

*Guler Tech methodology.* Implements WSTG-INJT-05 (NoSQL Injection sub-page, the `$where` examples) and WSTG-INJT-11 (Code Injection).

#### What it checks

Whether input reaches JavaScript evaluated by the database (`$where`, `$function`, `$accumulator`, map-reduce) or by the application (filters evaluated in process, `eval` of query strings), and whether server-side scripting is enabled.

#### Prerequisites

A parameter with operator injection (to add `$where` or `$expr` yourself) or with syntax injection into a `$where` string. Agreement that JavaScript-evaluating payloads are in scope.

#### Steps

1. **Is `$where` accepted at all?** If you control a whole filter object, add a constant expression and compare `true` and `false`, pinned to your own record:

```http
POST /api/orders/search HTTP/1.1
Host: api.example.com
Content-Type: application/json
Cookie: session=<SESSION_TEST_USER>

{"reference": "GT-ORDER-0001", "$where": "return true"}
```

   Then `"$where": "return false"`. Your order returned for the first and not for the second means JavaScript runs. An error saying that `$where` is not allowed, or that JavaScript execution is disabled, is informative too: the operator reached the server, and scripting is off or restricted.
2. **Through `$expr`.** Where `$where` is blocked by a key filter, `$expr` with `$function` reaches the same engine. A constant body (`function() { return true; }` with `args: []` and `lang: "js"`) against `return false` is the proof.
3. **Inside an existing `$where` string** (syntax injection), use a pair that changes the result without delays: a value that appends `&& true` against one that appends `&& false`, matched to the quoting.
4. **Delays only if agreed.** WSTG and PortSwigger both show timing proofs (`sleep()` in `$where`). Because `$where` runs per scanned document, put the sleep behind a condition that is true only for your own record (`this.reference == 'GT-ORDER-0001' && sleep(2000)`), keep other filter clauses that narrow the scan, use one or two seconds, and repeat three times against a baseline. Never use loops.
5. **Application-side evaluation.** In greybox tests, check whether filters are evaluated in the application as well as sent to the database: Mongoose `populate()` with a `match` derived from the request (CVE-2024-53900 and CVE-2025-23061 affected versions before 8.8.3 and 8.9.5), the `sift` library or other in-memory MongoDB-query matchers, `vm` or `eval` over query strings. Report the code path and version; do not try to execute operating-system commands.

#### Observation

Vulnerable (illustrative): `return true` gives your order, `return false` gives an empty list. Scripting disabled: an error mentioning that JavaScript execution is not allowed. Not vulnerable: `$where` is rejected by validation (`400`) before reaching the database.

#### Evaluation

- **Pass:** the operator is rejected by the application, and server-side scripting is disabled (`security.javascriptEnabled: false` or `--noscripting`) where the application does not need it.
- **Fail:** client-controlled JavaScript runs in the database. Report it as server-side JavaScript injection (CWE-943, with CWE-95 for the evaluation). Describe the impact in prose: per-document read of every field the query scans, an oracle for any account, and CPU denial of service. Do not demonstrate the denial of service.
- **Fail (application-side):** filter evaluation in the application process with attacker-controlled JavaScript is code execution on the application server. Prove it only by version and code path (or a constant `true`/`false` difference), and rate it as remote code execution.
- **Configuration finding:** scripting enabled but not needed, with no injection found, is a hardening note.

#### False positives

Managed services or older drivers may return generic errors for any unknown key; an error alone does not prove `$where` reached the evaluator. Application caching can return the same list for both variants; add a cache-busting parameter that the server ignores.

#### Automation

Code search for `$where`, `$function`, `$accumulator`, `mapReduce`, `populate(` with `match`, and `sift(`. Configuration checks for `security.javascriptEnabled` in `mongod.conf` and `mongos` configuration (see [GT-WEB-NOSQL-12](#gt-web-nosql-12-configuration-and-code-review)). Dependency scanning (npm audit, Dependabot, Snyk) flags vulnerable Mongoose versions.

### GT-WEB-NOSQL-9: Aggregation pipeline, sort and projection injection

*Guler Tech methodology.* Implements WSTG-INJT-05 (NoSQL Injection sub-page) for aggregation pipelines and query options.

#### What it checks

Whether the client can add stages to an aggregation pipeline, or control sort and projection documents, and so read collections or fields outside the endpoint's purpose.

#### Prerequisites

Endpoints that accept `pipeline`, `stages`, `groupBy`, `sort`, `fields`, `select`, `projection` or a `$match`-like filter; dashboards and reports in particular. Two accounts you control if the data is per user.

#### Steps

1. **Sort.** Compare `?sort=createdAt` with `?sort[createdAt]=1` and `?sort[createdAt]=-1` (or the JSON equivalent). If object sorts work, try sorting by a field the API does not return, for example `sort[passwordChangedAt]=1`, using only your own records. A changed order shows the hidden field is addressable.
2. **Projection.** Request a field the API hides: `?fields=email,resetToken` or `{"projection": {"resetToken": 1} }`. Use your own account's record; stop as soon as a hidden field appears.
3. **Pipeline stages.** If the endpoint takes a pipeline or a stage list, add a harmless stage first and see whether it is honoured:

```http
POST /api/reports/run HTTP/1.1
Host: api.example.com
Content-Type: application/json
Cookie: session=<SESSION_TEST_USER>

{"pipeline": [{"$match": {"owner": "<YOUR_USER_ID>"} }, {"$limit": 1}, {"$addFields": {"gtProbe": "GT-canary"} }]}
```

   `gtProbe` appearing in the output proves client stages run. Then check, without reading real data, whether a cross-collection stage is accepted: a `$lookup` into another collection with a `pipeline` that contains `{"$match": {"_id": "GT-no-such-id"} }` and `{"$limit": 1}` returns an empty joined array if the stage is allowed, and an error if it is blocked. An empty array is enough proof.
4. **Do not** add `$out`, `$merge`, `$function`, `$accumulator` or unbounded `$unionWith` stages. Report their reachability from the allowlist (or its absence) instead.
5. **Mongoose note.** Mongoose casts query filters but not aggregation pipelines, and `sanitizeFilter` is documented for query filters. A pipeline built from request data has no ODM protection at all.

#### Observation

Vulnerable (illustrative): the report contains `"gtProbe": "GT-canary"`, and the `$lookup` probe returns `"joined": []` instead of an error. Not vulnerable: unknown stages or keys are rejected with a `400`, or the server builds the pipeline itself and ignores client stages.

#### Evaluation

- **Pass:** the server builds pipelines from a fixed template and fills only validated values; sort and projection are chosen from allowlists of field names.
- **Fail:** client stages run. If `$lookup` or `$unionWith` is accepted, the endpoint can read any collection the database user can read; if `$out` or `$merge` is accepted, it can write. Rate by what the database user can reach (ask for its roles in a greybox test). Hidden-field projection or sort is a property-level exposure; rate it by the field's sensitivity.

#### False positives

Some products expose a documented pipeline API to trusted administrators or to per-tenant databases. That is a design decision; test whether the database user and tenancy limit what it can reach.

#### Automation

In code review, flag `aggregate(` calls whose argument includes request data, and `sort(`, `select(` or `project` with request objects. In CI, a test that posts a pipeline with a `$lookup` and asserts rejection.

### GT-WEB-NOSQL-10: Elasticsearch, CouchDB, DynamoDB and Redis

*Guler Tech methodology.* Implements WSTG-INJT-05 (NoSQL Injection sub-page), which notes that each NoSQL store has its own syntax and that testers need to learn it; this test covers the four other stores we meet most often.

#### What it checks

Store-specific injection shapes: search syntax in Elasticsearch or OpenSearch, Mango selectors in CouchDB, expressions and PartiQL in DynamoDB, and command or script composition with Redis.

#### Prerequisites

Fingerprints from GT-WEB-NOSQL-1. For Elasticsearch scoping tests, two accounts or tenants you control, each with a distinctive canary document (a product or ticket titled `GT-tenantA-canary`, `GT-tenantB-canary`).

#### Steps

**Elasticsearch and OpenSearch.**

1. Send `GT"`, `GT(` and `GT/` in the search field. A `400` or `500` with `query_shard_exception`, `parse_exception` or "Failed to parse query" means the text is parsed as `query_string` syntax; identical empty results mean it is treated as text (`match`) or simple syntax.
2. If syntax is parsed, test field selection on your own data: `title:GT-tenantA-canary` against `title:GT-no-such-title`. A difference shows field addressing works.
3. Test whether the scope lives inside the same string. From tenant A, search for `GT-tenantB-canary` (should return nothing), then for a value that would close a wrapping group and widen it, for example `x) OR (title:GT-tenantB-canary`. Tenant B's canary in tenant A's results is the proof; stop there.
4. Leading wildcards and regex (`*canary`, `/.*canary/`) are expensive on large indices; one request is enough to see whether they are accepted, do not repeat them.
5. If the API accepts a raw query object (`{"query": {"match_all": {} } }`), it is the Elasticsearch equivalent of a client-supplied MongoDB filter: check whether the tenant filter is added server-side as a separate `bool.filter` clause or can be replaced.

**CouchDB Mango.** CouchDB's `_find` endpoint takes a JSON `selector` with operators such as `$eq`, `$gt`, `$regex`, `$or` and `$exists`. Application endpoints that put request values into a selector are tested exactly as in GT-WEB-NOSQL-3 (an `$ne`/`$eq` pair, then `$exists` pairs). CouchDB's `$regex` uses PCRE-based Erlang regular expressions and cannot use indexes, so keep regex probes anchored and few. A CouchDB server reachable directly from the internet (`/_all_dbs`, Futon or Fauxton) is a configuration finding for a later subcategory, not injection.

**DynamoDB.** Condition, filter and key expressions take values through `:placeholders` (`ExpressionAttributeValues`) and names through `#placeholders`, so the common injection shapes are different:

- an API that lets the client choose a field or operator (`?filterField=status&op==`) and concatenates them into a `FilterExpression`. Send a field name with a space or a second clause (`status OR attribute_exists(passwordHash)`) and watch for `ValidationException` messages about invalid expressions;
- PartiQL statements built as strings. A single quote in a value that produces a PartiQL syntax error indicates concatenation; a true/false pair such as `GT-ORDER-0001' AND '1'='1` against `GT-ORDER-0001' AND '1'='2` (adjusted to what the PartiQL dialect accepts) confirms it. Note that PartiQL `SELECT` without a partition-key condition becomes a full table scan, which costs read capacity; do not send open conditions such as `OR 1=1`.

**Redis.** With normal client libraries Redis is not injectable through values, so look for the exceptions in code or through behaviour: user input in a Lua script body passed to `EVAL`, a command string split on spaces into arguments (an input with a space adds an argument, for example an extra `EX 1` changing an expiry or a second key name), user input used as a glob pattern for `KEYS` or `SCAN MATCH` (a `*` lists keys), user input in a key name that crosses a namespace (`session:` + input), or a hand-written protocol client where CR or LF in input starts a new command. Test only with values that affect your own keys, and never send `FLUSHALL`, `CONFIG` or other administrative commands.

#### Observation

Illustrative Elasticsearch syntax error, showing that the input is parsed:

```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{"error": "search failed", "detail": "query_shard_exception: Failed to parse query [tenant_id:42 AND (GT\")]"}
```

The detail field also leaks the wrapping clause, which shows that the tenant scope is inside the same query string.

#### Evaluation

- **Pass (Elasticsearch):** user text reaches `match` or `simple_query_string`; tenant and permission scope are separate `filter` clauses built server-side; errors are generic.
- **Fail:** cross-scope results, field addressing of hidden fields, or acceptance of raw query objects. Syntax errors alone are a lead and a low-severity error-handling finding.
- **Fail (CouchDB, DynamoDB):** operator or expression injection confirmed by a true/false pair.
- **Fail (Redis):** argument, pattern or script injection confirmed on your own keys; rate by what the reachable commands and keys allow.

#### False positives

Search engines legitimately support some syntax (quoted phrases, `-exclusions`) through `simple_query_string`; that is a feature. Hosted search services (Algolia, managed OpenSearch dashboards) may be out of scope; check before testing them.

#### Automation

Code search for `query_string`, string-built search bodies, `FilterExpression` concatenation, `executeStatement` or `ExecuteStatementCommand` with template literals, `EVAL` with concatenated scripts, `sendCommand` or `call` with `split(' ')`, and `KEYS` with user input.

### GT-WEB-NOSQL-11: GraphQL resolvers and generic filter APIs

*Guler Tech methodology.* Implements WSTG-INJT-05 (NoSQL Injection sub-page) through WSTG-APIT-99 (GraphQL).

#### What it checks

Whether GraphQL arguments or REST "filter" parameters that carry structured JSON are forwarded to the database, and whether server-side scoping survives the merge.

#### Prerequisites

The GraphQL schema (introspection, InQL, or the client bundle if introspection is off); two accounts you control.

#### Steps

1. Find arguments typed as `JSON`, `JSONObject`, `Object`, `Any` or a generic input such as `FilterInput` with an open `where: JSON` field.
2. Send an operator inside the argument, pinned to your own data:

```graphql
query {
  orders(filter: { reference: { _ne: "GT-no-such-ref" } }) { id reference }
}
```

   Many schemas rename operators (`_ne`, `ne`, `not`) and translate them; try the raw MongoDB form in variables too, because variables arrive as JSON and keep `$` keys:

```json
{"query": "query($f: JSON) { orders(filter: $f) { id reference } }", "variables": {"f": {"reference": {"$ne": "GT-no-such-ref"} } } }
```

3. Check whether the owner scope can be overridden: from account A, filter on `owner` with account B's ID (an ID you control). If B's orders come back, the resolver merges the client filter after its own scope.
4. Repeat for REST parameters such as `?filter={"status":"open"}` or `?where=…`.

#### Observation

Vulnerable (illustrative): the `$ne` variant returns all your orders, the literal variant returns none; with `owner` set to account B, B's order references appear. Not vulnerable: a schema validation error, or results unchanged.

#### Evaluation

- **Pass:** filter arguments are typed input objects with scalar fields, operators are mapped server-side from an allowlist, and the scope is applied last, so the client cannot override it.
- **Fail:** raw operators reach the database (operator injection), or the client filter overrides the scope (an authorisation bypass, rated like [IDOR and BOLA](/web/web-idor-bola/)).

#### False positives

Server-side operator translation that maps `_ne` to `$ne` on an allowlisted field is a feature; test only whether the scope holds and whether dangerous operators are excluded.

#### Automation

InQL to enumerate arguments and generate queries; graphql-cop for general GraphQL hygiene. In code review, search resolvers for `find(args`, `find({ ...args`, `aggregate(args` and JSON scalar types.

### GT-WEB-NOSQL-12: Configuration and code review

*Guler Tech methodology.* Implements the greybox side of WSTG-INJT-05 (NoSQL Injection sub-page), with WSTG-INJT-11 for server-side JavaScript.

#### What it checks

The settings and code patterns that decide whether the findings above are possible: server-side scripting, ODM options, middleware, validation and database privileges.

#### Prerequisites

Read access to the code, dependency manifests and database configuration, or a configuration questionnaire answered by the client.

#### Steps

1. **MongoDB server.** Check `security.javascriptEnabled` in each `mongod` and `mongos` configuration, or `--noscripting` in the service definition. On a running instance a database administrator can read the effective options with `db.adminCommand({ getCmdLineOpts: 1 })`. Note whether the application uses `$where`, `$function`, `$accumulator` or map-reduce at all.
2. **Database user.** Ask which roles the application's database user has. `readWrite` on one database is normal; `dbAdmin`, `root` or `readWriteAnyDatabase` turns any pipeline or JavaScript injection into wider access (ASVS `v5.0.0-13.2.2`, L2, least privilege for back-end connections).
3. **Mongoose.** Version (CVE-2024-53900 and CVE-2025-23061 are fixed in 8.9.5 and later); `mongoose.set('sanitizeFilter', true)` or per-query `setOptions({ sanitizeFilter: true })`; use of `trusted()`; `strictQuery` (default `false` since Mongoose 7, which means paths not in the schema stay in the filter); `Model.find(req.query)` or `find(req.body)` anywhere.
4. **Parsers and middleware.** Express major version, `query parser` setting, `express.urlencoded({ extended })`; any sanitiser middleware and whether it covers query, body, params and GraphQL variables.
5. **Validation.** Whether every endpoint that builds a query has a schema (zod, joi, class-validator, DRF serializers, Spring DTOs with Bean Validation, Laravel form requests) and whether string fields are declared as strings.
6. **Search and other stores.** `query_string` usage, search request bodies built as strings, DynamoDB expression and PartiQL construction, Redis `EVAL` and command building.

#### Observation

A short configuration table in the report: setting, current value, recommended value, and whether the application depends on the feature.

#### Evaluation

- **Pass:** scripting disabled (or justified and documented), least-privilege database user, typed validation on every query input, no request objects as filters.
- **Fail:** any of these missing is a hardening finding; combined with a confirmed injection, it raises that finding's severity.

#### False positives

Applications that genuinely need `$function` or map-reduce may keep scripting on; the finding then becomes "ensure no client input reaches it", checked in GT-WEB-NOSQL-8.

#### Automation

Semgrep or CodeQL (see [Static analysis](#static-analysis)); dependency scanning for ODM versions; infrastructure-as-code checks on `mongod.conf` templates.

## Secure implementation

### Design rules

- **Decide the type on the server.** Every value that goes into a query is validated against a schema that says "string" (or number, or enum) before the query is built. This is the single fix that removes operator injection, and it is what ASVS `v5.0.0-1.2.4` (L1, protected database queries, NoSQL named explicitly), `v5.0.0-2.2.1` (L1, positive input validation) and `v5.0.0-15.3.5` (L2, correct types and strict comparisons) ask for together.
- **Never pass a request object as a filter,** a pipeline, a sort, a projection or a search body. Build the query from named, validated fields. If clients need flexible filtering, define a small filter language (allowlisted fields, allowlisted operators) and translate it server-side.
- **Apply scope last.** Owner and tenant conditions are added after any client-derived conditions, as separate clauses the client cannot overwrite (`{ ...clientPart, owner: user.id }`, an Elasticsearch `bool.filter`).
- **Use the literal form for comparisons with untrusted values** where your driver allows it: `{ field: { $eq: value } }` in MongoDB is compared as a literal even if `value` is an object. The CodeQL query help for this class recommends exactly that.
- **Escape regular expressions** built from input (`v5.0.0-1.2.9`, L2), anchor them, cap their length, and prefer exact or prefix matches. Use a text index or a search engine for free-text search.
- **Keep query text out of strings.** No JSON built by concatenation or by templates with escaping disabled; no `$where` strings; no `query_string` for search boxes; PartiQL with `Parameters`; Redis commands with separate arguments and fixed Lua scripts.
- **Turn off what you do not use.** Disable MongoDB server-side scripting with `security.javascriptEnabled: false` (or `--noscripting`) on every `mongod` and `mongos` if the application does not need `$where`, `$function`, `$accumulator` or map-reduce. That keeps one injection from becoming code evaluation (`v5.0.0-1.3.2`, L1, avoid dynamic code execution).
- **Least privilege for the database user** (`v5.0.0-13.2.2`, L2): read-write on the application's database, nothing cluster-wide, separate users for reporting.
- **Bound every query:** `maxTimeMS`, result limits, request body size limits. This limits the damage of anything you missed (`v5.0.0-15.2.2`, L2, defences against resource-demanding functionality).
- **Return generic errors** (`v5.0.0-16.5.1`, L2). Database messages in responses turn blind injection into easy injection.
- **Treat sanitiser middleware as defence in depth,** not as the control. Mongoose `sanitizeFilter` is a reasonable second layer; unmaintained denylist middleware is not something to rely on.

### Node.js with Mongoose and the MongoDB driver

Validate with a schema, keep the types, and let the ODM's sanitiser catch what slips through:

```javascript
// auth.routes.js (Express 5, Mongoose, zod 4)
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { z } = require('zod');
const { User } = require('./models');

// Defence in depth: nested objects with $-keys in filters are wrapped in $eq
mongoose.set('sanitizeFilter', true);
// Unknown filter paths throw instead of being sent (or silently dropped)
mongoose.set('strictQuery', 'throw');

const router = express.Router();

const LoginBody = z.strictObject({
  email: z.string().trim().toLowerCase().max(254),
  password: z.string().min(1).max(1024),
});

router.post('/login', express.json({ limit: '10kb' }), async (req, res) => {
  const parsed = LoginBody.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_request' });

  const { email, password } = parsed.data; // both guaranteed to be strings
  const user = await User.findOne({ email }).select('+passwordHash').maxTimeMS(2000);
  const ok = user !== null && (await bcrypt.compare(password, user.passwordHash));
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' });

  req.session.userId = String(user._id);
  return res.json({ ok: true });
});

module.exports = router;
```

`z.strictObject` rejects unknown keys, and `z.string()` rejects objects, arrays, numbers and `null`, so `{"$ne": null}` never reaches Mongoose. With joi the equivalent is `Joi.object({ email: Joi.string().email().max(254).required(), password: Joi.string().max(1024).required() })`, which rejects unknown keys by default.

When *you* need an operator and `sanitizeFilter` is on, mark it with `mongoose.trusted()`; otherwise Mongoose wraps it in `$eq` like any other nested `$` object. A prefix search with an escaped, anchored regex:

```javascript
const ProductQuery = z.strictObject({
  q: z.string().max(64).default(''),
  sort: z.enum(['price', '-price', 'createdAt', '-createdAt']).default('-createdAt'),
});

const escapeRegex = (s) => s.replace(/[.*+?^$()|[\]\\{}]/g, '\\$&');

router.get('/products', async (req, res) => {
  const parsed = ProductQuery.safeParse(req.query); // Express 5: values are strings or arrays
  if (!parsed.success) return res.status(400).json({ error: 'invalid_request' });
  const { q, sort } = parsed.data;

  const filter = { tenantId: req.user.tenantId }; // scope from the session, never from the request
  if (q) filter.name = mongoose.trusted({ $regex: '^' + escapeRegex(q), $options: 'i' });

  const items = await Product.find(filter)
    .sort(sort)                 // an allowlisted string, not a client object
    .select('name price')       // fixed projection
    .limit(50)
    .maxTimeMS(2000)
    .lean();
  return res.json({ items });
});
```

With the plain MongoDB Node.js driver there is no `sanitizeFilter`, so validate types the same way and use `$eq` for values that came from a client:

```javascript
const user = await db.collection('users').findOne(
  { email: { $eq: email } },            // literal comparison even if email were an object
  { projection: { email: 1, passwordHash: 1 }, maxTimeMS: 2000 },
);
```

Aggregation pipelines are built on the server from a fixed template; only validated scalars go in, and Mongoose does not cast or sanitise them for you:

```javascript
const Status = z.enum(['open', 'paid', 'refunded']);

async function totalsByCategory(tenantId, rawStatus) {
  const status = Status.parse(rawStatus);
  return Order.aggregate([
    { $match: { tenantId, status } },
    { $group: { _id: '$category', total: { $sum: '$amount' } } },
    { $sort: { total: -1 } },
    { $limit: 20 },
  ]).option({ maxTimeMS: 5000 });
}
```

For GraphQL, type the filter and apply the scope last:

```graphql
enum OrderStatus { OPEN PAID REFUNDED }

input OrderFilter {
  reference: String
  status: OrderStatus
}

type Query {
  orders(filter: OrderFilter): [Order!]!
}
```

```javascript
const resolvers = {
  Query: {
    orders: async (_parent, { filter = {} }, ctx) => {
      const where = {};
      if (typeof filter.reference === 'string') where.reference = filter.reference;
      if (filter.status) where.status = filter.status.toLowerCase();
      where.owner = ctx.user.id; // last, so nothing in the filter can replace it
      return Order.find(where).limit(100).lean();
    },
  },
};
```

Two things to retire: `Model.find(req.query)` and `Model.find(req.body)` (Mongoose's own guide advises against passing user-defined objects such as `req.query` as filters), and Mongoose versions before 8.9.5 when `populate()` takes a `match` derived from the request. If you keep `express-mongo-sanitize` on an Express 4 app, treat it as a second layer; it is not maintained for Express 5.

### Elasticsearch from Node.js

User text is a *value* in a query that does not parse syntax, and tenancy is a separate filter:

```javascript
const { Client } = require('@elastic/elasticsearch');
const es = new Client({ node: process.env.ES_URL });

async function searchTickets(tenantId, text) {
  const q = z.string().max(200).parse(text);
  return es.search({
    index: 'tickets',
    size: 20,
    timeout: '2s',
    query: {
      bool: {
        must: [{ simple_query_string: { query: q, fields: ['title', 'body'], default_operator: 'and' } }],
        filter: [{ term: { tenant_id: tenantId } }], // never part of the user's query text
      },
    },
    _source: ['title', 'status', 'updated_at'],
  });
}
```

Use `match` if users need no syntax at all. Do not accept raw query objects from clients, and do not build request bodies with string concatenation. On clusters where you can change it, setting `search.allow_expensive_queries` to `false` (a dynamic cluster setting, changed through the cluster update settings API; Elastic notes it is not configurable on every deployment type) makes searches that contain script, fuzzy, regexp, prefix, wildcard and similar queries fail instead of running. It also blocks legitimate uses, so test it first.

### Django and PyMongo

Django's `request.GET` and `request.POST` return strings, so bracket parsing is not the issue; JSON bodies are. Validate them with a DRF serializer (whose `CharField` rejects dicts and lists) or an explicit type check, and use `$eq` with PyMongo:

```python
# views.py (Django REST framework + PyMongo)
import re

from django.conf import settings
from django.contrib.auth.hashers import check_password
from pymongo import MongoClient
from rest_framework import serializers, status
from rest_framework.decorators import api_view
from rest_framework.response import Response

client = MongoClient(settings.MONGO_URI, tls=True)
users = client.app.users
products = client.app.products


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    password = serializers.CharField(max_length=1024, trim_whitespace=False)


@api_view(["POST"])
def login(request):
    s = LoginSerializer(data=request.data)
    if not s.is_valid():
        return Response({"error": "invalid_request"}, status=status.HTTP_400_BAD_REQUEST)
    email = s.validated_data["email"].lower()
    user = users.find_one({"email": {"$eq": email} }, {"email": 1, "password_hash": 1}, max_time_ms=2000)
    if not user or not check_password(s.validated_data["password"], user["password_hash"]):
        return Response({"error": "invalid_credentials"}, status=status.HTTP_401_UNAUTHORIZED)
    request.session["uid"] = str(user["_id"])
    return Response({"ok": True})


class SearchSerializer(serializers.Serializer):
    q = serializers.CharField(max_length=64, required=False, allow_blank=True)


@api_view(["GET"])
def search(request):
    s = SearchSerializer(data=request.query_params)
    s.is_valid(raise_exception=True)
    query = {"tenant_id": request.user.profile.tenant_id}
    if s.validated_data.get("q"):
        query["name"] = {"$regex": "^" + re.escape(s.validated_data["q"]), "$options": "i"}
    docs = products.find(query, {"name": 1, "price": 1}, limit=50, max_time_ms=2000)
    return Response([{"name": d["name"], "price": d["price"]} for d in docs])
```

With the official **Django MongoDB Backend** (`django-mongodb-backend`), ordinary ORM lookups (`Product.objects.filter(name=q)`) take values, not operators. Its `raw_aggregate(pipeline)` method on `MongoManager` sends a pipeline straight to PyMongo's `aggregate()`; treat it like Django's `raw()` and never build its stages from request data.

### Spring Data MongoDB

Typed request DTOs stop the object at deserialisation: Jackson refuses to bind a JSON object into a `String` field and Spring answers `400`. Keep it that way, and avoid `Map<String, Object>` or `org.bson.Document` request bodies for anything that becomes a query.

```java
public record LoginRequest(
        @NotBlank @Email @Size(max = 254) String email,
        @NotBlank @Size(max = 1024) String password) {}

public interface UserRepository extends MongoRepository<UserDoc, String> {
    Optional<UserDoc> findByEmail(String email);          // derived query, value bound as a literal

    @Query("{ 'email' : ?0 }")                            // String parameters are escaped during binding
    Optional<UserDoc> findByEmailJson(String email);
}
```

For dynamic queries, use the Criteria API rather than JSON strings, and quote regex input:

```java
import static org.springframework.data.mongodb.core.query.Criteria.where;

import java.util.List;
import java.util.regex.Pattern;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Query;

public List<Product> search(MongoTemplate mongo, String tenantId, String term) {
    Query query = new Query(where("tenantId").is(tenantId));
    if (term != null && !term.isBlank()) {
        query.addCriteria(where("name").regex("^" + Pattern.quote(term), "i"));
    }
    query.fields().include("name", "price");
    query.limit(50).maxTimeMsec(2000);
    return mongo.find(query, Product.class);
}
```

What to avoid: `new BasicQuery("{ email: '" + email + "' }")` (syntax injection), `new BasicQuery(new Document(requestMap))` (operator injection), and SpEL inside `@Query` or `@Aggregation` that touches request-derived values. The Spring Data MongoDB reference warns that SpEL in query strings can accept a broad range of unwanted arguments, and CVE-2022-22980 was SpEL injection through exactly that pattern (fixed in 3.4.1 and 3.3.5). ASVS `v5.0.0-1.3.2` names SpEL as a dynamic-execution feature to avoid.

### Laravel MongoDB

PHP turns `email[$ne]=x` into an array before your code sees it, and the Laravel MongoDB integration (`mongodb/laravel-mongodb`) documents that with one or two arguments, `where()` reads an array value as a MongoDB operator document and warns against passing unvalidated input. Since v5.11, the three-argument form with `=` compares arrays as literal documents and wraps operator-looking values in `$eq`. Validate types first and use the three-argument form:

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use MongoDB\BSON\Regex;

public function login(Request $request)
{
    $data = $request->validate([
        'email' => ['required', 'string', 'email', 'max:254'],
        'password' => ['required', 'string', 'max:1024'],
    ]);

    $user = User::where('email', '=', strtolower($data['email']))->first();

    if (! $user || ! Hash::check($data['password'], $user->password)) {
        abort(401);
    }
    // ... start the session
}

public function search(Request $request)
{
    $data = $request->validate(['q' => ['nullable', 'string', 'max:64']]);

    $query = Product::where('tenant_id', '=', $request->user()->tenant_id);
    if (! empty($data['q'])) {
        $query->where('name', 'REGEX', new Regex('^' . preg_quote($data['q']), 'i'));
    }
    return $query->limit(50)->get(['name', 'price']);
}
```

Keep `whereRaw()` and `raw()` for queries you write in code, never for arrays from the request. The `string` validation rule is what rejects the array; without it, the three-argument form is your second line of defence on recent versions only.

### Database configuration

```yaml
# mongod.conf (and the equivalent for each mongos)
security:
  authorization: enabled
  javascriptEnabled: false   # same effect as --noscripting
net:
  bindIp: 10.0.2.15          # internal interface only
```

- Create an application user with `readWrite` on the application's database only; separate read-only users for reporting and analytics; no `root` or `*AnyDatabase` roles for applications.
- If the application truly needs `$function` or map-reduce, keep scripting on but document why, and make sure GT-WEB-NOSQL-8 is in every test plan.
- Set server-side time limits for heavy endpoints (`maxTimeMS` in code) and alert on slow queries.

### Static analysis

- **CodeQL:** `js/sql-injection` ("Database query built from user-controlled sources") covers NoSQL queries in JavaScript and is tagged with CWE-943; its help text recommends `$eq` or a type check. Python has a dedicated `py/nosql-injection` query.
- **Semgrep:** the registry includes njsscan's `node_nosqli_injection` rule (untrusted input in `findOne()`); write project rules for your own sinks, for example `Model.find($REQ.query)`, `$where` with template literals, `new BasicQuery($X + ...)`, `whereRaw($REQUEST...)` and `query_string` built from request data.
- **Dependencies:** npm audit, Dependabot or Snyk for Mongoose (CVE-2024-53900, CVE-2025-23061), Spring Data MongoDB (CVE-2022-22980) and abandoned sanitiser packages.

### Regression tests with malicious-looking input

For every endpoint that builds a query, post the same small set of hostile values for every field and assert that the request is rejected *and* that nothing changed. Keep the list short and readable:

```javascript
// login.nosql.test.js (Jest + supertest)
const request = require('supertest');
const app = require('../app');
const { seedUser } = require('./fixtures');

const hostile = [{ $ne: null }, { $gt: '' }, { $regex: '^' }, ['x'], { a: 'b' }, true, 0, null];

describe('login rejects non-string credentials', () => {
  let user;
  beforeAll(async () => { user = await seedUser({ email: 'alice@example.org', password: 'correct horse' }); });

  test.each(hostile)('password = %p', async (value) => {
    const res = await request(app).post('/api/login').send({ email: user.email, password: value });
    expect([400, 401]).toContain(res.status);
    expect(res.headers['set-cookie']).toBeUndefined();
  });

  test.each(hostile)('email = %p', async (value) => {
    const res = await request(app).post('/api/login').send({ email: value, password: 'correct horse' });
    expect([400, 401]).toContain(res.status);
  });

  test('bracket syntax in a form body is rejected', async () => {
    const res = await request(app).post('/login').type('form').send('email=alice%40example.org&password[$ne]=x');
    expect([400, 401]).toContain(res.status);
  });
});
```

Django REST framework:

```python
from rest_framework.test import APITestCase

HOSTILE = [{"$ne": None}, {"$gt": ""}, {"$regex": "^"}, ["x"], {"a": "b"}, True, None]


class LoginTypeTests(APITestCase):
    def test_password_must_be_a_string(self):
        for value in HOSTILE:
            with self.subTest(value=value):
                r = self.client.post("/api/login", {"email": "alice@example.org", "password": value}, format="json")
                self.assertIn(r.status_code, (400, 401))
                self.assertNotIn("sessionid", r.cookies)
```

Spring (MockMvc):

```java
@ParameterizedTest
@ValueSource(strings = {"{\"$ne\":null}", "{\"$gt\":\"\"}", "[\"x\"]", "true", "null"})
void passwordMustBeAString(String rawJsonValue) throws Exception {
    String body = "{\"email\":\"alice@example.org\",\"password\":" + rawJsonValue + "}";
    mvc.perform(post("/api/login").contentType(MediaType.APPLICATION_JSON).content(body))
       .andExpect(status().is4xxClientError());
}
```

Laravel:

```php
public function test_login_rejects_operator_arrays(): void
{
    foreach ([['$ne' => null], ['$gt' => ''], ['x'], true] as $value) {
        $this->postJson('/api/login', ['email' => 'alice@example.org', 'password' => $value])
             ->assertStatus(422);
    }
}
```

Add the same pattern for search, filter and GraphQL inputs (assert that `{"$ne": …}` returns the same as a literal miss, or a `400`), and one test per pipeline endpoint asserting that a client-supplied `$lookup` is rejected.

## Practice labs

**PortSwigger Web Security Academy** ([NoSQL injection topic](https://portswigger.net/web-security/nosql-injection)):

- [Detecting NoSQL injection](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-detection): syntax injection into a product category filter; the true/false pair technique from GT-WEB-NOSQL-6.
- [Exploiting NoSQL operator injection to bypass authentication](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication): operator injection into a MongoDB-backed login (GT-WEB-NOSQL-5, but in a lab you may leave the identity field open).
- [Exploiting NoSQL injection to extract data](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-data): JavaScript-based blind extraction; in the lab, extraction is the point.
- [Exploiting NoSQL operator injection to extract unknown fields](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-unknown-fields): `$where` used to discover field names and read a reset token.

**OWASP Juice Shop** ([companion guide, Injection](https://pwning.owasp-juice.shop/companion-guide/latest/part2/injection.html)): *NoSQL DoS* (let the server sleep, a `$where` evaluation challenge), *NoSQL Manipulation* (update multiple product reviews at once, operator injection into an update filter) and *NoSQL Exfiltration* (all your orders are belong to us, read other users' orders). The guide notes that some NoSQL challenges are not available in Docker or on Heroku, because the query syntax lets a player terminate the application process.

**OWASP crAPI** ([challenges](https://github.com/OWASP/crAPI/blob/develop/docs/challenges.md)): Challenge 12, *find a way to get free coupons without knowing the coupon code*, is the NoSQL injection challenge: the coupon check is the token-check pattern from GT-WEB-NOSQL-5.

Run labs locally or on the provider's infrastructure; the delay and extraction techniques that are out of bounds on client systems are fine there.

## Real-world cases

- **Rocket.Chat: blind operator injection leaks reset tokens (Sonar, 2021).** An unauthenticated method, `getPasswordPolicy`, passed a user-controlled JSON value into a MongoDB query. With `$regex`, an attacker could read a user's password reset token character by character and take over any account without 2FA whose email they knew (CVE-2021-22911). A second, authenticated injection in `users.list` used `$where` and error messages to read an administrator's password hash and 2FA secret, which the researchers chained to command execution through an integrations feature. Sonar's conclusion for the first bug: a type check that the value is a string. Fixed in 3.13.2, 3.12.4 and 3.11.4. [SonarSource write-up](https://www.sonarsource.com/blog/nosql-injections-in-rocket-chat/), [NVD CVE-2021-22911](https://nvd.nist.gov/vuln/detail/CVE-2021-22911).
- **Mongoose `populate()` match evaluated in Node.js (2024 to 2025).** Mongoose before 8.8.3 allowed `$where` in the `match` option of `populate()` (CVE-2024-53900); the fix was incomplete for a nested `$where` and was completed in 8.9.5 (CVE-2025-23061). OPSWAT's analysis explains why this was application-server code execution rather than database-side JavaScript: the match conditions were also evaluated locally by the `sift` library, outside MongoDB's restrictions. Applications exposed it when request parameters reached `populate()` options. [OPSWAT analysis](https://www.opswat.com/blog/technical-discovery-mongoose-cve-2025-23061-cve-2024-53900), [GitHub advisory GHSA-m7xq-9374-9rvx](https://github.com/advisories/GHSA-m7xq-9374-9rvx), [NVD CVE-2025-23061](https://nvd.nist.gov/vuln/detail/CVE-2025-23061).
- **Budibase: template interpolation into MongoDB queries (2026).** Two GitHub advisories published in July 2026 describe Budibase's MongoDB integration filling stored queries through Handlebars with escaping disabled and then calling `JSON.parse`. JSON metacharacters in a parameter changed the query structure (syntax injection), and a basic app user could override a per-user filter with an operator and read every document the connection could reach. The advisories contrast this with the SQL datasources, which were parameterised. [GHSA-qw6m-8fw2-2v64](https://github.com/advisories/GHSA-qw6m-8fw2-2v64), [GHSA-pmpg-2mxq-6xwr](https://github.com/advisories/GHSA-pmpg-2mxq-6xwr).
- **Spring Data MongoDB SpEL injection (2022).** Repository methods annotated with `@Query` or `@Aggregation` whose query used SpEL with parameter placeholders were vulnerable to SpEL injection when input was not sanitised; affected 3.4.0 and 3.3.4 and earlier, fixed in 3.4.1 and 3.3.5. [Spring advisory CVE-2022-22980](https://spring.io/security/cve-2022-22980).
- **The original Express write-up (Websecurify, 2014).** The post that popularised the class: Express's `qs` and body parsing turned `username[$gt]=` into an object, and `$gt` against an empty string matched the first user in the collection, often an administrator. The same shape still appears in Express 4 applications today. [Hacking NodeJS and MongoDB](https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html).

More write-ups are collected in [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

Rate on what the injected query can reach (one field of your own record, any user's record, any collection, code execution), the precondition (unauthenticated, any registered user, a specific role), whether it bypasses authentication, and the sensitivity of what is reachable. Scope: we use Scope Unchanged for database-side injection, because the impact stays in the data store the vulnerable application already owns, and Scope Changed when evaluation happens in a component that controls more than that application (for example JavaScript evaluated on a shared application server that hosts other services); explain the choice in the report. The vectors below are examples.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Unauthenticated login bypass through operator injection (any account, including administrators) | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | Anyone logs in as anyone; for the first account in the collection, usually as an administrator |
| Unauthenticated blind injection that reaches reset tokens or password hashes | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | Token extraction is account takeover for any named user, as in Rocket.Chat |
| Unauthenticated injection that reads other users' records (search, lookup) | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | Rate higher with volume and sensitivity (PII, financial, health) |
| Authenticated operator injection that crosses the user or tenant scope | High; Critical for sensitive multi-tenant data at scale | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Registration is often free, so `PR:L` is a weak barrier; the impact is an authorisation bypass |
| Authenticated pipeline injection with `$lookup` (any collection readable) | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Reach is the database user's whole read scope; raise if it includes credentials or other tenants |
| Pipeline injection that accepts `$out` or `$merge`, or filter injection into update endpoints | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1) | Writes to arbitrary collections; reported from allowlist analysis, not demonstrated |
| Client-controlled `$where` or `$function` in the database | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H` (9.1) unauthenticated; `PR:L` variant 8.1 | Per-document read of every field the query scans plus CPU denial of service; not operating-system execution by itself. Critical when unauthenticated and the scanned collection holds credentials or tokens |
| JavaScript evaluated in the application process (in-process filter matching, `eval`) | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | Code execution on the application server as the application's account; `S:C` (10.0) only when the host or its credentials reach beyond the application |
| Elasticsearch `query_string` injection that escapes a tenant clause | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Cross-tenant read through search |
| Operator injection confined to the caller's own data (filters that already return everything they own) | Low | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (4.3) | Real defect with no current cross-scope impact; rate up if any sensitive field becomes reachable |
| Unescaped regex or user-controlled pattern causing slow queries | Medium | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` (6.5) | Rate by the measured or documented cost; do not prove it with load |
| Missing type validation only (cast errors, no change in query meaning) | Low or Info | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) when errors leak query details; otherwise none | Hardening; combine with error leakage if messages expose queries |
| Server-side scripting enabled but unused, sanitiser middleware unmaintained | Info | none | Configuration hardening; raises the severity of any injection found |

When you report, include: the parameter and parser path (JSON, form, query string, GraphQL variable), the true/false pair or error that proves interpretation, the fields or collections shown to be reachable, the database user's privileges if known, confirmation that only your own accounts and canary values were used, and the fix in the client's stack.

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 / API Top 10 |
|---|---|---|---|---|
| GT-WEB-NOSQL-1 | WSTG-INJT-05, WSTG-INFO-06, WSTG-INFO-08, WSTG-ERRH-01 | v5.0.0-16.5.1 | CWE-209 (errors) | A05:2025 |
| GT-WEB-NOSQL-2 | WSTG-INJT-05 | v5.0.0-2.2.1, v5.0.0-15.3.5, v5.0.0-1.2.4 | CWE-1287, CWE-943 | A05:2025 |
| GT-WEB-NOSQL-3 | WSTG-INJT-05 | v5.0.0-1.2.4, v5.0.0-15.3.5 | CWE-943 | A05:2025 |
| GT-WEB-NOSQL-4 | WSTG-INJT-05, WSTG-INJT-04 | v5.0.0-1.2.4, v5.0.0-15.3.7, v5.0.0-1.5.3 | CWE-943, CWE-1287 | A05:2025 |
| GT-WEB-NOSQL-5 | WSTG-INJT-05, WSTG-ATHN-04 | v5.0.0-1.2.4, v5.0.0-15.3.5 | CWE-943 | A05:2025 (A07:2025 for the authentication impact) |
| GT-WEB-NOSQL-6 | WSTG-INJT-05 | v5.0.0-1.2.4 | CWE-943 | A05:2025 |
| GT-WEB-NOSQL-7 | WSTG-INJT-05 | v5.0.0-1.2.4, v5.0.0-1.2.9, v5.0.0-1.3.12 | CWE-943, CWE-1333 (ReDoS) | A05:2025 |
| GT-WEB-NOSQL-8 | WSTG-INJT-05, WSTG-INJT-11 | v5.0.0-1.3.2, v5.0.0-1.2.4 | CWE-943, CWE-95 | A05:2025 |
| GT-WEB-NOSQL-9 | WSTG-INJT-05 | v5.0.0-1.2.4, v5.0.0-15.3.1 | CWE-943 | A05:2025; API3:2023 for hidden-field projection |
| GT-WEB-NOSQL-10 | WSTG-INJT-05 | v5.0.0-1.2.4, v5.0.0-1.2.9 | CWE-943; CWE-77 for Redis command composition | A05:2025 |
| GT-WEB-NOSQL-11 | WSTG-INJT-05, WSTG-APIT-99 | v5.0.0-1.2.4, v5.0.0-8.2.2 | CWE-943 | A05:2025; API1:2023 when the scope is overridden |
| GT-WEB-NOSQL-12 | WSTG-INJT-05, WSTG-INJT-11 | v5.0.0-1.3.2, v5.0.0-13.2.2, v5.0.0-15.2.2 | CWE-943 (context) | A05:2025, A02:2025 for configuration |

ASVS levels: `v5.0.0-1.2.4` L1 (database queries, NoSQL included, use parameterisation or are otherwise protected), `v5.0.0-1.2.9` L2 (regex metacharacters escaped), `v5.0.0-1.3.2` L1 (avoid `eval()` and dynamic code execution such as SpEL), `v5.0.0-1.3.12` L3 (regular expressions free of exponential backtracking), `v5.0.0-1.5.3` L3 (parsers for the same data type behave consistently), `v5.0.0-2.2.1` L1 (positive input validation), `v5.0.0-8.2.2` L1 (data-specific access), `v5.0.0-13.2.2` L2 (least privilege for back-end connections), `v5.0.0-15.2.2` L2 (defences against resource-demanding functionality), `v5.0.0-15.3.1` L1 (return only the required fields), `v5.0.0-15.3.5` L2 (correct types and strict comparisons), `v5.0.0-15.3.7` L2 (HTTP parameter pollution), `v5.0.0-16.5.1` L2 (generic error messages).

CWE choice: CWE-943 (Improper Neutralization of Special Elements in Data Query Logic) is the entry for NoSQL injection. MITRE marks it as a Class with mapping allowed with review, and its existing Base-level children cover SQL, LDAP, XPath and XQuery rather than NoSQL, so CWE-943 is usually the most specific choice; add CWE-1287 (Improper Validation of Specified Type of Input, Base) when the root cause is purely the missing type check, and CWE-95 (Eval Injection, Variant) for JavaScript evaluation. CWE-74 and CWE-20 are marked discouraged for mapping. `A05:2025` is Injection in the OWASP Top 10:2025. The OWASP API Security Top 10 2023 has no injection category (the 2019 edition's API8:2019 Injection was dropped), so API mappings above are only for the authorisation or exposure side of a finding.

## References

**OWASP**

- WSTG: [NoSQL Injection (sub-page of WSTG-INJT-05)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/05.6-NoSQL_Injection), [Testing for SQL Injection (WSTG-INJT-05)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection), [HTTP Parameter Pollution (WSTG-INJT-04)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/04-HTTP_Parameter_Pollution), [Code Injection (WSTG-INJT-11)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/11-Code_Injection), [Bypassing Authentication Schema (WSTG-ATHN-04)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/04-Authentication/04-Bypassing_Authentication_Schema), [Improper Error Handling (WSTG-ERRH-01)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/08-Error_Handling/01-Improper_Error_Handling), [Testing GraphQL (WSTG-APIT-99)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/99-GraphQL)
- ASVS 5.0: [V1 Encoding and Sanitization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md), [V2 Validation and Business Logic](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x11-V2-Validation-and-Business-Logic.md), [V15 Secure Coding and Architecture](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md)
- [A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/)
- Cheat Sheets: [NoSQL Security](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html), [Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html), [Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html), [Node.js Security](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html) (query-string parsing into objects), [GraphQL](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)

**CWE**

- [CWE-943](https://cwe.mitre.org/data/definitions/943.html), [CWE-1287](https://cwe.mitre.org/data/definitions/1287.html), [CWE-95](https://cwe.mitre.org/data/definitions/95.html), [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html), [CWE-77](https://cwe.mitre.org/data/definitions/77.html), [CWE-209](https://cwe.mitre.org/data/definitions/209.html)

**PortSwigger**

- [NoSQL injection](https://portswigger.net/web-security/nosql-injection) (topic page and labs), [API testing](https://portswigger.net/web-security/api-testing), [GraphQL API vulnerabilities](https://portswigger.net/web-security/graphql)

**MongoDB**

- [`$where`](https://www.mongodb.com/docs/manual/reference/operator/query/where/), [`$function`](https://www.mongodb.com/docs/manual/reference/operator/aggregation/function/), [`$regex`](https://www.mongodb.com/docs/manual/reference/operator/query/regex/), [`$expr`](https://www.mongodb.com/docs/manual/reference/operator/query/expr/), [Server-side JavaScript](https://www.mongodb.com/docs/manual/core/server-side-javascript/) (`security.javascriptEnabled`, `--noscripting`), [configuration file options](https://www.mongodb.com/docs/manual/reference/configuration-options/)
- Mongoose: [API (`sanitizeFilter`, `trusted()`, `set()` options)](https://mongoosejs.com/docs/api/mongoose.html), [schema guide (`strictQuery`)](https://mongoosejs.com/docs/guide.html), [queries](https://mongoosejs.com/docs/queries.html)
- [Django MongoDB Backend QuerySet reference (`raw_aggregate()`)](https://django-mongodb-backend.readthedocs.io/en/latest/ref/models/querysets/)
- [Laravel MongoDB query builder (`where()` array handling, `whereRaw()`)](https://www.mongodb.com/docs/drivers/php/laravel-mongodb/current/query-builder/)

**Frameworks and other stores**

- Express: [migrating to Express 5](https://expressjs.com/en/guide/migrating-5.html) (query parser and `urlencoded` defaults), [application settings (`query parser`)](https://expressjs.com/en/5x/api/application/), [`express.json` and `express.urlencoded`](https://expressjs.com/en/5x/api/express/); [qs](https://github.com/ljharb/qs)
- [express-mongo-sanitize](https://github.com/fiznool/express-mongo-sanitize) (status as described above), [zod](https://zod.dev/api), [joi](https://github.com/hapijs/joi)
- Spring Data MongoDB: [repository query methods (`@Query`, SpEL)](https://docs.spring.io/spring-data/mongodb/reference/mongodb/repositories/query-methods.html), [CVE-2022-22980](https://spring.io/security/cve-2022-22980)
- Django REST framework: [serializer fields](https://www.django-rest-framework.org/api-guide/fields/)
- Elasticsearch: [`query_string` query](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query), [Query DSL (expensive queries)](https://www.elastic.co/docs/reference/query-languages/querydsl)
- CouchDB: [`_find`](https://docs.couchdb.org/en/stable/api/database/find.html), [Mango selectors](https://docs.couchdb.org/en/stable/ddocs/mango.html)
- DynamoDB: [expression attribute values](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ExpressionAttributeValues.html), [PartiQL `SELECT`](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.select.html), [`ExecuteStatement` (`Parameters`)](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ExecuteStatement.html)
- Redis: [security](https://redis.io/docs/latest/operate/oss_and_stack/management/security/) (string escaping and NoSQL injection)
- Prisma: [Client API reference (`findRaw`, `aggregateRaw`)](https://www.prisma.io/docs/orm/reference/prisma-client-reference)

**Static analysis**

- CodeQL: [Database query built from user-controlled sources (`js/sql-injection`)](https://codeql.github.com/codeql-query-help/javascript/js-sql-injection/), [NoSQL Injection (`py/nosql-injection`)](https://codeql.github.com/codeql-query-help/python/py-nosql-injection/)
- [njsscan](https://github.com/ajinabraham/njsscan) (rules also in the Semgrep registry)

**Tools**

- Burp extensions: [NoSQLi Scanner](https://portswigger.net/bappstore/605a859f0a814f0cbbdce92bc64233b4), [Content Type Converter](https://portswigger.net/bappstore/db57ecbe2cb7446292a94aa6181c9278), [InQL](https://portswigger.net/bappstore/296e9a0730384be4b2fffef7b4e19b1f), Param Miner
- [NoSQLMap](https://github.com/codingo/NoSQLMap), [nosqli](https://github.com/Charlie-belmer/nosqli), [Arjun](https://github.com/s0md3v/Arjun), [graphql-cop](https://github.com/dolevf/graphql-cop)
- Labs: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), [OWASP crAPI](https://github.com/OWASP/crAPI)
- Further reading on payloads: [PayloadsAllTheThings, NoSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection), [HackTricks, NoSQL injection](https://book.hacktricks.xyz/pentesting-web/nosql-injection)
