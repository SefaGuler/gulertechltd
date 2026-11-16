---
title: "Server-Side Prototype Pollution in Node.js"
date: 2026-11-15 20:14:00 +0000
subcategory: injection
summary: "Finding server-side prototype pollution in Node.js safely: unsafe merges and path setters, reversible black-box probes, gadget triage and fixes."
refs: [WSTG-INJT-22, v5.0.0-15.3.6, v5.0.0-15.3.3, v5.0.0-2.2.1, v5.0.0-15.2.1, "A08:2025", "A03:2025", CWE-1321, CWE-915, CWE-1395]
tags: [web, injection, prototype-pollution, nodejs, javascript, api-security]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Injection](/web/web-injection-testing-guide/). It covers server-side prototype pollution (`WSTG-INJT-22`, CWE-1321): a request whose *keys*, not just its values, are copied into a JavaScript object by a recursive merge, clone or path setter, so that a key such as `__proto__` or `constructor.prototype` writes onto `Object.prototype` and every object in the Node.js process inherits the attacker's property. It is an unusual injection class. Nothing is parsed by an interpreter at the moment of the request; the payload changes shared state, and the damage happens later, in unrelated code that reads a property it never set. That is also why testing it carelessly can break a production application for every user until the process restarts. You get the model (lookup chain, how keys reach the prototype, global versus local pollution, gadgets), the patterns that keep producing findings (hand-written merges, old lodash and friends, path setters, YAML and config imports), ten tests built on PortSwigger's non-destructive detection research with an explicit undo for each probe, and fixes: schema validation that rejects unknown keys, null-prototype objects and `Map`, patched libraries, `--disable-proto`, own-property checks, static analysis and regression tests. When the polluted property is a privilege flag, the outcome looks like mass assignment, so read this next to [mass assignment and BOPLA](/web/web-mass-assignment-bopla/). Client-side prototype pollution (browser sources, DOM XSS gadgets) will be covered in the Client-Side part of this series.

All requests and responses in this note are illustrative, written against fictional hosts (`app.example.com`, `api.example.com`). Where we say "in our lab", we reproduced the behaviour locally against the named package versions on our own machine at the time of writing; versions move, so re-check before relying on a detail.

## Contents

- [How it works](#how-it-works)
  - [Prototypes and the lookup chain](#prototypes-and-the-lookup-chain)
  - [How a key becomes a prototype write](#how-a-key-becomes-a-prototype-write)
  - [Global pollution and local prototype injection](#global-pollution-and-local-prototype-injection)
  - [Sources: where attacker-controlled keys come from](#sources-where-attacker-controlled-keys-come-from)
  - [Gadgets: why pollution matters](#gadgets-why-pollution-matters)
  - [Server-side versus client-side](#server-side-versus-client-side)
- [What goes wrong](#what-goes-wrong)
  - [Hand-written recursive merges](#hand-written-recursive-merges)
  - [Vulnerable library versions](#vulnerable-library-versions)
  - [Path setters and dotted-key updates](#path-setters-and-dotted-key-updates)
  - [Parsers configured to keep prototype keys](#parsers-configured-to-keep-prototype-keys)
  - [YAML, config and import features](#yaml-config-and-import-features)
  - [Denylist filters that miss variants](#denylist-filters-that-miss-variants)
  - [Security decisions that read inherited properties](#security-decisions-that-read-inherited-properties)
  - [Option objects that reach dangerous APIs](#option-objects-that-reach-dangerous-apis)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-WEB-PP-1: Fingerprint the runtime and map merge-shaped inputs](#gt-web-pp-1-fingerprint-the-runtime-and-map-merge-shaped-inputs)
  - [GT-WEB-PP-2: Polluted-property reflection with a unique canary](#gt-web-pp-2-polluted-property-reflection-with-a-unique-canary)
  - [GT-WEB-PP-3: Status code override probe](#gt-web-pp-3-status-code-override-probe)
  - [GT-WEB-PP-4: Formatting and header probes](#gt-web-pp-4-formatting-and-header-probes)
  - [GT-WEB-PP-5: Charset override probe on staging](#gt-web-pp-5-charset-override-probe-on-staging)
  - [GT-WEB-PP-6: Constructor route and filter variants](#gt-web-pp-6-constructor-route-and-filter-variants)
  - [GT-WEB-PP-7: Query strings, forms and path-setter inputs](#gt-web-pp-7-query-strings-forms-and-path-setter-inputs)
  - [GT-WEB-PP-8: YAML, config import and multipart sources](#gt-web-pp-8-yaml-config-import-and-multipart-sources)
  - [GT-WEB-PP-9: Gadget and impact assessment](#gt-web-pp-9-gadget-and-impact-assessment)
  - [GT-WEB-PP-10: Source, dependency and runtime review](#gt-web-pp-10-source-dependency-and-runtime-review)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Validate the shape at the boundary](#validate-the-shape-at-the-boundary)
  - [Null-prototype objects and Map](#null-prototype-objects-and-map)
  - [Safe merging and patched libraries](#safe-merging-and-patched-libraries)
  - [Read only own properties in security decisions](#read-only-own-properties-in-security-decisions)
  - [Harden options passed to child processes and templates](#harden-options-passed-to-child-processes-and-templates)
  - [Runtime flags and frozen prototypes](#runtime-flags-and-frozen-prototypes)
  - [Static analysis](#static-analysis)
  - [Regression tests](#regression-tests)
  - [Beyond Node: Deno and Python class pollution](#beyond-node-deno-and-python-class-pollution)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Prototypes and the lookup chain

JavaScript objects do not copy behaviour from classes; they delegate to a **prototype**. When code reads `user.isAdmin`, the engine looks for an own property called `isAdmin` on `user`. If there is none, it looks on `user`'s prototype, then on that object's prototype, and so on until it reaches `null`. Almost every plain object, array and function in a Node.js process ends that chain at the same object, `Object.prototype`. Objects created with `{}`, `JSON.parse()`, `new Object()` and most library helpers all inherit from it.

Two references lead to that shared object from any ordinary object:

| Reference | What it is | Notes |
|---|---|---|
| `obj.__proto__` | A getter/setter defined on `Object.prototype` that returns (or replaces) the object's prototype | Legacy accessor, still present in Node.js by default; removable with `--disable-proto` |
| `obj.constructor.prototype` | `obj.constructor` is `Object` for a plain object, and `Object.prototype` is the shared prototype | Not affected by `--disable-proto`; needs code that walks two levels and treats a function as something to recurse into |

If any code writes a property onto `Object.prototype`, every object in the process that does not have its own property of that name now "has" it. Arrays and class instances inherit it too, because their prototype chains end at `Object.prototype` as well. The change lasts until the process exits: there is no per-request or per-user copy of `Object.prototype`. That one fact drives both the impact (one request can change behaviour for every user) and the testing rules in [Before you start](#before-you-start).

### How a key becomes a prototype write

Prototype pollution needs three things in sequence: an attacker-controlled **key**, an operation that **walks into** that key, and an **assignment** at the end of the walk.

```javascript
// The classic unsafe recursive merge
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null &&
        typeof target[key] === 'object') {
      merge(target[key], source[key]);   // walks into target['__proto__'] === Object.prototype
    } else {
      target[key] = source[key];         // assignment lands on Object.prototype
    }
  }
  return target;
}

const settings = {};
merge(settings, JSON.parse('{"__proto__": {"polluted": "yes"} }'));
console.log({}.polluted);   // "yes" — a brand-new, unrelated object now has it
```

Note the role of `JSON.parse`. On its own it is safe: it creates an **own data property** literally named `__proto__` and does not change the parsed object's prototype. In our lab, `Object.keys(JSON.parse('{"__proto__":{} }'))` returned `["__proto__"]` and the object's prototype was still `Object.prototype`. Object spread (`{ ...parsed }`) is also safe, because it defines own properties rather than assigning. The danger appears one step later, when a merge reads `target['__proto__']`. On the *target*, which is an ordinary object, that read goes through the inherited `__proto__` getter and returns `Object.prototype`, and the merge recurses into it. So the "parser" is rarely the bug; the bug is code that copies parsed keys into another object without checking them.

The common sinks:

- **Recursive merge, extend and deep-defaults** functions: `merge(a, b)`, `deepExtend`, `defaultsDeep`, `mixin-deep`, hand-written `deepMerge` utilities.
- **Deep clone** functions that rebuild an object key by key into a fresh `{}`.
- **Path setters** that take a dotted or bracketed path: `set(obj, 'a.b.c', value)`, `_.set`, `setWith`, `zipObjectDeep`, "update a setting by path" helpers, JSON-path style patching.
- **Parsers that build nested objects** from flat input: query strings with bracket or dot notation, multipart field names, CSV or spreadsheet headers turned into nested keys, environment-style `A__B__C` keys.

### Global pollution and local prototype injection

Keep two outcomes apart, because they are tested and rated differently.

**Global pollution** writes onto `Object.prototype` itself (the merge example above). Every object in the process is affected, for every user, until restart.

**Local prototype injection** replaces the prototype of *one* object with an attacker-supplied object. `Object.assign(target, source)` uses ordinary assignment on the target, so a parsed own key `__proto__` triggers the `__proto__` *setter* on `target` and swaps its prototype:

```javascript
const opts = Object.assign({}, JSON.parse('{"__proto__": {"isAdmin": true} }'));
opts.isAdmin;                      // true  (inherited from the injected prototype)
Object.hasOwn(opts, 'isAdmin');    // false
({}).isAdmin;                      // undefined — nothing global changed
```

That is the behaviour we saw in our lab, and it is what CVE-2025-64718 describes for js-yaml before 4.1.1 and 3.14.2 (the prototype of the *parsed result* could be changed through `__proto__` in a merge key). Local injection is limited to that object, so its impact is usually what you would get from mass assignment on the same object (see [mass assignment and BOPLA](/web/web-mass-assignment-bopla/)): a property the developer never meant you to set, visible only to code that reads it through the chain. It cannot persist across requests or reach other users unless the object itself is stored or shared.

### Sources: where attacker-controlled keys come from

Any input whose *structure* the client controls can carry keys. In Node.js applications look at:

| Source | Example | Notes |
|---|---|---|
| JSON bodies | `PATCH /api/me/preferences` with nested objects | The most common source; `express.json()` keeps `__proto__` as an own key |
| Query strings with nesting | `?filter[status]=open`, `?settings.theme=dark` | `qs` (Express 4's default "extended" parser) drops `__proto__` and, by default, any key that would shadow an `Object.prototype` property such as `constructor`; risk returns with `allowPrototypes: true`, custom parsers, or code that turns a parameter name into a path |
| URL-encoded and multipart forms | `user[profile][bio]=…` | Same parser questions; `express-fileupload` with `parseNested` had CVE-2020-7699 |
| YAML, TOML, INI and JSON config uploads | "Import workspace settings", "upload pipeline definition" | Often merged into defaults with a deep merge |
| Path-plus-value APIs | `{"path": "notifications.email", "value": false}` | A path setter is the sink; the path string is the source |
| GraphQL `JSON` scalars and input objects | A custom `JSON` scalar for "metadata" | Typed inputs reject unknown keys; free-form JSON scalars do not |
| Message queues and webhooks | An inbound webhook payload merged into a job object | Pollution in a worker process affects all jobs that worker handles |
| Headers and cookies parsed into objects | JSON in a cookie, `X-Client-Config` | Less common, same pattern |

Express 5 changed two defaults that shrink the query-string and form surface: the default query parser is now "simple" (Node's `querystring`, no nesting), and `express.urlencoded()` defaults to `extended: false`. JSON bodies are unaffected by either change.

### Gadgets: why pollution matters

Pollution is a primitive, not an outcome. Its impact depends on a **gadget**: code that later reads a property it did not set, finds the inherited value, and does something meaningful with it. The gadgets we see in assessments fall into a few families, described here in prose only:

- **Authorisation and feature flags.** `if (user.isAdmin)`, `if (req.session.role === 'admin')` where the property is sometimes absent, `options.allowUnsafe`, `config.debug`. If the object lacks an own property, the polluted one decides. This is where pollution meets [mass assignment and BOPLA](/web/web-mass-assignment-bopla/), except that every user's object is affected at once.
- **Framework and library options.** Defaults objects that are read with `options.x || default`. Express, body-parser, `http-errors`, `qs` and `cors` all have options that, on some versions, can be changed through inherited properties; PortSwigger's detection techniques are built on exactly these (status codes, JSON indentation, character sets, exposed headers).
- **Denial of service.** Polluting a property that core code reads (an encoding, a header expectation, `toString`-style names, a length) can make every request fail or crash the process. Several such properties are known and are deliberately excluded from this note's tests.
- **Code execution.** Node's `child_process` functions accept option objects (`shell`, `env`, `argv0`, `execArgv`, `input` and others). If the application spawns a process and does not set an option explicitly, an inherited value is used; the Silent Spring paper (USENIX Security 2023) found 11 such universal gadgets in Node.js core APIs and used them for eight remote code execution exploits in NPM CLI, Parse Server and Rocket.Chat, and the GHunter follow-up (USENIX Security 2024) reported 56 new gadgets in Node.js and 67 in Deno. Template engines are the other classic family: several have read compile options from objects that inherit from `Object.prototype`, which turns pollution into server-side template injection (see [SSTI](/web/web-server-side-template-injection/)). We do not reproduce these chains; the references are in [Real-world cases](#real-world-cases) and [References](#references).

The practical consequence for a tester: once you have confirmed global pollution, the question "what reads inherited properties in this process?" is mostly answered by source code, dependency lists and staging experiments, not by trying gadget payloads against production.

### Server-side versus client-side

The same root cause exists in browsers: a client-side script parses `location.hash` or `location.search` into an object with an unsafe merge, and a library later reads a polluted property while building HTML, which typically ends in DOM XSS. The differences matter for scoping and reporting:

| | Server-side (this note) | Client-side |
|---|---|---|
| Where the prototype lives | The Node.js process serving all users | The victim's browser tab |
| Persistence | Until the process restarts | Until the page reloads |
| Who is affected | Everyone whose requests reach that process | The one user who opened the crafted URL |
| How you see it | Indirectly: changed status codes, formatting, headers, behaviour | Directly in DevTools: `({}).canary` in the console; DOM Invader automates source and gadget discovery |
| Typical impact | Privilege escalation, DoS, code execution | DOM XSS, client-side control bypass |

If your probe works only from a URL fragment and you confirm it in the browser console, you are testing client-side pollution; that belongs to the Client-Side part of this series. If the *server's* behaviour changes for a request made from a different client after your probe, it is server-side.

## What goes wrong

### Hand-written recursive merges

**What happens:** a team writes its own `deepMerge(defaults, req.body)` to apply partial updates to a settings document, a feature-flag override, or a "save filters" endpoint. The function iterates with `for…in` or `Object.keys`, recurses when both sides are objects, and never checks the key name.

**Why it matters:** this is the single most common source of new findings, because dependency scanners do not see it. One request can pollute the prototype for every user of that process.

**Where to look:** endpoints that accept *partial nested* objects and return the merged result: user preferences, notification settings, dashboard layouts, saved searches, tenant branding, "advanced options" panels, admin configuration screens, import features. In code, any function whose name contains `merge`, `extend`, `assign`, `defaults`, `clone` or `copy` and that calls itself.

### Vulnerable library versions

**What happens:** the application uses a utility library version with a known prototype pollution advisory and passes request data to the affected function. The classic examples are lodash's merge family:

| Advisory | Affected | What it says (paraphrased from NVD) |
|---|---|---|
| CVE-2018-3721 | lodash before 4.17.5 | `merge`, `mergeWith`, `defaultsDeep` could modify `Object.prototype` through `__proto__` |
| CVE-2018-16487 | lodash before 4.17.11 | The same functions could still be tricked into adding or modifying `Object.prototype` properties |
| CVE-2019-10744 | lodash before 4.17.12 | `defaultsDeep` polluted the prototype through a `constructor` payload |
| CVE-2020-8203 | lodash before 4.17.20 | `zipObjectDeep` polluted the prototype |
| CVE-2019-10747, CVE-2021-23440 | set-value before 3.0.1; the later one a bypass with array keys, fixed in 2.0.1 and 4.0.1 | Path setter reachable through `__proto__`, `constructor` and `prototype` |
| CVE-2020-28499 | `merge` package (all versions at the time of the advisory) | `_recursiveMerge` pollutes the prototype |
| CVE-2022-24999 | qs before 6.10.3, as used in Express before 4.17.3 | An `__proto__` key in the query string could hang the Node process (DoS, not pollution of the global prototype) |
| CVE-2025-64718 | js-yaml before 4.1.1 and 3.14.2 | The prototype of a parsed document could be changed through `__proto__` (local prototype injection) |

In our lab, lodash 4.17.4 polluted `Object.prototype` through `merge` (both `__proto__` and `constructor.prototype`), `defaultsDeep`, `set` (both path forms) and `zipObjectDeep`; lodash 4.17.21 blocked all of them.

**Why it matters:** the vulnerable function only matters if attacker-controlled structure reaches it. A vulnerable lodash used only on constants is a dependency hygiene finding, not a prototype pollution finding. Conversely, transitive dependencies are common: an old lodash pulled in by an internal SDK can still be the one your request reaches.

**Where to look:** `package-lock.json`, `yarn.lock` or `pnpm-lock.yaml` if you have them; otherwise error stack traces (they print `node_modules/<package>/…` paths), source maps, and behaviour differences between `__proto__` and `constructor.prototype` payloads that hint at which merge is in use.

### Path setters and dotted-key updates

**What happens:** the API accepts a path and a value (`{"path": "profile.address.city", "value": "Leeds"}`), or flattens a form into dotted keys, and calls a setter such as `_.set(doc, path, value)` or a hand-written loop that splits on `.` and walks into each segment. A path of `__proto__.x` or `constructor.prototype.x` lands on the prototype.

**Why it matters:** path setters often have no "both sides are objects" guard at all, so they reach the prototype even in code that would never merge a whole body. They also show up in admin tools ("set config key"), feature-flag services and spreadsheet importers.

**Where to look:** JSON-Patch-like endpoints, "update a single setting" endpoints, i18n or CMS key editors, bulk-edit features, any field named `path`, `key`, `field`, `property` or `selector`.

### Parsers configured to keep prototype keys

**What happens:** the parser itself is safe by default, but someone switched the safety off or replaced it. `qs` drops `__proto__` and, by default, ignores keys that would overwrite `Object.prototype` properties; with `allowPrototypes: true`, keys such as `constructor[prototype][x]` survive as nested own properties and become dangerous when a vulnerable merge later consumes them. In our lab, current `qs` dropped `__proto__` even with `allowPrototypes: true`, but kept `constructor` keys. Custom parsers (for example, a hand-written `a.b.c=value` decoder, or `express-fileupload` with `parseNested` before 1.1.8) may not drop anything.

**Why it matters:** testers often skip query strings because "Express drops `__proto__`". That is true of the default configuration only.

**Where to look:** `app.set('query parser', …)`, `qs.parse(…, { allowPrototypes: true })`, `express.urlencoded({ extended: true })` together with a downstream merge, middleware that converts `a.b` keys into nested objects, multipart libraries with "nested" options.

### YAML, config and import features

**What happens:** the application lets users upload or paste configuration (YAML pipeline files, JSON theme files, "import settings", Helm-style values, OpenAPI documents) and merges it into defaults. YAML adds its own feature: merge keys (`<<`), which older js-yaml versions handled in a way that let `__proto__` change the parsed object's prototype (CVE-2025-64718).

**Why it matters:** import features run with the importing user's privileges but often in a shared worker process, and they are designed to accept arbitrary nested structure, so there is no schema to stop unexpected keys.

**Where to look:** upload and import endpoints, CI or workflow definitions, integration settings, "restore from backup" features, admin bulk configuration.

### Denylist filters that miss variants

**What happens:** after a finding, developers add `if (key === '__proto__') continue;` or strip the substring `__proto__` from keys. Both are incomplete. The first misses `constructor` → `prototype`. The second, if it strips once and does not loop, turns a nested spelling back into the blocked word after stripping. PortSwigger's "bypassing flawed input filters" lab is built on this pattern.

**Why it matters:** a denylist is defence in depth, not a fix. You report an incomplete filter as part of the finding, with one or two variants as evidence, not as a bypass catalogue.

**Where to look:** any key filtering that is a string comparison or a `replace()`, filtering applied at only one of several entry points, or filtering on the top level only (nested keys never checked).

### Security decisions that read inherited properties

**What happens:** authorisation code reads optional properties that are sometimes absent: `if (user.isAdmin)`, `if (account.features.betaExport)`, `const limit = plan.maxSeats || 5`, `if (!opts.requireMfa)`. A polluted `isAdmin: true` or `requireMfa: false` changes the answer for every user whose object lacks its own property.

**Why it matters:** this is the gadget family that turns a "harmless" pollution into privilege escalation, and it lives in the application's own code, so no public gadget list covers it. It is also the most dangerous to probe on a live system, because the change applies to everyone (see [GT-WEB-PP-9](#gt-web-pp-9-gadget-and-impact-assessment)).

**Where to look:** session and user objects built from database rows (where nullable columns become missing properties), feature-flag lookups, plan and quota objects, middleware options with boolean defaults.

### Option objects that reach dangerous APIs

**What happens:** the application calls `child_process.spawn`, `exec`, `execFile` or `fork`, renders templates, or builds HTTP requests with option objects that do not set every security-relevant option explicitly. Inherited values fill the gaps.

**Why it matters:** this is how pollution becomes code execution (Silent Spring, GHunter, the Kibana CVE-2019-7609 Timelion exploit, Parse Server CVE-2022-24760). Note that the request that pollutes and the request that triggers the gadget can be minutes apart and come from different users, which makes such issues hard to reproduce and easy to miss in logs.

**Where to look:** features that generate PDFs or thumbnails, run converters, call `git`, spawn workers, or render user-selected templates; any `spawn`/`exec` call whose options object is built from defaults.

## Testing

### Before you start

**Scope and permission.** Test only on an authorised engagement (written scope and rules of engagement), a bug bounty programme whose rules allow this kind of testing, or a lab. Prototype pollution deserves its own line in the rules of engagement, because unlike most injection probes it **changes shared server state**. A polluted property persists for the lifetime of the Node.js process (PortSwigger's research says this plainly and notes that often the only way to undo a change is a restart), and it affects every user whose requests that process handles. Before you send the first `__proto__` key to a production system, agree in writing:

- that server-side prototype pollution probes are in scope for named hosts and endpoints;
- a test window, and a client contact who can **restart the application processes** on request;
- whether a **staging environment** with the same Node.js, framework and library versions exists. If it does, run everything beyond the reversible probes below on staging, and use production only to confirm that the same input reaches the same code.

**Proxy setup.** One Burp project per engagement with scope set to the in-scope hosts and Logger on, so you have exact timestamps for every probe and undo (the client will want them if anything misbehaves). Use the Raw tab when comparing JSON responses; the Pretty view re-indents JSON and hides the `json spaces` change. The **Server-Side Prototype Pollution Scanner** extension from the BApp Store (PortSwigger's open-source implementation of the research) automates the non-destructive techniques; run it on selected requests with a single technique rather than the full scan, which sends many more requests, and prefer it on staging.

**Use only reversible probes on shared systems.** The probes in this note are chosen because you can switch them off again, or because their side effect is cosmetic. Never use properties known to break processing for everyone. PortSwigger's research documents several (polluting a stream `encoding` crashed the Node process; polluting `expect` made every request return 417 with no way found to remove it; polluting `body`/`_body` made Express serve attacker content to everyone). Do not experiment with property names to "see what happens" on a live system; any name you pollute applies to every object in the process.

| Probe | What you pollute | Side effect for other users while active | Undo (our lab, at the time of writing) | Where to use |
|---|---|---|---|---|
| Status override ([PP-3](#gt-web-pp-3-status-code-override-probe)) | `status` set to an unusual 4xx/5xx code | Some error responses (for example malformed JSON) get that code; any application object without its own `status` now reads the value | Pollute `status` with `0`: body-parser's 400 came back | Production with approval |
| JSON spaces ([PP-4](#gt-web-pp-4-formatting-and-header-probes)) | `json spaces` set to a small number | All JSON responses indented | Pollute `json spaces` with `0` | Production with approval; only Express 4.17.x and older react |
| CORS exposed headers ([PP-4](#gt-web-pp-4-formatting-and-header-probes)) | `exposedHeaders` set to a canary header name | Extra `Access-Control-Expose-Headers` value on responses | Pollute `exposedHeaders` with `""`: the header disappeared | Production with approval, only if the `cors` middleware is in use |
| Canary reflection ([PP-2](#gt-web-pp-2-polluted-property-reflection-with-a-unique-canary)) | A unique, meaningless property name | Code that copies objects with `for…in` picks it up; it can end up **stored in other users' records** | None: the key stays until restart; you can only change its value | Staging first; production only with a clearly fake name and the client's agreement |
| Charset override ([PP-5](#gt-web-pp-5-charset-override-probe-on-staging)) | `content-type` with a UTF-7 charset | In our lab, **every** later request was parsed with the polluted content type: form posts broke, `+` sequences in JSON were decoded | None found; restart needed | **Staging or lab only** |
| Privilege flags, child-process or template options ([PP-9](#gt-web-pp-9-gadget-and-impact-assessment)) | `isAdmin`, `shell`, `NODE_OPTIONS`, template options | Applies to every user and every spawned process | Restart | **Staging or lab only**, described in prose here |

"Undo" only neutralises the value. The key itself remains on `Object.prototype` until the process restarts, with its harmless value. When the client's code also reads a property of that name (`status` is a common field name), even the neutral value can matter; check the code or choose another probe.

**Multiple processes.** Most production deployments run several Node.js processes: cluster workers, PM2 instances, container replicas behind a load balancer, warm serverless containers. A probe pollutes only the process that handled it. Expect inconsistent results (two requests out of five show the effect), repeat the observation a few times before concluding, and send the undo the same way until the effect has gone across a bounded number of follow-up requests. Record which instance identifiers (if the app exposes them, for example a response header) were affected, and tell the client; a restart of all instances is the clean end state.

**Safe proofs and stop rules.**

- The proof of server-side pollution is a **reversible behaviour change you caused and then removed**. You do not need, and should not attempt, a privilege escalation or command execution on a shared production system to make the finding credible. Gadget impact is assessed on staging, in a lab, or from code ([PP-9](#gt-web-pp-9-gadget-and-impact-assessment)).
- Stop immediately and contact the client if, after a probe: unrelated endpoints start returning errors, the undo does not restore behaviour, response times degrade, or monitoring alerts fire. Give them the timestamps and the exact properties you polluted so they can restart the affected processes.
- If a response unexpectedly contains another user's data (a reflected object that is not yours, someone else's settings), stop that line of testing, keep only minimum redacted evidence, do not request more, and report it immediately.
- Do not run payload lists or fuzzers (prototype pollution wordlists, scanner full scans) against production. A handful of hand-written requests per endpoint is enough.

**Rate limits.** Keep to a low request rate (one or two requests per second is a sensible default unless the rules say otherwise), and leave a pause between pollute, observe and undo so that you can correlate each change with its effect. Never script repeated pollution across many endpoints at once; you would not know which request caused which state.

**Accounts.** Use accounts you control. For property-injection impact (does a polluted flag change *your* permissions?), you need at least a normal user and a way to observe what a higher role sees; the actual escalation proof happens on staging.

### GT-WEB-PP-1: Fingerprint the runtime and map merge-shaped inputs

*Guler Tech methodology.* Implements the source-identification step of WSTG-INJT-22.

#### What it checks

Whether the back end (or a component of it) runs on Node.js or another JavaScript runtime, and which requests carry client-controlled nested structure into code that is likely to merge, clone or set by path. The output is the shortlist for tests 2 to 8.

#### Prerequisites

Burp Logger history from a full walk-through as a normal user; API documentation if available (OpenAPI, GraphQL schema, Postman collections); any client-side bundles or mobile apps that talk to the API.

#### Steps

1. Look for runtime hints: `X-Powered-By: Express` (often removed), framework error pages, stack traces with `node_modules/` or `at Object.<anonymous>` lines, `ETag` formats, `Content-Type: application/json; charset=utf-8` exactly as Express sends it, Next.js or Nuxt artefacts (`/_next/`, `/_nuxt/`) for full-stack apps, and default 404 bodies such as `Cannot GET /x`. Microservice architectures can mix runtimes, so fingerprint per host and per path prefix.
2. Filter Logger for requests with nested JSON bodies, bracket or dotted parameter names (`a[b]=`, `a.b=`), path-plus-value pairs, and uploads of structured files (YAML, JSON, TOML).
3. For each candidate, note whether the response **returns the merged object** (good for reflection, [PP-2](#gt-web-pp-2-polluted-property-reflection-with-a-unique-canary)), whether it accepts **partial updates** (a strong hint of a merge), and whether malformed input produces a **framework error** you can use as an oracle ([PP-3](#gt-web-pp-3-status-code-override-probe)).
4. Send a malformed JSON body to one harmless endpoint and record the default error status and body. This is your baseline for the status probe.

```http
POST /api/me/preferences HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
Content-Type: application/json

{"theme":
```

```bash
curl -s -i -X POST https://api.example.com/api/me/preferences \
  -H 'Authorization: Bearer <TOKEN_USER_A>' -H 'Content-Type: application/json' \
  --data '{"theme":'
```

#### Observation

An inventory such as (illustrative):

| Request | Structure | Returns merged object | Partial update | Error oracle |
|---|---|---|---|---|
| `PATCH /api/me/preferences` | nested JSON | yes | yes | 400 `SyntaxError` page |
| `PUT /api/workspaces/{id}/settings` | nested JSON | no (204) | yes | 400 |
| `POST /api/import/config` | YAML upload | summary only | merged into defaults | 422 |
| `GET /api/search?filter[status]=open` | bracket query | results | no | none |
| `POST /api/me/settings/set` | `{"path":…,"value":…}` | yes | yes | 400 |

#### Evaluation

No finding by itself. It tells you where to spend the limited number of probes you are willing to send to production. A verbose stack trace that reveals paths and library versions is reportable separately as information disclosure.

#### False positives

Hosts that only proxy to a non-JavaScript back end (a Node.js BFF in front of a Java API: the merge, if any, is in the BFF); static hosting on a Node-based CDN; Next.js sites whose API routes are thin wrappers around a third-party service.

#### Automation

Param Miner can find unlinked parameters on these endpoints. Keep the inventory in the engagement notes and reuse it for regression testing after a fix. For CI, the equivalent is an inventory of handlers that pass `req.body` into merge or set helpers, which [static analysis](#static-analysis) produces.

### GT-WEB-PP-2: Polluted-property reflection with a unique canary

*Guler Tech methodology.* Implements the server-side black-box detection of WSTG-INJT-22 (polluted-property reflection, as described by PortSwigger).

#### What it checks

Whether a nested `__proto__` key in a JSON body reaches a merge that writes onto a prototype, observed through a property you never sent appearing in a later response.

#### Prerequisites

An endpoint from [PP-1](#gt-web-pp-1-fingerprint-the-runtime-and-map-merge-shaped-inputs) that accepts a nested object and returns an object built from it (or another endpoint that returns objects copied with `for…in`). Your own account. Agreement that reflection probes are acceptable on this environment (see the table in [Before you start](#before-you-start): the canary cannot be removed without a restart). Run on staging first.

#### Steps

1. Choose a canary that cannot collide with anything real: `gt_pp_canary_<8 random hex>`, value `"1"`. Record it with a timestamp.
2. First send a **control** key that is not special, to see what normal reflection looks like:

```http
PATCH /api/me/preferences HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
Content-Type: application/json

{"theme":"dark","__proto__x":{"gt_pp_canary_3f9a1c2e":"1"} }
```

3. Then send the real probe:

```http
PATCH /api/me/preferences HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
Content-Type: application/json

{"theme":"dark","__proto__":{"gt_pp_canary_3f9a1c2e":"1"} }
```

4. Look for the canary in the response, then in a **different** request that returns a fresh object (for example `GET /api/me`, or the same `GET` as user B). The second observation separates "the server echoed my body" from "the prototype was polluted".

```bash
curl -s https://api.example.com/api/me -H 'Authorization: Bearer <TOKEN_USER_B>' | jq 'has("gt_pp_canary_3f9a1c2e")'
```

#### Observation

Illustrative outcomes:

```json
{"theme":"dark","__proto__x":{"gt_pp_canary_3f9a1c2e":"1"} }
```

The control key is stored and echoed as an ordinary nested object: normal.

```json
{"theme":"dark","gt_pp_canary_3f9a1c2e":"1"}
```

After the real probe, the canary appears as a **top-level** property, and later appears in user B's `GET /api/me` too: the merge walked into `__proto__` and the response serialiser (or a `for…in` copy) picked up the inherited property. In our lab, a handler that built its response with `for (const k in obj)` returned the canary on every later request, from any client.

PortSwigger also describes a quieter variant: if `__proto__x` is reflected but `__proto__` silently disappears, the key is being filtered or consumed, which is worth following up with [PP-3](#gt-web-pp-3-status-code-override-probe) rather than concluding "safe".

#### Evaluation

- **Fail (global pollution):** the canary appears in a response to a different request, ideally from a different session, after your probe. Report it, then tell the client the canary name and that a restart removes it.
- **Fail (local injection):** the canary appears only in the object you just updated, and is inherited rather than own (for example, it is visible in a template or business check but not when the object is re-serialised from the database). Treat as local prototype injection; impact is assessed like mass assignment on that object.
- **Pass (for this source):** the control and the real probe behave the same and the canary never appears elsewhere. Continue with [PP-3](#gt-web-pp-3-status-code-override-probe), because absence of reflection is not absence of pollution: `JSON.stringify` serialises only own properties, so most JSON APIs never reflect inherited ones.

#### False positives

The application stores arbitrary nested keys and echoes them: `{"__proto__": {...} }` stored as a literal key and returned under `__proto__` is not pollution. A document database that keeps your whole body and returns it later. Seeing the canary only in your own response, never in a fresh object, is reflection of your input, not proof.

#### Automation

The BApp extension's reflection technique automates the `__proto__` versus `__proto__x` comparison. For CI, the [regression test](#regression-tests) sends the same body to every handler that accepts nested JSON and asserts that `({}).<canary>` is still `undefined` afterwards.

### GT-WEB-PP-3: Status code override probe

*Guler Tech methodology.* Implements WSTG-INJT-22 server-side detection using the status-code technique from PortSwigger's research.

#### What it checks

Whether polluting `status` changes the HTTP status of a framework error that does not set its own status. In Express applications, `body-parser` builds its parse errors through `http-errors`, which looks for `status`/`statusCode` on the underlying error object; an inherited value is used when there is no own one. In our lab this still worked on current Express 4 and Express 5 with their bundled body-parser versions.

#### Prerequisites

The baseline malformed-JSON response from [PP-1](#gt-web-pp-1-fingerprint-the-runtime-and-map-merge-shaped-inputs) (status and body). A candidate merge endpoint. Approval for reversible probes on this environment.

#### Steps

1. Confirm the baseline: malformed JSON returns, say, 400.
2. Pollute `status` with an unusual code **between 400 and 599** (outside that range, Node and Express fall back to 500 and you learn nothing). Pick one the application is unlikely to use, such as 555 or 518.

```http
PATCH /api/me/preferences HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
Content-Type: application/json

{"theme":"dark","__proto__":{"status":555} }
```

3. Send the malformed JSON again (from the same or another session) and record the status.
4. **Undo straight away:** pollute `status` with `0`, then confirm that malformed JSON returns the original status again. Repeat the check a few times if there are several instances.

```bash
B=https://api.example.com/api/me/preferences
H=(-H 'Authorization: Bearer <TOKEN_USER_A>' -H 'Content-Type: application/json')
curl -s -o /dev/null -w '%{http_code}\n' -X PATCH "$B" "${H[@]}" --data '{"theme":'                                  # baseline, e.g. 400
curl -s -o /dev/null -w '%{http_code}\n' -X PATCH "$B" "${H[@]}" --data '{"theme":"dark","__proto__":{"status":555} }'  # probe
curl -s -o /dev/null -w '%{http_code}\n' -X PATCH "$B" "${H[@]}" --data '{"theme":'                                  # 555 if polluted
curl -s -o /dev/null -w '%{http_code}\n' -X PATCH "$B" "${H[@]}" --data '{"theme":"dark","__proto__":{"status":0} }'    # undo
curl -s -o /dev/null -w '%{http_code}\n' -X PATCH "$B" "${H[@]}" --data '{"theme":'                                  # back to 400
```

#### Observation

In our lab (illustrative output): `400`, `200`, `555`, `200`, `400`. A custom JSON error body may also change: some error handlers echo `err.status` into the body, so `{"error":"Bad Request","status":555}` is the same signal.

#### Evaluation

- **Fail:** the status changes to exactly your chosen code after the probe and returns to the baseline after the undo. That is a confirmed global prototype pollution in the process that handled the requests. Report the endpoint, the merge-shaped input, the timestamps and the undo.
- **Pass (for this endpoint):** no change after two or three attempts. Not proof of safety: the app may set its own error status, use a different body parser, or have no reachable error path. Try another endpoint or [PP-4](#gt-web-pp-4-formatting-and-header-probes).

#### False positives

An application that legitimately maps `status` fields from your body into its error responses (for example a "report a problem" endpoint that echoes a status you sent). Rate limiting or a WAF returning its own code. A different instance answering the malformed request (the probe went to instance 1, the check to instance 2): repeat before concluding either way.

#### Automation

The BApp extension's status technique runs this check per request. On staging you can script the five-step sequence above per endpoint with a pause between steps. In CI, run the same sequence against the test server started in the [regression tests](#regression-tests); it needs no knowledge of the application's own gadgets.

### GT-WEB-PP-4: Formatting and header probes

*Guler Tech methodology.* Implements WSTG-INJT-22 server-side detection using the JSON spaces and exposed-headers techniques from PortSwigger's research.

#### What it checks

Whether polluting a framework option that has a cosmetic, reversible effect changes every later response. Two options are useful:

- **`json spaces`** (Express's indentation setting for `res.json()`). Express 4.18.0 changed `app.get()`/`app.set()` to ignore values inherited from `Object.prototype`, so only Express 4.17.x and older react; in our lab 4.17.3 indented every JSON response after the probe and current 4.x and 5.x did not. A positive result therefore also tells you the Express version is old.
- **`exposedHeaders`** (an option of the `cors` middleware). If the app uses `cors()` with default options, a polluted value is added to `Access-Control-Expose-Headers` on responses to cross-origin requests.

PortSwigger's research also describes an OPTIONS-based variant (polluting `head` removed `HEAD` from the router's OPTIONS response). We have not verified an undo for it; keep it for staging.

#### Prerequisites

As for [PP-3](#gt-web-pp-3-status-code-override-probe). For the CORS variant, evidence that the API answers cross-origin requests (`Access-Control-Allow-Origin` in responses to a request with an `Origin` header).

#### Steps

1. Baseline: request a JSON endpoint and save the **raw** body; for CORS, send a request with `Origin: https://example.org` and note `Access-Control-Expose-Headers` (usually absent).
2. Pollute one option at a time:

```http
PATCH /api/me/preferences HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
Content-Type: application/json

{"theme":"dark","__proto__":{"json spaces":4} }
```

```http
PATCH /api/me/preferences HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
Content-Type: application/json

{"theme":"dark","__proto__":{"exposedHeaders":"gt-pp-canary-3f9a"} }
```

3. Re-request the baseline endpoint (from another session if you can) and compare.

```bash
curl -s https://api.example.com/api/me -H 'Authorization: Bearer <TOKEN_USER_B>' | head -c 200; echo
curl -s -o /dev/null -D - https://api.example.com/api/me -H 'Origin: https://example.org' \
  -H 'Authorization: Bearer <TOKEN_USER_B>' | grep -i '^access-control-expose-headers'
```

4. **Undo:** `{"__proto__":{"json spaces":0} }` and `{"__proto__":{"exposedHeaders":""} }`; confirm the baseline is back.

#### Observation

Illustrative, after the `json spaces` probe on an old Express:

```text
{
    "id": 1001,
    "theme": "dark"
}
```

instead of `{"id":1001,"theme":"dark"}`. After the CORS probe: `Access-Control-Expose-Headers: gt-pp-canary-3f9a` on a response that did not have it. In our lab both undos restored the baseline.

#### Evaluation

- **Fail:** indentation or the exposed header appears on responses to *other* requests after the probe and disappears after the undo. Confirmed global pollution. A positive `json spaces` result also supports a separate outdated-component finding (Express before 4.18.0).
- **Pass (for this probe):** no change. On current Express, `json spaces` cannot react, so a negative result says nothing about pollution; rely on [PP-3](#gt-web-pp-3-status-code-override-probe).

#### False positives

An app that sets `json spaces` itself (all responses already indented: you cannot see a change). A reverse proxy or API gateway that re-serialises JSON or rewrites CORS headers. Comparing in Burp's Pretty tab instead of Raw.

#### Automation

The BApp extension implements both techniques. In CI, assert that `res.json()` output and CORS headers are identical before and after sending a polluting body to every JSON handler.

### GT-WEB-PP-5: Charset override probe on staging

*Guler Tech methodology.* Implements WSTG-INJT-22 server-side detection using the charset technique from PortSwigger's research. **Staging or lab only.**

#### What it checks

Whether polluting `content-type` with a UTF-7 charset makes body-parser decode later request bodies as UTF-7. PortSwigger explains why this works: Node's incoming-message code drops a header it believes is a duplicate, and its check sees the inherited property, so the polluted value replaces the real `Content-Type` of every later request. It is a useful probe when nothing else reflects, because the evidence is a string you control.

PortSwigger lists it among the non-destructive techniques, and on a single request it is. In our lab (Express 4.22 and 5.3 with their body-parser versions, on a current Node.js release) the side effect was severe: after the probe, **every** subsequent request in that process was treated as `application/json; charset=utf-7`. URL-encoded form posts failed with JSON parse errors, and JSON values containing `+` were mangled (a phone number `+44 20` was stored as ` 20`). Re-polluting with a UTF-8 content type did not bring form handling back; only a restart did. That is why this note restricts the probe to staging.

#### Prerequisites

A staging or lab instance you can restart, with an endpoint that reflects a string field you send.

#### Steps

1. Send a reflected field containing the UTF-7 encoding of `foo`, `+AGYAbwBv-`, and confirm it comes back unchanged.
2. Pollute `content-type`:

```json
{"theme":"dark","__proto__":{"content-type":"application/json; charset=utf-7"} }
```

3. Send the same reflected field again. If the response now contains `foo`, the body was decoded as UTF-7 because of the polluted header.
4. Restart the staging process.

#### Observation

Before: `{"name":"+AGYAbwBv-"}`. After: `{"name":"foo"}` (illustrative, matching our lab).

#### Evaluation

**Fail:** the reflected string is decoded after the probe. Confirmed global pollution, and evidence that request parsing for all users can be changed (an availability and integrity impact in itself). **Pass:** no change; fall back to the other probes.

#### False positives

An application that decodes UTF-7 by design (rare). A WAF that normalises bodies.

#### Automation

The BApp extension implements this technique; only point it at staging. In CI, the [regression test](#regression-tests) should include a `content-type` key in its polluting payload set, because it is one of the properties core code reads.

### GT-WEB-PP-6: Constructor route and filter variants

*Guler Tech methodology.* Implements the filter assessment in WSTG-INJT-22 (gray-box and black-box), using the constructor technique described by PortSwigger.

#### What it checks

Whether a defence that only handles `__proto__` (a key denylist, or `--disable-proto`) still lets the prototype be reached through `constructor.prototype`, and whether a key filter is applied once instead of until the key is clean.

#### Prerequisites

A working oracle from [PP-3](#gt-web-pp-3-status-code-override-probe) or [PP-4](#gt-web-pp-4-formatting-and-header-probes), and a candidate endpoint where the `__proto__` form did **not** trigger it (or where the client has told you a filter exists).

#### Steps

1. Repeat the status probe through the constructor route:

```json
{"theme":"dark","constructor":{"prototype":{"status":555} } }
```

2. Check the error status, then undo with the same route and value `0`.
3. If the client says a key filter strips `__proto__` from keys, try **one** nested spelling that becomes `__proto__` after a single non-recursive removal, for example a key of `__pro__proto__to__`, with the same oracle and undo. One or two variants are enough to show the filter is incomplete; do not build a list.

#### Observation

Two useful patterns (illustrative):

| `__proto__` probe | `constructor.prototype` probe | Likely explanation |
|---|---|---|
| polluted | not polluted | A hand-written merge that only recurses into `typeof === 'object'` values (`Object` is a function, so it never walks into `constructor`); in our lab a typical hand-written merge behaved exactly like this |
| not polluted | polluted | A `__proto__` denylist or `--disable-proto` in place, with a merge (like old lodash) that recurses into functions |
| polluted | polluted | Old lodash-style merge or a path setter with no checks |
| not polluted | not polluted | No reachable merge, a safe library, schema validation, or a null-prototype target |

#### Evaluation

**Fail:** any variant confirms pollution. If a filter exists and a variant passes it, include that in the finding: the fix is not a better denylist but the structural fixes in [Secure implementation](#secure-implementation). **Pass:** neither route changes behaviour with a working oracle on an endpoint that clearly merges input.

#### False positives

The constructor payload stored as a normal nested object and echoed (`{"constructor":{"prototype":{…} } }` in your own preferences): that is reflection, not pollution. Unrelated status changes caused by your second request being invalid for the endpoint.

#### Automation

Include both routes, and the nested spelling, in the payload set of the [regression test](#regression-tests). Static analysis queries for prototype-polluting functions (CodeQL `js/prototype-pollution-utility`) flag merges whose key checks are incomplete.

### GT-WEB-PP-7: Query strings, forms and path-setter inputs

*Guler Tech methodology.* Implements the source enumeration of WSTG-INJT-22 for non-JSON inputs.

#### What it checks

Whether nested query strings, URL-encoded or multipart forms, and path-plus-value APIs can carry a prototype key into a merge or setter.

#### Prerequisites

Candidates from [PP-1](#gt-web-pp-1-fingerprint-the-runtime-and-map-merge-shaped-inputs); a working oracle ([PP-3](#gt-web-pp-3-status-code-override-probe)) on the same host.

#### Steps

1. **Path setters.** If an endpoint takes a path and a value, send the path forms, one at a time, with the status oracle and immediate undo:

```http
POST /api/me/settings/set HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
Content-Type: application/json

{"path":"__proto__.status","value":555}
```

```json
{"path":"constructor.prototype.status","value":555}
```

Undo with the same path and `"value":0`. Also try the array form if the API accepts one (`{"path":["__proto__","status"],"value":555}`): array keys bypassed an earlier fix in set-value (CVE-2021-23440).

2. **Nested query strings and forms.** Send the bracket form of the constructor route on an endpoint that accepts nested parameters, because `qs` drops `__proto__` but keeps `constructor` keys when `allowPrototypes` is enabled:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  'https://api.example.com/api/search?filter[constructor][prototype][status]=555' \
  -H 'Authorization: Bearer <TOKEN_USER_A>'
```

Check the oracle, then undo with `=0`. Repeat with dotted keys (`filter.constructor.prototype.status=555`) only if the application accepts dotted nesting (the `allowDots` option, or a custom decoder).

3. **Multipart.** Where uploads come with structured field names (`meta[title]`, `meta.title`), repeat step 2 with the field name as the carrier.

#### Observation

The same oracle changes as in [PP-3](#gt-web-pp-3-status-code-override-probe). Note which carrier worked: it tells the developer which parser or setter to fix.

#### Evaluation

**Fail:** pollution confirmed through any carrier. A path setter that accepts prototype paths is a finding even if you cannot see an oracle, provided you can show the server accepted and applied the path (for example, the response echoes the setting tree with your key at the top level) — confirm on staging. **Pass:** no change, and the parser visibly drops the keys (a reflected query object without them).

#### False positives

A search endpoint that treats `filter[...]` keys as opaque strings in a database query: nothing is merged. The status change caused by the request being rejected by a WAF.

#### Automation

Add the path forms to the regression payload set for any setter. Semgrep's `prototype-pollution-loop` rule targets loops that walk a path into an object.

### GT-WEB-PP-8: YAML, config import and multipart sources

*Guler Tech methodology.* Implements the source enumeration of WSTG-INJT-22 for file and configuration inputs.

#### What it checks

Whether structured documents that users upload or paste (YAML, JSON, TOML configuration, settings exports, workflow definitions) are merged into defaults in a way that reaches a prototype, and whether the YAML parser lets `__proto__` change the parsed object's own prototype (local injection).

#### Prerequisites

An import or upload feature that accepts structured configuration, a sample of a legitimate document (export one from your own account first), and an oracle on the same back end. Staging preferred: import pipelines often run in a shared worker, and a polluted worker affects every job it processes.

#### Steps

1. Export a legitimate configuration from your own account and confirm a clean re-import works.
2. Add a prototype key at a place where the importer will merge it, carrying the status oracle value:

```yaml
# workspace-settings.yaml (own test workspace only)
theme: dark
notifications:
  email: true
__proto__:
  status: 555
```

3. Import it, check the oracle on an endpoint served by the **same** process type (an import worker may not serve HTTP; if so, the oracle must be something the worker produces, such as an import error status, and staging is the only practical place to test).
4. Undo by importing the same document with `status: 0`, or ask for a restart on staging.
5. For local injection, import a document using a YAML merge key that contains `__proto__` with a canary, and see whether the canary later influences behaviour for *that* object only (for example, it shows in the rendered settings page but not in the stored export). On js-yaml 4.1.1 and later, and 3.14.2 and later, this should not happen.

#### Observation

Global: the oracle changes after the import and returns after the undo. Local: the canary affects only the imported object. Neither: the importer validates against a schema or the parser drops the key.

#### Evaluation

**Fail (global):** confirmed pollution from a file source, rated as for JSON bodies; note that background workers make the impact window and the affected users harder to bound. **Fail (local):** prototype injection into the imported object; rate by what reads it. **Pass:** the import is rejected for an unknown key, or the key is dropped.

#### False positives

An importer that stores the document verbatim (a key called `__proto__` in the stored YAML is harmless until something merges it; note it for code review). Import errors caused by your edit breaking the document's schema rather than by pollution.

#### Automation

Add YAML and JSON fixtures with `__proto__` and `constructor.prototype` keys to the importer's unit tests and assert that the global prototype is untouched and the import is rejected. `npm audit` (or your SCA tool) flags js-yaml versions affected by CVE-2025-64718.

### GT-WEB-PP-9: Gadget and impact assessment

*Guler Tech methodology.* Implements the impact assessment ("identify gadgets") step of WSTG-INJT-22. **Pollution of privilege flags and process or template options is done on staging or in a lab only.**

#### What it checks

What a confirmed pollution actually lets an attacker do in this application: change an authorisation decision, deny service, or reach code execution. The goal is a defensible severity, not an exploit.

#### Prerequisites

A confirmed pollution from tests 2 to 8. For property injection: a normal user account, the responses an admin or higher role receives (from the client's admin account, documentation, or the JavaScript bundle). For anything beyond read-only analysis: a staging instance you can restart, or source code.

#### Steps

1. **Find candidate authorisation flags without polluting anything.** Compare your user object with a higher role's (`GET /api/me` as user and as admin). Look for properties that exist for the admin and are **absent**, not `false`, for the user: `isAdmin`, `isStaff`, `canExport`, `features.*`, `permissions.*`. An absent property is what a polluted one fills in; an own `false` is not overridden by pollution. The JavaScript bundle often shows which flags the front end checks, and those are usually mirrored on the server.

```bash
diff <(curl -s https://api.example.com/api/me -H 'Authorization: Bearer <TOKEN_USER_A>' | jq -r 'paths|map(tostring)|join(".")') \
     <(curl -s https://api.example.com/api/me -H 'Authorization: Bearer <TOKEN_ADMIN>'  | jq -r 'paths|map(tostring)|join(".")')
```

2. **On staging only**, pollute one candidate flag through the confirmed source, check whether user B (another account you control) gains the matching capability (a read-only admin page is enough), then restart. Never do this on production: every user of the process would gain the flag, including real customers. On production, report the confirmed pollution plus the candidate flags from step 1 and let the client confirm on staging, or review the code with them.
3. **Denial of service: do not demonstrate.** Public research documents properties whose pollution crashes the process or breaks every request. A confirmed global pollution reachable by an attacker therefore implies a DoS capability; state this with a reference rather than proving it.
4. **Code execution: describe, do not attempt on client systems.** If the application spawns child processes (PDF or image conversion, `git`, external tools) or renders templates with options built from defaults, list those code paths and the library versions, and reference the published gadget research (PortSwigger's RCE lab and research, Silent Spring, GHunter, the KTH gadget collection). PortSwigger describes an out-of-band detection that pollutes child-process options so that a newly spawned Node process makes a DNS lookup; it alters every process the application spawns, so it is out of scope on client systems unless explicitly approved in writing for a staging environment.
5. **Check local injection impact separately.** For local prototype injection (one object only), the question is the same as for mass assignment: does any code read a property from that object that you could not otherwise set? Test that like [mass assignment and BOPLA](/web/web-mass-assignment-bopla/), with your own objects.

#### Observation

A short impact statement per confirmed pollution, for example (illustrative): "Global pollution via `PATCH /api/me/preferences` (any authenticated user). `GET /api/me` omits `isAdmin` for non-admin users; the admin UI checks `user.isAdmin`. On staging, polluting `isAdmin` granted user B access to `/admin/reports`. The application spawns `convert` for thumbnail generation with default options; no gadget was tested."

#### Evaluation

Rate with the [rating table](#rating-findings): proven privilege change on staging and a matching production source is High to Critical; confirmed global pollution with no identified gadget is still at least Medium because of the documented DoS potential and the persistence for all users; local injection is rated by its own effect.

#### False positives

Flags that exist only in the front end (the server checks a role from the database, not the object property). Admin-only properties that are present as own `false` values for everyone. Behaviour changes on staging that come from your restart rather than the polluted flag: compare with a control run.

#### Automation

None against production. On staging, the client's own integration tests are the best gadget detector: run the suite with the polluted properties set (for example `Object.prototype.isAdmin = true` in a test bootstrap) and see which authorisation tests start passing that should fail. That inverted test is a cheap way for developers to find their own gadgets.

### GT-WEB-PP-10: Source, dependency and runtime review

*Guler Tech methodology.* Implements the gray-box testing of WSTG-INJT-22.

#### What it checks

With source access: every place request-controlled structure reaches a merge, clone or setter; which dependency versions are affected by known advisories; and which runtime defences are in place.

#### Prerequisites

Repository access or a code review session; lockfiles; deployment configuration (Dockerfile, process manager configuration, `NODE_OPTIONS`).

#### Steps

1. Search for the sink patterns and read each hit to see whether request data reaches it:

```bash
# Merge, extend, clone and set helpers (hand-written or library)
grep -rnE "(deep)?[Mm]erge\(|[Ee]xtend\(|defaultsDeep\(|mergeWith\(|zipObjectDeep\(|setWith\(|_\.set\(|\bset\(.*req\." src/
# Recursive copies keyed by request data
grep -rnE "for \(const \w+ in |Object\.keys\(.*\)\.forEach" src/ | grep -iE "merge|copy|clone|assign"
# Parser options that keep prototype keys
grep -rnE "allowPrototypes|parseNested|allowDots" src/ package.json
# Object.assign or spread of request bodies into options
grep -rnE "Object\.assign\([^)]*req\.(body|query)|\.\.\.req\.(body|query)" src/
```

2. Check dependency versions against advisories: `npm ls lodash qs js-yaml set-value merge express-fileupload`, `npm audit --omit=dev` (or the SCA tool the client uses). Record transitive paths for affected versions.
3. Check security reads in authorisation code: are flags read with own-property checks or from a typed record, or as `user.flag` on a plain object?
4. Check option objects passed to `child_process` and template rendering: are `shell`, `env` and similar options set explicitly, or built from `{}` defaults?
5. Check runtime flags: is Node started with `--disable-proto=delete` or `--disable-proto=throw` (in the command line or `NODE_OPTIONS`)? Remember it does not stop the constructor route.
6. Run CodeQL's JavaScript security queries (`js/prototype-pollution`, `js/prototype-pollution-utility`, `js/prototype-polluting-assignment`) and Semgrep's `prototype-pollution-loop` and `prototype-pollution-assignment` rules, and triage the results with the data flow in mind.

#### Observation

A list of sinks with the source that reaches each, the library and version where relevant, and the defences in place (schema validation, null-prototype targets, key checks, runtime flags).

#### Evaluation

**Fail:** a request-controlled key reaches a sink without structural protection (strict schema, null-prototype target, or a safe library that refuses prototype keys). Report with the code path; black-box confirmation on staging strengthens it. A vulnerable library version that request data reaches is a finding; one that request data does not reach is a dependency hygiene issue (`v5.0.0-15.2.1`), usually Low or informational.

**Pass:** all nested input is validated against strict schemas before use, merges target null-prototype objects or use safe libraries, and security reads use own properties.

#### False positives

Merges that only ever combine constants or server-side configuration. Test code and build scripts. Static-analysis hits on `obj[key] = value` where `key` comes from a fixed list.

#### Automation

Run CodeQL and Semgrep in CI on every pull request, keep SCA alerts blocking for prototype pollution advisories in runtime dependencies, and keep the [regression tests](#regression-tests) for every handler that accepts nested input.

## Secure implementation

### Design rules

ASVS 5.0 states the goal in `v5.0.0-15.3.6` (L2): JavaScript code is written so that prototype pollution is prevented, for example by using `Set()` or `Map()` instead of object literals. In practice, combine these layers; only the first three are real fixes, the rest is defence in depth:

1. **Validate the shape of every nested input at the boundary** against a schema that rejects unknown keys (`v5.0.0-2.2.1`, L1: positive validation against an expected structure). Most pollution payloads die here, because `__proto__` and `constructor` are not fields in anyone's schema. This also covers mass assignment (`v5.0.0-15.3.3`, L2).
2. **Do not use plain objects as dictionaries for client-controlled keys.** Use `Map`, or objects created with `Object.create(null)`.
3. **Use merge, clone and set utilities that refuse prototype keys**, in patched versions, and keep them patched (`v5.0.0-15.2.1`, L1: components within documented update time frames).
4. **Read security-relevant properties as own properties**, from typed records, not through the prototype chain.
5. **Build options objects for dangerous APIs explicitly**, including null-prototype `env` objects for child processes.
6. **Add runtime hardening** (`--disable-proto`, frozen prototypes) where the application tolerates it.
7. **Make it testable:** static analysis in CI and regression tests that send prototype keys to every handler that accepts nested input.

Key deny-lists (`__proto__`, `constructor`, `prototype`) belong in your own merge and setter helpers as a last line, never as the only control.

### Validate the shape at the boundary

With Zod 4, `z.strictObject()` rejects unknown keys (the default `z.object()` strips them, which is also safe for pollution, but strict mode tells you when clients send fields you did not expect). In our lab, `z.strictObject` rejected a parsed body containing an own `__proto__` key with an `unrecognized_keys` issue, and the same for `constructor`.

```javascript
const express = require('express');
const { z } = require('zod');

const Preferences = z.strictObject({
  theme: z.enum(['light', 'dark']).optional(),
  notifications: z.strictObject({
    email: z.boolean().optional(),
    sms: z.boolean().optional(),
  }).optional(),
});

function validate(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    req.validated = result.data;   // only the keys the schema knows
    next();
  };
}

const app = express();
app.use(express.json({ limit: '32kb' }));

const store = new Map();           // userId -> preferences

app.patch('/api/me/preferences', validate(Preferences), (req, res) => {
  const userId = req.user.id;
  const current = store.get(userId) ?? {};
  const next = {
    ...current,
    ...req.validated,
    notifications: { ...current.notifications, ...req.validated.notifications },
  };
  store.set(userId, next);
  res.json(next);
});
```

The merge is now explicit and one level deep, over validated data, using spread (which defines own properties and never invokes the `__proto__` setter). With JSON Schema validators such as Ajv the equivalent is `additionalProperties: false` on every object in the schema. Free-form "metadata" fields are where this breaks down: if a field must accept arbitrary keys, store it as a `Map` or a null-prototype object, constrain key names with a pattern (for example `^[a-zA-Z][a-zA-Z0-9_]{0,63}$`), and never deep-merge it into another object.

As an extra layer for JSON bodies, `express.json()` accepts a `reviver` that is passed to `JSON.parse`; returning `undefined` from a reviver deletes the key. In our lab this removed prototype keys at every depth:

```javascript
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
app.use(express.json({ reviver: (key, value) => (FORBIDDEN.has(key) ? undefined : value) }));
```

That is a deny-list, so treat it as defence in depth: it does nothing for query strings, forms, YAML or values that become keys later (path setters).

### Null-prototype objects and Map

Objects without a prototype have no `__proto__` accessor and inherit nothing, so a polluted `Object.prototype` cannot affect lookups on them, and a merge into them cannot climb to the shared prototype.

```javascript
// Dictionary of client-controlled keys
const counters = new Map();
counters.set(req.body.metric, (counters.get(req.body.metric) ?? 0) + 1);

// When an object is required (for example for JSON output)
const dict = Object.create(null);
dict[key] = value;                     // a key of "__proto__" is just a key here

// Literal form of the same thing
const defaults = { __proto__: null, theme: 'light', pageSize: 20 };
```

Two details. First, spreading a null-prototype object into `{}` gives you an ordinary object again, so keep the null prototype at every level you merge into. Second, some libraries expect `obj.hasOwnProperty()` to exist; call `Object.hasOwn(obj, key)` instead, which works on both kinds.

### Safe merging and patched libraries

If you need a deep merge, use a maintained library in a patched version and confirm it in your own tests, or write a small one that only walks plain objects, only copies own keys, and never recurses into an existing non-own value:

```javascript
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);

function isPlainObject(v) {
  if (v === null || typeof v !== 'object') return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function safeMerge(target, source) {
  for (const key of Object.keys(source)) {            // own enumerable keys only
    if (FORBIDDEN.has(key)) continue;                 // defence in depth
    const value = source[key];
    if (isPlainObject(value)) {
      const current = Object.hasOwn(target, key) && isPlainObject(target[key])
        ? target[key]
        : Object.create(null);
      target[key] = safeMerge(current, value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

const merged = safeMerge(Object.create(null), validatedInput);
```

Library guidance at the time of writing:

| Library | Use | Notes |
|---|---|---|
| lodash | 4.17.21 or later | In our lab 4.17.21 refused `merge`, `defaultsDeep`, `set` and `zipObjectDeep` pollution that 4.17.4 allowed. Older copies often arrive transitively; check `npm ls lodash` |
| qs | Current version, default options | Do not enable `allowPrototypes`; keep `plainObjects` in mind if you want null-prototype results |
| js-yaml | 4.1.1+ or 3.14.2+ | Fixes CVE-2025-64718; still validate the loaded document against a schema |
| set-value, mixin-deep, merge-style packages | Patched versions or replace | Several advisories over the years; prefer an explicit, validated update over generic path setters |
| express-fileupload | 1.1.8+, `parseNested` off unless needed | CVE-2020-7699 |
| Express | 4.18.0+ or 5.x | 4.18.0 stopped reading app settings from `Object.prototype`; Express 5 defaults to the simple query parser and `extended: false` forms |

For path setters, replace "set any path" APIs with explicit operations on known fields. If a generic path is unavoidable, validate each segment against an allowlist of field names for that resource, and reject `__proto__`, `constructor` and `prototype` segments in both string and array forms.

### Read only own properties in security decisions

Authorisation code should not depend on whether a property happens to be absent.

```javascript
// Fragile: an inherited isAdmin decides when the row has no own value
if (user.isAdmin) { /* ... */ }

// Better: own property, strict type
if (Object.hasOwn(user, 'isAdmin') && user.isAdmin === true) { /* ... */ }

// Best: build the security context explicitly from the database row
const ctx = Object.freeze({
  __proto__: null,
  userId: row.id,
  roles: new Set(row.roles ?? []),
});
if (ctx.roles.has('admin')) { /* ... */ }
```

The same applies to feature flags, plan limits and options with boolean defaults: normalise them into a complete, null-prototype or frozen object at load time so that every key has an own value.

### Harden options passed to child processes and templates

Published gadgets mostly work because Node and libraries read options that the application did not set. Setting an option explicitly helps, because an own property wins over an inherited one (`{ shell: false }` cannot be overridden by a polluted `shell`). It is not complete: in our lab, on a current Node.js release, a property polluted onto `Object.prototype` was copied into a child process's environment both with the default `env` and with an explicit `env: { PATH: '/usr/bin' }` literal, because the environment is built by iterating the object, which includes inherited keys. Only a null-prototype `env` object kept it out.

```javascript
const { execFile } = require('node:child_process');

const childEnv = Object.assign(Object.create(null), { PATH: '/usr/bin', LANG: 'C.UTF-8' });

execFile('/usr/bin/convert', [inputPath, outputPath], {
  shell: false,          // own value: a polluted "shell" cannot replace it
  env: childEnv,         // null prototype: inherited keys are not copied into the child
  timeout: 15_000,
  windowsHide: true,
}, callback);
```

Use `execFile` or `spawn` with argument arrays and no shell, as in the [OS command injection](/web/web-os-command-injection/) note. For template engines, pass a fresh, explicit options object, keep the engine patched, and never let request data choose template names or options (see [SSTI](/web/web-server-side-template-injection/)). These measures reduce the blast radius; the fix remains preventing the pollution.

### Runtime flags and frozen prototypes

**`--disable-proto=delete`** removes the `Object.prototype.__proto__` accessor; `--disable-proto=throw` makes access throw `ERR_PROTO_ACCESS`. Both are documented Node.js CLI options (added in v13.12.0 and v12.17.0). In our lab, `delete` stopped a hand-written merge and old lodash from polluting through `__proto__`, but old lodash still polluted through `constructor.prototype`, exactly as PortSwigger and the OWASP cheat sheet warn. Test your dependencies before enabling `throw`: code that legitimately uses `__proto__` (rare, mostly old libraries) will fail.

```bash
node --disable-proto=delete server.js
# or, where the process is started by a tool you do not control
NODE_OPTIONS="--disable-proto=delete" npm start
```

**`Object.freeze(Object.prototype)`** at start-up, after all modules that legitimately patch built-ins have loaded, makes writes to the shared prototype fail: silently in sloppy-mode code, with a `TypeError` in strict mode (in our lab, a polluting merge in a strict-mode module threw, and a basic Express 5 app served requests normally with the prototype frozen). Trade-offs: some libraries and polyfills add properties to built-in prototypes and will break, the freeze is shallow, and it covers only the prototypes you freeze (`Object.prototype` but not `Array.prototype` or `Function.prototype` unless you freeze those too). Roll it out behind your test suite and a canary deployment. Node's `--frozen-intrinsics` flag does this for all intrinsics but is marked experimental and may break code.

### Static analysis

- **CodeQL** (JavaScript/TypeScript security queries): `js/prototype-pollution` ("Prototype-polluting merge call": request data reaching a vulnerable merge function), `js/prototype-pollution-utility` ("Prototype-polluting function": your own recursive merge or extend utilities), and `js/prototype-polluting-assignment` ("Prototype-polluting assignment": `obj[a][b] = value` with tainted keys).
- **Semgrep** community rules `javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop` (loops that walk an object by key, the path-setter shape) and `…prototype-pollution-assignment.prototype-pollution-assignment` (assignment through tainted keys). They are audit-level rules with low confidence; expect to triage.
- **SCA** (`npm audit`, Dependabot, Snyk, OSV-Scanner): block merges that introduce runtime dependencies with prototype pollution advisories, and review transitive copies.

### Regression tests

Write one test per handler that accepts nested input, and make it check the global prototype, not just the response. The test below uses only `node:test` and `fetch`; in our lab it passed against the Zod-based handler above (with a fixed user ID in place of `req.user`) and failed when we swapped in an unsafe recursive merge.

```javascript
// pp.test.js — run with: node --test
const test = require('node:test');
const assert = require('node:assert');
const app = require('./app');

const PAYLOADS = [
  '{"__proto__":{"gt_pp_canary":"1"} }',
  '{"constructor":{"prototype":{"gt_pp_canary":"1"} } }',
  '{"notifications":{"__proto__":{"gt_pp_canary":"1"} } }',
  '{"theme":"dark","__proto__":{"status":555} }',
];

test('handlers reject prototype keys and leave Object.prototype untouched', async (t) => {
  const server = app.listen(0);
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;

  for (const body of PAYLOADS) {
    const res = await fetch(`${base}/api/me/preferences`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body,
    });
    assert.strictEqual(res.status, 400, `expected 400 for ${body}`);
    assert.strictEqual({}.gt_pp_canary, undefined);
    assert.strictEqual(Object.hasOwn(Object.prototype, 'status'), false);
  }

  // The framework's own error status is unchanged (the status-override oracle)
  const bad = await fetch(`${base}/api/me/preferences`, {
    method: 'PATCH', headers: { 'content-type': 'application/json' }, body: '{"theme":',
  });
  assert.strictEqual(bad.status, 400);
});
```

Good habits around it:

- Run the payload set against **every** route that takes nested input (generate the list from your router or OpenAPI document so new routes are covered automatically), including query, form, YAML-import and path-setter routes with their own payload forms.
- Run each test file in a fresh process (the default for `node --test`), because a failure pollutes the process and can make later tests pass or fail for the wrong reason.
- Add the inverted check from [PP-9](#gt-web-pp-9-gadget-and-impact-assessment) on staging: set candidate flags on `Object.prototype` in a test bootstrap and assert that authorisation tests still deny.

### Beyond Node: Deno and Python class pollution

**Deno** runs the same JavaScript semantics but does not expose `Object.prototype.__proto__` by default (the js-yaml advisory for CVE-2025-64718 notes that pollution protection through `__proto__` is on by default in Deno). The constructor route and the gadget problem remain: the GHunter paper reports 67 gadgets in Deno. Apply the same design rules. We have not reviewed Bun for this note.

**Python** has no prototypes, but the same "merge untrusted keys into objects" pattern can reach special attributes. Abdulrah33m's 2023 research calls it **class pollution**: a recursive merge that uses `setattr`/`getattr` with attacker-chosen names can walk through attributes such as `__class__`, `__init__` and `__globals__` to modify classes and module-level variables. The fixes rhyme with the JavaScript ones: validate input against schemas (Pydantic models with `extra='forbid'`), never map client keys onto attributes generically, and reject dunder names in any generic setter.

## Practice labs

**PortSwigger Web Security Academy** (server-side prototype pollution, each lab runs its own Node.js instance with a restart button, which is exactly the safety net you do not have on a client system):

- [Privilege escalation via server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-privilege-escalation-via-server-side-prototype-pollution): polluted-property reflection and an authorisation flag gadget.
- [Detecting server-side prototype pollution without polluted property reflection](https://portswigger.net/web-security/prototype-pollution/server-side/lab-detecting-server-side-prototype-pollution-without-polluted-property-reflection): solvable with the status, JSON spaces or charset techniques from [PP-3](#gt-web-pp-3-status-code-override-probe) to [PP-5](#gt-web-pp-5-charset-override-probe-on-staging).
- [Bypassing flawed input filters for server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-bypassing-flawed-input-filters-for-server-side-prototype-pollution): the constructor route and filter variants from [PP-6](#gt-web-pp-6-constructor-route-and-filter-variants).
- [Remote code execution via server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-remote-code-execution-via-server-side-prototype-pollution) and [Exfiltrating sensitive data via server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-exfiltrating-sensitive-data-via-server-side-prototype-pollution): the child-process gadget family. These are the right place to learn what [PP-9](#gt-web-pp-9-gadget-and-impact-assessment) only describes.

**Your own lab.** Most of the behaviour in this note is easy to reproduce on your own machine: an Express app with `express.json()`, a hand-written recursive merge on one route and a route that returns a fresh object, run once with Express 4.17.3 and lodash 4.17.4 and once with current versions. It is the quickest way to see which probes work on which versions and how the undo behaves, before you are in front of a client system.

**KTH LangSec gadget collection.** The [server-side-prototype-pollution](https://github.com/KTH-LangSec/server-side-prototype-pollution) repository (from the Silent Spring authors) collects gadgets and exploits for study in an isolated environment.

OWASP Juice Shop, crAPI and VAmPI do not have a dedicated server-side prototype pollution challenge at the time of writing (we found no such challenge in Juice Shop's challenge list), so use them for the neighbouring [mass assignment](/web/web-mass-assignment-bopla/) exercises instead.

## Real-world cases

- **Olivier Arteau, lodash and friends (2018).** Arteau's NorthSec 2018 research, *Prototype pollution attacks in NodeJS applications* ([paper and slides](https://github.com/HoLyVieR/prototype-pollution-nsec18)), named the class and reported a batch of vulnerable merge and clone libraries through the Node.js third-party modules programme. The lodash report, [HackerOne #310443](https://hackerone.com/reports/310443) (disclosed, 2018), shows the canonical `_.merge` with a JSON `__proto__` payload; NVD lists it as the reference for CVE-2018-3721.
- **Kibana, CVE-2019-7609.** Michał Bentkowski's [Prototype Pollution in Kibana](https://slides.com/securitymb/prototype-pollution-in-kibana) (OWASP Poland Day 2019) walks through how pollution in the Timelion visualiser was turned into code execution on the Kibana server. NVD describes the result as arbitrary code execution for anyone with access to Timelion, in Kibana before 5.6.15 and 6.6.1. It is also the example the WSTG page uses.
- **Parse Server, CVE-2022-24760.** The [Parse Server advisory GHSA-p6h4-93qp-jhcm](https://github.com/parse-community/parse-server/security/advisories/GHSA-p6h4-93qp-jhcm) describes remote code execution in the default configuration with MongoDB, rooted in prototype-pollution-vulnerable code in `DatabaseController.js`; fixed in 4.10.7.
- **Silent Spring (USENIX Security 2023).** Shcherbakov, Balliu and Staicu's [Silent Spring: Prototype Pollution Leads to Remote Code Execution in Node.js](https://www.usenix.org/conference/usenixsecurity23/presentation/shcherbakov) found 11 universal gadgets in Node.js core APIs and exploited eight RCE vulnerabilities in NPM CLI, Parse Server and Rocket.Chat. The follow-up [GHunter](https://www.usenix.org/conference/usenixsecurity24/presentation/cornelissen) (USENIX Security 2024) extended the gadget search to Node.js and Deno.
- **express-fileupload, CVE-2020-7699.** With `parseNested` enabled, versions before 1.1.8 let a crafted multipart request cause denial of service or arbitrary code execution (NVD). A reminder that "nested" parsing options on form and upload middleware are pollution sources.
- **PortSwigger's black-box research (2023).** Gareth Heyes's [Server-side prototype pollution: Black-box detection without the DoS](https://portswigger.net/research/server-side-prototype-pollution) is the origin of the reversible probes used in this note, and also documents the destructive ones to avoid.

## Rating findings

Rate by what the pollution reaches (a gadget you have shown on staging, or only the primitive), who can send the polluting request (unauthenticated, any user, a specific role), and how far it spreads (one object, one process serving everyone, background workers). Persistence for all users is part of the impact: a single request changes behaviour for everyone until restart.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Unauthenticated global pollution with a code-execution gadget confirmed on staging (or by code review) | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | Full compromise of the application process. Use `S:C` (10.0) when the process's privileges clearly reach other components (shared host, a container with access to other services' credentials), per the series convention. |
| Global pollution from any registered user with a code-execution or privilege-flag gadget | High–Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Self-registration usually satisfies `PR:L`. A privilege flag that makes every user an administrator is integrity and confidentiality impact on all data, and the change persists for everyone until restart. |
| Global pollution confirmed (status, formatting or header probe), no gadget identified | Medium–High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H` (7.1); `PR:N` gives 8.2 | You changed shared behaviour (`I:L`). `A:H` reflects documented properties whose pollution breaks every request or crashes the process; argue it with references rather than a demonstration. Programmes that insist on demonstrated impact often settle at Medium. |
| Pollution reachable only by an administrator (config import, admin settings) | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (7.2) with a gadget; lower without | High when administrators are not meant to have server access, Medium where they already deploy code. High privileges lower the score, but the effect on other users and the persistence remain; raise it if the admin role is broadly granted. A self-service tenant admin is `PR:L` (8.8), and effects on other tenants raise the severity for scale. |
| Local prototype injection on the caller's own object (Object.assign or YAML merge-key style) | Low–Medium | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` (4.3) | Same reasoning as mass assignment on that object; rate higher when the inherited property reaches an authorisation check, as in [mass assignment and BOPLA](/web/web-mass-assignment-bopla/). |
| Vulnerable merge library or parser in a reachable request path, pollution not demonstrated | Medium | depends on the advisory; for qs before 6.10.3 via the query string, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (7.5) | Evidence is the version plus a reachable code path. Do not demonstrate a process hang on production; say the vector was not exercised. |
| Vulnerable library version not reachable by request data | Low/Info | none | Dependency hygiene (`v5.0.0-15.2.1`); fix through normal patching. |
| Incomplete key filter (denylist misses the constructor route or nested spellings), no reachable sink found | Low/Info | none | Report it so the filter is not treated as the control; the real fix is schema validation and safe merging. |

## Mapping

OWASP Top 10:2025 does not list CWE-1321 in any category's mapped CWEs. Its parent, CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes), is mapped to A08:2025 Software or Data Integrity Failures, which is where we file it; vulnerable library versions are also A03:2025 Software Supply Chain Failures (CWE-1395, Dependency on Vulnerable Third-Party Component). There is no direct API Security Top 10 category; the property-injection outcome overlaps API3:2023 (BOPLA).

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 / API Top 10 |
|---|---|---|---|---|
| GT-WEB-PP-1 | WSTG-INJT-22, WSTG-INFO-06, WSTG-INFO-08 | v5.0.0-2.2.1 | CWE-1321 | A08:2025 |
| GT-WEB-PP-2 | WSTG-INJT-22 | v5.0.0-15.3.6, v5.0.0-2.2.1 | CWE-1321 | A08:2025 |
| GT-WEB-PP-3 | WSTG-INJT-22 | v5.0.0-15.3.6 | CWE-1321 | A08:2025 |
| GT-WEB-PP-4 | WSTG-INJT-22 | v5.0.0-15.3.6, v5.0.0-15.2.1 | CWE-1321, CWE-1395 | A08:2025, A03:2025 |
| GT-WEB-PP-5 | WSTG-INJT-22 | v5.0.0-15.3.6 | CWE-1321 | A08:2025 |
| GT-WEB-PP-6 | WSTG-INJT-22 | v5.0.0-15.3.6, v5.0.0-2.2.1 | CWE-1321 | A08:2025 |
| GT-WEB-PP-7 | WSTG-INJT-22 | v5.0.0-15.3.6, v5.0.0-15.3.7 | CWE-1321 | A08:2025 |
| GT-WEB-PP-8 | WSTG-INJT-22 | v5.0.0-15.3.6, v5.0.0-2.2.1, v5.0.0-15.2.1 | CWE-1321, CWE-1395 | A08:2025, A03:2025 |
| GT-WEB-PP-9 | WSTG-INJT-22 | v5.0.0-15.3.6, v5.0.0-15.3.3 | CWE-1321, CWE-915 | A08:2025, API3:2023 (property-injection outcome) |
| GT-WEB-PP-10 | WSTG-INJT-22 | v5.0.0-15.3.6, v5.0.0-15.2.1 | CWE-1321, CWE-1395 | A08:2025, A03:2025 |

ASVS levels: `v5.0.0-15.3.6` L2, `v5.0.0-15.3.3` L2, `v5.0.0-15.3.7` L2, `v5.0.0-2.2.1` L1, `v5.0.0-15.2.1` L1.

## References

OWASP:

- [WSTG-INJT-22: Testing for Prototype Pollution](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/22-Prototype_Pollution) (also [on GitHub](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Injection/22-Prototype_Pollution.md))
- [ASVS 5.0 V15 Secure Coding and Architecture](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md) (15.3.6 prototype pollution, 15.3.3 mass assignment)
- [Prototype Pollution Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
- [Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/), [A08:2025 Software or Data Integrity Failures](https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/), [A03:2025 Software Supply Chain Failures](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/)

CWE:

- [CWE-1321: Improperly Controlled Modification of Object Prototype Attributes](https://cwe.mitre.org/data/definitions/1321.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [CWE-1395: Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html)

PortSwigger:

- [Prototype pollution](https://portswigger.net/web-security/prototype-pollution) and [Server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side) (Web Security Academy)
- [Preventing prototype pollution](https://portswigger.net/web-security/prototype-pollution/preventing)
- Gareth Heyes, [Server-side prototype pollution: Black-box detection without the DoS](https://portswigger.net/research/server-side-prototype-pollution) (2023)
- [Server-Side Prototype Pollution Scanner](https://portswigger.net/bappstore/c1d4bd60626d4178a54d36ee802cf7e8) (BApp Store) and its [source](https://github.com/portswigger/server-side-prototype-pollution)

Research:

- Olivier Arteau, [prototype-pollution-nsec18](https://github.com/HoLyVieR/prototype-pollution-nsec18) (NorthSec 2018 paper and slides)
- Shcherbakov, Balliu, Staicu, [Silent Spring: Prototype Pollution Leads to Remote Code Execution in Node.js](https://www.usenix.org/conference/usenixsecurity23/presentation/shcherbakov) (USENIX Security 2023; [paper PDF](https://www.usenix.org/system/files/usenixsecurity23-shcherbakov.pdf), [arXiv](https://arxiv.org/abs/2207.11171))
- Cornelissen, Shcherbakov, Balliu, [GHunter: Universal Prototype Pollution Gadgets in JavaScript Runtimes](https://www.usenix.org/conference/usenixsecurity24/presentation/cornelissen) (USENIX Security 2024)
- [KTH-LangSec/server-side-prototype-pollution](https://github.com/KTH-LangSec/server-side-prototype-pollution) (gadget collection)
- Michał Bentkowski, [Prototype Pollution in Kibana](https://slides.com/securitymb/prototype-pollution-in-kibana)
- Abdulrah33m, [Prototype Pollution in Python](https://blog.abdulrah33m.com/prototype-pollution-in-python/) (class pollution, 2023)

Advisories:

- lodash: [CVE-2018-3721](https://nvd.nist.gov/vuln/detail/CVE-2018-3721), [CVE-2018-16487](https://nvd.nist.gov/vuln/detail/CVE-2018-16487), [CVE-2019-10744](https://nvd.nist.gov/vuln/detail/CVE-2019-10744), [CVE-2020-8203](https://nvd.nist.gov/vuln/detail/CVE-2020-8203)
- set-value: [CVE-2019-10747](https://nvd.nist.gov/vuln/detail/CVE-2019-10747), [CVE-2021-23440](https://nvd.nist.gov/vuln/detail/CVE-2021-23440); merge: [CVE-2020-28499](https://nvd.nist.gov/vuln/detail/CVE-2020-28499)
- qs: [CVE-2022-24999](https://nvd.nist.gov/vuln/detail/CVE-2022-24999); js-yaml: [CVE-2025-64718](https://nvd.nist.gov/vuln/detail/CVE-2025-64718) ([GHSA-mh29-5h37-fv8m](https://github.com/nodeca/js-yaml/security/advisories/GHSA-mh29-5h37-fv8m))
- Kibana: [CVE-2019-7609](https://nvd.nist.gov/vuln/detail/CVE-2019-7609); Parse Server: [CVE-2022-24760](https://nvd.nist.gov/vuln/detail/CVE-2022-24760); express-fileupload: [CVE-2020-7699](https://nvd.nist.gov/vuln/detail/CVE-2020-7699)

Platform and tool documentation:

- Node.js [command-line options](https://nodejs.org/api/cli.html) (`--disable-proto`, `--frozen-intrinsics`)
- MDN, [Inheritance and the prototype chain](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Inheritance_and_the_prototype_chain) and [Object.prototype.\_\_proto\_\_](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto)
- Express [API reference](https://expressjs.com/en/api.html) and [migrating to Express 5](https://expressjs.com/en/guide/migrating-5.html); [qs](https://github.com/ljharb/qs)
- [Zod API](https://zod.dev/api) (`z.strictObject`)
- CodeQL query help: [js/prototype-pollution](https://codeql.github.com/codeql-query-help/javascript/js-prototype-pollution/), [js/prototype-pollution-utility](https://codeql.github.com/codeql-query-help/javascript/js-prototype-pollution-utility/), [js/prototype-polluting-assignment](https://codeql.github.com/codeql-query-help/javascript/js-prototype-polluting-assignment/)
- Semgrep rules: [prototype-pollution-loop](https://semgrep.dev/r/javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop), [prototype-pollution-assignment](https://semgrep.dev/r/javascript.lang.security.audit.prototype-pollution.prototype-pollution-assignment.prototype-pollution-assignment) ([source](https://github.com/semgrep/semgrep-rules/tree/develop/javascript/lang/security/audit/prototype-pollution))
