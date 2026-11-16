---
title: "LDAP and XPath Injection"
date: 2026-11-15 20:10:00 +0000
subcategory: injection
summary: "Testing LDAP and XPath injection: filter and DN injection, blind boolean proofs, AD login quirks, XPath/XQuery lookups and RFC 4515/4514 fixes."
refs: [WSTG-INJT-06, WSTG-INJT-09, v5.0.0-1.2.6, v5.0.0-1.2.7, v5.0.0-1.1.2, v5.0.0-13.2.2, "A05:2025", CWE-90, CWE-643, CWE-652, CWE-303]
tags: [web, injection, ldap, xpath, active-directory, xquery]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Injection](/web/web-injection-testing-guide/). It covers two query languages that rarely get the attention SQL does but sit right next to authentication: LDAP search filters and distinguished names (`WSTG-INJT-06`), and XPath (and its bigger sibling XQuery) over XML documents (`WSTG-INJT-09`). Both appear where you least want an injection: the login form that checks Active Directory, the people search on an intranet, the "is this user in the admins group?" check, the SSO connector, the password reset that looks you up by email, and the XML file a legacy application uses as its user store. You get the model (filter and DN grammar, where the escaping rules come from, what changes with Active Directory), the variants that keep producing findings, ten tests that end at the least invasive proof and use your own test accounts, and fixes that use real library functions in Java, Spring, Python and Django, PHP and Laravel, and Node.js, with regression tests. SQL is covered in [SQL injection](/web/web-sql-injection/), document databases in [NoSQL injection](/web/web-nosql-injection/), and XML parser problems (external entities, XInclude) in [XXE and XML injection](/web/web-xxe-xml-injection/).

## Contents

- [How it works](#how-it-works)
  - [Where directory queries live](#where-directory-queries-live)
  - [Search filter grammar](#search-filter-grammar)
  - [Distinguished names](#distinguished-names)
  - [How the login flow uses LDAP](#how-the-login-flow-uses-ldap)
  - [Active Directory behaviours](#active-directory-behaviours)
  - [XPath and XQuery](#xpath-and-xquery)
- [What goes wrong](#what-goes-wrong)
  - [Concatenated search filters](#concatenated-search-filters)
  - [Filters that look parameterised](#filters-that-look-parameterised)
  - [Wildcards in search-then-bind logins](#wildcards-in-search-then-bind-logins)
  - [Password checks inside the filter](#password-checks-inside-the-filter)
  - [Group and role checks built from input](#group-and-role-checks-built-from-input)
  - [DN injection](#dn-injection)
  - [Empty passwords and unauthenticated bind](#empty-passwords-and-unauthenticated-bind)
  - [Anonymous bind and over-privileged service accounts](#anonymous-bind-and-over-privileged-service-accounts)
  - [Escaping in the wrong context](#escaping-in-the-wrong-context)
  - [Errors, oracles and expensive filters](#errors-oracles-and-expensive-filters)
  - [XPath injection in authentication and lookups](#xpath-injection-in-authentication-and-lookups)
  - [XPath 2.0 and later functions, and XQuery](#xpath-20-and-later-functions-and-xquery)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-WEB-LDAP-1: Map directory and XML-backed features](#gt-web-ldap-1-map-directory-and-xml-backed-features)
  - [GT-WEB-LDAP-2: Probe for filter metacharacters and errors](#gt-web-ldap-2-probe-for-filter-metacharacters-and-errors)
  - [GT-WEB-LDAP-3: Wildcards in search and lookup features](#gt-web-ldap-3-wildcards-in-search-and-lookup-features)
  - [GT-WEB-LDAP-4: Boolean filter injection](#gt-web-ldap-4-boolean-filter-injection)
  - [GT-WEB-LDAP-5: Blind injection and attribute discovery](#gt-web-ldap-5-blind-injection-and-attribute-discovery)
  - [GT-WEB-LDAP-6: Login filters and unauthenticated bind](#gt-web-ldap-6-login-filters-and-unauthenticated-bind)
  - [GT-WEB-LDAP-7: Group membership and authorisation filters](#gt-web-ldap-7-group-membership-and-authorisation-filters)
  - [GT-WEB-LDAP-8: DN injection](#gt-web-ldap-8-dn-injection)
  - [GT-WEB-LDAP-9: XPath injection in lookups and login](#gt-web-ldap-9-xpath-injection-in-lookups-and-login)
  - [GT-WEB-LDAP-10: Blind XPath, XPath 2.0 functions and XQuery](#gt-web-ldap-10-blind-xpath-xpath-20-functions-and-xquery)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Java and JNDI](#java-and-jndi)
  - [Spring LDAP and Spring Security](#spring-ldap-and-spring-security)
  - [Python and Django](#python-and-django)
  - [PHP and Laravel](#php-and-laravel)
  - [Node.js](#nodejs)
  - [Parameterised XPath and XQuery](#parameterised-xpath-and-xquery)
  - [Directory and service account hardening](#directory-and-service-account-hardening)
  - [Static analysis](#static-analysis)
  - [Regression tests](#regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Where directory queries live

LDAP is the protocol web applications use to talk to a directory: Microsoft Active Directory (AD) in most enterprises, OpenLDAP, 389 Directory Server, cloud directories with an LDAP interface, and the LDAP front ends of identity products. The web application almost never exposes LDAP itself. It takes something you typed, builds a query string, and sends it from the server using a service account. That is why injection is possible: the string you control is pasted into a query language the server trusts.

The features to look for:

| Feature | Typical query | What you control |
|---|---|---|
| Login against AD or OpenLDAP | search `(&(objectClass=user)(sAMAccountName=<input>))`, then bind as the found DN with your password | username, sometimes the domain |
| Direct bind login | bind as `uid=<input>,ou=people,dc=example,dc=com` | username inside a DN |
| People search, address book, "find a colleague" | `(&(objectClass=person)(|(cn=*<input>*)(mail=*<input>*)))` | the search box, sort or attribute parameters |
| Group membership checks | `(&(objectClass=group)(cn=app-admins)(member=<user DN>))` | the username (via the DN), sometimes the group name |
| SSO and identity glue | IdP connectors, VPN and Wi-Fi portals, ticketing and wiki plug-ins mapping a login to a directory entry | the username, `resource` or `login_hint` style parameters |
| Password reset and account recovery | `(mail=<input>)` to find the account, then a modify on its DN | email address, username |
| Self-service profile updates | modify `uid=<input>,ou=people,...` | a DN or username in the request |
| Admin tools | arbitrary attribute or OU selectors in reports and exports | base DN, attribute names, scope |

XPath shows up in fewer places, but in similar roles: applications that keep users, tenants or configuration in an XML file (`users.xml`, a SAML metadata store, a product catalogue), SOAP services that select nodes from the request or a back-end document, XML-native databases queried with XPath or XQuery (BaseX, eXist-db, MarkLogic), and "which back end handles this organisation?" lookups in an XML config file.

### Search filter grammar

RFC 4515 defines the string form of an LDAP search filter. A filter is always wrapped in parentheses and uses prefix notation:

| Construct | Example | Meaning |
|---|---|---|
| Equality | `(uid=alice)` | attribute equals value |
| Presence | `(mail=*)` | entry has the attribute |
| Substring | `(cn=Al*ce*)` | wildcard match; `*` can appear anywhere |
| Ordering and approximate | `(age>=18)`, `(cn~=alise)` | server-dependent matching |
| AND, OR, NOT | `(&(a=1)(b=2))`, `(|(a=1)(b=2))`, `(!(a=1))` | combine child filters |
| Extensible match | `(userAccountControl:1.2.840.113556.1.4.803:=2)` | a matching rule named by OID (used heavily in AD) |
| Absolute true and false (RFC 4526) | `(&)`, `(|)` | empty AND is true, empty OR is false; not every server or client library accepts them |

Five octets are special inside a value and must be escaped as a backslash plus two hex digits: `*` (`\2a`), `(` (`\28`), `)` (`\29`), `\` (`\5c`) and NUL (`\00`). That is the entire filter escaping rule. If an application inserts input into a filter without applying it, a `*` becomes a wildcard and a `)(` sequence closes the application's condition and opens one of yours.

Two properties make LDAP injection different from SQL injection:

- **No comments and no statement separators.** You cannot "comment out" the rest of the application's filter. A successful injection has to produce a filter that is still balanced, or the client library or server rejects it. Most practical payloads therefore add a condition *inside* the existing `&` or `|` (for example `alice)(objectClass=*`), which leaves the parentheses balanced.
- **Read-only by nature.** A search filter cannot modify the directory. Writes need a separate add, modify or delete operation, which is where DN injection matters.

### Distinguished names

A distinguished name (DN) is the path to one entry, most specific part first: `uid=alice,ou=people,dc=example,dc=com`. Each comma-separated part is a relative distinguished name (RDN); a `+` joins several attribute-value pairs into one multi-valued RDN. RFC 4514 defines the escaping: `"`, `+`, `,`, `;`, `<`, `>` and `\` must be escaped anywhere in a value, as must a leading space or `#`, a trailing space, and NUL. Other characters may be escaped, and many libraries also escape `=`.

The rule sets are different. `*` and parentheses are harmless in a DN, and `,` and `+` are harmless in a filter. An application that uses filter escaping for a DN (or the reverse) is still injectable; the OWASP LDAP Injection Prevention Cheat Sheet makes the same point and lists both sets.

### How the login flow uses LDAP

Three login designs exist, and each fails differently:

1. **Search, then bind.** The application binds with its service account, searches for the user (`(sAMAccountName=<input>)`), takes the DN from the first result and binds again as that DN with the password you typed. The directory checks the password. Injection in the search changes *which entry* is found; the password is still checked against that entry, so a bypass needs more than a wildcard. This is the most common design with AD.
2. **Direct bind with a DN template.** The application builds `uid=<input>,ou=people,dc=example,dc=com` and binds with your password. No search happens. Injection is DN injection, and the classic failure is an empty password (see [unauthenticated bind](#empty-passwords-and-unauthenticated-bind)).
3. **Compare inside the filter.** Older code searches for `(&(uid=<input>)(userPassword=<hash>))` and treats "one result" as "logged in". The password check is part of the filter, so filter injection can remove it. This is the design behind the textbook bypass in the WSTG page. It still appears in legacy code against OpenLDAP; it cannot work against AD, where the password attribute is not readable or searchable.

A fourth step often follows any of them: a group membership query that decides the user's role. That query is a separate injection point.

### Active Directory behaviours

Points that change how you test and rate against AD:

- **The password is never in a filter.** AD stores the password in `unicodePwd`, which can be written under strict conditions but not read or searched. Login is always a bind, so "filter injection bypasses the password" is not the AD failure mode; "the search returns the wrong DN" and "the group check returns true" are.
- **Login names come in several forms.** `sAMAccountName` (`alice`), `userPrincipalName` (`alice@example.com`) and `DOMAIN\alice` are all accepted by an AD bind, and applications often build one from another. Each conversion is a place where input is pasted into a string.
- **AD-specific matching rules.** Filters such as `(memberOf:1.2.840.113556.1.4.1941:=<group DN>)` (nested group membership, `LDAP_MATCHING_RULE_IN_CHAIN`) and `(userAccountControl:1.2.840.113556.1.4.803:=2)` (bitwise AND, here "account disabled") are common in group checks. If you see them in errors or source, the application is building AD filters by hand.
- **Ambiguous name resolution.** `(anr=<value>)` makes AD search a configurable set of naming attributes at once. People-search features sometimes use it, which means one input reaches many attributes.
- **Failed binds count towards lockout.** A bind with the wrong password increments the account's bad-password count. If injection makes the application bind as *someone else's* DN with your password, every attempt is a failed logon on a real account. This is the main safety constraint for login testing in AD environments (see [Before you start](#before-you-start)).
- **Errors are informative.** AD bind failures carry a sub-code in the diagnostic message (for example `data 52e` for invalid credentials, with other values for unknown user, disabled or locked accounts). An application that passes the raw message through has a username oracle even without injection.
- **Anonymous access is limited by default.** Current AD versions allow an anonymous bind to read the root DSE (server capabilities and naming contexts) but not, by default, to search the directory. A directory that answers anonymous searches has been configured to.

OpenLDAP and other servers differ in detail: unknown attributes in a filter may evaluate to "undefined" (no match) rather than an error, absolute true and false filters may be supported, and access controls on `userPassword` vary. Treat these as differences to observe, not assumptions.

### XPath and XQuery

XPath selects nodes from an XML document. A login against an XML user store typically looks like this (illustrative):

```text
//user[name/text()='<username>' and password/text()='<password>']/role/text()
```

Input lands inside string literals delimited by `'` or `"`. XPath 1.0 has no escape sequence inside a literal: a literal simply cannot contain its own delimiter. That is why concatenation is so dangerous and why the fix is variables, not escaping. Other properties:

- **No access control inside the document.** If you can change the expression, you can reach every node in the document, not just the user's own.
- **No comments in XPath 1.0.** As with LDAP, a working injection keeps the expression valid, usually by adding `and`/`or` conditions inside the predicate. XPath 2.0 and later allow `(: comments :)`.
- **Versions matter.** Java's built-in `javax.xml.xpath` (JAXP), libxml2 (and therefore lxml and PHP's `DOMXPath`) and .NET's `System.Xml.XPath` implement XPath 1.0. Saxon and XML databases implement XPath 2.0, 3.1 and XQuery, which add functions such as `doc()`, `lower-case()`, `matches()` and, in 3.0 and later, `unparsed-text()`. Those functions can read other documents or make network requests, so injection into a 2.0+ engine can reach outside the current document.
- **XQuery** (CWE-652) is a full query language over XML collections, with FLWOR expressions (`for … where … return`) and implementation-specific modules for files, HTTP and database updates. Concatenating input into XQuery is the XML-database equivalent of SQL injection.

## What goes wrong

### Concatenated search filters

The base case: `"(&(objectClass=person)(cn=" + q + "))"`. A `*` turns an exact lookup into a wildcard match; `alice)(objectClass=*` adds a condition the developer never wrote; `alice)(|(objectClass=*` (with the application's own closing parentheses completing it) changes the logic. **Why it matters:** the directory usually holds far more than the feature shows (every employee, service accounts, phone numbers, managers, group memberships, sometimes custom attributes with sensitive data), and the service account behind the web application can often read most of it. **Where to look:** people search, autocomplete endpoints for "assign to" and "share with" fields, address books, org charts, any API that takes a `username`, `login`, `email` or `uid` and returns directory data.

### Filters that look parameterised

Developers often reach for a formatter and believe they have parameterised the query: `String.format("(uid=%s)", u)`, Python `"(uid=%s)" % u`, or Java's `MessageFormat.format("(uid={0})", u)`. These are string formatting, not escaping. The `{0}` placeholder is the trap: JNDI's `DirContext.search(name, filterExpr, filterArgs, controls)` uses the same `{0}` syntax and *does* escape the arguments, so the two look identical in review. ForgeRock OpenAM's webfinger LDAP injection (see [Real-world cases](#real-world-cases)) was exactly this: `MessageFormat.format` with a filter pattern. **Where to look:** in source review, every `{0}`, `%s` or template literal that ends up in a `search` call; in black-box testing, there is no visible difference, so test every directory-backed parameter.

### Wildcards in search-then-bind logins

In a search-then-bind login, an unescaped `*` in the username makes the search return many entries. What the application does next decides the impact:

- It takes the first entry and binds with your password. You are not logged in (wrong password for that entry), but each attempt is a failed logon on whatever account came first, and with AD that counts towards lockout. In the Central Dogma advisory the search had a count limit of one and the realm bound to whatever entry came back first.
- It requires exactly one result. `*` fails, but a prefix such as `gtpentest-a*` that matches only your account succeeds, which proves the wildcard reached the filter.
- It logs the raw username but searches with the injected filter, so audit logs record a name that does not match the account actually used.

**Why it matters:** even without a bypass, you get an account and attribute oracle, a lockout lever against real users, and broken audit trails. **Where to look:** login forms, SSO connectors, API token exchanges that take a username and password, VPN and portal logins.

### Password checks inside the filter

When the password (or its hash) is part of the filter, filter injection can make the password condition irrelevant. With a filter `(&(uid=<u>)(userPassword=<p>))`, injecting into `u` so that the resulting filter matches an entry regardless of the password condition logs the attacker in as that entry. Whether a given payload works depends heavily on the client library and server. The 2008 Black Hat Europe paper by Alonso and colleagues observed that OpenLDAP processed only the first complete filter and ignored the rest, that some client components sent only the first filter, and that Microsoft ADAM rejected a string with two filters; many current client libraries validate the filter and reject trailing text before anything is sent. **Why it matters:** this is a real authentication bypass, usually as any user whose username you know or can wildcard. **Where to look:** legacy Java and PHP code against OpenLDAP, appliances, home-grown SSO.

### Group and role checks built from input

Authorisation often comes from a second query: "is this DN a member of `cn=app-admins`?", built as `(&(cn=app-admins)(member=<user DN>))` or `(&(objectClass=groupOfNames)(member=uid=<username>,ou=people,...))`. If the username or DN is pasted in unescaped, a crafted username can make the check true for a user who is not in the group. Parse Server's LDAP adapter had both problems at once: the user-supplied ID went unescaped into the bind DN and into the group filter, letting any authenticated directory user pass a restricted group check. **Why it matters:** privilege escalation to the application's admin role. **Where to look:** apps with role mapping from LDAP groups, "admin if in group X" configuration, tenant selection based on OU.

### DN injection

When input becomes part of a DN, the special characters are `,`, `+`, `=`, `\`, quotes, angle brackets, `;`, and leading `#` or spaces. A username `alice,ou=admins` produces `uid=alice,ou=admins,ou=people,dc=example,dc=com`, a different place in the tree; `alice+cn=x` produces a multi-valued RDN. For a bind this usually just fails, but the error may differ from a normal failure. For write operations (password reset, profile update, group add) the DN decides *which entry is modified*. **Why it matters:** in direct-bind logins it can change the bind target; in modify operations it can redirect a change to another entry; in group operations it can add the wrong member. **Where to look:** direct-bind login, password reset and change, profile update, group self-service, anything that echoes a DN back to you.

### Empty passwords and unauthenticated bind

RFC 4513 defines an "unauthenticated" simple bind: a non-empty name with an empty password. It establishes an anonymous session, and the DN is not checked at all. Some servers return success for it. If the application treats "bind succeeded" as "the password was right" and does not reject an empty password itself, anyone can log in as anyone by leaving the password blank. The RFC says clients should not let an empty password trigger this and servers should refuse it by default, but applications and older configurations do not always follow that. Spring Security's bind authenticator and django-auth-ldap reject empty passwords by default (django-auth-ldap has an opt-in setting to allow them); home-grown code usually does not. **Why it matters:** full authentication bypass with no injection at all. **Where to look:** every LDAP-backed login, including API endpoints and mobile back ends that call the same code. A password field that the front end marks as required is not evidence; send the request directly.

### Anonymous bind and over-privileged service accounts

Two configuration issues set the ceiling for any LDAP injection. If the directory accepts anonymous searches, an exposed LDAP port is a directory leak by itself (out of scope for a web test unless the port is in scope, but worth noting when it is). If the application's service account is a domain admin, a directory manager or simply has read access to every attribute, an injection inherits all of it. **Why it matters:** an injection with a read-only, attribute-restricted account is a nuisance; with a privileged one it is a data breach. **Where to look:** ask for the service account's permissions during the engagement; in source, look for bind credentials in configuration.

### Escaping in the wrong context

Escaping is easy to get almost right:

- filter escaping applied to a DN (or the reverse);
- escaping only `*` because "that's the dangerous one";
- an allowlist that permits `(`, `)` or `,` because real names contain them;
- input decoded twice, so `\2a` sent by the client is decoded to `*` before escaping (ASVS `v5.0.0-1.1.1` asks for decoding exactly once, before validation);
- escaping applied in the controller but a second code path (an API, a batch job, a mobile endpoint) calling the directory helper directly.

### Errors, oracles and expensive filters

Raw LDAP errors (`Bad search filter`, `InvalidSearchFilterException`, AD diagnostic strings) confirm the injection point and often disclose the filter, the base DN or the server type. Even with generic errors, a difference between "no such user", "wrong password" and "account locked" is a username oracle that injection makes much faster. Unindexed substring filters (`(description=*a*)`) and wildcard searches across a large directory are expensive for the server; a feature that lets anyone run them repeatedly is a resource-consumption issue, and it is also a reason to keep your own testing slow.

### XPath injection in authentication and lookups

XPath logins and lookups fail like SQL did twenty years ago: a quote breaks the expression (an error proves the injection point), `' or '1'='1` style conditions make a predicate always true, and the first matching node (often the first user in the file, frequently an administrator) is returned. Because there is no access control inside the document, a boolean oracle lets an attacker reconstruct the whole document: node names with `name()`, counts with `count()`, values with `substring()` and `string-length()`. Amit Klein's 2004 paper on blind XPath injection describes that technique. **Where to look:** SOAP services, legacy Java and .NET applications with XML user stores, configuration lookups keyed by tenant or organisation name, XSLT-driven reporting with user-supplied parameters.

### XPath 2.0 and later functions, and XQuery

On a 2.0+ engine, injection is not limited to the current document. `doc()` and `doc-available()` load other XML documents by URI, which can mean local files or network requests to internal hosts (an SSRF primitive); XPath 3.0 adds `unparsed-text()` for non-XML files. XML databases extend XQuery with modules for file access, HTTP requests and database updates, so XQuery injection can be a write or a server-side request, not just a read. The escalation is described in prose here on purpose; for testing, the proof is a version fingerprint or an out-of-band interaction with a collaborator you control (see [GT-WEB-LDAP-10](#gt-web-ldap-10-blind-xpath-xpath-20-functions-and-xquery)). Reading local files or reaching internal hosts needs explicit approval.

## Testing

Every test below assumes an authorised engagement with written scope and rules of engagement, a bug bounty programme whose rules allow injection testing, or a deliberately vulnerable lab. Requests, filters and responses are illustrative: hosts, DNs, attribute names and messages are made up, and real applications differ in detail.

### Before you start

**Scope.** Agree in writing which features may be tested for injection, whether the directory behind them is production AD or a test directory, and whether the LDAP service itself (ports 389 and 636, or 3268 and 3269 for an AD global catalogue) is in scope or only the web application. Most web engagements are the latter: you test what the application sends, not the directory directly. XML-backed features need the same agreement, plus explicit approval before any XPath 2.0 `doc()` test that makes the server request a URL.

**Accounts and markers.** Ask the client for test accounts in the directory rather than relying on self-registration:

| Identity | Why |
|---|---|
| Test user A, ordinary role, with a distinctive name prefix (for example `gtpentest-a`) | Every login and boolean proof targets this account |
| Test user B, same prefix (`gtpentest-b`) | Lets a wildcard such as `gtpentest-*` prove it matched more than one entry without touching anyone else |
| A known, harmless attribute value on A | For example `departmentNumber: GT-PENTEST` or a `description` canary; blind proofs check this value, never someone else's |
| Two test groups the client creates: `cn=gtpentest-users` (A and B are members) and `cn=gtpentest-admins` (only B is a member) | For [GT-WEB-LDAP-7](#gt-web-ldap-7-group-membership-and-authorisation-filters): proving a group check can be made true for A without touching real admin groups |
| The account lockout policy | Threshold and reset window, so you never approach it, even on your own accounts |

Choose a prefix that no real entry in the directory uses, and confirm that with the client. **Authentication-bypass checks use your own test account**: every login payload in this note names `gtpentest-a`, a prefix that only matches your accounts, or targets your own entry's DN.

**Lockout and real users.** In AD, a bind with the wrong password is a failed logon for the DN being bound. A username payload that matches someone else (a bare `*`, `a*`, `admin*`) combined with your password causes failed logons on real accounts and can lock them. Never send wildcard or filter-breaking usernames that could match accounts other than yours to a login endpoint. If the application gives no way to keep a payload confined to your prefix, stop and test that feature in a test directory or by source review.

**Proxy.** One Burp project per engagement, target scope set to the in-scope hosts, Logger on. Keep a Repeater tab per injection point with a baseline request, a "true" request and a "false" request side by side, and use Comparer for response diffs. Configure Burp Collaborator (or your own interactsh server) before any out-of-band XPath test. Burp Scanner has LDAP and XPath injection checks, and ZAP has active scan rules for both; in production, run them only against the specific parameters you are testing, not as a crawl-and-scan.

**Safe proofs.** Each test ends at the least invasive proof that input reaches the interpreter:

- an error or syntax difference (`gtpentest-a)` errors, `gtpentest-a` does not);
- a true/false pair (`gtpentest-a)(objectClass=*` returns your entry, `gtpentest-a)(objectClass=gtNoSuchClass` returns nothing);
- a known attribute value on **your own** entry (`gtpentest-a)(departmentNumber=GT*` true, `...=ZZ*` false);
- for XPath 2.0+, a version fingerprint or one out-of-band request to your collaborator.

Not in scope: extracting attribute values character by character from other entries, listing users or groups through wildcards, reading password hashes, retrieving other users' data through a bypass, or writes to anything other than your own entry.

**Directory enumeration.** Wildcard behaviour is proved, not exploited. One request that shows a wildcard matched more entries than your own (a result count, a "too many results" message, a list that is longer than your two accounts) is the finding. Record the count and that it happened; do not page through the results, export them, or repeat the query with different prefixes to map the directory. If a wildcard response already shows other people's details, note that it did, keep at most one redacted line as evidence, and move on.

**Stop on real data.** If any response returns data about a real person or an account you do not own (a name, an email address, a phone number, a group membership, a hash), stop that line of testing, keep only the minimum redacted evidence, do not download or keep more, and report it to the client or programme immediately. If a login payload ever logs you in as an account that is not yours, log out at once, do not use the session, and report.

**Rate limits.** One or two requests per second unless the rules say otherwise. Wildcard and substring filters are expensive on large directories, so keep wildcard requests to the handful needed for the proof. Pause if response times rise.

### GT-WEB-LDAP-1: Map directory and XML-backed features

*Guler Tech methodology.* Implements the identification step of WSTG-INJT-06 and WSTG-INJT-09 ("identify injection points"), with WSTG-INFO-06 (entry points).

#### What it checks

Which features send your input to a directory or an XPath engine, which login design each uses, and what the error handling reveals. The output is the work list for the other tests.

#### Prerequisites

Test accounts A and B; Burp Logger history from a full walk-through as A; any documentation the client provides (SSO and directory integration, the role mapping configuration).

#### Steps

1. Walk every feature that plausibly touches the directory: login (web, API, mobile back end), people and colleague search, "assign to" and "share with" autocompletes, org chart, profile pages, password reset and change, group or team management, admin reports.
2. Note for each request which parameters carry a username, email, display name, group name, DN or OU. DNs in responses (`"dn":"uid=gtpentest-a,ou=people,dc=example,dc=com"`) are a strong hint that input may also be used in DNs.
3. Fingerprint the directory from what the application discloses: AD-style attributes (`sAMAccountName`, `userPrincipalName`, `memberOf`, `objectGUID`), OpenLDAP-style (`uid`, `inetOrgPerson`, `entryUUID`), error strings, login hints such as "use `DOMAIN\username`".
4. Determine the login design: does a DN-shaped username work (`uid=gtpentest-a,ou=people,...`)? Does `DOMAIN\gtpentest-a` or `gtpentest-a@example.com` work? Is there a separate role lookup after login (a second slow step, a role appearing in the session)?
5. For XML-backed features: look for SOAP endpoints (`Content-Type: text/xml`, WSDL), XML request bodies, error messages mentioning XPath (`XPathException`, `XPathEvalError`, `Invalid predicate`), and features keyed by organisation or tenant name that might be a config lookup.
6. Send each candidate parameter once with a single `'` and once with a single `)` and note the responses alongside a baseline. Do not interpret them yet; that is the next test.

#### Observation

An inventory like this (illustrative):

| Request | Parameter | Likely query | Login design | Notes |
|---|---|---|---|---|
| `POST /login` | `username` | AD search then bind | search-then-bind | generic "invalid credentials" |
| `GET /api/people?q=` | `q` | substring filter over `cn`, `mail` | n/a | returns name, mail, phone |
| `POST /api/reset` | `email` | `(mail=...)` then modify | n/a | "if the address exists..." |
| `GET /api/me/groups` | none (session) | group filter with user DN | n/a | role mapping |
| `POST /soap/OrgLookup` | `<org>` | XPath over config XML | n/a | `XPathException` on `'` |

#### Evaluation

No finding by itself, except information exposure: raw LDAP or XPath error messages, base DNs and service-account names in responses, or the directory's internal attributes returned to ordinary users. Rate those by what they disclose (usually Low).

#### False positives

A `)` or `'` that produces an error because the application validates input (a 400 with a validation message) is not an injection signal. A DN in a response is not a vulnerability; it just tells you where to look.

#### Automation

In source review, grep for directory and XPath calls and their string building: `DirContext.search`, `LdapTemplate`, `ldap_search`, `ldap_bind`, `search_s`, `conn.search`, `client.search`, `XPath.compile`, `evaluate(`, `.xpath(`, `DOMXPath`, `SelectNodes`. Static analysis rules are listed in [Static analysis](#static-analysis).

### GT-WEB-LDAP-2: Probe for filter metacharacters and errors

*Guler Tech methodology.* Implements WSTG-INJT-06 ("trial-and-error with filter metacharacters").

#### What it checks

Whether LDAP filter metacharacters in a parameter change the server's behaviour in a way that only an unescaped filter explains.

#### Prerequisites

The inventory from [GT-WEB-LDAP-1](#gt-web-ldap-1-map-directory-and-xml-backed-features); account A; a non-login parameter to start with (people search or a lookup), so that probing does not generate failed logons.

#### Steps

1. Baseline: search for your own account by exact name.

```http
GET /api/people?q=gtpentest-a HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
Accept: application/json
```

2. Send a small set of single-character and short probes, one at a time, each next to the baseline:

```text
gtpentest-a)
gtpentest-a(
gtpentest-a\
gtpentest-a)(
gtpentest-a\29
```

3. Compare status, body, length and timing. The last probe is the control: `\29` is the escaped form of `)`. An application that escapes input searches for the literal text `gtpentest-a\29` (or for `gtpentest-a)` if it decodes escapes deliberately) and behaves the same as for any other unknown name.

```bash
for p in 'gtpentest-a' 'gtpentest-a)' 'gtpentest-a(' 'gtpentest-a%5C'; do
  curl -s -o /dev/null -w "%{http_code} %{size_download} $p\n" \
    -H 'Cookie: session=<SESSION_USER_A>' \
    "https://app.example.com/api/people?q=$p"
  sleep 1
done
```

#### Observation

Vulnerable (illustrative): the unbalanced probes produce a server error, and some stacks pass the cause through.

```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{"error":"javax.naming.directory.InvalidSearchFilterException: Unbalanced parenthesis"}
```

PHP applications using `ldap_search()` often surface `Bad search filter`; Python ldap3 raises `LDAPInvalidFilterError`. A generic `500` is also a signal when the baseline returns `200` and the escaped control returns `200` with no results.

Correct: every probe returns `200` with an empty result list (the literal string matched nobody), or a `400` validation error that is the same for all of them.

#### Evaluation

- **Fail (injection likely):** unbalanced probes (`)`, `(`, `)(`) cause errors or different responses while the escaped control does not. Confirm with the boolean pair in [GT-WEB-LDAP-4](#gt-web-ldap-4-boolean-filter-injection) before reporting.
- **Fail (information exposure):** the error discloses the filter, base DN, server type or a stack trace, regardless of injection.
- **Pass:** all probes behave like any other non-matching search.

#### False positives

- An input validator that rejects parentheses with a `400`: not injection, though check that the same validator protects every route to the directory.
- A WAF block page triggered by `)(`: a block is not an error from the interpreter. Look for the WAF's signature (block page, distinctive headers) and test the logic with the boolean pair instead.
- A search back end that is not LDAP at all (a database or a search index): parentheses can break those too. Fingerprint the error before naming the interpreter.

#### Automation

Burp Scanner's LDAP injection check and ZAP's active scan rule for LDAP injection probe the same way; run them on the specific parameter. In CI, a unit test that feeds these strings to the filter-building function and asserts the escaped output (see [Regression tests](#regression-tests)) is a better long-term control than a DAST scan.

### GT-WEB-LDAP-3: Wildcards in search and lookup features

*Guler Tech methodology.* Implements WSTG-INJT-06 (Example 1, search filters).

#### What it checks

Whether `*` in a parameter is treated as an LDAP wildcard where the feature should match literally, and whether a wildcard lets a user see more of the directory than the feature intends.

#### Prerequisites

Accounts A and B with the shared prefix; a search or lookup feature from the inventory; the client's statement of what the feature should return (exact match only? prefix search? which attributes?).

#### Steps

1. Exact match for your own account: `q=gtpentest-a`. Note the result count (1).
2. Prefix wildcard confined to your accounts: `q=gtpentest-*`. A literal search returns nothing; an LDAP wildcard returns A and B.
3. Escaped control: `q=gtpentest-\2a`. An escaping application searches for the literal string and returns nothing.
4. If, and only if, the feature is documented as exact-match and the prefix test returned both of your accounts, you may send **one** broader request to establish scale, for example `q=*` with any available size parameter set to the minimum (`limit=1`), and record only the reported count or "too many results" message. Skip this step if the feature returns full details for every match; the prefix result is enough.
5. For lookups that return a single object (`GET /api/users/gtpentest-a`), try `GET /api/users/gtpentest-*`: an endpoint designed for one exact user that returns "first match" for a wildcard is the same weakness in a different shape.

```http
GET /api/people?q=gtpentest-* HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
Accept: application/json
```

#### Observation

Vulnerable (illustrative): the wildcard reached the filter.

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"results":[{"uid":"gtpentest-a","cn":"GT Pentest A"},{"uid":"gtpentest-b","cn":"GT Pentest B"}],"count":2}
```

Correct for an exact-match feature: `{"results":[],"count":0}` for both `gtpentest-*` and `gtpentest-\2a`.

#### Evaluation

- **Fail:** a feature specified as exact-match treats `*` as a wildcard. Severity depends on what a wildcard exposes: a people search that already allows substring search loses nothing; a "check if a user exists" or password-reset lookup that becomes a directory dump is a real finding. A single-object endpoint that resolves a wildcard to "first match" is a finding even if the data is limited, because it is the same unescaped filter.
- **Fail (scale):** the step 4 count shows the whole directory is reachable from a low-privilege account.
- **Pass:** wildcards are literal (or rejected) wherever the feature does not offer wildcard search.

#### False positives

**Wildcard search legitimately supported.** Many people-search features are meant to match substrings, and the application adds `*` around your input itself (`(cn=*<input>*)`). Your `*` then behaves like any other character in a substring search, and returning A and B for `gtpentest-` without a `*` shows that. A wildcard is not the finding there; test the same parameter with [GT-WEB-LDAP-4](#gt-web-ldap-4-boolean-filter-injection), because the real question is whether `)(` is escaped. Similarly, an application that documents `*` as a supported search operator and escapes everything else is working as designed. Also exclude search back ends that are not LDAP (SQL `LIKE`, Elasticsearch) where `*` has its own meaning.

#### Automation

A replay helper in CI or Burp's Repeater with three saved requests (exact, prefix, escaped) per search endpoint is enough; there is nothing to fuzz.

### GT-WEB-LDAP-4: Boolean filter injection

*Guler Tech methodology.* Implements WSTG-INJT-06 ("inject metacharacters to alter the filter").

#### What it checks

Whether you can add a condition to the application's filter and see its truth value reflected in the response. A matching true/false pair is the clearest proof of LDAP filter injection, and it works whether or not wildcards are legitimately supported.

#### Prerequisites

An injection point from GT-WEB-LDAP-2 or GT-WEB-LDAP-3 that returns or reflects your own entry; account A.

#### Steps

1. Assume the application wraps your input as `(...(attr=<input>)...)`, where the closing parentheses come from the application. Send a pair that adds a condition inside the existing AND, keeping parentheses balanced:

```text
true:   gtpentest-a)(objectClass=*
false:  gtpentest-a)(objectClass=gtNoSuchClass
```

If the application's filter is `(&(objectClass=person)(uid=<input>))`, they become:

```text
(&(objectClass=person)(uid=gtpentest-a)(objectClass=*))
(&(objectClass=person)(uid=gtpentest-a)(objectClass=gtNoSuchClass))
```

2. If the input sits inside a substring the application builds (`(cn=*<input>*)`), use a pair that tolerates the extra wildcards, for example `gtpentest-a*)(objectClass=*` and `gtpentest-a*)(objectClass=gtNoSuchClass`.
3. If neither pair works, the input may be inside an OR (`(|(cn=*<input>*)(mail=*<input>*))`), where an added true condition matches everything. Do not try to broaden it; instead test a pair that narrows: `gtpentest-a)(&(objectClass=*)(uid=gtpentest-a` and the same with `gtNoSuchClass`. The aim is only to see the truth value flip on your own entry.
4. Optionally test the absolute filters from RFC 4526 (`gtpentest-a)(&` and `gtpentest-a)(|`). Some servers support them; many client libraries reject them as malformed before the request leaves the application, which is itself a useful error difference.
5. Repeat each request twice to rule out caching and flakiness.

#### Observation

Vulnerable (illustrative):

| Input | Results |
|---|---|
| `gtpentest-a` | 1 (your entry) |
| `gtpentest-a)(objectClass=*` | 1 (your entry) |
| `gtpentest-a)(objectClass=gtNoSuchClass` | 0 |
| `gtpentest-a\29\28objectClass=\2a` (escaped control) | 0 |

Correct: the true and false payloads both return 0 results, because each is searched as a literal string that matches no username.

#### Evaluation

- **Fail:** the true payload returns your entry, the false payload does not, and the escaped control does not. That is LDAP filter injection (CWE-90). Report the point and its context (search, lookup, login, group check), and rate it by what the filter controls, not by the proof itself.
- **Pass:** both payloads behave like a literal non-matching string.

#### False positives

- **Search engines that tokenise.** A full-text search that ignores punctuation may return your entry for both payloads, because it only matched `gtpentest-a`. That is a "both true" result, not a flip; injection requires the *false* payload to change the result.
- **Client-side filtering.** If the front end filters a cached list, the server never saw the payload. Confirm in Burp that the request with the payload reached the server.

#### Automation

The true/false/escaped triplet per parameter is easy to script with curl or a Burp Repeater group. For CI, the same three strings become a unit test of the filter builder that asserts the true and false inputs produce identical, fully escaped filters.

### GT-WEB-LDAP-5: Blind injection and attribute discovery

*Guler Tech methodology.* Implements WSTG-INJT-06 ("assess the severity of the injection") for injection points that show no data, only a difference in behaviour.

#### What it checks

Whether a confirmed injection point can be used as an oracle: presence of attributes and partial values on an entry, inferred from a yes/no response. This is how blind LDAP injection extracts data, and it decides the severity of points that return nothing directly (login forms, password reset, "user exists" checks). The proof uses **only your own entry and the attribute value you set**.

#### Prerequisites

An injection point that gives any observable difference (a message, a status code, a redirect, a response length, consistent timing); account A with a known attribute value (for example `departmentNumber: GT-PENTEST`).

#### Steps

1. Confirm the oracle on your own entry with the boolean pair from GT-WEB-LDAP-4. At a reset or "check username" endpoint that does not return data, the difference might be "we sent you an email" versus "no account found".
2. Attribute presence as behaviour proof: test whether attributes exist on your own entry. Standard ones you know your entry has, and one that cannot exist:

```text
gtpentest-a)(mail=*
gtpentest-a)(departmentNumber=*
gtpentest-a)(gtNoSuchAttribute=*
```

A true result for the first two and false for the third shows the oracle reads attribute presence. That is the finding; there is no need to try attribute names you do not already know exist.

3. Partial value proof on your own known value, two requests only:

```text
gtpentest-a)(departmentNumber=GT*
gtpentest-a)(departmentNumber=ZZ*
```

True then false shows that values can be inferred prefix by prefix, which is all an attacker needs to extract any readable attribute from any entry. Stop there. Do not iterate characters, do not repeat it for another entry, and do not test sensitive attributes (`userPassword`, `unicodePwd`, custom secret attributes) even on your own entry; the server's own access control on those is a question for the client, not for the oracle.

4. Note the service account's likely reach from what you already observed (did the people search show phone numbers, managers, groups?) to support the rating.

```http
POST /api/password-reset HTTP/1.1
Host: app.example.com
Content-Type: application/json

{"username":"gtpentest-a)(departmentNumber=GT*"}
```

#### Observation

Vulnerable (illustrative):

| Input | Response |
|---|---|
| `gtpentest-a` | `200 {"status":"sent"}` |
| `gtpentest-a)(departmentNumber=GT*` | `200 {"status":"sent"}` |
| `gtpentest-a)(departmentNumber=ZZ*` | `200 {"status":"not_found"}` |
| `gtpentest-a)(gtNoSuchAttribute=*` | `200 {"status":"not_found"}` |

If the true cases really send a reset email to your test mailbox, that is expected; check that only your account received one.

Correct: every injected string returns the same response as an unknown username (ideally the same response as a known one too; see ASVS `v5.0.0-6.3.8` on enumeration).

#### Evaluation

- **Fail:** the response distinguishes attribute presence or value prefixes on your entry. Report it as blind LDAP injection with a data-extraction impact bounded by what the service account can read. Unauthenticated blind injection that can read sensitive attributes is High; limited to directory attributes most employees can already see, Medium.
- **Pass:** no observable difference.

#### False positives

- **Timing-only differences** smaller than normal jitter. Repeat each request five times and compare medians before claiming a timing oracle.
- **Rate limiting** that flips responses after a few attempts. Space requests out and watch for `429` or "try again later".
- **Same message, different side effect** (one email sent, one not): that is still an oracle, but only for someone who can see the mailbox. Note it, rate it lower.

#### Automation

None against live systems beyond the handful of requests above. Character-by-character extraction tools exist; do not run them on client systems. In code review, any user-reachable search whose result changes a response without escaping is a blind injection point by definition.

### GT-WEB-LDAP-6: Login filters and unauthenticated bind

*Guler Tech methodology.* Implements WSTG-INJT-06 (Example 2, login) and WSTG-ATHN-04 (bypassing the authentication schema). **Own test account only.**

#### What it checks

Whether the login accepts an empty password as success (unauthenticated bind), whether the username reaches the login search or bind DN unescaped, and whether the password check can be removed through filter injection. Every payload names your own account or your own prefix, so no failed logons land on real users.

#### Prerequisites

Account A (`gtpentest-a`) and its password; the lockout threshold; the login design from GT-WEB-LDAP-1. Send requests directly from Repeater: the browser form's "required" attribute is irrelevant.

#### Steps

1. Baselines: A with the correct password (success), A with a wrong password (failure), an unknown username `gtpentest-zz` (failure). Note any difference between the two failures; that is already a username oracle.
2. **Empty password.** A's username with an empty password, then with the password parameter omitted, then with a single space (some stacks trim it to empty):

```http
POST /login HTTP/1.1
Host: app.example.com
Content-Type: application/x-www-form-urlencoded

username=gtpentest-a&password=
```

```bash
curl -s -i -X POST https://app.example.com/login \
  --data-urlencode 'username=gtpentest-a' --data-urlencode 'password=' | head -20
```

3. **Escape decoding.** A's username with one character written as an LDAP hex escape, with the **correct** password: `gtpentest\2da` (`\2d` is `-`). An application that escapes input searches for the literal backslash and fails; one that pastes input into a filter or DN lets the server decode `\2d` and logs you in as A. This proves unescaped input with no wildcard and no failed logon on anyone.
4. **Prefix wildcard confined to your account**, correct password: `gtpentest-a*`. Success means the wildcard reached the search. Then, once only, `gtpentest-*` with A's password: the result shows whether the application binds to "first match" (it may pick B and fail; that is one failed logon on your own account B).
5. **Boolean pair**, correct password: `gtpentest-a)(objectClass=*` (expect success if injectable) and `gtpentest-a)(objectClass=gtNoSuchClass` (expect failure). Same reasoning as GT-WEB-LDAP-4, applied to the login search.
6. **Password inside the filter.** Only if the login does not appear to bind as the user (for example, no bind-related errors and the application is known to compare passwords in a filter), test whether the password condition can be neutralised **for your own account**:
   - password `*` with username `gtpentest-a`: if the password is pasted raw into `(userPassword=<password>)`, this becomes a presence test and succeeds without the password;
   - username `gtpentest-a)(uid=gtpentest-a))(|(uid=gtpentest-a` with a wrong password: on client libraries that evaluate only the first complete filter, the password condition ends up in a second filter that is ignored. Strict libraries reject the string as malformed, which shows as an error.
7. Read the failure messages from steps 3 to 6. AD diagnostic strings or library exceptions in the response are a separate information-exposure finding.

#### Observation

Vulnerable to unauthenticated bind (illustrative): the empty password logs you in as A.

```http
HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: session=<SESSION_NEW>; HttpOnly; Secure; SameSite=Lax
```

Vulnerable to filter injection in the login search: step 3 or step 5 (true) logs you in as A with A's correct password while the escaped or false variant fails.

Correct: steps 2 to 6 all return the same generic failure as a wrong password, and the empty-password request is rejected before any bind (often visibly faster than a real bind).

#### Evaluation

- **Fail (Critical in most applications):** an empty or omitted password logs you in. Anyone can log in as any user whose name they know, including administrators. CWE-303 (the bind result is misinterpreted), with the LDAP detail in the description.
- **Fail (High):** step 6 logs you in as A without A's password. The password check is bypassable; the same payload with another username would log in as that user, so do not try it.
- **Fail (Medium, sometimes High):** steps 3 to 5 show unescaped input in the login search but the password is still verified by a bind. Impact: account and attribute oracle (GT-WEB-LDAP-5 on the login), lockout of arbitrary accounts through wildcards, audit-log confusion. Rate higher when the search result also drives role mapping (GT-WEB-LDAP-7).
- **Pass:** all of the above return the standard failure.

#### False positives

- **Your own session.** A login that "succeeds" because a valid session cookie for A was still in the request. Clear cookies between attempts.
- **SSO redirect.** A `302` to an identity provider is not a successful login; follow the redirect and check you actually reach an authenticated page as A.
- **Pre-filled password managers or saved credentials** in a browser replay; use Repeater, not the browser, for these steps.

#### Automation

An integration test that posts an empty password and asserts failure belongs in every LDAP-backed application's test suite (see [Regression tests](#regression-tests)). Semgrep has rules for anonymous or password-less binds in Java and PHP (see [Static analysis](#static-analysis)).

### GT-WEB-LDAP-7: Group membership and authorisation filters

*Guler Tech methodology.* Implements WSTG-INJT-06 together with WSTG-ATHZ-03 (privilege escalation), for roles derived from directory groups. **Own test accounts and the two test groups only.**

#### What it checks

Whether input reaching the role or group query can make a membership check true for an account that is not a member. This is the step that turns an LDAP injection into privilege escalation.

#### Prerequisites

Accounts A and B; `cn=gtpentest-users` (A and B members) and `cn=gtpentest-admins` (only B member), created by the client; an observable result of a group check: an access-check API, a role shown in `/api/me`, a feature that appears for members. If the only group that matters is the real admin group and there is no test equivalent, do this test by source review or in a test directory, not in production.

#### Steps

1. Find where membership is decided and what input reaches it. Common shapes:
   - an API that takes the group: `GET /api/access-check?group=gtpentest-users`;
   - an API or token exchange that takes the user: `POST /api/roles {"user":"gtpentest-a"}`;
   - the login username reused verbatim in a group filter such as `(&(cn=app-admins)(memberUid=<username>))`.
2. Baseline as A: the check for `gtpentest-users` is true, for `gtpentest-admins` false. As B, both true.
3. Wildcard in the group name, as A: `group=gtpentest-*`. If the check becomes true, the group value reached the filter unescaped and a non-member can pass a check for a group pattern.
4. Wildcard in the user identifier, as A, for the admin test group: `user=gtpentest-*` with `group=gtpentest-admins`. True means the check matched B's membership while you are A.
5. Boolean pair on the group value, as A: `gtpentest-admins)(objectClass=*` and `gtpentest-admins)(objectClass=gtNoSuchClass`. Both should be false for A; a difference between them confirms injection even when no wildcard works.
6. If any step returns true for `gtpentest-admins` as A, confirm once that the application grants the corresponding role (for example the role shown in `/api/me`), then log out. Do not use any function the role unlocks.

```http
GET /api/access-check?group=gtpentest-* HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
Accept: application/json
```

#### Observation

Vulnerable (illustrative):

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"group":"gtpentest-*","member":true}
```

Correct: `{"group":"gtpentest-*","member":false}` (the literal name matches no group), and the same for every injected variant.

#### Evaluation

- **Fail (High):** A passes a membership check for `gtpentest-admins` or a pattern including it. The same input against the real admin group would grant admin; say so in the report without demonstrating it.
- **Fail (Medium):** injection confirmed by the boolean pair but no route to a true result for a group A is not in. Note that a filter's tail (the application's closing parentheses and any conditions after your input) limits which payloads balance, and that a change in the code or a different attribute order can remove that limit.
- **Pass:** membership is decided from the authenticated DN with escaped values, and no input changes the result.

#### False positives

- **Nested groups.** A really is a member of `gtpentest-admins` through a nested group (AD's in-chain matching rule resolves nesting). Check the group in the directory with the client before reporting.
- **Cached roles.** A role granted earlier in the session, or a role cache that has not expired, can make a check look true. Use a fresh session.

#### Automation

Role mapping deserves a unit test with hostile usernames and group names (see [Regression tests](#regression-tests)), plus the access-control regression tests from [vertical privilege escalation](/web/web-vertical-privilege-escalation-bfla/).

### GT-WEB-LDAP-8: DN injection

*Guler Tech methodology.* Implements WSTG-INJT-06 for distinguished names (the "add or modify objects" impact). **Own test objects only.**

#### What it checks

Whether input pasted into a DN (direct-bind templates, password change and reset, profile updates, group self-service) is interpreted with DN syntax, and whether that could change which entry an operation targets.

#### Prerequisites

Account A; features from GT-WEB-LDAP-1 that build a DN from input (a `uid` or `username` in a write request, or a direct-bind login).

#### Steps

1. Direct-bind login, correct password, escape decoding: `gtpentest\2da`. In a DN, `\2d` is a valid hex escape for `-`, so an unescaped DN template binds as A; an escaping application binds as a non-existent `gtpentest\5c2da` and fails.
2. Direct-bind login, structure probes, correct password, one each:

```text
gtpentest-a,
gtpentest-a+cn=x
gtpentest-a\
"gtpentest-a"
```

Compare the failure messages with the normal wrong-password failure. A distinct error (invalid DN syntax, LDAP result code 34, a parser exception) shows the input is parsed as a DN.

3. Write operations, on your own entry only: in a request that updates A's profile and carries A's username or DN (`PUT /api/directory/users/gtpentest-a`), send the same harmless change (A's `description` set to `GT-PENTEST`) with the identifier written as `gtpentest\2da`. If the change is applied to A, the identifier is parsed as DN syntax on a write path.
4. Do **not** send a DN that points at another entry (`gtpentest-a,ou=admins`, another user's `uid`, a group DN) to a write operation. If steps 1 to 3 show DN parsing on a write path, the ability to redirect the write follows from the code, and the report says so.

```http
PUT /api/directory/users/gtpentest%5C2da HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
Content-Type: application/json

{"description":"GT-PENTEST"}
```

#### Observation

Vulnerable (illustrative): `gtpentest\2da` logs in as A, or the profile change lands on A; `gtpentest-a,` returns `{"error":"invalid DN syntax"}` instead of the usual `{"error":"invalid credentials"}`.

Correct: every variant fails like an unknown user, and the profile endpoint returns `404` or `403` for the escaped identifier.

#### Evaluation

- **Fail:** input is interpreted as DN syntax. On a login bind only, rate Medium (it usually just changes which DN is bound, and the password still has to match, but combine with GT-WEB-LDAP-6 step 2). On a write path, rate High when the operation is authorised by the identifier rather than by the session, because the write could be redirected to another entry.
- **Pass:** identifiers are escaped (or, better, the DN is taken from the authenticated session and never from the request).

#### False positives

- **Path decoding.** A web server or framework that decodes `%5C` in paths, or rejects backslashes, changes what reaches the application. Test the same value in a JSON body as well as in the path.
- **Legitimate DN logins.** Some applications deliberately accept a full DN as the username. Then structure probes error by design; test whether the application restricts which DNs are accepted (for example only under `ou=people`).

#### Automation

Unit tests on the DN builder with `,`, `+`, `=`, `\`, `#` at the start and a trailing space (see [Regression tests](#regression-tests)).

### GT-WEB-LDAP-9: XPath injection in lookups and login

*Guler Tech methodology.* Implements WSTG-INJT-09. Login steps: **own test account only.**

#### What it checks

Whether input is concatenated into an XPath expression, shown by a syntax error and a true/false pair, and whether an XML-backed login can be bypassed for your own account without its password.

#### Prerequisites

An XML-backed feature from GT-WEB-LDAP-1 (SOAP lookup, organisation or tenant lookup, XML user store login); account A in the XML user store if there is a login.

#### Steps

1. Syntax probes next to a baseline: a single `'`, a single `"`, and the pair `''` (two apostrophes). An expression built with `'` delimiters errors on `'`, and on XPath 1.0 also on `''`; a `"`-delimited one errors on `"`.

```http
POST /soap/OrgLookup HTTP/1.1
Host: app.example.com
Content-Type: text/xml; charset=utf-8
SOAPAction: "urn:OrgLookup"

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><OrgLookup><org>gtpentest-org'</org></OrgLookup></soapenv:Body>
</soapenv:Envelope>
```

2. Boolean pair in a string context (use the delimiter that errored):

```text
true:   gtpentest-org' and '1'='1
false:  gtpentest-org' and '1'='2
```

In a numeric context (`//org[id=<input>]`): `1001 and 1=1` and `1001 and 1=2`.

3. XML-backed login, own account, wrong password: username `gtpentest-a' or 'a'='b`. With an expression like `//user[name/text()='<u>' and password/text()='<p>']`, `and` binds tighter than `or`, so the predicate becomes "name is gtpentest-a, or (false and password matches)": true for your account whatever the password. No element names need to be known, and the payload cannot match anyone but you.
4. Control: username `gtpentest-a` with the same wrong password must fail.

```bash
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' -X POST https://app.example.com/xml-login \
  --data-urlencode "username=gtpentest-a' or 'a'='b" --data-urlencode 'password=not-my-password'
```

#### Observation

Vulnerable (illustrative): the quote errors, the pair flips, and the login payload succeeds as A.

```http
HTTP/1.1 500 Internal Server Error
Content-Type: text/xml

<faultstring>javax.xml.transform.TransformerException: Expected ], but found: '</faultstring>
```

| Input | Result |
|---|---|
| `gtpentest-org` | organisation found |
| `gtpentest-org' and '1'='1` | organisation found |
| `gtpentest-org' and '1'='2` | not found |
| username `gtpentest-a' or 'a'='b`, wrong password | logged in as A |

Correct: every probe behaves like an unknown name, and the login payload fails like any wrong password.

#### Evaluation

- **Fail (High, Critical when unauthenticated and administrators are in the same store):** the login payload logs you in as A without A's password. The same technique with `' or '1'='1` (which you do not send) would log in as the first user in the document. CWE-643.
- **Fail (High or Medium):** the boolean pair flips on a lookup. Every node in the document is readable through the oracle; rate by what the document holds (a user store with passwords is High, a list of public offices is Low).
- **Fail (Low):** errors expose the XPath expression or engine, with no confirmed injection.
- **Pass:** probes behave like literal strings.

#### False positives

- **XML parsing errors, not XPath errors.** A `'` inside an XML element is harmless to the XML parser, but `<` and `&` are not. If your probe broke the SOAP envelope, the error came from the parser; read the fault text.
- **SQL behind the SOAP service.** A quote breaking a back-end SQL query produces similar errors. Look for XPath-specific messages (`Expected ]`, `Invalid predicate`, `XPathException`) and use the boolean pair; SQL injection is tested in [SQL injection](/web/web-sql-injection/).

#### Automation

Burp Scanner and ZAP both include XPath injection checks. CodeQL ships XPath injection queries for Java, Python, JavaScript and C#. For CI, the login payload above makes a good negative test for any XML-backed authentication.

### GT-WEB-LDAP-10: Blind XPath, XPath 2.0 functions and XQuery

*Guler Tech methodology.* Implements WSTG-INJT-09 (blind XPath injection), plus XQuery injection (CWE-652), which WSTG does not test separately.

#### What it checks

Whether a confirmed XPath or XQuery injection point can evaluate arbitrary expressions (structure, version-specific functions, out-of-band requests). That sets the severity. The proof stops at structure-only expressions and one collaborator interaction; it never reads node names or values.

#### Prerequisites

A boolean injection point from GT-WEB-LDAP-9; Burp Collaborator or your own interactsh server; written approval before step 3.

#### Steps

1. **Expression evaluation with no data.** Every XML document has exactly one root element, so `count(/*)=1` is always true and `count(/*)=2` always false:

```text
gtpentest-org' and count(/*)=1 and 'a'='a
gtpentest-org' and count(/*)=2 and 'a'='a
```

A flip shows the engine evaluates functions over the whole document. This is the same primitive a blind extraction uses (`name()`, `string-length()`, `substring()`); do not go further.

2. **Version fingerprint.** `lower-case()` exists only in XPath 2.0 and later:

```text
gtpentest-org' and lower-case('A')='a' and 'a'='a
```

An XPath 1.0 engine (JAXP, libxml2, lxml, .NET, PHP `DOMXPath`) errors with an unknown function; a 2.0+ engine (Saxon, XML databases) returns true. Record which.

3. **Out-of-band, 2.0+ only, with approval.** One request using `doc-available()` with a URL on your collaborator, carrying no data:

```text
gtpentest-org' and doc-available('http://<COLLABORATOR_HOST>/gt-ldap-10') and 'a'='a
```

A DNS lookup or HTTP request from the server's network to your collaborator proves the engine can make outbound requests. Do not point `doc()` at local files or internal hosts, and do not build URLs that contain data from the document. Escalation to file reads or SSRF is described in [What goes wrong](#xpath-20-and-later-functions-and-xquery) and needs explicit approval.

4. **XQuery.** For XML databases and XQuery endpoints, repeat GT-WEB-LDAP-9 step 2 and step 1 above. XQuery supports `(: comments :)`, so a payload ending in `(:` may comment out the rest of the expression and produce a different error, which helps confirm the context. Do not send XQuery Update expressions (`insert node`, `delete node`, `replace value of`) or call implementation modules for files, HTTP or database administration.
5. **No timing payloads.** XPath has no sleep function, and heavy expressions over a large document load the server. Use the boolean oracle instead.

#### Observation

Vulnerable (illustrative):

| Input | Result |
|---|---|
| `... and count(/*)=1 and 'a'='a` | found |
| `... and count(/*)=2 and 'a'='a` | not found |
| `... and lower-case('A')='a' and 'a'='a` | found (XPath 2.0+) |
| `... and doc-available('http://<COLLABORATOR_HOST>/gt-ldap-10') and 'a'='a` | collaborator: DNS and HTTP from 203.0.113.20 |

Correct: all of these behave like literal strings.

#### Evaluation

- **Fail (High):** blind evaluation confirmed on a document that holds credentials or personal data; the whole document is extractable.
- **Fail (Medium; High once internal reach is shown):** the outbound request in step 3 arrived. The engine can reach other systems, which is a server-side request forgery primitive; rate it like SSRF with what the network position allows, and note that file reads may follow from the same functions.
- **Fail (Medium):** blind evaluation on a document with low-sensitivity content.
- **Pass:** probes are literal, or the engine is 1.0 with no injectable context.

#### False positives

- **Collaborator hits from scanners or link previews.** Use a unique path per test and confirm the source IP and timing match your request.
- **Version detection through errors only.** An "unknown function" error can come from a sanitiser that strips parentheses. Confirm the injection with the plain boolean pair first.

#### Automation

None beyond the handful of requests above against live systems. In code review, any XPath or XQuery string built by concatenation is the finding; use the parameterised APIs in [Parameterised XPath and XQuery](#parameterised-xpath-and-xquery).

## Secure implementation

### Design rules

- **Use the library's encoder for the right context, every time.** Filter values get RFC 4515 escaping; DN values get RFC 4514 escaping. The two are not interchangeable. Prefer APIs that build the filter or DN for you (JNDI filter arguments, Spring LDAP's query builder, LdapRecord's `where()`, ldapts filter objects) over escaping by hand. ASVS `v5.0.0-1.2.6` (L2) asks for exactly this, and `v5.0.0-1.1.2` (L2) asks that the encoding happens as the last step before the interpreter.
- **Validate as well, but never instead.** An allowlist for usernames (`^[a-z0-9._-]{1,64}$`) is a good extra layer; it is not a replacement for escaping, because display names, email addresses and group names legitimately contain characters that are special in filters or DNs.
- **Decide identity from the session, not the request.** Group checks and profile updates should use the DN the user authenticated as, taken from the server-side session, not a username or DN in the request.
- **Reject empty passwords before any bind,** and treat only a successful bind with a non-empty password as authentication. Prefer the framework's LDAP authenticator over home-grown bind logic.
- **Bind with a least-privileged service account** (ASVS `v5.0.0-13.2.2`): read-only, restricted to the subtrees and attributes the feature needs, with server-side size and time limits. An injection with that account reads little.
- **Wildcards are a feature, not a default.** If a search should support prefix or substring matching, escape the user's input and add the `*` yourself in code.
- **Return generic errors** (ASVS `v5.0.0-16.5.1`) and the same response for unknown user, wrong password and locked account.
- **XPath: bind variables, do not escape.** XPath 1.0 has no escape inside a string literal. Compile the expression once with `$variables` and supply the values at evaluation time (ASVS `v5.0.0-1.2.7`, L2). The same applies to XQuery external variables.

### Java and JNDI

Vulnerable: the filter is built by concatenation (or by `String.format` or `MessageFormat`, which are no better).

```java
// Vulnerable: input becomes filter syntax
String filter = "(&(objectClass=person)(uid=" + username + "))";
NamingEnumeration<SearchResult> results = ctx.search("ou=people,dc=example,dc=com", filter, controls);
```

Fixed: JNDI's `search(Name, String filterExpr, Object[] filterArgs, SearchControls)` substitutes `{0}`, `{1}`… and escapes each string argument according to the filter rules. DNs are built from `LdapName` and `Rdn` objects, which escape the value.

```java
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

public final class DirectoryLookup {
    private static final String PEOPLE = "ou=people,dc=example,dc=com";

    static NamingEnumeration<SearchResult> findPerson(DirContext ctx, String username) throws NamingException {
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        sc.setCountLimit(2);                               // expect one; two lets you detect ambiguity
        sc.setReturningAttributes(new String[] {"cn", "mail"});
        return ctx.search(new LdapName(PEOPLE),
                "(&(objectClass=person)(uid={0}))", new Object[] {username}, sc);
    }

    static LdapName userDn(String username) throws NamingException {
        LdapName dn = new LdapName(PEOPLE);
        dn.add(new Rdn("uid", username));                  // escaped: "a,ou=x" -> uid=a\,ou\=x
        return dn;
    }
}
```

`Rdn.escapeValue(value)` is available when you need the escaped string itself. For bind-based login, check the password before binding:

```java
if (password == null || password.isEmpty()) {
    throw new BadCredentialsException("Empty password");    // never let an empty password reach a simple bind
}
```

The OWASP ESAPI encoder's `encodeForLDAP` and `encodeForDN` are an alternative where the JNDI argument form does not fit.

### Spring LDAP and Spring Security

Spring LDAP's `LdapQueryBuilder` encodes values passed to `is()`, `gte()` and similar, and `filter(String format, String... params)` encodes the parameters. `filter(String)` with a single string is used as-is, and `like()` deliberately passes `*` through, so neither should receive raw input.

```java
import static org.springframework.ldap.query.LdapQueryBuilder.query;

import org.springframework.ldap.support.LdapNameBuilder;
import javax.naming.Name;

// Search: values are encoded by the builder
List<Person> people = ldapClient.search()
        .query(query().base("ou=people")
                .attributes("cn", "mail")
                .where("objectclass").is("person")
                .and("uid").is(username))
        .toList(new PersonAttributesMapper());

// Hard-coded filter with encoded parameters
query().base("ou=people").filter("(&(objectClass=person)(mail={0}))", email);

// DN: LdapNameBuilder escapes the RDN value
Name dn = LdapNameBuilder.newInstance("ou=people").add("uid", username).build();
```

`org.springframework.ldap.support.LdapEncoder.filterEncode(value)` and `LdapEncoder.nameEncode(value)` exist for the rare case where you must build a string yourself.

Spring Security's LDAP authentication substitutes the login name into `userSearchFilter` or `userDnPatterns` placeholders for you, and its bind authenticator refuses empty passwords:

```java
@Bean
AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource) {
    LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(contextSource);
    factory.setUserSearchBase("ou=people");
    factory.setUserSearchFilter("(uid={0})");   // {0} is the login name, inserted by the framework
    return factory.createAuthenticationManager();
}
```

For AD, `ActiveDirectoryLdapAuthenticationProvider` does the same with a `userPrincipalName` filter by default. If you replace the filter with your own, keep the `{0}` placeholder and never concatenate. Role mapping from groups should use the authenticated user's DN (Spring Security's `DefaultLdapAuthoritiesPopulator` does this by default), not request input.

### Python and Django

With **ldap3**, escape filter values with `escape_filter_chars` and RDN values with `escape_rdn`:

```python
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

def find_person(conn, username: str):
    flt = "(&(objectClass=person)(uid=%s))" % escape_filter_chars(username)
    conn.search("ou=people,dc=example,dc=com", flt, attributes=["cn", "mail"], size_limit=2)
    return conn.entries

def user_dn(username: str) -> str:
    return "uid=%s,ou=people,dc=example,dc=com" % escape_rdn(username)
```

With **python-ldap**, `ldap.filter.filter_format` escapes each value into a `%s` template, `ldap.filter.escape_filter_chars` escapes a single value, and `ldap.dn.escape_dn_chars` escapes a DN value:

```python
import ldap
import ldap.dn
import ldap.filter

flt = ldap.filter.filter_format("(&(objectClass=person)(mail=%s))", [email])
dn = "uid=%s,ou=people,dc=example,dc=com" % ldap.dn.escape_dn_chars(username)
results = conn.search_s("ou=people,dc=example,dc=com", ldap.SCOPE_SUBTREE, flt, ["cn"])
```

In **Django**, use django-auth-ldap rather than calling the directory from views. It escapes the `%(user)s` placeholder in search filters and DN templates and rejects empty passwords unless you set `AUTH_LDAP_PERMIT_EMPTY_PASSWORD = True` (do not).

```python
# settings.py
import ldap
from django_auth_ldap.config import LDAPSearch, GroupOfNamesType

AUTH_LDAP_SERVER_URI = "ldaps://ldap.example.com"
AUTH_LDAP_BIND_DN = "uid=svc-webapp,ou=services,dc=example,dc=com"
AUTH_LDAP_BIND_PASSWORD = env("LDAP_BIND_PASSWORD")
AUTH_LDAP_USER_SEARCH = LDAPSearch(
    "ou=people,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=%(user)s)"
)
AUTH_LDAP_GROUP_SEARCH = LDAPSearch("ou=groups,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(objectClass=groupOfNames)")
AUTH_LDAP_GROUP_TYPE = GroupOfNamesType()
AUTHENTICATION_BACKENDS = ["django_auth_ldap.backend.LDAPBackend"]
```

`LDAPSearch.search_with_additional_term_string()` is documented as taking an already escaped string; use `search_with_additional_terms()`, which escapes, when values come from users.

### PHP and Laravel

Plain PHP: `ldap_escape()` with the context flag. Without a flag it escapes every character, which is safe but produces filters that are hard to debug; with the wrong flag it is unsafe.

```php
<?php
$filter = sprintf(
    '(&(objectClass=person)(uid=%s))',
    ldap_escape($username, '', LDAP_ESCAPE_FILTER)
);
$sr = ldap_search($conn, 'ou=people,dc=example,dc=com', $filter, ['cn', 'mail'], 0, 2);

$dn = sprintf('uid=%s,ou=people,dc=example,dc=com', ldap_escape($username, '', LDAP_ESCAPE_DN));

if ($password === '') {
    throw new RuntimeException('Empty password');   // before ldap_bind()
}
$ok = @ldap_bind($conn, $dn, $password);
```

**Laravel** with LdapRecord: the query builder escapes fields and values passed to `where()`; `rawFilter()` does not, so never give it user input.

```php
<?php
use LdapRecord\Models\ActiveDirectory\User;

$user = User::where('samaccountname', '=', $request->input('username'))->first();   // escaped

// Never: User::rawFilter("(samaccountname={$request->input('username')})")->first();
```

For login, use LdapRecord-Laravel's authentication integration rather than calling `bind` yourself, so the empty-password and error-handling cases are handled in one place. **Symfony**: the Security component's LDAP user provider escapes the username; when you use the Ldap component directly, call `$ldap->escape($value, '', LdapInterface::ESCAPE_FILTER)` (or `ESCAPE_DN`) yourself, because the component does not escape for you.

### Node.js

**ldapjs** was decommissioned by its maintainer in May 2024 (the repository is archived and the npm package is marked deprecated), so do not start new work on it and plan to migrate existing code. **ldapts** is maintained at the time of writing and provides an `escapeFilter` tagged template, `Filter.escape()`, filter objects and a `DN` builder:

```javascript
import { Client, escapeFilter, AndFilter, EqualityFilter, DN } from 'ldapts';

const client = new Client({ url: 'ldaps://ldap.example.com' });

export async function findPerson(username) {
  // Tagged template: every interpolated value is escaped, the filter syntax is not
  const filter = escapeFilter`(&(objectClass=person)(uid=${username}))`;
  // Equivalent with filter objects:
  // new AndFilter({ filters: [
  //   new EqualityFilter({ attribute: 'objectClass', value: 'person' }),
  //   new EqualityFilter({ attribute: 'uid', value: username }) ] })
  const { searchEntries } = await client.search('ou=people,dc=example,dc=com', {
    scope: 'sub', filter, attributes: ['cn', 'mail'], sizeLimit: 2,
  });
  return searchEntries;
}

export function userDn(username) {
  return `${new DN({ uid: username }).toString()},ou=people,dc=example,dc=com`;   // value escaped
}

export async function login(username, password) {
  if (typeof password !== 'string' || password.length === 0) throw new Error('Empty password');
  const userClient = new Client({ url: 'ldaps://ldap.example.com' });
  try {
    await userClient.bind(userDn(username), password);
    return true;
  } finally {
    await userClient.unbind();
  }
}
```

A plain template literal (`` `(uid=${username})` ``) without the `escapeFilter` tag is the vulnerable version; the difference is one word, so make the tag mandatory in review.

### Parameterised XPath and XQuery

**Java (JAXP):** set an `XPathVariableResolver` before compiling, and reference values as `$name`.

```java
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import java.util.Map;

static String roleFor(Document users, String user, String pass) throws XPathExpressionException {
    Map<String, String> vars = Map.of("user", user, "pass", pass);
    XPath xp = XPathFactory.newInstance().newXPath();
    xp.setXPathVariableResolver(q -> vars.get(q.getLocalPart()));
    XPathExpression expr = xp.compile("string(//user[name/text()=$user and password/text()=$pass]/role)");
    return expr.evaluate(users);   // "x' or name/text()='gt'" is just a string value here
}
```

(Storing plaintext passwords in XML is its own finding; the example only shows the binding.) Parse the XML itself with DTDs disabled, as covered in [XXE and XML injection](/web/web-xxe-xml-injection/). With Saxon's s9api, declare the variable on the `XPathCompiler` and set it on the `XPathSelector`.

**Python (lxml):** pass variables as keyword arguments to `xpath()`, or compile once with `etree.XPath`.

```python
from lxml import etree

FIND_ROLE = etree.XPath("//user[name/text()=$u]/role/text()")

def role_for(doc, username: str):
    return FIND_ROLE(doc, u=username)          # or doc.xpath("//user[name/text()=$u]/role/text()", u=username)
```

**Node.js (`xpath` package):** parse once and supply `variables` at evaluation.

```javascript
import xpath from 'xpath';

const findRole = xpath.parse('string(//user[name/text()=$name]/role)');
export const roleFor = (doc, name) => findRole.evaluateString({ node: doc, variables: { name } });
```

**PHP:** `DOMXPath` has no variable binding. From PHP 8.4, `DOMXPath::quote($value)` returns a correctly quoted literal (using `concat()` when the value contains both quote types); on older versions, validate strictly or move the lookup out of XPath.

```php
<?php
$query = '//user[name/text()=' . DOMXPath::quote($username) . ']/role';   // PHP 8.4+
$nodes = (new DOMXPath($doc))->query($query);
```

**.NET:** binding variables into `XPathExpression` requires a custom `XsltContext`; most teams instead select a small set of candidate nodes with a fixed expression and compare values in code.

**XQuery:** declare external variables in the query (`declare variable $name external;`) and bind them through the driver: XQJ's `XQPreparedExpression.bindString(...)`, or the variable-binding API of your XML database's client. Never build XQuery strings from input, and disable or restrict modules for file, HTTP and update operations for the application's database user.

### Directory and service account hardening

These do not fix an injection, but they set its ceiling:

- **Service account:** read-only; scoped to the subtrees the application needs (for example `ou=people` and one `ou=groups`); no access to sensitive attributes; never a domain or directory administrator. Separate accounts for separate applications (ASVS `v5.0.0-13.2.1` and `v5.0.0-13.2.2`).
- **Limits:** server-side size and time limits for the service account, and indexes on the attributes the application filters on, so a wildcard cannot become a resource problem.
- **No unauthenticated or anonymous access:** OpenLDAP rejects unauthenticated binds (a DN with an empty password) unless `allow bind_anon_dn` is set, so leave it unset; `disallow bind_anon` and `require authc` stop anonymous binds and anonymous directory operations. In AD, keep anonymous access at its default (root DSE only).
- **Transport:** LDAPS or StartTLS for every bind that carries a password, and LDAP signing and channel binding where AD supports them.
- **Lockout and monitoring:** alert on bursts of failed binds from the application's servers and on searches by the service account that return unusually many entries.

### Static analysis

- **CodeQL:** LDAP injection queries for Java (`java/ldap-injection`), Python (`py/ldap-injection`) and C# (`cs/ldap-injection`); XPath injection queries for Java (`java/xml/xpath-injection`), Python (`py/xpath-injection`), JavaScript (`js/xpath-injection`) and C# (`cs/xml/xpath-injection`). All are part of the default security query packs at the time of writing.
- **Semgrep** (community rules): `java.lang.security.audit.ldap-injection`, `java.lang.security.audit.tainted-ldapi-from-http-request`, `java.lang.security.audit.anonymous-ldap-bind`, `java.lang.security.audit.tainted-xpath-from-http-request`, `php.lang.security.ldap-bind-without-password`, and C# rules for LDAP and XPath injection.
- **Review greps** for what scanners miss: `MessageFormat.format` or `String.format` near `search(`; template literals without `escapeFilter` passed to `client.search`; `rawFilter(`; `filter(` with a single concatenated string in Spring LDAP; `like(` with request input; `%` formatting into `search_s`; `.xpath(` or `compile(` with `+` or f-strings.

### Regression tests

Test the place that builds the query, with inputs that would change it, and assert the result is literal. Keep a shared list of hostile values:

```text
*    )    (    \    NUL    )(    *)(objectClass=*    gtpentest-a)(|(uid=*    a,ou=admins    a+cn=x    #a    " a "    ' or '1'='1    ' or 'a'='b
```

**Unit test of the builders (pytest):**

```python
import pytest
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn
from myapp.directory import person_filter, user_dn   # your builders

HOSTILE = ["*", ")", "(", "\\", "\x00", ")(", "*)(objectClass=*", "gtpentest-a)(|(uid=*"]

@pytest.mark.parametrize("value", HOSTILE)
def test_filter_values_are_escaped(value):
    assert person_filter(value) == "(&(objectClass=person)(uid=%s))" % escape_filter_chars(value)
    inner = person_filter(value)[len("(&(objectClass=person)(uid="):-2]
    assert not any(c in inner for c in "*()\x00")    # only escaped forms remain

@pytest.mark.parametrize("value", ["a,ou=admins", "a+cn=x", "#a", " a ", "a\\"])
def test_dn_values_are_escaped(value):
    assert user_dn(value) == "uid=%s,ou=people,dc=example,dc=com" % escape_rdn(value)
```

**Behaviour test against an in-memory directory:** ldap3's `MOCK_SYNC` strategy evaluates filters against entries you add in the test, so you can assert that `*` and `gtpentest-a)(objectClass=*` return nothing:

```python
from ldap3 import Server, Connection, MOCK_SYNC
from myapp.directory import find_person

def test_wildcard_and_filter_injection_return_nothing():
    conn = Connection(Server("fake"), user="cn=svc,dc=example,dc=com", password="x", client_strategy=MOCK_SYNC)
    conn.bind()
    conn.strategy.add_entry("uid=gtpentest-a,ou=people,dc=example,dc=com",
                            {"objectClass": ["person"], "uid": "gtpentest-a", "cn": "GT A"})
    conn.strategy.add_entry("uid=bob,ou=people,dc=example,dc=com",
                            {"objectClass": ["person"], "uid": "bob", "cn": "Bob"})
    assert len(find_person(conn, "gtpentest-a")) == 1
    for payload in ["*", "gtpentest-*", "gtpentest-a)(objectClass=*", "gtpentest\\2da"]:
        assert find_person(conn, payload) == []
```

In Java, the UnboundID LDAP SDK's `InMemoryDirectoryServer` (which Spring Boot also uses for its embedded LDAP test support) plays the same role; run the same payload list through the real service class and assert empty results, and assert that an empty password fails login.

**Login tests:** an empty password, an omitted password and a whitespace-only password must fail; a username of `*` must fail without a bind being attempted against any real entry (assert on the mock or a spy that no bind happened).

**XPath tests (lxml):**

```python
from lxml import etree
from myapp.xmlauth import role_for   # uses etree.XPath with $variables

DOC = etree.fromstring(b"<users><user><name>admin</name><role>admin</role></user>"
                       b"<user><name>gtpentest-a</name><role>user</role></user></users>")

def test_xpath_payloads_are_literal():
    assert role_for(DOC, "gtpentest-a") == ["user"]
    for payload in ["' or '1'='1", "gtpentest-a' or 'a'='b", "'] | //*[ '", "\" or \"1\"=\"1"]:
        assert role_for(DOC, payload) == []
```

Run these in CI alongside the authorisation regression tests from the [Access Control](/web/web-access-control-testing-guide/) notes, so a refactor that swaps the builder for string formatting fails the build.

## Practice labs

PortSwigger's Web Security Academy has no LDAP or XPath injection labs at the time of writing; its knowledge base describes both issues as Burp Scanner reports them ([LDAP injection](https://portswigger.net/kb/issues/00100500_ldap-injection), [XPath injection](https://portswigger.net/kb/issues/00100600_xpath-injection)). OWASP Juice Shop has no LDAP or XPath challenges either. Use these instead:

- **OWASP Mutillidae II** ([repository](https://github.com/webpwnized/mutillidae)): a deliberately vulnerable PHP application with an LDAP injection lesson and an XPath injection page (`user-info-xpath.php`) over an XML user store. The project's [Docker setup](https://github.com/webpwnized/mutillidae-docker) includes the LDAP server the lesson needs.
- **bWAPP** ([itsecgames.com](https://www.itsecgames.com/)): lists both XPath and LDAP injection among its bugs; the LDAP pages need a directory server to be configured before they work.
- **PentesterLab, Web for Pentester** ([exercise](https://pentesterlab.com/exercises/web-for-pentester)): has an "LDAP attacks" section (a null-bind login, where the parameters are removed entirely rather than sent empty, and a filter-injection login bypass) and an "XML attacks" section that includes XPath injection.
- **Build your own in ten minutes:** the vulnerable and fixed snippets in this note, plus ldap3's [mock strategy](https://ldap3.readthedocs.io/en/latest/mocking.html) or the UnboundID [in-memory directory server](https://docs.ldap.com/ldap-sdk/docs/javadoc/com/unboundid/ldap/listener/InMemoryDirectoryServer.html), make a lab where you can run every test above, including the wildcard and login ones, without any risk to a real directory. For XPath, an XML file and lxml or JAXP are enough.

## Real-world cases

- **LDAP injection in OpenAM's webfinger endpoint (PortSwigger research, 2021; CVE-2021-29156).** Michael Stepankin's [Hidden OAuth attack vectors](https://portswigger.net/research/hidden-oauth-attack-vectors) found that ForgeRock OpenAM built an LDAP filter from the webfinger `resource` parameter with `MessageFormat.format`, without escaping, which allowed unauthenticated blind injection; the research and the CVE describe character-by-character retrieval of sensitive values. A disclosed report to the U.S. Department of Defense programme shows the same CVE on one of its hosts ([HackerOne report 1278050](https://hackerone.com/reports/1278050), disclosed August 2021). It is the clearest example of a "looks parameterised" filter.
- **Wildcard username in an AD search-then-bind realm (Central Dogma, 2026; CVE-2026-11748).** The [advisory](https://github.com/advisories/GHSA-98q5-5qh2-7w75) describes an Active Directory realm that substituted the login name into `cn={0}` without RFC 4515 escaping and limited the search to one result: a username of `*` made the realm bind against the first entry returned, and payloads such as `bob)(uid=alice` were logged verbatim while the realm searched with the altered filter. It shows the authentication-confusion and audit-evasion variants from [What goes wrong](#wildcards-in-search-then-bind-logins).
- **Blind filter injection in a login flow (ZITADEL, 2026; CVE-2026-44671).** ZITADEL's LDAP identity provider did not escape usernames in its search filter. The [advisory](https://github.com/advisories/GHSA-rxvx-hhpj-q6px) is explicit that authentication bypass was not possible, but unauthenticated attackers could use different responses to enumerate usernames and extract attribute data: the GT-WEB-LDAP-5 scenario, rated High by the advisory.
- **DN and group filter injection to privilege escalation (Parse Server, 2026; CVE-2026-31828).** Parse Server's LDAP adapter interpolated the user-supplied ID into the bind DN and the group search filter without escaping, so any authenticated directory user could manipulate the DN and bypass group membership checks for restricted groups. The fix applied RFC 4514 and RFC 4515 escaping. [GitHub advisory](https://github.com/advisories/GHSA-7m6r-fhh7-r47c).
- **LDAP injection in a login form (GLPI, 2024; CVE-2023-51446).** GLPI's [advisory](https://github.com/glpi-project/glpi/security/advisories/GHSA-p995-jmfv-c7r8) states that when authentication is made against LDAP, the login form could be used for LDAP injection; fixed in 10.0.12. A reminder that mature, widely deployed applications ship this bug in the most obvious place.
- **XPath injection to command execution (Juniper J-Web, 2024; CVE-2024-39565).** NVD's [entry](https://nvd.nist.gov/vuln/detail/CVE-2024-39565) (CWE-643) describes an XPath injection in J-Web on Junos OS that let an unauthenticated attacker execute commands with the credentials of an administrator who was, or had recently been, logged in. The CVSS v3.1 vector there is `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`. XPath injection is not only an XML-login curiosity.
- **Blind XPath injection (research, 2004).** Amit Klein's [Blind XPath Injection](https://dl.packetstormsecurity.net/papers/bypass/Blind_XPath_Injection_20040518.pdf) paper set out how a single boolean oracle reconstructs an entire XML document, which is why GT-WEB-LDAP-10 stops at a structure-only proof.

More write-ups are collected in [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

Rate on what the injection controls (a search, a login, a role check, a write), the preconditions (unauthenticated, any user, a specific role), what the service account or document exposes, and whether the proof was a full bypass or an oracle. The vectors below are examples. Scope is Unchanged when the impact stays within the application and the directory data it is meant to use; it is Changed when the injected query makes the server send requests into other internal services (XPath 2.0 `doc()`; a callback to your own collaborator alone does not count) or the directory account's reach extends clearly beyond the application.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Empty or omitted password accepted as a successful login (unauthenticated bind) | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | Any account, including administrators, with only a username; no injection skill needed |
| LDAP or XPath login bypass without the password (password check inside the filter or expression) | High; Critical when administrators are reachable this way | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | Unauthenticated takeover of known or wildcard-matched accounts; the base score already sits in the Critical band, so justify a High rating by the limits you observed (which accounts the payload can reach, extra factors) |
| Group or role check made true by injected input | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1) | Any user to the application's privileged role |
| Unauthenticated blind LDAP or XPath injection reading sensitive attributes or a credential store | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | The whole readable directory or document, one bit at a time; automatable |
| Unauthenticated blind LDAP injection limited to usernames and ordinary directory attributes | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | Account enumeration and staff directory data; rate up if the directory holds personal data beyond names |
| Authenticated filter injection in people search exposing hidden entries or attributes | Medium; High for sensitive attributes | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (4.3) to `C:H` (6.5) | Depends on what the service account can read compared with what the feature should show |
| Unescaped username in a search-then-bind login, password still verified | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L` (6.5) | Oracle, wildcard-driven lockout of real accounts, audit confusion; not a bypass |
| DN injection on a write path authorised by the identifier | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` (6.5) | Writes can be redirected to another entry (password, group membership); severity follows the attribute written |
| DN injection on a bind only | Medium | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` (5.4) | Changes the bind target but the password still has to match |
| XPath 2.0+ injection with out-of-band requests | Medium; High once internal reach is shown | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | An interaction with your own collaborator shows outbound reach, not a change of scope; rate like SSRF by what the network position allows, and use `S:C` once requests into other internal services are shown |
| Wildcard accepted in an exact-match lookup, own entries only shown | Low | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (4.3) | Proves unescaped input; rate up once a boolean or blind impact is shown |
| Raw LDAP or XPath errors (filter, base DN, engine) without confirmed injection | Low | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | The base score overstates it; a hint for attackers, not access |
| Wildcard search supported by design, input otherwise escaped | Info | none | Working as designed; mention only if result limits are missing |

When you report, give the injection point and context, the true/false (or error) pair you observed, the proof on your own account, what the service account or document could expose (from the client, not from extraction), and confirmation that only your own test accounts and test groups were involved.

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 |
|---|---|---|---|---|
| GT-WEB-LDAP-1 | WSTG-INJT-06, WSTG-INJT-09, WSTG-INFO-06 | v5.0.0-16.5.1 | CWE-209 (errors) | A05:2025 |
| GT-WEB-LDAP-2 | WSTG-INJT-06, WSTG-ERRH-01 | v5.0.0-1.2.6, v5.0.0-16.5.1 | CWE-90, CWE-209 | A05:2025 |
| GT-WEB-LDAP-3 | WSTG-INJT-06 | v5.0.0-1.2.6 | CWE-90 | A05:2025 |
| GT-WEB-LDAP-4 | WSTG-INJT-06 | v5.0.0-1.2.6, v5.0.0-1.1.2 | CWE-90 | A05:2025 |
| GT-WEB-LDAP-5 | WSTG-INJT-06 | v5.0.0-1.2.6, v5.0.0-6.3.8, v5.0.0-13.2.2 | CWE-90 | A05:2025 |
| GT-WEB-LDAP-6 | WSTG-INJT-06, WSTG-ATHN-04 | v5.0.0-1.2.6, v5.0.0-6.3.8 | CWE-90, CWE-303 | A05:2025, A07:2025 |
| GT-WEB-LDAP-7 | WSTG-INJT-06, WSTG-ATHZ-03 | v5.0.0-1.2.6, v5.0.0-8.2.1 | CWE-90 | A05:2025, A01:2025 |
| GT-WEB-LDAP-8 | WSTG-INJT-06 | v5.0.0-1.2.6, v5.0.0-1.1.2 | CWE-90 | A05:2025 |
| GT-WEB-LDAP-9 | WSTG-INJT-09 | v5.0.0-1.2.7 | CWE-643 | A05:2025 |
| GT-WEB-LDAP-10 | WSTG-INJT-09 | v5.0.0-1.2.7, v5.0.0-13.2.4 | CWE-643, CWE-652 | A05:2025 |

ASVS levels: `v5.0.0-1.2.6` L2 (LDAP injection), `v5.0.0-1.2.7` L2 (XPath injection, parameterisation), `v5.0.0-1.1.2` L2 (encoding as the final step before the interpreter), `v5.0.0-6.3.8` L3 (no user enumeration through failed authentication), `v5.0.0-8.2.1` L1 (function-level access restricted to permitted consumers), `v5.0.0-13.2.2` L2 (back-end connections with least privilege), `v5.0.0-13.2.4` L2 (allowlist of external resources the application may reach), `v5.0.0-16.5.1` L2 (generic error messages). CWE choice: CWE-90 (LDAP injection), CWE-643 (XPath injection) and CWE-652 (XQuery injection) are all Base-level entries that MITRE allows for mapping, and they are the default for these findings. CWE-91 (XML injection, which MITRE also labels "Blind XPath Injection") exists but is broader; prefer CWE-643. For the empty-password login, CWE-303 (Incorrect Implementation of Authentication Algorithm) describes the root cause better than the class-level CWE-287, which MITRE marks as discouraged for mapping. `A05:2025` is Injection in the OWASP Top 10:2025, which lists CWE-90 and CWE-643 among its mapped CWEs; `A07:2025` is Authentication Failures and `A01:2025` Broken Access Control.

## References

**OWASP**

- WSTG: [Testing for LDAP Injection (WSTG-INJT-06)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/06-LDAP_Injection), [Testing for XPath Injection (WSTG-INJT-09)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/09-XPath_Injection)
- ASVS 5.0: [V1 Encoding and Sanitization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md) and the [5.0 source tree](https://github.com/OWASP/ASVS/tree/master/5.0)
- [A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/)
- Cheat Sheets: [LDAP Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html), [Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html), [Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
- Community pages: [LDAP Injection](https://owasp.org/www-community/attacks/LDAP_Injection), [XPATH Injection](https://owasp.org/www-community/attacks/XPATH_Injection), [Blind XPath Injection](https://owasp.org/www-community/attacks/Blind_XPath_Injection)

**CWE and standards**

- [CWE-90](https://cwe.mitre.org/data/definitions/90.html), [CWE-643](https://cwe.mitre.org/data/definitions/643.html), [CWE-652](https://cwe.mitre.org/data/definitions/652.html), [CWE-91](https://cwe.mitre.org/data/definitions/91.html), [CWE-303](https://cwe.mitre.org/data/definitions/303.html), [CWE-209](https://cwe.mitre.org/data/definitions/209.html)
- [RFC 4515](https://www.rfc-editor.org/rfc/rfc4515) (string representation of search filters, value escaping), [RFC 4514](https://www.rfc-editor.org/rfc/rfc4514) (string representation of distinguished names), [RFC 4513](https://www.rfc-editor.org/rfc/rfc4513) (authentication methods; section 5.1.2 on unauthenticated bind), [RFC 4526](https://www.rfc-editor.org/rfc/rfc4526) (absolute true and false filters)
- W3C: [XPath 1.0](https://www.w3.org/TR/1999/REC-xpath-19991116/), [XPath 3.1](https://www.w3.org/TR/xpath-31/), [XPath and XQuery Functions and Operators 3.1](https://www.w3.org/TR/xpath-functions-31/), [XQuery 3.1](https://www.w3.org/TR/xquery-31/)
- Microsoft: [Search filter syntax](https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax) (AD matching rule OIDs), [ANR attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-anr), [unicodePwd in MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2)
- OpenLDAP: [slapd.conf(5)](https://www.openldap.org/software/man.cgi?query=slapd.conf) (`allow bind_anon_dn`, `disallow bind_anon`, `require authc`)

**PortSwigger and research**

- Burp issue definitions: [LDAP injection](https://portswigger.net/kb/issues/00100500_ldap-injection), [XPath injection](https://portswigger.net/kb/issues/00100600_xpath-injection)
- Michael Stepankin, [Hidden OAuth attack vectors](https://portswigger.net/research/hidden-oauth-attack-vectors) (OpenAM webfinger LDAP injection)
- Amit Klein, [Blind XPath Injection](https://dl.packetstormsecurity.net/papers/bypass/Blind_XPath_Injection_20040518.pdf) (2004)
- Chema Alonso, Rodolfo Bordón, Antonio Guzmán and Marta Beltrán, [LDAP Injection & Blind LDAP Injection in Web Applications](https://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf) (Black Hat Europe 2008, presented by Chema Alonso and José Parada)

**Library and framework documentation**

- Java: [`DirContext.search` with filter arguments](https://docs.oracle.com/en/java/javase/21/docs/api/java.naming/javax/naming/directory/DirContext.html), [`Rdn`](https://docs.oracle.com/en/java/javase/21/docs/api/java.naming/javax/naming/ldap/Rdn.html), [`XPathVariableResolver`](https://docs.oracle.com/en/java/javase/21/docs/api/java.xml/javax/xml/xpath/XPathVariableResolver.html)
- Spring LDAP: [advanced query builder](https://docs.spring.io/spring-ldap/reference/query-builder-advanced.html), [`LdapEncoder`](https://docs.spring.io/spring-ldap/docs/current/api/org/springframework/ldap/support/LdapEncoder.html), [`LdapNameBuilder`](https://docs.spring.io/spring-ldap/docs/current/api/org/springframework/ldap/support/LdapNameBuilder.html); Spring Security: [LDAP authentication](https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/ldap.html)
- Python: [python-ldap `ldap.filter`](https://www.python-ldap.org/en/latest/reference/ldap-filter.html) and [`ldap.dn`](https://www.python-ldap.org/en/latest/reference/ldap-dn.html), [ldap3 mocking](https://ldap3.readthedocs.io/en/latest/mocking.html), [django-auth-ldap authentication](https://django-auth-ldap.readthedocs.io/en/latest/authentication.html), [lxml XPath](https://lxml.de/xpathxslt.html)
- PHP: [`ldap_escape`](https://www.php.net/manual/en/function.ldap-escape.php), [`DOMXPath::quote`](https://www.php.net/manual/en/domxpath.quote.php); [LdapRecord query builder](https://ldaprecord.com/docs/core/v4/searching); Symfony [LDAP security](https://symfony.com/doc/current/security/ldap.html)
- Node.js: [ldapts](https://github.com/ldapts/ldapts), [ldapjs (decommissioned)](https://github.com/ldapjs/node-ldapjs), [xpath](https://github.com/goto100/xpath)

**Tools and static analysis**

- [ZAP LDAP Injection scan rule](https://www.zaproxy.org/docs/alerts/40015/), [ZAP XPath Injection scan rule](https://www.zaproxy.org/docs/alerts/90021/)
- CodeQL query help: [java/ldap-injection](https://codeql.github.com/codeql-query-help/java/java-ldap-injection/), [py/ldap-injection](https://codeql.github.com/codeql-query-help/python/py-ldap-injection/), [cs/ldap-injection](https://codeql.github.com/codeql-query-help/csharp/cs-ldap-injection/), [java/xml/xpath-injection](https://codeql.github.com/codeql-query-help/java/java-xml-xpath-injection/), [py/xpath-injection](https://codeql.github.com/codeql-query-help/python/py-xpath-injection/), [js/xpath-injection](https://codeql.github.com/codeql-query-help/javascript/js-xpath-injection/), [cs/xml/xpath-injection](https://codeql.github.com/codeql-query-help/csharp/cs-xml-xpath-injection/)
- [Semgrep community rules](https://github.com/semgrep/semgrep-rules) (`java/lang/security/audit/` LDAP and XPath rules, `php/lang/security/ldap-bind-without-password`)
- [UnboundID LDAP SDK](https://github.com/pingidentity/ldapsdk) (`InMemoryDirectoryServer` for tests)
- Labs: [OWASP Mutillidae II](https://github.com/webpwnized/mutillidae), [bWAPP](https://www.itsecgames.com/), [PentesterLab Web for Pentester](https://pentesterlab.com/exercises/web-for-pentester)
