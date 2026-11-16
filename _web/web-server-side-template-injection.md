---
title: "Server-Side Template Injection and Code Injection"
date: 2026-11-15 20:06:00 +0000
subcategory: injection
summary: "Finding and confirming SSTI, expression-language, eval and SSI injection: template sinks, arithmetic probes, engine identification, sandboxes and fixes."
refs: [WSTG-INJT-18, WSTG-INJT-11, WSTG-INJT-08, v5.0.0-1.3.7, v5.0.0-1.3.2, v5.0.0-1.3.5, v5.0.0-1.3.8, "A05:2025", CWE-1336, CWE-94, CWE-95, CWE-917, CWE-97]
tags: [web, ssti, code-injection, expression-language, ssi, injection]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Injection](/web/web-injection-testing-guide/). It covers the family of bugs where user input stops being data and becomes something an interpreter *runs*: server-side template injection (SSTI, `WSTG-INJT-18`), expression-language injection in Java frameworks (SpEL, OGNL, Jakarta EL), `eval`-style code injection in Node.js, Python, PHP and Ruby (`WSTG-INJT-11`), lookup strings such as JNDI, and server-side includes (`WSTG-INJT-08`). They share one root cause, untrusted input concatenated into code or template *source* instead of being passed as a value, and one testing approach: send something the interpreter would evaluate, such as a multiplication, and see whether the answer comes back. You get the model (templates versus data, where user text reaches template source, sandboxed versus unsandboxed engines), the variants that keep producing findings (email and PDF templates, "custom message" features, view names, validation messages, rule builders), twelve tests that stop at the least invasive proof, an engine-identification table, and fixes for Python, Node.js, Spring, Laravel and Ruby with regression tests. OS command injection is in [OS command injection](/web/web-os-command-injection/); file inclusion (`WSTG-INJT-11.1`) and deserialisation belong to the Server-Side Request and Files subcategory, which is not written yet; client-side template injection in AngularJS and similar frameworks is cross-site scripting and belongs to the Client-Side subcategory.

## Contents

- [How it works](#how-it-works)
  - [Templates, data and the line between them](#templates-data-and-the-line-between-them)
  - [Plaintext context and code context](#plaintext-context-and-code-context)
  - [Expression languages and eval are the same problem](#expression-languages-and-eval-are-the-same-problem)
  - [Server-side includes](#server-side-includes)
  - [Sandboxed and unsandboxed engines](#sandboxed-and-unsandboxed-engines)
  - [Template engines at a glance](#template-engines-at-a-glance)
- [What goes wrong](#what-goes-wrong)
  - [User input concatenated into template source](#user-input-concatenated-into-template-source)
  - [Users who are allowed to write templates](#users-who-are-allowed-to-write-templates)
  - [Second-order rendering in email, PDF and notifications](#second-order-rendering-in-email-pdf-and-notifications)
  - [User input in a view name, template name or fragment](#user-input-in-a-view-name-template-name-or-fragment)
  - [Too much in the template context](#too-much-in-the-template-context)
  - [Expression evaluation in Java frameworks](#expression-evaluation-in-java-frameworks)
  - [eval and dynamic code in application logic](#eval-and-dynamic-code-in-application-logic)
  - [Lookup strings and JNDI](#lookup-strings-and-jndi)
  - [SSI on pages and on proxied responses](#ssi-on-pages-and-on-proxied-responses)
  - [Client-side template injection is a different bug](#client-side-template-injection-is-a-different-bug)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-WEB-SSTI-1: Inventory template sinks and user-controlled template content](#gt-web-ssti-1-inventory-template-sinks-and-user-controlled-template-content)
  - [GT-WEB-SSTI-2: Plaintext-context detection with a fuzz string and arithmetic](#gt-web-ssti-2-plaintext-context-detection-with-a-fuzz-string-and-arithmetic)
  - [GT-WEB-SSTI-3: Code-context detection](#gt-web-ssti-3-code-context-detection)
  - [GT-WEB-SSTI-4: Identify the template engine](#gt-web-ssti-4-identify-the-template-engine)
  - [GT-WEB-SSTI-5: Stored and second-order template rendering](#gt-web-ssti-5-stored-and-second-order-template-rendering)
  - [GT-WEB-SSTI-6: Assess sandbox and context exposure without exploiting](#gt-web-ssti-6-assess-sandbox-and-context-exposure-without-exploiting)
  - [GT-WEB-SSTI-7: Expression-language injection in Java applications](#gt-web-ssti-7-expression-language-injection-in-java-applications)
  - [GT-WEB-SSTI-8: eval-style code injection in Node.js, Python, PHP and Ruby](#gt-web-ssti-8-eval-style-code-injection-in-nodejs-python-php-and-ruby)
  - [GT-WEB-SSTI-9: Server-side include injection](#gt-web-ssti-9-server-side-include-injection)
  - [GT-WEB-SSTI-10: JNDI and lookup-string injection with out-of-band detection](#gt-web-ssti-10-jndi-and-lookup-string-injection-with-out-of-band-detection)
  - [GT-WEB-SSTI-11: Rule out client-side rendering and application-side maths](#gt-web-ssti-11-rule-out-client-side-rendering-and-application-side-maths)
  - [GT-WEB-SSTI-12: Source review for template, expression and eval sinks](#gt-web-ssti-12-source-review-for-template-expression-and-eval-sinks)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Python: Flask, Jinja2 and Django](#python-flask-jinja2-and-django)
  - [Node.js: Express, EJS, Handlebars and vm](#nodejs-express-ejs-handlebars-and-vm)
  - [Java: Spring, SpEL, Thymeleaf and FreeMarker](#java-spring-spel-thymeleaf-and-freemarker)
  - [PHP: Laravel Blade, Twig and Smarty](#php-laravel-blade-twig-and-smarty)
  - [Ruby: ERB and Liquid](#ruby-erb-and-liquid)
  - [SSI and JNDI configuration](#ssi-and-jndi-configuration)
  - [Static analysis](#static-analysis)
  - [Regression tests](#regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Templates, data and the line between them

A template engine takes two inputs: **template source** (text with placeholders, loops, conditionals and filters, written in the engine's language) and a **context** (the values to fill in). It compiles the source into something executable, often real code in the host language (Blade compiles to PHP, ERB and EJS to Ruby and JavaScript, Jinja2 to Python bytecode), and runs it against the context. Everything in the source is code. Everything in the context is data.

The safe pattern keeps user input on the data side. The template is a file the developers wrote (`greeting.html`, `invoice.ftl`), and the user's name arrives as a context value; the engine prints it, escaped, and never parses it. SSTI happens when user input crosses to the source side: the application builds the template string by concatenation, stores user-written text and later compiles it as a template, or lets the user pick part of a template's name or expression. ASVS 5.0 states the rule directly in `v5.0.0-1.3.7` (L2): templates must not be built from untrusted input, and where there is no alternative the input must be sanitised or strictly validated. CWE-1336 names the weakness.

The difference is often one line of code:

{% raw %}
```python
# Data: the user's name is a value; the engine prints it
render_template_string("Hello {{ name }}!", name=user_name)

# Source: the user's name becomes part of the template and is parsed
render_template_string("Hello " + user_name + "!")
```
{% endraw %}

With the second form, a user whose name is an expression in the engine's syntax gets that expression evaluated. The impact depends on what the engine lets an expression reach: in an unsandboxed engine that is usually the host language's runtime and therefore code execution on the server; in a well-sandboxed or logic-less engine it may be little more than reading values that happen to be in the context.

### Plaintext context and code context

WSTG-INJT-18 and James Kettle's 2015 research, which first documented the class, distinguish two places your input can land:

- **Plaintext context.** Your input is template text, outside any expression. Anything in engine syntax that you send is parsed: a multiplication wrapped in the engine's expression delimiters comes back as the product. This is the common case for "customise your message" and profile-field bugs, and it often looks like reflected XSS at first because HTML you send is also reflected unescaped.
- **Code context.** Your input is already inside an expression, for example a variable name the application wraps in delimiters itself (`greeting=user.name` rendered as the expression `user.name`). Sending delimiters of your own produces nothing interesting; you detect it by breaking *out* of the expression (closing the delimiter and adding text after it) or by sending something that is valid as an expression but not as a variable name.

Both matter because the detection technique differs, and a test that only tries plaintext probes will miss the second.

### Expression languages and eval are the same problem

Template engines are one kind of interpreter. Applications embed others:

- **Expression languages** in Java frameworks: Spring Expression Language (SpEL) in Spring, OGNL in Struts and in products built on WebWork such as Confluence, Jakarta EL (formerly JSP/Unified EL) in JSP, JSF and Bean Validation message interpolation, plus MVEL, JEXL and Groovy in rule engines. They are designed to evaluate expressions against objects, and most can call methods, construct objects and reference static classes. CWE-917 covers injection into them.
- **Dynamic code evaluation** in the host language: `eval`, `new Function` and the `vm` module in Node.js; `eval`, `exec` and `compile` in Python; `eval`, string `assert()` before PHP 8.0 and dynamic callables in PHP; `eval`, `instance_eval`, `class_eval` and `send` in Ruby. CWE-95 (eval injection) and CWE-94 (code injection) cover them.

ASVS 5.0 groups them under `v5.0.0-1.3.2` (L1): avoid `eval()` and dynamic code execution features such as SpEL, and where there is no alternative, sanitise user input before it is executed. The testing logic is the same as SSTI: send an expression with a predictable result and watch for the result.

### Server-side includes

Server-side includes (SSI) are directives in HTML comments, such as `<!--#echo var="DATE_LOCAL" -->`, that a web server expands before sending a page: Apache through `mod_include`, nginx through `ngx_http_ssi_module`, and IIS. They can print variables, include other files or URLs and, where enabled, execute commands (`#exec` in Apache). SSI injection (CWE-97) needs two things: SSI processing switched on for the response, and user input written into that response or into a file the server will later parse. It is rarer than it used to be, but it still appears on legacy `.shtml` sites and, more interestingly, where a reverse proxy has SSI enabled in front of an application that reflects user input. Apache's `IncludesNOEXEC` option permits SSI but disables `#exec cmd` and `#exec cgi`; nginx's SSI module has no command execution directive at all (its commands are `block`, `config`, `echo`, `if`, `include` and `set`).

### Sandboxed and unsandboxed engines

Most engines are **not sandboxes and do not claim to be**. Their documentation says so in plain terms: Twig "treats templates as trusted code" and its sandbox is "the only security boundary for templates written by untrusted authors"; the FreeMarker FAQ tells you to consider templates part of the source code, like `.java` files; Go's `html/template` security model "assumes that template authors are trusted"; the Django docs warn that the template system "isn't safe against untrusted template authors"; EJS's security policy calls it "effectively a JavaScript runtime"; Laravel's Blade "does not restrict you from using plain PHP code in your templates". For these engines, a user who controls template source has, in principle, the power of a developer.

Some engines offer a sandbox or restricted mode for user-written templates: Jinja2's `SandboxedEnvironment` and `ImmutableSandboxedEnvironment`, Twig's sandbox (from Twig 3.29 the `Twig\Sandbox\Sandbox` class, previously `SandboxExtension`), Smarty's `\Smarty\Security` policy, FreeMarker's `TemplateClassResolver` and member-access policies, Velocity's `SecureUberspector`. Others are designed for untrusted authors from the start by having almost no logic: Mustache, and Liquid ("Safe, customer facing template language", in Shopify's own words). Handlebars sits in between: logic-less by design, but compiled to JavaScript in your process and historically escapable (CVE-2019-19919, prototype access leading to code execution before 4.3.0; the 4.6.0 release added restrictions on prototype property access).

What a sandbox implies for testing and rating:

- **A sandbox narrows impact; it does not remove the finding.** Sandboxes are allow-lists over a huge surface, and they break. Jinja2 has had sandbox escapes through `str.format` (CVE-2016-10745), `str.format_map` (CVE-2019-10906), an indirect reference to `format` (CVE-2024-56326) and the `attr` filter (CVE-2025-27516, fixed in 3.1.6). Twig published more than ten sandbox-bypass advisories between May and July 2026 alone (GitHub Advisory Database, at the time of writing), and the `Twig\Sandbox\Sandbox` redesign arrived in 3.29. Report a sandboxed SSTI with the engine, version and sandbox in use, and rate it on what is reachable today plus the history of escapes.
- **The context is outside the sandbox's protection.** Every sandbox doc makes the same point: objects you pass in can be iterated, printed and, if their methods are allowed, called. An ORM model with a `delete()` method, a request object or a settings object in the context is the usual way a "safe" engine leaks secrets or changes data. The PortSwigger lab on information disclosure via user-supplied objects is built on exactly this in Django.
- **Resources are never limited.** Jinja2, Twig and FreeMarker all state that a template can burn unbounded CPU or memory. A sandboxed template feature with no time or size limit is a denial-of-service finding by itself.

### Template engines at a glance

The table is a testing aid, not a security ranking. "Expression form" uses descriptions rather than literal delimiters; the exact probes are in [GT-WEB-SSTI-4](#gt-web-ssti-4-identify-the-template-engine).

| Engine | Language | Expression form | Arithmetic in expressions | Untrusted-template stance in its docs | Typical impact of injected source |
|---|---|---|---|---|---|
| Jinja2 | Python | double curly braces; statement tags with brace-percent | Yes | Default environment is not sandboxed; `SandboxedEnvironment` exists with stated limits | Code execution unsandboxed; data exposure or escape in sandbox |
| Tornado templates | Python | double curly braces | Yes | No sandbox | Code execution |
| Mako | Python | `${...}` and Python blocks | Yes | No sandbox | Code execution |
| Django templates | Python | double curly braces; brace-percent tags | No (error) | "Isn't safe against untrusted template authors" | Data exposure via context objects, XSS; code execution is unusual |
| Twig | PHP | double curly braces | Yes | Templates are trusted code; sandbox is the only boundary | Code execution unsandboxed |
| Smarty | PHP | single braces | Yes | `\Smarty\Security` policy for untrusted editors | Code execution without a policy |
| Blade (Laravel) | PHP | double curly braces, `@` directives | Yes | Compiles to plain PHP | Code execution |
| FreeMarker | Java | `${...}`, `<#...>` directives | Yes | Treat templates as source code; restrict `?new` and member access | Code execution with default settings |
| Velocity | Java | `$var`, `#set(...)` directives | Yes | `SecureUberspector` for untrusted writers | Code execution via reflection by default |
| Thymeleaf | Java | `${...}` in `th:` attributes, `[[...]]` inline, `__...__` preprocessing | Yes (SpEL or OGNL) | Expressions are SpEL in Spring apps | Code execution where an expression is user-controlled |
| ERB, Slim, Haml | Ruby | `<%= ... %>`, `#{...}` | Yes | Ruby code | Code execution |
| Liquid | Ruby (and ports) | double curly braces, brace-percent tags | Filters only | Designed for untrusted authors | Data exposure via exposed objects |
| Handlebars | JavaScript | double curly braces | No | Logic-less; prototype access restricted since 4.6.0 | Usually data exposure; code execution in old versions |
| Mustache | many | double curly braces | No | Logic-less | Usually none beyond the data passed |
| Pug (formerly Jade) | JavaScript | `#{...}`, `-` code lines | Yes | Templates are JavaScript | Code execution |
| EJS | JavaScript | `<%= ... %>` | Yes | "Effectively a JavaScript runtime" | Code execution |
| Nunjucks | JavaScript | double curly braces | Yes | Jinja-like, no real sandbox | Code execution |
| Razor | C# | `@(...)`, `@{...}` | Yes | Views are compiled C# | Code execution where an app compiles user strings at runtime |
| Go `text/template`, `html/template` | Go | double curly braces | No (built-in functions only) | "Assumes that template authors are trusted" | Calls methods on the data passed; impact depends on those methods |

## What goes wrong

### User input concatenated into template source

**What happens:** a developer wants a dynamic greeting, a personalised error, or a page title that includes a search term, and builds the template string with concatenation or string formatting before rendering it: Flask's `render_template_string("Hello " + name)`, `Jinja2.from_string(...)`, `ejs.render(prefix + input)`, `Blade::render("Hello ".$name)`, `new Template("t", new StringReader(text), cfg)` in FreeMarker, `Velocity.evaluate(ctx, out, "t", text)`, `ERB.new(text).result`. WSTG-INJT-18's Flask example is this pattern exactly.

**Why it matters:** in an unsandboxed engine this is code execution for anyone who can reach the parameter, often unauthenticated.

**Where to look:** anything echoed back in a rendered page that was not a stored record: search terms, `?name=`, `?message=`, `?error=`, `?title=` parameters, "Hello, X" banners, custom 404 and error pages that include the requested path, marketing landing pages with `?utm_` text rendered into the page. PortSwigger's "unknown language with a documented exploit" lab hides its bug in a `message` parameter that displays "out of stock".

### Users who are allowed to write templates

**What happens:** templating is the feature. A CMS or theme editor, an email-template editor for tenants, a "custom invoice layout", a notification designer, a wiki macro, a report builder, a "custom fields with formatting" feature, a marketing tool that lets customers write merge templates. The application renders what the user wrote with the same engine and environment it uses for its own templates.

**Why it matters:** this is SSTI by design. It is a finding whenever the people who can write templates are not supposed to run code on the server: tenant administrators in a SaaS product, content editors, support staff, customers. Kettle's research showed it on Alfresco (FreeMarker, reachable by low-privilege users via a stored XSS that made an administrator install a template) and XWiki (Velocity in wiki pages that registered users could edit). PortSwigger notes that a content-editor account becomes a server compromise when template editing is unrestricted.

**Where to look:** every admin or settings screen that accepts more than plain text: "Templates", "Email", "Notifications", "Branding", "Layouts", "Invoice", "Snippets", "Macros", "Pages". Ask which roles can reach them and who those roles are in practice.

### Second-order rendering in email, PDF and notifications

**What happens:** user input is stored safely, then rendered later in a different place by a different code path that builds a template from it: the display name inserted into a "your account was updated" email template, the company name concatenated into a PDF invoice template, an order note turned into an SMS or push notification, a ticket subject rendered into a Slack or webhook message template. WSTG-INJT-14 (incubated vulnerabilities) describes the general shape: the payload is planted in one request and fires in another.

**Why it matters:** the web view usually escapes the value correctly, so the bug is invisible in the browser. The Uber report in [Real-world cases](#real-world-cases) is this pattern: a profile name of `'7'*7` in Jinja2 delimiters came back as `7777777` in the account-update email.

**Where to look:** every field that later appears in an email, PDF, export, notification, calendar invite or third-party message. Follow each one to its rendered output with an address and device you control.

### User input in a view name, template name or fragment

**What happens:** the application chooses which template to render from a request parameter (`?lang=en` mapped to `"user/" + lang + "/welcome"`, `?section=billing`), and the framework treats the view name as more than a file name. Veracode's Spring View Manipulation research shows the sharpest case: in Spring MVC with Thymeleaf, a view name containing a fragment expression is parsed, and Thymeleaf's expression preprocessing (double underscores around an expression) evaluates SpEL inside it. A controller method that returns `void` can be affected too, because Spring derives the view name from the request path. The same research lists the safe cases: `@ResponseBody` and `@RestController` return values are bodies, not view names; `redirect:` views do not evaluate expressions; a handler that takes `HttpServletResponse` is treated as having handled the response.

**Why it matters:** expression evaluation in Spring is code execution unless the context is restricted. Thymeleaf has added restrictions to expressions in view names and fragment selectors over successive 3.x releases, and bypasses have followed (CVE-2023-38286, a sandbox bypass in Thymeleaf through 3.1.1.RELEASE affecting Spring Boot Admin), so check the version rather than assuming.

**Where to look:** parameters that select a page, language, theme, layout, section or "partial"; any 500 error mentioning "Error resolving template" or a template path that contains your input.

### Too much in the template context

**What happens:** even with a safe engine or a sandbox, the context contains rich objects: the ORM model instead of its two printable fields, the request, the user object with its password hash, the settings module, a service with methods. Template authors can print, iterate and sometimes call them.

**Why it matters:** this turns a "logic-less" or sandboxed template feature into data disclosure (framework secret keys, other users' data reachable through relations) or unintended writes. The PortSwigger Django lab asks you to steal the framework's secret key through exactly this.

**Where to look:** errors that list available variables, documentation of "variables you can use in your template", and whether the variables are scalars or objects with attributes.

### Expression evaluation in Java frameworks

**What happens:** an expression language is evaluated over input that an attacker influences. The public CVE history is long:

| CVE | Product | What was evaluated |
|---|---|---|
| CVE-2017-5638 (S2-045) | Apache Struts 2 Jakarta multipart parser | A malicious `Content-Type` value: the bulletin describes an exception whose message is displayed to the user, and public analyses showed that message was evaluated as OGNL |
| CVE-2018-11776 (S2-057) | Apache Struts 2 | Namespace handling with `alwaysSelectFullNamespace` |
| CVE-2020-17530 (S2-061) | Apache Struts 2 | Forced OGNL evaluation (the percent-brace syntax) applied to raw user input in tag attributes |
| CVE-2021-26084, CVE-2022-26134 | Confluence Server and Data Center | OGNL injection, unauthenticated |
| CVE-2023-22527 | Confluence Data Center and Server | Template injection on older versions, unauthenticated |
| CVE-2016-4977 | Spring Security OAuth 2.0.0 to 2.0.9, 1.0.0 to 1.0.5 | The `response_type` parameter in whitelabel views was executed as SpEL |
| CVE-2018-1273 | Spring Data Commons | Property binder evaluating special elements in request parameters |
| CVE-2022-22947 | Spring Cloud Gateway | Code injection through an enabled, exposed and unsecured Gateway Actuator endpoint |
| CVE-2022-22963 | Spring Cloud Function | A user-supplied SpEL routing expression |
| CVE-2020-9296 | Netflix Titus | Java EL in Bean Validation custom constraint messages built from user input |
| CVE-2022-22954 | VMware Workspace ONE Access and Identity Manager | Server-side template injection |

At the time of writing, every entry in the table except CVE-2016-4977 and CVE-2020-9296 is listed in the CISA Known Exploited Vulnerabilities catalogue.

**Why it matters:** most of these were unauthenticated code execution on internet-facing systems, and several were mass-exploited.

**Where to look:** in custom code, anything that calls `SpelExpressionParser.parseExpression` on a value from a request, configuration a user can edit, or a database field; "filter", "sort", "rule", "condition", "formula" and "routing" parameters; validation error messages that echo your input (a sign that the message template contains it); Struts tags with forced evaluation; and product versions of Struts, Confluence and Spring Cloud components in the fingerprint.

### eval and dynamic code in application logic

**What happens:** application code evaluates a string that contains user input: a calculator or "formula" field, a pricing or discount rule written in JavaScript or Python, an "advanced search" that is evaluated, old code that parses JSON with `eval`, a PHP callback name taken from a parameter (`call_user_func($_GET['f'], ...)`), a Ruby `send(params[:action])`, a webhook "transform" field, a low-code automation step.

**Why it matters:** it is code execution in the application's own process with its credentials, which is usually as bad as it gets for the web tier.

**Where to look:** inputs that accept expressions (`price * 0.9`, `a > 3 && b < 5`), parameters that look like function or method names, features described as "rules", "formulas", "conditions", "scripts" or "custom logic". Features that run customer code *by design* are a different question (is the code isolated properly?); treat them as a sandbox assessment with explicit approval, not as a black-box injection test.

### Lookup strings and JNDI

**What happens:** a library expands special syntax in strings it processes. The best-known case is Log4j 2's message lookups: before the fixes for CVE-2021-44228 (Log4Shell), a logged string containing a `jndi:` lookup in dollar-brace syntax made the logging library perform a JNDI lookup to an attacker-chosen LDAP or other endpoint, which could lead to code execution. Application code can do the same directly with `InitialContext.lookup(userInput)`. ASVS 5.0 `v5.0.0-1.3.8` (L2) requires untrusted input to be sanitised before JNDI queries and JNDI to be configured securely.

**Why it matters:** the input does not need to be rendered anywhere visible; any header, username or field that gets logged is a sink, and the lookup may fire minutes later in a different system that processes the logs.

**Where to look:** Java services (including appliances and vendor products in scope), anything that logs request data; detection is out-of-band only, see [GT-WEB-SSTI-10](#gt-web-ssti-10-jndi-and-lookup-string-injection-with-out-of-band-detection).

### SSI on pages and on proxied responses

**What happens:** user input is written into a page that the web server parses for SSI directives: a guestbook or comment stored into an `.shtml` page, an error page template with SSI, or an nginx location with `ssi on` that proxies an application response containing reflected input. WSTG-INJT-08 also notes headers such as `Referer` and `User-Agent` written into dynamically generated pages.

**Why it matters:** with `#exec` enabled (Apache `Options +Includes` without `IncludesNOEXEC`), it is command execution. Without it, `#include` can still pull in local files or internal URLs that the server can reach, and `#echo` discloses server variables.

**Where to look:** `.shtml`, `.shtm` and `.stm` extensions, legacy sections of old sites, and proxy configurations (grey-box) with SSI enabled.

### Client-side template injection is a different bug

**What happens:** a client-side framework (classically AngularJS 1.x, also Vue templates compiled in the browser) compiles user-controlled text inside the page as a template, so an expression in its delimiters runs in the victim's browser. WSTG tracks it as WSTG-CLNT-15 and PortSwigger as a cross-site scripting context.

**Why it matters for this note:** it produces the same "the multiplication came back" signal as SSTI, but it is XSS, rated and fixed as XSS. [GT-WEB-SSTI-11](#gt-web-ssti-11-rule-out-client-side-rendering-and-application-side-maths) shows how to tell them apart; testing CSTI itself belongs to the Client-Side subcategory, not written yet.

## Testing

### Before you start

**Scope and authorisation.** Every test here assumes an authorised engagement with written scope and rules of engagement, a bug bounty programme whose rules allow injection testing, or a deliberately vulnerable lab. SSTI and code injection are unusual in one way: the distance between "the multiplication came back" and "I am running code on the server" can be a single request, so agree the **proof ceiling** with the client before you start. Our default, and the one this note follows: detection is a syntax error or behaviour difference, an arithmetic result, an engine identification, a bounded time delay or an out-of-band DNS interaction. Anything beyond that (reading configuration objects, listing classes, reading files, running even `id`) needs explicit written approval *for that finding*, and then stops at a harmless command such as `id` or `hostname`. No shells, no file writes, no persistence, no use of what you found to go further.

**Accounts and objects.** Use accounts you control, at least one per role that can reach template features (user, tenant admin, content editor), and your own tenant for multi-tenant products. For anything that renders into email, SMS or PDF, use a mailbox, phone number and download location you own. **Never edit a template that real users receive**: a tenant-wide email template, a live CMS page, a shared notification. Use a preview or "send test" function, a draft, or a template you created; record the original content and restore it.

**Proxy.** One Burp project per engagement, target scope set to the in-scope hosts, Logger on, so every probe you sent is on record with its location. Useful tools: Repeater for single probes, Intruder only with a short, fixed probe list and throttling, Comparer for "with probe versus without" diffs, the **Backslash Powered Scanner** extension (it looks for input transformations that suggest interpretation), and Burp Scanner's active checks, which include SSTI, used with care in production.

**Collaborator.** For blind cases (email rendering, logs, background jobs), you need an out-of-band receiver you control: **Burp Collaborator** in Burp Suite Professional, or a self-hosted **interactsh** server. Prefer your own infrastructure over public shared receivers so interaction data from a client stays with you. Generate one payload per injection point so a hit tells you where it came from.

**Safe proof ladder.** Work up and stop at the first rung that proves the point:

1. A **syntax difference**: the fuzz string or an unclosed delimiter produces an error or a change that plain text does not.
2. An **arithmetic result** with a distinctive answer. We use `1234*5678`, which is `7006652`; `7*7 = 49` is classic but 49 appears on many pages by accident.
3. An **engine discriminator** (an expression that behaves differently in two engines, such as multiplying a string by a number).
4. Only where there is no output: a **bounded time delay** (a few seconds, repeated three times against a baseline) or an **out-of-band DNS lookup** to your collaborator.

Do not use payloads that enumerate classes (`__subclasses__`, `getClass()` chains), read environment variables, print configuration or context objects, or call OS functions, unless that specific step is approved.

**Payload hygiene.** Keep payloads short and one per request. Use a unique marker per location (`gt-ssti-07`) so a stored probe that fires later can be traced. Stored probes (profile names, template drafts, ticket subjects) are visible to other people and other systems; remove them when you finish and list them in your notes for the client.

**Rate limits and load.** One or two requests per second unless the rules say otherwise. Scanners (SSTImap, TInjA, Burp Scanner) send hundreds of probes per parameter; throttle them (`--delay` in SSTImap, `--ratelimit` in TInjA) and point them at single parameters, not whole sites. Never send templates that loop or build large output (ranges, repeated string multiplication); a sandboxed engine will happily run them and you will have caused the denial of service you were meant to report. Time-based probes block a worker or, in Node.js, the event loop for every user of that process; keep delays to a few seconds and the number of requests small.

**Stop rules.** Stop that line of testing, keep only the minimum redacted evidence and report it immediately if: a probe output shows another user's data, secrets, keys, environment values or credentials (for example in an error page or a rendered context object); a probe you planted renders for someone other than you (a real customer receives your email, a shared page shows your marker); or the application slows down or errors start appearing for other requests. Do not "confirm" by reading more.

All requests and responses in this note are **illustrative**: hosts are fictional (`app.example.com`, `api.example.com`, `admin.example.com`) and output is shortened.

### GT-WEB-SSTI-1: Inventory template sinks and user-controlled template content

*Guler Tech methodology.* Implements the "detect template injection vulnerability points" objective of WSTG-INJT-18 and the injection-point identification of WSTG-INJT-11 and WSTG-INJT-08, using WSTG-INFO-06 (entry points) and WSTG-INJT-14 (incubated vulnerabilities) for the second-order paths.

#### What it checks

Where user-controlled text could become template source, expression source or SSI input, and where it is rendered. The output is the work list for tests 2 to 10.

#### Prerequisites

Accounts per role; a full Burp Logger walk-through; a mailbox and phone number you control; product documentation for any template or "variables" features.

#### Steps

1. Walk every feature with Logger on. Mark every parameter whose value comes back in a response, an email, a PDF, a notification or an export.
2. List features where users *write* templates or rich text: email and notification editors, invoice and PDF layouts, CMS pages and themes, wiki pages, macros, "custom message", "signature", "auto-reply", report builders, formula or rule fields, webhook payload templates.
3. For each, note who can use it (role, tenant admin, any user), where it is rendered (web page, email, PDF, SMS, third-party message), and what variables the product documents ("you can use the customer's first name and order number").
4. Fingerprint the stack: framework headers and cookies, error pages, file extensions (`.ftl`, `.vm`, `.twig`, `.shtml` in URLs or errors), JavaScript bundles mentioning template engines, the product and version of off-the-shelf software (Confluence, Struts, Spring Cloud components, CMSs).
5. Mark Java expression surfaces: parameters named `filter`, `sort`, `expression`, `condition`, `rule`, `routing`, `formula`; validation errors that echo input; Struts `.action` URLs.
6. Note anything that selects a template by name: `?lang=`, `?theme=`, `?layout=`, `?section=`, `?view=`, `?page=`.
7. Note logging sinks for lookup strings: headers and fields that a Java back end is likely to log (User-Agent, `X-Forwarded-For`, usernames on login failure).

#### Observation

A table like this (illustrative):

| Input | Where it is rendered | Who controls it | Engine guess | Tests |
|---|---|---|---|---|
| `GET /search?q=` | Results page heading | Anyone | Jinja2 (Flask cookie) | 2, 4, 11 |
| Profile display name | Web profile, "account updated" email | Any user | Unknown, email service | 5 |
| Tenant email template editor | Order emails to customers | Tenant admin | Twig (error page) | 5, 6 |
| `GET /doc?section=` | Selects a page | Anyone | Thymeleaf (Spring Boot) | 7 |
| Price rule field | Evaluated at checkout | Merchant | Node.js service | 8 |
| `GET /help/*.shtml` | Static help pages | Comment form writes into page | Apache SSI | 9 |

#### Evaluation

No finding by itself. A template editor available to roles that should not run code is worth noting as a design risk even before you test it, because it determines the severity of anything you find.

#### False positives

Placeholders that are clearly replaced by a fixed lookup (`[[first_name]]` with a documented list of variables) are not templates in the engine sense; test them anyway in test 2, but expect them to be safe.

#### Automation

Crawl output and Logger export filtered for reflected parameter values; Param Miner to find unlinked parameters such as `template`, `view` or `lang`. In CI, keep a list of every place the code calls a "render from string" API (see [GT-WEB-SSTI-12](#gt-web-ssti-12-source-review-for-template-expression-and-eval-sinks)) and require a security review when it grows.

### GT-WEB-SSTI-2: Plaintext-context detection with a fuzz string and arithmetic

*Guler Tech methodology.* Implements the plaintext-context detection in WSTG-INJT-18.

#### What it checks

Whether text you submit is parsed as template source, using a fuzz string to trigger errors and arithmetic in each common syntax family to trigger evaluation.

#### Prerequisites

The input list from test 1; a baseline response for each input with a harmless value (`gt-ssti-baseline`).

#### Steps

1. Send the baseline value and save the response.
2. Send the fuzz string from PortSwigger's methodology, which combines the opening and closing characters of many template syntaxes. An exception, a 500, or output where part of the string has disappeared, where plain text would have been reflected verbatim, suggests interpretation:

   {% raw %}
   ```text
   ${{<%[%'"}}%\
   ```
   {% endraw %}

3. Whether or not the fuzz string errors, send arithmetic in each syntax family, one per request:

   {% raw %}
   ```text
   {{1234*5678}}
   ${1234*5678}
   <%= 1234*5678 %>
   #{1234*5678}
   {1234*5678}
   @(1234*5678)
   [[${1234*5678}]]
   #set($x=1234*5678)$x
   <#assign x=1234*5678>${x}
   ```
   {% endraw %}

   The last two are directive forms for Velocity and FreeMarker, which WSTG-INJT-18 points out are not reached by expression probes alone; the assignment is followed by an interpolation so that the value is printed.
4. Look for `7006652` in the response, including in places other than where the input normally appears (title, error box, hidden fields, JSON).
5. Repeat any hit twice, with a different product (`4321*8765 = 37873565`) to rule out coincidence and caching.

Raw request and the two possible responses (the `q` value is the double-curly probe, URL-encoded):

```http
GET /search?q=%7B%7B1234*5678%7D%7D HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
```

Evaluated (vulnerable):

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<h1>Results for 7006652</h1>
```

Treated as data (correct):

{% raw %}
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<h1>Results for {{1234*5678}}</h1>
```
{% endraw %}

The curl equivalent:

{% raw %}
```bash
curl -sG 'https://app.example.com/search' \
  --data-urlencode 'q={{1234*5678}}' \
  -H 'Cookie: session=<SESSION_USER_A>' | grep -o '7006652'
```
{% endraw %}

#### Observation

Which probe evaluated, where the result appeared, and any error text (save it; it is the best input for test 4).

#### Evaluation

**Fail (finding):** an arithmetic probe returns the product, reproducibly, from the server's response (confirm with test 11 that it is not client-side). **Lead, not yet a finding:** the fuzz string causes an error but no arithmetic evaluates; try test 3 (code context) and test 4 (an engine that does not do arithmetic). **Pass:** every probe is reflected literally or encoded, and no error differs from the baseline.

#### False positives

The application does its own maths (a quantity or calculator field); client-side frameworks evaluating the expression in the browser; the probe stripped by an input filter so that the remaining digits look like a result (check the full output, not just a grep). See [GT-WEB-SSTI-11](#gt-web-ssti-11-rule-out-client-side-rendering-and-application-side-maths).

#### Automation

A short Intruder list of the nine probes above with a grep-match on `7006652`, throttled. **TInjA** and **SSTImap** automate polyglot detection across many engines; run them per parameter, through Burp, with a delay, and read what they send (see test 4 for the constraints). In CI, see [regression tests](#regression-tests).

### GT-WEB-SSTI-3: Code-context detection

*Guler Tech methodology.* Implements the code-context detection in WSTG-INJT-18.

#### What it checks

Whether your input is placed *inside* an existing template expression, for example as a variable name or an argument, so that delimiter-based probes do nothing but an expression without delimiters is evaluated.

#### Prerequisites

A parameter whose value looks like an identifier or path (`greeting=username`, `field=user.name`, `sort=price`, `format=short`), or that changes output in a way that suggests a lookup.

#### Steps

1. Baseline: `greeting=username` renders `Hello user01`.
2. Send an expression that is valid without delimiters: `greeting=1234*5678`. If it is inside an expression, it renders `Hello 7006652`.
3. Send an HTML tag after the value: `greeting=username<tag>`. In code context this usually gives a blank value or an error rather than a reflected tag.
4. Try to close the expression and add text, for each delimiter family, for example (the first is the WSTG and PortSwigger example for double-curly engines):

   {% raw %}
   ```text
   greeting=username}}<tag>
   greeting=username}<tag>
   greeting=username%><tag>
   ```
   {% endraw %}

   Output of `Hello user01<tag>` means you closed the expression and the rest is being parsed as template text, which brings you back to test 2 for engine identification.

#### Observation

Which variant rendered the product or the injected tag after the expected value.

#### Evaluation

**Fail:** a delimiter-free arithmetic expression evaluates, or a close-delimiter plus text renders the text after the expected value. **Pass:** the value is treated as an opaque key: unknown keys give a consistent "not found" or empty result and nothing you send is evaluated.

#### False positives

Lookups against an allow-list where `1234*5678` simply returns empty and the close-delimiter variants from step 4 also return empty: no evaluation. Sort and filter parameters that a database interprets (`sort=price desc`) are SQL or NoSQL questions, covered in [SQL injection](/web/web-sql-injection/) and [NoSQL injection](/web/web-nosql-injection/).

#### Automation

SSTImap and TInjA try some code-context escapes. In CI, unit-test the function that maps the parameter to an expression with values containing operators and delimiters, and assert they are rejected.

### GT-WEB-SSTI-4: Identify the template engine

*Guler Tech methodology.* Implements the "identify the templating engine" step of WSTG-INJT-18, following Kettle's decision-tree approach.

#### What it checks

Which engine, and if possible which version, is evaluating your input. Identification decides the severity (sandboxed or not, known escapes) and the fix.

#### Prerequisites

A confirmed or suspected evaluation point from test 2, 3 or 5.

#### Steps

1. **Read the error first.** Invalid syntax often names the engine and sometimes the version. Typical strings: ERB errors mentioning `(erb)` and `NameError`, `jinja2.exceptions.TemplateSyntaxError`, `Twig\Error\SyntaxError`, `freemarker.core.ParseException`, `org.apache.velocity` exceptions, `org.thymeleaf.exceptions`, `Liquid::SyntaxError`, Handlebars "Parse error on line 1", Django's "Could not parse the remainder", EJS and Pug stack traces naming the template file.
2. **Then use discriminating probes.** Send them one at a time; the IDs are used in the table below.

   {% raw %}
   ```text
   P1   ${1234*5678}
   P2   {{1234*5678}}
   P3   {{7*'7'}}
   P4   a{*gt*}b
   P5   ${"z".join("ab")}
   P6   <%= 1234*5678 %>
   P7   #{1234*5678}
   P8   #set($x=1234*5678)$x
   P9   <#assign x=1234*5678>${x}
   P10  [[${1234*5678}]]
   P11  {{len "abcdefg"}}
   P12  {{this}}
   P13  @(1234*5678)
   P14  <%= typeof process %>
   P15  {{ 'gt'|upper }}
   ```
   {% endraw %}

3. Walk the table below and record the engine, the version if visible, and the exact probe that proved it. Do not stop at the first hit: as PortSwigger points out, the same payload can succeed in more than one engine (P3 returns `49` in Twig and `7777777` in Jinja2).

| Step | Probe | Response shows | Suggests | Next |
|---|---|---|---|---|
| 1 | P1 | `7006652` (possibly with a leading `$`) | A dollar-brace engine: FreeMarker, Mako, Smarty, Thymeleaf or other Java EL contexts | P4 |
| 2 | P4 | `ab` (the comment vanished) | Smarty | Check version and `\Smarty\Security` use (test 6) |
| 3 | P5 | `azb` | Mako (Python) | Test 6 |
| 4 | P9 | `7006652` | FreeMarker | Test 6 |
| 5 | P10 | `7006652` | Thymeleaf inline expression (SpEL in Spring, OGNL otherwise) | Test 7 |
| 6 | P2 | `7006652` | Jinja2, Twig, Nunjucks, Tornado, Blade | P3 |
| 7 | P3 | `7777777` | Python string repetition: Jinja2 or Tornado | P15 (`GT` points to Jinja2, an error to Tornado) |
| 8 | P3 | `49` | PHP or JavaScript coercion: Twig, Nunjucks or Blade | P15 (`GT` points to Twig or Nunjucks, a PHP error to Blade), then the stack |
| 9 | P2 | Error "Could not parse the remainder" | Django templates | Test 6 (context exposure) |
| 10 | P2 | Empty output | Logic-less engine (Mustache, Handlebars) or Liquid | P12, P11 |
| 11 | P12 | `[object Object]` | Handlebars or another JavaScript engine | Check Handlebars version (test 6) |
| 12 | P11 | `7` | Go `text/template` or `html/template` | Test 6 (methods on the data) |
| 13 | P6 | `7006652` | ERB (Ruby) or EJS (JavaScript) | P14 (`object` points to EJS) |
| 14 | P7 | `7006652` | Pug, Ruby string interpolation (Slim, Haml), Java EL deferred syntax or SpEL template context | Stack fingerprint, test 7 for Java |
| 15 | P8 | `7006652` | Velocity | Check `SecureUberspector` (test 6) |
| 16 | P13 | `7006652` | Razor compiled at runtime | Test 6 |


#### Observation

The engine name with the probe and response that show it, for example: "P2 returned `7006652`; P3 returned `7777777`; P15 returned `GT`; error text on invalid syntax names `jinja2.exceptions.TemplateSyntaxError`."

#### Evaluation

This test classifies a finding from tests 2, 3 or 5; it is not a separate finding. If identification fails but evaluation is proven, report it as SSTI in an unidentified engine and rate on the demonstrated behaviour.

#### False positives

Engines are forked and embedded; a JavaScript engine that coerces like Twig, or a Python wrapper that behaves like Jinja2, can mislead one probe. Use at least two independent signals (error text plus a discriminator).

#### Automation

**SSTImap** (an actively maintained fork of the no-longer-maintained **tplmap**) and **TInjA** identify engines automatically. Run them through Burp (`-p` or `--proxyurl`), against one parameter, with a delay (`--delay`, `--ratelimit`), and in detection mode only. SSTImap's capability check reports whether code evaluation and shell execution work, and its options for OS shells, command execution, file upload and download, and bind or reverse shells must not be used on client systems; check what its detection phase sends in Logger before running it outside a lab. Hackmanit's **Template Injection Table** lists polyglots and how each engine responds, which is a good manual reference.

### GT-WEB-SSTI-5: Stored and second-order template rendering

*Guler Tech methodology.* Implements WSTG-INJT-18 detection for stored input, using the incubated-testing approach of WSTG-INJT-14.

#### What it checks

Whether input that is stored safely is later concatenated into a template by another component: email, PDF, SMS, push notification, export, chat or webhook message, or a tenant-editable template feature.

#### Prerequisites

The second-order paths from test 1; a mailbox and phone number you control; your own tenant and a template you created (or a preview / "send test" function) for template editors; a Collaborator payload for each path where output is not visible to you.

#### Steps

1. Set a stored field you own (display name, company name, address line, order note, ticket subject) to an arithmetic probe with a marker, one syntax family at a time, for example `gt5a-` followed by the double-curly product probe, or `gt5b-` followed by the dollar-brace probe.
2. Trigger every rendering path for that field: change a setting to get an "account updated" email, place a test order to get an invoice PDF, open a support ticket, export your data.
3. Check each output for `7006652` next to the marker. In emails, check both the HTML and plain-text parts, and the subject line.
4. For template editors: in a draft or test template you own, put the probe in the template body, use the product's preview or "send test email to me", and read the result. If the editor documents variables, also try a documented variable (it should render) and an undocumented one such as `self` or `this` in the engine's syntax (it should render as empty or an error). Do not save probes into live templates that real customers receive.
5. Where nothing comes back to you (a PDF generated for a back-office user, a message to a third-party system), and only if arithmetic is impossible to observe, use a bounded time delay on the rendering request or an out-of-band DNS interaction from a template expression, and only where approved for that path. Many engines need code-level access to make a DNS request; if reaching your collaborator requires calling OS or network functions, that is beyond the detection ceiling and needs explicit approval.
6. Restore every field and template you changed.

#### Observation

The rendering path, the probe, and the output (for example: "Display name `gt5a-` plus the double-curly probe; account-update email body shows `gt5a-7006652`; the web profile page shows the literal probe").

#### Evaluation

**Fail:** any rendering path evaluates the probe. Severity depends on who can set the field (any user versus tenant admin), the engine (test 4) and whether the output reaches other people. **Pass:** every path shows the literal text, correctly escaped for its medium.

#### False positives

An email service that supports its own merge tags on purpose (for example a marketing platform's personalisation syntax) evaluating only its documented tags: that is a feature, not SSTI, unless arbitrary expressions evaluate. A PDF generator that renders HTML (and JavaScript) in a headless browser executes your HTML, which is a different bug class (HTML injection into PDF, sometimes leading to SSRF or local file reads) and belongs to the Server-Side Request and Files subcategory.

#### Automation

Hard to automate black-box because the output arrives asynchronously. In CI, render every email and PDF template in tests with fixture values containing probes and assert the output contains the literal probe, not `7006652` (see [regression tests](#regression-tests)).

### GT-WEB-SSTI-6: Assess sandbox and context exposure without exploiting

*Guler Tech methodology.* Implements the impact-assessment part of WSTG-INJT-18 ("build the exploit") as a documentation-and-configuration review rather than an exploitation step, and ASVS `v5.0.0-1.3.5` (sanitise or disable user-supplied scriptable or expression template content).

#### What it checks

How bad a confirmed SSTI is: which engine and version, whether a sandbox or restricted mode is used, what objects are in the context, and whether known escapes apply. The goal is an accurate severity without running code on the server.

#### Prerequisites

A confirmed evaluation point and engine from tests 2 to 5. Grey-box access (source or configuration) makes this test far more reliable; ask for it.

#### Steps

1. **Engine and version.** From error pages, dependency manifests (grey-box), response headers or the product version. Compare against the advisories for that engine (Jinja2 sandbox escapes CVE-2016-10745, CVE-2019-10906, CVE-2024-56326, CVE-2025-27516; Handlebars CVE-2019-19919; Twig's sandbox advisories; EJS CVE-2022-29078; Thymeleaf CVE-2023-38286).
2. **Sandbox in use?** Grey-box: look for `SandboxedEnvironment` or `ImmutableSandboxedEnvironment` (Jinja2), `Twig\Sandbox\Sandbox` or `SandboxExtension` with a strict `SecurityPolicy` (Twig), `enableSecurity()` with a `\Smarty\Security` policy (Smarty), `setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER)` and a restrictive member-access policy (FreeMarker), `SecureUberspector` (Velocity), `SimpleEvaluationContext` (SpEL). Black-box: the engine's documented "safe mode" behaviour may be observable as specific security errors (Twig and Jinja2 both raise named security errors when a sandbox blocks something).
3. **Context exposure.** Ask, or read in code, what the template receives. Scalars and plain dictionaries are low risk; ORM models, request objects, settings or service objects are not. Black-box, the product's documented variables are the minimum; do **not** dump the whole context (Django's debug tag, iterating `_context` in Twig, `self` introspection in Jinja2) on a client system unless approved, because the output routinely contains secrets.
4. **Resource limits.** Is there a timeout, an output-size limit or a separate worker for rendering user templates? Grey-box only; do not test this with expensive templates.
5. **Write the impact in prose with references.** For an unsandboxed engine where the documentation and public research show a path from template expressions to the host language (Kettle's paper and the PortSwigger exploitation page cover FreeMarker, Velocity, Smarty, Twig, Jade/Pug and others; the PayloadsAllTheThings and HackTricks SSTI pages collect engine-specific material), state that code execution is the expected impact and cite the research. Only demonstrate it with explicit approval, and then with `id` or `hostname`.

#### Observation

A short impact statement, for example: "Jinja2 3.1.4, default `Environment` (not sandboxed), context includes the Flask `request` and `config` objects. Unsandboxed Jinja2 gives template authors access to Python objects; public research documents code execution from this position. Not demonstrated, per rules of engagement."

#### Evaluation

This test sets severity for the finding from tests 2 to 5 (see [Rating findings](#rating-findings)). A sandboxed engine on a version with a known escape is rated as unsandboxed. A sandbox with rich objects in the context is rated on what those objects expose.

#### False positives

A sandbox error on a probe proves the sandbox is on, not that it is sufficient; a missing error does not prove the sandbox is off (some engines silently render undefined values as empty).

#### Automation

Dependency scanning (OSV, GitHub Dependabot, Snyk or similar) for the engine versions; a Semgrep or CodeQL rule that flags non-sandboxed environments used with user-supplied templates ([static analysis](#static-analysis)).

### GT-WEB-SSTI-7: Expression-language injection in Java applications

*Guler Tech methodology.* Implements WSTG-INJT-11 for Java expression languages and the view-name variant of WSTG-INJT-18; checks ASVS `v5.0.0-1.3.2`.

#### What it checks

Whether user input is evaluated by SpEL, OGNL, Jakarta EL or a similar expression language, including through Thymeleaf view names and Bean Validation messages.

#### Prerequisites

A Java stack (Spring, Struts, JSF, Jakarta EE, Confluence or another Java product); the Java expression surfaces from test 1.

#### Steps

1. **Product versions first.** If the fingerprint shows Struts, Confluence, Spring Cloud Function, Spring Cloud Gateway or another product with a published expression-injection CVE, check the version against the advisory. A vulnerable version in scope is reported from the version evidence and the vendor advisory; do not fire public exploits at it. If the client wants live confirmation, agree it in writing and use a vendor- or researcher-published *detection* check that stops at arithmetic or an out-of-band DNS lookup.
2. **Arithmetic in each EL syntax.** Send, one per request, in the parameters you marked: the dollar-brace and hash-brace forms (`${1234*5678}`, `#{1234*5678}`), the Struts forced-evaluation form (`%{1234*5678}`), and a bare `1234*5678` for parameters that look like whole expressions (`filter`, `condition`, `sort`).
3. **View-name selection.** For parameters that select a page (`lang`, `section`, `view`), send a value wrapped in Thymeleaf preprocessing (two underscores either side of the dollar-brace arithmetic, followed by `::.x` as in the Veracode research). A 500 error mentioning a template or fragment named `7006652` shows evaluation. Repeat for path segments of handlers that do not appear to use the value (a `void` controller method takes its view name from the path).
4. **Validation messages.** Submit the dollar-brace arithmetic into fields that produce validation errors echoing your input. An error message containing `7006652` means the message template contains your input and EL interpolation is on.
5. **Spring error pages and OAuth flows.** For old Spring Security OAuth (CVE-2016-4977), the `response_type` parameter in the authorisation endpoint's whitelabel views; check the version instead of probing where possible.

```http
GET /doc?section=__%24%7B1234*5678%7D__%3A%3A.x HTTP/1.1
Host: app.example.com
```

Vulnerable (illustrative, shortened):

```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{"status":500,"error":"Internal Server Error","message":"Error resolving template [user/7006652], template might not exist or might not be accessible by any of the configured Template Resolvers"}
```

Correct: `404 Not Found` (unknown section, allow-list rejected it) with no template name in the body.

Recent Spring Boot versions do not include exception messages in error responses by default, so you may only see a status difference. Compare three requests: a valid section (200), an invalid plain value such as `nosuchsection` (the application's normal error), and the expression (a different error, typically 500). A difference between the last two is a lead to confirm with a second product, not proof on its own.

#### Observation

The syntax that evaluated, where, and the response (status, error text with the product).

#### Evaluation

**Fail:** any EL syntax evaluates user input, or a product version with a published expression-injection CVE is in scope and unpatched. **Pass:** probes are reflected literally or rejected; view names come from an allow-list; product versions are patched.

#### False positives

Some error pages echo your raw input inside a message without evaluating it (`Invalid value '${1234*5678}'`); look for the product, not the expression. `400` errors from a strict parameter parser are not evidence of evaluation.

#### Automation

Burp Scanner has expression-language injection checks; product-version checks belong in your vulnerability scanning. In code: CodeQL `java/spel-expression-injection`, `java/ognl-injection`, `java/server-side-template-injection`, `java/mvel-expression-injection`, `java/jexl-expression-injection`; Semgrep `java.spring.security.audit.spel-injection.spel-injection`, `java.lang.security.audit.el-injection.el-injection`, `java.lang.security.audit.ognl-injection.ognl-injection`.

### GT-WEB-SSTI-8: eval-style code injection in Node.js, Python, PHP and Ruby

*Guler Tech methodology.* Implements WSTG-INJT-11 (excluding file inclusion, `WSTG-INJT-11.1`); checks ASVS `v5.0.0-1.3.2`.

#### What it checks

Whether input reaches `eval` or an equivalent in the application language: Node.js `eval`, `new Function`, `vm.runIn*Context`; Python `eval`, `exec`; PHP `eval`, string `assert()` before PHP 8.0, dynamic callables; Ruby `eval`, `instance_eval`, `send`.

#### Prerequisites

Inputs that accept expressions, rules, formulas or names of functions (test 1).

#### Steps

1. **Arithmetic and string operations without delimiters.** `1234*5678` in a field that should be a number or a plain string. If the field is a "formula" by design, the application doing maths is expected; move to step 2.
2. **Language discriminators that are harmless.** String concatenation and methods that only exist in one language, one per request:

   ```text
   "gt"+"probe"            JavaScript or Python: gtprobe; Ruby: gtprobe; PHP: 0 or a TypeError
   "gt"."probe"            PHP: gtprobe
   "gt".upper()            Python: GT
   "gt".upcase             Ruby: GT
   "gt".toUpperCase()      JavaScript: GT
   ```

   In a formula field that legitimately accepts `price * 0.9`, a string method returning `GT` shows the formula is evaluated by the host language, not by a restricted parser.
3. **Syntax errors.** A lone quote or an unbalanced bracket (`'`, `1+`, `)`). Stack traces naming `SyntaxError` with `eval` or `Function` (Node.js), `SyntaxError` in `<string>` (Python), `ParseError` in `eval()'d code` (PHP), `SyntaxError` with `(eval)` (Ruby) identify the sink.
4. **Bounded time delay, only when nothing is reflected.** Python `__import__('time').sleep(3)`, PHP `sleep(3)`, Ruby `sleep(3)`; three repetitions against a baseline, then a zero-second control. For Node.js, avoid time delays: synchronous waits block the event loop for every user of that process. Use the syntax-error and arithmetic signals instead.
5. **Function-name parameters.** For parameters that name a function or method (`action=`, `callback=`, `format=`, `f=`), send a name that exists in the language but not in the app's list (PHP `phpversion`, Ruby `class`). A response that changes to the language's answer (a PHP version string, `String`) shows dynamic dispatch on user input.

#### Observation

The signal (arithmetic, discriminator, error text, timing table with three runs and a control), and the sink if the error names it.

#### Evaluation

**Fail:** user input is evaluated by the host language. This is code execution in the application process; rate it as such without demonstrating further. **Pass:** expression fields are parsed by a restricted grammar (arithmetic on numbers and named variables only; strings and method calls rejected), and function-name parameters are mapped through an allow-list.

#### False positives

Formula features built on a safe expression library that supports string functions by design (spreadsheet-like `UPPER("gt")`); the test is whether you can reach the *host language*, not whether a formula language has functions. Timing differences caused by input length or validation cost: always run the zero-second control.

#### Automation

SSTImap includes `eval`-like injection plugins for several languages; the constraints from test 4 apply. In code: CodeQL `js/code-injection`, `py/code-injection`, `rb/code-injection`, `cs/code-injection`; Semgrep `javascript.lang.security.audit.code-string-concat.code-string-concat`, `python.lang.security.audit.eval-detected.eval-detected`, `python.django.security.injection.code.user-eval.user-eval`, `php.lang.security.eval-use.eval-use`, `ruby.lang.security.no-eval.ruby-eval`.

### GT-WEB-SSTI-9: Server-side include injection

*Guler Tech methodology.* Implements WSTG-INJT-08.

#### What it checks

Whether input reaches a response or file that the web server parses for SSI directives, and which directives are enabled.

#### Prerequisites

Signs of SSI from test 1 (`.shtml`, `.shtm`, `.stm` pages, Apache or IIS on a legacy site, an nginx reverse proxy in front of an application) and the inputs that are written into those pages.

#### Steps

1. Check that the characters SSI needs survive: `<`, `!`, `#`, `=`, `/`, `.`, `"`, `-`, `>` (WSTG-INJT-08 lists the same set). If the application encodes `<` in that output, SSI injection there is not possible.
2. Send an `echo` directive for a harmless server variable, in the input that lands in the page (stored comment, profile field, or a header such as `Referer` or `User-Agent` if the page displays it):

   ```text
   <!--#echo var="DATE_LOCAL" -->
   ```

   On nginx the SSI module's embedded variable is lower case: `<!--#echo var="date_local" -->`.
3. View the page. A date where your directive was, and no visible comment in the HTML source, means SSI processed it. The literal comment in the page source means it was not processed.
4. Do not test `#exec`. If `echo` works, the next question (is `#exec` enabled?) is answered from configuration: ask for the Apache `Options` directive for that location (`Includes` versus `IncludesNOEXEC`) or the nginx configuration. If the client explicitly approves a live check, `<!--#exec cmd="hostname" -->` is the ceiling.
5. Do not use `#include` to read files. Its presence is implied by working SSI; report it with the configuration evidence.

```http
POST /guestbook/sign HTTP/1.1
Host: app.example.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=<SESSION_USER_A>

name=gt9&message=%3C%21--%23echo+var%3D%22DATE_LOCAL%22+--%3E
```

Processed (vulnerable), in the guestbook page:

```text
gt9 wrote: Saturday, 14-Nov-2026 10:42:07 GMT
```

Not processed (correct): the message appears HTML-encoded, or the comment is visible in the page source unchanged.

#### Observation

The directive, where it was planted, the rendered output, and the configuration evidence for `exec`.

#### Evaluation

**Fail:** SSI directives from user input are processed. High or Critical with `exec` enabled; Medium where only `echo` and `include` work (see [rating](#rating-findings)). **Pass:** input is HTML-encoded before it is written into SSI-parsed output, or SSI is off for content that contains user input.

#### False positives

A date that comes from the application's own template next to your message; a CDN or edge layer processing Edge Side Includes (ESI) rather than SSI is a related but separate issue that belongs to the HTTP and Infrastructure subcategory.

#### Automation

Grey-box: search server configuration for `Options +Includes`, `AddOutputFilter INCLUDES`, `XBitHack` and nginx `ssi on`. In CI, assert that templates writing user input into `.shtml` output encode `<`.

### GT-WEB-SSTI-10: JNDI and lookup-string injection with out-of-band detection

*Guler Tech methodology.* Implements the expression-language part of WSTG-INJT-11 for logging and naming lookups; checks ASVS `v5.0.0-1.3.8`.

#### What it checks

Whether a Java component expands lookup syntax in user-controlled strings and makes an outbound JNDI request, the Log4Shell (CVE-2021-44228) pattern, or passes user input to `InitialContext.lookup`.

#### Prerequisites

A Java stack or Java-based products in scope; written agreement from the client for out-of-band testing (the payload persists in logs and may be processed later by other systems, such as a SIEM or log pipeline, which may belong to a third party); a Collaborator or self-hosted interactsh domain.

#### Steps

1. Agree the list of fields and headers, and tell the client's security team the time window and your collaborator domain, so alerts from their monitoring are expected.
2. Place one lookup string per field, each with a unique subdomain so a hit identifies the field:

   ```text
   ${jndi:ldap://ua-gt10.<your-collaborator-domain>/a}
   ```

   Typical places: `User-Agent`, `X-Forwarded-For`, `Referer`, the username on a failed login, search terms, form fields that are logged.
3. Watch the collaborator for DNS lookups. A DNS query for `ua-gt10.<domain>` from the client's infrastructure shows the string was expanded. Your collaborator does not answer LDAP with anything the target could load, so nothing further happens; do not run an LDAP server that returns references or serialised objects.
4. Allow for delay: lookups may happen hours later when logs are processed. Keep the collaborator session and check again before reporting.

#### Observation

The DNS interaction with timestamp, source resolver or IP, and the subdomain that identifies the field.

#### Evaluation

**Fail:** a lookup from target infrastructure arrives for your unique subdomain. Identify, with the client, which system made it (the web tier, a log processor); that system is where the vulnerable library lives. **Pass:** no interaction across the agreed window, and (grey-box) Log4j versions are current and application code does not pass user input to JNDI lookups.

#### False positives

DNS lookups from security products that pre-fetch domains they see in traffic (email and web gateways, URL scanners) rather than from the application: check the source and whether the lookup was DNS-only from a known scanner range. The subdomain-per-field approach and the timing help separate them.

#### Automation

Burp Scanner and other scanners include Log4Shell checks using out-of-band interactions; software composition analysis finds vulnerable Log4j versions faster and more reliably than black-box probing. In code, search for `InitialContext().lookup(` and `JndiTemplate` with non-constant arguments.

### GT-WEB-SSTI-11: Rule out client-side rendering and application-side maths

*Guler Tech methodology.* Supports WSTG-INJT-18 confirmation and separates it from client-side template injection (WSTG-CLNT-15).

#### What it checks

That an arithmetic hit from tests 2, 3, 5 or 7 is evaluated on the **server** by a template or expression engine, not in the browser by a client-side framework, and not by a legitimate calculation in the application.

#### Prerequisites

A hit from an earlier test.

#### Steps

1. **Look at the raw HTTP response in Burp, not the browser.** If the raw response body contains the literal probe and the browser shows `7006652`, the evaluation is client-side (AngularJS, Vue compiled in the browser, or similar). Record it as a client-side template injection lead for the Client-Side tests and stop treating it as SSTI.
2. **Check the response for the product.** If the raw response already contains `7006652`, the server produced it.
3. **Rule out legitimate maths.** Does the field accept calculations by design (quantity "2*3", a calculator, a spreadsheet-like cell)? Send the arithmetic *without* any template delimiters, and with delimiters of an unrelated engine: if all of them evaluate the same way, the application is doing its own maths. Then try a discriminator from test 4 or 8; a legitimate calculator rejects string operations such as the string-times-number probe P3.
4. **Rule out caching and coincidence.** Change the numbers (`4321*8765` is `37873565`) and add a cache-buster parameter. If the old product comes back, you are looking at a cached page or a value that was already there.
5. **Rule out server-side rendering of a client framework.** Some server-side renderers (Angular Universal, Vue or Nuxt SSR, Next.js) run the client framework on the server. Arithmetic evaluated during server-side rendering of a client template is still a template injection on the server, and its impact depends on what that renderer exposes; note the framework and assess it like any other engine in test 6.

#### Observation

Raw response excerpt with and without the product; the cache-buster check; the discriminator result.

#### Evaluation

**Server-side SSTI confirmed:** the raw response contains the product of a fresh calculation, the field is not a calculator by design, and an engine discriminator behaves as an engine would. **Client-side (CSTI):** the raw response contains the literal probe; report as XSS in the Client-Side work. **Not a vulnerability:** documented calculator behaviour without access to strings or host-language features.

#### False positives

This test exists to remove them; the residual risk is a server-side renderer that you mistake for a pure client-side framework (step 5).

#### Automation

Tools that drive a headless browser (TInjA's CSTI mode) report client-side evaluation separately; make sure your report distinguishes the two.

### GT-WEB-SSTI-12: Source review for template, expression and eval sinks

*Guler Tech methodology.* Grey-box companion to WSTG-INJT-18, WSTG-INJT-11 and WSTG-INJT-08; checks ASVS `v5.0.0-1.3.7`, `v5.0.0-1.3.2`, `v5.0.0-1.3.5` and `v5.0.0-1.3.8`.

#### What it checks

Every place in the code base that compiles a template from a string, evaluates an expression or code string, chooses a view from input, performs a JNDI lookup or emits SSI; and, for each, whether the string can contain user input.

#### Prerequisites

Read access to the source (or a build artefact) and configuration.

#### Steps

1. Search for the sinks. A starting list (adapt to the stack):

   ```bash
   # Python
   grep -rnE 'render_template_string|from_string\(|Template\(|Environment\(|eval\(|exec\(' --include='*.py' .
   # Node.js
   grep -rnE 'ejs\.render\(|pug\.(render|compile)\(|Handlebars\.compile\(|nunjucks\.renderString\(|new Function\(|eval\(|vm\.run' --include='*.js' --include='*.ts' .
   # Java
   grep -rnE 'parseExpression\(|StandardEvaluationContext|new Template\(|Velocity\.evaluate|buildConstraintViolationWithTemplate|InitialContext\(\)\.lookup|OgnlUtil|ValueStack' --include='*.java' .
   # PHP
   grep -rnE 'Blade::render|Blade::compileString|createTemplate\(|template_from_string|eval\(|assert\(|call_user_func|->fetch\(.string:' --include='*.php' .
   # Ruby
   grep -rnE 'ERB\.new|Liquid::Template\.parse|instance_eval|class_eval|eval\(|\.send\(params' --include='*.rb' .
   ```

2. For each hit, trace the string argument back to its sources. Concatenation, f-strings, template literals or `String.format` with request data, database fields that users write, or tenant configuration are findings or design risks.
3. Check controllers that return view names built from input (Spring `return "x/" + param`), `void` handlers in Spring MVC with Thymeleaf, and Express handlers that pass `req.query` or `req.body` as the render options (`res.render(view, req.query)`), which the EJS security policy explicitly calls out.
4. For user-template features, confirm the sandbox class and policy used, the objects in the context, the engine version, and the rendering time and size limits.
5. Check web server configuration for SSI (`Includes` versus `IncludesNOEXEC`, `ssi on`), and Log4j versions in every Java artefact including vendored ones.

#### Observation

A list of sinks with source, reachability and status (safe: constant template; risk: user-writable template with sandbox; finding: request data in template source).

#### Evaluation

**Fail:** any path where request data or user-written content reaches template, expression or code source without a sandbox and strict allow-list. **Pass:** templates are constants or files; user content only ever arrives as context values; user-template features use a sandbox or logic-less engine with scalar-only context and resource limits.

#### False positives

`Template(` and `eval(` match many unrelated APIs (database query builders, test helpers, client-side code in the same repository). Confirm the import and the runtime.

#### Automation

Run the CodeQL and Semgrep rules listed in [static analysis](#static-analysis) in CI and fail the build on new results in production code.

## Secure implementation

### Design rules

1. **Templates are code; user input is data.** Load templates from files (or constants) that go through code review, and pass user input only as context values. This one rule removes almost every SSTI and is what `v5.0.0-1.3.7` asks for.
2. **Never compile a string that contains user input.** No `render_template_string(prefix + input)`, no `Blade::render($userText)`, no `ejs.render(userText)`, no `parseExpression(request.getParameter(...))`, no `eval`. Code review should treat every "render from string" or "evaluate string" call as a security-sensitive sink.
3. **If users must write templates, give them a smaller language.** In order of preference: fixed placeholders replaced by your own code from an allow-list (`[[first_name]]`); a logic-less engine (Mustache) or one designed for untrusted authors (Liquid); a sandboxed environment of a full engine (Jinja2 `SandboxedEnvironment`, Twig `Sandbox`), with a strict policy and kept up to date.
4. **Keep the context boring.** Pass scalars and plain dictionaries built for the template (`{"first_name": "Alex", "order_number": "A-1001"}`), not ORM models, request objects, settings or services. The sandbox does not protect what you hand it.
5. **Limit resources and isolate.** Render user templates with a time limit and output-size limit, in a worker process or container with no secrets and minimal network access, as both ASVS `v5.0.0-15.2.5` (L3, extra protection around dangerous functionality) and PortSwigger's prevention advice suggest. Assume a sandbox escape will be found one day and decide what it should reach.
6. **Do not use language-level "sandboxes" for untrusted code.** Node's documentation says `node:vm` "is not a security mechanism"; vm2's maintainer discontinued it, stating it contains critical security issues. If running customer code is the product, use process- or VM-level isolation designed for it.
7. **Replace `eval` with a parser.** Data formats have parsers (`JSON.parse`, `json.loads`, `ast.literal_eval` for Python literals). Formula features need a small grammar over numbers and named variables, not the host language.
8. **Allow-list names.** View names, template names, callbacks and method names chosen from input go through a fixed map.

### Python: Flask, Jinja2 and Django

Flask: pass input as a variable, never as template text.

{% raw %}
```python
from flask import Flask, request, render_template, render_template_string

app = Flask(__name__)

@app.get("/greet")
def greet_vulnerable():
    name = request.args.get("name", "")
    return render_template_string("Hello " + name + "!")      # user text becomes template source

@app.get("/greet-fixed")
def greet_fixed():
    name = request.args.get("name", "")
    return render_template_string("Hello {{ name }}!", name=name)   # constant template, input as data
    # better still: return render_template("greet.html", name=name)
```
{% endraw %}

User-written templates (for example tenant email templates) in Jinja2: a sandboxed environment, scalar context, current version, limits.

```python
from jinja2.sandbox import ImmutableSandboxedEnvironment
from jinja2 import StrictUndefined, TemplateError

# Jinja2 3.1.6 or later: earlier 3.1.x releases have known sandbox escapes (CVE-2024-56326, CVE-2025-27516)
sandbox = ImmutableSandboxedEnvironment(autoescape=True, undefined=StrictUndefined)

MAX_TEMPLATE = 20_000
MAX_OUTPUT = 200_000

def render_tenant_email(template_source: str, order) -> str:
    if len(template_source) > MAX_TEMPLATE:
        raise ValueError("template too large")
    context = {                                   # plain values, never the ORM object
        "first_name": order.customer.first_name,
        "order_number": order.number,
        "total": f"{order.total:.2f}",
    }
    try:
        out = sandbox.from_string(template_source).render(context)
    except TemplateError as exc:                  # includes sandbox SecurityError
        raise ValueError("template rejected") from exc
    if len(out) > MAX_OUTPUT:
        raise ValueError("output too large")
    return out
```

Run this in a worker with a timeout (a task queue's time limit, or a subprocess), because the sandbox does not limit CPU or memory. Where the template only needs to insert a few values, skip the engine:

```python
import html
import re

ALLOWED = {"first_name", "order_number", "total"}
PLACEHOLDER = re.compile(r"\[\[([a-z_]+)\]\]")

def fill(text: str, values: dict) -> str:
    def sub(m):
        key = m.group(1)
        return html.escape(str(values[key])) if key in ALLOWED and key in values else m.group(0)
    return PLACEHOLDER.sub(sub, text)
```

Django: do not build `Template` objects from user input; the Django documentation warns that the template system is not safe against untrusted template authors.

```python
from django.http import HttpResponse
from django.shortcuts import render
from django.template import Template, Context

def greet_vulnerable(request):
    return HttpResponse(Template("Hello " + request.GET.get("name", "")).render(Context({})))

def greet_fixed(request):
    return render(request, "greet.html", {"name": request.GET.get("name", "")})
```

Python `eval`: replace with `json.loads` for data, `ast.literal_eval` for Python literals (it does not execute code, though the Python docs note it can still exhaust memory or the C stack on crafted input, so limit the length), and a restricted evaluator for formulas:

```python
import ast
import operator

OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}

def calc(expr: str, variables: dict[str, float]) -> float:
    if len(expr) > 200:
        raise ValueError("expression too long")
    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            return node.value
        if isinstance(node, ast.Name) and node.id in variables:
            return variables[node.id]
        if isinstance(node, ast.BinOp) and type(node.op) in OPS:
            return OPS[type(node.op)](ev(node.left), ev(node.right))
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -ev(node.operand)
        raise ValueError("unsupported expression")      # no calls, attributes, strings or power
    return ev(ast.parse(expr, mode="eval"))
```

### Node.js: Express, EJS, Handlebars and vm

Express: templates are files in `views/`; locals are built explicitly. Do not pass `req.query` or `req.body` as the locals object: Express merges it into the render options, which is how CVE-2022-29078 in EJS 3.1.6 turned a query parameter into compile-time code, and the EJS security policy lists this pattern as unsafe use.

```javascript
const express = require('express');
const ejs = require('ejs');
const app = express();
app.set('view engine', 'ejs');

// Vulnerable: user text compiled as an EJS template
app.get('/greet', (req, res) => {
  res.send(ejs.render('Hello ' + req.query.name));
});

// Vulnerable: request data used as render options and locals
app.get('/page', (req, res) => res.render('page', req.query));

// Fixed: file template, explicit locals with expected types
app.get('/greet-fixed', (req, res) => {
  res.render('greet', { name: String(req.query.name ?? '') });
});
```

User-written templates: Mustache is logic-less and escapes double-brace tags by default. Pass plain data; Mustache calls functions in the view as lambdas, so do not include functions or rich objects.

```javascript
const Mustache = require('mustache');

function renderTenantEmail(templateSource, order) {
  if (templateSource.length > 20000) throw new Error('template too large');
  const view = {                      // plain strings only
    firstName: String(order.customer.firstName),
    orderNumber: String(order.number),
  };
  return Mustache.render(templateSource, view);
}
```

If you use Handlebars for user templates, keep it current (prototype-access restrictions arrived in 4.6.0 and 4.7.0), do not enable `allowProtoPropertiesByDefault` or `allowProtoMethodsByDefault`, register no helpers that touch the file system, network or objects, and pass plain data. Pug, EJS and Nunjucks compile templates to JavaScript; Nunjucks's own documentation says it does not sandbox execution and is not safe for user-defined templates.

`eval`, `new Function` and `vm`: there is no safe way to run untrusted JavaScript in-process with these. Use `JSON.parse` for data, a formula grammar for calculations, and for genuine customer code a separate isolate in a separate, locked-down process or container (vm2's maintainers point users to `isolated-vm`; it still needs the process isolation around it).

### Java: Spring, SpEL, Thymeleaf and FreeMarker

SpEL: do not parse user input. Where a user selects a property or sort order, map it through an allow-list to code, not to an expression. If an expression from a semi-trusted source is unavoidable, evaluate it in `SimpleEvaluationContext`, which excludes Java type references, constructors and bean references and makes you choose the property access level.

```java
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;

// Comparator, HttpStatus and ResponseStatusException imports omitted for brevity
ExpressionParser parser = new SpelExpressionParser();

// Vulnerable: request data parsed as SpEL with the full-featured context
Object v1 = parser.parseExpression(request.getParameter("filter"))
                  .getValue(new StandardEvaluationContext(product));

// Better: no expression at all; allow-listed field names mapped to code
Comparator<Product> order = switch (request.getParameter("sort")) {
    case "price" -> Comparator.comparing(Product::getPrice);
    case "name"  -> Comparator.comparing(Product::getName);
    default      -> throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
};

// If an expression is unavoidable: restricted, read-only context
EvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
Object v2 = parser.parseExpression(adminConfiguredPropertyPath).getValue(ctx, product);
```

Thymeleaf view names: never build a view name from input; allow-list it, or return data with `@ResponseBody`/`@RestController`. A `void` handler mapped to a path with user-controlled segments should take `HttpServletResponse` or return an explicit view.

```java
@Controller
class DocController {
    private static final Set<String> SECTIONS = Set.of("overview", "billing", "security");

    // Vulnerable: the view name contains request data and is expression-preprocessed
    @GetMapping("/doc-vulnerable")
    String docVulnerable(@RequestParam String section) {
        return "user/" + section;
    }

    // Fixed: allow-list before the value becomes part of a view name
    @GetMapping("/doc")
    String doc(@RequestParam String section) {
        if (!SECTIONS.contains(section)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return "user/" + section;
    }
}
```

Bean Validation: current Hibernate Validator does not enable Expression Language for custom violations by default; keep it that way, and pass values as message parameters rather than concatenating them into the message template.

```java
// Vulnerable (if EL is enabled for custom violations): user value inside the template
context.buildConstraintViolationWithTemplate("Invalid value: " + value).addConstraintViolation();

// Fixed: the value is a parameter, not part of the template
context.disableDefaultConstraintViolation();
context.unwrap(HibernateConstraintValidatorContext.class)
       .addMessageParameter("value", value)
       .buildConstraintViolationWithTemplate("Invalid value: {value}")
       .addConstraintViolation();
```

FreeMarker for user templates: the FAQ's checklist is the spec. Use a restrictive object wrapper and member-access policy, set the `new` built-in resolver to `TemplateClassResolver.ALLOWS_NOTHING_RESOLVER` (the FAQ says `SAFER_RESOLVER` is not restrictive enough), keep `?api` disabled (the default), use a template loader that cannot reach other files, and run with time limits because FreeMarker cannot cap CPU or memory. Velocity: `SecureUberspector` for untrusted template writers. Struts: never apply forced OGNL evaluation to user input and keep Struts current; S2-061 is exactly that mistake.

### PHP: Laravel Blade, Twig and Smarty

Blade compiles to plain PHP; never pass user text to `Blade::render()` or `Blade::compileString()`.

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Blade;

// Vulnerable: user text compiled as Blade, which is PHP
Route::get('/greet', fn (Request $r) => Blade::render('Hello '.$r->input('name')));

// Vulnerable: tenant-written template compiled at send time
$html = Blade::render($tenant->welcome_template, ['user' => $user]);

// Fixed: a view file you control, input as data
Route::get('/greet-fixed', fn (Request $r) => view('greet', ['name' => (string) $r->input('name')]));
```

User-written templates in a Laravel or Symfony application: render them in a dedicated, sandboxed Twig environment. From Twig 3.29 the documentation recommends the `Twig\Sandbox\Sandbox` class with a strict `SecurityPolicy`; older 3.x code registers `SandboxExtension`, which is internal from 3.29 with its sandbox-toggling methods deprecated. Keep Twig current: many sandbox bypasses were fixed in 2026.

```php
use Twig\Environment;
use Twig\Loader\ArrayLoader;
use Twig\Sandbox\Sandbox;
use Twig\Sandbox\SecurityPolicy;

$env = new Environment(new ArrayLoader([]));          // dedicated; never the application environment
$policy = new SecurityPolicy(
    allowedTags: ['if', 'for'],
    allowedFilters: ['escape', 'upper', 'lower', 'date'],
    allowedMethods: [],
    allowedProperties: [],
    allowedFunctions: [],
);
$policy->setStrict(true);                             // required by the Sandbox class
$sandbox = new Sandbox($env, $policy);

$html = $sandbox->createTemplate($tenant->welcome_template)->render([
    'first_name'   => $user->first_name,              // scalars, not Eloquent models
    'order_number' => $order->number,
]);
```

Smarty for user templates: `enableSecurity()` with a `\Smarty\Security` policy, restricting `$static_classes` (the default empty array allows all static classes; set it to `null` to disable them), `$streams`, modifiers and tags, and no `string:` or `eval:` resources built from user input.

PHP `eval`: remove it. `assert()` no longer evaluates strings from PHP 8.0, `create_function()` was removed in PHP 8.0, and the `/e` modifier of `preg_replace` is long gone (PHP 7.0); code that still relies on them is on an unsupported PHP version anyway. Map callback names through an allow-list instead of `call_user_func($input)`.

### Ruby: ERB and Liquid

```ruby
# Vulnerable: user text compiled as ERB, which is Ruby
ERB.new(params[:template]).result(binding)

# Fixed for user-written templates: Liquid with plain hashes
template = Liquid::Template.parse(tenant.welcome_template)
html = template.render("first_name" => user.first_name, "order_number" => order.number)
```

Liquid only exposes what you pass; do not pass objects that define `to_liquid` drops with methods you would not let a customer call. Replace `send(params[:x])` with a `case` or a hash of allowed methods.

### SSI and JNDI configuration

- **Apache:** if SSI is needed, use `Options +IncludesNOEXEC` rather than `+Includes`, enable it only on directories of pages you author, and HTML-encode user input before it is written into those pages. If SSI is not needed, do not load `mod_include`.
- **nginx:** keep `ssi off` (the default) on locations that proxy application responses; if a location needs SSI, make sure the upstream encodes user input.
- **IIS:** remove the Server-Side Includes feature where it is not used.
- **Log4j and JNDI:** run a current Log4j 2 release (the releases that fixed CVE-2021-44228 and its follow-ups removed message lookups and disabled JNDI by default; check the Log4j security page for the minimum version for your Java line), inventory vendored copies, and never pass user input to `InitialContext.lookup`. Egress filtering from application servers turns the next lookup-style bug from code execution into a failed connection.

### Static analysis

Rules that find the sinks in this note (verify names against your tool version):

| Stack | CodeQL | Semgrep registry |
|---|---|---|
| Python | `py/template-injection`, `py/code-injection` | `python.flask.security.audit.render-template-string.render-template-string`, `python.lang.security.audit.eval-detected.eval-detected`, `python.django.security.injection.code.user-eval.user-eval` |
| JavaScript and TypeScript | `js/code-injection`, `js/template-object-injection` | `javascript.lang.security.audit.code-string-concat.code-string-concat`, `javascript.express.security.express-insecure-template-usage.express-insecure-template-usage` |
| Java | `java/server-side-template-injection`, `java/spel-expression-injection`, `java/ognl-injection`, `java/mvel-expression-injection`, `java/jexl-expression-injection` | `java.spring.security.audit.spel-injection.spel-injection`, `java.lang.security.audit.el-injection.el-injection`, `java.lang.security.audit.ognl-injection.ognl-injection` |
| PHP | (not covered by CodeQL at the time of writing) | `php.lang.security.eval-use.eval-use` |
| Ruby | `rb/code-injection` | `ruby.lang.security.no-eval.ruby-eval` |
| C# | `cs/code-injection` | |

`js/template-object-injection` targets exactly the `res.render(view, req.query)` pattern. Add custom rules for your own "render from string" helpers, which generic rules will not know about.

### Regression tests

Every rendering path that handles user input gets a test that feeds it probes from several syntax families and asserts the output contains the probe as text, not its product. Include stored paths (email, PDF, notifications), not just HTTP responses.

{% raw %}
```python
import pytest

PROBES = [
    "{{1234*5678}}", "${1234*5678}", "<%= 1234*5678 %>", "#{1234*5678}",
    "{1234*5678}", "[[${1234*5678}]]", "<#assign x=1234*5678>${x}", "#set($x=1234*5678)$x",
]
PRODUCT = "7006652"

@pytest.mark.parametrize("probe", PROBES)
def test_display_name_is_never_evaluated(client, user, probe):
    client.force_login(user)
    client.post("/profile", {"display_name": probe})
    page = client.get("/profile").content.decode()
    assert PRODUCT not in page

    email = render_account_updated_email(user_id=user.id)      # the second-order path
    assert PRODUCT not in email.html and PRODUCT not in email.text

def test_tenant_template_renders_documented_variables():
    out = render_tenant_email("Hi {{ first_name }}", order=make_order(first_name="Alex"))
    assert out == "Hi Alex"

@pytest.mark.parametrize("source", ["{{ ''.__class__ }}", "{{ config }}", "{{ order.customer.password }}"])
def test_tenant_template_sandbox_blocks_internals(source):
    with pytest.raises(ValueError):                           # SecurityError or StrictUndefined -> ValueError
        render_tenant_email(source, order=make_order())
```
{% endraw %}

The first test covers a path where user input must only ever be data. The other two cover a deliberate user-template feature: documented variables render, and internals (underscore attributes, objects that were never passed) raise instead of rendering. For Java, a MockMvc test that requests `/doc?section=` with the Thymeleaf preprocessing probe and expects `404`; for Node.js, a Jest or Supertest test that sends `{"name": "<%= 1234*5678 %>"}` and asserts the literal comes back. Run the same probe list against every new template feature as part of its definition of done.

## Practice labs

**PortSwigger Web Security Academy, server-side template injection.** Seven labs, from detection to custom exploits. They ask you to run code (delete a file from a home directory, steal a secret key) because they are labs; on client systems you stop at the proof ladder in [Before you start](#before-you-start).

- [Basic server-side template injection](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic) (ERB)
- [Basic server-side template injection (code context)](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context) (Tornado)
- [Server-side template injection using documentation](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation) (FreeMarker, via a content-manager account editing product templates)
- [Server-side template injection in an unknown language with a documented exploit](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit) (practise identification with the fuzz string and error messages)
- [Server-side template injection with information disclosure via user-supplied objects](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects) (Django, context exposure)
- [Server-side template injection in a sandboxed environment](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-a-sandboxed-environment) (FreeMarker with a poorly implemented sandbox)
- [Server-side template injection with a custom exploit](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-a-custom-exploit) (PHP, developer-supplied objects)

Use the first three to practise [GT-WEB-SSTI-2](#gt-web-ssti-2-plaintext-context-detection-with-a-fuzz-string-and-arithmetic) to [GT-WEB-SSTI-4](#gt-web-ssti-4-identify-the-template-engine), and the information-disclosure and sandbox labs for the reasoning in [GT-WEB-SSTI-6](#gt-web-ssti-6-assess-sandbox-and-context-exposure-without-exploiting). The [client-side template injection](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection) material and its AngularJS labs are the counterpart for [GT-WEB-SSTI-11](#gt-web-ssti-11-rule-out-client-side-rendering-and-application-side-maths).

**OWASP Juice Shop.** The **SSTi** challenge (Injection category, difficulty 6) asks for arbitrary command execution through a server-side template. It is tagged "Danger Zone" and is disabled by default when Juice Shop runs in Docker or on Heroku; run it from source locally, or change `challenges.safetyMode`, on an isolated machine.

**Vulhub.** Docker environments for the Java expression-injection CVEs in this note, for practising version fingerprinting and out-of-band detection on your own machine: `struts2/s2-045`, `struts2/s2-061`, `spring/CVE-2016-4977`, `spring/CVE-2022-22947`, `spring/CVE-2022-22963`, `confluence/CVE-2022-26134`, `confluence/CVE-2023-22527` and `log4j/CVE-2021-44228` in the [vulhub repository](https://github.com/vulhub/vulhub). Run them on an isolated network.

**Spring View Manipulation.** Veracode's [research repository](https://github.com/veracode-research/spring-view-manipulation) is a runnable Spring Boot and Thymeleaf application with vulnerable and safe controllers side by side, useful for [GT-WEB-SSTI-7](#gt-web-ssti-7-expression-language-injection-in-java-applications) and for checking the fixes.

OWASP crAPI and VAmPI do not include template or code injection scenarios at the time of writing.

## Real-world cases

- **Uber, Jinja2 in an account email (HackerOne report [125980](https://hackerone.com/reports/125980), 2016).** The reporter, `orange`, set a profile name to a Jinja2 expression multiplying the string `'7'` by 7 and received the "Your Uber account information has been updated" email with the name rendered as `7777777`: second-order SSTI through an email template, identified as Jinja2 by Python string repetition. The report is disclosed and shows a bounty of $10,000. It is the pattern in [GT-WEB-SSTI-5](#gt-web-ssti-5-stored-and-second-order-template-rendering).
- **Shopify, Handlebars in a merchant email template (HackerOne report [423541](https://hackerone.com/reports/423541), 2018, disclosed 2019).** Found during the H1-514 event in the Return Magic app's workflow email templates: a template printing the context object rendered `[Object Object]`, suggesting a JavaScript engine. The researcher's [write-up](https://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html) explains how it became code execution through a then-unknown Handlebars weakness, the kind of history that makes "logic-less" a property of the language rather than a guarantee.
- **Alfresco and XWiki (James Kettle, PortSwigger Research, 2015).** The [original research](https://portswigger.net/research/server-side-template-injection) includes case studies of FreeMarker template injection in Alfresco, where a low-privilege user's stored XSS made an administrator install a malicious template, and Velocity in XWiki wiki pages editable by registered users: the "users allowed to write templates" variant.
- **Confluence (CVE-2021-26084, CVE-2022-26134, CVE-2023-22527).** Two unauthenticated OGNL injections and an unauthenticated template injection in Confluence Server and Data Center, all in the CISA Known Exploited Vulnerabilities catalogue at the time of writing. See Atlassian's advisories for [CVE-2022-26134](https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html) and [CVE-2023-22527](https://confluence.atlassian.com/security/cve-2023-22527-rce-remote-code-execution-vulnerability-in-confluence-data-center-and-confluence-server-1333990257.html). For testers, the lesson is the order of work in [GT-WEB-SSTI-7](#gt-web-ssti-7-expression-language-injection-in-java-applications): fingerprint the product version first.
- **Spring Cloud Function (CVE-2022-22963).** The [Spring advisory](https://spring.io/security/cve-2022-22963) describes a user-supplied SpEL routing expression leading to remote code execution in the routing functionality: an expression language exposed to request data by a framework feature, not by application code.
- **Bean Validation messages (Netflix Titus CVE-2020-9296 and others).** Alvaro Muñoz's [Bean Stalking](https://github.blog/security/vulnerability-research/bean-stalking-growing-java-beans-into-remote-code-execution/) research (GitHub Security Lab, 2020) found Java EL injection in several projects, including Netflix Titus and Sonatype Nexus, where custom constraint violation messages were built by concatenating the invalid value into the message template.

## Rating findings

Rate on what an attacker reaches from the evaluation point, who can reach it, and whether the impact leaves the component. Use the engine assessment from [GT-WEB-SSTI-6](#gt-web-ssti-6-assess-sandbox-and-context-exposure-without-exploiting): an unsandboxed engine where public research documents code execution is rated as code execution even when you did not demonstrate it, and the report says so. Following the series convention, Scope is Changed when code execution on the host clearly reaches beyond the vulnerable application (a shared host, other services' credentials, a cloud instance role); other tenants of the same platform do not by themselves make it Changed. Scope is Unchanged when the application runs isolated and the impact is confined to it and its own data.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Unauthenticated SSTI, EL or `eval` injection in an unsandboxed engine on an internet-facing app | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | Code execution from the internet as the application's account. Use `S:C` (10.0) only when escape is shown: a host shared with other systems, a privileged container, or credentials for separately run systems |
| Any registered user, unsandboxed (profile field rendered into an email or PDF template) | Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Self-registration makes the precondition trivial; second-order delivery does not lower impact. `S:C` (9.9) only when escape is shown, as above |
| Tenant admin template editor with code execution in a multi-tenant SaaS | High to Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | A self-service tenant admin is a customer, not an operator, so `PR:L`. Reaching other tenants' data on the same platform raises the severity for scale but does not by itself make Scope Changed; use `S:C` (9.9) only when escape from the host is shown |
| Template editor with code execution, editable only by the operator's own administrators | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (7.2) | High when administrators are not meant to have server access (support staff, content editors), Medium where they already deploy code, which you state as an accepted design risk. Say which |
| Sandboxed engine on a version with a public sandbox escape | As unsandboxed | As the matching row above | A known escape makes the sandbox irrelevant to the rating; the fix is the upgrade plus the design rules |
| Sandboxed, current engine; secrets or other users' data readable through context objects | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Confidentiality impact only; raise it when the secret enables a further attack (a framework secret key that signs sessions) and say so |
| Logic-less or sandboxed engine, only documented scalar values reachable | Low or Informational | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (4.3) | Evaluation proven but nothing sensitive reachable; report the design risk (an engine upgrade or a richer context changes it) |
| User-template feature without time or size limits | Medium | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` (6.5) | Sandboxes do not limit resources; one template can occupy a worker. Assessed from code or configuration, not by testing it |
| Unpatched product with a published OGNL, SpEL or template-injection CVE (Struts, Confluence, Spring Cloud) | Critical (per vendor) | Use the vendor or NVD vector | Version evidence plus advisory is sufficient; most of these are in the CISA KEV catalogue |
| JNDI lookup expansion confirmed by out-of-band DNS (Log4Shell pattern) | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (10.0) | Matches the CVE-2021-44228 rating; the lookup may fire in a log processor, which is itself a scope change |
| SSI injection with `#exec` enabled | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | Command execution as the web server user; use `PR:L` (8.8) when only registered users can post the content |
| SSI injection with only `echo` and `include` | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | Server variable disclosure and inclusion of reachable files or internal URLs; raise if include reaches sensitive internal content |
| Client-side template injection (AngularJS-style), found while testing for SSTI | Rate as XSS | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | Runs in the victim's browser; handled in the Client-Side subcategory |

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 |
|---|---|---|---|---|
| [GT-WEB-SSTI-1](#gt-web-ssti-1-inventory-template-sinks-and-user-controlled-template-content) | WSTG-INJT-18, WSTG-INJT-11, WSTG-INJT-08, WSTG-INJT-14 | `v5.0.0-1.3.7`, `v5.0.0-1.3.5` | CWE-1336, CWE-94 | `A05:2025` |
| [GT-WEB-SSTI-2](#gt-web-ssti-2-plaintext-context-detection-with-a-fuzz-string-and-arithmetic) | WSTG-INJT-18 | `v5.0.0-1.3.7` | CWE-1336 | `A05:2025` |
| [GT-WEB-SSTI-3](#gt-web-ssti-3-code-context-detection) | WSTG-INJT-18 | `v5.0.0-1.3.7` | CWE-1336 | `A05:2025` |
| [GT-WEB-SSTI-4](#gt-web-ssti-4-identify-the-template-engine) | WSTG-INJT-18 | `v5.0.0-1.3.7` | CWE-1336 | `A05:2025` |
| [GT-WEB-SSTI-5](#gt-web-ssti-5-stored-and-second-order-template-rendering) | WSTG-INJT-18, WSTG-INJT-14 | `v5.0.0-1.3.7`, `v5.0.0-1.3.5` | CWE-1336 | `A05:2025` |
| [GT-WEB-SSTI-6](#gt-web-ssti-6-assess-sandbox-and-context-exposure-without-exploiting) | WSTG-INJT-18 | `v5.0.0-1.3.5`, `v5.0.0-1.3.7`, `v5.0.0-15.2.5` | CWE-1336, CWE-94 | `A05:2025` |
| [GT-WEB-SSTI-7](#gt-web-ssti-7-expression-language-injection-in-java-applications) | WSTG-INJT-11, WSTG-INJT-18 | `v5.0.0-1.3.2`, `v5.0.0-1.3.7` | CWE-917 | `A05:2025` |
| [GT-WEB-SSTI-8](#gt-web-ssti-8-eval-style-code-injection-in-nodejs-python-php-and-ruby) | WSTG-INJT-11 | `v5.0.0-1.3.2` | CWE-95, CWE-94 | `A05:2025` |
| [GT-WEB-SSTI-9](#gt-web-ssti-9-server-side-include-injection) | WSTG-INJT-08 | `v5.0.0-1.3.5`, `v5.0.0-1.2.1` | CWE-97 | `A05:2025` |
| [GT-WEB-SSTI-10](#gt-web-ssti-10-jndi-and-lookup-string-injection-with-out-of-band-detection) | WSTG-INJT-11 | `v5.0.0-1.3.8` | CWE-917 | `A05:2025` |
| [GT-WEB-SSTI-11](#gt-web-ssti-11-rule-out-client-side-rendering-and-application-side-maths) | WSTG-INJT-18, WSTG-CLNT-15 | `v5.0.0-1.3.7` | CWE-1336 (server), CWE-79 (client) | `A05:2025` |
| [GT-WEB-SSTI-12](#gt-web-ssti-12-source-review-for-template-expression-and-eval-sinks) | WSTG-INJT-18, WSTG-INJT-11, WSTG-INJT-08 | `v5.0.0-1.3.7`, `v5.0.0-1.3.2`, `v5.0.0-1.3.5`, `v5.0.0-1.3.8` | CWE-1336, CWE-94, CWE-95, CWE-917, CWE-97 | `A05:2025` |

Notes on the mapping: all five CWEs used here are current (not deprecated) in CWE 5.0. CWE-1336, CWE-95, CWE-917 and CWE-97 are marked as allowed for vulnerability mapping; CWE-94 is "allowed with review", so prefer the more specific CWE-95 for `eval` and CWE-1336 for templates, and use CWE-94 only when neither fits. OWASP Top 10:2025 `A05:2025 Injection` lists CWE-94, CWE-95, CWE-97 and CWE-917 among its mapped CWEs; CWE-1336 is not in its list at the time of writing, but template injection is an injection weakness and we map it there. The OWASP API Security Top 10 2023 has no injection category; an injection in an API is still `A05:2025`.

## References

**OWASP**

- WSTG: [Testing for Server-side Template Injection (WSTG-INJT-18)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/18-Server-side_Template_Injection), [Testing for Code Injection (WSTG-INJT-11)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/11-Code_Injection), [Testing for SSI Injection (WSTG-INJT-08)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/08-SSI_Injection), [Testing for Incubated Vulnerability (WSTG-INJT-14)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/14-Incubated_Vulnerability), [Testing for Client-side Template Injection (WSTG-CLNT-15)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/15-Client-Side_Template_Injection)
- ASVS 5.0: [V1 Encoding and Sanitization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md) (`v5.0.0-1.3.2`, `v5.0.0-1.3.5`, `v5.0.0-1.3.7`, `v5.0.0-1.3.8`)
- [OWASP Top 10:2025 A05 Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- Community pages: [Code Injection](https://owasp.org/www-community/attacks/Code_Injection), [Server-Side Includes (SSI) Injection](https://owasp.org/www-community/attacks/Server-Side_Includes_%28SSI%29_Injection)
- Cheat sheets: [Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html), [Node.js Security](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)

**CWE**

- [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) Improper Neutralization of Special Elements Used in a Template Engine
- [CWE-94](https://cwe.mitre.org/data/definitions/94.html) Improper Control of Generation of Code ('Code Injection')
- [CWE-95](https://cwe.mitre.org/data/definitions/95.html) Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
- [CWE-917](https://cwe.mitre.org/data/definitions/917.html) Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')
- [CWE-97](https://cwe.mitre.org/data/definitions/97.html) Improper Neutralization of Server-Side Includes (SSI) Within a Web Page

**Research and PortSwigger**

- James Kettle, [Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection) (PortSwigger Research, 2015) and the [whitepaper (PDF)](https://portswigger.net/kb/papers/serversidetemplateinjection.pdf)
- Web Security Academy: [Server-side template injection](https://portswigger.net/web-security/server-side-template-injection), [Exploiting server-side template injection vulnerabilities](https://portswigger.net/web-security/server-side-template-injection/exploiting), [Client-side template injection](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection)
- Veracode research, [Spring View Manipulation](https://github.com/veracode-research/spring-view-manipulation)
- Alvaro Muñoz, [Bean Stalking: Growing Java beans into Remote Code Execution](https://github.blog/security/vulnerability-research/bean-stalking-growing-java-beans-into-remote-code-execution/) (GitHub Security Lab)
- [Exploring SSTI in Flask/Jinja2](https://www.lanmaster53.com/blog/2016/03/09/exploring-ssti-flask-jinja2/)
- Further reading (engine-specific material, not for use beyond the proof ceiling on client systems): [PayloadsAllTheThings, Server Side Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection), [HackTricks, SSTI](https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html)

**Engine and framework documentation**

- [Jinja sandbox](https://jinja.palletsprojects.com/en/stable/sandbox/), [Twig sandbox](https://twig.symfony.com/doc/3.x/sandbox.html), [Smarty security](https://smarty-php.github.io/smarty/stable/api/security/), [FreeMarker FAQ (untrusted templates)](https://freemarker.apache.org/docs/app_faq.html), [Velocity developer guide (SecureUberspector)](https://velocity.apache.org/engine/2.3/developer-guide.html)
- [Spring Framework, SpEL evaluation contexts](https://docs.spring.io/spring-framework/reference/core/expressions/evaluation.html), [Django templates](https://docs.djangoproject.com/en/stable/topics/templates/), [Laravel Blade](https://laravel.com/docs/12.x/blade)
- [Node.js vm module](https://nodejs.org/api/vm.html), [EJS security policy](https://github.com/mde/ejs/blob/main/SECURITY.md), [Handlebars runtime options](https://handlebarsjs.com/api-reference/runtime-options.html), [Mustache](https://mustache.github.io/), [Liquid](https://github.com/Shopify/liquid)
- Go [html/template](https://pkg.go.dev/html/template) and [text/template](https://pkg.go.dev/text/template)
- Python [ast.literal_eval](https://docs.python.org/3/library/ast.html#ast.literal_eval); PHP [eval](https://www.php.net/manual/en/function.eval.php) and [assert](https://www.php.net/manual/en/function.assert.php)
- Apache [mod_include](https://httpd.apache.org/docs/current/mod/mod_include.html) and [Options (IncludesNOEXEC)](https://httpd.apache.org/docs/current/mod/core.html#options); nginx [ngx_http_ssi_module](https://nginx.org/en/docs/http/ngx_http_ssi_module.html)
- [Apache Log4j security](https://logging.apache.org/log4j/2.x/security.html)

**Advisories**

- Apache Struts [S2-045](https://cwiki.apache.org/confluence/display/WW/S2-045), [S2-057](https://cwiki.apache.org/confluence/display/WW/S2-057), [S2-061](https://cwiki.apache.org/confluence/display/WW/S2-061)
- Spring [CVE-2022-22963](https://spring.io/security/cve-2022-22963), [CVE-2022-22947](https://spring.io/security/cve-2022-22947), [CVE-2018-1273](https://spring.io/security/cve-2018-1273)
- Atlassian [CVE-2022-26134](https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html), [CVE-2023-22527](https://confluence.atlassian.com/security/cve-2023-22527-rce-remote-code-execution-vulnerability-in-confluence-data-center-and-confluence-server-1333990257.html)
- CVE records: [CVE-2022-22954](https://www.cve.org/CVERecord?id=CVE-2022-22954), [CVE-2021-44228](https://www.cve.org/CVERecord?id=CVE-2021-44228); GitHub advisories for [Jinja CVE-2024-56326](https://github.com/advisories/GHSA-q2x7-8rv6-6q7h) and [Twig](https://github.com/advisories?query=ecosystem%3Acomposer+twig%2Ftwig)
- [CISA Known Exploited Vulnerabilities catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

**Tools**

- [SSTImap](https://github.com/vladko312/SSTImap), [tplmap](https://github.com/epinna/tplmap) (no longer maintained), [TInjA](https://github.com/Hackmanit/TInjA), [Template Injection Table](https://github.com/Hackmanit/template-injection-table)
- [Backslash Powered Scanner](https://portswigger.net/bappstore/9cff8c55432a45808432e26dbb2b41d8) ([source](https://github.com/PortSwigger/backslash-powered-scanner)), [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator), [interactsh](https://github.com/projectdiscovery/interactsh)
- CodeQL query help: [java/spel-expression-injection](https://codeql.github.com/codeql-query-help/java/java-spel-expression-injection/), [java/server-side-template-injection](https://codeql.github.com/codeql-query-help/java/java-server-side-template-injection/), [py/template-injection](https://codeql.github.com/codeql-query-help/python/py-template-injection/), [js/code-injection](https://codeql.github.com/codeql-query-help/javascript/js-code-injection/), [js/template-object-injection](https://codeql.github.com/codeql-query-help/javascript/js-template-object-injection/); Semgrep [render-template-string](https://semgrep.dev/r/python.flask.security.audit.render-template-string.render-template-string)
- Labs: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) ([companion guide](https://pwning.owasp-juice.shop/)), [vulhub](https://github.com/vulhub/vulhub)
