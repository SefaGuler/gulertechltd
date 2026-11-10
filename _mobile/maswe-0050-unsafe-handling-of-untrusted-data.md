---
title: "MASWE-0050: Unsafe Handling of Untrusted Data"
date: 2026-11-10 10:09:00 +0000
subcategory: code
summary: "Testing Android and iOS apps for deserialisation, SQL injection, path and zip traversal, XXE and unvalidated intent results, with semgrep, r2 and Frida."
refs: [MASWE-0050, MASVS-CODE-4, CWE-20, CWE-22, CWE-73, CWE-89, CWE-116, CWE-345, CWE-348, CWE-349, CWE-502, CWE-611, CWE-924]
tags: [android, ios, masvs-code, injection, deserialization, path-traversal]
---

This note is part of our [MASVS-CODE guide](/mobile/masvs-code-code-quality-guide/) and covers OWASP [MASWE-0050](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/): data from outside the app reaching code that treats it as if the app had written it. Every app takes in data it did not create. It arrives as server responses, intent extras, deep-link parameters, files the user imports, archives, XML, activity results, rows from another app's content provider, the pasteboard, and bytes from Bluetooth or NFC. Most of it is harmless until it meets a *sink*: a SQL statement, a file path, an object deserialiser, an XML parser, a native buffer, or a dialog the user trusts. MASWE-0050 is the weakness of letting it get there unchecked. It is the widest weakness in the CODE category and the longest note in this series. It covers the four OWASP tests filed under it (Java deserialisation and content-provider SQL injection on Android, activity-result data on Android, `NSKeyedUnarchiver` on iOS) with their demos, and the five Knowledge pages behind them. After those come six Guler Tech checks for the sinks OWASP has no test for yet: zip extraction, XML external entities, file names from IPC and links, format strings and security-relevant UI text, native code, and SQL or predicate injection outside content providers. Every test here proves its finding with a benign observation on a device you control. None of them needs an exploit.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Object Serialization (MASTG-KNOW-0021)](#android-object-serialization-mastg-know-0021)
  - [Android: ContentProvider (MASTG-KNOW-0117)](#android-contentprovider-mastg-know-0117)
  - [Android: URI Schemes in Intent Results (MASTG-KNOW-0138)](#android-uri-schemes-in-intent-results-mastg-know-0138)
  - [iOS: Object Serialization (MASTG-KNOW-0075)](#ios-object-serialization-mastg-know-0075)
  - [Android: Explicit vs Implicit Intents (MASTG-KNOW-0025)](#android-explicit-vs-implicit-intents-mastg-know-0025)
  - [Paths, archives and XML parsers (Guler Tech background)](#paths-archives-and-xml-parsers-guler-tech-background)
- [Tests](#tests)
  - [Before you start: mapping sources to sinks](#before-you-start-mapping-sources-to-sinks)
  - [MASTG-TEST-0337: References to Object Deserialization of Untrusted Data (Android)](#mastg-test-0337-references-to-object-deserialization-of-untrusted-data-android)
  - [MASTG-TEST-0339: SQL Injection in Content Providers (Android)](#mastg-test-0339-sql-injection-in-content-providers-android)
  - [MASTG-TEST-0375: Missing Validation of Data Returned from Implicit Intents (Android)](#mastg-test-0375-missing-validation-of-data-returned-from-implicit-intents-android)
  - [MASTG-TEST-0386: References to Object Deserialization of Untrusted Data (iOS)](#mastg-test-0386-references-to-object-deserialization-of-untrusted-data-ios)
  - [Other untrusted-data sinks](#other-untrusted-data-sinks)
  - [GT-CODE-0050-1: Zip path traversal in archive extraction (Android and iOS)](#gt-code-0050-1-zip-path-traversal-in-archive-extraction-android-and-ios)
  - [GT-CODE-0050-2: XML external entities in XML parsing (Android and iOS)](#gt-code-0050-2-xml-external-entities-in-xml-parsing-android-and-ios)
  - [GT-CODE-0050-3: Path traversal from IPC and link-supplied file names (Android and iOS)](#gt-code-0050-3-path-traversal-from-ipc-and-link-supplied-file-names-android-and-ios)
  - [GT-CODE-0050-4: Format strings, output encoding and untrusted text in security UI (Android and iOS)](#gt-code-0050-4-format-strings-output-encoding-and-untrusted-text-in-security-ui-android-and-ios)
  - [GT-CODE-0050-5: Untrusted input reaching native code (Android and iOS)](#gt-code-0050-5-untrusted-input-reaching-native-code-android-and-ios)
  - [GT-CODE-0050-6: SQL and predicate injection outside content providers (Android and iOS)](#gt-code-0050-6-sql-and-predicate-injection-outside-content-providers-android-and-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0039: Prevent SQL Injection in ContentProviders](#mastg-best-0039-prevent-sql-injection-in-contentproviders)
  - [MASTG-BEST-0057: Sanitize Data Coming from External Components](#mastg-best-0057-sanitize-data-coming-from-external-components)
  - [MASTG-BEST-0064: Use Safe APIs for Object Deserialization](#mastg-best-0064-use-safe-apis-for-object-deserialization)
  - [MASTG-BEST-0049: Restrict and Validate Access to Exported Content Providers](#mastg-best-0049-restrict-and-validate-access-to-exported-content-providers)
  - [Secure patterns (Guler Tech)](#secure-patterns-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0050 applies when data from outside the app's trust boundary reaches a sensitive operation without being validated, sanitised or parsed safely. The OWASP requirement is *"The app securely handles untrusted data."* It maps to [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/), "The app validates and sanitizes all untrusted inputs", and in MASVS v1 to MSTG-PLATFORM-2. It is tagged for the L1, L2 and EUDIW profiles, so it is a baseline expectation for every app, not a hardening extra. OWASP has folded nine former beta weaknesses (MASWE-0079 to MASWE-0088, except 0085) into this one entry. That is why its CWE list is long:

| CWE | Name | Where it shows up in mobile apps |
|---|---|---|
| [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | Improper Input Validation | The umbrella: type, length, format and range not checked at the boundary |
| [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | Path Traversal | `../` in file names from intents, links, providers and archive entries |
| [CWE-73](https://cwe.mitre.org/data/definitions/73.html) | External Control of File Name or Path | A provider's `DISPLAY_NAME`, a server's `Content-Disposition`, a deep-link `file=` parameter used as a path |
| [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | SQL Injection | `appendWhere()`, `rawQuery()`, `execSQL()`, `sqlite3_exec()` with concatenated input |
| [CWE-116](https://cwe.mitre.org/data/definitions/116.html) | Improper Encoding or Escaping of Output | Untrusted values concatenated into JavaScript, HTML, URLs, JSON, predicates or format strings |
| [CWE-345](https://cwe.mitre.org/data/definitions/345.html) | Insufficient Verification of Data Authenticity | Trusting an archive, configuration or result without checking where it came from |
| [CWE-348](https://cwe.mitre.org/data/definitions/348.html) | Use of Less Trusted Source | Taking the caller's identity from an extra instead of from the platform (`getCallingPackage()`, `sourceApplication`) |
| [CWE-349](https://cwe.mitre.org/data/definitions/349.html) | Acceptance of Extraneous Untrusted Data With Trusted Data | Extra keys in a `Bundle` or JSON object accepted along with the expected ones |
| [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | Deserialization of Untrusted Data | `ObjectInputStream.readObject()`, `NSKeyedUnarchiver` without secure coding, polymorphic JSON mappers |
| [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | Improper Restriction of XML External Entity Reference | XML parsers that process DTDs and resolve external entities |
| [CWE-924](https://cwe.mitre.org/data/definitions/924.html) | Improper Enforcement of Message Integrity During Transmission | Data accepted from a channel that does not protect it against change |

Android's security guidance covers the same ground in seven risk pages: [path traversal](https://developer.android.com/privacy-and-security/risks/path-traversal), [zip path traversal](https://developer.android.com/privacy-and-security/risks/zip-path-traversal), [SQL injection](https://developer.android.com/privacy-and-security/risks/sql-injection), [unsafe deserialisation](https://developer.android.com/privacy-and-security/risks/unsafe-deserialization), [XML external entities injection](https://developer.android.com/privacy-and-security/risks/xml-external-entities-injection), [untrustworthy ContentProvider-provided filename](https://developer.android.com/privacy-and-security/risks/untrustworthy-contentprovider-provided-filename) and [use of native code](https://developer.android.com/privacy-and-security/risks/use-of-native-code). Apple has no equivalent catalogue; its archived [Secure Coding Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/ValidatingInput.html) chapter on validating input is still the best Apple-authored overview.

OWASP describes the threat as MAS-THREAT-0050, *"Attackers can execute injection attacks against the app"*, reached through two attacks:

| Attack | Description | Typical attacker position |
|---|---|---|
| MAS-ATTACK-0047 | Delivering crafted deep links or intents from a malicious app or web page | Another app on the device with no permissions, or a web page or message the user opens |
| MAS-ATTACK-0059 | Supplying crafted input through any external interface (network, IPC, files, UI or peripherals) | A malicious or compromised server, a file the user is persuaded to import, an app answering an implicit intent, a nearby Bluetooth or NFC device |

**What counts as untrusted.** Anything the app did not create itself in its current process, whatever the transport. The list is longer than most threat models admit:

- **Network responses**, including over TLS. TLS tells you who sent the data, not that it is safe to parse. A compromised backend, a malicious third-party API, a CDN serving user-uploaded content and an attacker who has broken certificate validation ([MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/)) all deliver input.
- **Platform IPC**: intent extras and data URIs, activity results, broadcast extras, content-provider rows and metadata, `Messenger` and AIDL arguments on Android; URL scheme and universal-link parameters, `NSUserActivity` payloads, app extension input, shared App Group containers and the pasteboard on iOS.
- **Files**: anything chosen through a document picker, received through "Open in" or a share sheet, downloaded, unpacked from an archive, or found on shared storage.
- **Data the app wrote earlier** to a place someone else can write: external storage on Android, shared containers, backups that are restored, synced data.
- **User interface input**: text fields, QR codes, scanned documents, OCR, speech.
- **Peripherals**: Bluetooth LE characteristics, NFC tags, USB accessories.

**What counts as a sink.** Any operation whose behaviour changes when the data has an unexpected shape: query languages (SQL, `NSPredicate`, Realm queries), file-system paths, object deserialisers, XML parsers with DTD processing, script and markup builders (`evaluateJavascript`, `loadDataWithBaseURL`, `WKWebView.evaluateJavaScript(_:)`), format strings, native buffers, intent and URL builders, and screens that ask the user to approve something.

Keep the neighbouring weaknesses apart:

| Question | Where it lives |
|---|---|
| Is an exported component or content provider reachable by any app at all? | [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/) |
| Does the app send intents to the right recipient, and does it forward intents it did not build? | [MASWE-0032](/mobile/maswe-0032-insecure-intents/) |
| Does a deep link or universal link reach the app, and does its handler validate parameters? | [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/) |
| Does a WebView load or execute untrusted content? | [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/) and [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/) |
| Does the app load code (DEX, native libraries, scripts) from a place others can write? | [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/) |
| Does the app use a dependency with a known parser or deserialisation CVE? | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) |
| Is security-relevant data the app reads back from its own storage protected against tampering? | [MASWE-0057](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0057/) (MASVS-RESILIENCE, test [MASTG-TEST-0338](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0338/)) |
| Once untrusted data is inside: does it reach a sink unchecked? | This note |

Reachability is usually the hard part. A `readObject()` call on a bundled resource is not a finding. The same call on an intent extra of an exported activity is. Most work in this note goes into connecting a source an attacker can influence to a sink, and showing that connection with evidence.

## Modes of Introduction

**Missing validation at trust boundaries.** The app takes an extra, a query parameter or a JSON field and uses it without checking type, length, format or range. Kotlin's non-null types do not help: a JSON mapper or an `Intent` gives you whatever was sent, and a `String` can still be 50 MB long or contain `../`, `'`, `%n`, NUL or a right-to-left override character.

**Untrusted data in queries.** Values are concatenated into SQL (`"id=" + segment`), into `NSPredicate(format:)` strings, or into Realm filter strings, instead of being bound as parameters. Content providers are the classic case because the caller hands the provider SQL fragments by design.

**Untrusted paths and archives.** A file name from a zip entry, a provider's `DISPLAY_NAME`, a deep-link parameter or a server header is joined to a directory with `File(dir, name)`, `dir.resolve(name)` or `appendingPathComponent(name)`, and the result is never canonicalised and checked against the directory.

**Insecure parsing.** XML is parsed with DTD processing and external entities enabled, often by a third-party parser bundled with an SDK. Untrusted values are emitted into another language (JavaScript, HTML, URL, CSV, format strings) without encoding for that context.

**Insecure deserialisation.** Data is turned back into rich objects by a mechanism that picks the class from the data: Java `ObjectInputStream`, `Bundle.getSerializable()` and the untyped `getSerializableExtra()`, `NSKeyedUnarchiver` without secure coding, Jackson with default typing, or XStream. The class's own code runs before the app can check what it got.

**Weakly validated URI handling.** `android.net.Uri.parse()` and Foundation's `URL(string:)` accept nearly anything, percent-decode path segments and query items on access, and disagree with other parsers about edge cases. Security decisions made with `startsWith()`, `contains()` or `hasPrefix()` on URL strings are routinely bypassed.

**Trusting returned data.** An activity result, a `content://` URI chosen by another app, or a provider's metadata is used as if the app had produced it (MASTG-TEST-0375).

**Unsafe presentation of untrusted data.** A payee name, a device name, a file name or a server message is shown in a confirmation dialog, notification or warning without limits on length, line breaks or bidirectional control characters, so it can push the real text off screen or imitate the app's own wording.

## Impact

- **Disclosure or modification of app data.** Path traversal, SQL injection and XXE let an attacker read or overwrite files and database rows inside the app's sandbox: tokens in `shared_prefs`, databases, cached documents, keys wrapped by the keystore but stored on disk.
- **Code execution in the app's context.** Overwriting a file the app later loads as code (a downloaded native library, a DEX or JAR, a JavaScript bundle for a hybrid or React Native app, an `.odex` in older layouts), deserialisation that runs a class's initialiser with attacker-chosen fields, or memory corruption in a native parser all end with the attacker's logic running with the app's identity and permissions.
- **Authorisation bypass.** Injected SQL or predicates widen a query beyond the rows the caller should see. A substituted object (`AdminUser` instead of `BaseUser`) changes a decision taken on the decoded value.
- **Spoofed content and decisions.** Untrusted text in security-relevant UI makes the user approve the wrong payee, ignore a real warning or trust a forged message. OWASP lists this impact twice in MASWE-0050 ("Compromise of Content or UI Integrity" and "Application Content Spoofing" carry the same text).
- **Denial of service.** Entity expansion in XML, decompression bombs, huge or deeply nested serialised objects, and unchecked exceptions in exported components crash the app or exhaust memory. This is usually a low-impact outcome on its own, but repeatable crashes at start-up can lock a user out.

## Mitigations

- **Validate at every trust boundary**, as early as possible, against an allow-list of what is expected (type, length, character set, format, range). Reject; do not try to repair.
- **Bind, do not concatenate.** Use `selectionArgs`, `?` placeholders, `SQLiteStatement` bindings, Room DAOs, `sqlite3_bind_*`, `NSPredicate(format:)` arguments (`%@`, `%K`). Configure `SQLiteQueryBuilder` with `setStrict(true)`, a projection map, `setStrictColumns(true)` and `setStrictGrammar(true)`.
- **Canonicalise and contain paths.** Never use an outside file name as a path. Generate your own name where you can. Where you cannot, keep only the final component, reject `.`, `..` and empty names, canonicalise the joined path and check that it is inside the intended directory, with a trailing separator in the comparison.
- **Harden parsers.** Disallow `DOCTYPE` declarations in XML. Where DTDs are needed, disable external entities and external DTD loading explicitly and verify the setting took effect. Encode output for the context it goes into.
- **Deserialise safely.** Prefer data formats that map onto declared types (`Codable`, kotlinx.serialization, Moshi, protobuf). Never use Java serialisation on untrusted input. Where `NSKeyedUnarchiver` is required, use secure coding with class allow-lists. Use the typed `getParcelableExtra(name, Class)` and `getSerializableExtra(name, Class)` APIs.
- **Validate results and returned URIs.** Accept only the schemes, authorities and MIME types you expect, ignore provider-supplied file names, and never accept `file://` URIs from another app.
- **Keep untrusted text distinguishable.** Limit length and lines, strip control and bidirectional override characters, and render outside data in a visually distinct field rather than inside the app's own sentences.
- **Reduce the attack surface first**: do not export what does not need to be exported, protect providers with `signature` permissions, and do not accept serialised objects over IPC at all.

## Knowledge

OWASP links five Knowledge pages to the tests of this weakness. MASTG-KNOW-0021 and MASTG-KNOW-0075 describe serialisation on Android and iOS; OWASP files both under MASVS-PLATFORM, hence their URLs. MASTG-KNOW-0117 describes content providers and their query APIs. MASTG-KNOW-0138 describes the URIs that come back in activity results. MASTG-KNOW-0025 (implicit intents) is documented in full in our [MASWE-0032 note](/mobile/maswe-0032-insecure-intents/) and only summarised here. A last section gives the background on paths, archives and XML parsers that our own tests rely on.

### Android: Object Serialization (MASTG-KNOW-0021)

Source: [MASTG-KNOW-0021](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0021/). The page lists six ways to turn objects into bytes and back. For this weakness the question for each one is the same: **when the app reads the bytes back, who decides which class is created, and does any code run before the app can check the result?**

#### Java Serializable

A class that implements `java.io.Serializable` can be written with `ObjectOutputStream.writeObject()` and recreated with `ObjectInputStream.readObject()`. The stream names every class it contains, with its `serialVersionUID`. `readObject()` looks each class up on the app's class path, allocates an instance without calling its constructor, fills in the fields from the stream, and then calls the class's own `readObject(ObjectInputStream)`, `readResolve()` and `validateObject()` hooks if it has them. Only then does `readObject()` return, and only then can the app's cast or `is` check run.

```kotlin
open class BaseUser(val username: String) : Serializable
class AdminUser(username: String) : BaseUser(username) { var isAdmin = false }

val obj = ObjectInputStream(ByteArrayInputStream(bytes)).readObject()  // any class in the stream is created here
if (obj is BaseUser) UserManager.currentUser = obj                      // AdminUser passes this check
```

Three consequences follow, and they are the three levels at which you rate a finding:

1. **Object substitution.** Any serialisable subclass of the expected type passes the type check. In the OWASP demo for MASTG-TEST-0337, a stream containing `AdminUser` with `isAdmin = true` replaces the current user. No special classes are needed: the app's own model is enough.
2. **Code in other classes.** Every serialisable class reachable from the app's class path (app code, AndroidX, the SDKs it bundles, the Android framework classes visible to apps) can be named in the stream, and its deserialisation hooks run with values the stream supplies. When a chain of such hooks ends in something powerful (file writes, reflection, `Runtime.exec`), it is called a *gadget chain*. You do not need to build one to report the weakness. Showing that the app deserialises untrusted bytes without restricting classes is the finding; whether a usable chain exists on its class path decides how far the impact goes.
3. **Resource exhaustion.** Deeply nested or very large object graphs (nested `HashSet`s, huge arrays) consume CPU and memory during deserialisation, before any app check.

`Serializable` reaches Android apps by more paths than an explicit `ObjectInputStream`:

| Path | What runs `ObjectInputStream` |
|---|---|
| `ObjectInputStream(stream).readObject()` / `readUnshared()` | The app, explicitly |
| `intent.getSerializableExtra(name)`, `bundle.getSerializable(key)` | `Parcel.readSerializable()` inside the framework, when the extra is read |
| `getSerializableExtra(name, Class)` (API 33+), `IntentCompat.getSerializableExtra(intent, name, Class)` | The same, but the platform method (API 33+) checks the class before creating the object; `IntentCompat` delegates to it on API 34+ and checks after creation on API 33 and lower |
| `savedInstanceState`, `SavedStateHandle`, Navigation arguments of `Serializable` type | The framework when the state is restored (normally the app's own data) |
| Libraries: Apache Commons Lang `SerializationUtils.deserialize()`, Kryo, FST, Hessian, XStream, Jackson with default typing | The library |

Java 9 added `ObjectInputFilter` for class allow-lists during deserialisation. Android's `java.io` does not include it (there is no `ObjectInputFilter` in the Android API reference), so on Android the allow-list has to be built by subclassing `ObjectInputStream` and overriding `resolveClass()`, the "look-ahead" pattern recommended by Android's [unsafe deserialisation](https://developer.android.com/privacy-and-security/risks/unsafe-deserialization) guidance and the [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html). It is shown under [Secure patterns](#secure-patterns-guler-tech). Classes that should never be deserialised can refuse in their own `readObject()` by throwing.

The page's other remarks on `Serializable` concern storage: a `.ser` file is neither encrypted nor integrity-protected, and a class change breaks old files. That is still true and is why legacy MASTG-TEST-0034 asked testers to look for serialised objects on disk. If the app writes serialised objects to external storage, a shared container or anywhere else another app can write, reading them back is deserialisation of untrusted data.

#### JSON

Android ships `org.json` (`JSONObject`, `JSONArray`). Most apps use Gson, Moshi, Jackson or kotlinx.serialization. These map JSON onto **types the app declares**, so plain JSON cannot name an arbitrary class, with one exception that matters here: **polymorphic typing by class name**. Jackson with `activateDefaultTyping(...)` or the deprecated `enableDefaultTyping()`, or a field annotated `@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)`, reads a class name from the document and instantiates it. That reintroduces every problem of Java serialisation, and Jackson's long CVE history around gadget classes comes from exactly this. the `RuntimeTypeAdapterFactory` from Gson's extras, Moshi's `PolymorphicJsonAdapterFactory` and kotlinx.serialization's sealed or registered polymorphism map a *label* to a class from a list the app registered, which is safe from substitution.

Other JSON pitfalls are validation problems rather than deserialisation ones. Gson can create objects without running their constructors, so checks and defaults in constructors or Kotlin `init` blocks may not run and a non-null Kotlin property can end up `null`. Unknown fields are ignored silently by most mappers, so extra keys a server or IPC caller adds are dropped, but mappers configured to merge into existing objects can accept fields the developer never meant to be settable (CWE-349). The page's other remark, that JSON strings are immutable and hard to wipe from memory, is a storage concern covered in our [STORAGE guide](/mobile/masvs-storage-1-secure-storage-guide/).

#### XML

Android offers `XmlPullParser` (implemented by KXmlParser, created through `Xml.newPullParser()` or `XmlPullParserFactory`), the SAX parser from `javax.xml.parsers.SAXParserFactory`, and DOM through `DocumentBuilderFactory`. Apps also bundle third-party parsers: Xerces, Woodstox (through Jackson's XML module), Simple XML, dom4j, JDOM. The security issue is XML external entities (XXE): a document whose `DOCTYPE` declares an entity backed by a `file:` or `http:` URI, which a parser that resolves external entities replaces with the file content or the response. Entity expansion without external resources ("billion laughs") is the related denial-of-service problem. Parsers differ in their defaults and in which hardening features they accept, which is why our [GT-CODE-0050-2](#gt-code-0050-2-xml-external-entities-in-xml-parsing-android-and-ios) check verifies behaviour at runtime instead of trusting a reading of the code. (The page also names an `ExpatPullParser` implementation; current Android releases use KXmlParser for pull parsing and Expat behind the SAX parser.)

#### ORM

OrmLite, SugarORM, greenDAO and ActiveAndroid map objects to SQLite tables; Realm uses its own storage engine. Most of those libraries are no longer maintained, and MongoDB has deprecated the Atlas Device SDKs that Realm became; new code uses Room. For this weakness the ORM matters in two ways. First, every ORM has a raw-query escape hatch (Room's `@RawQuery` and `SimpleSQLiteQuery`, greenDAO's `queryRaw`, Realm's string-based queries) where concatenation brings back injection, covered by [GT-CODE-0050-6](#gt-code-0050-6-sql-and-predicate-injection-outside-content-providers-android-and-ios). Second, an ORM database that another component can modify is a source of untrusted rows. Encryption of ORM storage is a storage topic.

#### Parcelable

`Parcelable` is Android's IPC serialisation: a class writes its fields to a `Parcel` and a `CREATOR` reads them back. Intent extras, `Bundle`s, `Intent`s themselves, `Uri`s and `PendingIntent`s are all `Parcelable`. As with `Serializable`, the class to create is named in the parcel, so the untyped `getParcelableExtra(name)` can return a different `Parcelable` than the app expects, and a class whose `writeToParcel()` and `createFromParcel()` read and write a different number of fields corrupts the rest of the bundle. Mismatches of that kind in framework classes were behind platform privilege-escalation bugs such as [CVE-2021-0928](https://nvd.nist.gov/vuln/detail/CVE-2021-0928). Android 13 added the typed `getParcelableExtra(name, Class)`, `getParcelableArrayListExtra(name, Class)` and `Parcel.readParcelable(ClassLoader, Class)`. The intent-related details (lazy unparcelling of bundles, `BadParcelableException` crashes, AndroidX `IntentCompat`) are in the [Object Serialization section of our MASWE-0032 note](/mobile/maswe-0032-insecure-intents/). Android's guidance, repeated by the page, is not to persist `Parcel` bytes to disk: the format is not stable across releases and may contain `IBinder` references.

#### Protocol Buffers

Protobuf (usually `protobuf-javalite` on Android) maps a binary message onto generated classes, so the schema, not the data, decides the types. Unknown fields are kept but not interpreted. It is not encrypted or authenticated. The risk left is the parser itself: [CVE-2015-5237](https://nvd.nist.gov/vuln/detail/CVE-2015-5237), the example the page cites, is an integer overflow in the C++ implementation, relevant when the app parses protobuf in native code. Java protobuf has had denial-of-service fixes too; dependency checks for them belong in [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/).

### Android: ContentProvider (MASTG-KNOW-0117)

Source: [MASTG-KNOW-0117](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0117/). Our [MASWE-0018 note](/mobile/maswe-0018-missing-auth-on-app-components/) covers the access-control half of content providers (export state, read and write permissions, path permissions, `FileProvider` configuration). This section covers the query side, where SQL injection happens.

#### URIs and how a provider reads them

A content URI is `content://<authority>/<path>[/<id>]`. The authority is declared in the manifest (`<provider android:authorities="com.example.app.provider">`) and identifies the provider. The path names the resource (a table, a file, a virtual collection) and an optional last segment is a row ID. Clients call `ContentResolver.query()`, `insert()`, `update()`, `delete()`, `openFile()` and `call()`; on a device shell the `content` command does the same:

```bash
adb shell content query --uri content://com.example.app.provider/notes \
  --projection _id:title --where "title LIKE ?" --sort "_id DESC"
```

Inside the provider, three APIs extract parts of the URI, and all three hand you caller-controlled values when the provider is reachable by other apps:

| API | Returns | Pitfall |
|---|---|---|
| `uri.pathSegments` / `getPathSegments()` | Decoded list of segments after the authority | Decoding happens on access: a segment written as `1%20OR%201%3D1` is read as `1 OR 1=1`, and `..%2F..%2Fx` as `../../x` |
| `uri.lastPathSegment` / `getLastPathSegment()` | The decoded last segment | Same decoding; the usual source of path traversal in `openFile()` |
| `ContentUris.parseId(uri)` | The last segment parsed as `long` | Safe for SQL: it throws `NumberFormatException` for anything that is not a number |
| `uri.getQueryParameter(name)` | Decoded query parameter | Often forgotten as an input; the same rules apply |

#### UriMatcher

`UriMatcher` maps URI patterns to integer codes that the provider switches on. `#` matches one segment made of digits only; `*` matches one segment of any text:

```kotlin
val uriMatcher = UriMatcher(UriMatcher.NO_MATCH).apply {
    addURI(AUTHORITY, "students", STUDENTS)               // exact
    addURI(AUTHORITY, "students/#", STUDENT_ID)           // digits only
    addURI(AUTHORITY, "students/filter/*", STUDENT_FILTER) // anything in one segment
}
```

A `#` route therefore guarantees that the segment it matched is numeric (the matcher works on the decoded segments, so `%31` is read as `1` and still numeric), and concatenating that segment into SQL is not exploitable even though static rules flag it. A `*` route guarantees nothing about content. When you review a provider, record which route feeds which SQL fragment.

#### SQLiteQueryBuilder

[`SQLiteQueryBuilder`](https://developer.android.com/reference/android/database/sqlite/SQLiteQueryBuilder) builds the `SELECT` that most providers run in `query()`:

| Method | Behaviour | Security note |
|---|---|---|
| `setTables(String)` | Sets the `FROM` clause | A join string here is fine if it is constant |
| `appendWhere(CharSequence)` | Appends text to the `WHERE` clause **verbatim** | Injection sink when the text contains outside data |
| `appendWhereEscapeString(String)` | Appends the value quoted with `DatabaseUtils.sqlEscapeString()` | Safe for one string literal |
| `setProjectionMap(Map)` | Maps the column names callers may request to real columns | Without it, callers can request any expression as a "column" |
| `setStrict(true)` (API 14) | Validates `selection` separately so a caller cannot break out of its parentheses; ignores columns not in the projection map | Recommended on every exported provider |
| `setStrictColumns(true)` (API 29) | Rejects requested columns that are not in the projection map | Recommended |
| `setStrictGrammar(true)` (API 29) | Rejects subqueries and other grammar that is not needed in a `WHERE` or `ORDER BY` | Stops a `selection` from reading other tables |
| `query(db, projection, selection, selectionArgs, groupBy, having, sortOrder)` | Builds and runs the query | `selection` is combined with the `appendWhere` text as `(appendWhere) AND (selection)` |

#### selection, selectionArgs, projection and sortOrder

`query()` receives four SQL fragments from the caller: `projection` (columns), `selection` (a `WHERE` expression with `?` placeholders), `selectionArgs` (values bound to the placeholders) and `sortOrder`. Values in `selectionArgs` are bound and cannot change the statement. The other three are SQL text by design. This is the point most reviews get wrong in both directions:

- A provider that passes the caller's `selection` to the query is **not automatically vulnerable**. If the caller is allowed to read the whole table anyway, letting it filter that table gains nothing. Android's [SQL injection](https://developer.android.com/privacy-and-security/risks/sql-injection) page says as much.
- It **is** a problem when the provider restricts what a caller may see and relies on SQL to do it: an `appendWhere("owner_id=" + callerId)` row filter, a projection that hides columns, or **several providers or permission levels sharing one database file**. A `selection` of `1) OR (1=1` turns `(owner_id=7) AND (selection)` into `(owner_id=7) AND (1) OR (1=1)`, and a subquery in `selection`, `projection` or `sortOrder` reads tables the provider never meant to expose. `setStrict(true)` and `setStrictGrammar(true)` close those two routes.
- Anything concatenated from the URI path or a query parameter into `appendWhere()`, `rawQuery()` or `execSQL()` is injection, whatever the caller is allowed to read, because it lets the URI change the statement in ways the provider's own logic did not plan for.

#### Access control in brief

`android:exported` decides whether other apps can reach the provider at all. For providers the default is `false` for apps with `targetSdkVersion` 17 or higher and `true` below that; the presence of an intent filter plays no part for providers (MASTG-KNOW-0117's sentence tying the default to intent filters describes activities, services and receivers, not providers). `android:readPermission`, `android:writePermission` and `android:permission` (overridden by the specific two) require a permission whose `protectionLevel` decides who can hold it; `signature` is the only level that keeps other developers' apps out. `android:grantUriPermissions` and `<grant-uri-permission>` allow per-URI grants. Details and tests are in the [MASWE-0018 note](/mobile/maswe-0018-missing-auth-on-app-components/). For SQL injection, reachability is the first question: a provider that only the app itself can reach turns injection into a code-quality issue.

### Android: URI Schemes in Intent Results (MASTG-KNOW-0138)

Source: [MASTG-KNOW-0138](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0138/).

When an app asks another app for content (pick a file, take a photo, choose a contact, import a document), the answer comes back as a result `Intent`. Legacy code receives it in `onActivityResult(requestCode, resultCode, data)`; current code registers an `ActivityResultLauncher` with a contract such as `GetContent` or `OpenDocument`. Either way, the responding app controls everything in that `Intent`: the data URI (`getData()`), additional URIs in `getClipData()`, every extra, and the flags. When the result points to a `content://` URI, the provider behind it also controls every column the app queries and the bytes it serves.

#### Schemes

| Scheme | How the caller accesses it | Whose permissions apply |
|---|---|---|
| `content://` | `ContentResolver.openInputStream()`, `query()`, `openFileDescriptor()`; routed to the provider's `openFile()`/`query()` | The provider's permissions and URI grants; the **provider** decides what bytes and metadata to return |
| `file://` | `openInputStream()` opens the path directly | The **caller's** own file-system permissions; nothing stands between the returned path and the caller's private files |

The `file://` row is the dangerous one. If a responder returns `file:///data/data/com.example.app/shared_prefs/session.xml`, and the caller copies "the selected file" to an upload queue, a shared cache or another app, the caller has read and exported its own private file on the attacker's behalf. Android 7.0 added `FileUriExposedException` for apps targeting API 24 or higher, but it is thrown in the **sending** app when it passes a `file://` URI out of its process. A malicious responder can target a lower API level or relax its own `StrictMode` policy, so the exception protects nobody on the receiving side. Only the receiver's own scheme check does.

#### Provider metadata

For `content://` results, apps commonly query `OpenableColumns.DISPLAY_NAME` (the column `_display_name`) and `OpenableColumns.SIZE` to name and size the copy:

```kotlin
fun displayName(uri: Uri): String? =
    contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
        if (c.moveToFirst()) c.getString(0) else null
    }

val target = File(File(filesDir, "public"), displayName(uri) ?: "download")  // name comes from the other app
```

The framework does not sanitise values a provider returns. A display name of `../private/secret.txt` makes `File(publicDir, name)` resolve to `files/private/secret.txt`, and a size of `-1` or `2^62` is just as possible. The page's example, a name that resolves to `../lib-main/lib.so`, comes from the "Dirty Stream" research by Microsoft (Black Hat Asia 2023, referenced from Android's [untrustworthy ContentProvider-provided filename](https://developer.android.com/privacy-and-security/risks/untrustworthy-contentprovider-provided-filename) page): apps that copied shared files under the provider's display name could be made to overwrite native libraries they later loaded from their data directory, turning a file copy into code execution, or to overwrite `shared_prefs` files that held server addresses and tokens.

The relationship between the URI, the bytes the provider serves and the metadata it reports is entirely up to the provider. A file named `report.pdf` with MIME type `application/pdf` may contain anything.

#### Which requests are exposed

- **Custom actions** (`Intent("com.example.app.REQUEST_FILE")`) are answered by whichever app declares that action. On a device with an attacker app and no other handler, the attacker answers without any user choice. This is the scenario of OWASP's demo.
- **Standard actions** (`ACTION_GET_CONTENT`, `ACTION_PICK`, `MediaStore.ACTION_IMAGE_CAPTURE`) show a chooser if several apps handle them; the user picks the responder, and a malicious app can present itself as a file manager or camera.
- **System pickers** (`ACTION_OPEN_DOCUMENT`, `ACTION_CREATE_DOCUMENT`, the photo picker) are displayed by the system UI. The user still picks a location, and any installed app can provide a `DocumentsProvider` that appears there. The system UI does not rewrite the display names or bytes such a provider returns.

The safe position is the same for all three: treat the result as attacker-controlled input.

### iOS: Object Serialization (MASTG-KNOW-0075)

Source: [MASTG-KNOW-0075](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0075/). As on Android, the question for each mechanism is who decides which class gets created when data is decoded.

#### NSCoding and NSSecureCoding

`NSCoding` is the Objective-C archiving protocol: a class implements `encode(with:)` and `init?(coder:)`. `NSKeyedArchiver` writes an object graph to a property-list-based archive in which **every object records its class name**, and `NSKeyedUnarchiver` reads it back. With plain `NSCoding`, decoding a key creates whatever class the archive names, provided the class exists in the process (the app, its frameworks, or any system framework loaded into it), and runs that class's `init?(coder:)`. The app's `as? ExpectedType` check runs afterwards, when the object already exists and its initialiser has already had its side effects.

`NSSecureCoding` (iOS 6) closes that gap. A class adopts it by returning `true` from the static `supportsSecureCoding`. An unarchiver with `requiresSecureCoding` enabled then:

- refuses any class in the archive that does not adopt `NSSecureCoding`, and
- creates an object only if its class is in the allow-list that the decoding call supplied (`decodeObject(of:forKey:)`, `decodeObject(ofClasses:forKey:)`, `unarchivedObject(ofClass:from:)`, `unarchivedObject(ofClasses:from:)`).

The check happens **before** the object is created, which is the whole point. Secure coding restricts types; it does not encrypt or authenticate the archive, so an archive that must not be altered still needs a MAC or signature, and decoded values still need validation.

#### NSKeyedUnarchiver API by safety

| API | Availability | Secure coding | Verdict for untrusted data |
|---|---|---|---|
| `NSKeyedUnarchiver.unarchiveObject(with:)`, `unarchiveObject(withFile:)` | Deprecated since iOS 12 | Not enforced | Unsafe |
| `unarchiveTopLevelObjectWithData(_:)` | iOS 9, deprecated since iOS 12 | Not enforced | Unsafe |
| `init(forReadingWith:)` (ObjC `initForReadingWithData:`) | Deprecated since iOS 12 | Off by default | Unsafe unless the code enables it |
| `init(forReadingFrom:)` (ObjC `initForReadingFromData:error:`) | iOS 11 | **On by default**; `decodingFailurePolicy` set to `.setErrorAndReturn` | Safe if left on and every decode names classes |
| `requiresSecureCoding = false` | iOS 6 | Turns enforcement off | Red flag |
| `decodeObject(forKey:)` | iOS 2 | No class list of its own | Context-dependent; unsafe when secure coding is off |
| `decodeObject(of:forKey:)`, `decodeObject(ofClasses:forKey:)` | iOS 6 | Class-restricted | Safe pattern |
| `decodeArrayOfObjects(ofClass:forKey:)`, `decodeDictionary(withKeysOfClass:objectsOfClass:forKey:)` | iOS 14 | Class-restricted collections | Safe pattern |
| `unarchivedObject(ofClass:from:)`, `unarchivedObject(ofClasses:from:)` | iOS 11 | Required, class-restricted | Safe pattern for the top level |
| `unarchivedArrayOfObjects(ofClass:from:)`, `unarchivedDictionary(ofKeyClass:objectClass:from:)` | iOS 14 | Required, class-restricted | Safe pattern for collections |

Sources: Apple's [`NSKeyedUnarchiver`](https://developer.apple.com/documentation/foundation/nskeyedunarchiver), [`init(forReadingFrom:)`](https://developer.apple.com/documentation/foundation/nskeyedunarchiver/init%28forreadingfrom:%29), [`requiresSecureCoding`](https://developer.apple.com/documentation/foundation/nskeyedunarchiver/requiressecurecoding) and [`NSSecureCoding`](https://developer.apple.com/documentation/foundation/nssecurecoding) reference pages.

Pitfalls that turn a "secure" call into an insecure one:

- **Allow-lists that are too wide.** `decodeObject(ofClasses: [NSObject.self], ...)` or an allow-list containing a broad base class accepts almost anything. Collections must list both the container and the element classes (`[NSArray.self, Session.self]`), and developers who get errors tend to widen the list until they stop.
- **Turning enforcement off.** `requiresSecureCoding = false` after `init(forReadingFrom:)` is a common migration shortcut from the deprecated APIs. Apple's reference says that once secure coding is enabled the setter throws if you try to disable it, yet the pattern is widespread and OWASP's demo relies on it. Treat it as a finding whenever you see it, and confirm on the target iOS version whether decoding proceeds.
- **Classes that adopt `NSSecureCoding` but decode their own fields with `decodeObject(forKey:)`.** The outer class is checked, but nested values are not class-restricted in the way the developer assumed.
- **Side effects in `init?(coder:)`.** The initialiser of an allowed class runs on attacker-chosen values. File writes, network calls or keychain changes inside it are reachable by anyone who can supply an archive containing that class, as OWASP's `CachedDocument` example shows.

#### Codable, JSON and property lists

Swift's `Codable` (`Encodable` + `Decodable`) with `JSONDecoder` or `PropertyListDecoder` decodes into **the type the code asks for**. The data cannot name a class, so object substitution is not possible. What remains is validation: a `Codable` struct accepts any `String` or `Int` the JSON supplies, so lengths, ranges and formats still need checking, and custom `init(from:)` implementations can contain the same side effects as `init?(coder:)`. `JSONSerialization` and `PropertyListSerialization` return untyped `Any` trees of Foundation types (dictionaries, arrays, strings, numbers, dates, data), which are safe to create but must be cast and validated. Third-party JSON libraries listed by the page (Mantle, JSONModel, SwiftyJSON, ObjectMapper, YYModel and others) vary; those that map onto classes by name from the data deserve the same scrutiny as `NSCoding`.

The page shows archives stored in `UserDefaults` with `NSKeyedArchiver.archivedDataWithRootObject` and read back with `unarchiveObjectWithData`. Data in `UserDefaults` is normally written only by the app, but an archive stored in an **App Group** suite (`UserDefaults(suiteName:)`), on the pasteboard, in iCloud key-value storage or in a file other components can write is untrusted when read back.

#### XML

Apple's `XMLParser` (`NSXMLParser`) is a SAX-style parser on libxml2. Its [`shouldResolveExternalEntities`](https://developer.apple.com/documentation/foundation/xmlparser/shouldresolveexternalentities) property defaults to `false`; Apple notes that setting it to `true` "may cause other I/O operations, either network-based or disk-based". Apps that set it to `true`, or that call libxml2 directly with `XML_PARSE_NOENT` or `XML_PARSE_DTDLOAD`, or that bundle wrappers (KissXML, GDataXML, Fuzi, Ono, AEXML, SWXMLHash and others listed by the page), need checking. [CVE-2015-3784](https://nvd.nist.gov/vuln/detail/CVE-2015-3784), an XXE in the iOS Office document viewer, is the page's example of how this goes wrong even in system code.

#### Core Data, Realm and Protocol Buffers

Core Data persists objects in SQLite, binary or in-memory stores without encryption or integrity protection. One detail matters for deserialisation: **transformable attributes** are stored as archived data. Since iOS 12, Apple provides `NSSecureUnarchiveFromDataTransformer` and recommends it over the older `NSKeyedUnarchiveFromData` transformer, which does not enforce secure coding. A model whose transformable attributes use the old transformer or a custom one that calls the deprecated unarchiving APIs is decoding archives without class restrictions. Realm stores data in its own format, encrypted only if the app passes an encryption key. [swift-protobuf](https://github.com/apple/swift-protobuf) maps messages onto generated types, like Android's protobuf. The page's encryption remarks belong to the [STORAGE guide](/mobile/masvs-storage-1-secure-storage-guide/).

#### Where untrusted archives come from on iOS

Custom URL scheme and universal-link parameters (base64 archives in query items, as in OWASP's demo), files opened from Mail, Files or a share sheet, App Group containers shared with extensions and other apps from the same team, the pasteboard (custom pasteboard types often carry archives), `NSUserActivity` payloads from Handoff, iCloud documents and key-value storage, push notification payloads, and server responses. Each of those is a source for MASTG-TEST-0386.

### Android: Explicit vs Implicit Intents (MASTG-KNOW-0025)

Source: [MASTG-KNOW-0025](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0025/), documented in full in our [MASWE-0032 note](/mobile/maswe-0032-insecure-intents/). In short: an **explicit** intent names its target component or package; an **implicit** intent names an action (plus optional data and categories) and lets the system pick any app whose intent filter matches. If several apps match, the user chooses; if exactly one does, it is delivered without a choice. For this note, the consequence is simple: whenever the app starts an implicit intent *for a result*, the app that answers is chosen by the device's installed apps and the user, not by the developer, and its answer is untrusted input (MASTG-TEST-0375).

### Paths, archives and XML parsers (Guler Tech background)

Our tests below depend on how path APIs behave. These are the rules worth knowing by heart.

**Joining paths does not resolve them.** `File(dir, name)` in Java and Kotlin, `dir.resolve(name)` in Kotlin, `Path.resolve()` in `java.nio`, and `URL.appendingPathComponent(_:)` or `NSString.appendingPathComponent(_:)` in Foundation all keep `..` components. The kernel resolves them when the file is opened. `File("/data/user/0/app/files/public", "../private/x").path` is `/data/user/0/app/files/public/../private/x`, which the kernel opens as `files/private/x`.

**Absolute names behave differently by API.** `File(parent, "/etc/x")` in Java appends the child to the parent (`parent/etc/x`). Kotlin's `File.resolve("/etc/x")` and `java.nio.file.Path.resolve("/etc/x")` return the absolute path itself and drop the parent. `File("/etc/x")` on its own obviously uses it as is. Swift's `appendingPathComponent("/etc/x")` appends.

**Decoding happens before you see the value.** `Uri.getPathSegments()`, `Uri.getLastPathSegment()` and `Uri.getQueryParameter()` on Android, and `URLComponents.queryItems` and `URL.path` on iOS, return percent-decoded values. A check on the encoded string (`!uri.toString().contains("..")`) is bypassed by `%2E%2E%2F`.

**Canonicalise, then compare with a trailing separator.** `File.getCanonicalFile()` on Android resolves `.`, `..` and symbolic links. `URL.standardizedFileURL` on iOS removes `.` and `..`, and `resolvingSymlinksInPath()` also follows links. The containment check must compare against the base directory **plus a separator**: `"/data/user/0/app/files_evil".startsWith("/data/user/0/app/files")` is true. Android's own [path traversal](https://developer.android.com/privacy-and-security/risks/path-traversal) example (`saferOpenFile`) compares without the separator, so copy its idea but not its exact check. On iOS, apply the same normalisation to both sides: `resolvingSymlinksInPath()` strips a leading `/private` from paths such as `/private/var/mobile/...`, so a resolved child compared with an unresolved base fails in confusing ways.

**Symbolic links defeat name checks.** A check on the *name* (no `..`, no leading `/`) does not stop an archive or a writable directory that contains a symbolic link pointing elsewhere: writing `link/x` follows the link. `java.util.zip` does not create symlinks, but tar extractors, Apache Commons Compress, libarchive and several iOS zip libraries can. Both [CVE-2023-39138](https://nvd.nist.gov/vuln/detail/CVE-2023-39138) in ZIPFoundation (fixed in 0.9.18) and [CVE-2022-36943](https://nvd.nist.gov/vuln/detail/CVE-2022-36943) in SSZipArchive (fixed in 2.5.4) were symlink-based traversals in libraries that already checked names.

**Android 14 added a platform check for zip entries.** For apps targeting API 34 or higher, `ZipFile(String)` and `ZipInputStream.getNextEntry()` throw `ZipException` when an entry name contains `..` or starts with `/` ([Android 14 behaviour changes](https://developer.android.com/about/versions/14/behavior-changes-14#zip-path-traversal)). Apps can switch it off with `dalvik.system.ZipPathValidator.clearCallback()` or replace it with `setCallback()`. It does not cover apps targeting lower API levels, third-party or native extractors, tar or 7z formats, or traversal through symbolic links, and it does nothing for file names that do not come from zip entries.

**Zip archives are also a resource problem.** The size an entry declares is not trustworthy, and a small archive can expand to gigabytes. Extractors should cap total uncompressed size and entry count and write into an empty directory the app owns.

**XML features have standard names, but parsers disagree on which they honour.** The features used in hardening code are `http://apache.org/xml/features/disallow-doctype-decl`, `http://xml.org/sax/features/external-general-entities`, `http://xml.org/sax/features/external-parameter-entities`, `http://apache.org/xml/features/nonvalidating/load-external-dtd`, `XMLConstants.FEATURE_SECURE_PROCESSING`, and for StAX `XMLInputFactory.SUPPORT_DTD` and `IS_SUPPORTING_EXTERNAL_ENTITIES`. A parser that does not recognise a feature may throw from `setFeature()`; if the app catches and ignores that exception, the hardening silently did nothing. Android's built-in parsers have historically not fetched external entities by default, but that is a property of a particular implementation and release, not a guarantee, and it says nothing about the third-party parser an SDK bundled. Verify behaviour at runtime.

## Tests

OWASP files four tests under MASWE-0050: three for Android and one for iOS. Two of them (0337 and 0386) find deserialisation call sites, 0339 finds SQL injection in content providers, and 0375 traces activity results at runtime. They replace these legacy (MASTG v1) tests:

| Legacy test | `covered_by` in the OWASP source | Where it is covered on this site |
|---|---|---|
| [MASTG-TEST-0025](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0025/) Testing for Injection Flaws (Android) | MASTG-TEST-0339 | Here, plus [GT-CODE-0050-6](#gt-code-0050-6-sql-and-predicate-injection-outside-content-providers-android-and-ios) for SQL outside providers |
| [MASTG-TEST-0034](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0034/) Testing Object Persistence (Android) | MASTG-TEST-0337 | Here |
| [MASTG-TEST-0026](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0026/) Testing Implicit Intents (Android) | MASTG-TEST-0372, 0374, 0375 | 0375 here (its "arbitrary file read" and "code execution" cases are both about returned data); 0372 and 0374 in our [MASWE-0032 note](/mobile/maswe-0032-insecure-intents/) |
| [MASTG-TEST-0079](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0079/) Testing Object Persistence (iOS) | MASTG-TEST-0386, MASTG-TEST-0302 | 0386 here; 0302 (sensitive data unencrypted in private storage) in our [MASWE-0001 note](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/) |
| [MASTG-TEST-0002](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0002/) Testing Local Storage for Input Validation (Android) | MASTG-TEST-0338 | OWASP moved it to MASWE-0057 (integrity of stored data, MASVS-RESILIENCE). The input-validation half, validating values read back from storage others can write, is part of the source inventory below and of GT-CODE-0050-3 and 0050-6 |

Tests that sit next to this weakness but are documented elsewhere on this site:

- **MASTG-TEST-0372 and 0374** (implicit intents used internally, implicit intents carrying sensitive extras) live in OWASP's MASVS-CODE folder but are filed under MASWE-0032: see the [MASWE-0032 note](/mobile/maswe-0032-insecure-intents/). MASTG-TEST-0375 overlaps with them because it starts from an implicit intent, but its subject is what the app does with the answer, which is why OWASP filed it here and why we document it in full below.
- **Deep-link input validation** (MASTG-TEST-0394 on Android, 0370 and 0395 on iOS) is in the [MASWE-0029 note](/mobile/maswe-0029-insecure-deep-links/). Deep links are one of the main *sources* for the sinks in this note; when a deep-link parameter reaches a deserialiser, SQL or a file path, test the sink here and the handler there.
- **WebView content** (MASTG-TEST-0398, 0399, 0400, also in OWASP's MASVS-CODE folder) is in the [MASWE-0035 note](/mobile/maswe-0035-webviews-loading-untrusted-content/), and JavaScript bridges in the [MASWE-0033 note](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/).
- **Reachability of content providers** (whether a provider is exported and unprotected) is tested in the [MASWE-0018 note](/mobile/maswe-0018-missing-auth-on-app-components/). Do it before MASTG-TEST-0339.

OWASP's static tests stop at "the API is used". Every test below adds the two questions that decide a rating: **can someone outside the app control the input**, and **what does the sink do with it**. The evidence always comes from the app under test on a device you control: decompiled code, the manifest, runtime hooks on the app's own methods, and files appearing inside the app's own sandbox.

### Before you start: mapping sources to sinks

Decompile once and build a source-to-sink inventory; every test below draws on it.

```bash
# Android: pull, decompile, read the manifest
adb shell pm path com.example.app
adb pull /data/app/~~<random>/com.example.app-<random>/base.apk app.apk
jadx -d out --deobf app.apk
apktool d -o apktool-out app.apk
aapt2 dump badging app.apk | grep -E "package:|sdkVersion|targetSdkVersion"

# Components other apps can reach (exported, or with intent filters)
grep -nE '<(activity|activity-alias|service|receiver|provider)|android:exported|<intent-filter|android:permission|readPermission|writePermission' \
  apktool-out/AndroidManifest.xml
```

Restrict searches to the app's own packages (and the SDKs you intend to assess) so that framework and AndroidX code does not drown the results. Then list sources and sinks:

```bash
APP=out/sources/com/example/app

# Sources: IPC, results, providers, links, files, network
grep -rnE 'getIntent\(\)|get(String|Int|Long|Boolean|Bundle|Parcelable|Serializable|ByteArray)(Array|ArrayList)?Extra\(|getExtras\(\)|getData\(\)|getClipData\(\)|onActivityResult|registerForActivityResult|getQueryParameter|getPathSegments|getLastPathSegment|OpenableColumns|openInputStream\(|getContentResolver\(\)\.query' $APP

# Sinks
grep -rnE 'ObjectInputStream|readObject\(|readUnshared\(|getSerializable|appendWhere\(|rawQuery\(|execSQL\(|compileStatement\(|SimpleSQLiteQuery|new File\(|File\(|\.resolve\(|FileOutputStream\(|ZipInputStream|ZipFile\(|getNextEntry|DocumentBuilderFactory|SAXParserFactory|XmlPullParserFactory|XMLInputFactory|setFeature\(|evaluateJavascript|loadDataWithBaseURL|String\.format\(|native ' $APP
```

On iOS, work on a decrypted app bundle (see [MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/) for obtaining one) and inventory the entry points before the APIs:

```bash
unzip -q App.ipa -d ipa && BIN=ipa/Payload/App.app/App
plutil -p ipa/Payload/App.app/Info.plist | grep -A8 -E 'CFBundleURLTypes|CFBundleDocumentTypes|UTImportedTypeDeclarations|LSSupportsOpeningDocumentsInPlace|UIFileSharingEnabled'
codesign -d --entitlements - ipa/Payload/App.app 2>/dev/null | grep -A4 -E 'associated-domains|application-groups'
ls ipa/Payload/App.app/PlugIns 2>/dev/null       # app extensions share data with the app

# Selectors and Swift symbols of interest (main binary and embedded frameworks)
for b in "$BIN" ipa/Payload/App.app/Frameworks/*.framework/*; do
  [ -f "$b" ] || continue
  echo "== $b"
  rabin2 -zz "$b" 2>/dev/null | grep -oE 'unarchiveObjectWith(Data|File):|unarchiveTopLevelObjectWithData:error:|initForReadingWithData:|initForReadingFromData:error:|setRequiresSecureCoding:|decodeObjectForKey:|decodeObjectOfClass(es)?:forKey:|unarchivedObjectOfClass(es)?:fromData:error:|setShouldResolveExternalEntities:|sqlite3_(exec|prepare_v2)|predicateWithFormat:|stringWithFormat:' | sort | uniq -c
done
```

Record each source and each sink with its class and method, then connect them in jadx or r2 (OWASP's [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/) and [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)). A sink without a reachable untrusted source is a code-quality note, not a vulnerability. A source that reaches a sink in an exported component, a link handler or a result handler is where the tests below start.

### MASTG-TEST-0337: References to Object Deserialization of Untrusted Data (Android)

Source: [MASTG-TEST-0337](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0337/). Platform: Android. Type: static (code). Knowledge: [MASTG-KNOW-0021](#android-object-serialization-mastg-know-0021). Replaces legacy MASTG-TEST-0034.

#### Overview

The test finds places where the app recreates Java objects from serialised data and checks whether that data can come from outside the app (intent extras, bundles, IPC payloads, files others can write, network responses) without a class restriction or validation before use. OWASP's steps are two techniques: reverse engineer the app ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), in practice jadx) and search the code for the relevant APIs ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), in practice semgrep and grep).

#### Prerequisites

- The APK (and splits) decompiled with jadx; the source inventory from [Before you start](#before-you-start-mapping-sources-to-sinks).
- [semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) and the OWASP rule `mastg-android-object-deserialization.yml` from the MASTG repository (`rules/`).
- For the dynamic confirmation: a test device with frida-server, and the app's exported components listed.

#### Steps

1. **Run the OWASP rule** against the decompiled Java:

   ```bash
   semgrep -c mastg-android-object-deserialization.yml out/sources/ --text
   ```

   The rule matches `new java.io.ObjectInputStream(...)` followed by `.readObject()` on the same variable. That is the explicit case only.

2. **Widen the search**, because the rule misses most real paths:

   ```bash
   grep -rnE 'extends ObjectInputStream|ObjectInputStream\(|\.readObject\(\)|\.readUnshared\(\)' out/sources/
   grep -rnE 'getSerializableExtra\(|getSerializable\(|readSerializable\(' out/sources/
   grep -rnE 'SerializationUtils\.deserialize|com\.esotericsoftware\.kryo|org\.nustaq\.serialization|com\.caucho\.hessian|com\.thoughtworks\.xstream|enableDefaultTyping|activateDefaultTyping|JsonTypeInfo\.Id\.CLASS' out/sources/
   ```

   The second line matters most in practice: `getSerializableExtra(name)` deserialises the extra inside the framework, so an exported activity that reads a `Serializable` extra is the same sink as an explicit `ObjectInputStream`, without the word appearing in app code. Typed reads (`getSerializableExtra(name, Foo::class.java)` on API 33+) check the class first.

3. **Classify each hit by source.** Follow the bytes back in jadx: a bundled asset or a file only the app writes is trusted; an extra of an exported component, a broadcast, a provider row, a downloaded file, a server response or external storage is not. Record whether the component is exported (manifest) and whether a permission protects it.

4. **Look for a class restriction.** A subclass of `ObjectInputStream` that overrides `resolveClass()` and throws for classes outside an allow-list is a mitigation. A cast or `is` check *after* `readObject()` is not.

5. **Confirm reachability at runtime (benign).** Hook the deserialiser and deliver a value that is not a valid serialised object through the source you identified. The stream fails to parse, so nothing is instantiated, but the hook shows the bytes reached `ObjectInputStream`:

   ```javascript
   // deser-trace.js: frida -U -f com.example.app -l deser-trace.js
   Java.perform(() => {
     const OIS = Java.use('java.io.ObjectInputStream');
     const Log = Java.use('android.util.Log');
     const Exc = Java.use('java.lang.Exception');
     const where = () => Log.getStackTraceString(Exc.$new()).split('\n').slice(1, 8).join('\n');

     OIS.$init.overload('java.io.InputStream').implementation = function (s) {
       console.log('[ObjectInputStream] created\n' + where());
       return this.$init(s);
     };
     OIS.resolveClass.implementation = function (desc) {
       console.log('[resolveClass] ' + desc.getName());
       return this.resolveClass(desc);
     };
   });
   ```

   ```bash
   # The extra name comes from the code you reviewed; the value is deliberately not a serialised object
   adb shell am start -n com.example.app/.MainActivity --es payload_b64 'Z3Rwcm9iZQ=='
   adb logcat -d | grep -iE 'StreamCorrupted|invalid stream header'
   ```

   For a `Serializable` extra read with `getSerializableExtra(name)`, the same hook fires when the app reads the extra. If you need to show that the app also accepts *unexpected classes*, deliver a serialised instance of a harmless JDK class such as `java.lang.String` or `java.util.Date` that you created with `ObjectOutputStream` on your workstation, and observe `[resolveClass] java.lang.String` followed by the app's own type-check failure in logcat. That proves the absence of look-ahead filtering without involving any class whose deserialisation does anything.

#### Observation

A list of deserialisation call sites, each with: the API (explicit `ObjectInputStream`, `getSerializableExtra`, library), the source of the bytes, the component and its export state, the presence or absence of a `resolveClass()` allow-list, what the app does with the result, and for confirmed paths the hook output showing `ObjectInputStream` created from your input with the stack through the app's handler.

#### Evaluation

The test **fails** if data from a source another party can control (an extra or bundle of an exported or otherwise reachable component, IPC, a shared or external file, a network response) is deserialised with Java serialisation, or with a polymorphic mapper that takes class names from the data, without restricting the classes before instantiation.

It **passes** if the app does not deserialise untrusted data with these mechanisms, uses typed APIs for `Serializable` extras (`getSerializableExtra(name, Class)` on API 33+), or uses an `ObjectInputStream` subclass whose `resolveClass()` admits only an explicit list of expected classes, and validates the resulting values before use. Deserialisation of bundled, read-only or app-private data that no other party can write is not a failure; note it as a code-quality observation if the format is Java serialisation.

#### Demo

[MASTG-DEMO-0100](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0100/MASTG-DEMO-0100/) (fail). `MainActivity` (exported, it is the launcher) calls `processIntent(intent)` in `onCreate()`. That method decodes the base64 extra `payload_b64` and deserialises it:

```kotlin
fun processIntent(intent: Intent) {
    val b64 = intent.getStringExtra("payload_b64") ?: return
    val ois = ObjectInputStream(ByteArrayInputStream(Base64.getDecoder().decode(b64)))
    val untrusted = ois.readObject()            // FAIL: any serialisable class is created here
    ois.close()
    if (untrusted is BaseUser) UserManager.currentUser = untrusted
}
```

The OWASP rule reports the call site in the decompiled code:

```text
MastgTest_reversed.java
❯❱ rules.mastg-android-object-deserialization
      [MASVS-CODE-4] The application makes use of Object deserialization in the code using the
      ObjectInputStream.readObject() function call.
      107┆ ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedPayload));
      108┆ Object untrustedObject = ois.readObject();
```

The demo also ships a generator that serialises an `AdminUser` with `isAdmin = true` and an `adb` command that delivers it, after which the app shows `PRIVILEGED ADMIN!`. We do not reproduce the generator. The rule output, the exported launcher activity and a hook showing your non-object probe reaching `ObjectInputStream` are enough to establish the finding. The `AdminUser` substitution illustrates the impact ceiling for this app: an attacker with any app on the device (no permissions needed, since the launcher activity is exported) can replace the signed-in user with an object of their choosing.

### MASTG-TEST-0339: SQL Injection in Content Providers (Android)

Source: [MASTG-TEST-0339](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0339/). Platform: Android. Type: static (code). Knowledge: [MASTG-KNOW-0117](#android-contentprovider-mastg-know-0117). Best practice: [MASTG-BEST-0039](#mastg-best-0039-prevent-sql-injection-in-contentproviders). Replaces legacy MASTG-TEST-0025.

#### Overview

The test looks for content providers that build SQL from URI input (path segments, query parameters) or pass caller SQL fragments into queries that are supposed to restrict access. The OWASP observation names the classic pair, `Uri.getPathSegments()` into `SQLiteQueryBuilder.appendWhere()`. Its steps, like 0337's, are reverse engineering plus an API search.

#### Prerequisites

- Decompiled APK and manifest.
- The provider list with export state and permissions (from the [MASWE-0018 note](/mobile/maswe-0018-missing-auth-on-app-components/) tests). A provider no other app can reach turns this into a code-quality issue; test it anyway, but rate it accordingly.
- semgrep with `mastg-android-sql-injection-contentprovider.yml`; adb for the dynamic check.

#### Steps

1. **List providers and their protection:**

   ```bash
   grep -n -A6 '<provider' apktool-out/AndroidManifest.xml
   adb shell dumpsys package com.example.app | grep -A3 -i 'ContentProvider Authorities'
   ```

2. **Run the OWASP rule:**

   ```bash
   semgrep -c mastg-android-sql-injection-contentprovider.yml out/sources/ --text
   ```

   It matches `$QB.appendWhere($VAR)` or `$QB.appendWhere("..." + $VAR)` where `$VAR` was assigned from `$URI.getPathSegments().get(...)` earlier in the same block. It does not see `getLastPathSegment()`, `getQueryParameter()`, values passed through helper methods, `rawQuery()`/`execSQL()` inside providers, or the caller's `selection`.

3. **Widen the search inside provider classes:**

   ```bash
   grep -rlE 'extends ContentProvider|: ContentProvider\(' out/sources/ > providers.txt
   xargs grep -nE 'appendWhere\(|rawQuery\(|execSQL\(|getPathSegments|getLastPathSegment|getQueryParameter|setStrict|setStrictColumns|setStrictGrammar|setProjectionMap|UriMatcher|addURI\(' < providers.txt
   ```

4. **Review each `query()`, `update()` and `delete()`** in jadx. For each SQL fragment, note where it comes from (URI route and pattern, `selection`, `projection`, `sortOrder`), whether the route is `#` (digits only) or `*` (any text), and whether `setStrict`, a projection map, `setStrictColumns` and `setStrictGrammar` are set. Note whether the provider restricts rows or columns with SQL that the caller's fragments could undo, and whether other tables in the same database hold data the provider does not expose.

5. **Confirm on the device** with the shell's `content` command. Use observations that read nothing beyond the provider's own data: a syntax error, and a change in row count.

   ```bash
   AUTH=com.example.app.provider

   # Baseline: what one row looks like through the route under test
   adb shell 'content query --uri "content://'"$AUTH"'/students/filter/id%3D2"'

   # A single quote in the segment: a SQLiteException in logcat shows the segment is parsed as SQL
   adb shell 'content query --uri "content://'"$AUTH"'/students/filter/name%3D%27"'
   adb logcat -d | grep -E 'SQLiteException|unrecognized token|syntax error' | tail -3

   # A tautology: more rows than the baseline shows the segment changes the WHERE clause
   adb shell 'content query --uri "content://'"$AUTH"'/students/filter/id%3D2%20OR%201%3D1"'

   # Caller selection against a row-restricted route: does it widen the result?
   adb shell 'content query --uri "content://'"$AUTH"'/students" --where "1) OR (1=1"'

   # Strict grammar: a harmless subquery should be rejected if setStrictGrammar(true) is in place
   adb shell 'content query --uri "content://'"$AUTH"'/students" --where "id IN (SELECT 1)"'
   ```

   Run these as the shell user on a test device. The shell is not an ordinary app (it holds several system permissions), so when a provider is protected by a permission, also check with the [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/) method which apps can actually reach it.

#### Observation

For each provider: export state and permissions, the `UriMatcher` routes, the SQL fragments built from URI input or caller input with their code locations, the strict-mode settings, and the `content` command output (error in logcat, row counts before and after).

#### Evaluation

The test **fails** if:

- data from the URI (path segment matched by `*`, last segment, query parameter) is concatenated into `appendWhere()`, `rawQuery()`, `execSQL()` or any other SQL text, or
- the provider relies on SQL to restrict what a caller may read or change (row filters through `appendWhere`, hidden columns, other tables in the same database, several permission levels over one database) and passes the caller's `selection`, `projection` or `sortOrder` into the query without `setStrict(true)`, a projection map with `setStrictColumns(true)`, and `setStrictGrammar(true)`.

It **passes** if URI-derived values are bound with `selectionArgs` or come from `#` routes or `ContentUris.parseId()`, and caller fragments either cannot widen access (the caller may read the whole table anyway) or are constrained by the strict settings above.

A finding's severity depends on reachability: an injectable provider that only the app can reach is a code-quality issue; one any app can reach is a vulnerability whose rating follows the data behind it.

#### Demo

[MASTG-DEMO-0102](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0102/MASTG-DEMO-0102/) (fail). An exported `StudentProvider` (`android:exported="true"`, no permission) over a `students` table:

```kotlin
when (uriMatcher.match(uri)) {
    STUDENTS -> { }                                   // caller's selection used as is below
    STUDENT_ID -> qb.appendWhere("id=" + uri.pathSegments[1])   // route "students/#": digits only
    STUDENT_FILTER -> qb.appendWhere(uri.pathSegments[2])      // route "students/filter/*": any text
}
val cursor = qb.query(db, projection, selection, selectionArgs, null, null, sortOrder)
```

The rule reports two findings:

```text
MastgTest_reversed.java
❯❱ rules.mastg-android-sql-injection-contentprovider
      [MASVS-CODE-4] Possible SQL Injection: unvalidated user input from `Uri.getPathSegments()`
      concatenated into `SQLiteQueryBuilder.appendWhere()`
       95┆ qb.appendWhere("id=" + id);
        ⋮┆----------------------------------------
       99┆ qb.appendWhere(filter);
```

Read the two results critically. Line 95 is a **false positive**: the `students/#` route only matches numeric segments, so `id` cannot contain SQL. Line 99 is the real finding: `students/filter/*` accepts any decoded segment, so `content://org.owasp.mastestapp.provider/students/filter/id%3D2%20OR%201%3D1` returns every row. The demo describes a second vector, the caller's `selection` on the `students` route, which the rule does not detect at all. In this demo it gains nothing, because the route applies no restriction and the whole table is already readable; it would matter as soon as the provider added a row filter or shared the database with other tables. Rate the demo on what the table holds and who can reach the provider: here any app, without permissions.

### MASTG-TEST-0375: Missing Validation of Data Returned from Implicit Intents (Android)

Source: [MASTG-TEST-0375](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0375/). Platform: Android. Type: dynamic (hooks) with manual review. Knowledge: [MASTG-KNOW-0025](#android-explicit-vs-implicit-intents-mastg-know-0025), [MASTG-KNOW-0138](#android-uri-schemes-in-intent-results-mastg-know-0138). Best practice: [MASTG-BEST-0057](#mastg-best-0057-sanitize-data-coming-from-external-components). Replaces part of legacy MASTG-TEST-0026.

#### Overview

When the app asks another app for something through an implicit intent and waits for a result, the responder controls the answer: the data URI, the clip data, the extras, and, behind a `content://` URI, the provider's metadata and bytes. The test traces those flows at runtime and checks whether returned values reach security-relevant operations (file paths and writes, parsing, storage, navigation, backend requests, account selection, authorisation or transaction logic) without validation. The APIs involved are the launch (`startActivityForResult`, `ActivityResultLauncher.launch`), the callback (`onActivityResult`, `ActivityResultCallback.onActivityResult`), the reads (`Intent.getData`, `getClipData`, `getExtras`, `ContentResolver.query`, `ContentResolver.openInputStream`) and whatever the app does next.

OWASP's steps are three techniques: install the app ([MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), `adb install`), hook the relevant APIs ([MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), method hooking with Frida), and exercise every flow that requests data from another app. The demo uses [Frooky](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0145/), a Frida-based tool that takes hook definitions as JSON and writes one JSON line per call with arguments and stack traces. Plain Frida does the same job.

#### Prerequisites

- A test device you control with frida-server (or the app repackaged with Frida Gadget).
- The list of result requests from static review: `startActivityForResult`, `registerForActivityResult` with their contracts (`GetContent`, `OpenDocument`, `TakePicture`, `PickContact`, custom contracts) and the actions they use. Custom actions are the highest-risk ones.

  ```bash
  grep -rnE 'startActivityForResult\(|registerForActivityResult\(|ActivityResultContracts\.|onActivityResult\(' out/sources/com/example/app/
  grep -rnE 'new Intent\("[a-z0-9_.]+\.[A-Z_]+"\)|setAction\("' out/sources/com/example/app/ | grep -v 'android.intent.action'
  ```

- For each custom action, a check of who can answer it: `adb shell cmd package query-activities -a <action>` lists the installed handlers.

#### Steps

1. **Start the app with a trace of result handling.** The script below logs the result `Intent` the app reads, the provider metadata it queries, the streams it opens and the files it creates, each with a short stack trace filtered to the app's package. It also contains an optional, off-by-default probe that replaces the `_display_name` value the app receives with a marker containing `../`, so you can test the sink with a legitimate picker and without any other app.

   ```javascript
   // result-trace.js: frida -U -f com.example.app -l result-trace.js
   const PKG = 'com.example.app';
   const PROBE_NAME = null;          // e.g. '../gt_probe_0375.txt' to test the file sink
   Java.perform(() => {
     const Log = Java.use('android.util.Log');
     const Exc = Java.use('java.lang.Exception');
     const appStack = () => Log.getStackTraceString(Exc.$new()).split('\n')
       .filter(l => l.includes(PKG)).slice(0, 4).join('\n');

     const Intent = Java.use('android.content.Intent');
     Intent.getData.implementation = function () {
       const r = this.getData(); const s = appStack();
       if (s.includes('onActivityResult') || s.includes('ActivityResult')) console.log('[result.getData] ' + r + '\n' + s);
       return r;
     };
     Intent.getClipData.implementation = function () {
       const r = this.getClipData(); if (r) console.log('[result.getClipData] ' + r + '\n' + appStack());
       return r;
     };

     const CR = Java.use('android.content.ContentResolver');
     CR.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String')
       .implementation = function (u, p, sel, args, sort) {
         console.log('[query] ' + u + '\n' + appStack());
         return this.query(u, p, sel, args, sort);
       };
     CR.openInputStream.implementation = function (u) {
       console.log('[openInputStream] ' + u + '\n' + appStack());
       return this.openInputStream(u);
     };

     const CW = Java.use('android.database.CursorWrapper');
     CW.getString.implementation = function (i) {
       let v = this.getString(i);
       const col = this.getColumnName(i);
       if (col === '_display_name') {
         console.log('[DISPLAY_NAME] ' + v);
         if (PROBE_NAME) { console.log('  probe: replaced with ' + PROBE_NAME); v = PROBE_NAME; }
       }
       return v;
     };

     const File = Java.use('java.io.File');
     File.$init.overload('java.io.File', 'java.lang.String').implementation = function (d, n) {
       const s = appStack(); if (s) console.log('[File] ' + d + ' + ' + n + '\n' + s);
       return this.$init(d, n);
     };
     Java.use('java.io.FileOutputStream').$init.overload('java.io.File').implementation = function (f) {
       const s = appStack(); if (s) console.log('[FileOutputStream] ' + f.getAbsolutePath() + '\n' + s);
       return this.$init(f);
     };
   });
   ```

2. **Exercise every flow that requests a result**: attachments, profile pictures, document import, "pick a contact", QR scanning through another app, account pickers. Use the normal handlers on the device (the system picker, the camera, the Files app).

3. **Read the trace for each flow.** Note the returned URI and its scheme, which provider answered, the display name and size, and the operations that follow: is the name used in `File(...)`? Is the stream parsed (images, PDFs, archives, XML)? Is the URI or an extra sent to the backend or used to choose an account?

4. **Test the file sink with the probe (benign).** Set `PROBE_NAME = '../gt_probe_0375.txt'`, restart, pick any harmless file through the same flow, and check where the copy landed:

   ```bash
   adb shell run-as com.example.app ls -la files/ files/public/ cache/ 2>/dev/null   # debuggable builds
   adb shell su -c 'find /data/data/com.example.app -name gt_probe_0375.txt'           # rooted test device
   ```

   A file named `gt_probe_0375.txt` one directory above the intended folder shows the name reached the write unchanged. The probe stays inside the app's own sandbox and replaces only a value the app receives.

5. **Check scheme handling.** In code, verify that the result handler rejects `file://` (and anything other than `content://`) before opening the URI, and that the provider authority is checked where the app expects a specific provider. If you want runtime evidence, temporarily make the `getData` hook return `Uri.parse('file:///data/data/com.example.app/files/gt_marker.txt')` after creating that marker with `run-as`, and watch whether the app opens it and copies it somewhere more widely readable.

#### Observation

Per flow: the request (action, launch API, contract), the callback, the returned data (URI with scheme and authority, clip data, extras, display name, size), the APIs used to read it, and the operations reached afterwards with arguments and stack traces. For the probe, the `File` and `FileOutputStream` lines showing the marker name, and the location where the marker file appeared.

#### Evaluation

The test **fails** if data returned through an implicit-intent result reaches a security-relevant operation without validation: a provider display name or extra used as a path component, a `file://` URI opened with the app's identity, a returned URI or extra sent to the backend or used to select an account or confirm a transaction, or returned content parsed by a sink covered elsewhere in this note without the protections described there.

It **passes** if the app accepts only the schemes and authorities it expects, generates its own file names (or keeps only a sanitised final component and checks containment), treats returned content as untrusted input to its parsers, and does not let returned values influence authorisation or transaction decisions.

As OWASP's "further validation" says, confirm with the stack traces in jadx where each value came from (`getData()`, clip data, extras, provider metadata), that an external responder controls it, and what it affects. The finding's reach depends on how the request is answered: a custom action that any app can declare is the worst case; a standard action needs a user choice; a system picker needs the user to choose a location offered by a third-party documents provider.

#### Demo

[MASTG-DEMO-0139](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0139/MASTG-DEMO-0139/) (fail). `VulnerableActivity` requests a file with the custom action `org.owasp.mastestapp.REQUEST_FILE` and copies it under the provider's display name:

```kotlin
startActivityForResult(Intent("org.owasp.mastestapp.REQUEST_FILE"), REQUEST_CODE_GET_CONTENT)

override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    val uri = data?.data ?: return
    var fileName = "temp_file"
    contentResolver.query(uri, null, null, null, null)?.use {
        val i = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        if (it.moveToFirst() && i >= 0) fileName = it.getString(i)      // FAIL: name from another app
    }
    val outFile = File(File(filesDir, "public"), fileName)               // FAIL: used as a path
    val content = contentResolver.openInputStream(uri)?.use { it.bufferedReader().readText() } ?: ""
    FileOutputStream(outFile).use { it.write(content.toByteArray()) }
}
```

The Frooky hook file traces `java.io.File(File, String)` and `java.io.FileOutputStream(File)`. The relevant lines of its output (shortened):

```text
java.io.File.$init  from VulnerableActivity.onActivityResult(MastgTest.kt:65)
    args: /data/user/0/org.owasp.mastestapp/files, "public"
java.io.File.$init  from VulnerableActivity.onActivityResult(MastgTest.kt:67)
    args: /data/user/0/org.owasp.mastestapp/files/public, "../private/secret.txt"
java.io.FileOutputStream.$init  from VulnerableActivity.onActivityResult(MastgTest.kt:69)
    args: /data/user/0/org.owasp.mastestapp/files/public/../private/secret.txt
```

The write lands on `files/private/secret.txt`, a file the app created earlier in `onCreate()` with the content "Original Secret Content", and replaces it with whatever the responder served.

The other side of the demo is [MASTG-DEMO-0141](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0141/MASTG-DEMO-0141/), a separate app that plays the responder. We describe it rather than reproduce it. It declares an exported activity with an intent filter for `org.owasp.mastestapp.REQUEST_FILE`, so Android routes the demo app's request to it (directly, if it is the only handler). That activity finishes with a result whose data is a `content://` URI on the responder's own exported provider. When the victim queries that URI, the provider reports `../private/secret.txt` as `DISPLAY_NAME` and serves replacement content for the stream. The observable result is three log lines from the responder (the URI it returned, the display name it reported, the content it served) and the overwritten file in the victim's sandbox. OWASP notes that the responder is not malicious in isolation: answering an intent and naming a file are normal behaviours. The vulnerability is entirely in the caller's trust. For an assessment you do not need such an app: the trace plus the probe in step 4 show the same path with evidence from the app under test alone.

### MASTG-TEST-0386: References to Object Deserialization of Untrusted Data (iOS)

Source: [MASTG-TEST-0386](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0386/). Platform: iOS. Type: static (code) with manual review. Knowledge: [MASTG-KNOW-0075](#ios-object-serialization-mastg-know-0075). Best practice: [MASTG-BEST-0064](#mastg-best-0064-use-safe-apis-for-object-deserialization). Replaces legacy MASTG-TEST-0079 together with MASTG-TEST-0302.

#### Overview

The test finds `NSKeyedUnarchiver` usage that does not enforce secure coding or class restrictions and checks whether the archive can come from somewhere an attacker influences: files, IPC, URL and universal-link parameters, network responses, pasteboard data, app extensions, App Group containers or local archives others can write. OWASP lists the patterns: broad APIs (`decodeObject(forKey:)`, `unarchiveObject(with:)`, `unarchiveTopLevelObjectWithData(_:)`), unarchivers created with `init(forReadingFrom:)` or `initForReadingWithData:` and then used without class restrictions, `requiresSecureCoding = false`, and classes that rely on `NSCoding` instead of `NSSecureCoding`. The steps are to extract the binaries ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), exploring the app package) and search them for the APIs ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), static analysis), then review each hit in the disassembly ([MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)).

#### Prerequisites

- A decrypted IPA (App Store binaries are FairPlay-encrypted; use an app you build, a development build from the client, or a decrypted copy obtained on a jailbroken test device).
- radare2 (`r2`, `rabin2`), or Ghidra/Hopper for the review; Frida for the optional runtime check.
- The entry-point inventory from [Before you start](#before-you-start-mapping-sources-to-sinks): URL schemes, universal links, document types, extensions, App Groups.

#### Steps

1. **Unpack and list the binaries:**

   ```bash
   unzip -q App.ipa -d ipa
   find ipa/Payload/App.app -type f -perm +111 | xargs file | grep Mach-O
   ```

2. **Inventory the decoding APIs** in the main binary and every embedded framework. Objective-C calls appear as selectors; Swift-only overlays appear as mangled imports:

   ```bash
   BIN=ipa/Payload/App.app/App
   rabin2 -zz "$BIN" | grep -E 'unarchiveObjectWith|unarchiveTopLevelObjectWithData|initForReadingWithData|initForReadingFromData|setRequiresSecureCoding|decodeObjectForKey|decodeObjectOfClass|unarchivedObjectOfClass'
   rabin2 -i "$BIN" | grep -E 'NSKeyedUnarchiver|decodeObject|unarchivedObject'
   rabin2 -s "$BIN" | grep -E 'supportsSecureCoding|initWithCoder|init.*coder'    # classes that adopt NSCoding
   ```

3. **Find the functions that use them** with cross-references. OWASP's demo uses an r2 script; the core of it is:

   ```bash
   r2 -q -A -c 'axt @ reloc.fixup.setRequiresSecureCoding:; axt @ reloc.fixup.decodeObjectForKey:' "$BIN"
   ```

   The relocation names depend on how r2 labels the selector references in your binary; if the `reloc.fixup.` form finds nothing, search with `/r` or `axt` on the selector string address from `izz`.

4. **Review each function.** Look for: `setRequiresSecureCoding:` called with `0`; `decodeObjectForKey:` used for the root object or for objects whose class matters; deprecated top-level APIs; allow-lists containing `NSObject` or other broad classes; classes that implement `init(coder:)` but not `supportsSecureCoding`; and side effects inside `init(coder:)` implementations (file writes, URL loads, keychain writes, notifications).

5. **Connect each unsafe decode to a source.** Walk the callers up to an entry point: `application(_:open:options:)` or `scene(_:openURLContexts:)` for URL schemes, `onOpenURL` in SwiftUI, `scene(_:continue:)` or `application(_:continue:restorationHandler:)` for universal links and Handoff, document handlers, extension hosts, pasteboard reads, App Group file reads, network completion handlers.

6. **Optional runtime confirmation (benign).** Trace the unarchiver while you drive the entry point with legitimate data, and record which classes are decoded and whether secure coding is on:

   ```javascript
   // nscoding-trace.js: frida -U -f com.example.app -l nscoding-trace.js
   const U = ObjC.classes.NSKeyedUnarchiver;
   const bt = ctx => Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 6).map(DebugSymbol.fromAddress).join('\n  ');

   Interceptor.attach(U['- setRequiresSecureCoding:'].implementation, {
     onEnter(args) { console.log('[setRequiresSecureCoding:] ' + args[2].toInt32() + '\n  ' + bt(this.context)); }
   });
   Interceptor.attach(U['- decodeObjectForKey:'].implementation, {
     onEnter(args) { this.key = new ObjC.Object(args[2]).toString(); },
     onLeave(ret) {
       if (!ret.isNull()) console.log('[decodeObjectForKey:] ' + this.key + ' -> ' + new ObjC.Object(ret).$className);
     }
   });
   Interceptor.attach(U['+ unarchivedObjectOfClasses:fromData:error:'].implementation, {
     onEnter(args) { console.log('[unarchivedObjectOfClasses:] ' + new ObjC.Object(args[2]).toString()); }
   });
   ```

   To show that an insecure path accepts a class it did not ask for, deliver through the same entry point an archive whose root object is a plain `NSString` (create it on your Mac with `NSKeyedArchiver.archivedData(withRootObject:requiringSecureCoding:)`). The trace shows `-> __NSCFString` (or a similar Foundation string class) on the insecure path, while a class-restricted path fails with a decoding error before creating anything. No app-specific class is involved, so nothing in the app runs except its own decoding code.

#### Observation

A list of decoding call sites with, for each: the API, whether secure coding is enforced, the classes allowed, the classes that adopt `NSCoding` without `NSSecureCoding`, side effects in `init(coder:)` implementations, and the path from an entry point to the call. For runtime checks, the trace lines.

#### Evaluation

The test **fails** if the app decodes data from a potentially untrusted or attacker-influenced source with APIs that do not enforce secure coding and class restrictions: deprecated top-level unarchiving, `requiresSecureCoding = false`, root or security-relevant objects decoded with `decodeObject(forKey:)` while secure coding is off, or allow-lists so broad that they restrict nothing.

It **passes** if every decode of attacker-influenced data uses secure coding with explicit class lists (`unarchivedObject(ofClass:from:)`, `decodeObject(of:forKey:)` and their collection variants), the decoded classes adopt `NSSecureCoding` and decode their own fields the same way, and decoded values are validated before use.

As OWASP stresses, a reference alone does not fail the test. Unsafe APIs on constant, bundled or otherwise trusted data are a code-quality note and a migration recommendation.

#### Demo

[MASTG-DEMO-0149](https://mas.owasp.org/MASTG/demos/ios/MASVS-CODE/MASTG-DEMO-0149/MASTG-DEMO-0149/) (fail, marked draft in the OWASP repository). The app registers the URL scheme `mastgtest`. A link of the form `mastgtest://import?session=<base64 archive>` is decoded twice, once insecurely and once securely:

```swift
private static func decodeInsecurely(_ data: Data) -> String {
    let unarchiver = try NSKeyedUnarchiver(forReadingFrom: data)
    unarchiver.requiresSecureCoding = false                                       // FAIL
    let object = unarchiver.decodeObject(forKey: NSKeyedArchiveRootObjectKey)     // FAIL: any class
    unarchiver.finishDecoding()
    // ... casts to InsecureUserSession only after the object exists
}

private static func decodeSecurely(_ data: Data) -> String {
    let session = try NSKeyedUnarchiver.unarchivedObject(ofClass: SecureUserSession.self, from: data)  // PASS
    // ...
}
```

The sample also contains `CachedDocument`, an `NSSecureCoding` class whose `init?(coder:)` writes a file named by the archive into `Documents` (an offline-cache restore). Because the insecure path accepts any class, an archive naming `CachedDocument` makes the app write a file of the sender's choosing just by opening a link. The secure path rejects the class before its initialiser runs. OWASP's demo includes a generator for such a link; we do not reproduce it.

The r2 script's output shows the evidence. The cross-references put both the secure-coding switch and the unrestricted decode in the same function:

```text
Functions that set requiresSecureCoding:
sym.MASTestApp.MastgTest.decodeInsecurely... 0x70c8 [DATA:r--] ldr x1, reloc.fixup.setRequiresSecureCoding:

Functions that call unrestricted decodeObject(forKey:):
sym.MASTestApp.InsecureUserSession.coder... 0x443c [DATA:r--] ldr x1, reloc.fixup.decodeObjectForKey:
sym.MASTestApp.CachedDocument.coder...      0x5678 [DATA:r--] ldr x1, reloc.fixup.decodeObjectForKey:
sym.MASTestApp.MastgTest.decodeInsecurely... 0x7130 [DATA:r--] ldr x1, reloc.fixup.decodeObjectForKey:
```

and the disassembly shows the value passed to the setter:

```text
0x000070c8  ldr x1, [x8, 0x408]   ; str.setRequiresSecureCoding:
0x000070cc  mov w8, 0
0x000070d0  and w2, w8, 1         ; argument = NO
0x000070d4  bl sym.imp.objc_msgSend
```

Further back, `importSharedSession(from:)` (at `0x6644`) reads the `session` query item with `URLComponents`, base64-decodes it, and calls `decodeInsecurely` at `0x6d20`, so the unsafe decode is reachable from any link the user opens in Safari, Notes or Messages. You can open such a link on a test device with `xcrun devicectl device process launch --device <id> --payload-url '<url>' <bundle id>` or, on a jailbroken device, `uiopen '<url>'` ([MASTG-TECH-0169](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0169/)). For a benign confirmation use a link whose archive holds a plain `NSString`, as in step 6.

Two details of the demo are worth knowing when you meet the pattern in real apps. The `decodeObject(forKey:)` hits inside `CachedDocument.init(coder:)` are not separate findings on their own: when the enclosing unarchiver enforces secure coding, a nested `decodeObject(forKey:)` is checked against the allow-list of the enclosing call (recent iOS versions log a console warning when they let through a plain property-list type such as `NSString` that the list did not name). Recommend `decodeObject(of:forKey:)` anyway, so the class's safety does not depend on how it is reached. And the demo's reliance on `requiresSecureCoding = false` after `init(forReadingFrom:)` working is exactly the point on which Apple's reference documentation says the setter should throw; whatever your iOS version does, the code expresses an intent to decode without restrictions and should be reported.

### Other untrusted-data sinks

OWASP's four tests cover deserialisation, provider SQL and activity results. MASWE-0050 and the Android risk pages it maps to are wider: zip path traversal, XXE, path traversal from file names, output encoding, native code and SQL outside providers have no OWASP test yet. The six checks below fill those gaps. They follow the same structure as the OWASP tests and the same rule: evidence comes from the app under test, and proof is the smallest benign observation that shows untrusted data reaching the sink (a marker file appearing one directory too high inside the app's own sandbox, a hook printing the argument, a request arriving at your own lab server). Where a sibling note already tests the source (deep links, WebViews, exported providers), these checks point there and focus on the sink.

### GT-CODE-0050-1: Zip path traversal in archive extraction (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Apps unpack archives more often than their feature list suggests: offline content packs, theme and sticker bundles, downloaded web assets for hybrid apps, OTA updates of React Native or other JavaScript bundles, imported backups, document formats that are zip containers (DOCX, XLSX, EPUB, KMZ). Each entry carries its own path, chosen by whoever built the archive. If the extractor joins that path to its destination without a containment check, an entry named `../../shared_prefs/config.xml` is written outside the destination ("zip slip", Android's [zip path traversal](https://developer.android.com/privacy-and-security/risks/zip-path-traversal) risk). The check covers `java.util.zip` and third-party extractors on Android, and ZIPFoundation, SSZipArchive (ZipArchive) and libarchive-style code on iOS.

#### Prerequisites

- Decompiled APK or the iOS binary with its frameworks; the app's dependency manifest where available (Gradle files, `Podfile.lock`, `Package.resolved`, `Cartfile.resolved`).
- The app's `targetSdkVersion` (Android 14's platform check depends on it).
- A test device you control; Frida; Python 3 on your workstation to build a test archive.
- Knowledge of where the archive comes from (download URL, document picker, share target, IPC).

#### Steps

1. **Find extraction code on Android:**

   ```bash
   grep -rnE 'ZipInputStream|ZipFile\(|getNextEntry\(|\.entries\(\)|ZipEntry|getName\(\)' out/sources/com/example/app/ | grep -iE 'zip|entry'
   grep -rnE 'ZipPathValidator|clearCallback|setCallback' out/sources/
   grep -rnE 'org\.apache\.commons\.compress|net\.lingala\.zip4j|ArchiveStreamFactory|TarArchiveInputStream|SevenZFile' out/sources/ | cut -d: -f1 | sort -u
   # Native extractors (minizip, libzip, libarchive) in bundled libraries
   for so in apktool-out/lib/*/*.so; do llvm-nm -D --defined-only "$so" 2>/dev/null | grep -qE 'unzOpen|zip_open|archive_read_new' && echo "$so"; done
   ```

2. **Review each extractor.** The vulnerable shape is an entry name flowing into a path without a check:

   ```kotlin
   ZipInputStream(input).use { zis ->
       var e = zis.nextEntry
       while (e != null) {
           val out = File(destDir, e.name)          // FAIL: entry name used as a path
           out.parentFile?.mkdirs()
           out.outputStream().use { zis.copyTo(it) }
           e = zis.nextEntry
       }
   }
   ```

   A safe extractor canonicalises `File(destDir, e.name)` and checks it starts with `destDir.canonicalPath + File.separator` before writing; see [Secure patterns](#secure-patterns-guler-tech). Also check for a total-size and entry-count limit, and that `destDir` is a fresh directory the app owns.

3. **Account for Android 14.** If the app targets API 34 or higher and uses `ZipFile(String)` or `ZipInputStream`, the platform throws on names with `..` or a leading `/`, unless the code calls `ZipPathValidator.clearCallback()`. Record this as a mitigating platform control, not as the app's fix: it does not apply on lower targets, in other extractors, or to symlinks, and the app's code still has the bug.

4. **Find extraction code on iOS:**

   ```bash
   grep -E '"(ZIPFoundation|SSZipArchive|ZipArchive|Zip)"|ZIPFoundation|SSZipArchive' Podfile.lock Package.resolved Cartfile.resolved 2>/dev/null
   ls ipa/Payload/App.app/Frameworks/ | grep -iE 'zip'
   rabin2 -zz "$BIN" | grep -E 'unzipFileAtPath|unzipItemAtURL|unzipItem|SSZipArchive|archive_read_extract|unzOpen'
   ```

   Current releases of ZIPFoundation check entry paths for traversal in `FileManager.unzipItem(at:to:)`; versions before 0.9.18 were vulnerable to traversal through symbolic links ([CVE-2023-39138](https://nvd.nist.gov/vuln/detail/CVE-2023-39138)). SSZipArchive before 2.5.4 had the same class of symlink issue ([CVE-2022-36943](https://nvd.nist.gov/vuln/detail/CVE-2022-36943)). Code that iterates `Archive` entries itself and calls `extract(_:to:)` with `destination.appendingPathComponent(entry.path)` bypasses the library's own check and needs the same review as the Android loop above.

5. **Trace extraction at runtime.** On Android, hook the entry names and the files created during extraction:

   ```javascript
   // zip-trace.js
   Java.perform(() => {
     const ZE = Java.use('java.util.zip.ZipEntry');
     ZE.getName.implementation = function () { const n = this.getName(); console.log('[ZipEntry] ' + n); return n; };
     const File = Java.use('java.io.File');
     File.$init.overload('java.io.File', 'java.lang.String').implementation = function (d, n) {
       if (n.indexOf('..') !== -1 || n.startsWith('/')) console.log('[File] suspicious child: ' + d + ' + ' + n);
       return this.$init(d, n);
     };
   });
   ```

   On iOS, hook the file-creation calls the extractor ends in (`open` and `openat` in `libsystem_kernel.dylib`, or `-[NSFileManager createFileAtPath:contents:attributes:]`) and print paths containing `/../`. On iOS 17 and later, Swift's `URL` is implemented in Swift and may not pass through the Objective-C `NSURL` methods, so hook at the file-system level rather than on path-joining methods.

6. **Confirm with a benign archive.** Build a test archive containing one normal entry and one entry whose name climbs exactly one level, holding a marker text:

   ```bash
   python3 -c "import zipfile; z=zipfile.ZipFile('gt_probe.zip','w'); z.writestr('ok.txt','gt'); z.writestr('../gt_probe_zip.txt','gt'); z.close()"
   unzip -l gt_probe.zip
   ```

   Deliver it through the feature that accepts archives (import it from the document picker, serve it from your lab server in place of the content pack on a debug build that points at it, or share it to the app). Then look for the marker:

   ```bash
   adb shell run-as com.example.app find . -name 'gt_probe_zip.txt'      # Android, debuggable build
   find ~/Library/Developer/CoreSimulator/Devices/*/data/Containers/Data/Application -name gt_probe_zip.txt 2>/dev/null   # iOS simulator
   ```

   The marker one level above the extraction directory, inside the app's container, proves the finding. Do not build archives that climb further, overwrite existing files or contain symbolic links outside a disposable test install; the one-level marker is the evidence a report needs.

#### Observation

The extraction code locations and libraries (with versions), the archive source, the presence or absence of a containment check, size and count limits, `targetSdkVersion` and any `ZipPathValidator` calls, the trace of entry names, and the location of the marker file.

#### Evaluation

The test **fails** if an archive from a source someone else can influence (a download that is not integrity-checked against a key the app holds, a user-imported file, a share target, IPC, shared storage) is extracted with entry names used as paths without canonicalisation and containment, or with a library version known to be vulnerable, or if the app disables Android's validator without its own check. It also fails if extraction follows symbolic links out of the destination.

It **passes** if every extractor checks each resolved path against the destination with a separator-terminated canonical prefix, rejects or skips symbolic links, limits size and entry count, and extracts into an app-owned empty directory; or if archives come only from a source whose integrity the app verifies with a signature before extraction.

#### Demo

A minimal vulnerable Android extractor is the loop in step 2. With the probe archive, the trace shows:

```text
[ZipEntry] ok.txt
[ZipEntry] ../gt_probe_zip.txt
[File] suspicious child: /data/user/0/com.example.app/files/packs + ../gt_probe_zip.txt
```

and `run-as ... find` reports `./files/gt_probe_zip.txt` instead of `./files/packs/gt_probe_zip.txt`. On a device running Android 14 with the app targeting API 34 and using `ZipInputStream`, the same archive produces `java.util.zip.ZipException` at `getNextEntry()` instead; record that the platform blocked it, and report the missing check in the app with lower severity.

### GT-CODE-0050-2: XML external entities in XML parsing (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

XML still reaches mobile apps: SOAP and legacy enterprise APIs, RSS and Atom feeds, SVG images, GPX and KML tracks, SAML responses, configuration downloads, and the XML inside OOXML and EPUB containers. A parser that processes the document's `DOCTYPE` can be told to fetch an external resource (a local file or a URL) and insert it into the parsed content, or to expand entities until memory runs out. Android's [XXE risk page](https://developer.android.com/privacy-and-security/risks/xml-external-entities-injection) recommends disabling DTDs entirely. This check finds the parsers, reads their configuration, and confirms behaviour with a probe that can only cause a request to your own lab server.

#### Prerequisites

- Decompiled code or binaries; a list of XML inputs and their sources.
- A lab HTTP server reachable from the test device (for example `python3 -m http.server 8000` on a laptop at 192.168.1.50 on the test Wi-Fi).
- A way to feed the app a document through a real input (an imported file, a debug build pointed at a lab endpoint, or a proxy that rewrites one lab response; see our [traffic interception lab](/mobile/mobile-traffic-interception-lab/)).

#### Steps

1. **Find parsers and their configuration (Android):**

   ```bash
   grep -rnE 'DocumentBuilderFactory|SAXParserFactory|XmlPullParserFactory|Xml\.newPullParser|XMLInputFactory|TransformerFactory|SchemaFactory|org\.simpleframework\.xml|XmlMapper|org\.dom4j|org\.jdom2|XMLReader' out/sources/com/example/app/
   grep -rnE 'setFeature\(|setExpandEntityReferences|setXIncludeAware|setEntityResolver|setProperty\(.*(SUPPORT_DTD|IS_SUPPORTING_EXTERNAL_ENTITIES)|FEATURE_PROCESS_DOCDECL|FEATURE_SECURE_PROCESSING' out/sources/com/example/app/
   ```

   For each parser, note the features set, whether the `setFeature()` calls sit in a `try` block that swallows exceptions, whether a custom `EntityResolver` resolves systemIds by opening them, and which third-party parser is on the class path (Simple XML and Jackson's XML module bring their own).

2. **Find parsers and their configuration (iOS):**

   ```bash
   rabin2 -zz "$BIN" | grep -E 'setShouldResolveExternalEntities:|initWithContentsOfURL:|initWithData:|NSXMLParser|XMLParser'
   rabin2 -i "$BIN" | grep -E 'xmlReadMemory|xmlReadFile|xmlCtxtReadMemory|xmlCtxtUseOptions|xmlSubstituteEntitiesDefault|xmlParseMemory|htmlReadMemory'
   ```

   With `XMLParser`, a finding needs `shouldResolveExternalEntities = true` (the default is `false`). With libxml2 directly, look for the `XML_PARSE_NOENT` (value 2) and `XML_PARSE_DTDLOAD` (value 4) option bits or `xmlSubstituteEntitiesDefault(1)`. Note also the `XMLParserDelegate` methods `parser(_:foundExternalEntityDeclarationWithName:publicID:systemID:)` and `parser(_:resolveExternalEntityName:systemID:)`: the second one lets the app return data for an external entity itself.

3. **Map each parser to its input** and the input to its source: a bundled resource is trusted; a server response is untrusted to the degree the server can be influenced; imported files and IPC are untrusted.

4. **Probe DTD processing (benign).** Feed the parser, through the real input, a document whose `DOCTYPE` declares one internal entity and one external entity that points at your lab server:

   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE probe [
     <!ENTITY gtint "gt-internal-probe">
     <!ENTITY gtext SYSTEM "http://192.168.1.50:8000/gt-xxe-probe">
   ]>
   <probe><a>&gtint;</a><b>&gtext;</b></probe>
   ```

   Three outcomes are possible. The parser rejects the document (DTDs disallowed: the safe result). It parses and shows `gt-internal-probe` but your server sees no request (DTDs processed, external entities off: acceptable but not ideal, since entity expansion is still possible). Or your server logs `GET /gt-xxe-probe` from the device (external entities resolved: the finding). Adapt the element names to the schema the app expects, so the document gets past the app's own checks to the parser. The probe reads nothing from the device and sends nothing to the server except the request itself.

5. **Hook to confirm which parser handled it**, for example `javax.xml.parsers.DocumentBuilder.parse` and `org.xmlpull.v1.XmlPullParser.setInput` on Android, or `-[NSXMLParser parse]` and `-[NSXMLParser setShouldResolveExternalEntities:]` on iOS, logging the stack and the value set.

#### Observation

The parsers in use with their configuration, the input each one processes and its source, the probe outcome (rejected, internal entity expanded, lab server request) and the hook output naming the parser.

#### Evaluation

The test **fails** if a parser that processes untrusted XML resolves external entities or loads external DTDs (the probe produces a request, or the configuration shows `shouldResolveExternalEntities = true`, libxml2 `XML_PARSE_NOENT`/`XML_PARSE_DTDLOAD`, or Java features left at insecure defaults on a parser that resolves them). A parser that expands internal entities without limits on untrusted input is a lower-severity finding (denial of service).

It **passes** if untrusted XML is parsed with `DOCTYPE` declarations disallowed, or with external entities and external DTD loading explicitly disabled in a way verified to take effect, and the probe document is rejected or parsed without any request.

#### Demo

A typical vulnerable pattern on Android, where hardening is attempted but silently fails on a parser that does not support the feature:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
try {
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
} catch (ParserConfigurationException ignored) { }   // FAIL if this throws: hardening silently skipped
Document doc = dbf.newDocumentBuilder().parse(responseStream);
```

and on iOS:

```swift
let parser = XMLParser(data: downloadedData)
parser.shouldResolveExternalEntities = true          // FAIL: default is false
parser.delegate = self
parser.parse()
```

With the probe served as `downloadedData`, the lab server log is the evidence:

```text
192.168.1.23 - - [10/Nov/2026 10:12:41] "GET /gt-xxe-probe HTTP/1.1" 404 -
```

### GT-CODE-0050-3: Path traversal from IPC and link-supplied file names (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

MASTG-TEST-0375 covers file names that come back in activity results. The same mistake happens with file names that arrive in other ways: a share target that saves `EXTRA_STREAM` under the provider's display name (the "Dirty Stream" pattern of Android's [untrustworthy ContentProvider-provided filename](https://developer.android.com/privacy-and-security/risks/untrustworthy-contentprovider-provided-filename) risk), an exported activity or service with a `fileName` extra, a deep link with `?file=`, a download that uses the server's `Content-Disposition` name or `URLUtil.guessFileName()`, a push payload naming a cached asset; on iOS, a URL scheme parameter joined with `appendingPathComponent`, a file received through "Open in" or a share extension saved under its suggested name, or names exchanged through an App Group container. Android's [path traversal](https://developer.android.com/privacy-and-security/risks/path-traversal) page describes the impact: overwritten files when writing, leaked files when reading. The parameter-validation side of deep-link handlers is tested in the [MASWE-0029 note](/mobile/maswe-0029-insecure-deep-links/), and `openFile()` traversal in exported providers in the [MASWE-0018 note](/mobile/maswe-0018-missing-auth-on-app-components/); here we follow names from the remaining sources to file-system sinks.

#### Prerequisites

- Decompiled code or binary; the exported components, share targets (`ACTION_SEND`, `ACTION_SEND_MULTIPLE` filters), document types (`CFBundleDocumentTypes`), share extensions and URL handlers from the inventory.
- A test device you control with Frida, and `run-as` (debuggable build) or root/jailbreak to inspect the sandbox; or a simulator for iOS.

#### Steps

1. **Find name sources and file sinks (Android):**

   ```bash
   APP=out/sources/com/example/app
   grep -rnE 'EXTRA_STREAM|OpenableColumns|_display_name|Content-Disposition|guessFileName|getLastPathSegment|getQueryParameter\("(file|name|path)' $APP
   grep -rnE 'new File\(|File\([a-zA-Z]+, |\.resolve\(|openFileOutput\(|FileOutputStream\(|FileInputStream\(|copyTo\(|renameTo\(' $APP
   ```

2. **Find name sources and file sinks (iOS):** in the disassembly or source, look for `appendingPathComponent`/`appendingPathComponent:`, `URL(fileURLWithPath:)`, `FileManager` `createFile`, `copyItem`, `moveItem`, `removeItem`, `Data.write(to:)`, and trace their arguments back to `URLComponents.queryItems`, `url.lastPathComponent` of an incoming URL, `NSItemProvider.suggestedName`, `UIDocumentPickerViewController` results, `Documents/Inbox` handling, or server JSON fields.

3. **For each pair, check the guard.** Accept only: a name the app generates (UUID, hash), or a sanitised final component (no `/`, not `.` or `..`, not empty, length-limited) joined to an app-owned directory and then canonicalised and checked against that directory with a trailing separator. Reject string checks on the raw or encoded value.

4. **Drive the source with a benign marker name.** Use the real input channel where you can, and keep the marker inside the app's own sandbox:

   ```bash
   # Exported activity with a file-name extra (names from your code review)
   adb shell am start -n com.example.app/.ImportActivity --es fileName '../gt_probe_path.txt'

   # Deep link parameter (percent-encoded so the handler receives ../ after decoding)
   adb shell am start -a android.intent.action.VIEW -d 'exampleapp://save?file=..%2Fgt_probe_path.txt'
   ```

   ```bash
   # iOS simulator: custom URL scheme with the same marker
   xcrun simctl openurl booted 'exampleapp://save?file=..%2Fgt_probe_path.txt'
   ```

   For share targets and document imports, the name comes from the sending provider. Use the Frida display-name probe from [MASTG-TEST-0375](#mastg-test-0375-missing-validation-of-data-returned-from-implicit-intents-android) (it applies to any `content://` URI the app queries) while you share a harmless file from the Files app.

5. **Observe the sink and the result.** Hook `File(File, String)`, `FileOutputStream` and `FileInputStream` on Android, or `open`/`openat` on iOS, and look for the marker. Then search the sandbox:

   ```bash
   adb shell run-as com.example.app find . -name 'gt_probe_path.txt'
   xcrun simctl get_app_container booted com.example.app data | xargs -I{} find {} -name gt_probe_path.txt
   ```

   For read sinks (a "view file" handler that opens `File(base, name)`), point the marker at a file you created yourself in the sandbox (`run-as com.example.app sh -c 'echo gt > files/gt_marker.txt'`) and check whether the app displays or uploads its content when given `../gt_marker.txt`.

#### Observation

Source-to-sink pairs with code locations, the guard present (if any), the command or action used to deliver the marker, the hook output showing the marker reaching the sink unchanged, and the location where the marker file was written or the marker content read.

#### Evaluation

The test **fails** if a file name or path from IPC, a link, a share or import, a provider or a server reaches a file-system operation without a containment check, so that a name containing `../` (after decoding) or an absolute path makes the app read or write outside the intended directory. It **passes** if the app generates its own names, or sanitises to a single safe component and verifies canonical containment before every read and write.

#### Demo

A share target that keeps the sender's name:

```kotlin
// Exported activity with an ACTION_SEND intent filter
val uri = IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java) ?: return
val name = contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
    ?.use { if (it.moveToFirst()) it.getString(0) else null } ?: "shared"
val dest = File(cacheDir, "shared/" + name)                       // FAIL: provider-chosen name
contentResolver.openInputStream(uri)?.use { i -> dest.outputStream().use { i.copyTo(it) } }
```

With the display-name probe active and a text file shared from the Files app, the trace shows `[File] /data/user/0/com.example.app/cache + shared/../gt_probe_path.txt` and the marker appears in `cache/` instead of `cache/shared/`. The iOS equivalent is `let dest = inbox.appendingPathComponent(components.queryItems?.first { $0.name == "file" }?.value ?? "x")` followed by `data.write(to: dest)`.

### GT-CODE-0050-4: Format strings, output encoding and untrusted text in security UI (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

This check covers the output side of CWE-116 and the "unsafe presentation" mode of MASWE-0050: untrusted values written into another language or onto a screen without encoding or limits. Three sink families are left once the WebView ones are set aside:

- **Script and markup.** Untrusted data concatenated into `evaluateJavascript()`, `loadUrl("javascript:...")`, `loadDataWithBaseURL()`, `WKWebView.evaluateJavaScript(_:)` or `loadHTMLString(_:baseURL:)` is HTML or JavaScript injection. These sinks are tested in the [MASWE-0035 note](/mobile/maswe-0035-webviews-loading-untrusted-content/) (string-built scripts and HTML) and the [MASWE-0033 note](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/) (bridges), and deep-link parameters that reach WebViews in the [MASWE-0029 note](/mobile/maswe-0029-insecure-deep-links/). Use those tests; this check only records the finding under CWE-116 when the root cause is missing encoding.
- **Format strings and structured text.** On iOS, `String(format: untrusted)`, `NSString(format:)`, `[NSString stringWithFormat:untrusted]`, `NSLog(untrusted)` and `-[NSMutableString appendFormat:]` with an outside value *as the format* interpret `%@`, `%s`, `%n` and friends: at best garbage or a crash, at worst reads of memory (CWE-134, uncontrolled format string). In C or C++ code (JNI libraries, iOS C code), `printf`, `snprintf`, `syslog` and `__android_log_print` with an outside format are the classic memory-corruption bug. In Java and Kotlin, `String.format(untrusted)` cannot corrupt memory but throws `UnknownFormatConversionException`, a crash in an exported component. Related encoding mistakes: query parameters built by concatenation (`"...?to=" + payee`, letting a value add `&amount=`), JSON or XML built by string templates, CSV exports with values starting with `=`, `+`, `-` or `@` that spreadsheet software evaluates.
- **Security-relevant UI.** Untrusted text shown in confirmation dialogs, payment or pairing screens, permission rationales, notifications or warnings without length and line limits: a payee name with twenty line breaks pushes the real amount off the dialog, a device name reads "Verified by Example Bank", a file name containing a right-to-left override character (U+202E) displays its extension reversed, so an executable or archive can pass for a PDF.

#### Prerequisites

- Decompiled code or binaries; for iOS a disassembler.
- A list of screens that ask the user to approve something (payments, transfers, device pairing, account linking, permission prompts the app shows itself) and the data each displays.
- A way to put a test value into each source (a test account with a configurable display name, a lab server, a test Bluetooth peripheral name).

#### Steps

1. **Find format-string sinks with non-constant formats:**

   ```bash
   # iOS: format APIs present; review each call site for a non-literal first argument
   rabin2 -zz "$BIN" | grep -E 'stringWithFormat:|initWithFormat:|appendFormat:|localizedStringWithFormat:' | head
   rabin2 -i "$BIN" | grep -E '_NSLog|_NSLogv|_printf|_syslog|_vsnprintf'
   # Android native code: printf-family imports in app libraries
   for so in apktool-out/lib/arm64-v8a/*.so; do echo "== $so"; llvm-nm -D --undefined-only "$so" | grep -E 'printf|syslog|__android_log_print'; done
   # Android Java/Kotlin: format with a variable as the format
   grep -rnE 'String\.format\([a-z][A-Za-z0-9_]*[,)]|\.format\([a-z][A-Za-z0-9_]*\)' out/sources/com/example/app/
   ```

   In Swift, `String(format: someVariable)` with no arguments is the giveaway; in Objective-C, `stringWithFormat:` or `NSLog` with a single non-literal argument. In disassembly, the format argument is loaded from a register rather than from a `cfstring` reference. Clang's `-Wformat-security` warns about exactly this at build time; ask whether it is enabled and treated as an error.

2. **Find string-built URLs, JSON and scripts** where outside values are concatenated rather than encoded (`Uri.Builder.appendQueryParameter` and `URLComponents.queryItems` encode; string concatenation does not):

   ```bash
   grep -rnE '"https?://[^"]*\?[^"]*=" *\+|\+ *"&[a-z_]+="' out/sources/com/example/app/
   grep -rnE 'JSONObject\("\{|"\{\\"[a-z]' out/sources/com/example/app/
   ```

3. **Review security-relevant screens.** For each value from outside the app (payee and merchant names, device names, file names, server messages, push content), check whether the UI limits length and lines, strips control and bidirectional characters, and presents it in a clearly separate field from the app's own wording. Android's `BidiFormatter` and iOS's `Text` with explicit line limits help; free-form concatenation into a sentence ("Send £10 to " + name + "?") does not.

4. **Confirm with benign values.** Put harmless markers into each source: a name such as `GT%@%@%@` or `GT%x%x` for format strings (no `%n`; the aim is to see the specifiers interpreted or not, not to write memory), a name with several line breaks and a long tail for UI tests, `GT&gtprobe=1` for URL building, `=1+1` for CSV export. Observe the screen, the outgoing request in your proxy, the exported file, and logcat or the iOS console for crashes.

#### Observation

Call sites with non-constant formats and their sources, concatenation-built URLs or documents with the value that reached them, screenshots of security-relevant screens with the test values, and any crash logs.

#### Evaluation

The test **fails** if an outside value is used as a format string in C, C++ or Objective-C/Swift Foundation APIs; if outside values are concatenated into URLs, scripts, markup or structured documents so that a test value changes their structure; or if a screen that asks the user to approve a security-relevant action displays outside text that can hide or imitate the action's real details. A Java or Kotlin `String.format` with an outside format is a robustness issue (crash) and rated as such.

It **passes** if formats are literals, outside values are passed as arguments or encoded for their context, and approval screens constrain and visually separate outside text.

#### Demo

```swift
// FAIL: the device name chosen by whoever named the Bluetooth peripheral is used as the format
let title = String(format: peripheral.name ?? "Unknown")
// PASS
let title = String(format: NSLocalizedString("pair.title", comment: ""), peripheral.name ?? "Unknown")
```

A peripheral named `GT%@%@` shows object descriptions or crashes on the failing line, and shows the literal text `GT%@%@` on the passing one.

### GT-CODE-0050-5: Untrusted input reaching native code (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Android's [use of native code](https://developer.android.com/privacy-and-security/risks/use-of-native-code) risk and the "memory corruption in native parsers" mode of MASWE-0050 cover input that crosses from Java, Kotlin or Swift into C or C++: image and media decoders, PDF and font renderers, protobuf or custom binary parsers, compression, crypto wrappers and game engines. Memory-safety bugs there turn a malformed input into a crash or code execution. Our older note [MASTG-KNOW-0005: Memory corruption bugs](/mobile/mastg-know-0005-memory-corruption-bugs/) covers the bug classes, JNI pitfalls and tooling in depth, and the [MASWE-0045 note](/mobile/maswe-0045-compiler-security-features-not-used/) covers the compiler hardening that makes them harder to exploit. This check only answers the MASWE-0050 question: **which untrusted inputs reach native code, and does anything validate them on the way?**

#### Prerequisites

- The app's native libraries (`lib/<abi>/*.so` on Android; embedded frameworks and static code in the main binary on iOS).
- Decompiled Java/Kotlin to find `native` methods; a disassembler for the native side.
- A test device with Frida.

#### Steps

1. **List the bridges.** On Android, find `native` declarations and their libraries, and the registration in each library:

   ```bash
   grep -rnE '\bnative\b.*\(' out/sources/com/example/app/ | grep -vE '^\s*//'
   grep -rnE 'System\.loadLibrary\("([^"]+)"\)' out/sources/com/example/app/
   for so in apktool-out/lib/arm64-v8a/*.so; do echo "== $so"; llvm-nm -D --defined-only "$so" | grep -E ' Java_|JNI_OnLoad'; done
   ```

   Libraries that only export `JNI_OnLoad` register their methods with `RegisterNatives`; find the method table from `JNI_OnLoad` in the disassembler. On iOS, list C and C++ libraries among the frameworks and look for Swift code passing `Data` to them (`withUnsafeBytes`, `UnsafeRawPointer`, `UnsafeMutablePointer`).

2. **Map inputs to bridges.** For each native method, find the Java or Swift callers and the source of their arguments: network bytes, files from pickers or archives, images from other apps, IPC strings. Native methods that only receive constants or app-generated data are out of scope here.

3. **Check the native side for trust in lengths and formats.** In the disassembly, look at how the method takes its input: `GetByteArrayElements`/`GetByteArrayRegion` with lengths from the data instead of `GetArrayLength`, `GetStringUTFChars` followed by `strcpy`/`sprintf` into fixed buffers, length fields read from the input and used in `memcpy` or `malloc` without bounds, and recursion driven by input depth. Note any validation done before the call on the managed side.

4. **Trace the boundary at runtime** while you exercise the features with normal inputs, to confirm which inputs reach which functions:

   ```javascript
   // jni-trace.js: log calls to one exported JNI function with the length of its byte[] argument
   const lib = Process.getModuleByName('libparser.so');
   const fn = lib.getExportByName('Java_com_example_app_Parser_parse');
   Interceptor.attach(fn, {
     onEnter(args) {
       // args[0] = JNIEnv*, args[1] = jclass/jobject, args[2] = first Java argument (jbyteArray here)
       const env = Java.vm.tryGetEnv();
       if (env) console.log('[parse] input length ' + env.getArrayLength(args[2]));
     }
   });
   ```

   (Attach after the library has loaded, for example from a hook on `System.loadLibrary`.)

5. **Exercise robustness with benign malformed inputs** through the normal channel: an empty file, a truncated file of the expected type, a file with a length field larger than the data. Watch for native crashes:

   ```bash
   adb logcat -b crash -d | tail -50              # tombstone summaries
   adb shell ls /data/tombstones 2>/dev/null      # rooted or userdebug devices
   ```

   On iOS, crash reports appear under Settings > Privacy & Security > Analytics & Improvements > Analytics Data, or in Xcode's device logs. A reproducible `SIGSEGV` or `SIGABRT` in the app's own library from a malformed input is the evidence. Do not go further than demonstrating the crash; exploitability analysis belongs to a dedicated engagement with the developer's sanitiser builds (HWASan on Android, Address Sanitizer in Xcode) and fuzzing harnesses.

#### Observation

The JNI or C bridge inventory, the untrusted inputs that reach each native function, validation present on either side, the trace output, and crash logs with the faulting library and function.

#### Evaluation

The test **fails** if untrusted input reaches native parsing code that trusts lengths, counts or structure taken from the input without bounds checks, or if a benign malformed input crashes the native code. It **passes** if native code receives only validated or app-generated data, or the parser is a maintained library at a version without known issues ([MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/)), checks every length against the buffer it reads, and survives the malformed inputs. Rate severity with the [MASTG-KNOW-0005 note](/mobile/mastg-know-0005-memory-corruption-bugs/): a crash alone is Low to Medium; a write past a buffer reachable by a remote input is High or Critical even before anyone writes an exploit.

#### Demo

```c
// FAIL: the length comes from the input, the buffer is fixed
JNIEXPORT jint JNICALL Java_com_example_app_Parser_parse(JNIEnv *env, jclass cls, jbyteArray in) {
    uint8_t hdr[64];
    jbyte *p = (*env)->GetByteArrayElements(env, in, NULL);
    uint16_t n = (uint8_t)p[0] | ((uint8_t)p[1] << 8);   // attacker-controlled length
    memcpy(hdr, p + 2, n);                                // overflows when n > 64
    (*env)->ReleaseByteArrayElements(env, in, p, JNI_ABORT);
    return n;
}
```

A file whose first two bytes say `0x0100` (256) and that holds 300 bytes produces a tombstone in `libparser.so` at `Java_com_example_app_Parser_parse`. The fix checks `n <= sizeof(hdr)` and `n + 2 <= (*env)->GetArrayLength(env, in)` before copying.

### GT-CODE-0050-6: SQL and predicate injection outside content providers (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

MASTG-TEST-0339 covers content providers. Apps also build queries over their own databases from search fields, deep-link parameters, server data and sync payloads, and the same concatenation creates the same injection, reached by different attackers: a malicious link, a crafted server response, or text another user synced. On iOS there is no OWASP test for this at all, and query languages beyond SQL are injectable too: `NSPredicate(format:)` (used by Core Data fetch requests and `filtered(using:)`) and Realm's string queries interpret quotes and operators. This check replaces the non-provider part of legacy MASTG-TEST-0025 and the "validate on read" part of MASTG-TEST-0002.

#### Prerequisites

- Decompiled code or binaries; the list of inputs that reach search, filter and sync code.
- A test device or simulator with Frida; logcat or the iOS console.

#### Steps

1. **Find query construction on Android:**

   ```bash
   APP=out/sources/com/example/app
   grep -rnE '(rawQuery|execSQL|compileStatement|rawQueryWithFactory)\(' $APP | grep -E '\+|String\.format|\$\{|StringBuilder'
   grep -rnE 'SimpleSQLiteQuery\(|@RawQuery' $APP
   grep -rnE '\.query\([^)]*\+' $APP          # selection built by concatenation in SQLiteDatabase.query
   ```

   Room `@Query` methods with `:param` bindings are safe; `@RawQuery` with a `SimpleSQLiteQuery` built by concatenation is not. SQLCipher and other SQLite wrappers expose the same methods and need the same review.

2. **Find query construction on iOS:**

   ```bash
   rabin2 -i "$BIN" | grep -E 'sqlite3_(exec|prepare|prepare_v2|prepare_v3|bind_)'
   rabin2 -zz "$BIN" | grep -E 'predicateWithFormat:|executeQuery:|executeUpdate:|executeStatements:|filter|LIKE|==' | head -40
   ```

   Look for `sqlite3_exec` or `sqlite3_prepare_v2` whose SQL text is built with `String(format:)`, `stringWithFormat:` or interpolation and few or no `sqlite3_bind_*` calls; FMDB `executeQuery:` with a formatted string instead of `executeQuery:withArgumentsInArray:` or variadic arguments; `NSPredicate(format: "name == '\(input)'")` or `NSPredicate(format: "... \(input)")` instead of `NSPredicate(format: "name == %@", input)`; Realm `filter("name == '\(input)'")`. Libraries such as GRDB build bound statements from Swift string interpolation in their own `SQL` literals, which is safe; plain Swift `String` interpolation passed as SQL text is not.

3. **Trace queries at runtime** with a hook that prints the SQL text the app passes in, then type or deliver a single quote through each input:

   ```javascript
   // sql-trace.js (Android)
   Java.perform(() => {
     const DB = Java.use('android.database.sqlite.SQLiteDatabase');
     DB.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (sql, args) {
       console.log('[rawQuery] ' + sql + ' | args=' + (args ? args.length : 0));
       return this.rawQuery(sql, args);
     };
     DB.execSQL.overload('java.lang.String').implementation = function (sql) {
       console.log('[execSQL] ' + sql);
       return this.execSQL(sql);
     };
   });
   ```

   On iOS, attach to `sqlite3_prepare_v2` in `libsqlite3.dylib` and print `args[1].readUtf8String()`, or hook `+[NSPredicate predicateWithFormat:argumentArray:]` and print the format.

4. **Confirm with benign values.** A search term `GT'probe` that appears verbatim inside the SQL text (instead of as a bound `?`), followed by `SQLiteException: near "probe": syntax error` in logcat or an `NSInvalidArgumentException` for an unparsable predicate on iOS, is the evidence. For a semantic check, a value such as `GT' OR '1'='1` in a search over the user's *own* data shows whether the result set widens. Do not run modifying statements.

#### Observation

Query construction sites with the source of each concatenated value, the trace of SQL or predicate text containing your marker, and the error or result change.

#### Evaluation

The test **fails** if a value from outside the app (user input that crosses a privilege boundary, deep-link and IPC parameters, server or sync data, files) is concatenated into SQL text, an `NSPredicate` format or a Realm query string. It **passes** if all such values are bound (`?` with `selectionArgs` or `bindArgs`, Room parameters, `sqlite3_bind_*`, `%@` and `%K` predicate arguments). Concatenating values the user types into a query over their own local data, with no other source and no privilege difference, is a robustness issue (crashes on quotes) rather than a vulnerability; say so in the report.

#### Demo

```swift
// FAIL: the tag comes from a deep link (exampleapp://notes?tag=...)
let request = NSFetchRequest<Note>(entityName: "Note")
request.predicate = NSPredicate(format: "tag == '\(tag)' AND ownerID == %@", currentUserID)
// PASS
request.predicate = NSPredicate(format: "tag == %@ AND ownerID == %@", tag, currentUserID)
```

In the failing version, a quote in the tag changes the predicate's structure and can remove the owner condition; the benign marker `GT'probe` is enough to show it, because it throws `NSInvalidArgumentException: Unable to parse the format string`, which the console shows. The Android equivalent is `db.rawQuery("SELECT * FROM notes WHERE tag = '" + tag + "'", null)`, fixed with `db.rawQuery("SELECT * FROM notes WHERE tag = ?", arrayOf(tag))`.

## Best practices

OWASP links four best practices to this weakness's tests: two for Android data from other components and providers, one for iOS deserialisation, and one for provider access control. They are summarised below with our comments, followed by code patterns for the sinks the Guler Tech checks cover.

### MASTG-BEST-0039: Prevent SQL Injection in ContentProviders

Source: [MASTG-BEST-0039](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0039/). Platform: Android.

Build provider queries from `selection` with `?` placeholders and `selectionArgs`, never from concatenated URI segments, and use `SQLiteStatement` or the binding variants of `SQLiteDatabase` methods for `insert`, `update` and `delete`. The OWASP example moves the path segment into `selectionArgs`:

```kotlin
val idSegment = uri.pathSegments[1]
val cursor = qb.query(db, projection, "id = ?", arrayOf(idSegment), null, null, sortOrder)
```

Two additions from Android's [SQL injection](https://developer.android.com/privacy-and-security/risks/sql-injection) guidance make this complete. First, the example replaces the caller's `selection` with its own; a real provider usually has to combine both, and that is exactly where `setStrict(true)`, a projection map with `setStrictColumns(true)`, and `setStrictGrammar(true)` are needed so the caller's fragments cannot escape their parentheses, name hidden columns or run subqueries. Second, injection is only one part of provider security; keeping the provider unexported or behind a `signature` permission (MASTG-BEST-0049) removes most of the attackers in the first place.

### MASTG-BEST-0057: Sanitize Data Coming from External Components

Source: [MASTG-BEST-0057](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0057/). Platform: Android.

Treat intent extras, activity results and provider results as untrusted, and validate URIs and their metadata before reading, copying or passing them on. Three concrete rules:

- **Validate the scheme.** Accept `content://` and refuse `file://` from other apps. A `content://` URI goes through a provider and its access controls; a `file://` URI is opened with the caller's own identity and can point at the caller's private files.
- **Sanitise provider-supplied file names.** OWASP suggests keeping only the final component with `File(name).name`.
- **Anchor outputs to a directory you control** (`filesDir`, `cacheDir`) and never build an output path from an intent value alone; share your own files through `FileProvider` with temporary grants rather than raw paths.

Our comments: `File(name).name` alone is not enough. `File("..").name` is `..`, and `File("").name` is empty, so `File(dir, File(name).name)` can still resolve to the parent directory or to `dir` itself. Reject `.`, `..` and empty names, and add the canonical containment check from [Secure patterns](#secure-patterns-guler-tech). Android's own [guidance](https://developer.android.com/privacy-and-security/risks/untrustworthy-contentprovider-provided-filename) ranks the options correctly: **ignore the provider's name and generate your own** (`File.createTempFile()` or a UUID), and sanitise only when a user-visible name really must be kept (store the display name separately, as data, if the UI needs it). Validate the authority too when the app expects a particular provider, and treat the stream's content as untrusted input to whatever parser reads it.

### MASTG-BEST-0064: Use Safe APIs for Object Deserialization

Source: [MASTG-BEST-0064](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0064/). Platform: iOS.

For archives an attacker can influence (files, IPC payloads, network responses, pasteboard data, extensions, shared containers):

- adopt `NSSecureCoding` (`supportsSecureCoding` returns `true`) and decode nested objects with `decodeObject(of:forKey:)`;
- archive with `archivedData(withRootObject:requiringSecureCoding: true)` and keep `requiresSecureCoding` enabled when decoding;
- unarchive the top level with `unarchivedObject(ofClass:from:)` or `unarchivedObject(ofClasses:from:)`, listing collection classes together with their element classes;
- validate decoded values before they reach security decisions, paths, URLs, commands, authorisation logic or persistent state.

Our comments: prefer not to accept keyed archives from outside the app at all. For data exchange (links, server responses, extension communication), `Codable` with `JSONDecoder` or `PropertyListDecoder` gives typed decoding without any class lookup. Keep allow-lists narrow (no `NSObject`), keep side effects out of `init?(coder:)`, use `NSSecureUnarchiveFromDataTransformer` (or a subclass listing your classes) for Core Data transformable attributes, and protect archives whose integrity matters with a MAC, since secure coding restricts types, not content.

### MASTG-BEST-0049: Restrict and Validate Access to Exported Content Providers

Source: [MASTG-BEST-0049](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0049/). Platform: Android. Documented in detail in our [MASWE-0018 note](/mobile/maswe-0018-missing-auth-on-app-components/); the essentials:

- Set `android:exported="false"` explicitly on providers only the app uses.
- When a provider must be exported, protect it with `android:readPermission`, `android:writePermission` or `android:permission`, and declare the permission with `android:protectionLevel="signature"`; a custom permission without a protection level defaults to `normal`, which any app is granted at install.
- Share files with a non-exported `FileProvider`, narrow `file_paths.xml` entries (never `<root-path>` or `path="."`), and per-URI temporary grants (`FLAG_GRANT_READ_URI_PERMISSION`), revoking explicit grants when no longer needed.

For this weakness, the point is that access control decides *who* can send input to a provider's SQL and file code. A provider reachable only by the app's own components or the developer's other signed apps makes injection a code-quality issue. It does not make it correct.

### Secure patterns (Guler Tech)

**A single containment helper, used everywhere a name from outside meets the file system (Android):**

```kotlin
fun safeChild(base: File, untrustedName: String): File {
    val name = File(untrustedName).name                       // keep the last component only
    require(name.isNotEmpty() && name != "." && name != "..") { "Invalid file name" }
    val root = base.canonicalFile
    val target = File(root, name).canonicalFile               // resolves symlinks as well as ..
    require(target.path.startsWith(root.path + File.separator)) { "Path escapes base directory" }
    return target
}

// Better still, when the name does not need to survive:
val dest = File(File(filesDir, "imports").apply { mkdirs() }, UUID.randomUUID().toString())
```

**The same on iOS:**

```swift
enum PathError: Error { case invalidName, escapesBase }

func safeChild(of base: URL, name untrusted: String) throws -> URL {
    let name = (untrusted as NSString).lastPathComponent
    guard !name.isEmpty, name != ".", name != "..", !name.contains("/") else { throw PathError.invalidName }
    let root = base.standardizedFileURL.resolvingSymlinksInPath()
    let target = root.appendingPathComponent(name).standardizedFileURL.resolvingSymlinksInPath()
    guard target.path.hasPrefix(root.path + "/") else { throw PathError.escapesBase }
    return target
}
```

**Zip extraction with containment and limits (Android):**

```kotlin
fun unzip(input: InputStream, dest: File, maxBytes: Long = 200L * 1024 * 1024, maxEntries: Int = 2000) {
    val root = dest.canonicalFile
    require(root.isDirectory && root.list().isNullOrEmpty()) { "Destination must be an empty directory" }
    var total = 0L
    var count = 0
    ZipInputStream(input).use { zis ->
        while (true) {
            val entry = zis.nextEntry ?: break
            require(++count <= maxEntries) { "Too many entries" }
            val out = File(root, entry.name).canonicalFile
            require(out.path.startsWith(root.path + File.separator)) { "Illegal entry: " + entry.name }
            if (entry.isDirectory) { out.mkdirs(); continue }
            out.parentFile?.mkdirs()
            out.outputStream().use { os ->
                val buf = ByteArray(8192)
                while (true) {
                    val n = zis.read(buf)
                    if (n < 0) break
                    total += n
                    require(total <= maxBytes) { "Archive expands beyond limit" }
                    os.write(buf, 0, n)
                }
            }
        }
    }
}
```

On iOS, use a current ZIPFoundation or SSZipArchive release, extract with the library's own `unzipItem(at:to:)` or `unzipFile(atPath:toDestination:)` rather than a hand-written entry loop, and if you must iterate entries, pass each destination through `safeChild` and skip entries of type symlink.

**Activity results: accept content URIs only, ignore the name:**

```kotlin
private val openDoc = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
    if (uri == null || uri.scheme != ContentResolver.SCHEME_CONTENT) return@registerForActivityResult
    val dest = File(File(filesDir, "imports").apply { mkdirs() }, UUID.randomUUID().toString())
    contentResolver.openInputStream(uri)?.use { input -> dest.outputStream().use { input.copyTo(it) } }
    // keep the display name, if needed, as data in your database, never as a path
}
```

**Java deserialisation, if it cannot be removed: a look-ahead allow-list.** Every class in the stream, including serialisable superclasses and array types, passes through `resolveClass()`:

```kotlin
class AllowListObjectInputStream(input: InputStream, private val allowed: Set<String>) : ObjectInputStream(input) {
    override fun resolveClass(desc: ObjectStreamClass): Class<*> {
        if (desc.name !in allowed) throw InvalidClassException(desc.name, "Class not allowed")
        return super.resolveClass(desc)
    }
}
// Usage: AllowListObjectInputStream(stream, setOf("com.example.app.Settings")).readObject()
```

The better fix is a data format that maps onto declared types (kotlinx.serialization, Moshi, protobuf) and typed IPC reads (`IntentCompat.getParcelableExtra(intent, name, Foo::class.java)`).

**Provider queries:**

```kotlin
val qb = SQLiteQueryBuilder()
qb.setTables("notes")
qb.setProjectionMap(mapOf("_id" to "_id", "title" to "title"))
qb.setStrict(true)
qb.setStrictColumns(true)     // API 29
qb.setStrictGrammar(true)     // API 29
when (uriMatcher.match(uri)) {
    NOTE_ID -> qb.appendWhere("_id = " + ContentUris.parseId(uri))   // parseId only returns a long
}
return qb.query(db, projection, selection, selectionArgs, null, null, sortOrder)
```

**XML: reject any DOCTYPE.** With `XmlPullParser`, `nextToken()` reports the document type declaration as a `DOCDECL` token, which you can refuse whatever features the implementation supports:

```kotlin
val p = Xml.newPullParser().apply { setInput(stream, "UTF-8") }
var ev = p.nextToken()
while (ev != XmlPullParser.END_DOCUMENT) {
    if (ev == XmlPullParser.DOCDECL) throw XmlPullParserException("DOCTYPE not allowed")
    // handle START_TAG, TEXT, END_TAG ...
    ev = p.nextToken()
}
```

With `DocumentBuilderFactory` or `SAXParserFactory`, set `http://apache.org/xml/features/disallow-doctype-decl` to `true` and **let the call fail loudly** if the parser does not support it, so a configuration problem shows up in testing instead of silently leaving the parser open. On iOS, leave `shouldResolveExternalEntities` at `false` and abort parsing from `parser(_:foundExternalEntityDeclarationWithName:publicID:systemID:)` and `parser(_:foundInternalEntityDeclarationWithName:value:)` if the input format never needs a DTD.

**Untrusted text in approval screens:**

```kotlin
fun forDisplay(untrusted: String, max: Int = 40): String {
    val cleaned = untrusted.filterNot {
        val t = Character.getType(it)
        t == Character.CONTROL.toInt() || t == Character.FORMAT.toInt()   // drops line breaks and bidi overrides
    }
    return BidiFormatter.getInstance().unicodeWrap(cleaned.take(max))
}
```

Show the result in its own labelled field ("Payee:"), not inside a sentence the app wrote.

## Rating findings

Rate on three things: **who can supply the input** (any app on the device without permissions; a web page or message link the user taps; a file the user is persuaded to import or share; a server the attacker controls or has compromised; only someone with root or physical access), **what the sink does with it** (code execution in the app, writing or reading arbitrary app files, changing a security decision, widening a query, crashing), and **what is at stake** (credentials and tokens, personal or financial data, account actions, nothing sensitive). Code-quality findings, a dangerous API used on trusted data, start at Low or Info and move up only with a reachable source.

| Rating | Conditions |
|---|---|
| **Critical** | Without user interaction, or with one tap on a link, an attacker achieves code execution in the app's context (overwriting a native library, DEX, JavaScript bundle or other file the app later loads; deserialisation whose reachable classes write or load code; a native memory-corruption bug reached by remote input) or obtains or overwrites authentication material (tokens, credentials, keys) for the user's account. |
| **High** | Any installed app or a link with one tap reads or overwrites sensitive app data through path traversal, zip extraction, XXE or SQL injection; object substitution or an injected query changes an authorisation or transaction decision; a returned `file://` URI makes the app read and export its own private files; XXE resolves external entities on input from a server or file the attacker can supply. |
| **Medium** | The same impacts but the path needs a meaningful user choice (picking the attacker's app in a chooser, importing a file the attacker sent), or the data at stake is not sensitive; SQL injection in a provider whose callers could already read the whole table but which shares the database with other tables of moderate sensitivity; approval screens where untrusted text can hide or imitate transaction details; uncontrolled format strings in Objective-C or C on remote input without demonstrated memory impact. |
| **Low** | Denial of service through malformed input (entity expansion, decompression bombs, unchecked exceptions in exported components, `String.format` crashes); injection or traversal only reachable by the app's own components or with root or physical access; a sink with a plausible but unconfirmed untrusted source; Android 14's zip validator blocking an otherwise vulnerable extractor on all supported releases (the app's `minSdkVersion` is 34 or higher and it targets 34 or higher). |
| **Info** | Unsafe APIs used only on bundled or app-private data (deprecated `NSKeyedUnarchiver` calls, `ObjectInputStream` on an asset); `#`-constrained concatenation flagged by static rules; missing defence-in-depth such as strict query-builder settings on a provider that only the app can reach. |

Raise a level when the path runs automatically (at start-up, on every sync or push), when the attacker position is remote (a server-side or link-delivered input rather than an installed app), or when the affected data belongs to other users (shared or synced data, admin content). Lower a level when exploitation needs the user to approve an obviously unrelated app in a chooser and the impact is limited to the app's non-sensitive data. Do not lower for platform mitigations that only exist on newer releases than the app's `minSdkVersion` or `MinimumOSVersion` (Android 14's zip validator, Android 16's intent hardening): many users run older versions. In the report give the source and the sink with class and method names, the manifest or `Info.plist` entry that makes the source reachable, the `targetSdkVersion` or deployment target, the OS versions tested, the hook output or file listing that proves the path, and the fix at the sink.

## References

- OWASP MASWE: [MASWE-0050: Unsafe Handling of Untrusted Data](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/); related [MASWE-0018](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0018/), [MASWE-0029](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0029/), [MASWE-0032](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0032/), [MASWE-0035](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0035/), [MASWE-0057](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0057/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0021](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0021/), [MASTG-KNOW-0117](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0117/), [MASTG-KNOW-0138](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0138/), [MASTG-KNOW-0075](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0075/), [MASTG-KNOW-0025](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0025/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0337](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0337/), [MASTG-TEST-0339](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0339/), [MASTG-TEST-0375](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0375/), [MASTG-TEST-0386](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0386/); related [MASTG-TEST-0338](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0338/), [MASTG-TEST-0302](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0302/); legacy [MASTG-TEST-0002](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0002/), [MASTG-TEST-0025](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0025/), [MASTG-TEST-0026](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0026/), [MASTG-TEST-0034](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0034/), [MASTG-TEST-0079](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0079/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0100](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0100/MASTG-DEMO-0100/), [MASTG-DEMO-0102](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0102/MASTG-DEMO-0102/), [MASTG-DEMO-0139](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0139/MASTG-DEMO-0139/), [MASTG-DEMO-0141](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0141/MASTG-DEMO-0141/), [MASTG-DEMO-0149](https://mas.owasp.org/MASTG/demos/ios/MASVS-CODE/MASTG-DEMO-0149/MASTG-DEMO-0149/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0039](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0039/), [MASTG-BEST-0057](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0057/), [MASTG-BEST-0064](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0064/), [MASTG-BEST-0049](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0049/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0169](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0169/) (CC BY-SA 4.0)
- OWASP MASTG tools: [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [Frooky (MASTG-TOOL-0145)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0145/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [adb (MASTG-TOOL-0004)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/), [radare2 for iOS (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/) (CC BY-SA 4.0)
- OWASP cheat sheets: [Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html), [XML External Entity Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- Android Developers, risk pages: [Path traversal](https://developer.android.com/privacy-and-security/risks/path-traversal), [Zip path traversal](https://developer.android.com/privacy-and-security/risks/zip-path-traversal), [SQL injection](https://developer.android.com/privacy-and-security/risks/sql-injection), [Unsafe deserialization](https://developer.android.com/privacy-and-security/risks/unsafe-deserialization), [XML external entities injection](https://developer.android.com/privacy-and-security/risks/xml-external-entities-injection), [Untrustworthy ContentProvider-provided filename](https://developer.android.com/privacy-and-security/risks/untrustworthy-contentprovider-provided-filename), [Use of native code](https://developer.android.com/privacy-and-security/risks/use-of-native-code)
- Android Developers, guides and reference: [Content provider basics: protect against malicious input](https://developer.android.com/guide/topics/providers/content-provider-basics#Injection), [Android 14 behaviour changes (zip path traversal)](https://developer.android.com/about/versions/14/behavior-changes-14#zip-path-traversal), [`SQLiteQueryBuilder`](https://developer.android.com/reference/android/database/sqlite/SQLiteQueryBuilder), [`UriMatcher`](https://developer.android.com/reference/android/content/UriMatcher), [`OpenableColumns`](https://developer.android.com/reference/android/provider/OpenableColumns), [`ZipPathValidator`](https://developer.android.com/reference/dalvik/system/ZipPathValidator), [`Intent`](https://developer.android.com/reference/android/content/Intent), [Getting a result from an activity](https://developer.android.com/training/basics/intents/result), [Request a shared file](https://developer.android.com/training/secure-file-sharing/request-file), [`FileProvider`](https://developer.android.com/reference/androidx/core/content/FileProvider)
- Apple Developer Documentation: [`NSKeyedUnarchiver`](https://developer.apple.com/documentation/foundation/nskeyedunarchiver), [`init(forReadingFrom:)`](https://developer.apple.com/documentation/foundation/nskeyedunarchiver/init%28forreadingfrom:%29), [`requiresSecureCoding`](https://developer.apple.com/documentation/foundation/nskeyedunarchiver/requiressecurecoding), [`unarchivedObject(ofClass:from:)`](https://developer.apple.com/documentation/foundation/nskeyedunarchiver/unarchivedobject%28ofclass:from:%29), [`NSSecureCoding`](https://developer.apple.com/documentation/foundation/nssecurecoding), [Archives and serialization](https://developer.apple.com/documentation/foundation/archives-and-serialization), [`XMLParser.shouldResolveExternalEntities`](https://developer.apple.com/documentation/foundation/xmlparser/shouldresolveexternalentities), [`NSSecureUnarchiveFromDataTransformer`](https://developer.apple.com/documentation/foundation/nssecureunarchivefromdatatransformer); [Secure Coding Guide: Validating Input and Interprocess Communication](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/ValidatingInput.html) (archived)
- Research and advisories: Microsoft Threat Intelligence, [Dirty Stream Attack: Turning Android Share Targets Into Attack Vectors](https://i.blackhat.com/Asia-23/AS-23-Valsamaras-Dirty-Stream-Attack-Turning-Android.pdf) (Black Hat Asia 2023); Snyk, [Zip Slip vulnerability](https://snyk.io/research/zip-slip-vulnerability); [CVE-2023-39138](https://nvd.nist.gov/vuln/detail/CVE-2023-39138) (ZIPFoundation), [CVE-2022-36943](https://nvd.nist.gov/vuln/detail/CVE-2022-36943) (SSZipArchive), [CVE-2021-0928](https://nvd.nist.gov/vuln/detail/CVE-2021-0928) (Android parcel mismatch), [CVE-2015-3784](https://nvd.nist.gov/vuln/detail/CVE-2015-3784) (iOS XXE), [CVE-2015-5237](https://nvd.nist.gov/vuln/detail/CVE-2015-5237) (protobuf)
- CWE: [CWE-20](https://cwe.mitre.org/data/definitions/20.html), [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CWE-73](https://cwe.mitre.org/data/definitions/73.html), [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CWE-116](https://cwe.mitre.org/data/definitions/116.html), [CWE-134](https://cwe.mitre.org/data/definitions/134.html), [CWE-345](https://cwe.mitre.org/data/definitions/345.html), [CWE-348](https://cwe.mitre.org/data/definitions/348.html), [CWE-349](https://cwe.mitre.org/data/definitions/349.html), [CWE-502](https://cwe.mitre.org/data/definitions/502.html), [CWE-611](https://cwe.mitre.org/data/definitions/611.html), [CWE-924](https://cwe.mitre.org/data/definitions/924.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
