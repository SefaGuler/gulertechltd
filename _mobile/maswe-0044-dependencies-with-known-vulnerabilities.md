---
title: "MASWE-0044: Dependencies with Known Vulnerabilities"
date: 2026-11-10 10:03:00 +0000
subcategory: code
summary: "Finding known-vulnerable libraries in Android and iOS apps: SBOMs, Gradle, SwiftPM and CocoaPods scans, binary fingerprinting and reachability."
refs: [MASWE-0044, MASVS-CODE-3, CWE-1395, CWE-1357]
tags: [android, ios, masvs-code, sca, sbom, supply-chain]
---

This note is part of our [MASVS-CODE guide](/mobile/masvs-code-code-quality-guide/) and covers OWASP [MASWE-0044](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0044/): apps that ship third-party libraries, SDKs or frameworks with publicly known vulnerabilities. Most of the code in a typical mobile app was written by someone else: networking and JSON stacks, image loaders, analytics and advertising SDKs, crypto and database libraries, cross-platform runtimes, and the native code that some of them carry. Once that code is in the package, its bugs are the app's bugs, and the published ones come with an advisory, a version range and sometimes an exploit. The note explains how dependencies get into Android and iOS builds and what survives in the APK or IPA. It then covers SBOMs, package identifiers and vulnerability databases, the four OWASP tests with their demos (including two demos whose conclusions do not hold up), our black-box methods for identifying libraries and versions in a release build, and the part most scanner reports skip: deciding whether a reported CVE actually affects the app, and how to rate it.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Third-Party Libraries (MASTG-KNOW-0004)](#android-third-party-libraries-mastg-know-0004)
  - [iOS: Third-Party Libraries (MASTG-KNOW-0059)](#ios-third-party-libraries-mastg-know-0059)
  - [Background: SBOMs, package identifiers and vulnerability data](#background-sboms-package-identifiers-and-vulnerability-data)
- [Tests](#tests)
  - [Before you start: decide what ships](#before-you-start-decide-what-ships)
  - [MASTG-TEST-0272: Identify Dependencies with Known Vulnerabilities in the Android Project (Android)](#mastg-test-0272-identify-dependencies-with-known-vulnerabilities-in-the-android-project-android)
  - [MASTG-TEST-0274: Dependencies with Known Vulnerabilities in the App's SBOM (Android)](#mastg-test-0274-dependencies-with-known-vulnerabilities-in-the-apps-sbom-android)
  - [MASTG-TEST-0273: Identify Dependencies with Known Vulnerabilities by Scanning Dependency Managers Artifacts (iOS)](#mastg-test-0273-identify-dependencies-with-known-vulnerabilities-by-scanning-dependency-managers-artifacts-ios)
  - [MASTG-TEST-0275: Dependencies with Known Vulnerabilities in the App's SBOM (iOS)](#mastg-test-0275-dependencies-with-known-vulnerabilities-in-the-apps-sbom-ios)
  - [GT-CODE-0044-1: Libraries and versions in a release APK (Android)](#gt-code-0044-1-libraries-and-versions-in-a-release-apk-android)
  - [GT-CODE-0044-2: Frameworks and versions in an IPA (iOS)](#gt-code-0044-2-frameworks-and-versions-in-an-ipa-ios)
  - [GT-CODE-0044-3: Reachability and exploitability of a reported CVE (Android, iOS)](#gt-code-0044-3-reachability-and-exploitability-of-a-reported-cve-android-ios)
- [Secure implementation](#secure-implementation)
  - [Android (Gradle)](#android-gradle)
  - [iOS (SwiftPM, CocoaPods, Carthage)](#ios-swiftpm-cocoapods-carthage)
  - [Process](#process)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0044 applies when an app includes third-party libraries, SDKs or frameworks that contain publicly known vulnerabilities. The OWASP requirement is *"The app's third-party components are regularly checked for known vulnerabilities."* It maps to [MASVS-CODE-3](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/) ("The app only uses software components without known vulnerabilities"), to the v1 requirement MSTG-CODE-5, and to two CWEs: [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) (Dependency on Vulnerable Third-Party Component) and [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) (Reliance on Insufficiently Trustworthy Component). It is tagged for the L1, L2 and EUDIW profiles, so it is a baseline expectation for every app. In the Android Core App Quality guidelines it corresponds to the SDK maintenance and security provider initialisation items.

The MASVS control text is deliberately modest. A full white-box review of every component is not realistic in a mobile assessment, so MASVS-CODE-3 targets the "low-hanging fruit": vulnerabilities that are already public and can be found by matching component names and versions against advisory data. That makes this weakness unusual. Detection is cheap and largely automated. The real work is getting an accurate inventory, throwing out matches that do not apply, and working out what the remaining ones mean for this particular app.

OWASP describes the threat as MAS-THREAT-0044, *"Attackers can exploit publicly known vulnerabilities in the app's dependencies"*, reached through a single attack:

| Attack | Description | Attacker position |
|---|---|---|
| MAS-ATTACK-0073 | Identifying vulnerable dependency versions in the app package and using public advisories or exploits | Depends on the component: a network attacker (TLS and HTTP libraries), a malicious server or piece of content (parsers, decoders, WebView JavaScript), another app on the device (libraries reachable through IPC), or someone with the device in hand |

The first half of that attack costs the attacker almost nothing. The app package is public, library versions are often readable from it in minutes (see [GT-CODE-0044-1](#gt-code-0044-1-libraries-and-versions-in-a-release-apk-android) and [GT-CODE-0044-2](#gt-code-0044-2-frameworks-and-versions-in-an-ipa-ios)), and advisories usually name the vulnerable function. That asymmetry is the reason the weakness exists: a bug in first-party code has to be found, while a bug in a dependency is already documented.

Both platform owners put the responsibility on the app developer. Google Play's [Using SDKs safely and securely](https://support.google.com/googleplay/android-developer/answer/13326895) says that if you include an SDK, you are responsible for making sure its code and practices comply with Play policy, and that data collected by an SDK counts as data collected by the app. Apple's [App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/) make the developer responsible for everything in the app, "including ad networks, analytics services, and third-party SDKs", and Apple's [third-party SDK requirements](https://developer.apple.com/support/third-party-SDK-requirements/) page puts it plainly: *"you are responsible for all the code the SDK includes in your app"*. The privacy side of that (undeclared data collection by SDKs) is covered by MASWE-0073 in the PRIVACY category. This note is about security vulnerabilities.

> **Note:** The weakness file also carries `maswe-beta: [MASWE-0076]`. That is the ID this weakness had in the beta numbering (the OWASP demo projects are still named `MASTestApp-*-MASWE-0076`), not a reference to the current MASWE-0076, which is a privacy weakness about data management controls.

Keep the neighbouring weaknesses apart:

| Question | Where it lives |
|---|---|
| Does a component the app ships have a *published* vulnerability that applies to the shipped version? | This note (MASWE-0044) |
| Does the app use an API that the platform has deprecated for security reasons (`UIWebView`, old signing schemes, platform crypto providers)? | [MASWE-0046](/mobile/maswe-0046-use-of-deprecated-apis/) |
| Was code added to the app (or to one of its dependencies) on purpose to do harm, e.g. a compromised SDK release? | [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) |
| Does the app download and run code at runtime, outside its signed package? | [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/) |
| Were native libraries built without stack protection, PIE, RELRO and similar flags? | [MASWE-0045](/mobile/maswe-0045-compiler-security-features-not-used/) |
| Does the device run an OS version whose system components (WebView, TLS, media codecs) are still patched? | [MASWE-0041](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/) |
| Does the app update the Google Play services security provider before making TLS connections? | [MASWE-0026](/mobile/maswe-0026-insecure-tls-protocol-versions/) (`ProviderInstaller`) |

A "known vulnerability" in this note means a public advisory (a CVE, a GitHub Security Advisory, an OSV entry, a vendor security bulletin) whose affected range includes the version the app ships. "Outdated" alone is not a known vulnerability. An old library with no advisories is a maintenance finding at most, and an advisory that matched the wrong product is not a finding at all. Both come up later, because they make up most of what scanners report.

## Modes of Introduction

**Direct dependencies.** The developer declares a library in `build.gradle(.kts)` or a version catalogue, `Package.swift` or the Xcode package list, a `Podfile` or a `Cartfile`, and the package manager fetches it. The declared version is old when the app is built, or becomes vulnerable later while the app keeps shipping it. The same applies to first-party SDKs from Google, Apple's open-source packages, and vendor SDKs.

**Transitive dependencies.** Most of the components in an app were never declared by its developer. An SDK pulls in its own HTTP client, JSON parser, protobuf runtime and logging library, each with its own dependencies. Gradle resolves version conflicts by picking the highest requested version, so a transitive library can be newer *or* older than the developer expects, and a `strictly` constraint or a forced version somewhere in the graph can hold an old one in place. On iOS, `Package.resolved`, `Podfile.lock` and `Cartfile.resolved` all record the full resolved set, but nobody reads them.

**Vendored and copied code.** Source files or prebuilt binaries copied into the repository (`third_party/`, a `libs/*.jar`, an `.aar` or `.xcframework` dropped into the project, an amalgamated `sqlite3.c`, a minified `jquery.min.js` in `assets/`). No package manager knows about them, so no update tool or scanner that reads manifests will see them.

**Closed-source binary SDKs.** Payment, identity-verification, anti-fraud, advertising and RASP SDKs are usually shipped as binaries. They often embed their own copies of open-source libraries (OpenSSL, libcurl, SQLite, protobuf, zlib), sometimes statically linked and renamed, and their release notes rarely say which versions.

**Native libraries.** `.so` files in an APK and static or dynamic libraries in an iOS binary: OpenSSL and BoringSSL, SQLite and SQLCipher, libwebp, libpng, libjpeg-turbo, FFmpeg, zlib, libcurl. Memory-safety bugs in these are the ones that turn into code execution, and they are the hardest to inventory because they carry no package metadata.

**Dynamically loaded dependencies.** Code loaded at runtime (a DEX or JAR downloaded by an SDK, a JavaScript bundle fetched from a server, a plugin framework) does not appear in any build file. Its version is whatever the server delivers. Whether the loading itself is acceptable is [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/); here the point is that it escapes the inventory.

**Platform security components the app relies on.** On Android, apps that use the Google Play services security provider have to install it themselves (`ProviderInstaller`) to get current TLS fixes. On both platforms, system libraries such as WebKit, ImageIO, the TLS stack and media codecs are patched only through OS updates, which is why the supported OS range matters ([MASWE-0041](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/)).

**Cross-platform frameworks.** Flutter, React Native, Cordova, Capacitor, .NET MAUI and Unity bring a runtime (the Flutter engine, Hermes or JavaScriptCore, a WebView bridge) plus their own package ecosystems (`pubspec.lock`, `package-lock.json` or `yarn.lock`, NuGet) and native plugins. The native project files then show only the framework, not the packages that run inside it.

**JavaScript in WebViews.** Libraries bundled in `assets/` or the app bundle and loaded into a WebView (jQuery, Angular, Lodash, markdown renderers, PDF viewers) are dependencies too. A known XSS in one of them matters as soon as the page renders content an attacker can influence.

**Build and test tooling mistaken for app code.** The reverse case: test frameworks, annotation processors, Gradle plugins and CI actions appear in SBOMs and scanner reports although they never reach the device. They are a mode of introduction for *false positives*. OWASP's own suppression file for the Android demos exists for this reason: the gRPC and Netty matches it silences come from the Android test platform, not from the app. The opposite mistake is just as easy: an SBOM tool can label a shipped library as test-only (see [MASTG-TEST-0274](#mastg-test-0274-dependencies-with-known-vulnerabilities-in-the-apps-sbom-android)).

## Impact

The impact is inherited from the vulnerable component and depends on what the app does with it. Typical classes, with real examples:

- **Loss of transport security.** A flaw in a networking or TLS library defeats certificate validation or pinning, and a network attacker can read and modify traffic the app considers protected. Examples: OkHttp before 2.7.4 and 3.x before 3.1.2 (CVE-2016-2402, pinning bypass through a chain that contains the pinned certificate and a non-pinned trusted CA), OkHttp before 4.9.2 (CVE-2021-0341, hostname verification accepting a certificate for the wrong domain), AFNetworking 2.5.1 (default trust evaluation that effectively disabled certificate validation, fixed in 2.5.2) and AFNetworking before 2.5.3 (CVE-2015-3996, domain name not validated when pinning was off). See [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/) and [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/) for the testing side.
- **Code execution from content.** Memory-corruption bugs in decoders and parsers that handle attacker-supplied data: images, fonts, media, archives, documents. The libwebp heap overflow CVE-2023-4863 (fixed in libwebp 1.3.2) was exploited in the wild and affected every app that bundled its own vulnerable copy, independently of the browser and OS patches. A bug like this gives an attacker who can get an image in front of the app (a chat message, a profile picture, an ad) code execution in the app's sandbox.
- **Code execution through unsafe defaults.** Deserialisation and expression libraries that instantiate arbitrary types, such as SnakeYAML's default `Constructor` (CVE-2022-1471). These matter on mobile when the parsed data comes from a server, a deep link, an IPC call or a file the user opens.
- **Data exposure.** Libraries that log or echo headers, write caches to shared locations, or extract archives without path checks (zip path traversal is one of the issue types Google Play reports for SDKs).
- **Denial of service.** Crashes and resource exhaustion from crafted input (deeply nested JSON, decompression bombs, malformed HTTP responses). Usually low impact on a phone, higher when the crash can be triggered remotely and repeatedly, for example by a message that crashes the app on every launch.
- **Platform and regulatory consequences.** Google Play shows alerts in Play Console for apps that include SDK versions with vulnerabilities reported through the SDK Console, and rejects new releases that contain SDK versions labelled as causing policy violations. Regulators and contracts (PCI DSS, the EU Cyber Resilience Act's obligations for products with digital elements, sector rules) increasingly expect a component inventory and timely patching, so an app that ships a library with a critical public CVE can be a compliance problem before anyone exploits it.

## Mitigations

- **Keep an SBOM for every release.** Generate a CycloneDX (or SPDX) SBOM from the resolved dependency graph of the release build and keep it with the build artefacts. The NTIA [minimum elements](https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf) are supplier, component name, version, other unique identifiers (a purl), dependency relationships, the author of the SBOM data and a timestamp. CISA's [SBOM types](https://www.cisa.gov/sites/default/files/2023-04/sbom-types-document-508c.pdf) document distinguishes design, source, build, analysed, deployed and runtime SBOMs; for an app you want a *build* SBOM (what the build actually resolved), backed by an *analysed* one (what you can see in the binary) for components that no package manager knows about. [NIST SP 800-218](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf) (SSDF) task PS.3.2 asks for the same provenance data.
- **Scan continuously, not once.** Run SCA in CI on the release configuration and fail the build above an agreed severity, and also monitor the SBOMs of *released* versions (Dependency-Track does this), because new advisories appear for versions that were clean on release day. The OWASP [Vulnerable Dependency Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html) describes the triage cases (fix available, fix not available, not affected).
- **Update deliberately and pin what you build.** Use exact versions (no `+` ranges in Gradle, no unpinned branches in SwiftPM), commit lock files (`gradle.lockfile`, `Package.resolved`, `Podfile.lock`, `Cartfile.resolved`), verify artefact checksums (Gradle dependency verification, SwiftPM's `binaryTarget` checksums, CocoaPods' `SPEC CHECKSUMS`), and use an update bot (Dependabot, Renovate) so security releases arrive as reviewable changes.
- **Remove what you do not use.** Every SDK you drop is a set of future advisories you will not have to triage. Keep test and debug libraries in `testImplementation`, `androidTestImplementation` and `debugImplementation`, or in test targets on iOS.
- **Use trusted sources.** Official repositories (Google Maven, Maven Central, the vendor's own SwiftPM repository or CocoaPods spec), maintained projects, and SDK vendors that publish security advisories and changelogs. Check the [Google Play SDK Index](https://play.google.com/sdks) before adding an Android SDK. Signed XCFrameworks and privacy manifests are the iOS equivalents for binary SDKs.
- **Keep the platform security provider current** on Android (`ProviderInstaller.installIfNeeded()` or the asynchronous variant) and do not bundle your own TLS stack unless you also commit to patching it.
- **Record why an advisory does not apply.** When a vulnerable component stays in the build because the vulnerable code is not reachable, say so in a VEX statement or the scanner's suppression file, with the reasoning and a review date, so the decision is visible rather than silent.

## Knowledge

OWASP links two Knowledge pages to this weakness, one per platform, both titled "Third-Party Libraries". The Android one already has a long standalone note on this site, so it gets a summary here. The iOS one is covered in full. A third section explains the SBOM formats, identifiers and databases that all four tests depend on; it is our background material, not an OWASP Knowledge page.

### Android: Third-Party Libraries (MASTG-KNOW-0004)

Source: [MASTG-KNOW-0004](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0004/). Deep dive on this site: [Third-Party Libraries in Android Apps (MASTG-KNOW-0004)](/mobile/mastg-know-0004-third-party-libraries/), which covers inventory from a decompiled APK, OSV queries, reachability, debug libraries left in release builds, WebView and cross-platform layers, and licence exposure (LGPL and other copyleft obligations) in detail. The short version follows, plus the build-system detail the tests below rely on.

MASTG splits libraries into two groups. Some should never be in the production app: test and build-time libraries such as Mockito or Javassist. Others are packaged on purpose, such as OkHttp. The packaged ones bring three risks: a vulnerability in the library becomes a vulnerability in the app (MASTG's example is OkHttp's certificate-chain pinning bypass, CVE-2016-2402; MASTG says "prior to 2.7.5", the CVE record says before 2.7.4 and 3.x before 3.1.2), a library that is no longer maintained accumulates bugs nobody reports or fixes, and a copyleft licence can create legal obligations for the app owner. The same applies to JavaScript libraries running in WebViews and to plugins of cross-platform frameworks.

#### What actually ships: Gradle configurations

Whether a declared library ends up in the APK depends on its configuration, and getting this right removes a large share of false positives:

| Configuration | In the release APK? | Notes |
|---|---|---|
| `implementation`, `api`, `runtimeOnly` | Yes | `api` also exposes it to dependent modules; all three appear in `releaseRuntimeClasspath` |
| `compileOnly` | No | Compile-time only (annotations, provided APIs) |
| `ksp`, `kapt`, `annotationProcessor` | No | Code generators; their *output* ships, the processor does not |
| `debugImplementation` | No (debug only) | Debug tools (LeakCanary, Chucker, Flipper) |
| `releaseImplementation`, `<flavor>Implementation` | Only in matching variants | Check the variant you are testing |
| `testImplementation` | No | Local JVM tests |
| `androidTestImplementation` | No | Instrumented test APK, not the app APK |
| Build plugins (`plugins { }`, `buildscript { }`) | No | Gradle and AGP tooling; a supply-chain concern for the build, not a runtime one |

The authoritative list of what the release build resolves is the `releaseRuntimeClasspath` configuration of the application module (or `<flavor>ReleaseRuntimeClasspath` with flavours). Gradle resolves conflicts by choosing the highest requested version unless a constraint says otherwise, so the resolved version can differ from every declared one. `./gradlew :app:dependencyInsight --dependency okio --configuration releaseRuntimeClasspath` explains which path pulled a version in and why it won.

#### What survives in the APK

Libraries do not ship as JARs. AGP converts them to DEX and merges everything into `classes*.dex`, and R8 (when `isMinifyEnabled = true`) renames classes and removes code the app never calls. That has two consequences. A binary-only scan sees much less than the build does, which is why OWASP's Android tests scan the project rather than the APK. And a vulnerable class that R8 removed is not in the app at all, which matters for [reachability](#gt-code-0044-3-reachability-and-exploitability-of-a-reported-cve-android-ios). Some metadata does survive:

- `META-INF/*.version` files: AndroidX, Jetpack and Kotlin coroutines libraries each ship a one-line file such as `META-INF/androidx.core_core.version` containing the exact version.
- `*.properties` files at the APK root: Google Play services and Firebase libraries ship files such as `play-services-basement.properties` with `version=` and `client=` lines.
- `META-INF/*.kotlin_module` files name the Kotlin modules that were packaged (presence, not version).
- `lib/<abi>/*.so`: native libraries, which carry their own version strings and symbols.
- `assets/`: JavaScript bundles, WebView libraries, React Native and Cordova code, ML models.
- String constants such as `okhttp/4.9.1` (OkHttp's User-Agent), which survive minification because they are used at runtime.

AGP also embeds a record of the app's dependencies in the APK and App Bundle so that Play Console can warn about known issues. According to the [Android build documentation](https://developer.android.com/build/dependencies) this data is compressed, encrypted with a Google Play signing key and stored in the signing block. You cannot read it as a tester, and its absence (`dependenciesInfo { includeInApk = false; includeInBundle = false }`) only means Play Console cannot warn the developer.

#### Google Play SDK Index and SDK Console

Google runs a server-side check on top of this. SDK providers register in the SDK Console, can mark versions as outdated or deprecated, and receive reports of vulnerabilities and policy problems in their SDK versions. The [Play SDK Index](https://play.google.com/sdks) shows registered SDKs, their permissions and labels. When an app uses a labelled version, three places light up:

- **Play Console** shows an alert for SDK versions with reported vulnerabilities, and rejects new app versions that contain SDK versions labelled as causing policy violations ([SDK Console help on vulnerabilities and policy labels](https://support.google.com/googleplay/android-developer/answer/14514531)). The vulnerability types Google lists include static keys and IVs, ECB mode, zip path traversal, implicit `PendingIntent`s, implicit internal intents, known-vulnerable JavaScript libraries, OAuth in a WebView and leaked GCP keys.
- **Android Studio** shows "SDK insights" lint warnings in the version catalogue and the Project Structure dialog when an SDK in the index is outdated, deprecated, non-compliant or has known vulnerabilities ([Add build dependencies](https://developer.android.com/build/dependencies)). The standard `GradleDependency` lint check separately flags dependencies with newer versions available.
- **The SDK Index website**, which you can check manually for every SDK you identify.

These are useful signals, but limited to SDKs registered in the index and to issues reported through it. They are not a replacement for a CVE scan of the whole graph.

### iOS: Third-Party Libraries (MASTG-KNOW-0059)

Source: [MASTG-KNOW-0059](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0059/).

iOS apps rely on third-party code for the same reasons as Android apps, and the same three risks apply: vulnerabilities, unmaintained code and licence obligations (see the [Android deep dive](/mobile/mastg-know-0004-third-party-libraries/) for the licence side, which is identical). MASTG's example is AFNetworking 2.5.1, whose default trust evaluation effectively disabled certificate validation, so any app using it to talk to its API could be intercepted by a network attacker. The 2.5.2 release fixed that, and a second issue (CVE-2015-3996, the domain name not checked when no pinning mode was set) was fixed in 2.5.3. MASTG also separates libraries that should not be in the production app (OHHTTPStubs and other test helpers) from libraries that should (Alamofire).

What is harder on iOS is the inventory, because there are four ways to bring code in, and because the IPA keeps much less package metadata than an APK.

#### Integration routes

| Route | Declared in | Resolved versions in | Typical linkage | Notes |
|---|---|---|---|---|
| Swift Package Manager | `Package.swift`, or the Xcode project's package list (stored in `project.pbxproj`) | `Package.resolved` | Static by default | Built into Xcode since Xcode 11; Swift, Objective-C, C and C++ |
| CocoaPods | `Podfile` (and each pod's `.podspec`) | `Podfile.lock` (copied to `Pods/Manifest.lock`) | Static libraries, or dynamic frameworks with `use_frameworks!` | Ruby tool, central Specs repository |
| Carthage | `Cartfile` | `Cartfile.resolved` | Whatever the dependency builds (usually dynamic) | Builds into `Carthage/Build/`; the developer embeds the results manually |
| Manual / binary | Nothing, or a README | Nothing | Either | Vendored source, `.framework`, `.xcframework`, `.a` files committed to the repo or downloaded from a vendor |

Cross-platform apps add a layer: Flutter plugins arrive through CocoaPods or SwiftPM with Dart packages in `pubspec.lock`, React Native libraries through CocoaPods with JavaScript packages in `package-lock.json` or `yarn.lock`, and Cordova and Capacitor plugins through their own configuration. Scan both layers.

#### Swift Package Manager

`Package.swift` states *requirements*: `.package(url: "https://github.com/Alamofire/Alamofire.git", from: "5.8.0")` accepts anything from 5.8.0 up to the next major version, and `exact:`, `.upToNextMinor(from:)`, `branch:` and `revision:` are the other forms. The actual versions are recorded in `Package.resolved`, a JSON file with one *pin* per package:

```json
{
  "pins" : [
    {
      "identity" : "swift-nio",
      "kind" : "remoteSourceControl",
      "location" : "https://github.com/apple/swift-nio.git",
      "state" : {
        "revision" : "6aa9347d9bc5bbfe6a84983aec955c17ffea96ef",
        "version" : "2.33.0"
      }
    }
  ],
  "version" : 3
}
```

The top-level `version` is the file format (1, 2 or 3; format 1 uses an `object.pins` wrapper and different key names). `pins` is flat and contains **every** resolved package, transitive ones included, so `Package.resolved` alone gives you the full SwiftPM graph. A pin that tracks a branch has `branch` and `revision` but no `version`, which makes advisory matching impossible without mapping the commit to a release. Where to find the file:

- Package-based projects: next to `Package.swift`.
- Xcode projects: `<App>.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved`.
- Workspaces: `<App>.xcworkspace/xcshareddata/swiftpm/Package.resolved`.

Packages can also ship prebuilt binaries with `.binaryTarget(name:url:checksum:)`. SwiftPM verifies the checksum on download, but the version of the code inside is whatever the vendor built. SwiftPM links library products statically unless the package declares `type: .dynamic`, so SwiftPM dependencies usually disappear into the app binary.

#### CocoaPods

The `Podfile` names pods and version requirements (`pod 'Alamofire', '~> 5.8'`). `Podfile.lock` records the outcome:

```yaml
PODS:
  - Alamofire (5.8.1)
  - GoogleUtilities/Environment (7.13.0):
    - PromisesObjC (< 3.0, >= 1.2)

DEPENDENCIES:
  - Alamofire (~> 5.8)

SPEC REPOS:
  trunk:
    - Alamofire
    - GoogleUtilities

SPEC CHECKSUMS:
  Alamofire: 0123456789abcdef0123456789abcdef01234567

PODFILE CHECKSUM: 89abcdef0123456789abcdef0123456789abcdef

COCOAPODS: 1.15.2
```

`PODS` is the full resolved set including transitive pods and subspecs (`GoogleUtilities/Environment`), `DEPENDENCIES` is what the Podfile asked for, `SPEC REPOS` tells you whether a pod came from the public trunk or a private spec repository, and `EXTERNAL SOURCES` (when present) lists pods taken from a Git URL or a local path, which have no trunk version to match advisories against. With `use_frameworks!` each pod becomes a dynamic framework in the app's `Frameworks/` folder with a bundle identifier of the form `org.cocoapods.<Pod>`; without it (or with `:linkage => :static`) pods are linked statically. Pods used only by test targets are listed in the same lock file, so check the target blocks in the `Podfile` before reporting them. CocoaPods has [announced](https://blog.cocoapods.org/CocoaPods-Specs-Repo/) that its trunk will become read-only in December 2026: existing pods keep resolving, but no new versions can be published through it, so libraries that remain CocoaPods-only will stop receiving releases there. Expect projects to migrate to SwiftPM, and treat a pod whose maintainer has not moved as a maintenance risk.

#### Carthage

`Cartfile` lists sources (`github "Alamofire/Alamofire" ~> 5.8`, `git "https://example.com/lib.git"`, `binary "https://example.com/sdk.json"`), and `Cartfile.resolved` pins each one, transitive dependencies included:

```text
github "Alamofire/Alamofire" "5.8.1"
binary "https://example.com/VendorSDK.json" "3.2.0"
```

Carthage builds frameworks or XCFrameworks into `Carthage/Build/`, and the developer adds them to the target by hand. Nothing stops the embedded binary from being older or newer than the lock file says, so for Carthage projects compare `Cartfile.resolved` with what is actually in `Frameworks/`.

#### Binary SDKs, signatures and privacy manifests

Closed-source SDKs arrive as XCFrameworks: a folder with an `Info.plist` listing `AvailableLibraries` and one slice per platform (`ios-arm64`, `ios-arm64_x86_64-simulator`), each containing a `.framework` or a static library. Since Xcode 15 ([WWDC23, "Get started with privacy manifests"](https://developer.apple.com/videos/play/wwdc2023/10060/)) two mechanisms help with them:

- **SDK signatures.** XCFrameworks can be code-signed by their vendor, and Xcode checks that a new version of the SDK is signed by the same developer as the one it replaces. This protects against a tampered or substituted binary, not against a vulnerable one.
- **Privacy manifests** (`PrivacyInfo.xcprivacy`) declare data collection and the use of "required reason" APIs. Xcode merges them into a privacy report.

Apple's [list of commonly used third-party SDKs](https://developer.apple.com/support/third-party-SDK-requirements/) (86 entries at the time of writing, including OpenSSL, BoringSSL, Alamofire, AFNetworking, Firebase components, Flutter, FMDB, Realm, SDWebImage and sqflite) must include a privacy manifest, and a signature when used as a binary dependency, in new apps and in updates that add them. For a tester, both files are useful fingerprints: a `PrivacyInfo.xcprivacy` inside a framework or resource bundle names the SDK even when the binary is stripped.

#### What the IPA contains

- `Payload/<App>.app/<App>`: the main Mach-O binary, including all statically linked libraries (most SwiftPM packages, static pods, static XCFrameworks, mergeable libraries).
- `Payload/<App>.app/Frameworks/*.framework`: dynamic frameworks. Each has an `Info.plist` with `CFBundleIdentifier`, `CFBundleShortVersionString` (the marketing version, often the library release for CocoaPods and vendor frameworks) and `CFBundleVersion`. Swift runtime dylibs (`libswift*.dylib`) appear here for older deployment targets; they come from Apple's toolchain, not a third party.
- `Payload/<App>.app/PlugIns/*.appex`: app extensions, each with its own binary and possibly its own frameworks.
- `*.bundle` resource bundles, usually named after the pod or package that provides them, and `PrivacyInfo.xcprivacy` files.
- Web content for hybrid apps (`www/`, `public/`, `main.jsbundle`).

Code the OS provides (WebKit, ImageIO, Security, the system SQLite, Network.framework) is loaded from `/System/Library/` or `/usr/lib/` and patched with iOS updates. It is not the app's dependency in the MASWE-0044 sense. A *copy* of SQLite, OpenSSL or libwebp compiled into the app is, and it stays at whatever version the developer built.

### Background: SBOMs, package identifiers and vulnerability data

*Guler Tech background, not an OWASP Knowledge page.* Every test in this note matches components against advisories, and almost every false positive or false negative comes from how that matching works.

**SBOM formats.** [CycloneDX](https://cyclonedx.org/) (an OWASP standard, JSON or XML) is the format OWASP's tests and Dependency-Track use. A component entry has `type`, `group`, `name`, `version`, `purl`, optionally `scope` (`required`, `optional`, `excluded`), hashes, licences and properties, and the `dependencies` section records the graph. SPDX is the other common format. Both satisfy the NTIA minimum elements.

**Package URLs (purl).** A purl identifies a package in its own ecosystem: `pkg:maven/com.squareup.okhttp3/okhttp@4.9.1`, `pkg:swift/github.com/apple/swift-nio@2.33.0`, `pkg:cocoapods/Alamofire@5.8.1`, `pkg:npm/lodash@4.17.21`. Ecosystem-aware databases (GitHub Security Advisories, OSV, OSS Index) match on purls or on ecosystem plus package name, which is precise.

**CPEs.** The NVD indexes CVEs by [CPE](https://nvd.nist.gov/products/cpe) (`cpe:2.3:a:squareup:okhttp:4.9.1:*:*:*:*:*:*:*`): vendor, product, version. Tools that use the NVD, OWASP dependency-check in particular, have to *guess* a CPE from file names, manifests and package metadata. That guess is where most noise comes from: a CVE recorded against "swift" or against another vendor's product that bundles a library gets matched to an unrelated package with a similar name, and a package whose CPE nobody guessed gets no matches at all.

**Databases.** For mobile work you will meet:

| Source | Keyed by | Strong for | Weak for |
|---|---|---|---|
| NVD | CPE | Native libraries with stable CPEs (OpenSSL, SQLite, libwebp, zlib, curl) | Package-level precision; Swift and CocoaPods |
| GitHub Security Advisories | Ecosystem + package | Maven, npm, pub, Swift (by repository URL) | CocoaPods-only and closed-source SDKs |
| OSV.dev | Ecosystem + package (aggregates GHSA and others) | Maven, npm, pub, `SwiftURL` packages; batch API | Same gaps as its sources |
| Sonatype OSS Index | purl | Maven | Occasionally imports CVEs with details that differ from the NVD |
| Vendor bulletins | Product | Android Security Bulletins (which also cover AOSP-bundled libraries), Apple security releases, SDK vendors' own advisories | Not machine-readable in a uniform way |
| CISA KEV, FIRST EPSS | CVE | Prioritisation: known exploitation, exploitation probability | Not an inventory source |

**Tools.** The tests below use OWASP dependency-check ([MASTG-TOOL-0131](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0131/)), OWASP Dependency-Track ([MASTG-TOOL-0132](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0132/)) and cdxgen ([MASTG-TOOL-0134](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0134/)). We also use the CycloneDX Gradle plugin, osv-scanner, syft and grype, and blint ([MASTG-TOOL-0130](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0130/)) for binaries:

| Tool | Input | What it does | Mobile caveats |
|---|---|---|---|
| dependency-check (Gradle plugin or CLI) | Gradle configurations, JARs, `Package.resolved`, `Podfile.lock`, `Cartfile.resolved` | Infers CPEs, matches against NVD (plus OSS Index and others) | Needs an NVD API key; Swift, CocoaPods and Carthage analysers are experimental; CPE noise |
| CycloneDX Gradle plugin | Gradle's resolved graph | Writes a CycloneDX SBOM per project and an aggregate | Generation only; select configurations with `includeConfigs` |
| cdxgen | Project directories, lock files; also APK/AAB | Writes a CycloneDX SBOM, can submit it to Dependency-Track | Scope labels for Gradle projects are heuristic; verify against `releaseRuntimeClasspath` |
| Dependency-Track | CycloneDX SBOMs | Continuous matching (NVD, GHSA, OSV, OSS Index), audit workflow, policies | A server to run; quality depends on the SBOM |
| osv-scanner | Lock files (`gradle.lockfile`, `gradle/verification-metadata.xml`, `pubspec.lock`, `package-lock.json`) | Matches against OSV | Does not read `build.gradle` itself; check its supported-file list for Swift and CocoaPods |
| syft + grype | Directories, lock files, SBOMs | syft generates SBOMs, grype matches them | Coverage of Swift and CocoaPods data is thinner than for Maven |
| blint | APK, AAB, IPA, native binaries | SBOM from a compiled app | MASTG and the tool's own docs say APK SBOMs are incomplete |

**VEX.** A Vulnerability Exploitability eXchange statement records whether a product is affected by a vulnerability in one of its components. CycloneDX VEX uses analysis states such as `not_affected` with justifications such as `code_not_present`, `code_not_reachable`, `requires_configuration` and `protected_by_mitigating_control`. Dependency-Track's audit view writes the same information. Use it to close out matches that do not apply, so the next scan does not reopen them.

## Tests

OWASP links four tests to MASWE-0044, two per platform. [MASTG-TEST-0272](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0272/) (Android) and [MASTG-TEST-0273](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0273/) (iOS) scan the project's dependency declarations with an SCA tool. [MASTG-TEST-0274](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0274/) (Android) and [MASTG-TEST-0275](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0275/) (iOS) build or obtain a CycloneDX SBOM and analyse it in Dependency-Track. All four need the source project, its lock files or an SBOM from the developers; OWASP types them as `static, code` and `static, developer`. They replace two legacy (MASTG v1) tests:

| Legacy test | Replaced by | What the new tests drop |
|---|---|---|
| [MASTG-TEST-0042](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0042/) Checking for Weaknesses in Third Party Libraries (Android) | MASTG-TEST-0272, MASTG-TEST-0274 | The black-box route (decompiling, MobSF), RetireJS for hybrid apps, and the licence check in an "about" screen |
| [MASTG-TEST-0085](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0085/) Checking for Weaknesses in Third Party Libraries (iOS) | MASTG-TEST-0273, MASTG-TEST-0275 | Listing frameworks with objection and `otool -L`, searching vendored source, RetireJS, the licence check |

The legacy tests' triage logic is still sound and worth keeping: if a vulnerable library ships with the app, upgrade it; if no fixed version exists, establish whether the vulnerability affects the app and replace the library if it does or might; if the library is build-time only, judge it as a risk to the build pipeline instead.

Because the new tests assume access to the project, we add three Guler Tech checks: [GT-CODE-0044-1](#gt-code-0044-1-libraries-and-versions-in-a-release-apk-android) and [GT-CODE-0044-2](#gt-code-0044-2-frameworks-and-versions-in-an-ipa-ios) identify libraries and versions in the release binaries (black-box, and as a cross-check of the SBOM in grey-box work), and [GT-CODE-0044-3](#gt-code-0044-3-reachability-and-exploitability-of-a-reported-cve-android-ios) decides whether a matched CVE affects the app. Licence checks are covered in the [MASTG-KNOW-0004 note](/mobile/mastg-know-0004-third-party-libraries/).

> **Warning:** Several statements in the OWASP techniques and demos for these tests are wrong or out of date. (1) [MASTG-DEMO-0052](https://mas.owasp.org/MASTG/demos/ios/MASVS-CODE/MASTG-DEMO-0052/MASTG-DEMO-0052/) concludes that swift-nio 2.33.0 has "at least 2 known vulnerabilities", but the two CVEs in its output (CVE-2020-9861 and CVE-2022-1642) are about Swift for Linux and swift-corelibs-foundation, not swift-nio, and the CVE-2022-3918 named in its evaluation does not appear in the output at all. (2) [MASTG-DEMO-0051](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0051/MASTG-DEMO-0051/) lists the flagged OkHttp and Okio components with `"scope": "optional"` and a `debugAndroidTestCompileClasspath` property, although the SBOM's own dependency graph shows the app module depending on OkHttp directly; a tester who trusted the scope, or ran cdxgen with `--required-only`, would have dropped them. (3) [MASTG-TECH-0132](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0132/) says cdxgen supports neither CocoaPods nor transitive SwiftPM dependencies; current cdxgen documents both. (4) [MASTG-TECH-0133](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0133/) says dependency-check can scan only one file at a time; its `--scan` option can be repeated. (5) [MASTG-TECH-0130](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0130/) sends you to "the frontend of dependency-check" where it means Dependency-Track, and MASTG-TECH-0132 calls Visual Studio Code (MASTG-TOOL-0133) "the Docker container". The procedures below are corrected.

### Before you start: decide what ships

Every scanner result has to be mapped back to one question: is this component, at this version, in the build that users install? Settle that first.

**Android.** Work on the release variant of the application module. The resolved runtime graph is the reference list:

```bash
./gradlew :app:dependencies --configuration releaseRuntimeClasspath > release-deps.txt
grep -cE -- '--- ' release-deps.txt                       # rough component count
grep -E 'okhttp|okio|sqlcipher|conscrypt' release-deps.txt  # spot-check libraries of interest
./gradlew :app:dependencyInsight --dependency com.squareup.okhttp3:okhttp \
  --configuration releaseRuntimeClasspath                   # who pulled it in, and why this version
```

In the tree, `4.9.1 -> 4.12.0` means conflict resolution upgraded the requested version, `(*)` marks a subtree already printed, and `(c)` a constraint. With product flavours, use `<flavor>ReleaseRuntimeClasspath`. Repeat for every module that produces an APK (wear, TV, instant app) and for dynamic feature modules.

**iOS.** Work out which targets ship (the app, its extensions, App Clips) and what each links:

```bash
xcodebuild -list -project App.xcodeproj
xcodebuild -resolvePackageDependencies -project App.xcodeproj -scheme App
grep -n 'productName' App.xcodeproj/project.pbxproj | sort -u     # SwiftPM products linked by targets
sed -n '/^target/,/^end/p' Podfile                                  # pods per target (test targets too)
```

For package-based projects, `swift package show-dependencies --format json` prints the resolved graph.

**Both.** Get the actual release build as well (the APK from a test device or the store, a decrypted IPA), so that you can confirm findings against what ships. Lock files and SBOMs describe what the build resolved. They say nothing about vendored binaries, native code inside SDKs, or code loaded at runtime.

### MASTG-TEST-0272: Identify Dependencies with Known Vulnerabilities in the Android Project (Android)

Source: [MASTG-TEST-0272](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0272/). Platform: Android. Type: static (code); needs the project source. Knowledge: MASTG-KNOW-0004. Technique: [MASTG-TECH-0131](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0131/) (SCA at build time). Tool: OWASP dependency-check ([MASTG-TOOL-0131](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0131/)).

#### Overview

Dependencies are declared and resolved in the Gradle build and end up merged into DEX, so the reliable place to scan them is the build. The dependency-check Gradle plugin walks the resolved configurations, finds the artefacts in Gradle's cache (`~/.gradle/caches/modules-2/files-2.1/`), derives a CPE and a purl for each, and matches them against the NVD and other sources (Sonatype OSS Index, among others). Transitive dependencies are included because the plugin works on the resolved graph, not on the declarations.

#### Prerequisites

- The Android project, buildable on your machine (JDK, Android SDK, network access to the repositories it uses).
- An [NVD API key](https://nvd.nist.gov/developers/request-an-api-key). Without one the initial NVD download is throttled to the point of being unusable.
- Knowledge of the release variant name (see [Before you start](#before-you-start-decide-what-ships)).

#### Steps

1. **Add the plugin to the application module's build file** (`app/build.gradle.kts`, not the root file). Limit the scan to the release runtime classpath so that test, debug and tooling configurations do not flood the report:

   ```kotlin
   plugins {
       id("com.android.application")
       id("org.owasp.dependencycheck") version "12.1.1" // use the current release
   }

   dependencyCheck {
       formats = listOf("HTML", "JSON")
       scanConfigurations = listOf("releaseRuntimeClasspath")
       suppressionFile = "dependency-check-suppressions.xml"
       nvd {
           apiKey = System.getenv("NVD_API_KEY")
       }
   }
   ```

   Keep the key out of the build file and out of version control. If you leave `scanConfigurations` empty, the plugin scans every configuration except test ones (`skipTestGroups` defaults to `true`), which still includes debug, lint and Android test-platform configurations. OWASP notes that some plugin versions fail with `NoSuchMethodError` around `ZipFile.builder()`; the fix is to pin `org.apache.commons:commons-compress` on the build classpath, as described in the [dependency-check issue](https://github.com/dependency-check/DependencyCheck/issues/7405#issuecomment-2785588330).

2. **Run the analysis:**

   ```bash
   export NVD_API_KEY=...   # your key
   ./gradlew :app:dependencyCheckAnalyze
   ```

   The first run downloads the NVD data set and takes a while; later runs update it incrementally. For multi-module projects, `dependencyCheckAggregate` produces one report for the whole build.

3. **Extract the hits** from `app/build/reports/dependency-check-report.json` (the HTML report next to it is easier to read for a handful of findings):

   ```bash
   jq -r '.dependencies[] | select(.vulnerabilities != null)
          | .fileName as $f
          | ((.packages // []) | map(.id) | join(",")) as $p
          | .vulnerabilities[] | [$f, $p, .name, .severity, .source] | @tsv' \
     app/build/reports/dependency-check-report.json | sort -u
   ```

4. **Triage each hit before you report it:**
   - Is the component in `releaseRuntimeClasspath` (`dependencyInsight`)? If not, it does not ship.
   - Is the match the right product? Compare the `vulnerabilityIds` CPE and the advisory text with the library. A CVE whose description names another product that merely *bundles* the library, or a same-named project, is a CPE mismatch.
   - Is the resolved version inside the affected range according to a primary source (the GitHub advisory, the OSV entry, the project's changelog or security page)? Note the first fixed version.
   - Then assess reachability with [GT-CODE-0044-3](#gt-code-0044-3-reachability-and-exploitability-of-a-reported-cve-android-ios).

5. **Record false positives** in the suppression file, scoped as narrowly as possible (one purl and one CVE, not a whole group), with a note explaining why:

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">
       <suppress>
           <notes>Not affected: the app sets no headers from untrusted input and does not log exception messages; reviewed 2026-11, ticket SEC-123.</notes>
           <packageUrl regex="true">^pkg:maven/com\.squareup\.okhttp3/okhttp@.*$</packageUrl>
           <cve>CVE-2023-0833</cve>
       </suppress>
   </suppressions>
   ```

   The example only shows the syntax; the justification has to be true for the app in question (see the demo). Use suppressions for matches that are wrong or do not apply, never to hide a finding that has simply not been fixed yet.

6. **Cross-check with a second source.** If the project uses Gradle dependency locking, scan the lock file with osv-scanner, which matches by Maven coordinates rather than CPE:

   ```bash
   ./gradlew :app:dependencies --write-locks     # requires dependencyLocking { lockAllConfigurations() }
   grep 'releaseRuntimeClasspath' app/gradle.lockfile > release.lockfile.txt
   osv-scanner scan -L app/gradle.lockfile
   ```

   Each line of `gradle.lockfile` reads `group:artifact:version=configuration1,configuration2`, so the `grep` tells you which reported packages are in the release classpath. Also open the version catalogue in Android Studio and read the SDK Index warnings described in [MASTG-KNOW-0004](#android-third-party-libraries-mastg-know-0004).

#### Observation

The dependency-check report (HTML and JSON) for the release runtime classpath, and for each hit: the component and resolved version, how it entered the graph (direct or through which parent), the advisory ID and source, the affected range and first fixed version from a primary source, and your triage outcome (applies, does not ship, wrong product, version outside range).

#### Evaluation

The test **fails** if a component in the release runtime classpath has a published vulnerability whose affected range includes the resolved version and which, after triage, describes this component rather than a different product.

It **passes** if no such component exists, or if every reported match is shown not to ship, not to apply to this product, or to fall outside the affected range, and these decisions are recorded.

A confirmed match whose vulnerable code is not reachable is still a failure of MASVS-CODE-3 (the component has a known vulnerability), but it is rated low (see [Rating findings](#rating-findings)). Do not pass a test because "the app probably does not use that function" without doing the work in GT-CODE-0044-3.

#### Demo

[MASTG-DEMO-0050](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0050/MASTG-DEMO-0050/) (fail). A Compose app declares an old OkHttp next to its AndroidX dependencies and applies the dependency-check plugin with the NVD key configured as in step 1 (the demo leaves `scanConfigurations` at its default):

```kotlin
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.owasp.dependencycheck") version "10.0.4"
}

dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
    implementation(platform("androidx.compose:compose-bom:2024.04.00"))
    implementation("org.jetbrains.kotlin:kotlin-reflect:1.9.10")
    implementation("com.squareup.okhttp3:okhttp:4.9.1") // vulnerable library
}
```

`./gradlew dependencyCheckAnalyze` reports 303 dependencies, four of them vulnerable, with five vulnerabilities in total (57 more are suppressed when the OWASP suppression file for gRPC and Netty from the test platform is used). The OkHttp entry, shortened:

```json
{
  "fileName": "okhttp-4.9.1.jar",
  "packages": [{ "id": "pkg:maven/com.squareup.okhttp3/okhttp@4.9.1", "confidence": "HIGH" }],
  "vulnerabilityIds": [{ "id": "cpe:2.3:a:squareup:okhttp:4.9.1:*:*:*:*:*:*:*", "confidence": "HIGHEST" }],
  "vulnerabilities": [
    { "source": "OSSINDEX", "name": "CVE-2021-0341", "severity": "HIGH", "cwes": ["CWE-295"] },
    { "source": "NVD", "name": "CVE-2023-0833", "severity": "MEDIUM", "cwes": ["CWE-209"] }
  ]
}
```

(The report was produced with plugin 12.1.1, according to the OSS Index URLs in it, although the sample build file pins 10.0.4.) How to read the two hits:

- **CVE-2021-0341** is real for this version. `OkHostnameVerifier` could accept a certificate for the wrong domain. The [GitHub advisory](https://github.com/advisories/GHSA-3cqm-mf7h-prrj) gives the fixed version as 4.9.2. The same CVE also appears in the February 2021 [Android Security Bulletin](https://source.android.com/security/bulletin/2021-02-01) (A-171980069), because the platform's `HttpURLConnection` implementation is an internal fork of OkHttp; the bulletin fixes the platform copy, not the one in the app. OSS Index notes that its details differ from the NVD record, which is a reminder to read the primary advisory. Any app that makes HTTPS calls through OkHttp with its default hostname verifier uses the affected code, so this one goes to GT-CODE-0044-3 for exploitability rather than reachability.
- **CVE-2023-0833** is written about Red Hat AMQ Streams, which ships OkHttp, but the flaw is OkHttp's: an illegal header value triggers an exception whose message contains the value. The NVD configuration lists `squareup:okhttp` before 4.9.2 as vulnerable, so the match is legitimate, even though the GitHub advisory database (and therefore OSV) does not list it for OkHttp. Databases disagree more often than you would expect, which is why a single source is not enough. In an app, this matters when exception messages end up in logs or crash reports and the headers carry tokens.

Upgrading to a current OkHttp release (4.12.x or 5.x) removes both, and is the fix to recommend whatever the triage says.

### MASTG-TEST-0274: Dependencies with Known Vulnerabilities in the App's SBOM (Android)

Source: [MASTG-TEST-0274](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0274/). Platform: Android. Type: static (developer); needs the project or an SBOM from the developers. Knowledge: MASTG-KNOW-0004. Technique: [MASTG-TECH-0130](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0130/) (SCA by creating an SBOM). Tools: cdxgen ([MASTG-TOOL-0134](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0134/)), Dependency-Track ([MASTG-TOOL-0132](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0132/)).

#### Overview

Instead of scanning during the build, this test produces a CycloneDX SBOM of the project and loads it into Dependency-Track, which matches it against several vulnerability sources and keeps re-checking it as new advisories appear. The SBOM is also the deliverable that the development team should be producing for each release. Asking for it is part of the test: a team that cannot produce one has no inventory to monitor.

#### Prerequisites

- The Android project (for generating the SBOM) or a CycloneDX SBOM from the developers. For a supplied SBOM, check `metadata.timestamp`, `metadata.tools` and the `metadata.component` version against the build you are assessing.
- cdxgen (`npm install -g @cyclonedx/cdxgen`) with a working Gradle build, or the CycloneDX Gradle plugin.
- Docker, to run Dependency-Track locally; a GitHub token if you want the GitHub Advisories source.

#### Steps

1. **Generate the SBOM.** Two options, both from the project root:

   ```bash
   # cdxgen: runs Gradle and records every resolvable configuration
   cdxgen -t java -o sbom.json .
   ```

   or, with the [CycloneDX Gradle plugin](https://github.com/CycloneDX/cyclonedx-gradle-plugin) (3.x syntax) applied to the root project and restricted to the release runtime classpath in `app/build.gradle.kts`:

   ```kotlin
   tasks.cyclonedxDirectBom {
       includeConfigs = listOf("releaseRuntimeClasspath")
   }
   ```

   ```bash
   ./gradlew :app:cyclonedxDirectBom
   ls app/build/reports/cyclonedx-direct/bom.json
   ```

   The plugin route gives you exactly the shipped graph. cdxgen gives you everything, labelled with heuristic scopes.

2. **Check the SBOM before uploading it.** Count the components and look at where each came from:

   ```bash
   jq '.components | length' sbom.json
   jq -r '.components[] | [.group, .name, .version, (.scope // "-"),
          ((.properties // []) | map(select(.name == "GradleProfileName") | .value) | join(","))] | @tsv' \
     sbom.json | sort > components.tsv
   ```

   For cdxgen SBOMs, the `scope` and `GradleProfileName` values describe the first configuration in which cdxgen met the component, not every configuration that contains it. Do not drop `optional` components (and do not use `--required-only` on Android projects) until you have checked them against `releaseRuntimeClasspath`.

3. **Start Dependency-Track:**

   ```bash
   mkdir dtrack && cd dtrack
   curl -LO https://dependencytrack.org/docker-compose.yml
   docker compose up -d
   ```

   The frontend listens on `http://localhost:8080`, the API on `http://localhost:8081`. Log in as `admin` / `admin` and set a new password when prompted. Under *Administration → Vulnerability Sources* and *Analyzers*, enable the NVD mirror, OSS Index, GitHub Advisories and OSV (Maven ecosystem), and wait for the first mirror to finish. Under *Administration → Access Management → Teams*, use the *Automation* team's API key and make sure it has the `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD` permissions.

4. **Upload the SBOM.** The multipart form is simpler than the base64 JSON body shown in MASTG-TECH-0130:

   ```bash
   export DT_API_KEY=...   # the Automation team key
   curl -s -X POST "http://localhost:8081/api/v1/bom" \
     -H "X-Api-Key: $DT_API_KEY" \
     -F "autoCreate=true" -F "projectName=example-android" -F "projectVersion=1.4.2" \
     -F "bom=@sbom.json"
   ```

   cdxgen can also submit directly with `--server-url`, `--api-key` and `--project-name`.

5. **Read the findings** in the project's *Audit Vulnerabilities* tab, or through the API:

   ```bash
   UUID=$(curl -s -H "X-Api-Key: $DT_API_KEY" \
     "http://localhost:8081/api/v1/project/lookup?name=example-android&version=1.4.2" | jq -r .uuid)
   curl -s -H "X-Api-Key: $DT_API_KEY" "http://localhost:8081/api/v1/finding/project/$UUID" \
     | jq -r '.[] | [.component.group, .component.name, .component.version,
                     .vulnerability.vulnId, .vulnerability.source, .vulnerability.severity] | @tsv'
   ```

6. **Triage in Dependency-Track.** For each finding, apply the checks from step 4 of MASTG-TEST-0272 (ships? right product? in range?) and then GT-CODE-0044-3, and record the result as an analysis state (*Exploitable*, *In Triage*, *False Positive*, *Not Affected*, *Resolved*) with a justification. Those decisions stay attached to the project and can be exported as VEX.

#### Observation

The SBOM (with its generation metadata), the Dependency-Track component count, and the list of findings with component, version, advisory ID, source and severity, plus your analysis state for each.

#### Evaluation

The test **fails** if the SBOM contains a component that ships in the release build and has a known vulnerability that applies to its version (same criteria as MASTG-TEST-0272).

It **passes** if no such component exists. Two further results are worth reporting even when it passes: the development team could not provide an SBOM at all (a process observation; there is no inventory to monitor after release), and the SBOM disagrees with the release binary in a way that matters, for example libraries found by [GT-CODE-0044-1](#gt-code-0044-1-libraries-and-versions-in-a-release-apk-android) that are missing from it.

#### Demo

[MASTG-DEMO-0051](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0051/MASTG-DEMO-0051/) (fail). cdxgen is run in the root of an Android project (the demo's front matter links it to MASTG-TEST-0272, but it implements this test's method):

```bash
cdxgen -t java -o sbom.json
```

The SBOM lists 203 components, most of them from test and tooling configurations (`debugAndroidTestCompileClasspath`, `androidTestImplementation`, `_internal-unified-test-platform-*`, `kotlin-extension`). After upload, Dependency-Track reports seven vulnerable components and seven vulnerabilities. OWASP's evaluation picks out OkHttp with two vulnerabilities and Okio with one:

```json
[
  { "group": "com.squareup.okhttp3", "name": "okhttp", "version": "4.8.0", "scope": "optional",
    "purl": "pkg:maven/com.squareup.okhttp3/okhttp@4.8.0?type=jar",
    "properties": [{ "name": "GradleProfileName", "value": "debugAndroidTestCompileClasspath" }] },
  { "group": "com.squareup.okio", "name": "okio", "version": "2.7.0", "scope": "optional",
    "purl": "pkg:maven/com.squareup.okio/okio@2.7.0?type=jar",
    "properties": [{ "name": "GradleProfileName", "value": "debugAndroidTestCompileClasspath" }] }
]
```

Read on its own, this says "test-only, ignore". The `dependencies` section of the same SBOM says otherwise: `pkg:maven/MASTestApp/app@latest` depends directly on `okhttp@4.8.0`, which depends on `okio@2.7.0`. The instrumented-test classpath contains the app's own dependencies, and that is where cdxgen happened to meet them first. Confirm with `./gradlew :app:dependencyInsight --dependency okhttp --configuration releaseRuntimeClasspath`; if OkHttp appears there, the findings stand. For Okio 2.7.0 the advisory is CVE-2023-3635 ([GHSA-w33c-445m-f8w7](https://github.com/advisories/GHSA-w33c-445m-f8w7), a signed-to-unsigned conversion in `GzipSource` leading to a crash, fixed in 3.4.0 and 1.17.6), which matters if the app decompresses gzip data from a server it does not control. The fix is the same as in the previous demo: a current OkHttp, which brings a current Okio with it.

### MASTG-TEST-0273: Identify Dependencies with Known Vulnerabilities by Scanning Dependency Managers Artifacts (iOS)

Source: [MASTG-TEST-0273](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0273/). Platform: iOS. Type: static (code); needs the dependency manager files. Knowledge: MASTG-KNOW-0059. Technique: [MASTG-TECH-0133](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0133/) (SCA by scanning package manager artefacts). Tools: OWASP dependency-check ([MASTG-TOOL-0131](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0131/)), Visual Studio Code with the SARIF Viewer extension ([MASTG-TOOL-0133](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0133/)).

#### Overview

On iOS, versions are often impossible to read back from the IPA because most dependencies are linked statically and stripped. The lock files that SwiftPM, CocoaPods and Carthage write are therefore the best inventory, and you do not need the whole Xcode project to use them: `Package.resolved`, `Podfile.lock` and `Cartfile.resolved` are enough. The test feeds them to dependency-check's experimental Swift, CocoaPods and Carthage analysers, which derive CPEs and match them against the NVD. Because those analysers are experimental and CPE matching for Swift packages is weak, the test needs a second, ecosystem-aware source and a careful triage.

#### Prerequisites

- The lock files of every dependency manager the project uses (ask for all three; projects often mix them), plus the `Podfile` to see which pods belong to test targets.
- dependency-check CLI and an NVD API key.
- Optionally the IPA, to compare the lock files with what actually shipped ([GT-CODE-0044-2](#gt-code-0044-2-frameworks-and-versions-in-an-ipa-ios)).

#### Steps

1. **Collect the artefacts.** In a project checkout:

   ```bash
   find . -name Package.resolved -not -path '*/.build/*' -not -path '*/DerivedData/*'
   find . -maxdepth 3 \( -name Podfile -o -name Podfile.lock -o -name Cartfile.resolved -o -name '*.podspec' \)
   ```

2. **Read the resolved versions** so you know what the scanner should find:

   ```bash
   # Package.resolved format 2 or 3
   jq -r '.pins[] | [.identity, .location, (.state.version // ("branch:" + (.state.branch // "-"))), .state.revision] | @tsv' Package.resolved
   # Package.resolved format 1
   jq -r '.object.pins[] | [.package, .repositoryURL, (.state.version // "-"), .state.revision] | @tsv' Package.resolved
   # CocoaPods: the full resolved set
   sed -n '/^PODS:/,/^$/p' Podfile.lock
   cat Cartfile.resolved
   ```

   Pins without a version (branch or revision pins) and pods from `EXTERNAL SOURCES` cannot be matched automatically. List them separately and map each commit to a release by hand.

3. **Run dependency-check** on all files in one go:

   ```bash
   dependency-check --enableExperimental --nvdApiKey "$NVD_API_KEY" \
     --project example-ios -f ALL -o dc-report \
     -s Package.resolved -s Podfile.lock -s Cartfile.resolved
   ```

   `-f ALL` writes HTML, JSON and SARIF (among others) into `dc-report/`. Open the SARIF file in VS Code with the SARIF Viewer, or extract the hits from the JSON with the `jq` command from [MASTG-TEST-0272](#mastg-test-0272-identify-dependencies-with-known-vulnerabilities-in-the-android-project-android).

4. **Query an ecosystem-aware source for SwiftPM packages.** OSV indexes GitHub's Swift advisories under the `SwiftURL` ecosystem, keyed by repository URL without the scheme:

   ```bash
   jq '{queries: [.pins[] | select(.state.version != null)
        | {package: {ecosystem: "SwiftURL",
                     name: (.location | sub("^https://"; "") | sub("\\.git$"; ""))},
           version: .state.version}]}' Package.resolved > osv-query.json
   curl -s https://api.osv.dev/v1/querybatch -d @osv-query.json \
     | jq -r '.results[] | [(.vulns // [])[].id] | join(" ")'
   ```

   The results come back in the same order as the queries. For pods, check the GitHub Advisory Database and the pod's own repository and security page; database coverage of CocoaPods-only libraries is thin.

5. **Triage each hit:**
   - **Wrong product.** CVEs recorded against the Swift toolchain, Swift for Linux or `swift-corelibs-foundation` are regularly matched to Swift packages by name. `swift-corelibs-foundation` is the Foundation implementation for Linux and other non-Apple platforms; iOS apps use Apple's Foundation, so those CVEs do not apply to an iOS app at all.
   - **Not shipped.** Pods and packages used only by test targets (`OHHTTPStubs`, snapshot testing, mocking libraries) and build tools (SwiftLint, SwiftGen, Sourcery as plugins) do not reach the IPA.
   - **Version range.** Confirm against the GitHub advisory or the project's release notes.
   - **Linkage.** For a vulnerable package that ships, find out which target links it and whether the vulnerable module is part of the product the app uses (packages often have several products).
   - Then assess reachability with [GT-CODE-0044-3](#gt-code-0044-3-reachability-and-exploitability-of-a-reported-cve-android-ios).

6. **Compare with the binary.** Frameworks in the IPA that no lock file explains (vendor XCFrameworks, manually embedded libraries) are outside this test's view; inventory them with GT-CODE-0044-2.

#### Observation

The dependency-check report (SARIF or JSON), the OSV results for SwiftPM pins, the list of unversioned pins and external pods, and for each hit: component, version, advisory, source, affected range, fixed version and triage outcome.

#### Evaluation

The test **fails** if a package or pod that is linked into a shipping target has a known vulnerability that applies to its resolved version. It **passes** if there is none, with false positives and test-only matches documented. Unversioned pins and binary SDKs that could not be checked are a stated limitation of the result, not a pass.

#### Demo

[MASTG-DEMO-0052](https://mas.owasp.org/MASTG/demos/ios/MASVS-CODE/MASTG-DEMO-0052/MASTG-DEMO-0052/). The project resolves a single package, swift-nio 2.33.0 (the `Package.resolved` shown in [MASTG-KNOW-0059](#ios-third-party-libraries-mastg-know-0059) above), and dependency-check is run on it:

```bash
dependency-check --enableExperimental -f SARIF --nvdApiKey "$NVD_API_KEY" -s Package.resolved
```

The SARIF output contains two rules, shortened:

```json
{ "id": "CVE-2020-9861",
  "shortDescription": { "text": "high severity - CVE-2020-9861 Uncontrolled Recursion vulnerability in pkg:swift/swift-nio@2.33.0" },
  "fullDescription": { "text": "A stack overflow issue existed in Swift for Linux. ... deeply nested malicious JSON input." } }
{ "id": "CVE-2022-1642",
  "shortDescription": { "text": "high severity - CVE-2022-1642 Incorrect Type Conversion or Cast vulnerability in pkg:swift/swift-nio@2.33.0" },
  "fullDescription": { "text": "A program using swift-corelibs-foundation is vulnerable to a denial of service attack ... JSONDecoder ..." } }
```

OWASP's evaluation says swift-nio "has at least 2 known vulnerabilities as part of Swift with CVE-2022-3918 and CVE-2022-1642". Neither the descriptions nor the NVD data support that. Both CVEs in the output describe other software: CVE-2020-9861 is recorded against Swift on Ubuntu and CVE-2022-1642 against `swift-corelibs-foundation`, with CPEs restricted to Linux and Windows. CVE-2022-3918, which the evaluation names, is not in the output and is likewise a `swift-corelibs-foundation` issue (CRLF injection through `FoundationNetworking`). For an iOS app all of them are CPE false positives, and the correct demo result is "dependency-check found no applicable vulnerability". Running step 4 against the same pin gives the matches that do concern swift-nio: at the time of writing OSV lists GitHub advisories published in 2026 whose ranges include 2.33.0 (for example GHSA-rj37-6j9x-74q6, unbounded HTTP/1 header blocks in `NIOHTTP1`'s `HTTPDecoder`, fixed in 2.100.0). Those are the findings to triage, and whether they matter depends on whether the app uses `NIOHTTP1` to parse responses from servers an attacker can influence.

### MASTG-TEST-0275: Dependencies with Known Vulnerabilities in the App's SBOM (iOS)

Source: [MASTG-TEST-0275](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0275/). Platform: iOS. Type: static (developer); needs the project or an SBOM. Knowledge: MASTG-KNOW-0059. Technique: [MASTG-TECH-0132](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0132/) (SCA by creating an SBOM). Tools: cdxgen ([MASTG-TOOL-0134](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0134/)), Dependency-Track ([MASTG-TOOL-0132](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0132/)).

#### Overview

The iOS counterpart of MASTG-TEST-0274: generate (or request) a CycloneDX SBOM for the Xcode project and analyse it in Dependency-Track. cdxgen reads `Package.resolved` and `Package.swift` for SwiftPM and, in current versions, `Podfile` and `Podfile.lock` for CocoaPods (MASTG-TECH-0132 still says CocoaPods is unsupported). Carthage is not among cdxgen's documented project types, so Carthage dependencies have to be added another way.

#### Prerequisites

- The Xcode project or a CycloneDX SBOM from the developers (check its metadata as in MASTG-TEST-0274).
- cdxgen; for package-based projects with test-scope detection, a Swift toolchain.
- A running Dependency-Track instance with the GitHub Advisories and OSV sources enabled (step 3 of MASTG-TEST-0274). The NVD alone is a poor source for Swift packages.

#### Steps

1. **Generate the SBOM** in the project root:

   ```bash
   cdxgen -o sbom.json .            # auto-detect: SwiftPM and CocoaPods in one BOM
   cdxgen -t swift -o sbom-spm.json .
   cdxgen -t cocoa -o sbom-pods.json .
   ```

   For Package.swift-based projects, cdxgen marks packages used only by test targets as `optional`, so `--required-only` is reasonable there. For Xcode projects that only have a `Package.resolved`, there is no target information and every pin is listed.

2. **Clean and complete the SBOM.** cdxgen also records things that are not app components, for example GitHub Actions used by the repository's CI:

   ```bash
   jq -r '.components[] | [.purl, (.scope // "-")] | @tsv' sbom.json
   jq '.components |= map(select(.purl | startswith("pkg:github/") | not))' sbom.json > sbom-app.json
   ```

   Add what the SBOM cannot see: Carthage dependencies from `Cartfile.resolved`, vendor XCFrameworks and native libraries found with [GT-CODE-0044-2](#gt-code-0044-2-frameworks-and-versions-in-an-ipa-ios). CycloneDX lets you add components by hand (name, version, purl or CPE); for native libraries, a CPE is what makes NVD matching work.

3. **Upload and read the findings** exactly as in steps 4 and 5 of [MASTG-TEST-0274](#mastg-test-0274-dependencies-with-known-vulnerabilities-in-the-apps-sbom-android), with a project name and version that identify the iOS build.

4. **Triage** each finding with the checks from step 5 of MASTG-TEST-0273 (wrong product, not shipped, version range, linkage), then GT-CODE-0044-3, and record the analysis state in Dependency-Track.

#### Observation

The SBOM and its provenance, the components added by hand, and the Dependency-Track findings with your analysis state for each.

#### Evaluation

The test **fails** if a component that ships in the IPA has an applicable known vulnerability for its version. It **passes** if there is none and the SBOM covers all integration routes the project uses. An SBOM that leaves out Carthage or binary SDKs makes the result incomplete; report that as a limitation.

#### Demo

[MASTG-DEMO-0053](https://mas.owasp.org/MASTG/demos/ios/MASVS-CODE/MASTG-DEMO-0053/MASTG-DEMO-0053/) (fail). `cdxgen -o sbom.json` in the project root finds the `Package.resolved` inside `MASTestApp.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/` and produces three components, shortened:

```json
"components": [
  { "group": "actions", "name": "checkout", "version": "v4", "purl": "pkg:github/actions/checkout@v4" },
  { "group": "github.com/apple", "name": "swift-nio", "version": "1.4.0",
    "purl": "pkg:swift/github.com/apple/swift-nio@1.4.0",
    "evidence": { "identity": { "field": "purl", "methods": [ { "technique": "manifest-analysis" } ] } } },
  { "group": "github.com/apple", "name": "swift-nio-zlib-support", "version": "1.0.0",
    "purl": "pkg:swift/github.com/apple/swift-nio-zlib-support@1.0.0" }
]
```

`actions/checkout` is a CI action, not app code; remove it before uploading. Note also that this demo uses swift-nio 1.4.0, while MASTG-DEMO-0052 used 2.33.0, so the two iOS demos do not describe the same project state. Dependency-Track reports two vulnerabilities for swift-nio 1.4.0, and here the matches are genuine: OSV lists, among others, CVE-2022-3215 ([GHSA-7fj7-39wj-c64f](https://github.com/advisories/GHSA-7fj7-39wj-c64f), CRLF injection in HTTP headers, no fix in the 1.x line) and [GHSA-mgc4-wqv7-4pxm](https://github.com/advisories/GHSA-mgc4-wqv7-4pxm) (request smuggling through a malformed `Transfer-Encoding` header, fixed in 1.14.2) for that version. The fix is a current 2.x release. Both advisories are about HTTP handling, so for rating, the next question is whether the app uses swift-nio's HTTP stack at all and against which servers.

### GT-CODE-0044-1: Libraries and versions in a release APK (Android)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Identify the third-party libraries, SDKs and native libraries in a release APK, with versions where the binary allows it. Use this in black-box assessments, where the OWASP tests cannot be run, and in grey-box ones to check that the SBOM matches what ships (vendored JARs, native code inside SDKs and copied JavaScript never appear in Gradle's graph). MASTG describes the manual route only briefly in [MASTG-TECH-0129](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0129/) and [MASTG-TECH-0157](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0157/); this is the full procedure.

#### Prerequisites

- The release APK (for split installs, all splits: `adb shell pm path com.example.app`, then `adb pull` each path).
- unzip, jadx ([MASTG-TOOL-0018](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)), `strings`, `llvm-readelf` from the NDK (or binutils `readelf`), jq.
- Optional: blint ([MASTG-TOOL-0130](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0130/)), retire.js, and a test device with Frida ([MASTG-TOOL-0001](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/)).

#### Steps

1. **Unpack** the APK ([MASTG-TECH-0007](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0007/)):

   ```bash
   mkdir apk && unzip -q app-release.apk -d apk
   ```

2. **Read the version files libraries leave behind:**

   ```bash
   # AndroidX, Jetpack, kotlinx: one exact version per file
   for f in apk/META-INF/*.version; do printf '%s\t%s\n' "$(basename "$f" .version)" "$(head -1 "$f")"; done | sort
   # Google Play services and Firebase
   grep -H '^version=' apk/*.properties 2>/dev/null
   # Kotlin modules that were packaged (presence only)
   ls apk/META-INF/*.kotlin_module 2>/dev/null | xargs -n1 basename
   # Maven metadata, when the build kept it
   find apk/META-INF/maven -name pom.properties -exec grep -H '^version=' {} \; 2>/dev/null
   ```

3. **List library namespaces from the DEX code** ([MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/)):

   ```bash
   jadx --no-res -d jadx-out app-release.apk
   find jadx-out/sources -mindepth 2 -maxdepth 3 -type d | sed 's|jadx-out/sources/||' | sort -u > namespaces.txt
   grep -E '^(okhttp3|okio|retrofit2|com/google/gson|com/fasterxml|org/yaml|io/grpc|com/bumptech|com/facebook|io/sentry|net/sqlcipher)' namespaces.txt
   ```

   R8 renames library classes that have no keep rules, so missing names do not prove absence. Many libraries ship consumer keep rules or are referenced by reflection, which keeps their package names.

4. **Look for version constants in code.** Libraries embed versions in User-Agent strings and SDK version fields, and these survive minification because they are used at runtime:

   ```bash
   unzip -p app-release.apk 'classes*.dex' | strings -a | grep -E '^okhttp/[0-9]' | sort -u
   grep -rhoE '"[A-Za-z][A-Za-z0-9_.-]*/[0-9]+\.[0-9]+\.[0-9]+[^"]*"' jadx-out/sources | sort | uniq -c | sort -rn | head -30
   grep -rnE '(SDK_VERSION|VERSION_NAME|LIBRARY_VERSION)\s*=\s*"' jadx-out/sources | head -30
   ```

5. **Inventory native libraries** ([MASTG-TECH-0157](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0157/)). Well-known C libraries embed their version as text, and some export a version function:

   ```bash
   find apk/lib -name '*.so' | sort
   for so in apk/lib/arm64-v8a/*.so; do
     echo "== $so"
     strings -a "$so" | grep -E -m8 'OpenSSL [0-9]+\.[0-9]+\.[0-9]+[a-z]?|libcurl/[0-9.]+|libpng version [0-9.]+|(in|de)flate [0-9.]+ Copyright|^3\.[0-9]{2}\.[0-9]+$|^20[0-9]{2}-[0-9]{2}-[0-9]{2} [0-9:]{8} [0-9a-f]{20,}'
     llvm-readelf --dyn-syms -W "$so" | grep -oE 'WebPGetDecoderVersion|sqlite3_libversion|OpenSSL_version|SSLeay_version|curl_version' | sort -u
   done
   llvm-readelf -p .comment apk/lib/arm64-v8a/libexample.so     # compiler that built it
   ```

   The OpenSSL banner reads like `OpenSSL 1.1.1w  11 Sep 2023`; SQLite carries its version (`3.45.1`) and a source ID that starts with the release date; zlib and libpng print theirs in copyright strings. BoringSSL has no release numbers, and libwebp has no version string, only `WebPGetDecoderVersion()`. Library file names (`libsqlcipher.so`, `libconscrypt_jni.so`, `libflutter.so`, `libhermes.so`) identify SDKs and frameworks even when nothing else does.

6. **Ask the library itself at runtime** when the binary has no version text. Calling a library's own version function inside the app on a test device is a read-only observation (adjust module names to what you found in step 5):

   ```javascript
   // frida -U -n "Example App" -l libversions.js   (attach after the app has loaded its native code)
   const webp = Process.findModuleByName('libexample-webp.so');
   const webpVer = webp && webp.findExportByName('WebPGetDecoderVersion');
   if (webpVer) {
     const v = new NativeFunction(webpVer, 'int', [])();
     console.log(`libwebp ${(v >> 16) & 0xff}.${(v >> 8) & 0xff}.${v & 0xff}`);
   }
   const sqlite = Process.findModuleByName('libsqlcipher.so');
   const sqliteVer = sqlite && sqlite.findExportByName('sqlite3_libversion');
   if (sqliteVer) console.log('SQLite ' + new NativeFunction(sqliteVer, 'pointer', [])().readCString());
   ```

   `Process.enumerateModules()` lists which of the app's libraries are actually loaded ([MASTG-TECH-0029](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0029/)).

7. **Check web and cross-platform layers:**

   ```bash
   find apk/assets -name '*.js' | head -50
   retire --path apk/assets                                    # known-vulnerable JavaScript libraries
   strings -a apk/lib/arm64-v8a/libapp.so 2>/dev/null | grep -oE 'package:[a-z0-9_]+/' | sort -u   # Flutter: Dart packages
   file apk/assets/index.android.bundle 2>/dev/null            # React Native: plain JS or Hermes bytecode
   ```

8. **Optionally generate a binary SBOM** and run it through the same matching as the source SBOM:

   ```bash
   blint sbom -i app-release.apk -o apk-sbom.json
   grype sbom:./apk-sbom.json
   ```

   Treat it as a list of leads. MASTG and blint's own documentation both describe APK-derived SBOMs as incomplete.

9. **Map each identified component and version to advisories**: OSV (`ecosystem: "Maven"`, `name: "group:artifact"`) for Java and Kotlin libraries, the NVD by CPE for native libraries, the Play SDK Index for registered SDKs, and the vendor's security page for closed-source SDKs.

#### Observation

An inventory table: component, version (or "unknown"), evidence (file, string, symbol, runtime call) and confidence, followed by the advisories that apply to each identified version.

#### Evaluation

The check **fails** if a shipped component is identified with a version inside the affected range of an applicable advisory. Where the version cannot be determined, say so and state what was tried; do not report a CVE against a guessed version. Components found here but missing from the developers' SBOM are reported as an inventory gap in MASTG-TEST-0274.

#### Demo

Illustrative output for a release build of the MASTG-DEMO-0050 app (OkHttp 4.9.1 declared with `implementation`):

```text
$ for f in apk/META-INF/*.version; do printf '%s\t%s\n' "$(basename "$f" .version)" "$(head -1 "$f")"; done | grep core
androidx.core_core          1.12.0
androidx.core_core-ktx      1.12.0
$ unzip -p app-release.apk 'classes*.dex' | strings -a | grep -E '^okhttp/[0-9]'
okhttp/4.9.1
```

OkHttp's User-Agent constant gives away the exact release, which falls inside the range of CVE-2021-0341 (fixed in 4.9.2). The same check against an app built with a current OkHttp returns the newer version and no match.

### GT-CODE-0044-2: Frameworks and versions in an IPA (iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The iOS counterpart of GT-CODE-0044-1: inventory dynamic frameworks with their versions, infer statically linked libraries, and find native libraries and web content, from a decrypted IPA and optionally from the running app. It replaces the "listing application libraries" part of legacy MASTG-TEST-0085 and follows [MASTG-TECH-0082](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0082/) and [MASTG-TECH-0158](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0158/).

#### Prerequisites

- A decrypted IPA ([MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/)): a development or ad hoc build from the client, or an App Store build decrypted on a test device. Check with `otool -l <binary> | grep -A4 LC_ENCRYPTION_INFO`; `cryptid 1` means the code is still encrypted and string searches will find nothing useful.
- macOS with the Xcode command line tools (`otool`, `nm`, `plutil`, `strings`), optionally radare2.
- Optional: a test device with Frida ([MASTG-TOOL-0039](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/)) or objection ([MASTG-TOOL-0074](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0074/)).

#### Steps

1. **Unpack** the IPA:

   ```bash
   mkdir ipa && unzip -q App.ipa -d ipa
   APP=$(find ipa/Payload -maxdepth 1 -name '*.app' | head -1)
   EXE=$(plutil -extract CFBundleExecutable raw -o - "$APP/Info.plist")
   ```

2. **List dynamic frameworks with their versions:**

   ```bash
   for fw in "$APP"/Frameworks/*.framework; do
     p="$fw/Info.plist"
     printf '%s\t%s\t%s\t%s\n' "$(basename "$fw" .framework)" \
       "$(plutil -extract CFBundleIdentifier raw -o - "$p" 2>/dev/null)" \
       "$(plutil -extract CFBundleShortVersionString raw -o - "$p" 2>/dev/null)" \
       "$(plutil -extract CFBundleVersion raw -o - "$p" 2>/dev/null)"
   done
   ls "$APP"/Frameworks/*.dylib 2>/dev/null         # Swift runtime dylibs (Apple), rarely anything else
   ```

   Bundle IDs of the form `org.cocoapods.<Pod>` mark CocoaPods frameworks, whose `CFBundleShortVersionString` is normally the pod version. Vendor frameworks usually carry the SDK version. A version of `1.0` for everything usually means the build system did not set it; do not read it as the library's version.

3. **Read the load commands** of every Mach-O, not only the main binary ([MASTG-TOOL-0060](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0060/)):

   ```bash
   otool -L "$APP/$EXE"
   for fw in "$APP"/Frameworks/*.framework; do otool -L "$fw/$(basename "$fw" .framework)"; done
   ls -d "$APP"/PlugIns/*.appex 2>/dev/null                 # extensions: repeat otool -L on each
   otool -l "$APP/$EXE" | grep -A2 LC_RPATH
   ```

   `@rpath/...` entries are bundled code; `/System/Library/` and `/usr/lib/` entries are the OS.

4. **Infer statically linked libraries** from what they leave in the main binary. Objective-C class names and Swift module names survive stripping:

   ```bash
   strings -a "$APP/$EXE" | grep -oE '\b(Alamofire|Kingfisher|SnapKit|RxSwift|Starscream|SDWebImage|AFNetworking|Realm|GRPC|NIOHTTP1|NIOCore|Firebase[A-Za-z]*|GTMSessionFetcher)\b' | sort | uniq -c
   strings -a "$APP/$EXE" | grep -E '^(AF|SD|FIR|GTM|FBSDK|RLM)[A-Z][A-Za-z]+$' | sort -u | head -40
   nm -U "$APP/$EXE" 2>/dev/null | grep -E 'VersionString|VersionNumber' | head
   ```

   `<Name>VersionString` and `<Name>VersionNumber` symbols come from Xcode's `apple-generic` versioning and usually hold the project's build number, not the library release. Treat them as presence indicators only.

5. **Find native C libraries and version text** in the main binary and in each framework, with the same patterns as step 5 of GT-CODE-0044-1 (OpenSSL banners, SQLite version and source ID, zlib, libpng, curl). A bundled `sqlite3` or OpenSSL in an iOS app is the app's responsibility to patch, unlike the system copies in `/usr/lib`.

6. **Use SDK fingerprints:** privacy manifests and resource bundles name SDKs even when their code is fully stripped.

   ```bash
   find "$APP" -name PrivacyInfo.xcprivacy
   find "$APP" -maxdepth 2 -name '*.bundle'
   ```

7. **Confirm at runtime** which bundled libraries load. With objection, `ios bundles list_frameworks` prints each framework with its bundle ID, version and path. With Frida:

   ```javascript
   // frida -U -n "Example App" -l modules.js
   Process.enumerateModules()
     .filter(m => m.path.includes('.app/'))
     .forEach(m => console.log(m.name + '\t' + m.path));
   ```

   Frameworks loaded later with `dlopen()` appear only after the feature that loads them has run.

8. **Check hybrid layers:** `main.jsbundle` (React Native), `www/` or `public/` (Cordova, Capacitor) with `retire --path`, and for Flutter the Dart package names in `Frameworks/App.framework/App` (`strings -a ... | grep -oE 'package:[a-z0-9_]+/'`).

9. **Map** each identified component and version to advisories: OSV `SwiftURL` and the GitHub Advisory Database for Swift packages, the pod's repository for pods, the NVD for native libraries, the vendor's advisories for closed SDKs.

#### Observation

An inventory table (component, version or "unknown", linkage: dynamic, static or loaded at runtime, evidence, confidence) and the advisories that apply to identified versions.

#### Evaluation

As GT-CODE-0044-1: the check **fails** if a shipped component with an identified version falls inside the affected range of an applicable advisory. Unknown versions are reported as a limitation. Differences between the IPA and the lock files or SBOM (a framework at a different version than `Cartfile.resolved` says, a vendor SDK no manifest mentions) are reported against MASTG-TEST-0273 or 0275.

#### Demo

Illustrative output of step 2 for an app that integrates its pods with `use_frameworks!`:

```text
Alamofire        org.cocoapods.Alamofire       5.8.1     1
VendorPaySDK     com.example.vendorpay.sdk     3.2.0     3200
```

Alamofire 5.8.1 can be matched directly against GitHub advisories. `VendorPaySDK` is a closed-source XCFramework; its version can only be checked against the vendor's release notes and security advisories, and step 5 against its binary is how you find out whether it embeds its own OpenSSL or SQLite. MASTG's legacy example shows the same information through objection's `list_frameworks` (CocoaPods frameworks such as Bolts and RealmSwift, each with its version).

### GT-CODE-0044-3: Reachability and exploitability of a reported CVE (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

A CVE against a component the app ships tells you that vulnerable code *may* be in the app. It does not tell you whether that code is in the binary, whether the app calls it, whether an attacker can get input to it, or under which conditions the bug triggers. Advisories are written for the component in general, and their CVSS vector describes the worst plausible use of it. This check answers those questions for one advisory at a time, so the finding can be rated for this app. Its result is a VEX-style decision: *affected* (with the attacker position and preconditions) or *not affected* (with a justification you can show).

#### Prerequisites

- A confirmed match from one of the tests above: component, shipped version, advisory.
- The advisory, its references and, where available, the fixing commit or pull request.
- The decompiled app (jadx for Android, a disassembler such as radare2 or Hopper for iOS); the R8 `mapping.txt` for Android if the developers can provide it.
- A test device with Frida for runtime confirmation, and the app's normal test accounts.

#### Steps

1. **Pin down the vulnerable code and its trigger.** From the advisory and the fix, write down the affected class, function or module, the kind of input that triggers the bug, and any configuration it needs. Examples: CVE-2021-0341 is in `OkHostnameVerifier` (every HTTPS connection through OkHttp's default verifier); CVE-2023-3635 is in Okio's `GzipSource` (gzip-encoded data); CVE-2022-1471 needs SnakeYAML's default `Constructor` parsing untrusted YAML; CVE-2023-4863 needs libwebp to decode an attacker-supplied lossless WebP image.

2. **Check that the code is in the binary.** R8 and the iOS linker remove unused code, and many libraries are modular.

   ```bash
   # Android, unobfuscated or kept library classes
   grep -rl 'class OkHostnameVerifier' jadx-out/sources
   # Android with R8: map the original name using the developers' mapping file
   grep -E '^okio\.GzipSource ->' mapping.txt
   # Native (both platforms): is the vulnerable function exported or present?
   llvm-readelf --dyn-syms -W apk/lib/arm64-v8a/libexample-webp.so | grep -E 'WebPDecode'
   ```

   If the code is absent, the result is *not affected: code not present*. Keep the evidence.

3. **Find the call paths from app code.** In jadx-gui, use *Find Usage* on the vulnerable method or on the library entry points that lead to it, and search the app's own packages for the APIs that would feed it:

   ```bash
   grep -rnE 'new Yaml\(|Yaml\(\)' jadx-out/sources/com/example/
   grep -rnE 'hostnameVerifier\(|HostnameVerifier' jadx-out/sources/com/example/
   ```

   A custom `HostnameVerifier` that replaces OkHttp's default, for example, removes `OkHostnameVerifier` from the path (and may introduce its own problems; see [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/)). On iOS, use cross-references to the library's Swift or Objective-C entry points in the disassembler.

4. **Confirm at runtime** that the app reaches the vulnerable code during normal use. A trace hook that logs calls and returns the original result changes nothing in the app's behaviour:

   ```javascript
   // Android: frida -U -f com.example.app -l trace-okhostname.js
   Java.perform(() => {
     const V = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
     V.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (host, session) {
       const ok = this.verify(host, session);
       console.log('[OkHostnameVerifier] ' + host + ' -> ' + ok);
       return ok;
     };
   });
   ```

   ```javascript
   // Native decoder in the app's own library (Android or iOS)
   const m = Process.findModuleByName('libexample-webp.so');
   Interceptor.attach(m.findExportByName('WebPDecode'), {
     onEnter(args) { console.log('WebPDecode, ' + args[1].toInt32() + ' bytes'); }
   });
   ```

   With R8, use the obfuscated class name from `mapping.txt`. Exercise the features that should lead there (log-in, feeds, image galleries, file import, chat) and note which ones do.

5. **Trace the input back to its source** and name the attacker position. Ask where the data that reaches the vulnerable call comes from:
   - the app's own backend only (attacker needs to compromise the server, or break TLS first);
   - content other users create, relayed by the backend (any registered user: images, messages, profile fields, shared documents);
   - third parties such as ad networks, CDNs or link previews (whoever controls that content);
   - another app on the device (exported components, content providers, deep links; see [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/));
   - a web page or link the user opens, or a file the user imports (one user interaction);
   - the network itself (any on-path attacker for TLS-layer bugs).

   The benign proof of reachability is an observation such as "an image another test account uploads reaches `WebPDecode` in the app's bundled libwebp", recorded with the hook above. Do not build or run an exploit for the CVE.

6. **Check the preconditions and mitigations.** Does the bug need a configuration the app does not use, an OS version below the app's minimum, or input the server already rejects? Does a separate control (certificate pinning in front of a hostname-verification bug, server-side image re-encoding in front of a decoder bug) block the attacker? Is the vulnerable library used in a separate process or extension with less access?

7. **Check what is known about exploitation:** the [CISA KEV catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), the [EPSS](https://www.first.org/epss/) score, public proof-of-concept code, and whether the CVE is part of a documented exploit chain. CVE-2023-4863, for example, is in KEV.

8. **Record the decision** in Dependency-Track or a CycloneDX VEX document: *exploitable* (or *affected*) with the attacker position and preconditions, or *not affected* with `code_not_present`, `code_not_reachable`, `requires_configuration` or `protected_by_mitigating_control`, and the evidence from steps 2 to 6.

#### Observation

Per advisory: whether the vulnerable code is present (with evidence), the call path from app code, the runtime trace, the input source and attacker position, the preconditions and mitigations, and the exploitation status (KEV, EPSS, public PoC).

#### Evaluation

This check does not pass or fail on its own. It classifies each confirmed match from the other tests as **affected and reachable by an attacker** (rate on impact and attacker position), **present but not reachable by an attacker** (Low), or **not affected** (code not present, or the trigger cannot occur; report as Info with the justification). An advisory you could not analyse stays *affected* and is rated on the advisory's own terms, with the gap stated.

#### Demo

CVE-2021-0341 in the MASTG-DEMO-0050 app. Step 2: OkHttp 4.9.1 is unobfuscated in the demo build and `okhttp3.internal.tls.OkHostnameVerifier` is present. Step 3: the app does not set its own `HostnameVerifier`. Step 4: the trace hook prints a line for each HTTPS host the app contacts during log-in, for example:

```text
[OkHostnameVerifier] api.example.com -> true
```

Step 5: the input is the server certificate, so the attacker is on the network path, and no user interaction is needed. Step 6: exploitation also requires a certificate from a CA the device trusts that the flawed comparison accepts for the app's host, which is a high bar; certificate pinning, if the app implements it correctly, would stop it independently. Result: affected, reachable by a network attacker with high attack complexity. Rate it Medium (High if the connection carries credentials and the app has no pinning), and recommend upgrading OkHttp.

## Secure implementation

MASWE-0044 has no OWASP best-practice pages. The patterns below are what we recommend to development teams.

### Android (Gradle)

Declare versions once in the version catalogue, lock the resolved graph, verify artefacts and override vulnerable transitive versions explicitly:

```kotlin
// app/build.gradle.kts
dependencies {
    implementation(libs.okhttp)                     // exact version in gradle/libs.versions.toml
    constraints {
        implementation("com.squareup.okio:okio:3.4.0") {
            because("CVE-2023-3635 (GzipSource), fixed in 3.4.0")
        }
    }
}

dependencyLocking {
    lockAllConfigurations()                         // ./gradlew :app:dependencies --write-locks
}
```

- Generate checksum verification metadata once with `./gradlew --write-verification-metadata sha256 help` and commit `gradle/verification-metadata.xml` ([Gradle dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html)); a substituted artefact then fails the build.
- Run dependency-check (with `failBuildOnCVSS`) or a CycloneDX SBOM plus Dependency-Track upload in CI on `releaseRuntimeClasspath`, and archive the SBOM with each release.
- Keep test and debug tools in `testImplementation`, `androidTestImplementation` and `debugImplementation`.
- Enable R8 for release builds. Removing unused library code reduces exposure; it is not a substitute for updating.
- Install the Google Play services security provider before network calls ([MASWE-0026](/mobile/maswe-0026-insecure-tls-protocol-versions/)):

  ```kotlin
  ProviderInstaller.installIfNeededAsync(context, object : ProviderInstaller.ProviderInstallListener {
      override fun onProviderInstalled() { startNetworking() }
      override fun onProviderInstallFailed(errorCode: Int, recoveryIntent: Intent?) {
          GoogleApiAvailability.getInstance().showErrorDialogFragment(activity, errorCode, REQUEST_PROVIDER)
      }
  })
  ```

- Leave `dependenciesInfo` enabled so Play Console can warn about known SDK issues, and act on the Play Console and Android Studio SDK Index warnings.

### iOS (SwiftPM, CocoaPods, Carthage)

- **SwiftPM:** commit `Package.resolved`; prefer version requirements over `branch:`; set the lower bound of `from:` to a release that contains the security fixes you rely on (the committed `Package.resolved` is the real pin, and `from:` still lets security releases in); use `binaryTarget` only with a checksum. In CI, build with `xcodebuild ... -disableAutomaticPackageResolution` so the build fails instead of silently resolving new versions.

  ```swift
  dependencies: [
      .package(url: "https://github.com/apple/swift-nio.git", from: "2.100.0"),
  ]
  ```

- **CocoaPods:** commit `Podfile.lock`, run `pod install --deployment` in CI (it refuses to change the lock file), pin `:git` pods to a `:tag` or `:commit`, keep test pods in test targets, and plan the move of pods to SwiftPM given the trunk's read-only date.
- **Carthage:** commit `Cartfile.resolved`, build with `carthage bootstrap` (which honours it), and check that the embedded frameworks match it.
- **Binary SDKs and vendored code:** require signed XCFrameworks and privacy manifests from vendors, ask them which open-source components and versions they embed, and add those to the SBOM by hand (with CPEs for native libraries).
- Use an update bot: Dependabot supports Swift packages, and Renovate supports both SwiftPM and CocoaPods.

### Process

- One SBOM per release, generated in CI from the release configuration, completed with vendored and native components, stored with the build and loaded into Dependency-Track (or an equivalent) for monitoring after release.
- Agreed response times by severity *after* reachability analysis, so a reachable critical issue gets fixed in days and an unreachable one does not block a release.
- Triage decisions recorded as VEX or suppressions with reasons and review dates.
- A short review before adding any SDK: maintenance activity, security advisories, Play SDK Index status, data collection, licence, and what it pulls in transitively.
- Periodic removal of SDKs and libraries the app no longer needs.

## Rating findings

Rate on four things: **what the vulnerable component does in this app** (and what the bug gives an attacker there), **whether the vulnerable code is reachable** with attacker-influenced input ([GT-CODE-0044-3](#gt-code-0044-3-reachability-and-exploitability-of-a-reported-cve-android-ios)), **the attacker position** (network attacker, malicious server or content, another user of the service, another app on the device, physical access) and **user interaction**, and **what is known about exploitation** (KEV, EPSS, public exploit). Start from the advisory's CVSS vector, then re-score it for the app (environmental metrics) and give both. An advisory's 9.8 for a parser the app never feeds untrusted data is not the app's 9.8, and saying so is what makes the rating defensible.

| Rating | Conditions |
|---|---|
| **Critical** | A shipped, reachable component has a known vulnerability that gives code execution in the app, or full loss of transport security on authentication traffic, without user interaction beyond normal use, and the input can be supplied by a remote attacker with no special position (another user of the service, an ad, a link preview, any network attacker on public Wi-Fi with no further preconditions). A KEV listing or public exploit for such a bug puts it here. |
| **High** | Reachable known vulnerability with code execution, authentication-material disclosure or significant data exposure that needs one user action (opening a file or link) or a constrained position (on-path attacker with high attack complexity on a channel that carries credentials, another app on the device reaching the component through IPC); or a reachable vulnerability in a component that processes other users' content where exploitation is plausible but not public. |
| **Medium** | Reachable known vulnerability with limited impact (remotely triggerable crash or resource exhaustion, low-value information disclosure); a high-impact bug whose input comes only from the app's own backend (attacker must compromise the server or defeat TLS first); a TLS-layer bug that a correctly implemented pin already blocks; a vulnerable component that is called but whose input could not be traced. |
| **Low** | The vulnerable component ships and the version is affected, but the vulnerable code is not reachable by an attacker (never called, feature disabled, input fully trusted), or exploitation requires physical access or a rooted or jailbroken device; unmaintained security-relevant libraries without known CVEs; Play Console or SDK Index warnings about outdated SDK versions with security implications. |
| **Info** | Matches that do not ship (test, debug, build tooling, CI components); CPE and name mismatches, which are not findings at all and appear only in a methods appendix; vulnerable code not present in the binary (removed by R8 or the linker); outdated versions without advisories; no SBOM or SCA process in place (process observation); licence observations. |

Raise a level when the component handles data from other users or from third parties at scale, when the issue is listed in KEV or has a high EPSS score, or when the same vulnerable component ships in several of the vendor's apps that share data. Lower a level when the app's minimum OS version or another independent control (pinning, server-side re-encoding of uploads, a separate process with no access to sensitive data) blocks the attack. Never lower because "the library is popular" or "no exploit is known yet". In the report, give for each finding: component and exact version, how it was identified (lock-file line, `dependencyInsight` output, binary evidence), the advisory IDs and the source you trust for the affected range, the first fixed version, the reachability evidence (call path and trace), the attacker position and user interaction, and the recommended upgrade. Group findings by component so that one upgrade closes several CVEs in one line of the remediation plan.

## References

- OWASP MASWE: [MASWE-0044: Dependencies with Known Vulnerabilities](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0044/); related [MASWE-0073](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0073/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-CODE-3](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0004](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0004/), [MASTG-KNOW-0059](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0059/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0272](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0272/), [MASTG-TEST-0274](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0274/), [MASTG-TEST-0273](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0273/), [MASTG-TEST-0275](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0275/); legacy [MASTG-TEST-0042](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0042/), [MASTG-TEST-0085](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0085/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0050](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0050/MASTG-DEMO-0050/), [MASTG-DEMO-0051](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0051/MASTG-DEMO-0051/), [MASTG-DEMO-0052](https://mas.owasp.org/MASTG/demos/ios/MASVS-CODE/MASTG-DEMO-0052/MASTG-DEMO-0052/), [MASTG-DEMO-0053](https://mas.owasp.org/MASTG/demos/ios/MASVS-CODE/MASTG-DEMO-0053/MASTG-DEMO-0053/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0130](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0130/), [MASTG-TECH-0131](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0131/), [MASTG-TECH-0132](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0132/), [MASTG-TECH-0133](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0133/), [MASTG-TECH-0129](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0129/), [MASTG-TECH-0157](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0157/), [MASTG-TECH-0029](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0029/), [MASTG-TECH-0007](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0007/), [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/), [MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/), [MASTG-TECH-0082](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0082/), [MASTG-TECH-0158](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0158/) (CC BY-SA 4.0)
- OWASP MASTG tools: [dependency-check (MASTG-TOOL-0131)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0131/), [Dependency-Track (MASTG-TOOL-0132)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0132/), [Visual Studio Code (MASTG-TOOL-0133)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0133/), [cdxgen (MASTG-TOOL-0134)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0134/), [blint (MASTG-TOOL-0130)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0130/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Frida for Android (MASTG-TOOL-0001)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [otool (MASTG-TOOL-0060)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0060/), [objection for iOS (MASTG-TOOL-0074)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0074/) (CC BY-SA 4.0)
- OWASP: [Vulnerable Dependency Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html), [Dependency-Check](https://owasp.org/www-project-dependency-check/) ([Gradle plugin configuration](https://dependency-check.github.io/DependencyCheck/dependency-check-gradle/configuration.html), [CLI arguments](https://dependency-check.github.io/DependencyCheck/dependency-check-cli/arguments.html), [suppression](https://jeremylong.github.io/DependencyCheck/general/suppression.html)), [Dependency-Track documentation](https://docs.dependencytrack.org/), [CycloneDX](https://cyclonedx.org/), [cdxgen project types](https://cdxgen.github.io/cdxgen/#/PROJECT_TYPES)
- Tools: [CycloneDX Gradle plugin](https://github.com/CycloneDX/cyclonedx-gradle-plugin), [osv-scanner](https://google.github.io/osv-scanner/), [OSV.dev](https://osv.dev/), [grype](https://github.com/anchore/grype), [syft](https://github.com/anchore/syft), [blint](https://github.com/owasp-dep-scan/blint), [retire.js](https://retirejs.github.io/retire.js/)
- Android Developers: [Add build dependencies](https://developer.android.com/build/dependencies) (incl. dependency information for Play Console and SDK insights), [Security best practices: keep services and dependencies up to date](https://developer.android.com/privacy-and-security/security-best-practices), [About user safety and SDKs](https://developer.android.com/guide/practices/sdk-best-practices), [Update your security provider](https://developer.android.com/training/articles/security-gms-provider); Google Play Help: [Using SDKs safely and securely](https://support.google.com/googleplay/android-developer/answer/13326895), [SDK vulnerabilities and policy labels in SDK Console](https://support.google.com/googleplay/android-developer/answer/14514531), [Google Play SDK Index](https://play.google.com/sdks); video: [Best practices for integrating SDKs into your app or game](https://www.youtube.com/watch?v=3klmiHX0uVQ); [Android Security Bulletin, February 2021](https://source.android.com/security/bulletin/2021-02-01)
- Apple: [App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/), [Third-party SDK requirements](https://developer.apple.com/support/third-party-SDK-requirements/), [WWDC23: Get started with privacy manifests](https://developer.apple.com/videos/play/wwdc2023/10060/), [Swift packages](https://developer.apple.com/documentation/xcode/swift-packages); [Swift Package Manager](https://www.swift.org/documentation/package-manager/), [CocoaPods](https://cocoapods.org/), [CocoaPods Specs repo announcement](https://blog.cocoapods.org/CocoaPods-Specs-Repo/), [Carthage](https://github.com/Carthage/Carthage)
- SBOM and supply-chain guidance: [NTIA, The Minimum Elements for a Software Bill of Materials](https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf), [CISA, Types of SBOM Documents](https://www.cisa.gov/sites/default/files/2023-04/sbom-types-document-508c.pdf), [NIST SP 800-218 (SSDF)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf), [Gradle dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html), [CISA KEV catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://www.first.org/epss/)
- Advisories cited: [CVE-2016-2402](https://nvd.nist.gov/vuln/detail/CVE-2016-2402), [CVE-2021-0341 / GHSA-3cqm-mf7h-prrj](https://github.com/advisories/GHSA-3cqm-mf7h-prrj), [CVE-2023-0833](https://nvd.nist.gov/vuln/detail/CVE-2023-0833), [CVE-2023-3635 / GHSA-w33c-445m-f8w7](https://github.com/advisories/GHSA-w33c-445m-f8w7), [CVE-2015-3996](https://nvd.nist.gov/vuln/detail/CVE-2015-3996), [CVE-2023-4863](https://nvd.nist.gov/vuln/detail/CVE-2023-4863), [CVE-2022-1471](https://nvd.nist.gov/vuln/detail/CVE-2022-1471), [CVE-2022-3215 / GHSA-7fj7-39wj-c64f](https://github.com/advisories/GHSA-7fj7-39wj-c64f), [GHSA-mgc4-wqv7-4pxm](https://github.com/advisories/GHSA-mgc4-wqv7-4pxm), [GHSA-rj37-6j9x-74q6](https://github.com/advisories/GHSA-rj37-6j9x-74q6), [CVE-2020-9861](https://nvd.nist.gov/vuln/detail/CVE-2020-9861), [CVE-2022-1642](https://nvd.nist.gov/vuln/detail/CVE-2022-1642), [CVE-2022-3918](https://nvd.nist.gov/vuln/detail/CVE-2022-3918)
- CWE: [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html), [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
