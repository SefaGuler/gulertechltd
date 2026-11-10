---
title: "MASWE-0048: Malicious Code Included in the App"
date: 2026-11-10 10:07:00 +0000
subcategory: code
summary: "Checking your own release build for hidden or unexpected code: SDK inventory, build diffs, backdoor indicators, runtime destinations, pipeline integrity."
refs: [MASWE-0048, MASVS-CODE-3, CWE-506, CWE-507, CWE-511]
tags: [android, ios, masvs-code, supply-chain, sdk, build-integrity]
---

This note is part of our [MASVS-CODE guide](/mobile/masvs-code-code-quality-guide/) and covers OWASP [MASWE-0048](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0048/): an app that ships code its owner did not intend to ship. That code may have been planted by an insider, pulled in by a compromised or hostile SDK, injected by a build tool or CI job, or simply left behind as a "temporary" test switch that nobody removed. The note is written for two readers: app owners who need to show that their release build contains what they think it contains, and assessors asked to give that assurance. Everything here is review and detection on the app's own artefacts: its source, lockfiles, build configuration, release binaries and runtime behaviour. **OWASP has no MASTG tests and no Knowledge pages for MASWE-0048**, so the background and the five checks below (GT-CODE-0048-1 to GT-CODE-0048-5) are Guler Tech methodology. The note complements [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) (dependencies with *known vulnerabilities*) and OWASP's [MASWE-0075 Non-Reproducible Builds](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0075/) (being unable to prove *what was built*). It also links to [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/) for code that arrives after installation.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Android and iOS: What counts as malicious code](#android-and-ios-what-counts-as-malicious-code)
  - [Android and iOS: Supply-chain entry points](#android-and-ios-supply-chain-entry-points)
  - [Android: Gradle, Maven repositories and build plugins](#android-gradle-maven-repositories-and-build-plugins)
  - [iOS: CocoaPods, Swift Package Manager, Carthage and binary frameworks](#ios-cocoapods-swift-package-manager-carthage-and-binary-frameworks)
  - [Cross-platform: npm and pub in React Native and Flutter apps](#cross-platform-npm-and-pub-in-react-native-and-flutter-apps)
  - [Android and iOS: Publicly documented incidents](#android-and-ios-publicly-documented-incidents)
  - [Android: Google Play rules for SDKs and code transparency](#android-google-play-rules-for-sdks-and-code-transparency)
  - [iOS: Apple third-party SDK requirements and hidden features](#ios-apple-third-party-sdk-requirements-and-hidden-features)
  - [Android and iOS: Hidden functionality and backdoors](#android-and-ios-hidden-functionality-and-backdoors)
- [Tests](#tests)
  - [Before you start: collect the evidence set](#before-you-start-collect-the-evidence-set)
  - [GT-CODE-0048-1: SDK and dependency inventory against an approved list (Android, iOS)](#gt-code-0048-1-sdk-and-dependency-inventory-against-an-approved-list-android-ios)
  - [GT-CODE-0048-2: Release build diff against source and the previous release (Android, iOS)](#gt-code-0048-2-release-build-diff-against-source-and-the-previous-release-android-ios)
  - [GT-CODE-0048-3: Hidden functionality and backdoor indicators (Android, iOS)](#gt-code-0048-3-hidden-functionality-and-backdoor-indicators-android-ios)
  - [GT-CODE-0048-4: Unexpected network destinations at runtime (Android, iOS)](#gt-code-0048-4-unexpected-network-destinations-at-runtime-android-ios)
  - [GT-CODE-0048-5: Build pipeline and dependency-integrity controls (Android, iOS)](#gt-code-0048-5-build-pipeline-and-dependency-integrity-controls-android-ios)
  - [Supplementary: reputable scanners](#supplementary-reputable-scanners)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0048 applies when the app package contains malicious code. The OWASP requirement is *"The app package does not contain malicious code."* It maps to [MASVS-CODE-3](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/) and to three CWEs:

| CWE | Name | What it looks like in a mobile app |
|---|---|---|
| [CWE-506](https://cwe.mitre.org/data/definitions/506.html) | Embedded Malicious Code | An SDK or module that collects or sends data, clicks ads or runs commands without the owner's knowledge |
| [CWE-507](https://cwe.mitre.org/data/definitions/507.html) | Trojan Horse | A library that does what its README says *and* something else (an "analytics" module that also reads the photo library) |
| [CWE-511](https://cwe.mitre.org/data/definitions/511.html) | Logic/Time Bomb | Code that stays dormant until a date, a server flag, a locale, an account or an app version activates it |

MASVS-CODE-3 is worded around components "without known vulnerabilities", which fits MASWE-0044 better than this weakness. OWASP files MASWE-0048 under it anyway because both are about trusting third-party code. Expect to explain this in reports: a clean SCA scan does not satisfy MASWE-0048, because malicious code rarely has a CVE on the day it ships.

OWASP describes the threat as MAS-THREAT-0048, *"Attackers can run malicious functionality inside the trusted app"*, reached through two attacks:

| Attack | Description | Attacker position |
|---|---|---|
| MAS-ATTACK-0060 | Compromising a dependency, SDK or build tool in the app's supply chain | Supply chain: package registry account, SDK vendor, build plugin, CI system, developer tooling |
| MAS-ATTACK-0061 | Introducing malicious code through an insider or a compromised developer account | Insider, or an outsider holding a developer's credentials or session |

Neither needs anything from the end user. The code arrives through the normal update channel, signed with the owner's key and approved by the store, and runs with every permission and every piece of data the user has granted to the app. That is why the weakness is tagged for profiles L1, L2 and EUDIW: every app is exposed to it, not just high-assurance ones.

Keep the neighbouring weaknesses apart:

| Question | Where it lives |
|---|---|
| Does a dependency have a published vulnerability (CVE, advisory)? | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) |
| Can anyone rebuild the released binary from source and get the same bytes? | [MASWE-0075](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0075/) (MASVS-PRIVACY) |
| Does the app download and run code after installation? | [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/) |
| Are secrets or test credentials hard-coded in the package? | [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/) (a hard-coded test *account that works* is also a backdoor indicator here) |
| Does the shipped code contain code that is present *on purpose* and does something the owner did not intend? | This note |

One limitation needs saying early. No test can prove the *absence* of malicious code. What you can do is shrink the space where it could hide: you know every component, every component is accounted for, the release build matches reviewed source, the app talks only to expected destinations, and the pipeline would make tampering hard and visible. The checks in this note are built around that idea. Report results as "no unexpected functionality found within the following scope", never as "the app is free of malware".

## Modes of Introduction

**Malicious developer or compromised developer account.** Someone with commit rights adds code that is hard to spot in review: a condition in the login path, an "analytics" call to a new host, a feature flag with a default that does something else. A stolen session or token on a code-hosting account has the same effect. Weak points are review rules that allow self-approval, admin bypass of branch protection, and force-pushes to release branches.

**Compromised or hostile dependencies.** A library or SDK that is malicious from the start (published under a look-alike name, a *typosquat*), one that turns malicious when a maintainer account is taken over or ownership is transferred, or one whose vendor adds data collection or ad fraud the app owner never agreed to. In Java and Kotlin ecosystems there is also *dependency confusion*: a private group or package name that a public repository can also serve, combined with a build that asks the public repository first.

**Compromised build tools and plugins.** Gradle plugins, Kotlin compiler plugins, annotation processors and KSP processors run inside the build and can change bytecode. CocoaPods runs `prepare_command` from pod specs and the `post_install` hook from the Podfile. SwiftPM build-tool plugins and Swift macros run during the build. npm packages can declare install scripts. A tampered IDE or SDK (the XcodeGhost case below) changes every app built with it.

**Compromised CI/CD.** The build runs somewhere other than a developer's laptop: a hosted or self-hosted runner, a pipeline defined in the repository, third-party actions or orbs, cached dependencies and signing secrets. Whoever controls one of those can change the artefact after review and before signing.

**Hidden functionality.** Debug menus, QA shortcuts, hard-coded test accounts, "magic" parameters, environment switches and remote-config flags that enable code nobody reviewed for production. Most of this is not written with bad intent, but the effect is the same: functionality in the shipped app that the owner, the store and the user do not know about.

## Impact

- **Compromise of sensitive data.** The code runs inside the app's sandbox with the app's permissions and keys. It can read whatever the app can read (tokens, messages, files, photos, location, contacts if granted) and send it out with the app's own network stack, so it looks like normal app traffic.
- **Execution of unauthorised code.** Backdoors and dormant features can be switched on remotely and at any time, for one user or for everyone. They give an attacker actions under the user's identity, or a way round authentication.
- **Harm to the owner's business.** The owner distributes malware to their own users. That can lead to app removal and developer account action under store policy, incident response, data protection breach notification (in the UK, ICO notification within 72 hours where the UK GDPR threshold is met), and lasting loss of trust.
- **Scale.** A single malicious dependency reaches every user of every app that ships it, which is why attackers target popular SDKs and build tools rather than individual apps.

## Mitigations

- **Review code and changes.** Require review by someone other than the author for every change to protected branches, including build files, CI definitions and lockfiles. Enforce strong authentication (hardware-backed MFA) for code hosting, package registries and store consoles, and remove access when people leave.
- **Know and limit the supply chain.** Keep an approved list of SDKs and libraries with an owner and a purpose for each. Pin versions with lockfiles, verify checksums or signatures, restrict which repository may serve which package, and monitor components with SCA ([MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/)).
- **Protect the build pipeline.** Build releases only in CI from reviewed commits. Pin CI actions and images by digest, keep signing keys out of developer machines, scope secrets to release jobs, and produce provenance attestations (SLSA). Aim for reproducible builds ([MASWE-0075](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0075/)).
- **Analyse the shipped artefact.** Before each release, diff the release build against the previous one and against what the source says it should contain, observe its network destinations, and scan it. Investigate everything you cannot explain.
- **Keep debug code out of release builds.** Use build variants, source sets and compile-time conditions so that test-only code is not compiled into release builds, rather than relying on runtime checks.

## Background

There are no OWASP Knowledge pages for this weakness. This section explains where malicious code enters Android and iOS builds, what the stores require, and what hidden functionality looks like, so that the tests make sense.

### Android and iOS: What counts as malicious code

The boundary is intent and disclosure, not technique. The same Frida-visible behaviour, "reads the clipboard and posts it to a server", can be a disclosed feature, an SDK behaving outside its contract, or malware. For a review, classify what you find into four groups:

| Group | Example | How to treat it |
|---|---|---|
| Malicious | Credential or key exfiltration, ad-fraud clickers in hidden WebViews, remote command execution, logic bombs | Incident: stop the release, involve incident response |
| Undisclosed data collection by an SDK | An SDK collects installed-app lists, precise location or contact data beyond what the owner configured and declared | Policy and privacy breach. On Google Play it can fall under the [Malware and Mobile Unwanted Software policies](https://support.google.com/googleplay/android-developer/answer/13326895); on iOS it contradicts the privacy manifest and nutrition label |
| Hidden functionality | Debug menu, hard-coded test account, magic deep-link parameter, undocumented server switch | Security finding; severity depends on what it unlocks |
| Unexplained but benign | A transitive library nobody chose, a leftover sample class, an unused native library | Hygiene finding; still remove or document it, because "unexplained" is what malicious code looks like at first |

Both store operators treat SDK behaviour as the app owner's responsibility. Google's guidance on [using SDKs safely and securely](https://support.google.com/googleplay/android-developer/answer/13326895) states that developers are responsible for making sure third-party SDK code and practices in their app comply with Play policy, and that data collected by an SDK is treated as if the developer collected it. Apple's [third-party SDK requirements](https://developer.apple.com/support/third-party-SDK-requirements/) say the same about all code an SDK brings into the app. "The vendor did it" does not change the rating.

### Android and iOS: Supply-chain entry points

Map each place where code enters the build. The tests in this note check each row.

| Entry point | Android | iOS | Typical control | Test |
|---|---|---|---|---|
| Direct and transitive libraries | Maven Central, Google Maven, JitPack, vendor repositories; AAR/JAR files in `libs/` | CocoaPods trunk or private spec repos, SwiftPM (Git URLs or registries), Carthage, vendored `.xcframework`s | Approved list, lockfiles, checksums, repository content filtering | GT-CODE-0048-1, GT-CODE-0048-5 |
| Closed-source SDK binaries | AARs with obfuscated classes and `.so` libraries | Binary `.xcframework`s, static `.a` libraries | Vendor due diligence, privacy manifests, XCFramework signatures, runtime observation | GT-CODE-0048-1, GT-CODE-0048-4 |
| Build tooling | Gradle wrapper, Android Gradle Plugin, third-party Gradle plugins, Kotlin compiler plugins, KSP/kapt processors | Xcode itself, CocoaPods hooks and `prepare_command`, SwiftPM plugins and macros, build-phase scripts | Pinned versions and checksums, plugin allow-list, trust prompts not skipped | GT-CODE-0048-5 |
| Cross-platform layers | npm packages bundled into `index.android.bundle`, Dart packages compiled into `libapp.so` | Same, `main.jsbundle`, `App.framework` | Lockfiles with integrity hashes, install-script review | GT-CODE-0048-1, GT-CODE-0048-5 |
| CI/CD | Workflow files, runners, third-party actions, caches, signing secrets | Same, plus App Store Connect API keys and distribution certificates | Branch protection, pinned actions, isolated release jobs, provenance | GT-CODE-0048-5 |
| First-party source | Insider changes, leftover debug code | Same | Review, release diff, hidden-functionality review | GT-CODE-0048-2, GT-CODE-0048-3 |
| Remote configuration | Firebase Remote Config, feature-flag SDKs, own config endpoints | Same | Inventory of flags, review of what each one enables | GT-CODE-0048-3, GT-CODE-0048-4 |

### Android: Gradle, Maven repositories and build plugins

**Resolution order and repository trust.** Gradle tries the repositories declared in `settings.gradle(.kts)` (`dependencyResolutionManagement`) or in the module, in order, and takes the first one that has the requested module. If `mavenCentral()` or a broad proxy comes before your private repository, and your internal group (`com.example.internal`) is not registered on Maven Central, someone else can publish that group there. The usual fix is *repository content filtering*: `exclusiveContent` or `content { includeGroup(...) }`, so that a given group can only ever come from one repository (see [Secure implementation](#secure-implementation)). JitPack builds artefacts from any public Git repository on request. That is convenient, but it means the artefact is only as trustworthy as that repository and its tags.

**Dynamic versions.** `implementation("com.example:sdk:2.+")`, version ranges and `latest.release` let a new upstream release enter your build without a code change. Gradle [dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html) writes the resolved versions to `gradle.lockfile` (and `buildscript-gradle.lockfile` for the build script classpath) when you run a build with `--write-locks`. After that the build fails if resolution would produce something else.

**Checksums and signatures.** Gradle [dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html) checks every downloaded artefact, including plugins and build-script dependencies, against `gradle/verification-metadata.xml`. That file lists the expected SHA-256 (or SHA-512) checksums and, optionally, trusted PGP keys. You generate it with `./gradlew --write-verification-metadata sha256 help` and run builds with the default strict mode. Generating the file only records what you downloaded at that moment. If a component was already malicious then, the file locks in the malicious version, so someone has to review the first generation and every diff to it. Verification is also only as good as its enforcement: `--dependency-verification lenient` or `off` on the command line, or `org.gradle.dependency.verification` in `gradle.properties`, turns it into a warning or disables it.

**The Gradle wrapper.** `gradlew` downloads the Gradle distribution named in `gradle/wrapper/gradle-wrapper.properties`. Setting `distributionSha256Sum` there makes the wrapper check the checksum of the distribution. The `gradle-wrapper.jar` committed to the repository is itself executable code; Gradle publishes checksums for it and a [wrapper validation action](https://github.com/gradle/actions) for CI.

**Plugins change bytecode.** Gradle plugins run arbitrary code at configuration and execution time. The Android Gradle Plugin's instrumentation API (`AsmClassVisitorFactory`, registered with `transformClassesWith`) lets a plugin rewrite every class of a variant before dexing. Performance monitoring and some SDKs use it for legitimate reasons. It also means a plugin can change release code without any change to your source. The same is true of Kotlin compiler plugins. Init scripts in `~/.gradle/init.d/` or in `GRADLE_USER_HOME` on a CI runner apply to every build on that runner without appearing in the repository.

**What ends up in the APK.** R8 shrinks, optimises and obfuscates. Class and package names in a release APK often do not match the source unless you keep the `mapping.txt` file for each release. AndroidX and some other libraries add `META-INF/*.version` files. The dependency metadata that AGP adds to the signing block for Google Play is encrypted for Google and you cannot use it for an audit. Inventory and diffs therefore work best on the project (`./gradlew :app:dependencies`) together with the mapping file.

### iOS: CocoaPods, Swift Package Manager, Carthage and binary frameworks

**CocoaPods.** `Podfile.lock` pins the exact pod versions (`PODS`), where each came from (`SPEC REPOS`, `EXTERNAL SOURCES`, `CHECKOUT OPTIONS` with a Git commit for Git sources) and a `SPEC CHECKSUMS` section. Those checksums are SHA-1 hashes of each pod's *podspec*, not of the downloaded source or binary. A changed tag or a replaced HTTP archive behind an unchanged podspec is not detected by them. Podspecs can declare a `prepare_command` (a shell command run when the pod is downloaded) and `script_phases` (build phases added to your target). The Podfile's `post_install` hook runs Ruby on your machine with your project open. All of these are code execution in your build. In 2024 researchers at E.V.A Information Security published vulnerabilities in the CocoaPods trunk server in 2024, including the ability to claim ownership of "orphaned" pods ([CVE-2024-38368](https://nvd.nist.gov/vuln/detail/CVE-2024-38368)). CocoaPods fixed these on the server side in 2023, but the case shows why a pod's identity does not prove its owner. The CocoaPods maintainers have also [announced](https://blog.cocoapods.org/) that trunk becomes read-only (planned for 2 December 2026): existing versions stay installable, but no new pods or versions will be published. Pods you still depend on will no longer receive fixes through trunk, so this is a good moment to inventory them.

**Swift Package Manager.** `Package.resolved` (in `<App>.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/` or `<App>.xcworkspace/xcshareddata/swiftpm/`) records, for each package, its identity, location (Git URL), version and the exact Git `revision`. Pinning a commit hash is SwiftPM's integrity control for source packages, so `Package.resolved` must be committed and enforced in CI with `xcodebuild -onlyUsePackageVersionsFromResolvedFile` or `-disableAutomaticPackageResolution`. Remote binary targets (`.binaryTarget(name:url:checksum:)`) have to declare a SHA-256 checksum, and SwiftPM refuses an archive that does not match it. Package plugins (build-tool and command plugins) and Swift macros run code during the build. Xcode asks the developer to trust and enable each one. CI scripts often pass `-skipPackagePluginValidation` and `-skipMacroValidation` to `xcodebuild` to avoid that prompt. When they do, nothing asks whether a new plugin version should be trusted.

**Carthage.** `Cartfile.resolved` pins Git tags or commits. Prebuilt binaries are fetched from a JSON specification URL (`binary "https://..."`), and Carthage does not verify a checksum for those downloads, so their integrity rests on the hosting.

**Binary frameworks and XCFramework signatures.** Closed-source SDKs arrive as `.xcframework`s. Since Xcode 15, Xcode records the signing identity of a signed XCFramework and reports an error if a later version is signed by someone else or no longer signed ([Verifying the origin of your XCFrameworks](https://developer.apple.com/documentation/xcode/verifying-the-origin-of-your-xcframeworks)). The signature lives in `_CodeSignature/` inside the bundle, and `codesign -dv --verbose=2 Vendor.xcframework` shows the authority and Team ID. This confirms *who* built the framework, not *what* it does.

**The toolchain.** Xcode is the build tool for every iOS app. Install it only from the Mac App Store or developer.apple.com, and check its signature with `codesign --verify --deep --strict /Applications/Xcode.app` and `spctl --assess --verbose /Applications/Xcode.app`. XcodeGhost (below) is the reason. App Store builds are no longer recompiled from bitcode (bitcode was deprecated in Xcode 14), so the binary Apple distributes is the one your archive produced, encrypted with FairPlay and re-signed by Apple.

### Cross-platform: npm and pub in React Native and Flutter apps

React Native apps compile their npm dependency tree into one JavaScript bundle (`assets/index.android.bundle` in the APK, `main.jsbundle` in the IPA). This is often the largest third-party footprint of the app and the one native reviews miss. `package-lock.json` (or `yarn.lock`, `pnpm-lock.yaml`) records an `integrity` hash (normally SHA-512) for every package. `npm ci` installs exactly what the lockfile says and fails if `package.json` and the lockfile disagree. Packages can declare `preinstall`, `install` and `postinstall` scripts that run on the build machine. In lockfile v2 and v3 they are marked with `"hasInstallScript": true`.

Flutter apps compile Dart packages into native code (`lib/<abi>/libapp.so` on Android, `App.framework` on iOS). `pubspec.lock` pins versions, and recent Dart SDKs also record a `sha256` for packages from pub.dev. `dart pub get --enforce-lockfile` (also `flutter pub get --enforce-lockfile`) refuses to change the lockfile and checks those hashes. Flutter plugins also bring their own Gradle and CocoaPods or SwiftPM dependencies, so a Flutter app has three dependency trees to review, not one.

### Android and iOS: Publicly documented incidents

These public cases each show a different entry point. We describe them only at the level of "what was compromised and what defenders learned". Follow the sources for details.

| Year | Case | Entry point | Lesson for app owners |
|---|---|---|---|
| 2015 | **XcodeGhost**: modified copies of Xcode, distributed outside Apple's channels, linked extra code into every app built with them. Infected apps passed App Review and reached the App Store. Apple removed affected apps and asked developers to rebuild with a genuine Xcode. ([Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/novel-malware-xcodeghost-modifies-xcode-infects-apple-ios-apps-and-hits-app-store/)) | Build toolchain | Install tools only from the vendor and verify their signatures. Store review does not catch everything. A release diff would have shown unexpected code and a new network destination. |
| 2018 | **event-stream**: a popular npm package was handed over to a new maintainer, who added a dependency (`flatmap-stream`) containing obfuscated code aimed at one specific application, the Copay cryptocurrency wallet. npm removed the packages. ([npm blog](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident)) | Transitive dependency, maintainer change | JavaScript bundled into hybrid and React Native apps is part of the app. Lockfile changes in transitive packages need review, and a change of maintainer is a risk signal. |
| 2021 | **Codecov Bash Uploader**: the script that many CI pipelines downloaded and ran on every build was modified to send CI environment variables to a third party. ([Codecov security update](https://about.codecov.io/security-update/)) | CI tooling | CI jobs that fetch and run remote scripts without checking them expose every secret in that job, including signing material. Pin and verify, and scope secrets to release jobs. |
| 2023 | **Goldoson**: a third-party Android library found in more than 60 Google Play apps collected device data (installed apps, nearby Wi-Fi and Bluetooth devices, location) and could load ad pages in hidden WebViews. McAfee reported that the app developers had not written it. Google removed or required updates to the apps. ([McAfee Labs](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/goldoson-privacy-invasive-and-clicker-android-adware-found-in-popular-apps-in-south-korea/)) | Third-party SDK | An SDK can do more than its description says, and the store holds the app owner responsible. Runtime observation of destinations and data access finds this kind of behaviour. |
| 2024 | **xz-utils (CVE-2024-3094)**: after a long effort to become a trusted maintainer, someone added a backdoor to release tarballs of a widely used compression library. It was found before it reached most stable Linux distributions. ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-3094)) | Insider in an upstream project | Not a mobile case, but the clearest public example of a malicious maintainer. Release artefacts differed from the Git source, which is exactly what reproducible builds and release diffs are designed to catch. |
| 2025 | **SparkCat**: Kaspersky found an SDK in apps on both Google Play and the App Store that used on-device OCR to look for cryptocurrency recovery phrases in users' photo galleries. The apps were removed. ([Kaspersky](https://www.kaspersky.com/blog/ios-android-ocr-stealer-sparkcat/52980/)) | Third-party SDK | Both platforms are affected, App Review included. Permissions granted for a legitimate feature (photo access) are available to every SDK in the app. |

The common thread: in every case the shipped code was signed by a legitimate party and delivered through a legitimate channel. What gave it away was behaviour (new destinations, data access) or a mismatch between the source and the shipped artefact.

### Android: Google Play rules for SDKs and code transparency

- **Owner responsibility.** [Using SDKs safely and securely](https://support.google.com/googleplay/android-developer/answer/13326895) makes the developer responsible for SDK compliance and requires non-compliant SDK versions to be removed or replaced. It lists the policies SDKs most often violate, including Malware, Mobile Unwanted Software, User Data and Permissions, and notes that bad SDK code can make an app violate an unrelated policy.
- **Google Play SDK Index.** The [SDK Index](https://play.google.com/sdks) lists widely used SDKs with their data-collection details and, where relevant, labels for versions that are outdated or violate policy. Play Console also warns about such versions in your releases. Check it as part of GT-CODE-0048-1.
- **Data safety form.** What the app and all of its SDKs collect has to match the Data safety section. Data that a runtime check observes leaving the device but the form does not declare is a compliance finding, whatever the security rating.
- **Code transparency for app bundles.** With [code transparency](https://developer.android.com/guide/app-bundle/code-transparency), the developer signs a list of the hashes of all DEX files and native libraries in the bundle with a separate key that only the developer holds. Anyone can then check that the code on a device matches it: `bundletool check-transparency --mode=connected_device --package-name="com.example.app"`. This answers "did the code change between my build and the device?", which matters because Play App Signing means Google holds the app signing key. It does not cover resources, assets or the manifest, and post-build anti-tamper tools break it.
- **Play-side changes.** Some Play services, for example the automatic integrity protection offered with the Play Integrity API, add code to the delivered app after upload. A diff between your build and a Play-delivered APK must allow for such changes and confirm they are the documented ones.

### iOS: Apple third-party SDK requirements and hidden features

- **Privacy manifests.** A `PrivacyInfo.xcprivacy` property list declares an app's or SDK's data collection (`NSPrivacyCollectedDataTypes`), tracking status and tracking domains (`NSPrivacyTracking`, `NSPrivacyTrackingDomains`), and the reasons it uses certain APIs (`NSPrivacyAccessedAPITypes`). Xcode combines all manifests into a privacy report (Organizer, archive, *Generate Privacy Report*). On iOS 17 and later, the system blocks connections to declared tracking domains unless the user has granted App Tracking Transparency permission. See Apple's [privacy manifest files](https://developer.apple.com/documentation/bundleresources/privacy-manifest-files).
- **Commonly used SDKs.** Apple's [third-party SDK requirements](https://developer.apple.com/support/third-party-SDK-requirements/) list SDKs that must include a privacy manifest and, when used as binary dependencies, a valid signature. Since [1 May 2024](https://developer.apple.com/news?id=pvszzano) App Store Connect enforces this for new apps and for updates that add a listed SDK. The page says the developer is responsible for all code the SDK brings into the app.
- **Signatures.** Covered above: Xcode validates that a new version of a signed SDK comes from the same developer.
- **No hidden features.** [App Store Review Guideline](https://developer.apple.com/app-store/review/guidelines/) 2.3.1(a) prohibits hidden, dormant or undocumented features, and 2.5.2 restricts downloading or executing code that changes the app's features. A remote-config switch that unlocks a feature App Review never saw conflicts with both, so for an iOS app it is a store-compliance problem as well as a security one.

A privacy manifest is a declaration, not enforcement (except for tracking domains). It tells you what an SDK *says* it does. GT-CODE-0048-4 checks what it actually does.

### Android and iOS: Hidden functionality and backdoors

Most hidden functionality we find in assessments was left in on purpose by the development team, not planted by an attacker. It is still a finding, because an attacker who discovers it can use it, and because it is indistinguishable from a deliberate backdoor until someone asks. The common forms:

| Form | What it looks like | Why it matters |
|---|---|---|
| Debug or QA menu | An activity or view controller reached by a gesture (shake, long-press, N taps on the logo), a hidden deep link, or an exported component | Environment switching, feature-flag overrides, log export, "skip" buttons for verification steps |
| Hard-coded test accounts or OTPs | `if (email == "qa@example.com")` short-circuits login, or a fixed OTP is always accepted | Authentication bypass if the backend trusts the client, or if the same account also exists in production |
| Magic parameters | A query parameter, intent extra, HTTP header or launch argument that unlocks functionality | Reachable by anyone who learns the string, often from a deep link |
| Environment switches | Build includes staging or development base URLs that can be selected at runtime | Traffic to less-protected backends, a way to point the app at an attacker's server |
| Undisclosed remote-config switches | Flags whose default is off but which enable unreviewed code paths (extra data collection, alternative payment flows, code download) | Logic bomb pattern (CWE-511): behaviour changes without a release, for chosen users |
| Time, locale or install-source conditions | Code that only runs after a date, outside certain countries, or when not installed from a store | Classic evasion of store review; legitimate uses exist (regional features), so review what it gates |

Remote configuration and server-driven features are normal, and they are not the problem in themselves. The problem is a switch that turns on *code nobody reviewed for production*, or that turns on behaviour the privacy disclosures do not cover. The question for every flag is: what code runs when it is true, and has that code passed the same review as the rest of the release?

## Tests

OWASP has no MASTG tests for MASWE-0048, and no legacy (MASTG v1) test in the MASVS-CODE folders is mapped to it, so these tests replace nothing. The five checks below are Guler Tech methodology. They work best when the app owner gives you source access (white-box), but GT-CODE-0048-2, -3 and -4 also give useful results with only the release binaries.

All checks look at the app under test and its own build. Where we need proof, it is an observation: a diff line, a manifest entry, a lockfile entry, a domain in a traffic log, a Frida trace of the app's own method. No check requires writing or running malicious code.

### Before you start: collect the evidence set

Agree the scope with the app owner and collect these artefacts first:

| Artefact | Android | iOS |
|---|---|---|
| Release build under review | The AAB as uploaded, plus the APKs the store delivers to a test device (`adb shell pm path com.example.app`, then `adb pull` each path) | The exported IPA from the release archive (not encrypted), and the App Store build installed on a test device |
| Previous release | Same, for release N-1 | Same |
| Source at the release tag | Repository at the exact commit CI built | Same |
| Symbol and mapping files | R8 `mapping.txt` for both releases | dSYMs (optional, helps with symbol names) |
| Dependency state | `gradle.lockfile`(s), `gradle/verification-metadata.xml`, `package-lock.json`/`pubspec.lock` if relevant | `Podfile.lock`, `Package.resolved`, `Cartfile.resolved`, vendored frameworks |
| Declarations | Approved SDK list, Data safety answers, changelog / merged PRs between N-1 and N | Approved SDK list, privacy report from the archive, App Privacy answers, changelog |
| Pipeline | CI workflow files, runner configuration, who can approve and trigger releases | Same, plus where certificates and App Store Connect API keys are held |

Decompile both Android releases once and keep the output:

```bash
mkdir -p rel/n rel/n-1
for v in n n-1; do
  jadx -d rel/$v/jadx rel/$v/base.apk            # MASTG-TOOL-0018
  apktool d -o rel/$v/apktool rel/$v/base.apk     # decoded manifest and resources, MASTG-TOOL-0011
done
```

For an AAB, build a universal APK with [bundletool](https://developer.android.com/tools/bundletool) (`bundletool build-apks --bundle=app.aab --output=app.apks --mode=universal`, then unzip `universal.apk` from `app.apks`). For iOS, unzip both IPAs into `rel/n/Payload` and `rel/n-1/Payload`.

### GT-CODE-0048-1: SDK and dependency inventory against an approved list (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

Platform: Android and iOS. Type: static and manual (project files, release binary, vendor documentation). Related: [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/), which uses the same inventory to look for known vulnerabilities, and our [third-party libraries note](/mobile/mastg-know-0004-third-party-libraries/).

#### Overview

You cannot spot unexpected code until you know what is expected. This check builds a complete inventory of direct and transitive dependencies, SDKs, build plugins and vendored binaries, confirms that the release binary contains the same components, and compares the result with the owner's approved list. For each component it asks three questions: is it approved, is it the genuine package from the genuine publisher, and does it have a known history of abusive behaviour?

#### Prerequisites

- Project source at the release tag, with a working build environment, or at least the lockfiles.
- The release APK/AAB and IPA.
- The owner's approved list (name, coordinates, purpose, owner, approved version range). If none exists, that is the first finding, and you build the list with the team.
- cdxgen ([MASTG-TOOL-0134](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0134/)) and optionally Dependency-Track ([MASTG-TOOL-0132](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0132/)), as in [MASTG-TECH-0130](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0130/) and [MASTG-TECH-0132](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0132/).

#### Steps

1. **Android: list what the release variant resolves, including plugins.**

   ```bash
   ./gradlew -q :app:dependencies --configuration releaseRuntimeClasspath > inv/android-runtime.txt
   ./gradlew -q buildEnvironment > inv/android-buildscript.txt     # plugins and build-script classpath
   cdxgen -t java -o inv/android-sbom.json .
   find . -name '*.aar' -o -name '*.jar' | grep -v '/build/' > inv/android-vendored.txt   # files in libs/ etc.
   ```

   Repeat `dependencies` for every application module and for flavours that ship (`prodReleaseRuntimeClasspath`). Use `dependencyInsight` to find out who pulled in a transitive dependency:

   ```bash
   ./gradlew -q :app:dependencyInsight --dependency analytics --configuration releaseRuntimeClasspath
   ```

2. **iOS: list pods, packages, Carthage dependencies and vendored binaries.**

   ```bash
   sed -n '/^PODS:/,/^DEPENDENCIES:/p' Podfile.lock > inv/ios-pods.txt
   jq -r '.pins[] | "\(.identity) \(.location) \(.state.version // "-") \(.state.revision)"' \
       App.xcworkspace/xcshareddata/swiftpm/Package.resolved > inv/ios-spm.txt      # v2/v3 format
   cat Cartfile.resolved > inv/ios-carthage.txt 2>/dev/null
   find . \( -name '*.xcframework' -o -name '*.framework' -o -name '*.a' \) -not -path '*/DerivedData/*' > inv/ios-vendored.txt
   cdxgen -o inv/ios-sbom.json .          # covers SwiftPM; CocoaPods and Carthage need the lockfiles above
   ```

   `Package.resolved` in version 1 format uses `.object.pins[]` with `package`, `repositoryURL` and `state` instead.

3. **Cross-platform layers.** For React Native, `jq -r '.packages | keys[]' package-lock.json` gives every installed package. For Flutter, `pubspec.lock` lists every Dart package with its source.

4. **Check the binary against the inventory.** Packages in the release that the project inventory does not explain are the interesting ones:

   ```bash
   # Android: top-level packages defined in the DEX (deobfuscated with the release mapping)
   apkanalyzer dex packages --defined-only --proguard-mappings mapping.txt rel/n/base.apk \
     | awk '$1=="P"{print $NF}' | awk -F. 'NF<=3' | sort -u > inv/android-binary-packages.txt
   unzip -l rel/n/base.apk 'lib/*' 'META-INF/*.version' 'assets/*' | awk '{print $4}' > inv/android-binary-files.txt

   # iOS: embedded frameworks, app extensions and linked libraries
   ls rel/n/Payload/App.app/Frameworks rel/n/Payload/App.app/PlugIns 2>/dev/null
   otool -L rel/n/Payload/App.app/App
   find rel/n/Payload -name PrivacyInfo.xcprivacy
   ```

   Every native library (`lib/arm64-v8a/*.so`), embedded framework and top-level package should map to an inventory entry.

5. **Compare with the approved list.** For each component record: approved yes/no, version within the approved range, owner. Unapproved components need a decision from the owner, not from you.

6. **Check identity and provenance of each third-party component.**
   - Coordinates match the publisher's documentation exactly (Maven group, CocoaPods name, SwiftPM URL, npm scope). Look for look-alikes: a fictional `com.examp1e.analytics` next to the genuine `com.example.analytics`, a pod or npm name with one extra or swapped letter, a SwiftPM URL pointing to a personal fork instead of the vendor's organisation.
   - Repository the artefact actually came from (Gradle's `--scan` or `--info` output, `SPEC REPOS` in `Podfile.lock`, `location` in `Package.resolved`). An internal package served from a public repository is a dependency-confusion indicator.
   - Maintainer or ownership changes and unusual release patterns in recent history (new maintainer, burst of releases, a package that was dormant for years). For npm, `npm view <package> maintainers time --json` shows maintainers and publish dates.
   - Binary SDKs: XCFramework signature and Team ID (`codesign -dv --verbose=2 Vendor.xcframework`), and whether the vendor publishes checksums for its AARs.

7. **Check reputation and store status.** Look up each SDK in the [Google Play SDK Index](https://play.google.com/sdks) (policy-violation labels, outdated-version warnings) and in Apple's commonly used SDK list (privacy manifest and signature required). Search the vendor name and package name together with "malware", "spyware" or "removed from Google Play". Use the OSV database ([osv.dev](https://osv.dev)), which also records malicious-package advisories (`MAL-` IDs) for npm and other registries. `osv-scanner` reports them along with ordinary vulnerabilities.

8. **Check declarations against the inventory.** Every SDK that collects data should appear in the Data safety answers and, on iOS, in the privacy report. Every listed SDK on Apple's list should ship a `PrivacyInfo.xcprivacy`:

   ```bash
   for f in $(find rel/n/Payload -name PrivacyInfo.xcprivacy); do echo "== $f"; plutil -p "$f" | grep -E 'NSPrivacyTracking|Domains|CollectedDataType"' ; done
   ```

#### Observation

The inventory (SBOM plus lockfiles plus build plugins), the list of components found in the binary, the diff between them, the approved-list comparison, and for each unapproved or suspicious component the evidence: coordinates, source repository, maintainer history, store or advisory status.

#### Evaluation

The check **fails** if any of these applies:

- the release contains a component (library, SDK, native library, framework, build plugin that instruments code) that is not on the approved list and the owner cannot explain;
- a component's identity does not match its publisher (look-alike name, wrong group or organisation, fork without a recorded reason), or an internal package is resolvable from a public repository;
- a component has a malicious-package advisory, a Play SDK Index policy-violation label for the shipped version, or a public report of abusive behaviour that applies to the shipped version;
- the binary contains code that no inventory entry explains.

It **passes** if every component in the binary maps to an approved inventory entry from a verified publisher, with no adverse reputation for the shipped versions. A missing approved list is a finding in itself (Low or Medium, see [Rating findings](#rating-findings)), even if every component you found looks benign.

#### Demo

A typical result: the Gradle tree shows a transitive SDK nobody added directly.

```text
releaseRuntimeClasspath
+--- com.example.payments:checkout:5.2.0
|    +--- com.example.payments:core:5.2.0
|    \--- com.examp1e.metrics:collector:1.0.3        <-- not on the approved list
\--- com.squareup.okhttp3:okhttp:4.12.0
```

`dependencyInsight` shows that `checkout` pulled in `com.examp1e.metrics:collector`. Its group differs from the payment vendor's (`examp1e`, digit one) and it was served by a repository declared without content filtering. `apkanalyzer dex packages` confirms that the package `com.examp1e.metrics` is in the release DEX. This is a fail: an unapproved component with a look-alike identity. The next step is GT-CODE-0048-4 to see what it does at runtime, and an incident decision by the owner.

### GT-CODE-0048-2: Release build diff against source and the previous release (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

Platform: Android and iOS. Type: static (binary comparison). Related: [MASWE-0075](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0075/), [app signing](/mobile/mastg-know-0003-app-signing/).

#### Overview

Malicious code introduced in the pipeline, by a plugin or by an insider has to show up somewhere in the artefact. This check compares the release under review with two baselines: the **previous release** (everything new must be explained by the changelog) and a **rebuild from the tagged source** (everything in the release must come from the source). It looks at the parts that change behaviour: classes and packages, native libraries, permissions and entitlements, exported components and extensions, URL schemes and associated domains, embedded URLs and hosts, and the signing identity.

#### Prerequisites

- Release N and N-1 (APK and AAB, IPA), decompiled as in [Before you start](#before-you-start-collect-the-evidence-set).
- Android SDK command-line tools (`apkanalyzer`, `aapt2` ([MASTG-TOOL-0124](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/)), `apksigner` ([MASTG-TOOL-0123](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/))), jadx, `llvm-readelf`.
- macOS with Xcode command-line tools (`codesign`, `otool`, `plutil`), optionally radare2's `rabin2`.
- Optional: [diffoscope](https://diffoscope.org/) for byte-level comparison, and a CI-equivalent environment to rebuild the tag.

#### Steps

1. **Signing identity (both platforms).** The signer must be the same as in the previous release, or the change must be a documented key rotation.

   ```bash
   apksigner verify --print-certs -v rel/n/base.apk | grep -E 'Signer #1 certificate (DN|SHA-256)'
   apksigner verify --print-certs -v rel/n-1/base.apk | grep -E 'Signer #1 certificate (DN|SHA-256)'
   codesign -dv --verbose=2 rel/n/Payload/App.app 2>&1 | grep -E 'Authority|TeamIdentifier'
   ```

2. **Android manifest surface.** Compare permissions, components and their export state, intent filters and flags:

   ```bash
   for v in n n-1; do
     aapt2 dump permissions rel/$v/base.apk | sort > rel/$v/perms.txt
     aapt2 dump badging rel/$v/base.apk | grep -E "^(package|sdkVersion|targetSdkVersion|uses-permission|application-debuggable|testOnly)" > rel/$v/badging.txt
     apkanalyzer manifest print rel/$v/base.apk > rel/$v/AndroidManifest.xml
   done
   diff rel/n-1/perms.txt rel/n/perms.txt
   diff rel/n-1/badging.txt rel/n/badging.txt
   diff <(grep -E '<(activity|service|receiver|provider|data|action)' rel/n-1/AndroidManifest.xml | sort) \
        <(grep -E '<(activity|service|receiver|provider|data|action)' rel/n/AndroidManifest.xml | sort)
   ```

   New permissions, new exported components, new `<data android:scheme>` entries, `android:debuggable="true"` and `android:testOnly="true"` all need an explanation. Exported components are rated under [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/). Here the question is only "was this supposed to be added?".

3. **Android code and native libraries.** Compare file lists and sizes first, then packages, then native libraries:

   ```bash
   apkanalyzer apk compare --different-only rel/n-1/base.apk rel/n/base.apk > diff/apk-compare.txt
   for v in n n-1; do
     apkanalyzer dex packages --defined-only --proguard-mappings rel/$v/mapping.txt rel/$v/base.apk \
       | awk '$1=="P"{print $NF}' | sort -u > rel/$v/packages.txt
     unzip -o -q rel/$v/base.apk 'lib/*' -d rel/$v/unz
     (cd rel/$v/unz && find lib -name '*.so' -exec shasum -a 256 {} \; | sort -k2) > rel/$v/so-hashes.txt
   done
   diff rel/n-1/packages.txt rel/n/packages.txt
   diff rel/n-1/so-hashes.txt rel/n/so-hashes.txt
   llvm-readelf --dyn-syms --needed-libs rel/n/unz/lib/arm64-v8a/libnew.so | head -50
   ```

   For a changed package, diff the decompiled sources (`diff -ru rel/n-1/jadx/sources/com/example rel/n/jadx/sources/com/example`). Without mapping files, R8 renames classes between builds and the diff becomes noisy. In that case compare package structure, string constants and API usage instead of names.

4. **Android: embedded URLs and hosts.** Extract every URL and host-like constant from code, resources and native libraries, and diff the sets:

   ```bash
   for v in n n-1; do
     { rg -o --no-filename 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+' rel/$v/jadx rel/$v/apktool;
       find rel/$v/unz/lib -name '*.so' -exec strings -a {} \; | grep -Eo 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+'; } \
       | sed -E 's#^(https?://[^/:?]+).*#\1#' | sort -u > rel/$v/hosts.txt
   done
   diff rel/n-1/hosts.txt rel/n/hosts.txt
   ```

   For React Native, include `assets/index.android.bundle`. If it is Hermes bytecode (`file` reports "Hermes JavaScript bytecode"), run `strings` on it.

5. **iOS bundle surface.** Compare Info.plist keys, entitlements, extensions, frameworks and linked libraries:

   ```bash
   for v in n n-1; do
     A=rel/$v/Payload/App.app
     plutil -convert xml1 -o rel/$v/Info.xml $A/Info.plist
     codesign -d --entitlements :- $A > rel/$v/entitlements.xml 2>/dev/null
     ls $A/Frameworks $A/PlugIns 2>/dev/null > rel/$v/bundles.txt
     otool -L $A/App | sort > rel/$v/linked.txt
     rabin2 -c $A/App 2>/dev/null | sort -u > rel/$v/classes.txt   # ObjC (and some Swift) class metadata
     find $A -type f -exec shasum -a 256 {} \; | sed "s#$A/##" | sort -k2 > rel/$v/files.txt
   done
   diff rel/n-1/Info.xml rel/n/Info.xml
   diff rel/n-1/entitlements.xml rel/n/entitlements.xml
   diff rel/n-1/bundles.txt rel/n/bundles.txt
   diff rel/n-1/linked.txt rel/n/linked.txt
   diff rel/n-1/classes.txt rel/n/classes.txt
   ```

   Watch for new usage-description keys (`NS...UsageDescription` means new access to protected data), new `CFBundleURLTypes`, new background modes (`UIBackgroundModes`), `LSApplicationQueriesSchemes`, new entitlements (associated domains, keychain access groups, app groups, network extensions) and `get-task-allow` set to `true` (a development signature, never acceptable in a release build). For hosts, run the URL extraction from step 4 over `strings -a` of the main binary and every framework.

   An App Store build pulled from a device is FairPlay-encrypted: `otool -l App | grep -A4 LC_ENCRYPTION_INFO` shows `cryptid 1`, and code diffs need the exported IPA from the archive instead. Owners should keep the exported IPA for each release for this reason.

6. **Compare with a rebuild from source.** Build the release tag in a clean CI-equivalent environment with the same toolchain versions and compare with the shipped artefact. With reproducible builds, `diffoscope` should show only the signature. Without them it shows expected noise (timestamps, signing blocks, sometimes R8 ordering). Everything else in code or native libraries needs an explanation. If the app uses code transparency, `bundletool check-transparency --mode=apk --apk-zip=delivered.zip --transparency-key-certificate=transparency.cert` checks the delivered DEX and native libraries against the developer's signed list without a full rebuild.

7. **Explain every difference.** Map each new package, library, permission, entitlement, component, extension, scheme and host to a merged change, a dependency update recorded in the lockfile diff, or a documented store-side modification.

#### Observation

The diff outputs for each step, the list of differences with the change or ticket each one maps to, and the list of differences nobody can explain.

#### Evaluation

The check **fails** if:

- the release contains code, a native library, a framework or an app extension that neither the source at the tag nor a recorded dependency update explains;
- a permission, entitlement, usage description, exported component, URL scheme or associated domain was added without a corresponding change;
- the release talks to a host (by embedded URL) that is new, not explained by a change, and not on the owner's list of approved destinations;
- the signing certificate or Team ID changed without a documented rotation;
- a release build is debuggable (`application-debuggable` or `get-task-allow`).

It **passes** if every difference against N-1 maps to a reviewed change, and a rebuild from the tag shows no code differences other than the documented store-side ones.

#### Demo

An abridged result from step 2 and step 4, between two releases whose changelog only mentions "UI fixes":

```text
$ diff rel/n-1/perms.txt rel/n/perms.txt
> uses-permission: name='android.permission.QUERY_ALL_PACKAGES'
> uses-permission: name='android.permission.ACCESS_WIFI_STATE'

$ diff rel/n-1/hosts.txt rel/n/hosts.txt
> https://cfg.collector.example.net

$ diff rel/n-1/packages.txt rel/n/packages.txt
> com.examp1e.metrics
> com.examp1e.metrics.internal
```

Three linked differences: two new permissions that give access to the installed-app list and Wi-Fi details, a new configuration host and a new package, with no matching change. This fails, and it shows why the diff and the inventory belong together: GT-CODE-0048-1 tells you which dependency brought `com.examp1e.metrics` in.

### GT-CODE-0048-3: Hidden functionality and backdoor indicators (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

Platform: Android and iOS. Type: static (code search) and dynamic (Frida, objection on a test device). Related: [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/), [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/).

#### Overview

The check looks for functionality in the release build that should not be there or is not documented: debug and QA menus, test accounts and fixed OTPs, magic parameters, environment switches, and remote-config flags that enable unreviewed code. Static search finds candidates. Runtime observation of the app's own behaviour shows which candidates are reachable and which flags the app actually reads.

#### Prerequisites

- Decompiled release (jadx output, decoded manifest) or source. For iOS, the decrypted or archive-exported binary, plus class and string listings (`rabin2 -c`, `rabin2 -zz`, or `strings -a`).
- A test device with Frida ([MASTG-TOOL-0031](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/)), and test accounts provided by the owner.
- The owner's list of documented feature flags and remote-config keys, if one exists.

#### Steps

1. **Search for debug and test leftovers.** Start broad, then read every hit in context:

   ```bash
   rg -n -i -e 'debug ?menu|qa ?menu|dev ?menu|internal ?tools|god ?mode|backdoor|cheat|easter' \
         -e 'bypass|skip(Auth|Login|Otp|Verification|Pin)|disable(Auth|Pinning|Ssl)|force(Login|Unlock)' \
         -e 'test(user|account|password|otp)|qa@|tester@|staging|sandbox|dev\.api|uat\.' \
         rel/n/jadx/sources rel/n/apktool/res > hidden/candidates.txt
   rg -n -e 'BuildConfig\.DEBUG' -e 'isDebuggable' -e 'FLAG_DEBUGGABLE' rel/n/jadx/sources | head -50
   ```

   For iOS, run the same patterns over `strings -a` output of the main binary and frameworks, and look for view controllers with names like `Debug`, `Internal`, `QA`, `Dev`, `Settings`:

   ```bash
   strings -a rel/n/Payload/App.app/App | rg -i 'debug|internal|qa|staging|bypass|skip|backdoor|testuser' | sort -u
   rabin2 -c rel/n/Payload/App.app/App | rg -i 'debug|internal|qa|dev|flag|override'
   ```

2. **Find entry points to those screens.** On Android, check whether a debug activity is in the release manifest at all (`grep -n -i 'debug\|internal' rel/n/AndroidManifest.xml`), whether it is exported, and which code starts it. Look for gesture triggers: `SensorManager` with an accelerometer listener next to a "shake" counter, click counters on a logo, `onLongClick` on version text. On iOS, look for `motionEnded:withEvent:` overrides, tap gesture recognisers with high `numberOfTapsRequired`, and launch-argument or environment checks (`ProcessInfo.processInfo.arguments`, `UserDefaults` keys read on launch).

3. **Find comparisons against literals in authentication and authorisation code.** In login, OTP, PIN and entitlement code, look for `equals` or `==` against string constants, and for constants returned as success:

   ```bash
   rg -n -e '\.equals\("[^"]+@[^"]+"\)' -e '== "[^"]+@[^"]+"' -e '"(000000|123456|111111|999999)"' rel/n/jadx/sources
   ```

   For each hit, trace whether the comparison can short-circuit a server check. A client-side bypass only matters if the backend accepts the result (an offline session, a locally trusted "verified" flag, an unlocked premium feature). Confirm it against the test backend using the owner's test accounts, never against real accounts.

4. **Find magic parameters.** List every query parameter, intent extra, header and launch argument the app reads, then look for ones that gate behaviour instead of carrying data:

   ```bash
   rg -n -o -e 'getQueryParameter\("[^"]+"\)' -e 'get(String|Boolean|Int)Extra\("[^"]+"' rel/n/jadx/sources | sort | uniq -c | sort -rn
   ```

   Parameters named like `debug`, `qa`, `env`, `admin`, `override`, `unlock`, or compared with a fixed value, are candidates. For deep links, cross-check with the deep-link inventory from [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/).

5. **Inventory remote-config and feature-flag reads.** Statically, search for the SDK's getter calls. At runtime, log which keys the app reads, so you see flags whose names are built at runtime too. A minimal Frida script for Firebase Remote Config that only logs the app's own reads:

   ```javascript
   // rc-keys.js — log Remote Config keys the app reads (observation only)
   if (Java.available) {
     Java.perform(() => {
       const RC = Java.use('com.google.firebase.remoteconfig.FirebaseRemoteConfig');
       ['getBoolean', 'getString', 'getLong', 'getDouble', 'getValue'].forEach((m) => {
         RC[m].overloads.forEach((o) => {
           o.implementation = function (...args) {
             const v = o.apply(this, args);
             console.log(`[rc] ${m}("${args[0]}") -> ${v}`);
             return v;
           };
         });
       });
     });
   }
   if (ObjC.available && ObjC.classes.FIRRemoteConfig) {
     Interceptor.attach(ObjC.classes.FIRRemoteConfig['- configValueForKey:'].implementation, {
       onEnter(args) { console.log(`[rc] configValueForKey: ${new ObjC.Object(args[2])}`); }
     });
   }
   ```

   ```bash
   frida -U -f com.example.app -l rc-keys.js
   ```

   Use the app through its main flows and collect the key list. For each key, find the code it gates (in jadx, follow the key string or the getter's call sites) and compare it with the owner's documented flags. Other flag SDKs (LaunchDarkly, Optimizely, in-house config endpoints) work the same way: hook their getters, or record the config response with the proxy from GT-CODE-0048-4.

6. **Look for conditional dormancy.** Search for date comparisons (`System.currentTimeMillis()`, `Date()`, `Calendar` against constants), locale and country checks (`Locale.getDefault()`, `TelephonyManager.getSimCountryIso()`, `Locale.current.region`), installer checks (`getInstallSourceInfo`, `getInstallerPackageName`) and emulator or "being reviewed" checks near code that does something unusual. Legitimate uses exist (regional features, licence checks, anti-fraud). What matters is what the condition gates.

7. **Confirm reachability on a test device.** For each candidate, show the minimal benign observation: the debug screen opens in the release build after the gesture; the magic parameter changes which code path runs (Frida trace of the app's own method, or a visible UI change); the test account logs in against the production configuration of a test environment. Record the build number and how you reached it.

#### Observation

The list of candidates with code locations; for each: what it does, how it is reached, whether it is in the release build, whether it is documented, and the runtime evidence (screenshots, Frida output, log lines). The list of remote-config keys read at runtime with the code each one gates.

#### Evaluation

The check **fails** if the release build contains any of these:

- a debug, QA or internal menu, or an environment switch, that a user (or anyone with the device) can reach;
- a hard-coded account, password, OTP or PIN that the app or the backend accepts, or a client-side comparison that skips a check the backend relies on;
- a magic parameter, extra, header or launch argument that unlocks functionality;
- a remote-config or time/locale/installer condition that enables code which is not documented, not reviewed for production, or does something the privacy disclosures do not cover (extra data collection, downloading code, changing payment or authentication flows).

It **passes** if test-only code is absent from the release build (not merely hidden), and every flag the app reads is documented, gates only reviewed code, and stays within the declared behaviour.

#### Demo

A pattern we see in practice: a QA shortcut that survived into release because it is guarded by a parameter instead of by the build type.

```kotlin
class LinkRouterActivity : AppCompatActivity() {       // exported, https://app.example.com/open
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uri = intent.data
        if (uri?.getQueryParameter("qa_tools") == "enable-7731") {   // magic value, no BuildConfig.DEBUG check
            startActivity(Intent(this, InternalToolsActivity::class.java))   // env switch, flag overrides, log export
            finish(); return
        }
        route(uri)
    }
}
```

Step 4 finds `getQueryParameter("qa_tools")` with a fixed comparison. Step 7 confirms it on a test device: opening `https://app.example.com/open?qa_tools=enable-7731` in the release build shows the internal tools screen. The fix is to move `InternalToolsActivity` and the check into the `debug` source set so that release builds do not contain them at all.

### GT-CODE-0048-4: Unexpected network destinations at runtime (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

Platform: Android and iOS. Type: dynamic (traffic observation on a test device). Related: our [traffic interception lab](/mobile/mobile-traffic-interception-lab/) and [NETWORK guide](/mobile/masvs-network-secure-communication-guide/).

#### Overview

Malicious and over-collecting code has to send what it collects somewhere. This check records every destination the release build contacts during realistic use, attributes each one to the app's own code or an SDK, and compares the set with the owner's list of approved destinations and the privacy declarations. It complements the static host list from GT-CODE-0048-2: static extraction finds hosts that are never contacted in your session; runtime observation finds hosts that are built at runtime or delivered by configuration.

#### Prerequisites

- The release build installed from the store or from the release artefact on a test device you control (Android emulator or rooted device; iOS device).
- An interception proxy (Burp Suite or mitmproxy) set up as in the [lab note](/mobile/mobile-traffic-interception-lab/), and a way to see connections the proxy does not, such as DNS logs or a device-side connection log:
  - Android: [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) or NetGuard (both VPN-based, no root needed), which log connections per app.
  - iOS: the **App Privacy Report** (Settings > Privacy & Security > App Privacy Report, iOS 15.2 and later), which lists the domains each app contacted in the last seven days and can be exported with *Save App Activity* as an NDJSON file.
- The owner's list of approved backend and third-party domains, and the Data safety / App Privacy declarations.

#### Steps

1. **Start from a clean state.** Fresh install, cleared DNS cache (reboot or toggle airplane mode), the device-side logger running. On iOS, turn the App Privacy Report off and on again to clear old data.

2. **Record a baseline session.** Launch, sign in with a test account, and go through the main features, including the ones that use permissions (location, photos, contacts). Leave the app in the background for a while (background tasks and SDK uploads are often batched), then reopen it. Repeat with different consent choices: tracking allowed and denied (ATT on iOS, the consent dialog on both platforms).

3. **Collect the destinations from all sources.**

   ```bash
   # mitmproxy: hosts seen in a saved flow file (Burp: Target > Site map, copy the host list)
   mitmdump -nr session.flows --flow-detail 1 | grep -oE 'https?://[^/: ]+' | sort | uniq -c | sort -rn
   # PCAPdroid: export the connections list as CSV from the app and pull it
   adb pull /sdcard/Download/PCAPdroid_connections.csv evidence/
   # iOS App Privacy Report export (AirDrop or save to Files, then copy over)
   jq -r 'select(.type=="networkActivity") | "\(.bundleID) \(.domain)"' evidence/App_Privacy_Report.ndjson | sort | uniq -c
   ```

   The simplest reliable source for the proxy side is your proxy's own host list (Burp's site map, or mitmproxy's flow list). Use the device-side log for the complete set: it also catches traffic that ignores the proxy, uses certificate pinning or is not HTTP.

4. **Attribute each destination.** For every host, find the code that contacts it: search the decompiled code and SDK binaries for the host or its parts (GT-CODE-0048-2, step 4), check the SDK's documentation for its endpoints, and if the host is not in any string, attribute it at runtime. On Android, a Frida hook on the app's own name lookups shows which code path asks for a host:

   ```javascript
   // dns-origin.js — print the Java stack for lookups of a host under investigation
   Java.perform(() => {
     const IA = Java.use('java.net.InetAddress');
     const Log = Java.use('android.util.Log');
     const Ex = Java.use('java.lang.Exception');
     IA.getAllByName.implementation = function (host) {
       if (host && host.indexOf('example.net') !== -1) {
         console.log(`[dns] ${host}\n${Log.getStackTraceString(Ex.$new())}`);
       }
       return this.getAllByName(host);
     };
   });
   ```

   This covers lookups made through Java networking (OkHttp, `HttpURLConnection`). SDKs with their own native stack (Cronet, native libraries) do not pass through it. For those, the native library that contains the host string is usually the answer.

5. **Inspect the content sent to unknown or unexpected destinations.** Where the proxy can see the traffic, record what is sent: identifiers, device data, location, contact or photo data, lists of installed apps, clipboard contents. Where it cannot (pinning in an SDK, non-HTTP), record the volume and timing and treat it as unknown content. Do not try to break third-party protections beyond the authorised scope; the attribution and the fact of the connection are already evidence.

6. **Compare with the declarations.** For each destination: approved by the owner? Covered by the Data safety form and App Privacy answers? On iOS, listed in an SDK's `NSPrivacyTrackingDomains` (those should not be contacted when tracking is denied)? Does any destination receive data before the user has consented?

#### Observation

A table of destinations: host, first-seen time and trigger (start-up, login, feature X, background), attributed component, data sent (or "not visible"), approved yes/no, declared yes/no. Attach the proxy export, the device-side log and the Frida output for attributed hosts.

#### Evaluation

The check **fails** if the app contacts a destination that the owner has not approved and cannot attribute to an approved component, if any destination receives personal data that the privacy declarations do not cover, if data goes to tracking destinations after the user has refused tracking or consent, or if an approved SDK contacts hosts or sends data outside its documented behaviour. It **passes** if every destination is attributed to an approved component, every data flow is declared, and consent choices are honoured.

A pass is only as good as the coverage: features not exercised and conditions not met (dates, regions, server flags) are outside it. Say so in the report.

#### Demo

An abridged App Privacy Report export after a 20-minute session, filtered for the app under test:

```text
$ jq -r 'select(.type=="networkActivity" and .bundleID=="com.example.app") | .domain' report.ndjson | sort | uniq -c
  41 api.example.com
  12 cdn.example.com
   9 firebaseinstallations.googleapis.com
   3 cfg.collector.example.net
   2 upload.collector.example.net
```

`api.example.com` and `cdn.example.com` are the owner's. The Firebase host belongs to an approved SDK. `collector.example.net` is on neither list, is not mentioned in the privacy report, and the hook in step 4 attributes it (on the Android build) to `com.examp1e.metrics`. Combined with the permissions diff from GT-CODE-0048-2, this is enough to stop the release.

### GT-CODE-0048-5: Build pipeline and dependency-integrity controls (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

Platform: Android and iOS. Type: manual (configuration and process review) with static checks of build files. Related: [MASWE-0075](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0075/), [SLSA](https://slsa.dev/).

#### Overview

The first four checks look at one release. This one asks whether the process would make malicious code hard to introduce and easy to notice in *every* release. It reviews dependency pinning and verification, build-tool trust, CI/CD configuration, signing key custody and provenance.

#### Prerequisites

- Read access to the repository, CI configuration and branch protection settings; an interview with whoever runs releases.
- The build files: `settings.gradle(.kts)`, module `build.gradle(.kts)`, `gradle.properties`, `gradle/wrapper/gradle-wrapper.properties`, `gradle/verification-metadata.xml`, lockfiles; `Podfile`, `Podfile.lock`, `Package.swift` / `Package.resolved`, `Cartfile.resolved`; `package.json` and lockfile or `pubspec.yaml` and `pubspec.lock`; CI workflow files and scripts.

#### Steps

1. **Android dependency integrity.**

   ```bash
   ls gradle/verification-metadata.xml && grep -E '<verify-(metadata|signatures)>' gradle/verification-metadata.xml
   rg -n 'dependency-verification|dependency\.verification' gradle.properties .github ci 2>/dev/null   # disabled or lenient?
   rg -n -e ':[0-9.]*\+"' -e 'latest\.(release|integration)' -e '\[[0-9.]+,' --glob '*.gradle*' --glob '*.toml' .   # dynamic versions
   rg -n -e 'lockAllConfigurations|dependencyLocking' --glob '*.gradle*' . ; find . -name '*gradle.lockfile' -not -path '*/build/*'
   grep distributionSha256Sum gradle/wrapper/gradle-wrapper.properties
   rg -n -A8 'repositories' settings.gradle* build.gradle* | rg -e 'maven|jitpack|exclusiveContent|includeGroup|content'
   ```

   Check that verification is on and enforced in CI, versions are fixed and locked, the wrapper is checksummed and validated, and internal groups are restricted to the internal repository with content filtering. Review the history of `verification-metadata.xml`: are new entries reviewed, or regenerated wholesale on every update?

2. **Android build plugins.** From `./gradlew buildEnvironment` and the `plugins {}` blocks, list every third-party plugin with its version and purpose. Flag plugins that instrument bytecode (their documentation mentions "bytecode", "instrumentation" or "ASM"; AGP adds tasks with names like `transformReleaseClassesWithAsm`). Check CI runners for init scripts (`~/.gradle/init.d`, `$GRADLE_USER_HOME/init.d`).

3. **iOS dependency integrity.**
   - `Podfile.lock` committed. CI uses `pod install --deployment`, which fails if the Podfile and lockfile disagree instead of updating the lockfile. Git-sourced pods are pinned to a `:commit`, not a branch. `post_install` hooks and pods with `prepare_command` or `script_phases` are listed and reviewed (`pod spec cat <PodName>` prints a pod's spec; search the output for `prepare_command` and `script_phases`, and search the Podfile for `post_install`).
   - `Package.resolved` committed. CI builds with `-onlyUsePackageVersionsFromResolvedFile` or `-disableAutomaticPackageResolution`. If CI passes `-skipPackagePluginValidation` or `-skipMacroValidation`, there is a reviewed list of the plugins and macros it trusts, pinned by revision.
   - Remote binary targets declare checksums. Vendored XCFrameworks are signed, and Xcode's recorded identity has not been reset without a reason.
   - Xcode on build machines comes from Apple and passes `codesign --verify --deep --strict` and `spctl --assess`.

4. **Cross-platform integrity.** CI installs with `npm ci` (or `yarn install --immutable`, `pnpm install --frozen-lockfile`) and `flutter pub get --enforce-lockfile`. Packages with install scripts are known (`jq -r '.packages | to_entries[] | select(.value.hasInstallScript) | .key' package-lock.json`), and the team has decided whether to run them (`npm ci --ignore-scripts` breaks some native modules, so this is a reviewed decision, not a default).

5. **CI/CD review.** Ask and verify:
   - Release builds run only in CI, from protected branches or signed tags, with required review by someone other than the author. Administrators cannot bypass that without an audit trail.
   - Changes to workflow files, build scripts, lockfiles and verification metadata need the same review as code (CODEOWNERS on those paths).
   - Third-party CI actions, orbs and container images are pinned by commit SHA or digest, not by mutable tag. Nothing downloads and runs remote scripts without a checksum check (the Codecov lesson).
   - Pull requests from forks cannot reach release secrets. Self-hosted runners used for releases are not shared with untrusted jobs and are rebuilt rather than reused.
   - Dependency caches are scoped so that a pull-request job cannot poison the cache a release job uses.

6. **Signing key custody.** On Android: is Play App Signing used, who holds the upload key, where is it stored (CI secret store or HSM, not a laptop), and is there a documented procedure for upload key reset? If the app uses code transparency, who holds that key? On iOS: who can create distribution certificates and App Store Connect API keys, where are they stored, and are API keys scoped to the minimum role? Compare the signing identity of the last releases (GT-CODE-0048-2, step 1). See [app signing](/mobile/mastg-know-0003-app-signing/).

7. **Provenance and reproducibility.** Does CI produce signed provenance for release artefacts (SLSA Build Level 2 or 3, for example with GitHub artifact attestations, checked with `gh attestation verify app-release.aab --owner example-org`)? Is there an SBOM for each release? Can the team rebuild a past release and get an identical result (MASWE-0075)? Are the exported IPA and AAB, mapping files and SBOM archived for every release, so that GT-CODE-0048-2 is possible later?

#### Observation

A control-by-control table (present / partial / absent, with evidence: file excerpts, CI settings screenshots, interview notes), plus the specific gaps, such as "verification metadata regenerated without review in 6 of the last 10 updates" or "release workflow uses three actions pinned by tag".

#### Evaluation

The check **fails** if any of the following is true:

- dependencies are not pinned (dynamic versions without locking, lockfiles not committed or not enforced in CI);
- Android builds have no checksum verification, or it is disabled or lenient in CI;
- internal packages can be resolved from public repositories;
- release builds can be produced outside CI or from unreviewed changes, or one person can change and release on their own;
- release secrets (upload key, certificates, API keys) are reachable from untrusted jobs or kept on developer machines;
- build-time code execution (plugins, macros, install scripts, CocoaPods hooks) is trusted automatically without a reviewed list.

Missing provenance, SBOMs or reproducibility are weaknesses to report (Low to Medium) rather than failures on their own, unless the owner has committed to them, for example in a security standard or a contract. The check **passes** when dependencies are pinned and verified, build-time code is reviewed, releases come only from reviewed commits in a hardened pipeline, and signing material is held separately.

#### Demo

A vulnerable combination we find often, in `settings.gradle.kts` and a module build file:

```kotlin
dependencyResolutionManagement {
    repositories {
        mavenCentral()                                   // asked first, for every group
        maven("https://repo.example.com/internal")       // internal com.example.internal.* artefacts
    }
}
// app/build.gradle.kts
dependencies {
    implementation("com.example.internal:auth-core:3.+")   // dynamic version, no lockfile
}
```

No `verification-metadata.xml`, no lockfile and no content filtering means that a public artefact `com.example.internal:auth-core:3.99` would be preferred and accepted without any change in the repository. With verification enabled, an artefact that is not in the metadata stops the build. An abridged message:

```text
> Dependency verification failed for configuration ':app:releaseRuntimeClasspath'
  One artifact failed verification: auth-core-3.99.jar (com.example.internal:auth-core:3.99) from repository MavenRepo
```

The fix is in [Secure implementation](#secure-implementation).

### Supplementary: reputable scanners

Automated scanners are a useful extra signal before release, not a substitute for the checks above. Known-bad code is what they detect best; targeted or new malicious code usually passes them.

- **MobSF** ([MASTG-TOOL-0035](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0035/)) runs locally (`docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest`) and reports permissions, trackers, embedded domains, APKiD results (packers, obfuscators, unusual compilers) and other indicators for APKs and IPAs. Running it locally keeps the build inside your organisation, so use it for pre-release and confidential builds. Diff its results between releases: a new tracker or a new packer signature is worth asking about.
- **VirusTotal** aggregates many antivirus engines. Look up the SHA-256 first (`shasum -a 256 app-release.apk`, then search the hash), which reveals nothing. **Uploading shares the file**: VirusTotal's [terms of service](https://docs.virustotal.com/docs/terms-of-service) ask users not to submit confidential or commercially sensitive material, and submitted files can be made available to its partners and premium customers. Upload only builds that are already public, or use a private scanning service under contract. Expect generic "adware" or "riskware" labels from a few engines on apps with ad SDKs. One or two such labels on a public build are a reason to look at the SDK, not proof of malware.
- **Exodus Privacy** ([exodus-privacy.eu.org](https://exodus-privacy.eu.org/)) identifies known tracker SDKs in Android apps from their code signatures. It is useful for cross-checking GT-CODE-0048-1.

## Secure implementation

These are the patterns we recommend to app owners. They map to the failure conditions above.

**Gradle: restrict where each group comes from, pin, lock and verify.**

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)   // no ad-hoc repositories in modules
    repositories {
        exclusiveContent {
            forRepository { maven("https://repo.example.com/internal") }
            filter { includeGroupByRegex("com\\.example\\.internal(\\..*)?") }   // only ever from here
        }
        google()
        mavenCentral()
    }
}
// app/build.gradle.kts
dependencyLocking { lockAllConfigurations() }
```

```bash
./gradlew :app:dependencies --write-locks                         # creates/updates gradle.lockfile
./gradlew --write-verification-metadata sha256 help               # then review the diff before committing
```

```xml
<!-- gradle/verification-metadata.xml (excerpt) -->
<verification-metadata xmlns="https://schema.gradle.org/dependency-verification">
   <configuration>
      <verify-metadata>true</verify-metadata>
      <verify-signatures>false</verify-signatures>
   </configuration>
   <components>
      <component group="com.squareup.okhttp3" name="okhttp" version="4.12.0">
         <artifact name="okhttp-4.12.0.jar">
            <sha256 value="(sha-256 of the artefact)" origin="Generated by Gradle"/>
         </artifact>
      </component>
   </components>
</verification-metadata>
```

Add `distributionSha256Sum` to `gradle-wrapper.properties` and validate `gradle-wrapper.jar` in CI. Treat changes to `verification-metadata.xml`, lockfiles and `libs.versions.toml` as security-relevant changes with CODEOWNERS review. Optionally enable code transparency for the app bundle, with its key held outside CI.

**iOS: pin and enforce.** Commit `Podfile.lock` and `Package.resolved`. In CI, run `pod install --deployment` and `xcodebuild ... -onlyUsePackageVersionsFromResolvedFile`. Pin Git-sourced pods to commits. Use only signed XCFrameworks for closed-source SDKs and investigate any signature identity change Xcode reports. Do not pass `-skipPackagePluginValidation` or `-skipMacroValidation` unless the trusted set is reviewed and pinned. Plan the move of remaining CocoaPods dependencies to SwiftPM before trunk becomes read-only.

**Cross-platform.** `npm ci` or the equivalent frozen-lockfile install, review of packages with install scripts, `flutter pub get --enforce-lockfile`.

**Keep test code out of release builds.** On Android, put debug screens, QA tools, test endpoints and their manifest entries in `src/debug/` (or a `qa` flavour), so the release variant never compiles them, instead of checking `BuildConfig.DEBUG` at runtime next to code that ships. On iOS, use a separate build configuration or target with `#if DEBUG` (or a custom compilation condition) around the code *and* its entry points, and check that the Release configuration does not define the condition. Never accept fixed OTPs or test accounts in the production backend. Test accounts belong in test environments, and production allow-lists for app review use dedicated, monitored, low-privilege accounts.

**Govern remote configuration.** Keep a register of flags with owner, purpose, the code each one gates and whether it is in the privacy disclosures. Code behind a flag goes through the same review and release testing as any other code. A flag must not be able to enable code download or data collection that App Review, Play review or the user disclosures did not cover.

**Govern SDKs.** Approve each SDK with an owner and a documented purpose. Configure it for minimum data collection. Read its privacy manifest and SDK Index entry, and review the lockfile diff of every SDK update, including transitive changes. Remove SDKs nobody owns.

**Harden the pipeline and prove the result.** Releases are built only in CI from protected, reviewed commits. Actions and images are pinned by digest. Signing material is scoped to release jobs or held in an HSM. Each release produces signed provenance, an SBOM and an archived set of artefacts (AAB/APK, exported IPA, mapping files, dSYMs). Before each release, run GT-CODE-0048-2 and GT-CODE-0048-4 as a release gate. Work towards reproducible builds (MASWE-0075).

## Rating findings

Rate on three things: **whether the functionality is malicious, undisclosed or merely unexplained**, **what it can reach** (credentials, personal data, authentication, payments, code execution), and **who can activate it** (anyone using the app, anyone who knows a string, the server operator or SDK vendor, only someone who can modify the pipeline). The attacker positions behind this weakness are the supply chain and insiders (MAS-ATTACK-0060 and 0061). No user interaction is needed once the code ships, and the impact reaches the whole user base. For control weaknesses (GT-CODE-0048-1 and -5), rate how easy it would be for that attacker to get code into a release without anyone noticing.

| Rating | Conditions |
|---|---|
| **Critical** | Confirmed malicious code in a release build: exfiltration of credentials, keys, messages, photos or other personal data to an unapproved destination; remote command or code execution capability; ad fraud or hidden WebViews. A backdoor that bypasses authentication or authorisation against the production backend (working hard-coded account, fixed OTP, magic parameter granting account access). Treat these as incidents: stop distribution and start incident response. |
| **High** | An SDK sends personal data to destinations or for purposes outside the privacy declarations, or ignores refused consent; release code, native libraries or permissions that neither source nor changelog explains (until explained, handle as a possible incident); a reachable debug or internal menu exposing sensitive functions (environment switching to attacker-chosen servers, flag overrides, data export); an unapproved SDK with a look-alike identity or adverse reputation in the shipped build; release pipeline in which one person, or an untrusted pull-request job, can change and ship a release, or release signing material is exposed. |
| **Medium** | No checksum verification and no lockfiles, with dynamic versions or unfiltered repositories that allow dependency confusion; build-time code (plugins, macros, install scripts, CocoaPods hooks) trusted automatically; remote-config switches that enable unreviewed but not demonstrably harmful code paths; reachable debug screens with only diagnostic content; unapproved SDKs with broad data access but no observed misuse; signing identity change without documented rotation. |
| **Low** | Leftover test code present but unreachable in release; hard-coded test identifiers the backend rejects; no approved-SDK list but a benign inventory; CI actions pinned by tag; missing SBOM or provenance; unexplained but benign transitive components; Carthage binaries without checksums. |
| **Info** | Generic "riskware" scanner labels traced to a known, approved ad SDK; documented, reviewed feature flags; store-side code changes (Play automatic protection) that are documented and expected; recommendations towards reproducible builds and code transparency. |

Raise a level when the app handles payments, health data, identity documents or credentials for other services, or when the flaw affects all users silently (start-up, background). Lower a level for Medium and Low process findings when strong compensating controls exist, for example reproducible builds checked by an independent party. Do not lower a confirmed malicious-code finding because a third party wrote the code. In the report give the artefact and build number, the component and code location, the diff or lockfile line, the runtime evidence (destination log, trace), the declarations it conflicts with, and the owner of the fix. State the scope of assurance explicitly: features exercised, builds compared, and what was not covered.

## References

- OWASP MASWE: [MASWE-0048: Malicious Code Included in the App](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0048/); related [MASWE-0044](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0044/), [MASWE-0049](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0049/), [MASWE-0075](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0075/), [MASWE-0004](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0004/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-CODE-3](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0130](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0130/), [MASTG-TECH-0132](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0132/), [MASTG-TECH-0136](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0136/), [MASTG-TECH-0137](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0137/), [MASTG-TECH-0111](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0111/), [MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0116](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0116/), [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/) (CC BY-SA 4.0)
- OWASP MASTG tools: [cdxgen (MASTG-TOOL-0134)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0134/), [dependency-track (MASTG-TOOL-0132)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0132/), [MobSF (MASTG-TOOL-0035)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0035/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [aapt2 (MASTG-TOOL-0124)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/), [apksigner (MASTG-TOOL-0123)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/), [codesign (MASTG-TOOL-0114)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0114/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [mitmproxy (MASTG-TOOL-0097)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/), [Burp Suite (MASTG-TOOL-0077)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/) (CC BY-SA 4.0)
- Google Play: [Using SDKs safely and securely](https://support.google.com/googleplay/android-developer/answer/13326895), [Google Play SDK Index](https://play.google.com/sdks)
- Android Developers: [Code transparency for app bundles](https://developer.android.com/guide/app-bundle/code-transparency), [bundletool](https://developer.android.com/tools/bundletool), [apkanalyzer](https://developer.android.com/tools/apkanalyzer)
- Apple: [Third-party SDK requirements](https://developer.apple.com/support/third-party-SDK-requirements/), [Privacy requirement reminder (1 May 2024)](https://developer.apple.com/news?id=pvszzano), [Privacy manifest files](https://developer.apple.com/documentation/bundleresources/privacy-manifest-files), [Verifying the origin of your XCFrameworks](https://developer.apple.com/documentation/xcode/verifying-the-origin-of-your-xcframeworks), [App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/) (2.3.1, 2.5.2)
- Gradle: [Dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html), [Dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html), [gradle/actions (wrapper validation)](https://github.com/gradle/actions)
- CocoaPods: [CocoaPods blog (trunk read-only plan)](https://blog.cocoapods.org/); CocoaPods trunk vulnerabilities reported by E.V.A Information Security in 2024: [CVE-2024-38366](https://nvd.nist.gov/vuln/detail/CVE-2024-38366) and [CVE-2024-38368](https://nvd.nist.gov/vuln/detail/CVE-2024-38368)
- Supply-chain frameworks and tools: [SLSA](https://slsa.dev/), [Reproducible Builds](https://reproducible-builds.org/), [diffoscope](https://diffoscope.org/), [OSV](https://osv.dev/), [PCAPdroid](https://github.com/emanuele-f/PCAPdroid), [Exodus Privacy](https://exodus-privacy.eu.org/), [VirusTotal terms of service](https://docs.virustotal.com/docs/terms-of-service)
- Incident sources: Palo Alto Networks Unit 42, [XcodeGhost](https://unit42.paloaltonetworks.com/novel-malware-xcodeghost-modifies-xcode-infects-apple-ios-apps-and-hits-app-store/); npm, [Details about the event-stream incident](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident); Codecov, [Security update](https://about.codecov.io/security-update/); McAfee Labs, [Goldoson](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/goldoson-privacy-invasive-and-clicker-android-adware-found-in-popular-apps-in-south-korea/); NVD, [CVE-2024-3094](https://nvd.nist.gov/vuln/detail/CVE-2024-3094); Kaspersky, [SparkCat](https://www.kaspersky.com/blog/ios-android-ocr-stealer-sparkcat/52980/)
- CWE: [CWE-506](https://cwe.mitre.org/data/definitions/506.html), [CWE-507](https://cwe.mitre.org/data/definitions/507.html), [CWE-511](https://cwe.mitre.org/data/definitions/511.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
