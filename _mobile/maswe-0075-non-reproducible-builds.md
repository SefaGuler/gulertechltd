---
title: "MASWE-0075: Non-Reproducible Builds"
date: 2026-11-10 22:09:00 +0000
subcategory: privacy
summary: "Testing whether a mobile app's shipped binary can be rebuilt from its source: Android diffs, F-Droid and Play limits, iOS FairPlay, provenance."
refs: [MASWE-0075, MASVS-PRIVACY-3, CWE-1357, CWE-494]
tags: [android, ios, masvs-privacy, reproducible-builds, supply-chain, code-signing]
---

This note is part of our [MASVS-PRIVACY guide](/mobile/masvs-privacy-privacy-testing-guide/) and covers OWASP [MASWE-0075](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0075/): an app whose build is not reproducible. Rebuilding the same source with the same toolchain does not give the same binary, so nobody can show that the app on users' phones was built from the source that was published or audited. It sits in the privacy group for a simple reason. An app's privacy promises ("end-to-end encrypted", "no trackers", "location never leaves the device") can be checked in the source, but a source review only covers the binary users run if that binary can be shown to come from that source. **OWASP has no MASTG tests and no Knowledge pages for MASWE-0075.** The background and the four checks below (GT-PRIV-0075-1 to GT-PRIV-0075-4) are Guler Tech methodology. The note sits next to [MASWE-0048 Malicious Code Included in the App](/mobile/maswe-0048-malicious-code-included-in-the-app/), which covers what to do when a binary turns out to contain code you did not expect. This note covers whether you can tell in the first place.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Why reproducibility is a privacy control](#why-reproducibility-is-a-privacy-control)
  - [What reproducible means](#what-reproducible-means)
  - [Sources of non-determinism](#sources-of-non-determinism)
  - [Android: signatures, F-Droid and Play delivery](#android-signatures-f-droid-and-play-delivery)
  - [iOS: FairPlay, re-signing and partial verification](#ios-fairplay-re-signing-and-partial-verification)
  - [Tools](#tools)
- [Tests](#tests)
  - [GT-PRIV-0075-1: Build twice from the same commit and compare (Android)](#gt-priv-0075-1-build-twice-from-the-same-commit-and-compare-android)
  - [GT-PRIV-0075-2: Compare a distributed APK with a local build ignoring signatures (Android)](#gt-priv-0075-2-compare-a-distributed-apk-with-a-local-build-ignoring-signatures-android)
  - [GT-PRIV-0075-3: Compare a local build with a decrypted copy of the distributed build (iOS)](#gt-priv-0075-3-compare-a-local-build-with-a-decrypted-copy-of-the-distributed-build-ios)
  - [GT-PRIV-0075-4: Build-process review for reproducibility and provenance (Android and iOS)](#gt-priv-0075-4-build-process-review-for-reproducibility-and-provenance-android-and-ios)
- [Secure implementation](#secure-implementation)
  - [Android build settings](#android-build-settings)
  - [iOS build settings](#ios-build-settings)
  - [Publishing releases that others can verify](#publishing-releases-that-others-can-verify)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app offers reproducible builds."* MASWE-0075 maps to **MASVS-PRIVACY-3** ("The app is transparent about data collection and usage") and to [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) (Reliance on Insufficiently Trustworthy Component) and [CWE-494](https://cwe.mitre.org/data/definitions/494.html) (Download of Code Without Integrity Check). The CWE mapping is loose. Neither CWE describes reproducibility. They describe what goes wrong without it: users install code whose link to the reviewed source nobody can check. OWASP describes the threat as "apps can include code that is different from the audited source code", and lists two attacks: compromising a dependency, SDK or build tool in the supply chain, and distributing tampered builds that cannot be told apart from legitimate ones.

Of the PRIVACY weaknesses, this is the only one that carries **only the P profile** (no EUDIW). In practice it matters most in three cases:

- **Open-source apps that make privacy claims.** Examples are messengers, password managers, crypto wallets, VPNs and health or contact-tracing apps. Their users, journalists and researchers are told "read the code". Reproducible builds are what makes that advice meaningful for the binary in the store.
- **Apps that a third party audited.** A certification, a government assessment, or a published audit report covers a specific source revision. Reproducibility lets the auditor or the client show that the release is that revision.
- **Closed-source apps with a strong supply-chain requirement.** The public cannot verify these, but the owner can. If a second, independent build environment reproduces the release, a compromised CI runner or build machine would show up.

What is covered, and by which test:

| Question | Platform | Test |
|---|---|---|
| Does building the same commit twice, in different clean environments, give identical output? | Android | [GT-PRIV-0075-1](#gt-priv-0075-1-build-twice-from-the-same-commit-and-compare-android) |
| Does the APK users actually install match a build from the published source, apart from signatures and documented store metadata? | Android | [GT-PRIV-0075-2](#gt-priv-0075-2-compare-a-distributed-apk-with-a-local-build-ignoring-signatures-android) |
| Does the App Store executable match a local build, as far as FairPlay encryption and Apple's re-signing allow anyone to check? | iOS | [GT-PRIV-0075-3](#gt-priv-0075-3-compare-a-local-build-with-a-decrypted-copy-of-the-distributed-build-ios) |
| Is the build process set up so that reproduction is possible: pinned toolchain and dependencies, fixed timestamps, provenance, published instructions? | Both | [GT-PRIV-0075-4](#gt-priv-0075-4-build-process-review-for-reproducibility-and-provenance-android-and-ios) |

There are no legacy v1 tests to replace, because MASVS v1 had no privacy category.

Keep the neighbours apart:

| Question | Where it lives |
|---|---|
| Can anyone show the binary was built from the claimed source? | This note |
| Does the binary contain code nobody intended (planted, injected by a build tool, hostile SDK)? Release-to-release diffs, CI hardening, code transparency for app bundles | [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) |
| Are the dependencies vulnerable, and is there an SBOM? | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/), [third-party libraries](/mobile/mastg-know-0004-third-party-libraries/) |
| How do APK and iOS code signatures work? | [App signing (MASTG-KNOW-0003)](/mobile/mastg-know-0003-app-signing/) |
| Is the app obfuscated (and does the obfuscator use a random seed)? | [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/) |
| Do the app's data collection declarations match what it does? | [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) |

This is technical testing guidance, not legal advice. As far as we know, no privacy law requires reproducible builds. They are evidence: they support a controller's transparency claims and the "data protection by design" argument under [Art. 25 GDPR](https://eur-lex.europa.eu/eli/reg/2016/679/oj) by showing that the reviewed code is the code that runs. Whether that matters for a given regulatory position is for the client's DPO or legal team.

## Modes of Introduction

**The source is not available to whoever needs to verify.** This applies either to the public (for open-source claims) or to the auditor (for closed-source assurance). OWASP lists it first. Without the source, the build scripts and the build environment definition, there is nothing to reproduce.

**Build outputs depend on when, where and on what machine the build ran.** Typical causes are a timestamp in `BuildConfig`, a build number made from the date, absolute paths in native libraries or Swift binaries, the host name or user name in a generated file, entries in an archive or a hash map in a different order, and output that changes with the number of CPU cores.

**Unpinned build environment.** A `+` or `latest.release` dependency version, a Gradle wrapper without a checksum, a CI image referenced by a moving tag (`:latest`), "whatever Xcode the runner has today", or SwiftPM and CocoaPods resolution that is not locked. A release built this way cannot be rebuilt next month even by its own team.

**No provenance.** Nothing records which commit, which pipeline, which toolchain and which dependency set produced the release. Without that record, an outsider has nothing to reproduce against.

**Non-deterministic obfuscation or protection.** Commercial obfuscators and app shielding tools often use a random seed per build, and some are applied after the build by a separate service. Each release is then unique by design, so it can never be compared with a rebuild unless the seed and the tool version are recorded and reused.

**Store-side transformation.** Google Play builds and signs APKs from an app bundle and can add its own code (automatic integrity protection). The App Store encrypts and re-signs the executable. The developer cannot fully control either. Both can be planned for (see [Background](#background)), but only if the team knows they happen.

## Impact

- **Tampering goes unnoticed.** If a dependency, build plugin, CI runner, signing service or developer machine is compromised, the malicious code reaches every user. Nobody can notice by rebuilding, because a rebuild is expected to differ anyway. The xz-utils backdoor (CVE-2024-3094) showed this class of problem: the release tarballs contained build logic that was not in the Git source. [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) covers it in more depth.
- **Privacy claims cannot be checked.** A published source that shows no analytics SDK, no contact upload and end-to-end encryption says nothing about the binary if the two cannot be linked. Users, researchers and supervisory authorities are left with trust instead of evidence.
- **Audits do not carry over.** A source code review or a certification covers a specific revision. Without reproducibility the release is "probably" that revision, and the audit report has to say so.
- **Weaker incident response.** If a release is suspected of tampering, a reproducible build answers the question in an hour. Without one, the team has to reverse engineer its own app.

## Mitigations

- **Make the source and build definition available** to whoever must verify: the public for open-source apps, an auditor or an internal second team for closed-source apps. This includes build scripts, CI definitions and the container or VM image definition.
- **Make the build deterministic.** Remove timestamps, absolute paths, host and user data and unstable ordering from the outputs. Take any needed time value from `SOURCE_DATE_EPOCH` (the commit time). Follow the [reproducible-builds.org](https://reproducible-builds.org/docs/) guidance.
- **Pin and record the environment**: the Gradle wrapper with its checksum, the JDK, the Android build tools and NDK versions, the Xcode version, a CI image by digest, and locked and verified dependencies.
- **Publish provenance and verification instructions.** Sign provenance for each release (SLSA), tag releases, record the commit, publish hashes and a step-by-step "how to reproduce this release" guide, and say exactly which differences (signatures, store metadata) are expected.
- **Make protections deterministic.** Record and reuse obfuscator seeds and tool versions. Prefer protections applied inside the reproducible build over post-build services.
- **Plan for the store.** On Android, publish a reproducible APK outside Play (website, F-Droid), use code transparency for bundles, or both. Document whether Play automatic protection is on. On iOS, be honest that public verification is only partial (see [iOS](#ios-fairplay-re-signing-and-partial-verification)).

## Background

There is no OWASP Knowledge item for this weakness. The sections below explain the mechanisms a tester needs.

### Why reproducibility is a privacy control

Most privacy controls are about what the app does with data. This one is about whether anyone can **check** what the app does. MASVS-PRIVACY-3 asks for transparency about data collection and usage. For an app whose transparency rests on its published source, transparency is only as strong as the link between that source and the shipped binary.

The pattern repeats across privacy-critical apps:

- **Contact-tracing apps (2020–2022).** Many national COVID-19 apps published their source to win public trust, and civil-society groups asked straight away whether the store binaries matched it. Publishing the source answered part of the question. Only a reproducible build could answer the rest.
- **Messengers and VPNs.** "We can't read your messages" is a claim about client code. One public Android messenger documents a full reproducible-build procedure (OWASP's own references link to it). It is a good model for what verification instructions should look like.
- **Wallets.** Wallets hold keys that can be stolen directly. Independent projects rebuild wallet apps and publish whether each release is verifiable, which shows that users in this sector care about it.

A reproducible build does not make the code trustworthy. It moves the question from "is this binary what they say?" to "is this source acceptable?". That second question can then be answered by reading the code, and by the other tests in this series.

### What reproducible means

The [reproducible-builds.org definition](https://reproducible-builds.org/docs/definition/): a build is reproducible if, given the same source code, build environment and build instructions, any party can recreate bit-by-bit identical copies of all specified artefacts. Three parts of that definition matter in practice:

- **"Same build environment"** is part of the input. Pinning the toolchain is allowed, and in fact expected. A build that only reproduces with Xcode 16.2 on macOS 15 is still reproducible, provided that environment is documented and can be obtained.
- **"Specified artefacts"** lets the project define what is compared. For mobile apps the comparison excludes the signature, because an independent party cannot produce the developer's signature. F-Droid's and Signal's procedures both compare everything *except* signing data (and, for Play, Play-added metadata). This is accepted practice, but the exclusions must be listed and justified. "We ignored META-INF" can hide code (see GT-PRIV-0075-2).
- **"Bit-by-bit identical"** is stricter than "functionally equivalent". Decompiling both and comparing Java source is not reproducibility. It is a weaker check, useful for triage only.

Related terms you will meet: **deterministic build** (same machine, same output twice, which GT-PRIV-0075-1 checks first), **verifiable build** (a third party actually did reproduce a release), and **provenance** (a signed statement of what was built, from which source, by which builder). Provenance is not reproducibility. SLSA provenance tells you which pipeline claims to have built the artefact. Reproducibility lets you check that claim without trusting the pipeline. The two work best together.

### Sources of non-determinism

The common causes in mobile builds, roughly in the order you will hit them:

| Source | Where it shows up | Typical fix |
|---|---|---|
| **Build timestamps** | `BuildConfig` fields set from `System.currentTimeMillis()` or `Date()`; `CFBundleVersion` made from the date; `__DATE__`/`__TIME__` in C/Objective-C; generated "about" screens | Take the time from `SOURCE_DATE_EPOCH` (commit time), or drop it |
| **Archive metadata** | ZIP entry timestamps, permissions and order in APKs, AABs and JARs | AGP has zeroed APK entry timestamps since version 2.2.2. F-Droid reports that AGP 7.1 fixed an entry-ordering bug. Gradle 9 makes its own archive tasks reproducible by default; on older Gradle, set `isPreserveFileTimestamps = false` and `isReproducibleFileOrder = true` |
| **Absolute paths** | Native `.so` debug info and `__FILE__` strings; Swift `#filePath` and assertion messages; generated source comments | Build at a fixed path, or use `-ffile-prefix-map` / `-fdebug-prefix-map` style flags; strip debug info from shipped libraries |
| **Build IDs** | ELF `.note.gnu.build-id` in NDK libraries; Mach-O `LC_UUID` | These are content hashes. They match if the inputs match, so a difference here usually means some other input differed |
| **Unpinned dependencies** | Dynamic Gradle versions, unlocked SwiftPM/CocoaPods/npm resolution, a moving CI image | Lockfiles plus checksum verification; image by digest |
| **Toolchain versions** | Different JDK, build tools, NDK, AGP, Kotlin, Xcode or Swift | Pin and document; build in a container (Android) or a pinned Xcode (iOS) |
| **R8 / D8** | F-Droid reports that some R8 optimisations have been non-deterministic, with DEX output depending on the number of CPU cores. Fixes landed in R8 3.0.69 (core library desugaring) and in 8.6.33, 8.7.20 and 8.8 (CPU-core dependence), and AGP 8.8 fixed a DEX class-ordering issue for bundles | Use current AGP/R8; test with different core counts; record the version |
| **PNG crunching** | AAPT's PNG optimisation has given different output across builds | Optimise PNGs before committing and set `isCrunchPngs = false` |
| **Baseline profiles** | `assets/dexopt/baseline.prof` and `baseline.profm` have been reported to differ between builds | Rebuild with matching core count; current AGP; as a last resort disable the profile task, and record that you did |
| **VCS info** | AGP 8.3 and later write `META-INF/version-control-info.textproto` with the commit hash | Not a problem if you build from the same clean tagged commit. A dirty tree or a different commit shows up here, which is useful |
| **Obfuscators and protection tools** | Random seeds, licence or timestamp watermarks, post-build services | Fixed seeds, recorded tool versions, protection inside the reproducible build |
| **Signing** | v1 JAR signatures (`META-INF/*.SF`, `*.RSA`/`*.EC`, `MANIFEST.MF`) and the APK Signing Block (v2/v3); iOS `_CodeSignature/` and the signature blob in `__LINKEDIT` | Not removable. Compare with the signature excluded or copied (see below) |
| **Host data** | User name, host name, locale, time zone, `umask`, environment variables written into generated files or plists (`BuildMachineOSBuild` in iOS `Info.plist`) | Build in a container; for iOS, pin the macOS version as well as Xcode |

The table draws on [F-Droid's reproducible builds documentation](https://f-droid.org/docs/Reproducible_Builds/), which is the best maintained list of Android causes. The version numbers above are as F-Droid reports them; check the current page before quoting them in a report.

`SOURCE_DATE_EPOCH` is the [standard environment variable](https://reproducible-builds.org/docs/source-date-epoch/) for a fixed build time: a UNIX timestamp, normally the last commit time (`git log -1 --pretty=%ct`). Many compilers and packaging tools read it directly. AGP and Xcode do not. For mobile builds its main use is in your own build scripts: any place that wants "now" should read `SOURCE_DATE_EPOCH` instead (see [Secure implementation](#secure-implementation)).

### Android: signatures, F-Droid and Play delivery

**Signatures make bit-identical APKs from different signers impossible.** An independent party cannot sign with the developer's key, so their rebuild can never match the signed release byte for byte. APK Signature Scheme v2 and v3 sign the whole file (everything outside the APK Signing Block), which in turn means the unsigned contents are fully defined. The accepted approach uses that:

1. Build the APK unsigned.
2. **Copy the signature** from the official APK onto the unsigned rebuild. [apksigcopier](https://github.com/obfusk/apksigcopier) does this: it extracts the v1 signature files and the APK Signing Block and inserts them into the other APK.
3. Run `apksigner verify` on the result. If the official signature verifies over your rebuilt bytes, the rebuild is identical to the release in every byte the signature covers, which is all of them apart from the signing block itself.

`apksigcopier compare official.apk rebuilt.apk` does steps 2 and 3 in one go. This is stronger than any diff with exclusions, because the developer's own signature proves the match. It has one practical requirement: the developer must sign with `apksigner` (or a tool that lays out the APK the same way), so that signing does not change any other bytes. F-Droid's documentation currently warns that `apksigner` from build-tools 35.0.0-rc1 onwards produces APKs that apksigcopier cannot verify, and recommends build-tools 34 for signing. Check the current state before you rely on it.

**F-Droid's process.** F-Droid builds every app from source on its own build servers. For apps that opt in, its metadata names where the developer's official APK lives (`Binaries:`) and which signing certificate is allowed (`AllowedAPKSigningKeys`). F-Droid rebuilds, copies the developer's signature onto its rebuild and checks that it verifies. **Only if it matches** does F-Droid publish the developer-signed APK, so users get the same signature as from the developer's site and can update across channels. If it does not match, nothing is published. A separate [verification server](https://f-droid.org/docs/Verification_Server/) rebuilds F-Droid's own published APKs and reports whether each one reproduces, with a diffoscope log when it does not. The fdroidserver command behind this is `fdroid verify`. Our understanding from fdroidserver is that it compares freshly built unsigned APKs with the ones in the repository, but F-Droid's docs do not give its full command line. A green F-Droid reproducibility status for a version is strong, independent evidence. It covers the APK F-Droid publishes, not what Play delivers.

**Why Play delivery breaks byte-for-byte comparison.** With an Android App Bundle (AAB), Google Play, not the developer, produces the APKs users install:

- Play **generates split APKs** (base, ABI, screen density, language) per device from the bundle. Users never receive the artefact the developer built.
- With **Play App Signing**, which is required for new apps since 2021, Play signs the APKs with an app signing key that Google holds. The developer's upload key signs only the bundle.
- Play adds **its own metadata**: typically a source stamp (`stamp-cert-sha256` and `com.android.stamp.*` manifest meta-data), Play-specific manifest meta-data, and Play's own data inside the APK Signing Block. Signal's comparison script ignores this class of "harmless metadata added by the Play Store".
- With **automatic integrity protection** turned on in Play Console, Play adds runtime checks to the app's code. The shipped DEX then differs from anything the developer can rebuild. Google documents that this feature is incompatible with code transparency.

You can still verify a Play install, but the method changes. You build the AAB from source, use `bundletool` to generate the splits for your test device, pull the installed splits from that device, and compare each pair while ignoring signatures and the documented Play metadata (GT-PRIV-0075-2). This is what Signal's published procedure does.

**Code transparency for app bundles** is Google's partial answer. The developer signs a list of hashes of the DEX files and native libraries with a separate key that stays with the developer, and `bundletool check-transparency` checks an installed app against it. It shows that Play did not change the code. It does not cover resources, assets or the manifest, and it does not show that the code matches the public source. The [MASWE-0048 note](/mobile/maswe-0048-malicious-code-included-in-the-app/) explains how to set it up and check it. Treat it as a complement to reproducible builds, not a replacement.

### iOS: FairPlay, re-signing and partial verification

There is no iOS equivalent of the F-Droid model, and public verification of App Store binaries is only partly possible. Before you promise a client anything, know why:

- **FairPlay encryption.** App Store executables (and, in our experience, TestFlight ones) are encrypted on the device. The `LC_ENCRYPTION_INFO_64` load command has `cryptid 1`, and the range `cryptoff`..`cryptoff+cryptsize`, which covers the start of `__TEXT` and so the code, is ciphertext. Xcode's local build has the same load command with `cryptid 0`. To compare code you need a decrypted copy. The only way to get one is to dump it from memory on a **jailbroken** device (frida-ios-dump, bagbak), which ordinary users cannot do.
- **Apple re-signs.** The installed app carries Apple's signature, not the developer's. `_CodeSignature/`, the code signature blob at the end of `__LINKEDIT` (and the load command sizes that describe it) and `embedded.mobileprovision` differ by design. There is no signature-copying trick as on Android: the developer's distribution signature is replaced, not kept.
- **App Thinning.** The App Store delivers device-specific variants: asset catalogues (`Assets.car`) with only the device's scale and idiom, and on-demand resources outside the bundle. Comparing resources therefore needs a local export thinned for the same device model. Executables are normally arm64-only today, so architecture slicing rarely matters.
- **Bitcode is gone.** Before Xcode 14, Apple could recompile apps from bitcode, so the shipped machine code was Apple's build, not the developer's. Xcode 14 deprecated bitcode and the App Store no longer accepts bitcode submissions from Xcode 14 builds, so on current apps the shipped `__TEXT` should be the developer's own compiler output. Once decrypted, it can be compared.
- **Xcode is not designed for reproducibility.** Apple documents no reproducible-build mode. Known sources of variation are `BuildMachineOSBuild`, `DTXcodeBuild` and `DTSDKBuild` in `Info.plist` (so the macOS version of the build machine is part of the output), absolute paths in Swift and Objective-C binaries, `__DATE__`/`__TIME__`, compiled asset catalogues and storyboards, and build-phase scripts that write dates or build numbers. Teams that try usually reach identical executables with care and still see differences in compiled resources.

The realistic iOS position is this. The **developer or an authorised auditor** can show that (a) two local builds match (determinism), (b) a local build matches the archive that was uploaded to App Store Connect, and (c) on a jailbroken test device, the decrypted App Store executable's sections match the local build. The **public** cannot do any of this without a jailbreak. An iOS app can therefore not offer verifiable builds to its users in the way an Android app can through F-Droid. A report should say this plainly rather than mark every iOS app as failing a requirement it cannot meet.

### Tools

| Tool | Use here | Notes |
|---|---|---|
| [diffoscope](https://diffoscope.org/) | Recursive, format-aware diff: unpacks APK/AAB/IPA, decodes DEX (via dexdump/baksmali), ELF, Mach-O, binary XML and plists | `diffoscope --html report.html a.apk b.apk`; `--text -` for the terminal; `--exclude GLOB` to skip paths; exit status 0 = identical, 1 = different. Install from your distro or use the official container image |
| [apksigcopier](https://github.com/obfusk/apksigcopier) | Copy or compare APK signatures | `extract`, `patch`, `copy`, `compare` |
| apksigner (build-tools) | Verify signatures and print signer certificates | `apksigner verify --print-certs --verbose app.apk` ([MASTG-TOOL-0123](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/)) |
| [bundletool](https://developer.android.com/tools/bundletool) | Generate device-specific APKs from an AAB; check code transparency | `build-apks --connected-device`, `check-transparency` |
| `zipinfo` | Show ZIP entry order, timestamps, permissions and compression | `zipinfo -l app.apk`; `-T` prints sortable timestamps |
| aapt2 | Dump the binary manifest as text for diffing | `aapt2 dump xmltree --file AndroidManifest.xml app.apk` |
| apktool / jadx | Triage only: decode resources or decompile to see *what* a DEX difference is | Decoding is lossy. Never use it to claim two builds are identical ([MASTG-TOOL-0011](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [MASTG-TOOL-0018](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)) |
| [reprotest](https://salsa.debian.org/reproducible-builds/reprotest) | Builds twice while varying time, paths, user, locale, time zone, `umask`, CPU count and file ordering | From Debian; its default `null` back end runs builds locally |
| otool, lipo, plutil, codesign | Mach-O load commands, architecture slicing, plist conversion, signature inspection | [MASTG-TOOL-0060 otool](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0060/), [MASTG-TOOL-0114 codesign](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0114/) |
| frida-ios-dump / bagbak | Decrypted dump of an installed iOS app on a jailbroken device | [MASTG-TOOL-0050](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0050/), [MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/) |
| `gh attestation verify` | Check GitHub artifact attestations (SLSA provenance) | `gh attestation verify app-release.aab --owner example-org` |

## Tests

OWASP has no tests for MASWE-0075. All four tests below are ours. Run GT-PRIV-0075-1 first: if the team cannot reproduce its own build, comparing against the store is pointless. GT-PRIV-0075-4 can run on its own as a design review when you have no time for builds.

### GT-PRIV-0075-1: Build twice from the same commit and compare (Android)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Build the release variant twice from the same tagged commit, in two clean environments that differ in the things that should not matter (checkout path, time zone, locale, CPU count, time of day), and compare the outputs. Identical output shows the build is deterministic. Any difference names a source of non-determinism to fix before anyone can verify a release.

#### Prerequisites

- Source access at the release tag, including the Gradle wrapper and all build scripts. Ask for the documented build instructions and the container image or Dockerfile the team uses. If there is none, that is already an observation for GT-PRIV-0075-4.
- Docker or Podman, and enough disk space for two full Gradle caches.
- A way to build the release variant **without the production signing key**. Usually it is enough to leave the keystore environment variables unset, so the build produces `app-release-unsigned.apk` or an unsigned AAB. You never need the client's signing key for this test.
- diffoscope (for example its container image), `sha256sum`, `zipinfo`.

#### Steps

1. Prepare two separate checkouts at **different absolute paths**, so path leakage shows up:

   ```bash
   TAG=v1.4.2
   REPO=https://git.example.com/example/app.git
   for run in a b; do
     rm -rf "/tmp/repro-$run"; mkdir -p "/tmp/repro-$run"
     git clone --quiet "$REPO" "/tmp/repro-$run/src-$run"
     git -C "/tmp/repro-$run/src-$run" checkout --quiet "$TAG"
     git -C "/tmp/repro-$run/src-$run" status --porcelain   # must print nothing
   done
   ```

2. Build each one in a fresh container from the **same image, referenced by digest**, with different CPU sets, time zones and locales. Each container starts with an empty Gradle cache, so this also tests that dependencies resolve to the same artefacts:

   ```bash
   IMG=registry.example.com/android-build@sha256:<digest-from-the-team>

   docker run --rm --cpuset-cpus=0-1 -e TZ=UTC -e LANG=C.UTF-8 \
     -v /tmp/repro-a/src-a:/build/src-a -w /build/src-a "$IMG" \
     ./gradlew --no-daemon --no-build-cache --no-configuration-cache clean assembleRelease bundleRelease

   docker run --rm --cpuset-cpus=0-7 -e TZ=Pacific/Auckland -e LANG=de_DE.UTF-8 \
     -v /tmp/repro-b/src-b:/work/other/place/src-b -w /work/other/place/src-b "$IMG" \
     ./gradlew --no-daemon --no-build-cache --no-configuration-cache clean assembleRelease bundleRelease
   ```

   Run the second build at least a minute later, or on a different day, so wall-clock timestamps differ. Use the exact task names from the team's instructions (flavours change them, for example `assembleProdRelease`).

3. Compare hashes first:

   ```bash
   find /tmp/repro-a /tmp/repro-b -path '*/outputs/*' \( -name '*.apk' -o -name '*.aab' \) \
     -exec sha256sum {} \; | sort -k2
   ```

4. If anything differs, run diffoscope on each pair and keep the HTML report as evidence:

   ```bash
   docker run --rm -v /tmp:/tmp registry.salsa.debian.org/reproducible-builds/diffoscope \
     --html /tmp/repro-apk.html --text - \
     /tmp/repro-a/src-a/app/build/outputs/apk/release/app-release-unsigned.apk \
     /tmp/repro-b/src-b/app/build/outputs/apk/release/app-release-unsigned.apk
   ```

5. For each difference, find the cause with the [Sources of non-determinism](#sources-of-non-determinism) table. For ZIP-level differences, `zipinfo -l` on both files shows entry order, timestamps and compression. For DEX differences, diffoscope's dexdump section shows which classes differ. Use jadx on just those classes to see what they are (a `BuildConfig` timestamp, an R8 ordering change, or real logic).

6. Optional: let reprotest apply more variations automatically. Its build command is run through a shell:

   ```bash
   cd /tmp/repro-a/src-a
   reprotest --vary=-user_group,-domain_host \
     './gradlew --no-daemon clean assembleRelease' \
     'app/build/outputs/apk/release/*.apk'
   ```

   Its `time` variation uses faketime, and some JVM builds misbehave under it. If the build hangs, add `-time` to `--vary` and vary the time manually as in step 2.

#### Observation

Record the tag and commit, the image digest, the Gradle, AGP, JDK, build-tools and NDK versions (`./gradlew --version`, `gradle/libs.versions.toml`), the hashes of both outputs, and for each difference the file inside the archive, what changed and the likely cause.

#### Evaluation

- **Pass:** the unsigned APK and the AAB are byte-identical across both builds.
- **Pass with notes:** identical only after a documented, narrow workaround, such as a fixed core count, or baseline profiles disabled with the reason recorded.
- **Fail:** any difference. Classify it:
  - *Fixable noise*: timestamps, paths, ordering, PNG crunching, baseline profile. Report the cause and the fix.
  - *Uncontrolled inputs*: a different dependency version or toolchain resolved in the two runs. This is an unpinned build and is serious, because it means the team cannot reproduce its own release either.
  - *Unexplained code differences* in DEX or `.so` that you cannot trace to a known cause. Do not dismiss these. Escalate them under [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) until explained.

#### Demo

A typical first result for an app that writes its build time into `BuildConfig`. The output below is illustrative and was not produced against a real app:

```kotlin
// app/build.gradle.kts — the cause
android {
    defaultConfig {
        buildConfigField("long", "BUILD_TIME", "${System.currentTimeMillis()}L")
    }
}
```

```text
$ sha256sum */src-*/app/build/outputs/apk/release/app-release-unsigned.apk
3f1c…9a0e  repro-a/src-a/app/build/outputs/apk/release/app-release-unsigned.apk
b72d…14c5  repro-b/src-b/app/build/outputs/apk/release/app-release-unsigned.apk

$ diffoscope --text - a.apk b.apk
--- a.apk
+++ b.apk
├── classes.dex
│ ├── dexdump -a -d -f -h {}
│ │ @@ -51210,15 +51210,15 @@
│ │ -  Class #812 - 'Lcom/example/app/BuildConfig;'
│ │ ...
│ │ -      value         : (long) 1762812542117
│ │ +      value         : (long) 1762812719004
```

The fix ([Secure implementation](#secure-implementation)) takes the value from `SOURCE_DATE_EPOCH`. After the fix, both hashes are equal and diffoscope exits with status 0 and no output.

### GT-PRIV-0075-2: Compare a distributed APK with a local build ignoring signatures (Android)

*Guler Tech methodology — not an OWASP test.*

#### Overview

GT-PRIV-0075-1 shows the team *can* reproduce its build. This test shows that **what users actually install** matches a build from the published source. How you compare depends on how the app is distributed:

| Channel | What users get | Comparison |
|---|---|---|
| Website, GitHub release, F-Droid with developer signature | One APK signed by the developer | Copy the signature and verify (`apksigcopier compare`). Strongest result |
| F-Droid built and signed by F-Droid | One APK signed by F-Droid | Same method against F-Droid's APK; also check F-Droid's verification status |
| Google Play (AAB) | Play-generated split APKs signed with the Play app signing key | Build the AAB, generate splits for the test device with bundletool, pull the installed splits, diff each pair with documented exclusions |

#### Prerequisites

- GT-PRIV-0075-1 passes, or you know exactly which differences to expect.
- The exact version under test. Read it from the distributed artefact (`aapt2 dump badging app.apk | grep version`) or from the device (`adb shell dumpsys package com.example.app | grep -E 'versionCode|versionName'`), and map it to a tag or commit. Check `META-INF/version-control-info.textproto` in the APK if present: it contains the commit.
- For Play: a test device you control, with the app installed **from Play** under a test account, plus adb and bundletool. A device-specific comparison only covers the splits that device receives. Pick a common configuration and say which.
- apksigcopier and apksigner (build-tools), diffoscope, aapt2.

#### Steps

**A. Single developer-signed APK (website, release page, F-Droid developer-signed):**

1. Download the official APK and record its hash and signer:

   ```bash
   sha256sum official.apk
   apksigner verify --print-certs --verbose official.apk | grep -E 'Verified using|SHA-256 digest'
   ```

   Check that the signer certificate digest matches the one the project publishes (website, F-Droid `AllowedAPKSigningKeys`, Play listing).

2. Build the same tag unsigned, as in GT-PRIV-0075-1, giving `app-release-unsigned.apk`.

3. Copy the official signature onto your build and verify:

   ```bash
   apksigcopier compare official.apk app-release-unsigned.apk && echo MATCH
   ```

   If your local APK is signed (for example with a debug key), apksigcopier removes that signature first. Use `--unsigned` when the second file is already unsigned; check `apksigcopier compare --help` for your version. The manual equivalent is `apksigcopier copy official.apk app-release-unsigned.apk signed-rebuild.apk` followed by `apksigner verify signed-rebuild.apk`.

4. If verification fails, diff the two to see why. Here, unlike in case B, signature files are the only acceptable difference:

   ```bash
   diffoscope --html official-vs-rebuild.html official.apk app-release-unsigned.apk
   ```

5. For apps on F-Droid, also look up the version on F-Droid's verification results and note whether F-Droid reproduced it.

**B. Google Play delivery:**

1. Pull the installed splits from your test device:

   ```bash
   mkdir -p from-device
   adb shell pm path com.example.app | sed 's/^package://' | while read -r p; do
     adb pull "$p" from-device/
   done
   ls from-device/   # base.apk, split_config.arm64_v8a.apk, split_config.xxhdpi.apk, split_config.en.apk ...
   ```

2. Build the AAB for the same tag (`bundleRelease`, or the flavour the team ships to Play), then generate the splits for the same device:

   ```bash
   bundletool build-apks --bundle=app-release.aab --output=local-apks \
     --output-format=DIRECTORY --connected-device
   ls local-apks/splits/   # base-master.apk, base-arm64_v8a.apk, base-xxhdpi.apk, base-en.apk ...
   ```

   bundletool signs these with the debug keystore. That does not matter, because signatures are excluded from the comparison.

3. Get an overview of which entries differ in each pair (base-to-base, ABI-to-ABI and so on):

   ```bash
   rm -rf cmp && mkdir -p cmp/play cmp/local
   unzip -q from-device/base.apk -d cmp/play
   unzip -q local-apks/splits/base-master.apk -d cmp/local
   diff -rq cmp/play cmp/local
   ```

4. Compare the manifests as text, because the binary XML differs if Play added anything:

   ```bash
   diff <(aapt2 dump xmltree --file AndroidManifest.xml from-device/base.apk) \
        <(aapt2 dump xmltree --file AndroidManifest.xml local-apks/splits/base-master.apk)
   ```

5. Run diffoscope on each pair for the detail and keep the reports. **Do not** exclude `META-INF/*` wholesale: `META-INF/services/` (ServiceLoader registrations, which decide what code runs), Kotlin module files and `version-control-info.textproto` live there too. Exclude only named signature files, or leave everything in and annotate the expected differences.

6. Check whether Play automatic protection is enabled (ask the team, or look at Play Console's *App integrity* page with them). If it is, DEX differences are expected and the comparison cannot pass for code. Record that and use code transparency, if the team uses it, as the code-level check instead (see [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/)).

7. If the project publishes a comparison script (for example one modelled on Signal's `apkdiff.py`), run it as well. Then read its exclusion list and check that every excluded path is really non-functional.

#### Observation

Record the channel, version, signer certificate digest, hashes of every compared file, the test device model and Android version, and for each pair the list of differing entries with your classification: *signature*, *documented store metadata*, *explained build noise* or *unexplained*.

#### Evaluation

- **Pass (single APK):** `apksigcopier compare` succeeds, meaning the official signature verifies over your rebuilt bytes. Nothing else needs explaining.
- **Pass (Play):** for every compared pair, the only differences are signing data (`META-INF/*.SF`, `*.RSA`/`*.EC`/`*.DSA`, `MANIFEST.MF` from v1 signing, and the APK Signing Block) and documented Play additions (source stamp file, `com.android.stamp.*` and other Play-added manifest meta-data). DEX, native libraries, resources, assets and all other manifest content are identical.
- **Fail:** any difference in DEX, `.so`, `resources.arsc`, `res/`, `assets/`, `META-INF/services/` or functional manifest content (components, permissions, exported flags, `meta-data` the app or an SDK reads) that is not explained by a documented store transformation. Distinguish carefully:
  - If GT-PRIV-0075-1 also fails on the same files, the cause is probably build non-determinism. Report it under this weakness.
  - If GT-PRIV-0075-1 passes but the distributed APK differs, the shipped code was **not** built from the claimed source, or was changed after the build. Treat this as a potential [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) incident: stop, tell the client, and investigate before writing it up as a reproducibility finding.
  - Automatic protection explains DEX differences, but it also means the code cannot be verified from source. Report it as such, Info to Low depending on the app's claims.

#### Demo

Illustrative output for a matching website APK and for a Play base split. Neither was produced against a real app:

```text
$ apksigcopier compare official-1.4.2.apk app-release-unsigned.apk && echo MATCH
MATCH

$ diff -rq cmp/play cmp/local
Files cmp/play/AndroidManifest.xml and cmp/local/AndroidManifest.xml differ
Files cmp/play/META-INF/BNDLTOOL.RSA and cmp/local/META-INF/BNDLTOOL.RSA differ
Files cmp/play/META-INF/BNDLTOOL.SF and cmp/local/META-INF/BNDLTOOL.SF differ
Files cmp/play/META-INF/MANIFEST.MF and cmp/local/META-INF/MANIFEST.MF differ
Only in cmp/play: stamp-cert-sha256

$ diff <(aapt2 dump xmltree --file AndroidManifest.xml from-device/base.apk) \
       <(aapt2 dump xmltree --file AndroidManifest.xml local-apks/splits/base-master.apk)
< E: meta-data (line=0)
<   A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.android.stamp.source" (Raw: "com.android.stamp.source")
<   A: http://schemas.android.com/apk/res/android:value(0x01010024)="https://play.google.com/store" (Raw: "https://play.google.com/store")
...
```

All differences here are signing material and Play's source stamp. `classes*.dex`, `lib/`, `res/` and `resources.arsc` do not appear in the list, which is a pass. The exact names of v1 signature files and the Play meta-data you see vary.

### GT-PRIV-0075-3: Compare a local build with a decrypted copy of the distributed build (iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

This test checks how far an iOS release can be shown to match its source. It has three stages, each weaker in what it can prove and harder to run than the one before: local determinism, local build against the uploaded archive, and local build against a decrypted dump of the App Store or TestFlight copy on a jailbroken test device. Only the main executable and frameworks' **sections** are compared. The code signature, FairPlay-related fields and Apple-added files are excluded by necessity. The [iOS background](#ios-fairplay-re-signing-and-partial-verification) explains why.

Limits to state in every report:

- This is **partial verification**. Apple's signature replaces the developer's, so nothing ties the device copy to the developer cryptographically, as apksigcopier does on Android.
- Stage 3 needs a **jailbroken device** and the client's authorisation to decrypt their own app. End users cannot repeat it. It verifies one device's copy of one version.
- Thinned resources and on-demand resources differ per device and are compared only against an export thinned for the same model, where possible.
- A pass shows the code you compared is the same. It shows nothing about server-side behaviour, remote configuration or code loaded at runtime ([MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/)).

#### Prerequisites

- Source access at the release tag, and the **same Xcode version** that built the release. Read it from the shipped app's `Info.plist` (`DTXcode`, `DTXcodeBuild`). Plists are not encrypted, so this works on the App Store copy too. Ideally use the same macOS build as well (`BuildMachineOSBuild`).
- For stage 2: the `.xcarchive` or exported IPA the team uploaded for that version. Teams should archive these; if they cannot produce them, note it for GT-PRIV-0075-4.
- For stage 3: a jailbroken test device with Frida, the app installed from the App Store or TestFlight under a test account, and frida-ios-dump or bagbak ([MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/)).
- `otool`, `lipo`, `plutil`, Python 3, and the small section-hashing script below.

#### Steps

1. **Stage 1: local determinism.** Archive the release configuration twice, from two checkouts at different paths, without signing:

   ```bash
   for run in a b; do
     xcodebuild -workspace "/tmp/ios-$run/App.xcworkspace" -scheme App -configuration Release \
       -destination 'generic/platform=iOS' -archivePath "/tmp/ios-$run/App.xcarchive" \
       -disableAutomaticPackageResolution \
       CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" archive
   done
   ```

   Use `-project` instead of `-workspace` if the app has no workspace. Then compare the `.app` bundles inside `Products/Applications/` (step 4).

2. **Stage 2: local build against the uploaded archive.** Compare your `.app` with the one inside the team's uploaded `.xcarchive` or exported IPA for the same version. Both are unencrypted. Expect differences only in signing (`_CodeSignature/`, `embedded.mobileprovision`, the signature blob) and in keys added at export time.

3. **Stage 3: decrypted device copy.** On the jailbroken test device, dump the installed app and check that the executable is decrypted:

   ```bash
   iproxy 2222 22 &
   python3 dump.py -H 127.0.0.1 -p 2222 -u mobile -P '<device password>' com.example.app
   unzip -q App.ipa -d device
   otool -l device/Payload/App.app/App | grep -A4 LC_ENCRYPTION_INFO_64   # expect cryptid 0
   ```

   frida-ios-dump writes the decrypted bytes over the encrypted range and sets `cryptid` to 0. Everything else comes from the file on the device. bagbak (`bagbak com.example.app`) also dumps app extensions.

4. Thin both executables to the same architecture if needed (`lipo -info`, then `lipo -thin arm64 App -output App.arm64`). Hash every section with this script, which uses the standard library only and parses a thin 64-bit Mach-O:

   ```python
   #!/usr/bin/env python3
   """Print UUID, encryption info and a SHA-256 per section of a thin 64-bit Mach-O."""
   import hashlib, struct, sys

   LC_SEGMENT_64, LC_UUID, LC_ENCRYPTION_INFO_64 = 0x19, 0x1B, 0x2C
   ZEROFILL_TYPES = {0x1, 0xC, 0x12}  # S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL

   def main(path):
       data = open(path, "rb").read()
       if struct.unpack_from("<I", data, 0)[0] != 0xFEEDFACF:
           sys.exit("not a thin 64-bit Mach-O; run lipo -thin arm64 first")
       ncmds = struct.unpack_from("<I", data, 16)[0]
       off = 32
       for _ in range(ncmds):
           cmd, cmdsize = struct.unpack_from("<II", data, off)
           if cmd == LC_UUID:
               print("UUID", data[off + 8:off + 24].hex())
           elif cmd == LC_ENCRYPTION_INFO_64:
               cryptoff, cryptsize, cryptid = struct.unpack_from("<III", data, off + 8)
               print(f"ENCRYPTION cryptoff={cryptoff} cryptsize={cryptsize} cryptid={cryptid}")
           elif cmd == LC_SEGMENT_64:
               seg = data[off + 8:off + 24].rstrip(b"\0").decode()
               nsects = struct.unpack_from("<I", data, off + 64)[0]
               s = off + 72
               for _ in range(nsects):
                   sect = data[s:s + 16].rstrip(b"\0").decode()
                   size = struct.unpack_from("<Q", data, s + 40)[0]
                   fileoff = struct.unpack_from("<I", data, s + 48)[0]
                   flags = struct.unpack_from("<I", data, s + 64)[0]
                   if fileoff and (flags & 0xFF) not in ZEROFILL_TYPES:
                       digest = hashlib.sha256(data[fileoff:fileoff + size]).hexdigest()[:16]
                       print(f"{seg},{sect} size={size} sha256={digest}")
                   s += 80
           off += cmdsize

   if __name__ == "__main__":
       main(sys.argv[1])
   ```

   ```bash
   python3 -I macho_sections.py local/App.app/App  > local.txt
   python3 -I macho_sections.py device/Payload/App.app/App > device.txt
   diff local.txt device.txt
   ```

   Repeat for each framework in `Frameworks/` (`*.framework/<name>`). Keep the script outside the dumped app directory.

5. Compare the rest of the bundle, excluding what Apple or signing necessarily changes, and convert plists to XML before diffing:

   ```bash
   diff -rq -x _CodeSignature -x SC_Info -x embedded.mobileprovision -x '*.car' \
     local/App.app device/Payload/App.app
   diff <(plutil -convert xml1 -o - local/App.app/Info.plist) \
        <(plutil -convert xml1 -o - device/Payload/App.app/Info.plist)
   ```

   `Assets.car` differs because of App Thinning. Compare it only against a local export thinned for the same device model (the `thinning` option in `ExportOptions.plist` for non-App Store export methods), or leave it out and say so.

#### Observation

Record the version, the Xcode and macOS versions used for the release and for your rebuild, which stages you ran, the section hash lists, `LC_UUID` for each binary, and every differing file with its classification.

#### Evaluation

- **Stage 1 pass:** all executables and frameworks have identical section hashes and UUIDs across the two local builds, and bundle files are identical. If this fails, the app is not deterministic. Report the causes (paths, timestamps, plist keys from build scripts) and stop: stages 2 and 3 cannot pass.
- **Stage 2 pass:** your build matches the uploaded archive except for signing material. A mismatch here, with stage 1 passing, means the release was built from a different source, a different toolchain or a different environment than the team states. Investigate it like a GT-PRIV-0075-2 failure.
- **Stage 3 pass (partial):** every section of every Mach-O, apart from what lies in `__LINKEDIT` (signature), has the same hash; the UUIDs match; the load commands differ only in what describes the code signature (`LC_CODE_SIGNATURE` and the `__LINKEDIT` size), because the dump has already reset `cryptid` to 0; and the bundle differs only in Apple-managed files and thinned assets. Write it up as "code sections verified for version X on device model Y", never as "reproducible build verified".
- **Fail:** any `__TEXT` or `__DATA*` section difference that is not explained by stage 1 noise. Escalate unexplained code differences under [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/).
- **Not testable** (Info, not Fail): no jailbroken device available for the iOS version the app requires, or no authorisation to decrypt. Report stages 1 and 2 only.

#### Demo

An illustrative stage 3 result (not from a real app). Only the encryption flag and the signature-related layout differ; all code and data sections match:

```text
$ diff local.txt device.txt
$ head -6 local.txt
UUID 4c1d2e3f5a6b47c8901d2e3f4a5b6c7d
ENCRYPTION cryptoff=16384 cryptsize=7340032 cryptid=0
__TEXT,__text size=6981204 sha256=8e1f0c2a9b7d3e41
__TEXT,__stubs size=10236 sha256=0d6a4c1e72b9f830
__TEXT,__objc_methname size=211876 sha256=a43b9e0c51d7f2e6
__TEXT,__cstring size=301442 sha256=5f7e2d1c0b9a8e3d

$ otool -l device/Payload/App.app/App | grep -A4 LC_CODE_SIGNATURE
      cmd LC_CODE_SIGNATURE
  cmdsize 16
  dataoff 9437296
 datasize 271088
```

`diff` printing nothing means every section hash, the UUID and the (decrypted) encryption fields match. The code signature location and size are not part of the script's output, and in our experience they always differ.

### GT-PRIV-0075-4: Build-process review for reproducibility and provenance (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

A design review of the build and release process. It answers two questions: could anyone reproduce a release, and does each release carry enough provenance to say what to reproduce? Use it alone when there is no time for builds, and always alongside GT-PRIV-0075-1 to -3 to explain their results. It overlaps with the pipeline review in [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) (GT-CODE-0048-5). That review asks whether the pipeline is hardened against tampering. This one asks whether its output can be **reproduced and verified**.

#### Prerequisites

- Read access to the repository, CI configuration and release documentation.
- An interview with whoever cuts releases: who builds, where, with what, and how the artefact reaches the store.

#### Steps

1. **Source and instructions.** Is the source for each release available to the people who need to verify it (public, or auditor)? Are releases tagged, with signed tags? Is there a written "how to reproduce release X" guide, and does it list expected differences?

2. **Toolchain pinning (Android).**

   ```bash
   grep -E 'distributionUrl|distributionSha256Sum' gradle/wrapper/gradle-wrapper.properties
   grep -rnE 'ndkVersion|buildToolsVersion|languageVersion|jvmToolchain' --include='*.gradle*' .
   cat .java-version .tool-versions 2>/dev/null
   grep -nE '^FROM' Dockerfile* ci/**/Dockerfile* 2>/dev/null   # expect @sha256: digests
   ```

3. **Dependency pinning (Android).**

   ```bash
   ls gradle/verification-metadata.xml gradle.lockfile */gradle.lockfile 2>/dev/null
   grep -rnE '"[^"]*:\+"|:[0-9.]*\+"|latest\.(release|integration)|-SNAPSHOT' \
     --include='*.gradle*' --include='*.toml' .
   ```

   Dynamic versions (`+`, `latest.*`) and `-SNAPSHOT` in a release build mean a rebuild can pull different code.

4. **Toolchain and dependency pinning (iOS).** Check `Package.resolved` (inside `*.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/` or `*.xcworkspace/xcshareddata/swiftpm/`), `Podfile.lock`, `Cartfile.resolved` and any JavaScript lockfile (React Native, Flutter `pubspec.lock`) are committed. Check that CI uses `xcodebuild -disableAutomaticPackageResolution` and `pod install --deployment`, and that the Xcode version is pinned (`.xcode-version`, the CI image, or the `xcodes` configuration).

5. **Timestamps and host data in the build.**

   ```bash
   grep -rnE 'currentTimeMillis|Instant\.now|LocalDateTime\.now|new Date\(\)|Date\(\)' \
     --include='*.gradle*' --include='*.kts' .
   grep -rnE '__DATE__|__TIME__|__TIMESTAMP__' --include='*.c' --include='*.cpp' --include='*.m' --include='*.h' .
   grep -rn 'date +' *.xcodeproj/project.pbxproj scripts/ 2>/dev/null   # run-script phases stamping dates
   grep -rn SOURCE_DATE_EPOCH . --include='*.gradle*' --include='*.sh' --include='*.yml' --include='*.pbxproj'
   ```

6. **Store-side and post-build steps.** Is the release signed or shielded by a service after the build (obfuscation SaaS, app wrapping)? Is Play automatic protection on? Is code transparency used, and who holds that key? Are App Store `.xcarchive` files and AABs archived per release?

7. **Provenance.** Does CI produce signed provenance (SLSA Build Level 2 or 3, for example GitHub artifact attestations)? Can you verify it?

   ```bash
   gh attestation verify app-release.aab --owner example-org
   ```

   Are artefact hashes published with the release notes?

#### Observation

A checklist with evidence per item: file and line, CI job, interview answer. For each gap, note which test it explains (for example "GT-PRIV-0075-1 DEX difference ← `BUILD_TIME` in `app/build.gradle.kts:41`").

#### Evaluation

- **Pass:** source and instructions are available to the intended verifiers; the toolchain is pinned (wrapper checksum, JDK, NDK, build tools, container by digest, or Xcode version); dependencies are locked and verified; no wall-clock time or host data goes into the build, or it comes from `SOURCE_DATE_EPOCH`; post-build modifications are documented and either deterministic or covered by code transparency; releases have tags, provenance and published hashes.
- **Fail:** any of these is missing. Weight them by consequence. An unpinned toolchain or dependencies means *even the team* cannot reproduce or investigate a release, which is the most serious. Missing public instructions matter only where the app claims public verifiability.
- **Not applicable / Info:** closed-source apps without a verifiability claim, where the owner has accepted that only internal reproducibility is in scope. Report internal gaps only.

#### Demo

An illustrative excerpt from a review (not from a real engagement):

```text
[FAIL] gradle/wrapper/gradle-wrapper.properties: no distributionSha256Sum
[FAIL] app/build.gradle.kts:41  buildConfigField("long", "BUILD_TIME", "${System.currentTimeMillis()}L")
[FAIL] gradle/libs.versions.toml:18  analytics = "com.example.sdk:analytics:3.+"
[OK]   gradle/verification-metadata.xml present, sha256 for all release dependencies
[WARN] .github/workflows/release.yml: runs-on: macos-latest (Xcode version not pinned)
[OK]   gh attestation verify app-release.aab --owner example-org -> verified, workflow release.yml@refs/tags/v1.4.2
[INFO] Play automatic protection: off; code transparency: not used
```

## Secure implementation

### Android build settings

Pin and verify the toolchain and dependencies, and take any time value from the commit:

```kotlin
// app/build.gradle.kts
val sourceDateEpoch: Long = providers.environmentVariable("SOURCE_DATE_EPOCH")
    .orElse("0").get().toLong()

android {
    ndkVersion = "27.2.12479018"            // exact version, not a range
    buildFeatures { buildConfig = true }
    defaultConfig {
        // Instead of System.currentTimeMillis():
        buildConfigField("long", "BUILD_EPOCH", "${sourceDateEpoch}L")
    }
    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isCrunchPngs = false            // optimise PNGs before committing instead
        }
    }
}

kotlin { jvmToolchain(17) }

dependencyLocking { lockAllConfigurations() }
```

```bash
# Lock dependency versions and record checksums (commit both outputs)
./gradlew :app:dependencies --write-locks
./gradlew --write-verification-metadata sha256 help

# Pin the wrapper with its checksum
./gradlew wrapper --gradle-version <x.y> --gradle-distribution-sha256-sum <sha256-from-gradle.org>

# Build with the commit time
export SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
./gradlew --no-daemon clean bundleRelease assembleRelease
```

Also:

- Build releases in a container image referenced by digest, and publish the Dockerfile.
- On Gradle before 9, for any archive tasks of your own, set `isPreserveFileTimestamps = false` and `isReproducibleFileOrder = true` on `AbstractArchiveTask`.
- For native code, pass `-ffile-prefix-map=${CMAKE_SOURCE_DIR}=.` (CMake) or the equivalent, and strip debug info from shipped libraries. Keep the unstripped ones for crash symbolication.
- Keep AGP's `vcsInfo` on and build from clean tags. It records the commit inside the APK.
- Sign with `apksigner` and keep the signing step separate from the build, so the unsigned artefact can be compared.
- Record obfuscator or protection tool versions and seeds per release. Prefer tools that run inside the Gradle build and are deterministic.
- Run GT-PRIV-0075-1 in CI on every release: two builds on different runners, with a hash comparison as a release gate.

### iOS build settings

- Commit `Package.resolved`, `Podfile.lock` and other lockfiles. Build with `-disableAutomaticPackageResolution` and `pod install --deployment`.
- Pin Xcode **and** macOS for release builds, for example with a dedicated CI image. Record both in the release notes.
- Never derive `CFBundleVersion` or any embedded value from the wall clock. Use the CI build number or commit count and record the mapping.
- Remove `__DATE__`/`__TIME__` (clang's `-Wdate-time` warns about them). Avoid run-script phases that write dates, host names or user names into the bundle.
- Use prefix-map compiler flags where your Xcode version supports them, to keep build paths out of binaries, and build at a fixed path in CI.
- Set `ZERO_AR_DATE=1` when you build static libraries, so `ar` writes no modification times.
- Archive every uploaded `.xcarchive` (with dSYMs) per version. It is the reference for stage 2 of GT-PRIV-0075-3.

### Publishing releases that others can verify

- Tag every release (signed tags), and publish the commit, the toolchain versions and the SHA-256 of each artefact (unsigned APK or AAB, signed APK, IPA) in the release notes.
- Write the verification guide the way Signal's is written: exact commands, the container, which differences are expected and why, and a comparison script with a short, justified exclusion list.
- Produce signed provenance in CI (SLSA, for example GitHub artifact attestations), so verifiers know what to reproduce and can check which pipeline built it.
- On Android, offer a developer-signed APK outside Play that is reproducible (website or F-Droid with developer signatures). For Play, use code transparency and leave automatic protection off if verifiability is a stated goal.
- On iOS, state honestly what can and cannot be verified, and offer auditors stages 1 and 2 of GT-PRIV-0075-3 as a standing procedure.

## Rating findings

The series-wide rule: privacy findings are rated by what personal data is exposed or processed beyond what is necessary, declared or consented; how sensitive it is; scale and reversibility; and whether the finding contradicts the app's own declarations or store policy. Regulatory risk is assessed by the client's legal team, not by severity scores.

Non-reproducibility does not expose data by itself. It removes the ability to **prove** that no exposure was added between source and binary. Ratings therefore depend mostly on what the app claims and who relies on verification:

| Rating | Conditions |
|---|---|
| **High** | A distributed binary contains code that is not in the claimed source and is not explained by non-determinism or a documented store step (GT-PRIV-0075-2 or GT-PRIV-0075-3 stage 2/3 failing while stage 1 or GT-PRIV-0075-1 passes). Rate and handle it as [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/); this weakness is the context, not the finding. |
| **Medium** | The app publicly claims reproducible or verifiable builds, or is open source and markets privacy guarantees (end-to-end encryption, no tracking, on-device processing) on that basis, and its releases cannot be reproduced. Or the toolchain and dependencies are so unpinned that the team cannot rebuild its own last release (GT-PRIV-0075-1 failing with different resolved dependencies), for an app handling sensitive data. |
| **Low** | Builds are non-deterministic for fixable reasons (timestamps, paths, PNG crunching, baseline profiles) in an open-source or audited app without an explicit reproducibility claim; missing verification instructions or provenance where verifiability is expected; Play automatic protection on in an app whose transparency rests on its source. |
| **Info** | Closed-source apps without a verifiability claim, reported as a recommendation (internal reproducibility, provenance); iOS limits that no developer can remove (FairPlay, Apple re-signing, thinning); stage 3 not testable; documented and expected store metadata differences. |

Raise a level for apps whose users face serious harm if the code is tampered with: messengers and VPNs used by at-risk groups, health and contact-tracing apps, wallets, apps processing special-category data, and apps aimed at children. Lower a level when an independent party (for example F-Droid's verification) already reproduces the same releases through another channel.

In the report give: the version and channel tested; the commit and toolchain used for the rebuild; for each test the hashes and the list of differences with their classification; the specific causes with file and line; what was **not** verified (signatures, thinned assets, other device configurations, iOS stages not run); and the concrete changes from [Secure implementation](#secure-implementation) that would fix it.

## References

- OWASP MASWE: [MASWE-0075: Non-Reproducible Builds](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0075/); related [MASWE-0048](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0048/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PRIVACY-3](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0054 Obtaining and Extracting Apps (iOS)](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/), [MASTG-TECH-0116 Obtaining Information about the APK Signature](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0116/) (CC BY-SA 4.0)
- OWASP MASTG tools: [MASTG-TOOL-0123 apksigner](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/), [MASTG-TOOL-0011 Apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [MASTG-TOOL-0018 jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [MASTG-TOOL-0050 Frida-ios-dump](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0050/), [MASTG-TOOL-0060 otool](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0060/), [MASTG-TOOL-0114 codesign](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0114/) (CC BY-SA 4.0)
- Reproducible Builds: [Definition](https://reproducible-builds.org/docs/definition/), [Documentation](https://reproducible-builds.org/docs/), [SOURCE_DATE_EPOCH specification](https://reproducible-builds.org/docs/source-date-epoch/), [diffoscope](https://diffoscope.org/), [reprotest](https://salsa.debian.org/reproducible-builds/reprotest)
- F-Droid: [Reproducible Builds](https://f-droid.org/docs/Reproducible_Builds/), [Verification Server](https://f-droid.org/docs/Verification_Server/); [apksigcopier](https://github.com/obfusk/apksigcopier)
- Signal: [Reproducible builds for Signal-Android](https://github.com/signalapp/Signal-Android/blob/main/reproducible-builds/README.md) (referenced by OWASP)
- SLSA: [slsa.dev](https://slsa.dev/); GitHub: [Artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
- Android: [APK signature schemes](https://source.android.com/docs/security/features/apksigning), [apksigner](https://developer.android.com/tools/apksigner), [bundletool](https://developer.android.com/tools/bundletool), [Code transparency for app bundles](https://developer.android.com/guide/app-bundle/code-transparency), [Play App Signing](https://support.google.com/googleplay/android-developer/answer/9842756), [Automatic protection](https://support.google.com/googleplay/android-developer/answer/13857328), [Gradle dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html), [Gradle dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html), [Gradle 9.0 release notes](https://docs.gradle.org/9.0.0/release-notes.html)
- Apple: [Xcode 14 release notes (bitcode deprecation)](https://developer.apple.com/documentation/xcode-release-notes/xcode-14-release-notes), [App Thinning](https://developer.apple.com/documentation/xcode/reducing-your-app-s-size)
- Legal context (not legal advice): [GDPR Art. 25](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- CWE: [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html), [CWE-494](https://cwe.mitre.org/data/definitions/494.html)
- Sibling notes: [PRIVACY hub](/mobile/masvs-privacy-privacy-testing-guide/), [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/); CODE: [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/), [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/), [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/), [App signing](/mobile/mastg-know-0003-app-signing/); RESILIENCE: [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
