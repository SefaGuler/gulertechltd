---
title: "Third-Party Libraries in Android Apps (MASTG-KNOW-0004)"
date: 2026-09-02
summary: "Identifying bundled dependencies in an APK, mapping them to known CVEs, and the licence exposure most reports leave out."
refs: [MASTG-KNOW-0004, MASVS-CODE-3, CWE-1035, CWE-937]
tags: [android, sca, dependencies, cve, supply-chain, masvs-code]
---

## What it is

Android apps ship a large amount of code the developer did not write. MASTG splits third-party libraries into two categories, and the distinction matters when you triage:

- **Libraries that should not be in the production build** — test and build-time dependencies such as `Mockito`, `JavaAssist`, JUnit, debug interceptors. Their presence in a release APK indicates a build-configuration problem and sometimes exposes test endpoints or fixtures.
- **Libraries packed into the production app** — `OkHttp`, `Retrofit`, `Glide`, `Gson`, Firebase SDKs, analytics and advertising SDKs. These execute in the app's process with the app's permissions.

Three distinct risks follow from this:

**Known vulnerabilities.** A library flaw becomes the app's flaw. The canonical example in MASTG is OkHttp before 2.7.5, where TLS chain pollution allowed certificate-pinning bypass — the app's pinning implementation was correct, and the library defeated it.

**Unmaintained code.** A library that is no longer maintained accumulates unreported and unfixed issues. Absence of CVEs for a dormant project is not evidence of safety.

**Licence exposure.** A copyleft licence such as LGPL-2.1 obliges the publisher to provide source access to users who request it, and to permit redistribution with modifications. For a commercial app this is a genuine intellectual-property exposure, and it is one that security reports routinely omit even though it is discovered by exactly the same inventory step.

The same applies one level down: JavaScript libraries loaded inside a `WebView`, and plugins in cross-platform frameworks such as Cordova and React Native, are third-party dependencies with the same three risks.

## How to test

### 1. Build an inventory

Start from the decompiled package structure — bundled libraries keep their package names:

```bash
apktool d target.apk -o out/
ls out/smali*/ | head -50
# or from jadx output
jadx -d jadx-out/ target.apk
find jadx-out/sources -maxdepth 3 -type d | sed 's|jadx-out/sources/||' | sort -u | head -80
```

Look for recognisable roots: `okhttp3`, `retrofit2`, `com/google/gson`, `com/squareup`, `io/reactivex`, `com/facebook`, `org/apache`, `com/bumptech/glide`.

Native libraries are a separate inventory:

```bash
unzip -l target.apk | grep '\.so$'
```

### 2. Pin down versions

Version identification is the step most assessments do badly, and an unversioned inventory cannot be mapped to CVEs. Sources, in order of reliability:

```bash
# a. dependency metadata Gradle embeds in recent builds
unzip -p target.apk META-INF/com/android/build/gradle/app-metadata.properties
unzip -l target.apk | grep -i "META-INF.*\.version"
unzip -p target.apk 'META-INF/*.version'

# b. per-library version constants
grep -rn "VERSION\s*=\s*\"" jadx-out/sources/okhttp3/ | head
grep -rn "userAgent\|USER_AGENT\|SDK_VERSION" jadx-out/sources/ | head -20

# c. Play Services / Firebase manifest values
grep -rn "com.google.android.gms.version" out/res/values/*.xml
```

Automated tooling does this better than manual grep. `apkid` fingerprints packers and compilers, and dedicated SCA tools match class signatures:

```bash
apkid target.apk
# LibScout / LibRadar / OWASP dependency-check against the app's build files where available
```

If you have access to the build (a white-box engagement), skip all of this and read the resolved dependency graph directly:

```bash
./gradlew :app:dependencies --configuration releaseRuntimeClasspath
./gradlew :app:dependencyCheckAnalyze     # OWASP dependency-check plugin
```

### 3. Map to known vulnerabilities

With `library:version` pairs, query the OSV database — it covers Maven coordinates and is the most practical source for Android:

```bash
curl -s https://api.osv.dev/v1/query -d '{
  "package": {"name": "com.squareup.okhttp3:okhttp", "ecosystem": "Maven"},
  "version": "3.12.0"
}' | jq '.vulns[] | {id, summary, severity}'
```

Batch the whole inventory through `/v1/querybatch` rather than one call per library. Cross-check anything that looks impactful against the library's own release notes — OSV ranges are occasionally broader than reality, and a finding you cannot substantiate will be pushed back on.

### 4. Determine reachability before you report severity

A vulnerable version present in the APK is not automatically an exploitable vulnerability in the app. Establish whether the affected code path is reachable:

```bash
# is the vulnerable class actually referenced by app code?
grep -rn "VulnerableClassName" jadx-out/sources/com/target/
```

Then confirm behaviourally where possible — for a TLS-related library flaw, test whether pinning actually fails; for a deserialization flaw, check whether attacker-controlled data reaches the sink. Report reachable issues at full severity and non-reachable ones as hygiene findings, and say which is which. This distinction is what separates a useful SCA section from a raw scanner dump.

### 5. Flag test and debug libraries in the release build

```bash
find jadx-out/sources -type d \( -name mockito -o -name junit -o -name robolectric -o -name javassist \) 
grep -rn "LoggingInterceptor\|setLevel(HttpLoggingInterceptor.Level.BODY)\|Timber.plant(.*DebugTree" jadx-out/sources/
```

An `HttpLoggingInterceptor` at `BODY` level in a release build writes full request and response bodies — including credentials and tokens — to logcat, readable by any app holding `READ_LOGS` on older platforms and by anyone with ADB access.

### 6. Cover WebView and cross-platform layers

```bash
unzip -l target.apk | grep -E "assets/.*\.js|www/|index.android.bundle"
unzip -p target.apk assets/index.android.bundle | grep -oE '"version":"[0-9.]+"' | sort -u
```

For React Native, extract the JS bundle and inspect it; for Cordova, review `assets/www/` and its plugin list. Retire.js signatures work against extracted bundles.

### 7. Record licences

```bash
unzip -l target.apk | grep -iE "LICENSE|NOTICE"
grep -rn "GPL\|LGPL\|AGPL\|MPL" out/res/raw/ out/assets/ 2>/dev/null | head
```

Note any copyleft licence in the report as a business-risk observation, separate from the security findings.

## Impact

Impact is inherited from whichever library is vulnerable, so it spans the full range. Realistic examples from Android assessments:

- A TLS-affecting library flaw (the OkHttp < 2.7.5 case) defeats certificate pinning, enabling interception of traffic the app believes is protected — typically **High**.
- A vulnerable image or media parsing library reachable from remote content gives a memory-corruption path in native code — **High** to **Critical** depending on exploitability.
- A deserialization flaw in a bundled utility library, reachable from IPC or a deep link, gives code execution in the app's context — **High**.
- An analytics or advertising SDK that over-collects gives a privacy finding and, where the data includes identifiers or location, a regulatory one.
- Test libraries left in the release build: **Low** on their own, but they signal build-pipeline weakness and often come with debug logging.

For CVSS, score the composition of app and library rather than the library's own published vector: an RCE in a parser the app never invokes with untrusted input does not merit the library's published score, and saying so explicitly makes the report defensible.

## Remediation

- Maintain an SBOM for the app and generate it as part of the build (CycloneDX Gradle plugin).
- Run dependency scanning in CI and fail the build on known-vulnerable versions of libraries in the release configuration.
- Keep test and debug dependencies out of release variants using `testImplementation` and `debugImplementation` rather than `implementation`.
- Strip logging interceptors from release builds and verify their absence in the built APK.
- Replace unmaintained libraries; treat "no recent releases" as a risk signal rather than stability.
- Track licence obligations for every bundled dependency and review them before release.

## References

- OWASP MASTG — [MASTG-KNOW-0004: Third-Party Libraries](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0004/) (CC BY-SA 4.0)
- [OSV — Open Source Vulnerability database and API](https://osv.dev/)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [CycloneDX Gradle plugin](https://github.com/CycloneDX/cyclonedx-gradle-plugin)
