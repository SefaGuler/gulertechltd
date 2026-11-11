---
layout: page
title: Bug Bounty Writeups
kicker: Mobile · OWASP MAS reading list
permalink: /bug-bounty-writeups/
summary: "50 public mobile bug bounty and disclosure writeups (Android and iOS), each mapped to an OWASP MASVS category and MASWE weakness, with what to check on your own tests."
---

50 publicly readable writeups of real vulnerabilities in real Android and iOS apps, grouped by [OWASP MASVS](https://mas.owasp.org/MASVS/) category. Each one is mapped to the MASWE weakness it demonstrates and links to the matching note on this site, so you can go from "how it was found in the wild" to "how to test for it".

Every link goes to the original author. The summaries and "what to check" lines are ours, written so you can decide in a few seconds whether a writeup is worth reading in full.

<div class="callout tip" markdown="1">
**How the list was built.**
- **Real apps only.** Every entry is a vulnerability in a named mobile app or SDK. Web-only bugs that happen to be reached from an app are left out.
- **Free to read.** The 26 HackerOne reports are publicly disclosed, and the rest are researcher, vendor or CERT write-ups.
- **Links checked.** Every link was opened and checked against its summary on 2026-11-11.
- **Bounty amounts** appear only where the programme made them public; "—" means not public, not "unpaid".
- **"Year"** is the year of public disclosure or publication.
</div>

**Split:** 37 Android · 7 iOS · 6 both platforms. Most of these issues have been fixed; where a vendor declined to fix, the entry says so.

| MASVS category | Writeups | Weaknesses covered | Testing guide |
|---|---|---|---|
| [MASVS-STORAGE](#storage) | 7 | 0001, 0002, 0004 | [Storage guide](/mobile/masvs-storage-1-secure-storage-guide/) |
| [MASVS-CRYPTO](#crypto) | 4 | 0003, 0007, 0012 | [Cryptography guide](/mobile/masvs-crypto-cryptography-guide/) |
| [MASVS-AUTH](#auth) | 5 | 0020, 0022 | [Authentication guide](/mobile/masvs-auth-authentication-guide/) |
| [MASVS-NETWORK](#network) | 5 | 0026, 0027, 0028 | [Network guide](/mobile/masvs-network-secure-communication-guide/) |
| [MASVS-PLATFORM](#platform) | 16 | 0029, 0030, 0032, 0033, 0034, 0035, 0038, 0039 | [Platform Interaction guide](/mobile/masvs-platform-platform-interaction-guide/) |
| [MASVS-CODE](#code) | 7 | 0044, 0049, 0050 | [Code Quality guide](/mobile/masvs-code-code-quality-guide/) |
| [MASVS-RESILIENCE](#resilience) | 3 | 0061, 0063 | [Resilience guide](/mobile/masvs-resilience-resilience-testing-guide/) |
| [MASVS-PRIVACY](#privacy) | 3 | 0070, 0077, 0078 | [Privacy guide](/mobile/masvs-privacy-privacy-testing-guide/) |

## MASVS-STORAGE: Storage {#storage}

Credentials and tokens in plaintext files, logs and backups; secrets shipped inside the app package. Full methodology: [Storage guide](/mobile/masvs-storage-1-secure-storage-guide/).

### 01. [Grammarly Keyboard for Android &lt;4.1 leaks user input through logs (except for sensitive input fields)](https://hackerone.com/reports/462416)

**Grammarly Keyboard** (Android) · homelander · HackerOne: Grammarly · 2019 · Bounty: —  
**Weakness:** [MASWE-0002 — Sensitive Data Stored Unencrypted Outside of Private Storage](/mobile/maswe-0002-sensitive-data-unencrypted-outside-private-storage/)

On older Android versions the keyboard wrote what users typed (apart from fields flagged sensitive) to the system log, where apps able to read logs on those versions could collect it — effectively a keylogger.

**What to check:** Watch logcat while typing and logging in, and confirm release builds log no user input, tokens or PII.

### 02. [Account hijacking possible through ADB backup feature](https://hackerone.com/reports/12617)

**Faceless** (Android) · trotmaster · HackerOne: Faceless · 2014 · Bounty: —  
**Weakness:** [MASWE-0002 — Sensitive Data Stored Unencrypted Outside of Private Storage](/mobile/maswe-0002-sensitive-data-unencrypted-outside-private-storage/)

android:allowBackup was left at its default, so anyone with the unlocked phone could pull the sandbox over adb backup — including a preferences XML holding the username and password — and restore it elsewhere to clone the account.

**What to check:** Check allowBackup / dataExtractionRules, run a backup, and look for credentials or tokens in the extracted data.

### 03. [Insecure Data Storage in Vine Android App](https://hackerone.com/reports/44727)

**Vine** (Android) · avicoder_ · HackerOne: X (Twitter) · 2015 · Bounty: $140  
**Weakness:** [MASWE-0001 — Sensitive Data Stored Unencrypted in Private Storage](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/)

The Vine app kept the user's username and password unencrypted in a WebView SQLite database in its private data directory, so any route into the sandbox (root, backup or a file-theft bug) exposed the credentials directly.

**What to check:** Inspect every database under /data/data/<pkg>, including WebView-generated ones, for plaintext credentials.

### 04. [Bug in iOS application which could lead to unauthorised access](https://hackerone.com/reports/7036)

**IRCCloud** (iOS) · uname · HackerOne: IRCCloud · 2014 · Bounty: —  
**Weakness:** [MASWE-0001 — Sensitive Data Stored Unencrypted in Private Storage](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/)

The iOS app stored its session identifier in a Preferences plist without NSFileProtectionComplete, so it could be read from a passcode-locked phone without a jailbreak and reused to take over the account.

**What to check:** Check where session tokens live (plist/NSUserDefaults vs Keychain) and which data-protection class each sensitive file uses.

### 05. [Attackers Can Manipulate Your WhatsApp and Telegram Media Files (Media File Jacking)](https://www.security.com/expert-perspectives/symantec-mobile-threat-defense-attackers-can-manipulate-your-whatsapp-and-telegram-media)

**WhatsApp, Telegram** (Android) · Yair Amit, Alon Gat (Symantec) · vendor disclosure · 2019 · Bounty: —  
**Weakness:** [MASWE-0002 — Sensitive Data Stored Unencrypted Outside of Private Storage](/mobile/maswe-0002-sensitive-data-unencrypted-outside-private-storage/)

WhatsApp by default, and Telegram with Save to Gallery on, wrote received media to shared external storage and later reloaded it, so a malicious app with storage permission could swap files in between — altering invoice bank details or replacing voice notes.

**What to check:** Check whether the app writes trusted files to shared storage and later reads them back without an integrity check.

### 06. [Disclosure of all uploads to Cloudinary via hardcoded api secret in Android app](https://hackerone.com/reports/351555)

**Reverb** (Android) · Sergey Toshin (bagipro) · HackerOne: Reverb.com · 2018 · Bounty: —  
**Weakness:** [MASWE-0004 — Sensitive Data Hardcoded in the App Package](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/)

The app shipped the full Cloudinary connection string including the API secret, although only the cloud name belongs on the client; anyone who decompiled it could list, replace or delete all of Reverb's tens of millions of hosted files.

**What to check:** Look for third-party SDK secrets (not just public IDs) in decompiled code and resources, and test what each key can actually do.

### 07. [Hardcoded credentials in Android App](https://hackerone.com/reports/246995)

**Zomato** (Android) · gerben_javado · HackerOne: Zomato · 2017 · Bounty: $500  
**Weakness:** [MASWE-0004 — Sensitive Data Hardcoded in the App Package](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/)

HTTP basic-auth credentials for a development environment were hardcoded in the app; with subdomain enumeration they opened a clone of the main admin panel, which Zomato took down and rotated within minutes.

**What to check:** Search the APK for hardcoded basic-auth or dev credentials and find which hosts, including obscure subdomains, accept them.


## MASVS-CRYPTO: Cryptography {#crypto}

Predictable randomness, home-grown encryption schemes and keys hardcoded in the binary. Full methodology: [Cryptography guide](/mobile/masvs-crypto-cryptography-guide/).

### 08. [Grammarly Keyboard for Android "Authorization Code with PKCE" flow implementation vulnerability that allows account takeover](https://hackerone.com/reports/824931)

**Grammarly Keyboard** (Android) · tomtenisse · HackerOne: Grammarly · 2020 · Bounty: —  
**Weakness:** [MASWE-0012 — Improper Random Number Generation](/mobile/maswe-0012-improper-random-number-generation/)

The PKCE code verifier came from a non-cryptographic PRNG, so a malicious app on the same device could predict it, redeem the authorization code and obtain the user's session; fixed by switching to SecureRandom.

**What to check:** Check that PKCE verifiers, nonces and tokens come from SecureRandom/SecRandomCopyBytes, never java.util.Random or Math.random.

### 09. [The initial E2EE password generated by Rocket.Chat mobile can be recovered in a practical timescale](https://hackerone.com/reports/2546437)

**Rocket.Chat (React Native)** (Android & iOS) · Hayato Kimura, Ryoma Ito, Kazuhiko Minematsu, Takanori Isobe · HackerOne: Rocket.Chat · 2024 · Bounty: —  
**Weakness:** [MASWE-0012 — Improper Random Number Generation](/mobile/maswe-0012-improper-random-number-generation/)

Before 4.5.1 the mobile app generated each user's initial end-to-end encryption password with a biased process that cut its entropy enough for a well-resourced attacker to brute-force it and reach the E2EE keys.

**What to check:** Check password/key generation uses a CSPRNG, uniform sampling without modulo bias, and enough real entropy.

### 10. ["Please Do Not Make It Public": Vulnerabilities in Sogou Keyboard Encryption Expose Keypresses to Network Eavesdropping](https://citizenlab.ca/2023/08/vulnerabilities-in-sogou-keyboard-encryption/)

**Sogou Input Method** (Android & iOS) · Jeffrey Knockel, Zoë Reichert, Mona Wang (Citizen Lab) · independent research · 2023 · Bounty: —  
**Weakness:** [MASWE-0007 — Improper Encryption](/mobile/maswe-0007-improper-encryption/)

Sogou's keyboard sent keystrokes over HTTP protected only by a home-grown scheme open to a CBC padding-oracle attack, so a network eavesdropper could decrypt what users typed; on Android it also leaked half the key.

**What to check:** Flag custom encryption layered over plain HTTP; expect TLS plus authenticated encryption (e.g. AES-GCM), not unauthenticated CBC.

### 11. [R7-2017-02: Hyundai Blue Link Potential Info Disclosure (FIXED)](https://www.rapid7.com/blog/post/2017/04/25/r7-2017-02-hyundai-blue-link-potential-info-disclosure-fixed)

**Hyundai Blue Link** (Android & iOS) · Will Hatzer, Arjun Kumar (via Rapid7) · vendor disclosure · 2017 · Bounty: —  
**Weakness:** [MASWE-0003 — Cryptographic Keys Stored Outside of Platform Keystore](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/)

Versions 3.9.4–3.9.5 uploaded logs containing the owner's username, password, PIN and GPS history, encrypted with a symmetric key hardcoded in the app and sent over HTTP — anyone intercepting them could decrypt them.

**What to check:** Search the binary for embedded symmetric keys and treat anything 'encrypted' with them as plaintext.


## MASVS-AUTH: Authentication {#auth}

App locks, PINs and biometric prompts that a second entry point or a hooked callback can walk around. Full methodology: [Authentication guide](/mobile/masvs-auth-authentication-guide/).

### 12. [Extremely simple way to bypass Nextcloud-Client PIN/Fingerprint lock](https://hackerone.com/reports/331489)

**Nextcloud Files** (Android) · volker_weissmann · HackerOne: Nextcloud · 2019 · Bounty: —  
**Weakness:** [MASWE-0020 — Local Authentication Can Be Bypassed](/mobile/maswe-0020-local-authentication-bypass/)

The PIN/fingerprint lock only guarded the app's own UI, while the app also exposed its files through the system Documents provider, so anyone holding the unlocked phone could browse, read and modify Nextcloud files in the Android file manager without passing the lock.

**What to check:** Check whether data behind an app lock is reachable another way: DocumentsProvider, share targets, widgets or cached files in shared storage.

### 13. [Bypass of biometrics security functionality is possible in Android application (com.shopify.mobile)](https://hackerone.com/reports/637194)

**Shopify** (Android) · tiago-danin · HackerOne: Shopify · 2019 · Bounty: $500  
**Weakness:** [MASWE-0020 — Local Authentication Can Be Bypassed](/mobile/maswe-0020-local-authentication-bypass/)

Fingerprint sign-in was not enforced on entry points: while the app was running, a deep link sent to its exported DeepLinkActivity (from a browser, adb or another app) opened admin screens without the fingerprint prompt.

**What to check:** Launch every exported or deep-link entry point while the lock screen is showing and confirm each one enforces the lock.

### 14. [Bypassing Android Biometric Authentication](https://sec-consult.com/blog/detail/bypassing-android-biometric-authentication/)

**Bitwarden, Dashlane, Signal** (Android) · Leonard Eschenbaum (SEC Consult Vulnerability Lab) · vendor disclosure · 2023 · Bounty: —  
**Weakness:** [MASWE-0020 — Local Authentication Can Be Bypassed](/mobile/maswe-0020-local-authentication-bypass/)

Biometric locks in Bitwarden, Dashlane and Signal could be bypassed with a hooked BiometricPrompt on a rooted device because two used no CryptoObject at all and the third's key lacked the recommended properties.

**What to check:** Confirm the biometric key requires user authentication, is actually used in the unlock path, and that the decrypted data is needed to proceed.

### 15. [Bypass for forced re-authentication upon biometrics change](https://hackerone.com/reports/1929915)

**Bitwarden** (Android) · rink_ · HackerOne: Bitwarden · 2023 · Bounty: —  
**Weakness:** [MASWE-0022 — Crypto Keys Not Invalidated on New Biometric Enrollment](/mobile/maswe-0022-keys-not-invalidated-on-biometric-enrollment/)

After a new fingerprint was enrolled Bitwarden should have demanded the master password, but adding a second account, unlocking it and switching back unlocked the victim's vault with the newly enrolled biometric.

**What to check:** Enrol a new biometric, then try every path to the vault (account switching, multiple vaults, autofill) to confirm re-authentication holds everywhere.

### 16. [Full Passcode bypass on Nextcloud App iOS (CVE-2023-28647)](https://hackerone.com/reports/1847368)

**Nextcloud iOS** (iOS) · ctulhu · HackerOne: Nextcloud · 2023 · Bounty: —  
**Weakness:** [MASWE-0020 — Local Authentication Can Be Bypassed](/mobile/maswe-0020-local-authentication-bypass/)

Anyone holding an unlocked iPhone could enable the app's Files-app integration and use it to reach Nextcloud data without the app passcode; fixed in 4.7.0.

**What to check:** Check that the app lock also covers extensions (File Provider, Share, Widgets) and that lock settings can't be changed without unlocking first.


## MASVS-NETWORK: Network {#network}

Missing certificate validation, pinning without hostname checks, and cleartext downloads that end in code execution. Full methodology: [Network guide](/mobile/masvs-network-secure-communication-guide/).

### 17. [Twitter iOS fails to validate server certificate and sends oauth token](https://hackerone.com/reports/168538)

**Twitter** (iOS) · floyd · HackerOne: X (Twitter) · 2016 · Bounty: $2,100  
**Weakness:** [MASWE-0027 — Insecure Certificate Validation](/mobile/maswe-0027-insecure-certificate-validation/)

Twitter for iOS 6.62 did not validate the TLS certificate for api.twitter.com, so on a stock iPhone with no extra CA a transparent proxy on a rogue Wi-Fi network could read API traffic including OAuth credentials.

**What to check:** Proxy the app with an untrusted CA on a clean device; any decrypted traffic means certificate validation is broken.

### 18. [Spinner: Semi-Automatic Detection of Pinning without Hostname Verification](https://acsac.org/2017/program-files/s206.html)

**HSBC, Bank of America, TunnelBear and others** (Android & iOS) · Chris McMahon Stone, Tom Chothia, Flavio D. Garcia (University of Birmingham) · independent research (coordinated disclosure) · 2017 · Bounty: —  
**Weakness:** [MASWE-0028 — Insecure Identity Pinning](/mobile/maswe-0028-insecure-identity-pinning/)

Several banking and VPN apps pinned an intermediate or root CA but skipped hostname verification, so anyone with any valid certificate from that CA could intercept traffic; nine of 400 security-sensitive apps tested were vulnerable.

**What to check:** When an app pins a CA rather than a leaf, test with a valid certificate for a different hostname from the same chain to confirm the hostname is still checked.

### 19. [Writeup – Samsung Galaxy Apps Store RCE via MITM (CVE-2018-20135)](https://adyta.pt/communication/writeup-samsung-galaxy-apps-store-rce-via-mitm/)

**Samsung Galaxy Apps Store** (Android) · André Baptista, Luís Maia, Rolando Martins · Samsung Mobile Security Rewards · 2019 · Bounty: —  
**Weakness:** [MASWE-0026 — Cleartext Traffic](/mobile/maswe-0026-cleartext-network-traffic/)

The store fetched its country API URL over plain HTTP, letting a network attacker point it at a fake server that controlled APK download links; because an empty signature was accepted, a backdoored APK installed silently with elevated privileges.

**What to check:** Check bootstrap/config requests use HTTPS and downloaded packages are signature-checked so missing or empty signatures fail closed.

### 20. [TikTok Vulnerability Enables Hackers to Show Users Fake Videos](https://mysk.blog/2020/04/13/tiktok-vulnerability-enables-hackers-to-show-users-fake-videos/)

**TikTok** (Android & iOS) · Talal Haj Bakry and Tommy Mysk · independent research · 2020 · Bounty: —  
**Weakness:** [MASWE-0026 — Cleartext Traffic](/mobile/maswe-0026-cleartext-network-traffic/)

TikTok loaded videos, profile photos and thumbnails from its CDN over plain HTTP; by redirecting one CDN hostname the researchers showed forged videos on verified accounts such as the WHO.

**What to check:** Capture all traffic including media and CDN requests and flag any cleartext HTTP — integrity matters as much as confidentiality.

### 21. [Vulnerability in Xiaomi Pre-installed Security App](https://research.checkpoint.com/2019/vulnerability-in-xiaomi-pre-installed-security-app/)

**Xiaomi Guard Provider** (Android) · Slava Makkaveev (Check Point Research) · vendor disclosure · 2019 · Bounty: —  
**Weakness:** [MASWE-0026 — Cleartext Traffic](/mobile/maswe-0026-cleartext-network-traffic/)

The preinstalled security app downloaded antivirus SDK updates and configuration over HTTP; an attacker on the same Wi-Fi could tamper with them and, with a path traversal overwriting a prior update, get malicious code loaded.

**What to check:** Check every update, signature database and config download uses TLS and that downloaded code is re-verified before loading.


## MASVS-PLATFORM: Platform Interaction {#platform}

Exported components, intent redirection, deep links, WebView bridges, screenshots, overlays and the clipboard — the largest group, because it is where most mobile bounties are paid. Full methodology: [Platform Interaction guide](/mobile/masvs-platform-platform-interaction-guide/).

### 22. [Access of Android protected components via embedded intent](https://hackerone.com/reports/200427)

**Slack** (Android) · Sergey Toshin (bagipro) · HackerOne: Slack · 2017 · Bounty: —  
**Weakness:** [MASWE-0032 — Insecure Intents](/mobile/maswe-0032-insecure-intents/)

Slack's exported HomeActivity pulled a nested Intent out of an extra and handed it to startActivity() unchecked, letting any installed app reach Slack's non-exported activities and drive the app in ways it never intended.

**What to check:** Check exported components for Intents taken from extras (getParcelableExtra) and relaunched without validating the target component.

### 23. [Possible to steal any protected files on Android](https://hackerone.com/reports/377107)

**ownCloud** (Android) · shell_c0de · HackerOne: ownCloud · 2021 · Bounty: $750  
**Weakness:** [MASWE-0032 — Insecure Intents](/mobile/maswe-0032-insecure-intents/)

ownCloud's exported share-receiving activity blocked file URIs under /data/data/ but not the equivalent /data/user/0/ path, so a malicious app could make it upload ownCloud's own private databases to the server.

**What to check:** For share targets that accept file:// or content:// URIs, test whether the path filter can be bypassed with alias paths, symlinks or canonicalisation tricks.

### 24. [Two weeks of securing Samsung devices: Part 1](https://oversecured.com/blog/two-weeks-of-securing-samsung-devices-part-1)

**Samsung preinstalled apps (Knox Core, Managed Provisioning, Secure Folder, Settings, TelephonyUI, PhotoTable)** (Android) · Oversecured (Sergey Toshin) · vendor disclosure (Samsung Mobile Security Rewards) · 2021 · Bounty: ~$20,000 total across 7 CVEs  
**Weakness:** [MASWE-0032 — Insecure Intents](/mobile/maswe-0032-insecure-intents/)

Several privileged Samsung system apps exposed exported services, activities and receivers, intent redirection and an over-broad FileProvider, letting third-party apps install apps, grant Device Admin, and read or overwrite files as system UIDs.

**What to check:** On OEM/system apps, treat every exported component and FileProvider path config as a privilege boundary.

### 25. [Intent redirection vulnerability in third-party SDK exposed millions of Android wallets to potential risk](https://www.microsoft.com/en-us/security/blog/2026/04/09/intent-redirection-vulnerability-third-party-sdk-android/)

**Apps embedding EngageLab EngageSDK (mainly crypto wallets)** (Android) · Microsoft Threat Intelligence · vendor disclosure (Microsoft MSVR coordinated disclosure) · 2026 · Bounty: —  
**Weakness:** [MASWE-0032 — Insecure Intents](/mobile/maswe-0032-insecure-intents/)

EngageSDK 4.5.4 added an exported activity that parsed an attacker-supplied URI into an intent and launched it, letting malicious apps reach the host app's non-exported providers and obtain persistent read/write grants to private data across apps with 50M+ installs.

**What to check:** Inspect the merged manifest for exported activities added by SDKs that parse intent URIs and relaunch them.

### 26. [1 click Account takeover via deeplink in \[com.kayak.android\]](https://hackerone.com/reports/1667998)

**KAYAK** (Android) · Carlos Bello (Fluid Attacks) · HackerOne: KAYAK · 2023 · Bounty: —  
**Weakness:** [MASWE-0029 — Insecure Deep Links](/mobile/maswe-0029-insecure-deep-links/)

An exported external-authentication activity reachable by deep link appended the user's session cookie to an attacker-controlled redirect URL, so one click leaked the session and enabled account takeover (CVSS 9.3).

**What to check:** Check whether any deep-link handler attaches session tokens or cookies to a URL taken from the link itself.

### 27. [Account takeover intercepting magic link for Arrive app](https://hackerone.com/reports/855618)

**Arrive (Shopify)** (Android) · nsl182 · HackerOne: Shopify · 2020 · Bounty: —  
**Weakness:** [MASWE-0029 — Insecure Deep Links](/mobile/maswe-0029-insecure-deep-links/)

Arrive's login magic link used a Branch.io app.link host that was not a verified Android App Link (empty assetlinks.json), so a malicious app could register the same host, capture the login token and take over the account.

**What to check:** Check that every domain carrying login or magic-link tokens is a verified App Link (autoVerify + valid assetlinks.json) or Universal Link.

### 28. [Periscope android app deeplink leads to CSRF in follow action](https://hackerone.com/reports/583987)

**Periscope** (Android) · kunal94 · HackerOne: X (Twitter) · 2020 · Bounty: $1,540  
**Weakness:** [MASWE-0029 — Insecure Deep Links](/mobile/maswe-0029-insecure-deep-links/)

An internal custom-scheme deep link made the logged-in user follow any account immediately, without the confirmation step the website enforces, so a link on any web page could force follows.

**What to check:** Check whether deep links trigger state-changing actions without user confirmation.

### 29. [Vulnerability in TikTok Android app could lead to one-click account hijacking (CVE-2022-28799)](https://www.microsoft.com/en-us/security/blog/2022/08/31/vulnerability-in-tiktok-android-app-could-lead-to-one-click-account-hijacking/)

**TikTok** (Android) · Microsoft Threat Intelligence (Dimitrios Valsamaras) · Coordinated disclosure (Microsoft MSVR → TikTok) · 2022 · Bounty: —  
**Weakness:** [MASWE-0033 — Sensitive Native Functionality Exposed in WebViews](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/)

A deep-link host check could be bypassed to load any URL into an in-app WebView that exposed a JavaScript bridge with 70+ native methods (token retrieval, profile changes, authenticated requests), so a single click could hijack an account.

**What to check:** Map which origins can reach each JavaScript bridge and confirm bridged WebViews only load an on-device-enforced allowlist of hosts.

### 30. [com.basecamp.bc3 Webview Javascript Injection and JS bridge takeover](https://hackerone.com/reports/1343300)

**Basecamp 3** (Android) · fr4via · HackerOne: Basecamp · 2022 · Bounty: —  
**Weakness:** [MASWE-0033 — Sensitive Native Functionality Exposed in WebViews](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/)

An unsanitised URL reached a JavaScript-enabled WebView that exposed several bridges (nativeBridge, NativeApp, TurboNative); script injected through a crafted link could call them and exfiltrate the account email, project data and cookies.

**What to check:** List every addJavascriptInterface object and its methods, then trace whether data from incoming URLs can become script in that WebView.

### 31. [Twitter lite (Android): Vulnerable to local file steal, Javascript injection, Open redirect](https://hackerone.com/reports/499348)

**Twitter Lite** (Android) · rahulkankrale · HackerOne: X (Twitter) · 2019 · Bounty: —  
**Weakness:** [MASWE-0034 — WebViews Allow Access to Local Resources with Untrusted Content](/mobile/maswe-0034-webviews-allow-access-to-local-resources/)

An exported activity passed any received URI to its WebView without scheme checks, so another app could load file:// pages that read local files or javascript: URLs that inject script, exposing user files and session data.

**What to check:** Check that WebViews reject file:// and javascript: from external input and that file access / universal access from file URLs are disabled.

### 32. [\[PayPal Android\] Remote theft of user session using push_notification_webview deeplink](https://hackerone.com/reports/424443)

**PayPal** (Android) · Sergey Toshin (bagipro) · HackerOne: PayPal · 2019 · Bounty: —  
**Weakness:** [MASWE-0035 — WebViews Loading Untrusted Content](/mobile/maswe-0035-webviews-loading-untrusted-content/)

A deep link meant for push-notification content opened any URL in an authenticated WebView, so a website or app could point it at an attacker server and harvest request headers carrying session data.

**What to check:** Check whether WebViews that attach auth headers or cookies can be navigated to hosts outside the app's own domains.

### 33. [Webview in LINE client for iOS will render application/octet-stream files as HTML](https://hackerone.com/reports/988332)

**LINE** (iOS) · s5s · HackerOne: LY Corporation (LINE) · 2021 · Bounty: $500  
**Weakness:** [MASWE-0035 — WebViews Loading Untrusted Content](/mobile/maswe-0035-webviews-loading-untrusted-content/)

LINE's in-app iOS WebView rendered responses served as application/octet-stream as HTML, so attacker-supplied files could run JavaScript inside the app's browser context.

**What to check:** Check how in-app WKWebViews handle downloads and non-HTML content types; untrusted files must never render as active HTML.

### 34. [One Bug To Rule Them All: Modern Android Password Managers and FLAG_SECURE Misuse](https://blog.doyensec.com/2019/08/22/modern-password-managers-flag-secure.html)

**1Password, Keeper, Dashlane** (Android) · Lorenzo Stella (Doyensec) · vendor disclosure · 2019 · Bounty: —  
**Weakness:** [MASWE-0038 — Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings](/mobile/maswe-0038-insufficient-screenshot-protection/)

The password managers set FLAG_SECURE on main activities but secrets also appeared in separate windows (toasts, dialogs, spinners, popups) the flag doesn't cover, so a screen-capturing app could record master secrets and passwords.

**What to check:** Verify FLAG_SECURE also covers dialogs, toasts, popups and other separate windows that display secrets, not just the main activity.

### 35. [CVE-2025-11598: personal data visible in app switcher in mObywatel for iOS](https://cert.pl/en/posts/2026/02/CVE-2025-11598/)

**mObywatel (Polish digital ID)** (iOS) · Maciej Krakowiak (DSecure.me), via CERT Polska · CERT Polska coordinated disclosure · 2026 · Bounty: —  
**Weakness:** [MASWE-0038 — Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings](/mobile/maswe-0038-insufficient-screenshot-protection/)

The app did not obscure its content when backgrounded, so the iOS App Switcher snapshot showed the holder's personal data from the last screen, even after the session ended; fixed in 4.71.0.

**What to check:** Background the app on a sensitive screen, open the App Switcher and confirm a privacy overlay or blur replaces the snapshot.

### 36. [Tapjacking in Cloudflare WARP Mobile Client for Android (CVE-2023-0654)](https://github.com/cloudflare/advisories/security/advisories/GHSA-5r97-pqv6-xpx7)

**Cloudflare WARP (1.1.1.1)** (Android) · Cloudflare · Cloudflare bug bounty / vendor advisory · 2023 · Bounty: —  
**Weakness:** [MASWE-0039 — App Vulnerable to Overlay Attacks](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/)

A misconfiguration left the WARP Android client open to tapjacking: a malicious app could draw over it so users believed they were using WARP while their taps went to the attacker's interface; fixed in 6.29.

**What to check:** Confirm security-relevant views use filterTouchesWhenObscured or setHideOverlayWindows so taps are ignored under overlays.

### 37. [Popular iPhone and iPad Apps Snooping on the Pasteboard](https://www.mysk.blog/2020/03/10/popular-iphone-and-ipad-apps-snooping-on-the-pasteboard/)

**TikTok, Viber, Truecaller, PUBG Mobile, news apps and others** (iOS) · Talal Haj Bakry and Tommy Mysk · independent research · 2020 · Bounty: —  
**Weakness:** [MASWE-0030 — Improper Use of the Clipboard](/mobile/maswe-0030-improper-use-of-the-clipboard/)

Dozens of popular iOS apps silently read the pasteboard every time they opened, including passwords or account numbers copied on a nearby Mac via Universal Clipboard; the research led to the iOS 14 paste banner.

**What to check:** Check the app reads the clipboard only after an explicit paste action and marks sensitive copied data local-only or expiring.


## MASVS-CODE: Code Quality {#code}

Path traversal through filenames and archives, unsafe deserialisation, dynamic code loading and memory-safety bugs in bundled native libraries. Full methodology: [Code Quality guide](/mobile/masvs-code-code-quality-guide/).

### 38. ["Dirty Stream" attack: discovering and mitigating a common vulnerability pattern in Android apps](https://www.microsoft.com/en-us/security/blog/2024/05/01/dirty-stream-attack-discovering-and-mitigating-a-common-vulnerability-pattern-in-android-apps/)

**Xiaomi File Manager, WPS Office** (Android) · Microsoft Threat Intelligence (Dimitrios Valsamaras) · Coordinated disclosure (Microsoft MSVR) · 2024 · Bounty: —  
**Weakness:** [MASWE-0050 — Unsafe Handling of Untrusted Data](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/)

Share-target activities trusted the display name returned by the sending app's content provider, so a malicious provider could supply a traversal filename and overwrite files in the receiver's private storage — chained into native-library loading for code execution in Xiaomi File Manager and token theft elsewhere.

**What to check:** Check every share or file-receive handler ignores or canonicalises the provider-supplied display name before building a destination path.

### 39. [How a double-free bug in WhatsApp turns to RCE](https://awakened1712.github.io/hacking/hacking-whatsapp-gif-rce/)

**WhatsApp** (Android) · Awakened · Facebook bug bounty / vendor disclosure · 2019 · Bounty: —  
**Weakness:** [MASWE-0044 — Dependencies with Known Vulnerabilities](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/)

WhatsApp bundled the open-source android-gif-drawable native library, which had a double-free when parsing crafted GIFs; opening the in-app gallery to generate previews triggered it, and the author turned it into code execution (CVE-2019-11932, fixed in 2.19.244).

**What to check:** Inventory bundled native/media libraries, match versions against known CVEs, and prioritise parsers that run automatically on received content.

### 40. [Why dynamic code loading could be dangerous for your apps: a Google example](https://oversecured.com/blog/why-dynamic-code-loading-could-be-dangerous-for-your-apps-a-google-example)

**Google app (com.google.android.googlequicksearchbox)** (Android) · Oversecured · Google VRP / vendor disclosure · 2021 · Bounty: —  
**Weakness:** [MASWE-0049 — Unsafe Dynamic Code Loading](/mobile/maswe-0049-unsafe-dynamic-code-loading/)

An intent redirection let a third-party app reach a file-writing content provider and plant a Play Core split module, which the Google app then loaded — persistent code execution with all of the Google app's permissions that survived removal of the attacker's app.

**What to check:** Find where the app loads dex/so/split modules from and check whether any other component can write to those locations.

### 41. [#Instagram_RCE: Code Execution Vulnerability in Instagram App for Android and iOS](https://research.checkpoint.com/2020/instagram_rce-code-execution-vulnerability-in-instagram-app-for-android-and-ios/)

**Instagram** (Android & iOS) · Gal Elbaz (Check Point Research) · Facebook bug bounty / vendor disclosure · 2020 · Bounty: —  
**Weakness:** [MASWE-0050 — Unsafe Handling of Untrusted Data](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/)

Fuzzing Instagram's integration of the Mozjpeg decoder found an integer overflow on JPEG dimensions leading to a heap out-of-bounds write (CVE-2020-1895), triggered when a crafted image was imported into the app.

**What to check:** Fuzz native image/media decoding paths with malformed input and review size arithmetic before buffer allocation.

### 42. [\[Android\] Directory traversal leading to disclosure of auth tokens](https://hackerone.com/reports/1378889)

**Slack** (Android) · danielllewellyn · HackerOne: Slack · 2022 · Bounty: $3,500  
**Weakness:** [MASWE-0050 — Unsafe Handling of Untrusted Data](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/)

A workspace file with a crafted name was saved by the Android client outside its intended folder, overwriting app configuration so Slack traffic — including auth tokens — could be sent to an attacker-controlled host.

**What to check:** Check that server- or user-supplied filenames are sanitised and canonicalised before downloads are written to disk.

### 43. [Path traversal in ZIP extract routine on LINE Android](https://hackerone.com/reports/859469)

**LINE** (Android) · kanytu · HackerOne: LY Corporation (LINE) · 2020 · Bounty: $475  
**Weakness:** [MASWE-0050 — Unsafe Handling of Untrusted Data](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/)

LINE Keep unzipped archives without validating entry names (Zip Slip), so under certain conditions a crafted archive plus a co-installed malicious app could overwrite files in LINE's private folders.

**What to check:** Check every unzip routine confirms each entry's canonical path stays inside the target directory.

### 44. [Unsafe deserialization leads to token leakage in PayPal & PayPal for Business \[Android\]](https://hackerone.com/reports/453791)

**PayPal, PayPal for Business** (Android) · Sergey Toshin (bagipro) with khilly · HackerOne: PayPal · 2021 · Bounty: —  
**Weakness:** [MASWE-0050 — Unsafe Handling of Untrusted Data](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/)

A JSON wrapper class could be made to instantiate arbitrary Java objects from attacker-supplied input, letting a malicious app on the same device read session data including API tokens; fixed in 2019, disclosed in 2021.

**What to check:** Trace intent extras and deep-link parameters into Serializable/Parcelable or polymorphic JSON deserialisers and check class types are allowlisted.


## MASVS-RESILIENCE: Resilience {#resilience}

Debug switches, demo packages and diagnostic backdoors that reached production builds. Full methodology: [Resilience guide](/mobile/masvs-resilience-resilience-testing-guide/).

### 45. [FlagLeft: We Found A Forgotten Flag in Microsoft 365 Android Apps](https://enclave.ai/blog/flagleft-microsoft-365-android-forgotten-flag-account-takeover)

**Microsoft Word, Excel, PowerPoint, OneNote, Loop, Microsoft 365 Copilot** (Android) · Yanir Tsarimi, Ofek Levin (Enclave) · Microsoft (MSRC) coordinated disclosure · 2026 · Bounty: —  
**Weakness:** [MASWE-0063 — Debug Mechanisms Not Disabled](/mobile/maswe-0063-debug-mechanisms-not-disabled/)

A shared Microsoft SDK shipped to production with debug mode on, which skipped the check restricting token requests to trusted callers, so any app on the device could silently obtain the signed-in user's Microsoft 365 tokens.

**What to check:** Check release builds for debug/dev flags (setIsDebugMode, BuildConfig.DEBUG branches) that relax security checks.

### 46. [iVerify discovers Android vulnerability impacting millions of Pixel devices (Showcase.apk)](https://iverify.com/blog/iverify-discovers-android-vulnerability-impacting-millions-of-pixel-devices-around-the-world)

**Showcase.apk (retail demo app in Pixel firmware)** (Android) · iVerify (with Palantir and Trail of Bits) · vendor disclosure (Google) · 2024 · Bounty: —  
**Weakness:** [MASWE-0061 — Debug Artifacts Not Removed](/mobile/maswe-0061-debug-artifacts-not-removed/)

A retail-demo package with system privileges shipped in Pixel firmware; it fetched its configuration over plain HTTP with weak verification, so once enabled a network attacker could inject code or install packages.

**What to check:** Check production builds for leftover demo, test or diagnostic components and confirm they are removed rather than merely disabled.

### 47. [OnePlus Device Root Exploit: Backdoor in EngineerMode App for Diagnostics Mode](https://www.nowsecure.com/blog/2017/11/14/oneplus-device-root-exploit-backdoor-engineermode-app-diagnostics-mode/)

**OnePlus EngineerMode** (Android) · Robert Baptiste (Elliot Alderson); verified by NowSecure · independent research · 2017 · Bounty: —  
**Weakness:** [MASWE-0063 — Debug Mechanisms Not Disabled](/mobile/maswe-0063-debug-mechanisms-not-disabled/)

A factory diagnostics app left in production OxygenOS had a hidden mode, unlocked by a password whose hash sat in a native library, that granted persistent ADB root; the hash was easily reversed.

**What to check:** Look for hidden diagnostic/engineering activities and hard-coded unlock codes in production builds; treat client-side secrets as public.


## MASVS-PRIVACY: Privacy {#privacy}

Audio sent before a call is answered, scripts injected into in-app browsers, and privacy settings silently reset. Full methodology: [Privacy guide](/mobile/masvs-privacy-privacy-testing-guide/).

### 48. [The State of State Machines](https://projectzero.google/2021/01/the-state-of-state-machines.html)

**Signal, Google Duo, Facebook Messenger, JioChat, Mocha** (Android) · Natalie Silvanovich (Google Project Zero) · vendor disclosure · 2021 · Bounty: —  
**Weakness:** [MASWE-0070 — Inadequate Awareness for Privacy Relevant Actions](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/)

Signalling flaws in several calling apps let a caller make the callee's device transmit microphone audio, and sometimes video, before the call was answered, with no indication to the victim.

**What to check:** Confirm nothing from camera or microphone is captured or sent until the user explicitly accepts, even when signalling messages arrive out of order.

### 49. [iOS Privacy: Instagram and Facebook can track anything you do on any website in their in-app browser](https://krausefx.com/blog/ios-privacy-instagram-and-facebook-can-track-anything-you-do-on-any-website-in-their-in-app-browser)

**Instagram, Facebook, Messenger** (iOS) · Felix Krause · independent research (Meta: intended behaviour) · 2022 · Bounty: —  
**Weakness:** [MASWE-0078 — Inadequate or Ambiguous User Consent Mechanisms](/mobile/maswe-0078-inadequate-user-consent-mechanisms/)

The apps opened external links in an in-app browser and injected a Meta tracking script into third-party pages without consent from the user or the site; Meta described it as intended for ad measurement.

**What to check:** Check whether in-app browsers inject scripts or observe content on third-party pages, and whether users are told and can opt out.

### 50. [Changing email address on Twitter for Android unsets "Protect your Tweets"](https://hackerone.com/reports/472013)

**Twitter for Android** (Android) · alexiaya · HackerOne: X (Twitter) · 2019 · Bounty: $2,940  
**Weakness:** [MASWE-0077 — Inadequate Data Visibility Controls](/mobile/maswe-0077-inadequate-data-visibility-controls/)

Verifying a new email address in the Android app silently switched off "Protect your Tweets", making follower-only tweets public without the user knowing.

**What to check:** Check that account flows such as email change, migration or re-login never reset privacy and visibility settings.

## Using these on an engagement

- **Read for the method, not just the bug.** Most of these were found by enumerating the same things every time: the merged manifest's exported components, every way a URL can reach a WebView, every place the app writes a file whose name it did not choose, and every entry point that skips the app lock.
- **Test the control, then test around it.** Many entries are bypasses of a control that was already there: TikTok's deep-link allowlist, ownCloud's path filter, Bitwarden's forced re-authentication, Shopify's and Nextcloud's app locks. Finding the control is where the test starts.
- **Expect findings in SDKs.** EngageSDK, Microsoft's shared auth SDK, Play Core, and the GIF and JPEG decoders in WhatsApp and Instagram all came from code the app team did not write. Review the merged manifest and the dependency list, not just the app's own sources.
- **Stay in scope.** Only test apps and accounts you are authorised to test, and follow each programme's rules on devices, accounts and disclosure.

Know a public writeup that belongs here? [Email us](mailto:info@gulertech.co.uk).
