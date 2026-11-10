---
title: "MASWE-0062: No Application-Level Payload Encryption"
date: 2026-11-10 20:11:00 +0000
subcategory: resilience
summary: "Testing app-level payload encryption on top of TLS: coverage, key management, AEAD, nonces and replay, and what it does and does not buy you."
refs: [MASWE-0062, MASVS-RESILIENCE-3, MASVS-NETWORK-1, CWE-319]
tags: [android, ios, masvs-resilience, payload-encryption, api-security, network]
---

This note is part of our [MASVS-RESILIENCE guide](/mobile/masvs-resilience-resilience-testing-guide/) and covers OWASP [MASWE-0062](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0062/): an app whose API traffic is protected by TLS and nothing else, so that anyone who controls the device sees clean JSON as soon as pinning is out of the way. Application-level payload encryption puts a second envelope inside the TLS tunnel: the request body is encrypted (and ideally authenticated) by the app before it reaches the network stack, and only the backend can open it. It is a resilience measure. It does not make an insecure API secure, it does not replace TLS or pinning, and on a device the attacker owns it can always be peeled off by finding the code that does it. What it does is move the attacker's first step from "install a proxy and read the API" to "reverse engineer the app's crypto", and, if the keys are designed properly, stop a recorded request from being edited and replayed by a script. Below you get what such schemes look like, what they buy, the mistakes we find most often, three tests of our own (OWASP has none for this weakness), secure designs for both platforms, and how to rate what you find.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [General: what application-level payload encryption is](#general-what-application-level-payload-encryption-is)
  - [General: what it buys and what it does not](#general-what-it-buys-and-what-it-does-not)
  - [General: common implementation mistakes](#general-common-implementation-mistakes)
  - [Android: platform building blocks](#android-platform-building-blocks)
  - [iOS: platform building blocks](#ios-platform-building-blocks)
  - [General: how testers analyse a payload encryption scheme](#general-how-testers-analyse-a-payload-encryption-scheme)
- [Tests](#tests)
  - [GT-RES-0062-1: Presence and coverage of payload encryption (Android and iOS)](#gt-res-0062-1-presence-and-coverage-of-payload-encryption-android-and-ios)
  - [GT-RES-0062-2: Key management for payload encryption (Android and iOS)](#gt-res-0062-2-key-management-for-payload-encryption-android-and-ios)
  - [GT-RES-0062-3: Construction, integrity and replay protection (Android and iOS)](#gt-res-0062-3-construction-integrity-and-replay-protection-android-and-ios)
- [Secure implementation](#secure-implementation)
  - [Design checklist](#design-checklist)
  - [Android: attested signing key and AEAD envelope](#android-attested-signing-key-and-aead-envelope)
  - [iOS: HPKE envelope and App Attest assertion](#ios-hpke-envelope-and-app-attest-assertion)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app applies application-level payload encryption in addition to transport-layer encryption."* MASWE-0062 maps to **MASVS-RESILIENCE-3** ("The app implements anti-static analysis mechanisms") and **MASVS-NETWORK-1** ("The app secures all network traffic according to the current best practices"), and to [CWE-319](https://cwe.mitre.org/data/definitions/319.html) (Cleartext Transmission of Sensitive Information). The CWE is a loose fit: with TLS in place nothing travels in cleartext over the network. The "cleartext" here is what the payload looks like to someone who has already terminated TLS on a device they control. It carries over MASVS v1's MSTG-RESILIENCE-13 ("As a defense in depth, next to having solid hardening of the communicating parties, application level payload encryption can be applied to further impede eavesdropping"), which never had a MASTG test either.

The weakness carries OWASP's **R** profile (plus EUDIW). It is relevant when the threat model includes someone reverse engineering and abusing the app's API from a device they own: payment and banking apps, games with server-side economies, ticketing and loyalty, apps whose API is a scraping target, wallets. For an app without that threat model, the absence of a second encryption layer is not a weakness at all.

**OWASP has no tests and no Knowledge pages for MASWE-0062.** The [Background](#background) section and the three tests below are ours, labelled "Guler Tech methodology". No legacy v1 test covered MSTG-RESILIENCE-13, so nothing is replaced.

Keep the neighbouring topics apart. Most "payload encryption" findings are really findings in one of these:

| Question | Where it lives |
|---|---|
| Does the app use TLS everywhere, with no cleartext fallback? | [MASWE-0026 cleartext traffic](/mobile/maswe-0026-cleartext-network-traffic/), [NETWORK hub](/mobile/masvs-network-secure-communication-guide/) |
| Does the app validate certificates and pin where it should? | [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/), [MASWE-0028 insecure identity pinning](/mobile/maswe-0028-insecure-identity-pinning/) |
| Is the payload key hard-coded in the package? | [MASWE-0004 hard-coded sensitive data](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/), [MASWE-0003 keys outside the keystore](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) |
| Is the cipher, mode or IV handling broken? | [MASWE-0007 improper encryption](/mobile/maswe-0007-improper-encryption/), [MASWE-0009 improper use of MAC](/mobile/maswe-0009-improper-use-of-mac/), [CRYPTO hub](/mobile/masvs-crypto-cryptography-guide/) |
| Can the server tell a genuine app on a genuine device from a script? | [MASWE-0056 app attestation](/mobile/maswe-0056-app-attestation-not-implemented/), [MASWE-0054 device attestation](/mobile/maswe-0054-device-attestation-not-implemented/) |
| Is the payload encryption itself readable because the app is not obfuscated? | [MASWE-0059 code obfuscation](/mobile/maswe-0059-code-obfuscation-not-implemented/) |
| Does the server trust values the client sends (price, score, role)? | Server-side authorisation and business logic, outside MASVS; rate it there |

## Modes of Introduction

**TLS as the only layer.** The default for almost every app. Security-relevant requests (login, payment initiation, transfers, score submission, promo-code redemption, risk signals) are plain JSON inside TLS. On a test device with the proxy CA trusted and pinning neutralised, every field is readable and editable.

**Encryption added as obfuscation, not as protocol.** A team adds "encryption" late, under time pressure: a hard-coded AES key and IV in a constants class, the whole body Base64-encoded AES-CBC or, worse, AES-ECB. It stops a casual proxy user and nobody else, and it often gives the team a false sense that the API is protected.

**Partial coverage.** The login call is encrypted, but the token refresh, the transfer confirmation or the analytics call carrying device risk signals is not. Or requests are encrypted and responses are not, so the API's data model is fully visible anyway.

**Confidentiality without integrity.** The payload is encrypted with an unauthenticated mode, so bits can be flipped, or the request is encrypted but not bound to its method, path, session or time, so an intercepted ciphertext can be replayed verbatim.

**SDK-provided envelopes.** A fraud, payments or anti-bot SDK encrypts its own telemetry. The app's own API is still plaintext. Note which is which; the SDK's envelope does not count for the app's endpoints.

## Impact

- **Cheap API mapping and abuse.** With plaintext payloads, an attacker with a rooted or jailbroken device, a proxy and a public pinning bypass script has the full API in an afternoon: every endpoint, parameter, enum and error code. Scraping, credential stuffing clients, fake account farms, bonus abuse and automated purchasing follow from that map.
- **Easy tampering with security-relevant state.** Fields the backend should not trust but does (client-computed totals, game results, device risk scores, feature flags) can be edited in the proxy without reading a line of code.
- **Replay and automation.** A request captured once can be replayed or scripted at scale when nothing binds it to a fresh, device-held key and a nonce.
- **What it does not protect against.** A network attacker without control of the device is already stopped by correct TLS and certificate validation. An attacker who controls the device can still extract keys or hook the plaintext. Rate the absence of this layer by the gap between those two.

## Mitigations

- **Keep TLS, certificate validation and, where justified, pinning.** Payload encryption sits inside them, never instead of them.
- **Encrypt security-relevant payloads end-to-end to the backend service** with an authenticated scheme (AEAD, JWE with an AEAD `enc`, COSE, HPKE), in both directions where responses carry sensitive data.
- **Do not ship a shared secret.** Use the server's public key for encryption (HPKE, ECDH-ES) and a per-install private key held in the Android Keystore or the Secure Enclave for signing or key agreement, ideally attested ([MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)).
- **Bind each message to its context**: method, path, session, timestamp and a unique request ID in the authenticated data, checked server-side with a replay window.
- **Protect the code that builds the envelope** with obfuscation and runtime integrity checks ([MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/), [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/)) so lifting the plaintext costs real reverse-engineering effort.
- **Make every security decision on the server.** Payload encryption raises the cost of seeing and forging requests; it never makes a client-supplied value trustworthy.

## Background

There is no OWASP Knowledge for this weakness. The sections below are ours.

### General: what application-level payload encryption is

TLS protects bytes between the app's network stack and the TLS terminator, which is usually a load balancer or CDN edge, not your application server. Application-level payload encryption protects the message itself, from the code that builds it inside the app to the service that consumes it. The common shapes:

| Scheme | What it is | Typical use |
|---|---|---|
| **JWE** ([RFC 7516](https://www.rfc-editor.org/rfc/rfc7516)) | JSON Web Encryption. A header names a key-management algorithm (`alg`, e.g. `RSA-OAEP-256`, `ECDH-ES+A256KW`, `dir`) and a content cipher (`enc`, e.g. `A256GCM`). Compact form is five base64url segments separated by dots. | Payment and banking APIs, card data, open-banking style message security |
| **JWS** ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)) / **HTTP Message Signatures** ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)) | Signing, not encryption. Integrity and origin of the request, no confidentiality. | Request signing with a per-device key |
| **COSE** ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)) | The CBOR equivalent of JOSE: `COSE_Encrypt0`, `COSE_Sign1`. | Constrained protocols, identity wallets (mdoc / ISO 18013-5) |
| **HPKE** ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)) | Hybrid public-key encryption: an ephemeral key encapsulation to the recipient's public key, an HKDF key schedule and an AEAD. Supports exporting secrets for a reply. | Modern envelopes; Oblivious HTTP ([RFC 9458](https://www.rfc-editor.org/rfc/rfc9458)) uses it to encrypt a request and derive the response key |
| **Session key from an attested handshake** | The app generates a hardware-backed key, proves it with key attestation or App Attest, runs ECDH with the server and derives per-session AEAD keys. | High-value apps with their own protocol |
| **Home-grown AES** | A fixed key and IV in the app, AES-CBC or ECB, Base64 body. | Everywhere it should not be |

Two distinctions matter for testing and rating:

- **Encryption vs signing.** Encryption hides the payload. Signing (HMAC with a shared key, or ECDSA/EdDSA with a per-device private key) proves who produced it and that it was not changed. An AEAD gives integrity under the encryption key, but if that key is known to every install, "integrity" only proves that *some* copy of the app, or anyone who extracted the key, produced the message. A per-device asymmetric key, ideally attested, is what lets the server reject forged or modified requests.
- **What the key is bound to.** A key that is the same in every install is a secret only until someone opens the APK or IPA. A server public key is not a secret and can be embedded safely. A per-install private key in hardware is the only client-side key that an attacker cannot simply copy to a script.

### General: what it buys and what it does not

What it buys:

- **Higher analysis cost.** Proxy interception alone shows opaque blobs. The attacker has to find, understand and hook (or reimplement) the envelope code, which, in an obfuscated and integrity-checked build, is real work. That is the MASVS-RESILIENCE-3 angle.
- **Protection behind the TLS terminator.** The payload stays encrypted through CDNs, WAFs, load balancers and logging middleware until it reaches the service that holds the key. That is a genuine data-protection benefit for card or identity data, independent of resilience.
- **Resistance to request forgery and replay at scale** when the scheme uses a per-device hardware key, nonces and server-side checks. A captured request can no longer be edited, and a script cannot mint new valid requests without the device.

What it does not buy:

- **Nothing against a network attacker that TLS does not already stop.** If certificate validation is broken ([MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/)) the payload layer is a mitigating factor, not a fix.
- **No protection against the device owner in the end.** The app has to hold the plaintext before it encrypts it. A Frida hook on the app's own encrypt function, a memory dump, or a debugger shows it. Protection lasts until the key or the hook point is found.
- **No server-side authorisation.** An encrypted `"amount": 1` is still a client-supplied amount.

### General: common implementation mistakes

| Mistake | Why it matters | See also |
|---|---|---|
| **Static symmetric key in the app** (constants class, `strings.xml`, native library, `Info.plist`, obfuscated but recoverable) | One extraction breaks every install. If the backend treats successful decryption as proof of a genuine client, the key becomes an API credential. | [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/) |
| **Key in `SharedPreferences`, `NSUserDefaults` or a plist** after first-run download | Readable by anyone with a backup or root, copied into scripts | [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) |
| **AES-ECB, or CBC/CTR with no MAC** | ECB leaks structure; unauthenticated modes allow bit-flipping and padding-oracle attacks against the server | [MASWE-0007](/mobile/maswe-0007-improper-encryption/) |
| **Fixed or reused IV / nonce**, especially with GCM | GCM nonce reuse under one key reveals the XOR of plaintexts and lets an attacker forge tags | [MASWE-0007](/mobile/maswe-0007-improper-encryption/) |
| **No replay protection** | AEAD says nothing about freshness; a captured ciphertext is valid forever | [MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/) |
| **Context not authenticated** | A valid encrypted body for `/profile` is accepted on `/transfer`, or one user's envelope in another user's session | |
| **Responses in plaintext** | Hides the request schema but leaks the data model and the data | |
| **Encryption instead of TLS** | Custom crypto over cleartext HTTP is a NETWORK finding first | [MASWE-0026](/mobile/maswe-0026-cleartext-network-traffic/) |
| **Server error oracles** | Distinct errors for "decryption failed", "bad padding", "bad signature", "stale timestamp" help an attacker probe the scheme | |
| **Debug bypass** | A header or build flag that makes the server accept plaintext, left reachable in production | [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/) |

### Android: platform building blocks

- **Android Keystore** generates and holds private keys in TEE or StrongBox hardware. Keys are non-exportable; the app can only ask the keystore to sign, decrypt or agree. `KeyProperties.PURPOSE_AGREE_KEY` (ECDH inside the keystore) is available from API 31; signing with `PURPOSE_SIGN` everywhere. See our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) for the keystore itself.
- **Key attestation** (`setAttestationChallenge()`) returns a certificate chain the server can verify to learn that the key lives in hardware, belongs to this package and signing certificate, and was generated for this challenge. That turns "a request signed by key K" into "a request signed by a key that only a genuine install of our app on a real device holds". It is covered in [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/) and [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/).
- **Play Integrity standard requests** accept a `requestHash`, a hash of the request you want to protect, which comes back inside the signed verdict. That binds a specific request to an integrity verdict, see the [MASWE-0056 note](/mobile/maswe-0056-app-attestation-not-implemented/).
- **Tink** ([developers.google.com/tink](https://developers.google.com/tink)) provides AEAD, hybrid encryption (including HPKE key templates) and signatures with safe defaults, and is the easiest way not to write your own envelope.
- **JCA**: `Cipher.getInstance("AES/GCM/NoPadding")` with a cipher-generated 12-byte IV and `updateAAD()` for context, `Signature.getInstance("SHA256withECDSA")` for keystore signing keys.

### iOS: platform building blocks

- **Secure Enclave keys** (`SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`, or CryptoKit `SecureEnclave.P256.Signing.PrivateKey` / `KeyAgreement.PrivateKey`) are P-256 only and never leave the enclave.
- **App Attest** (`DCAppAttestService`): the app generates a Secure Enclave key, Apple attests it once, and from then on the app signs `clientDataHash` (a hash of the request) with `generateAssertion`. Each assertion carries a counter the server must see increase, which gives replay resistance for free. See the [MASWE-0056 note](/mobile/maswe-0056-app-attestation-not-implemented/).
- **CryptoKit**: `AES.GCM` and `ChaChaPoly` AEADs with authenticated data, and from iOS 17 `HPKE.Sender` / `HPKE.Recipient` for envelopes to a server public key.
- **CommonCrypto** (`CCCrypt`) is what older and home-grown schemes use. It offers CBC and ECB without authentication, which is why it shows up in findings.

### General: how testers analyse a payload encryption scheme

The work follows the same path an attacker takes, on your own test device and a test account:

1. **Observe.** With TLS interception working ([traffic interception lab](/mobile/mobile-traffic-interception-lab/), pinning handled as in [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/)), see which bodies are opaque and what the envelope looks like: JOSE header, fixed prefix, length patterns, Base64 alphabet, a key ID.
2. **Find the routine.** In jadx, search for the envelope's markers and the crypto APIs: `Cipher.getInstance`, `GCMParameterSpec`, `SecretKeySpec`, `KeyAgreement`, `Signature.getInstance`, Tink (`com.google.crypto.tink`), Nimbus (`com.nimbusds.jose`), header names such as `X-Signature`. On iOS, search the binary's strings and imports for `CCCrypt`, `SecKeyCreateEncryptedData`, `SecKeyCreateSignature`, `generateAssertion`, CryptoKit symbols and JOSE library class names. Follow the call graph back to the HTTP client (OkHttp interceptor, `URLSessionDelegate`, Alamofire `RequestInterceptor`).
3. **Trace plaintext at the boundary.** Hook the app's own encrypt and decrypt functions, or the platform crypto calls they use, and log the input and output. This shows you the plaintext API without breaking anything, and is the evidence for how much the layer actually costs an attacker.
4. **Find the key's origin.** Constant, resource, preference file, downloaded, derived, keystore. This is where most schemes fall.
5. **Assess the construction and the server.** Mode, IV, authentication, what is bound, replay behaviour, error messages.

Record the effort: "one `frida-trace` command showed every plaintext request" and "three days to reconstruct an obfuscated native key schedule" are both legitimate results, and they lead to different ratings.

## Tests

All three tests are ours. Run them only against your own test accounts and with the app owner's authorisation. Tests 1 and 3 send traffic to the backend; agree the scope for replay and tampering requests (especially on payment endpoints) before you start.

### GT-RES-0062-1: Presence and coverage of payload encryption (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Establishes whether the app protects payloads above TLS at all, and if so, which endpoints and which directions are covered. The output is an endpoint inventory with a protection status per request and response, which tests 2 and 3 then work through.

#### Prerequisites

- A rooted Android or jailbroken iOS test device (or a Frida Gadget build) with your proxy CA trusted and pinning handled, per the [traffic interception lab](/mobile/mobile-traffic-interception-lab/).
- An intercepting proxy (Burp Suite, mitmproxy) that can export flows as HAR.
- A list of the app's security-relevant flows from the threat model: registration, login, step-up, token refresh, payments and transfers, profile changes, reward or score submission, anything a bot would want.
- A test account per role.

#### Steps

1. **Exercise every security-relevant flow** with the proxy capturing, including error paths (wrong password, failed payment) and background traffic (token refresh, config fetch, telemetry). Export the session as HAR.
2. **Classify each body.** A quick first pass over the HAR:

   ```python
   # classify_har.py - rough per-endpoint view of request/response bodies (python3 -I classify_har.py flows.har)
   import json, math, sys, collections
   def entropy(s):
       if not s: return 0.0
       c = collections.Counter(s); n = len(s)
       return -sum(v / n * math.log2(v / n) for v in c.values())
   def kind(text):
       t = (text or '').strip()
       if not t: return 'empty'
       if t[:1] in '{[':
           return 'json'
       if t.count('.') == 4 and ' ' not in t: return 'jwe-compact?'
       return 'opaque(H=%.1f)' % entropy(t)
   for e in json.load(open(sys.argv[1]))['log']['entries']:
       rq, rs = e['request'], e['response']
       print(rq['method'], rq['url'].split('?')[0][:70],
             '| req:', kind((rq.get('postData') or {}).get('text')),
             '| resp:', kind(rs['content'].get('text')))
   ```

   JSON bodies are plaintext. Opaque bodies with entropy close to 6 bits per character (Base64) or a five-segment dotted string are candidates for encryption. A JSON body with one opaque field (`"payload": "..."`, `"data": "..."`) is a common envelope shape too.
3. **Decode what you can.** Base64-decode opaque bodies and look at the first bytes: a JOSE header (`alg`, `enc`, `kid`), a version byte and key ID, a fixed-length prefix that looks like an IV (12 or 16 bytes), a trailing 16-byte tag. Compressed (gzip, `1f 8b`) or protobuf payloads are encoding, not encryption; protobuf without its schema is still readable with `protoc --decode_raw`.
4. **Check both directions and all hosts.** Note whether responses are protected, and whether first-party APIs on other hosts (auth server, payments service, config service) follow the same scheme.
5. **Check for a plaintext fallback.** Look in the decompiled client for a code path or header that sends plaintext (`if (BuildConfig.DEBUG)`, `X-Plain`, `encryption: false` in remote config) and, within the agreed scope, whether the server accepts a plaintext body on an endpoint that normally receives an envelope.
6. **Inventory third-party envelopes separately.** Fraud and anti-bot SDKs often encrypt their own telemetry. List them, but do not count them as protection for the app's API.

#### Observation

An endpoint table: method, path, host, request protection (none / encoded / encrypted / signed / both), response protection, the envelope format, and whether the server accepts plaintext in place of the envelope.

#### Evaluation

For an **R-profile** app the test **fails** if security-relevant endpoints carry plaintext request or response bodies inside TLS, if coverage is partial in a way that exposes the security-relevant flows, or if the server accepts plaintext where it should require the envelope. It **passes** if every security-relevant request (and every response that carries sensitive data) is protected by an envelope; then continue with tests 2 and 3, because presence says nothing about strength.

For an app outside the R profile, record the result as an observation. Plaintext payloads inside correct TLS are the normal, acceptable design.

#### Demo

Illustrative output of the classification script for an app that protects only part of its API:

```text
POST https://api.example.com/v2/auth/login          | req: opaque(H=5.9) | resp: opaque(H=6.0)
POST https://api.example.com/v2/auth/refresh        | req: json          | resp: json
GET  https://api.example.com/v2/accounts            | req: empty         | resp: json
POST https://api.example.com/v2/transfers           | req: jwe-compact?  | resp: json
POST https://telemetry.example.com/collect          | req: opaque(H=6.0) | resp: empty
```

Login and the transfer request are protected, token refresh and every response are not, and the telemetry blob belongs to a third-party SDK. For an R-profile app that is a coverage finding: the account data model and the refresh token are visible to anyone with a proxy.

### GT-RES-0062-2: Key management for payload encryption (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Determines where the keys for the envelope come from, whether they are the same in every install, and whether a script without the device can produce valid envelopes. This is the question that decides whether the layer is real or decorative.

#### Prerequisites

- The envelope endpoints from GT-RES-0062-1.
- The decompiled app: jadx output for Android; the decrypted IPA and a disassembler (Ghidra, radare2/rabin2, Hopper) for iOS.
- Frida on the test device, two test installs (two devices, or uninstall and reinstall) and a test account.

#### Steps

1. **Locate the crypto calls.** Android:

   ```bash
   jadx -d out app.apk
   grep -rnE 'Cipher\.getInstance|GCMParameterSpec|SecretKeySpec|IvParameterSpec|KeyAgreement|Signature\.getInstance|crypto\.tink|nimbusds\.jose|setAttestationChallenge' out/sources | grep -v '/androidx/'
   ```

   iOS (decrypted binary):

   ```bash
   rabin2 -i Payload/App.app/App | grep -E 'CCCrypt|SecKeyCreate|SecKeyCopy|DCAppAttest'
   rabin2 -zz Payload/App.app/App | grep -iE 'AES|GCM|jwe|kid|enc"|alg"|X-Signature'
   ```

   Repeat for embedded frameworks (`Payload/App.app/Frameworks/*`) and, on Android, for native libraries (`readelf --dyn-syms -W lib/arm64-v8a/*.so | grep -iE 'EVP_|AES_|aead'`).
2. **Trace the key material at runtime.** On Android, log the keys passed to `SecretKeySpec` and where `Cipher.init` keys come from:

   ```javascript
   // trace-payload-keys.js - log raw symmetric keys the app builds and keystore aliases it uses
   Java.perform(() => {
     const SKS = Java.use('javax.crypto.spec.SecretKeySpec');
     SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, alg) {
       const hex = Array.from(k, b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
       console.log('[SecretKeySpec] ' + alg + ' len=' + k.length + ' key=' + hex);
       console.log(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
       return this.$init(k, alg);
     };
     const KS = Java.use('java.security.KeyStore');
     KS.getKey.implementation = function (alias, pw) {
       console.log('[KeyStore.getKey] alias=' + alias + ' type=' + this.getType());
       return this.getKey(alias, pw);
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l trace-payload-keys.js
   ```

   On iOS, hook `CCCrypt` (the CRYPTO notes have a ready script in [MASWE-0007](/mobile/maswe-0007-improper-encryption/)) and log `args[3]` / `args[4]` (key, key length), and trace `SecKeyCreateRandomKey` and `SecItemCopyMatching` for key generation and lookup.
3. **Compare installs.** Run the same flow on two installs. A raw symmetric key that is identical on both is a static app-wide key. Then search for it in the package (`grep -r` over the jadx output and the unzipped APK for its hex or Base64 form; `rabin2 -zz` or a byte search on iOS) to find where it is stored or how it is derived.
4. **Classify the key source:** constant in code or resources; derived from constants (package name, signing certificate hash, fixed salt); downloaded at first run and stored in preferences, a plist or a database; derived from a server handshake; held in the Keystore / Secure Enclave. For a downloaded or derived key, check where it is stored afterwards (`run-as` is not available on release builds; use a root shell or a jailbroken file browser on the test device) and whether it is ever rotated.
5. **For asymmetric schemes, check what the server verifies.** Is the device public key registered with key attestation or App Attest, or just uploaded? Does the server tie the key to the account and refuse other keys?
6. **Optional, in scope only: forge from a script.** With the key and construction understood, build one envelope off-device (a few lines of Python) for a harmless request on your test account and see whether the server accepts it. Acceptance proves that the layer gives no client authenticity.

#### Observation

The key source, key length and algorithm, whether keys differ per install and per session, where any persisted key is stored, the call stack that leads to key creation, and whether an off-device envelope was accepted.

#### Evaluation

The test **fails** if:

- the payload key is a constant, or is derived only from values in the package, so it is the same across installs;
- a per-install or per-session key is stored outside the Keystore / Secure Enclave in a readable form;
- the scheme uses a client-side private or secret key that the server accepts without attestation and the server treats a valid envelope as proof of a genuine client;
- an envelope built off-device with extracted material is accepted.

It **passes** if encryption is to a server public key (no client secret needed to encrypt), and any client-side secret is a non-exportable hardware-backed key whose provenance the server verifies (key attestation, App Attest) and binds to the account or session.

A static key that is well hidden (native code, white-box crypto, heavy obfuscation) still fails; record the extraction effort, which goes into the rating.

#### Demo

A pattern we see often (simplified):

```kotlin
object PayloadCrypto {
    private val KEY = "k3y-For-Payloads-0001-padding-00".toByteArray()   // same in every install
    private val IV = ByteArray(16)                                       // all zeros
    fun encrypt(json: String): String {
        val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(KEY, "AES"), IvParameterSpec(IV))
        return Base64.encodeToString(c.doFinal(json.toByteArray()), Base64.NO_WRAP)
    }
}
```

Illustrative output of the key trace on two installs:

```text
[SecretKeySpec] AES len=32 key=6b33792d466f722d5061796c6f6164732d303030312d70616464696e672d3030
    at com.example.app.net.PayloadCrypto.encrypt(PayloadCrypto.kt:7)
    at com.example.app.net.EncryptInterceptor.intercept(EncryptInterceptor.kt:21)
```

Same key on both installs, readable as ASCII, in a constants object: fail. The fixed zero IV and missing authentication are construction findings for GT-RES-0062-3.

### GT-RES-0062-3: Construction, integrity and replay protection (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Checks whether the envelope is built correctly: an authenticated mode, unique nonces, context bound into the authenticated data, freshness checked by the server, and no error oracles. A scheme can have perfect key management and still let a captured request be replayed for ever.

#### Prerequisites

- GT-RES-0062-1 and -2 done; the envelope routine identified.
- Frida on the test device; the intercepting proxy with a repeater; agreement on which endpoints you may replay or tamper with (prefer idempotent or low-value test operations).

#### Steps

1. **Trace the app's own envelope function** to see plaintext, nonce and output together. Hook the class and method you found in jadx, not the whole crypto stack:

   ```javascript
   // trace-envelope.js - log what the app's own envelope routine receives and returns (test account only)
   Java.perform(() => {
     const P = Java.use('com.example.app.net.PayloadCrypto');   // from jadx
     P.encrypt.overload('java.lang.String').implementation = function (plain) {
       const out = this.encrypt(plain);
       console.log('[encrypt] in=' + plain + '\n          out=' + out.substring(0, 80) + '...');
       return out;
     };
   });
   ```

   For a quick survey without writing hooks, `frida-trace` can trace methods by pattern:

   ```bash
   frida-trace -U -f com.example.app -j '*!*encrypt*/isu' -j '*!*decrypt*/isu'   # Android, app classes only
   frida-trace -U -f com.example.app -i 'CCCrypt' -m '-[*Crypt* *]'                 # iOS
   ```

2. **Mode and authentication.** From the code and the trace: is it AES-GCM, ChaCha20-Poly1305, an HPKE AEAD, or JWE with an AEAD `enc`; or is it CBC/CTR/ECB without a MAC? If there is a separate MAC, is it encrypt-then-MAC over IV and ciphertext with a different key (see [MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/))?
3. **Nonce handling.** Send the same plaintext twice (e.g. the same harmless request) and compare envelopes. Identical ciphertexts mean a fixed IV or a deterministic scheme. In code, look for a constant `IvParameterSpec` / `GCMParameterSpec` or a counter that resets per launch.
4. **Context binding.** Check what goes into the AAD or the signed data: HTTP method, path, host, session or account ID, timestamp, request ID. Within scope, move a valid envelope from one endpoint to another, or from one test account's session to another's, and see whether the server accepts it.
5. **Replay.** Resend a captured request unchanged after a few seconds, then after several minutes. A request that is accepted again (a second identical action, or a 200 with the same effect) has no replay protection. With App Attest, check that the server rejects a reused assertion (the counter must increase).
6. **Tampering.** Flip one bit in the ciphertext and one in the IV or header. An authenticated scheme must reject both. Note the error responses: distinct messages for decryption, padding, signature and freshness failures are an oracle.
7. **Responses.** If responses are encrypted, check that they are bound to the request (an HPKE exported secret, a key derived from the request's ephemeral key, or the request ID in the AAD), so a stale response cannot be substituted.

#### Observation

The mode and parameters, the content of the AAD or signed data, the results of the identical-plaintext, cross-endpoint, cross-session, replay and bit-flip probes, and the server's error responses.

#### Evaluation

The test **fails** if any of these holds for a security-relevant endpoint: unauthenticated encryption (ECB, CBC or CTR without a correct MAC); nonce or IV reuse under the same key; a valid envelope accepted on another endpoint or in another session; an unchanged request accepted again outside a short, server-enforced window; a modified ciphertext accepted; distinguishable error responses that reveal which check failed.

It **passes** if the scheme uses an AEAD (or encrypt-then-MAC) with unique nonces, binds method, path, session and a timestamp or request ID into the authenticated data, and the server rejects replays, cross-context reuse and modified envelopes with a uniform error.

#### Demo

A minimal envelope that passes, in Kotlin (the key comes from the attested handshake in [Secure implementation](#secure-implementation)):

```kotlin
fun seal(key: SecretKey, method: String, path: String, sessionId: String, body: ByteArray): Envelope {
    val requestId = UUID.randomUUID().toString()
    val ts = System.currentTimeMillis() / 1000
    val aad = "$method\n$path\n$sessionId\n$ts\n$requestId".toByteArray()
    val c = Cipher.getInstance("AES/GCM/NoPadding")
    c.init(Cipher.ENCRYPT_MODE, key)          // provider generates a fresh 12-byte IV
    c.updateAAD(aad)
    return Envelope(iv = c.iv, ct = c.doFinal(body), ts = ts, requestId = requestId)
}
```

Illustrative probe results for a scheme that fails only on replay:

```text
identical plaintext x2     -> different IV and ciphertext          OK
bit flip in ciphertext     -> 400 {"error":"bad_request"}          OK (uniform error)
envelope moved to /profile -> 400 {"error":"bad_request"}          OK (path in AAD)
same request after 10 min  -> 200, second transfer created         FAIL (no replay check)
```

## Secure implementation

### Design checklist

- TLS with correct validation everywhere; pinning where the threat model calls for it.
- Encrypt to the **server's public key** (HPKE, JWE `ECDH-ES`), so the app needs no shared secret to encrypt.
- Sign or MAC with a **per-install hardware key**, registered with key attestation (Android) or App Attest (iOS), bound to the account at enrolment.
- **AEAD only**, fresh random nonce per message, never a fixed IV.
- **Authenticated context**: method, path, session or account ID, timestamp, request ID. Server keeps a replay cache for the timestamp window.
- **Responses**: encrypt with a key derived from the request's envelope (HPKE `exportSecret`, OHTTP style) where they carry sensitive data.
- **Uniform errors**, logging of failures server-side, rate limits on failures.
- **No plaintext fallback** in production, on client or server.
- Obfuscate and integrity-check the envelope code ([MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/), [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/)), and treat the whole layer as defence in depth: every authorisation and business-rule check stays on the server.

### Android: attested signing key and AEAD envelope

Generate the per-install signing key once, with an attestation challenge from the server, and register the attestation chain:

```kotlin
fun enrolSigningKey(serverChallenge: ByteArray): List<ByteArray> {
    val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
    kpg.initialize(
        KeyGenParameterSpec.Builder("api-signing", KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(serverChallenge)
            .build()
    )
    kpg.generateKeyPair()
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    return ks.getCertificateChain("api-signing").map { it.encoded }   // send to server for verification
}

fun signEnvelope(envelopeBytes: ByteArray): ByteArray {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val key = ks.getKey("api-signing", null) as PrivateKey
    return Signature.getInstance("SHA256withECDSA").run { initSign(key); update(envelopeBytes); sign() }
}
```

The server verifies the attestation chain once (root, challenge, package name and signing certificate digest, security level), stores the public key against the account, and from then on checks the signature over each envelope, including its timestamp and request ID. Encrypt the body itself with the `seal()` function from GT-RES-0062-3, using a session key from an ECDH exchange with the server (Tink's hybrid encryption primitives save you from writing the key schedule yourself).

### iOS: HPKE envelope and App Attest assertion

On iOS 17 and later, CryptoKit's HPKE encrypts to the server's public key without any secret in the app, and App Attest signs a hash of the envelope with a Secure Enclave key whose counter gives replay protection:

```swift
import CryptoKit
import DeviceCheck

func makeEnvelope(body: Data, aad: Data, serverKey: Curve25519.KeyAgreement.PublicKey,
                  appAttestKeyId: String) async throws -> (enc: Data, ct: Data, assertion: Data) {
    var sender = try HPKE.Sender(recipientKey: serverKey,
                                 ciphersuite: .Curve25519_SHA256_ChachaPoly,
                                 info: Data("api-v2".utf8))
    let ct = try sender.seal(body, authenticating: aad)          // aad: method, path, session, ts, request id
    let digest = Data(SHA256.hash(data: sender.encapsulatedKey + ct + aad))
    let assertion = try await DCAppAttestService.shared.generateAssertion(appAttestKeyId,
                                                                       clientDataHash: digest)
    return (sender.encapsulatedKey, ct, assertion)
}
```

The server opens the envelope with its HPKE private key, verifies the assertion against the App Attest public key it registered for this install, checks the counter has increased and checks the timestamp and request ID. For encrypted responses, derive the response key from the same HPKE context (`exportSecret`) so that a response only opens for the request that asked for it. For apps that support iOS versions before 17, use an ECDH (P-256) exchange with HKDF and `AES.GCM` instead.

## Rating findings

Missing application-level payload encryption is a **resilience** gap. It raises nothing an attacker cannot eventually get on a device they control, and it never replaces TLS, certificate validation or server-side authorisation. Rate it accordingly:

| Rating | Conditions |
|---|---|
| **Info** | App outside the R profile: plaintext payloads inside correct TLS are normal. Also, for an R-profile app, envelope present and sound but the code that builds it is easy to find and hook (record the effort as an observation, with an obfuscation recommendation). |
| **Low** | R-profile app with no payload encryption, or partial coverage, where the exposed payloads do not carry security-relevant state the server relies on; a correctly built envelope whose responses are plaintext. |
| **Medium** | R-profile app where the absence or weakness of the layer directly helps a documented abuse: a static app-wide key that the server treats as proof of a genuine client (any script that has the key can mint requests); replay of envelopes on state-changing endpoints; unauthenticated encryption or nonce reuse on security-relevant endpoints; a plaintext fallback accepted by the server. |
| **High** | The same, where the abuse has direct business or user impact the owner cares about: replayable or forgeable payment, transfer or account-creation requests that bots are already abusing, or a hard-coded key that also decrypts sensitive user data captured elsewhere (logs, intermediaries behind the TLS terminator). |

Adjustments:

- **Rate the root cause where it lives.** A hard-coded key is also a [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/) finding. Broken modes are [MASWE-0007](/mobile/maswe-0007-improper-encryption/). A server that trusts a client-supplied price or score is a server-side authorisation finding, often more severe than anything here, and adding encryption does not fix it.
- **Custom encryption instead of TLS** (envelope over cleartext HTTP) is rated under [MASWE-0026](/mobile/maswe-0026-cleartext-network-traffic/), with the quality of the envelope as a mitigating or aggravating factor.
- **A control that exists but falls to one hook** is rated by what the hook unlocks. One `frida-trace` command that shows every plaintext request usually means the layer costs an attacker minutes; say so, and rate the finding by what plaintext and forgery access then allows.
- **Never Critical** on its own. Critical impact belongs to the server-side flaw the missing layer made easier to find.

In the report, give the endpoint inventory, the envelope format, the key source and how it was found (file and class, or the trace output), the probe results from GT-RES-0062-3, the effort it took, and the concrete design change (server public key, attested per-install key, AAD content, replay window).

## References

- OWASP MASWE: [MASWE-0062: No Application-Level Payload Encryption](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0062/); related [MASWE-0026](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/), [MASWE-0028](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/), [MASWE-0063](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0063/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-RESILIENCE-3](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/), [MASVS-NETWORK-1](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/) (CC BY-SA 4.0)
- Sibling notes in this series: [MASWE-0063 debug mechanisms not disabled](/mobile/maswe-0063-debug-mechanisms-not-disabled/), [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/), [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/), [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/), [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/), [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/)
- IETF: [RFC 7515 JWS](https://www.rfc-editor.org/rfc/rfc7515), [RFC 7516 JWE](https://www.rfc-editor.org/rfc/rfc7516), [RFC 7518 JWA](https://www.rfc-editor.org/rfc/rfc7518), [RFC 9052 COSE](https://www.rfc-editor.org/rfc/rfc9052), [RFC 9180 HPKE](https://www.rfc-editor.org/rfc/rfc9180), [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421), [RFC 9458 Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458)
- Android: [Android Keystore system](https://developer.android.com/privacy-and-security/keystore), [Verifying hardware-backed key pairs with key attestation](https://developer.android.com/privacy-and-security/security-key-attestation), [Play Integrity: standard API requests](https://developer.android.com/google/play/integrity/standard), [Tink](https://developers.google.com/tink)
- Apple: [Establishing your app's integrity (App Attest)](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity), [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server), [CryptoKit HPKE](https://developer.apple.com/documentation/cryptokit/hpke), [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- Frida: [frida-trace](https://frida.re/docs/frida-trace/), [JavaScript API](https://frida.re/docs/javascript-api/)
- CWE: [CWE-319](https://cwe.mitre.org/data/definitions/319.html), [CWE-321](https://cwe.mitre.org/data/definitions/321.html) (hard-coded key), [CWE-294](https://cwe.mitre.org/data/definitions/294.html) (capture-replay)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
