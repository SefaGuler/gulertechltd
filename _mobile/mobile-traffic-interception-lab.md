---
title: "Intercepting Mobile App Traffic: Lab Setup and Techniques (MASVS-NETWORK)"
date: 2026-11-09 16:04:00 +0000
subcategory: network
summary: "Building an Android and iOS interception lab: proxy CAs (incl. Android 14 APEX), Burp and mitmproxy modes, non-proxy-aware apps, QUIC, Frida, evidence."
refs: [MASVS-NETWORK-1, MASVS-NETWORK-2, MASTG-TECH-0011, MASTG-TECH-0063, MASTG-TECH-0120]
tags: [android, ios, masvs-network, interception, mitmproxy, burp]
---

This note is the lab manual for our [MASVS-NETWORK guide](/mobile/masvs-network-secure-communication-guide/). Every dynamic test in the series — cleartext traffic, TLS versions, certificate validation, pinning — starts with the same question: can you see the app's traffic, and what did you have to change on the device to see it? The answer is both a prerequisite and evidence. An app whose traffic you can read after doing nothing more than joining your Wi-Fi is a different finding from one you could only read after installing a system CA on a rooted phone and patching out a pin. Below you will find how to choose an interception position, a complete Android lab (emulator and rooted device, user vs system CAs, the Android 14 Conscrypt APEX store, Network Security Configuration overrides, `adb reverse`, iptables), an iOS lab (Wi-Fi proxy, profile trust, `rvictl` packet capture), Burp Suite and mitmproxy configuration, what to do when the app ignores the proxy (rogue access point, ARP spoofing, passive capture, Flutter, Xamarin, QUIC), Frida hooks for when interception is not practical, what evidence to keep, a troubleshooting table, and the rules for doing this lawfully.

## Contents

- [Choosing an interception position](#choosing-an-interception-position)
  - [Know the endpoints first](#know-the-endpoints-first)
  - [Why apps ignore the system proxy](#why-apps-ignore-the-system-proxy)
  - [Certificate pinning](#certificate-pinning)
- [Android lab](#android-lab)
  - [Emulator or rooted device](#emulator-or-rooted-device)
  - [Getting traffic to the proxy](#getting-traffic-to-the-proxy)
  - [Exporting the proxy CA and naming it](#exporting-the-proxy-ca-and-naming-it)
  - [Installing the CA as a user CA](#installing-the-ca-as-a-user-ca)
  - [Installing the CA as a system CA up to Android 13](#installing-the-ca-as-a-system-ca-up-to-android-13)
  - [Installing the CA as a system CA on Android 14 and later](#installing-the-ca-as-a-system-ca-on-android-14-and-later)
  - [Why apps targeting API 24 and above ignore your user CA](#why-apps-targeting-api-24-and-above-ignore-your-user-ca)
  - [Redirecting with iptables on a rooted device](#redirecting-with-iptables-on-a-rooted-device)
  - [Proxy and VPN detection](#proxy-and-vpn-detection)
- [iOS lab](#ios-lab)
  - [Wi-Fi proxy](#wi-fi-proxy)
  - [Installing and fully trusting the CA](#installing-and-fully-trusting-the-ca)
  - [Packet capture with rvictl](#packet-capture-with-rvictl)
  - [Jailbroken and non-jailbroken devices](#jailbroken-and-non-jailbroken-devices)
- [Proxy configuration](#proxy-configuration)
  - [Burp Suite](#burp-suite)
  - [mitmproxy](#mitmproxy)
  - [ZAP](#zap)
  - [One lab CA for every tool](#one-lab-ca-for-every-tool)
- [Non-HTTP and non-proxy-aware traffic](#non-http-and-non-proxy-aware-traffic)
  - [Rogue access point (MASTG-TECH-0124)](#rogue-access-point-mastg-tech-0124)
  - [ARP spoofing (MASTG-TECH-0123)](#arp-spoofing-mastg-tech-0123)
  - [DNS redirection](#dns-redirection)
  - [Passive eavesdropping (MASTG-TECH-0122)](#passive-eavesdropping-mastg-tech-0122)
  - [Non-HTTP protocols through a proxy (MASTG-TECH-0121)](#non-http-protocols-through-a-proxy-mastg-tech-0121)
  - [Flutter (MASTG-TECH-0109 and MASTG-TECH-0110)](#flutter-mastg-tech-0109-and-mastg-tech-0110)
  - [Xamarin (MASTG-TECH-0125)](#xamarin-mastg-tech-0125)
  - [QUIC and HTTP/3](#quic-and-http3)
  - [Push notifications](#push-notifications)
- [Application-layer hooking](#application-layer-hooking)
  - [Android: logging OkHttp requests](#android-logging-okhttp-requests)
  - [iOS: logging URLSession requests](#ios-logging-urlsession-requests)
  - [Native TLS libraries](#native-tls-libraries)
- [Capturing evidence](#capturing-evidence)
- [Troubleshooting](#troubleshooting)
- [Ethics and scope](#ethics-and-scope)
- [References](#references)

## Choosing an interception position

OWASP describes the generic approach in [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/): run an interception proxy on your host, route the app's HTTP(S) to it, and install the proxy's CA on the device so the TLS connections it terminates are accepted. That works for most native apps. When it does not, the reason is almost always one of two things: the traffic never reaches the proxy, or it reaches the proxy and the app refuses the certificate. Pick the position that solves the first problem; the second is solved on the device (CA trust, Network Security Configuration, pinning bypass).

| Position | How you get it | What you see | What it needs | When it fails |
|---|---|---|---|---|
| **System proxy** | Wi-Fi proxy setting, `adb shell settings put global http_proxy`, emulator `-http-proxy` | HTTP and HTTPS from proxy-aware stacks (OkHttp, `HttpURLConnection`, URLSession, WebViews) | Device and host reachable; CA trusted for HTTPS | App ignores the proxy (see below), uses QUIC, or detects the proxy |
| **VPN-based redirect** | mitmproxy `--mode wireguard` with the WireGuard app; HTTP Toolkit; PCAPdroid (capture) | All TCP/UDP the OS routes into the tunnel, including non-proxy-aware apps; original destination preserved | No root or jailbreak; CA trusted for TLS | App detects the VPN; app or OS excludes traffic from the tunnel |
| **Transparent redirect on the device** | iptables `nat OUTPUT` DNAT on a rooted Android device; ProxyDroid | Whatever ports you redirect, per app if you match the UID | Root; proxy in invisible/transparent mode | IPv6 or UDP not redirected; DNAT hides the original destination from the proxy |
| **Rogue access point** | Your host is the AP (hostapd/dnsmasq, macOS Internet Sharing) plus a redirect rule | Every packet from the device, any OS, any app | Spare Wi-Fi interface or travel router | Device on mobile data; apps pin; DoH/DoT bypasses your DNS |
| **ARP spoofing** | bettercap on the same LAN | IPv4 traffic between device and gateway | Same L2 segment, no client isolation, no dynamic ARP inspection | IPv6, managed networks, client isolation; noisy |
| **DNS redirection** | Hosts entry or spoofed DNS answer pointing an API host at your proxy | Traffic to the redirected hostnames only | Control of DNS or root; listener on the original port | Hard-coded IPs, DoH/DoT, Private DNS |
| **Passive capture** | tcpdump on a rooted device, emulator `-tcpdump`, `rvictl` on macOS, capture on the AP | Every packet, but TLS stays encrypted | Root, macOS + USB for iOS, or the AP | Not a MITM: you cannot read or modify TLS payloads without keys |
| **App-layer hooking** | Frida on OkHttp, URLSession, `SSL_read`/`SSL_write` | Plaintext before encryption and after decryption, regardless of protocol or pinning | Instrumentation (root/jailbreak or a repackaged app with Frida Gadget) | Custom stacks, obfuscation, anti-instrumentation |
| **Patching the app** | Repackaging with a permissive NSC, reFlutter, Xamarin proxy patch | Depends on the patch | Re-signing; app tolerates a new signature | Integrity and signature checks |

Start at the top of the table and move down only when you have a reason. A system proxy with a trusted CA reproduces the attacker who controls the Wi-Fi and has persuaded the user to install a profile or certificate; a VPN, rogue AP or ARP spoofing reproduces the attacker who only controls the network. That difference matters when you rate cleartext and certificate-validation findings later: if the app accepts your proxy's certificate *without* any CA installed, you have found [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/), not a lab configuration.

### Know the endpoints first

[MASTG-TECH-0022](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0022/) (Android) and [MASTG-TECH-0074](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0074/) (iOS) recommend enumerating the hosts the app talks to before you capture anything. You get a list to compare the capture against (anything missing from the proxy is going somewhere else), host patterns for your proxy's allow and ignore lists, and the domains that the Network Security Configuration or pinning code refers to.

```bash
# Android: decompile and extract URLs with context
apktool d app.apk -o app_src
grep -rhoE 'https?://[A-Za-z0-9._~:/?#@!&()*+,;=%-]+' app_src | sort -u > urls.txt
apkleaks -f app.apk -o apkleaks.txt

# Network Security Configuration (MASTG-TECH-0151)
grep -o 'networkSecurityConfig="[^"]*"' app_src/AndroidManifest.xml
grep -n -E 'certificates|pin-set|cleartextTrafficPermitted|debug-overrides' app_src/res/xml/network_security_config.xml

# iOS: strings from the decrypted main binary and the Info.plist ATS block
strings -a Payload/Example.app/Example | grep -Eo 'https?://[^"[:space:]]+' | sort -u > urls.txt
plutil -p Payload/Example.app/Info.plist | grep -A 20 NSAppTransportSecurity
```

[MASTG-TECH-0151](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0151/) also shows `yq` queries for the NSC (for example `yq -p=xml -o=json '.' network_security_config.xml` to convert it to JSON for `jq`). Grep results in decompiled code give you the class and method that use each host, which is useful context when a request later fails only for one endpoint. Strings are a starting point only: hosts are often built at runtime or delivered by remote configuration, and OWASP is right that dynamic capture is the reliable source.

### Why apps ignore the system proxy

The system proxy is a hint that each networking library may or may not honour. Expect to see nothing in the proxy when:

- **The app uses Flutter.** Dart's `HttpClient` does not read the platform proxy settings and validates certificates inside the engine's own BoringSSL rather than through the platform trust APIs. See [Flutter](#flutter-mastg-tech-0109-and-mastg-tech-0110).
- **The app uses Xamarin's managed HTTP stack.** See [Xamarin](#xamarin-mastg-tech-0125).
- **The client was told not to.** On Android, `OkHttpClient.Builder().proxy(Proxy.NO_PROXY)` or `HttpURLConnection` opened with `Proxy.NO_PROXY` skips the system proxy by design; some security SDKs do this deliberately.
- **The app uses raw sockets.** MQTT, XMPP, WebRTC, gRPC over a custom channel, game protocols and anything built on BSD sockets or Network.framework's `NWConnection` do not go through an HTTP proxy.
- **The traffic is QUIC/HTTP/3.** It is UDP; an HTTP proxy only carries TCP. See [QUIC and HTTP/3](#quic-and-http3).
- **The app checks for a proxy** and refuses to work. See [Proxy and VPN detection](#proxy-and-vpn-detection).
- **The connection was opened before you set the proxy.** Pooled HTTP/2 connections survive a settings change. Force-stop the app after every change to the network setup.

React Native, Cordova/Capacitor and Kotlin Multiplatform apps generally use the platform stacks (OkHttp, URLSession, the system WebView) and behave like native apps.

### Certificate pinning

If the app pins, a trusted CA is not enough: the app compares the server's certificate or public key with values it ships with and rejects your proxy's leaf even though the OS accepts it. How to recognise pinning, which implementation is in use, and how to bypass it with objection, Frida, NSC `overridePins` and patching (OWASP [MASTG-TECH-0012](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012/) and [MASTG-TECH-0064](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0064/)) is covered in [MASWE-0028: Insecure Identity Pinning](/mobile/maswe-0028-insecure-identity-pinning/).

## Android lab

OWASP's Android setup is [MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/). What follows is that technique brought up to date for Android 14 and later, with the commands we use.

### Emulator or rooted device

| | Android Emulator (AVD) | Rooted physical device |
|---|---|---|
| Root | `adb root` works on **Google APIs** system images; it does not on **Google Play** images | Magisk (or KernelSU/APatch); `su` from `adb shell` |
| Writable `/system` | `emulator -avd <name> -writable-system`, then `adb root`, `adb shell avbctl disable-verification`, `adb reboot`, `adb root`, `adb remount` | Not practical on modern devices (dm-verity, read-only `system` partitions); use tmpfs/bind mounts or a Magisk module |
| Proxy | Extended controls → Settings → Proxy, or `emulator -avd <name> -http-proxy 127.0.0.1:8080`; host loopback is reachable from the guest as `10.0.2.2` | Wi-Fi proxy, `settings put global http_proxy`, `adb reverse` |
| Packet capture | `emulator -avd <name> -tcpdump emu.pcap` captures the guest's traffic without root | tcpdump as root |
| Weak spots | Root/emulator detection; apps that ship only ARM libraries on an x86_64 image; no Play Integrity | Hardware-backed attestation fails once unlocked; vendor ROM quirks |

Use the emulator for quick checks and for anything that needs a writable `/system`; use a physical device (a Pixel is the least troublesome) for apps that detect emulators or depend on Google Play services. On Apple Silicon Macs use `arm64-v8a` images, which avoids most ABI problems.

### Getting traffic to the proxy

The proxy host is `192.168.1.10` and the proxy listens on `8080` in all examples.

**Wi-Fi proxy.** Settings → Network & internet → Internet → (your network) → edit → Advanced options → Proxy: Manual, host `192.168.1.10`, port `8080`. The menu path differs between vendors. Turn off mobile data on the device so nothing leaves by the cellular interface.

**From adb.** The global HTTP proxy setting does the same without touching the Wi-Fi configuration and also applies on the emulator:

```bash
adb shell settings put global http_proxy 192.168.1.10:8080
adb shell settings get global http_proxy
# remove it again (":0" takes effect immediately; deleting the key may need a reboot)
adb shell settings put global http_proxy :0
```

This setting is device-wide, although it is sometimes described as a per-app proxy. For real per-app routing use the WireGuard app's per-application tunnel list with mitmproxy's WireGuard mode ([mitmproxy](#mitmproxy)), or an iptables rule matched on the app's UID ([below](#redirecting-with-iptables-on-a-rooted-device)).

**Over USB with `adb reverse`.** When the Wi-Fi has client isolation (common on guest and corporate networks, as MASTG-TECH-0011 notes) or you do not want the proxy reachable from the network at all, tunnel the proxy port over the USB connection:

```bash
adb reverse tcp:8080 tcp:8080
adb shell settings put global http_proxy 127.0.0.1:8080
adb reverse --list
# clean up
adb reverse --remove-all
adb shell settings put global http_proxy :0
```

The device's internet connectivity still comes from its own Wi-Fi; only the proxy hop runs over USB. Your proxy can then listen on `127.0.0.1` only, which is the safest listener there is.

Check the listener from the host before you blame the device:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -x http://127.0.0.1:8080 -k https://example.com/
```

### Exporting the proxy CA and naming it

Each proxy generates its own CA on first start.

- **Burp:** browse to `http://burp` from a proxied device or browser and choose *CA Certificate* (you get `cacert.der`), or Proxy → Proxy settings → *Import / export CA certificate* → *Certificate in DER format*.
- **mitmproxy:** the files are in `~/.mitmproxy/`. `mitmproxy-ca-cert.pem` is the certificate in PEM, `mitmproxy-ca-cert.cer` is the same PEM with the extension some Android versions expect. From a proxied device, `http://mitm.it` serves them with per-platform instructions.

Android's system store names each certificate after the **old-style (MD5-based) OpenSSL subject hash** with a `.0` suffix; the hash that OpenSSL 1.0+ prints by default with `-subject_hash` uses SHA-1 and gives a different name, which Android will not find. Compute the name and convert to PEM:

```bash
# Burp exports DER; convert to PEM first
openssl x509 -inform DER -in cacert.der -out proxy-ca.pem
# (for mitmproxy: cp ~/.mitmproxy/mitmproxy-ca-cert.pem proxy-ca.pem)

HASH=$(openssl x509 -inform PEM -subject_hash_old -noout -in proxy-ca.pem)
cp proxy-ca.pem "${HASH}.0"
echo "${HASH}.0"
```

If two certificates in the store share a subject hash, the second is named `.1`. The system store files are plain PEM; some guides append the `-text` output, which Android ignores.

### Installing the CA as a user CA

Push the certificate and install it from Settings:

```bash
adb push proxy-ca.pem /sdcard/Download/proxy-ca.crt
```

On Android 11 and later: Settings → Security & privacy → More security settings → Encryption & credentials → Install a certificate → **CA certificate** → accept the warning → pick the file. Older versions have *Install from storage* under Security. A screen lock is required. Apps can no longer install CA certificates for the user through `KeyChain.createInstallIntent()` since Android 11, so do not look for a shortcut; the Settings flow is the only route without root.

The certificate lands in `/data/misc/user/0/cacerts-added/` (already named `<hash>.0`) and appears under Trusted credentials → User. Chrome trusts it, which makes Chrome a good first test. Most apps do not: see [Why apps targeting API 24 and above ignore your user CA](#why-apps-targeting-api-24-and-above-ignore-your-user-ca).

### Installing the CA as a system CA up to Android 13

On Android 7 to 13, Conscrypt reads system CAs from `/system/etc/security/cacerts/`. Three ways to get your certificate there on a rooted device or a root-capable emulator:

1. **Writable system on the emulator.** Start with `-writable-system`, remount as shown in the [table above](#emulator-or-rooted-device), then:

    ```bash
    adb push "${HASH}.0" /system/etc/security/cacerts/
    adb shell chmod 644 "/system/etc/security/cacerts/${HASH}.0"
    adb reboot
    ```

    You must start the AVD with `-writable-system` every time afterwards, or the change is not visible.

2. **A Magisk module.** MASTG-TECH-0011 points to NVISO's *MagiskTrustUserCerts*, which copies every user-installed CA into the system store systemlessly at boot: install the CA as a user CA, install the module from the Magisk app, reboot, and check Trusted credentials → System.

3. **A temporary tmpfs overlay** (no reboot, lost at the next reboot). Run as root on the device, with your `<hash>.0` file pushed to `/data/local/tmp/`:

    ```bash
    mkdir -m 700 /data/local/tmp/ca-copy
    cp /system/etc/security/cacerts/* /data/local/tmp/ca-copy/
    mount -t tmpfs tmpfs /system/etc/security/cacerts
    mv /data/local/tmp/ca-copy/* /system/etc/security/cacerts/
    cp /data/local/tmp/*.0 /system/etc/security/cacerts/
    chown root:root /system/etc/security/cacerts/*
    chmod 644 /system/etc/security/cacerts/*
    chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*
    ```

    Restart the target app afterwards so it reloads the trust store.

MASTG-TECH-0011's manual method (`mount -o rw,remount /system` and copying the file) only works on older devices where `/system` can be remounted; on system-as-root devices from Android 10 onwards it usually fails.

### Installing the CA as a system CA on Android 14 and later

From Android 14 the system CA certificates are delivered inside the Conscrypt APEX module so that Google can update them through Google Play system updates. Conscrypt reads them from **`/apex/com.android.conscrypt/cacerts/`**; `/system/etc/security/cacerts/` still exists but is no longer used for trust decisions. Anything that only writes to the old directory — a manual copy, the tmpfs trick above, Magisk modules written before Android 14 — has no effect, and the symptom is a CA that is listed nowhere useful while every app still rejects the proxy.

APEX mounts are read-only and the mount is set up per process: each app inherits the mount namespace of Zygote when it is forked. The working technique, published by Tim Perry of HTTP Toolkit, builds a tmpfs with the full store plus your CA and bind-mounts it over the APEX directory inside the mount namespaces of Zygote (for apps started later) and of every running app. Run as root on the device (`adb shell`, then `su`), with your `<hash>.0` in `/data/local/tmp/`:

```bash
# 1. Build a tmpfs containing the current system CAs plus ours
mkdir -p -m 700 /data/local/tmp/ca-copy
cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/ca-copy/
mount -t tmpfs tmpfs /system/etc/security/cacerts
mv /data/local/tmp/ca-copy/* /system/etc/security/cacerts/
cp /data/local/tmp/*.0 /system/etc/security/cacerts/
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*

# 2. Bind it over the APEX directory in Zygote's namespace (affects apps started from now on)
for Z in $(pidof zygote) $(pidof zygote64); do
  nsenter --mount=/proc/$Z/ns/mnt -- \
    /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts
done

# 3. ...and in every app that is already running
for Z in $(pidof zygote) $(pidof zygote64); do
  for P in $(ps -o PID -P "$Z" | grep -v PID); do
    nsenter --mount=/proc/$P/ns/mnt -- \
      /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts
  done
done
```

Verify from the device that an app's view contains your certificate (`ls /apex/com.android.conscrypt/cacerts/ | grep <hash>` inside `nsenter --mount=/proc/<app pid>/ns/mnt`) and that Trusted credentials → System lists it. The change disappears at reboot; keep the script in `/data/local/tmp/` and re-run it. Magisk modules exist that do the same at boot; before relying on one, check that it explicitly supports the Android 14 APEX store. HTTP Toolkit's automatic Android setup and mitmproxy's documentation for system-trusted CAs on the emulator cover the same ground.

A system CA defeats the default "trust only system CAs" behaviour of every app on the device, but not an app-specific `<trust-anchors>` that lists only bundled certificates, not NSC pins, and not pinning in code.

### Why apps targeting API 24 and above ignore your user CA

Android 7.0 (API 24) introduced the Network Security Configuration and changed the default trust anchors. For an app with `targetSdkVersion` 24 or higher and no NSC saying otherwise, the default is "system CAs only". Apps targeting 23 or lower still trust user CAs by default. The [Android documentation](https://developer.android.com/privacy-and-security/security-config) and the [2016 announcement](https://android-developers.googleblog.com/2016/07/changes-to-trusted-certificate.html) describe the change; the security reason is that a user can be talked into installing a CA, and before this change that silently gave the installer every app's traffic.

Four things change the picture:

- **The app's NSC trusts user CAs.** `<certificates src="user" />` in `<base-config>` or in a `<domain-config>` makes your user CA work for those domains. If you find this in a release build, it is a finding in its own right ([MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/)).
- **`<debug-overrides>`.** Trust anchors inside `<debug-overrides>` apply **only** when the app is debuggable (`android:debuggable="true"`, which Gradle sets for debug builds). A development build from the client with this block is the cleanest way to test:

    ```xml
    <network-security-config>
        <base-config>
            <trust-anchors>
                <certificates src="system" />
            </trust-anchors>
        </base-config>
        <debug-overrides>
            <trust-anchors>
                <certificates src="user" />
            </trust-anchors>
        </debug-overrides>
    </network-security-config>
    ```

    Making a release APK debuggable by repackaging does **not** make it trust user CAs unless the NSC also contains a `<debug-overrides>` block; debuggability alone changes nothing about trust.

- **Repackaging with a permissive NSC.** MASTG-TECH-0011's approach: decode, add or edit the NSC, rebuild, re-sign.

    ```bash
    apktool d app.apk -o app_src
    # edit app_src/res/xml/network_security_config.xml, or create it and add
    #   android:networkSecurityConfig="@xml/network_security_config"
    # to the <application> element in app_src/AndroidManifest.xml
    apktool b app_src -o app-patched.apk
    zipalign -p -f 4 app-patched.apk app-aligned.apk
    keytool -genkeypair -keystore lab.keystore -alias lab -keyalg RSA -keysize 2048 -validity 3650
    apksigner sign --ks lab.keystore --ks-key-alias lab --out app-signed.apk app-aligned.apk
    adb install -r app-signed.apk
    ```

    Patch every `<domain-config>` that declares its own `<trust-anchors>`, not just `<base-config>`: domain-specific anchors replace the base ones for those domains. Apps installed from an app bundle consist of several APKs (`adb shell pm path com.example.app` lists them); pull them all, sign every split with the same key, and install with `adb install-multiple`. Tools such as Android-CertKiller (mentioned by OWASP) and apk-mitm automate the patch. A changed signature trips signature checks, Play Integrity and some SDKs' tamper detection, so prefer a system CA when you can.

- **A system CA.** As above, without touching the app.

Order of preference for a client test: debug build with `<debug-overrides>` → system CA on a rooted device or emulator → repackaging. In the report, say which one you used.

### Redirecting with iptables on a rooted device

For apps that ignore the proxy, redirect their TCP connections at the device's own netfilter, as MASTG-TECH-0011 and [MASTG-TECH-0109](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0109/) describe. Matching on the app's UID keeps the rest of the device out of your proxy:

```bash
APP_UID=$(adb shell dumpsys package com.example.app | grep -m1 -o 'userId=[0-9]*' | cut -d= -f2)
echo "$APP_UID"

adb shell su -c "iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner $APP_UID --dport 443 -j DNAT --to-destination 192.168.1.10:8080"
adb shell su -c "iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner $APP_UID --dport 80 -j DNAT --to-destination 192.168.1.10:8080"
# stop IPv6 and QUIC bypassing the rule: force the app back to IPv4 TCP
adb shell su -c "ip6tables -A OUTPUT -m owner --uid-owner $APP_UID -j REJECT"
adb shell su -c "iptables -A OUTPUT -p udp -m owner --uid-owner $APP_UID --dport 443 -j REJECT"

adb shell su -c "iptables -t nat -L OUTPUT -n -v"
```

Remove the rules with the same commands using `-D` instead of `-A` (or `iptables -t nat -F OUTPUT`; flushing whole tables also removes rules Android's `netd` installed, so prefer `-D` and reboot if in doubt).

DNAT rewrites the destination, so the proxy receives a connection that does not start with an HTTP `CONNECT` and cannot recover the original destination from the socket. **Burp** handles this with *Support invisible proxying* on the listener (it routes by the `Host` header and the TLS SNI). mitmproxy's `transparent` mode does not help here, because it looks up the original destination in the netfilter or pf state *of the machine it runs on*, and the rewrite happened on the phone. With mitmproxy, use WireGuard mode instead. ProxyDroid ([MASTG-TOOL-0120](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0120/)) wraps the same iptables approach in an app; it needs root, only redirects ports 80, 443 and 5228, and needs a transparent/invisible listener.

### Proxy and VPN detection

Some apps refuse to work when a proxy or VPN is configured. They typically read `System.getProperty("http.proxyHost")`, `ConnectivityManager.getDefaultProxy()` or `ProxyInfo` (MASTG-TECH-0011 shows a Frida override for a custom `isProxySet()`), or check `NetworkCapabilities.hasTransport(TRANSPORT_VPN)`. Two options:

- Move to a position the app cannot see: iptables redirect instead of a proxy setting, rogue AP instead of a VPN.
- Override the check with Frida. Find the real check in the decompiled code first; the generic hook below hides the JVM proxy properties:

```javascript
Java.perform(function () {
  var System = Java.use('java.lang.System');
  var hidden = ['http.proxyHost', 'https.proxyHost', 'http.proxyPort', 'https.proxyPort'];
  System.getProperty.overload('java.lang.String').implementation = function (key) {
    if (hidden.indexOf(key) !== -1) {
      return null;
    }
    return this.getProperty(key);
  };
});
```

Proxy detection is a resilience control (MASVS-RESILIENCE), not a network security control; note it in the report and move on.

## iOS lab

OWASP's iOS setup is [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/) for the proxy and [MASTG-TECH-0062](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0062/) for packet capture.

### Wi-Fi proxy

Settings → Wi-Fi → ⓘ next to the network → Configure Proxy → **Manual**, Server `192.168.1.10`, Port `8080`. The setting is per Wi-Fi network and does not apply to mobile data, so:

- turn off Mobile Data, or at least Wi-Fi Assist (Settings → Mobile Data → Wi-Fi Assist), which otherwise moves traffic to cellular when Wi-Fi looks poor;
- turn off iCloud Private Relay and *Limit IP Address Tracking* for the network on a test device, so Safari and system traffic do not take a different path from the app.

URLSession and WKWebView honour the proxy. Network.framework connections (`NWConnection`) and BSD sockets do not use the HTTP proxy for raw TCP.

**Client isolation.** If the network will not let the phone reach your host, OWASP's MASTG-TECH-0063 shows a USB route for jailbroken devices: forward SSH over USB with `iproxy 2222 22` ([MASTG-TOOL-0055](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0055/)), open a reverse tunnel with `ssh -R 8080:localhost:8080 mobile@localhost -p 2222`, and set the Wi-Fi proxy to `127.0.0.1:8080`. On a non-jailbroken device there is no SSH; use a network you control instead (macOS Internet Sharing, a travel router, or mitmproxy's WireGuard mode, which only needs UDP 51820 to reach your host).

**Simulator.** The iOS Simulator uses the Mac's network settings, so set the proxy on macOS and add the CA with `xcrun simctl keychain booted add-root-cert ~/.mitmproxy/mitmproxy-ca-cert.pem`. It runs simulator builds only, not App Store IPAs, so it is useful when the developer gives you a build and not otherwise.

### Installing and fully trusting the CA

1. With the proxy set, open Safari (not another browser) and go to `http://burp` (Burp; choose *CA Certificate*) or `http://mitm.it` (mitmproxy; choose iOS). Allow the configuration profile download.
2. Settings → *Profile Downloaded* (or Settings → General → VPN & Device Management on iOS 15 and later; *Profiles* on older versions) → Install, and enter the passcode.
3. **Settings → General → About → Certificate Trust Settings → enable full trust for the root certificate.**

Step 3 is the one people miss. Since iOS 10.3, a root certificate installed manually through a profile is *installed* but not trusted for TLS until you switch it on in Certificate Trust Settings. Until you do, Safari shows a certificate warning and apps fail the handshake. Profiles installed by an MDM are trusted automatically, which is why a CA can appear trusted on a managed device and not on your test phone.

If you generate your own CA for iOS, the leaf certificates your proxy issues must meet Apple's requirements from iOS 13: a `subjectAltName` with the DNS name, the `serverAuth` extended key usage, and a validity of 825 days or less. Burp and mitmproxy issue compliant leaves; hand-rolled proxies sometimes do not.

There is no user/system split on iOS: once fully trusted, the CA is accepted by every app that uses the default trust evaluation. If an app still fails, it pins (`NSPinnedDomains` in Info.plist, or code-level pinning), uses Flutter, or bundles its own trust store.

### Packet capture with rvictl

On macOS with Xcode installed you can capture everything the device sends, without a jailbreak, by creating a Remote Virtual Interface over USB:

```bash
idevice_id -l                       # UDID (libimobiledevice); Xcode's Devices window also shows it
rvictl -s <UDID>                    # creates rvi0
rvictl -l                           # list active interfaces
sudo tcpdump -i rvi0 -w ios.pcap    # or select rvi0 in Wireshark
rvictl -x <UDID>                    # remove it when done
```

The interface represents the device's whole network stack (Wi-Fi and cellular together; you cannot select one). It shows packets as they leave the device, so with a proxy configured you see connections to the proxy, and anything going *elsewhere* is traffic that ignores the proxy. That makes `rvictl` the fastest way to diagnose a non-proxy-aware iOS app. MASTG-TECH-0062 describes the filter `ip.addr == 192.168.1.1 && http` as a capture filter; it is Wireshark *display* filter syntax. The equivalent capture filter is `host 192.168.1.1 and tcp port 80`.

### Jailbroken and non-jailbroken devices

| Task | Non-jailbroken | Jailbroken |
|---|---|---|
| Proxy and CA | Yes | Yes |
| Packet capture | `rvictl` from a Mac | `rvictl`, or tcpdump on the device |
| Non-proxy-aware apps | WireGuard/VPN mode, rogue AP, ARP spoofing | Same, plus on-device tools |
| USB-only proxy path | No | `iproxy` + `ssh -R` |
| Frida | Only by injecting Frida Gadget into a decrypted, re-signed IPA (needs your own signing identity) | `frida-server`, attach to App Store apps |
| Pinning bypass | Only via a re-signed IPA with Gadget, or a developer build | objection, Frida scripts, tweaks |

App Store binaries are FairPlay-encrypted; you need a decrypted IPA (from a jailbroken device, or from the client) before you can patch or re-sign anything. On a non-jailbroken device, ask the client for a build with pinning disabled or a configuration that trusts your CA; it saves days and does not weaken the test as long as you test pinning separately on the release build.

## Proxy configuration

The three proxies OWASP lists ([MASTG-TOOL-0077](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/) Burp Suite, [MASTG-TOOL-0097](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/) mitmproxy, [MASTG-TOOL-0079](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0079/) ZAP) all do the job. We use Burp for manual testing and mitmproxy for scripting, WireGuard mode and long-running captures.

### Burp Suite

**Listener.** Proxy → Proxy settings → Proxy listeners → Add (or Edit the default):

- *Binding*: port `8080`; *Bind to address*: **Specific address** (your lab LAN IP) or **All interfaces**. The default `127.0.0.1` only accepts the host itself, and `adb reverse` setups. Avoid *All interfaces* on untrusted networks: anyone who can reach the port can use your proxy.
- *Request handling*: **Support invisible proxying** for any setup where the client does not know it is talking to a proxy (iptables DNAT, ARP spoofing, rogue AP, DNS redirection, reFlutter). Burp then accepts origin-form requests and TLS without a preceding `CONNECT`, routing by `Host` header and SNI. *Redirect to host / Redirect to port* and *Force use of TLS* send everything on that listener to one fixed upstream, which is what you want for DNS redirection of a single API host.
- *Certificate*: keep **Generate CA-signed per-host certificates** unless you have a reason.
- *HTTP*: HTTP/2 support is on by default and negotiated by ALPN. If an app misbehaves only through Burp, try turning it off to rule it out.

Use a second listener (another port) for invisible traffic rather than changing your main one.

**Intercept off.** Leave Proxy → Intercept off and work from HTTP history; a forgotten intercept stalls the app and causes timeouts that look like TLS failures.

**WebSockets.** Upgrades are proxied automatically and messages appear in Proxy → WebSockets history, where you can intercept and resend them.

**Upstream proxy.** Settings → Network → Connections → Upstream proxy servers, with a destination host pattern, for when the lab has to leave through a corporate proxy or you want to chain into another tool.

**TLS pass through.** Settings → Network → TLS → TLS pass through: hosts listed there are tunnelled without decryption. Add OS and vendor services (Apple, Google) that pin and would otherwise fill the event log with handshake failures and break system functions on the test device.

**Upstream TLS.** Burp does not reject invalid server certificates by default. That is convenient for testing, but remember it when you diagnose server-side certificate problems: what the app would see from the real server is not what it sees through Burp. Client certificates for mTLS go in Settings → Network → TLS → Client TLS certificates.

Messages such as *"The client failed to negotiate a TLS connection to api.example.com:443: Received fatal alert: certificate_unknown"* in the event log mean the app rejected your certificate — see [Troubleshooting](#troubleshooting).

### mitmproxy

mitmproxy ships as `mitmproxy` (console UI), `mitmweb` (web UI on `http://127.0.0.1:8081`) and `mitmdump` (non-interactive, scriptable). The listener defaults to port 8080 on all interfaces.

```bash
mitmweb --listen-port 8080
mitmdump -w flows.mitm                   # record everything to a flow file
mitmproxy -r flows.mitm                  # review it later
mitmdump -s addon.py                     # run a Python addon
```

**Modes** (`--mode`; since mitmproxy 9 you can pass several, each optionally with its own port as `mode@port`):

| Mode | What it does | Mobile use |
|---|---|---|
| `regular` (default) | Explicit HTTP proxy; clients send `CONNECT` | Wi-Fi proxy, `http_proxy` setting, `adb reverse` |
| `transparent` | Accepts redirected connections and recovers the original destination from the local netfilter/pf state | Rogue AP or ARP spoofing on the proxy host |
| `wireguard` | Runs a WireGuard server; prints a client configuration and QR code | Non-proxy-aware apps on unrooted Android and non-jailbroken iOS via the WireGuard app |
| `upstream:http://host:port` | Forwards everything to another proxy | Corporate egress proxy |
| `reverse:https://api.example.com` | Acts as the server for one upstream | DNS redirection of a single host; reFlutter-style setups |
| `socks5` | SOCKS5 proxy | Clients that support SOCKS |
| `dns` | DNS server whose queries appear as flows | Seeing and rewriting the app's DNS |

WireGuard mode is the most useful addition to mobile testing in years. Run `mitmweb --mode wireguard`, scan the QR code with the WireGuard app on the device (Android or iOS), install and trust the mitmproxy CA as above, and every app's traffic arrives at mitmproxy with its original destination intact, whether it honours proxies or not. On Android, the WireGuard app's per-application setting lets you tunnel only the target app. The device must reach your host on UDP 51820.

Transparent mode on a Linux AP host (adapted from the mitmproxy documentation):

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 443 -j REDIRECT --to-port 8080
mitmweb --mode transparent --showhost
```

On macOS, transparent mode reads pf's state table and needs extra privileges; follow the mitmproxy transparent-mode guide, or use WireGuard mode, which avoids the problem.

**Useful options:**

- `--ignore-hosts '^(.+\.)?(apple\.com|icloud\.com|googleapis\.com):443$'` — TLS passthrough for matching `host:port` (regex); `--allow-hosts` is the inverse (only these are decrypted). Use one or the other.
- `-k` / `--ssl-insecure` — do not verify upstream server certificates (needed for lab servers with private CAs).
- `--set client_certs=path` — client certificate(s) for mTLS upstreams.
- `--set http2=false` — force HTTP/1.1 towards the client when you suspect an HTTP/2 problem.
- `--set tcp_hosts=regex` — treat matching hosts as raw TCP (after TLS, if any), for non-HTTP protocols.
- `--set hardump=flows.har` — write a HAR file on exit (recent versions; with `-n -r flows.mitm` it converts a saved flow file).

WebSocket messages are shown inside the flow that upgraded; HTTP/2 and gRPC are decoded, with a protobuf content view for gRPC bodies.

**Scripting.** [MASTG-TECH-0100](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0100/) uses a mitmproxy addon to flag requests and responses that contain known sensitive values, which is the quickest way to check where a test account's personal data goes. A compact version:

```python
# pii_hits.py - run with: mitmdump -s pii_hits.py
from mitmproxy import http

# values you entered into the test account
NEEDLES = ["gt.tester@example.com", "+447700900123", "51.5072,-0.1276"]

def response(flow: http.HTTPFlow) -> None:
    parts = [flow.request.pretty_url, flow.request.get_text(strict=False) or ""]
    if flow.response:
        parts.append(flow.response.get_text(strict=False) or "")
    blob = "\n".join(parts)
    hits = [n for n in NEEDLES if n in blob]
    if hits:
        with open("pii_hits.log", "a") as fh:
            fh.write(f"{flow.request.method} {flow.request.pretty_url} -> {hits}\n")
```

Values can also be URL-encoded, Base64-encoded or hashed; add those forms to the list when it matters.

### ZAP

ZAP ([MASTG-TOOL-0079](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0079/)) works the same way: set the local proxy address and port in the options (Network → Local Servers/Proxies in current versions), export its root CA from the server-certificate options, install it on the device as above. Its strength for mobile work is the free active scanner against the API you have discovered; for interception itself it offers nothing Burp or mitmproxy lack.

### One lab CA for every tool

Generating one CA and importing it into every proxy means you install and trust it once per device:

```bash
openssl req -x509 -new -newkey rsa:2048 -nodes -days 365 \
  -keyout lab-ca.key -out lab-ca.crt -subj "/CN=GT Lab Interception CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# Burp: Proxy settings -> Import / export CA certificate -> Certificate and private key in DER format
openssl x509 -in lab-ca.crt -outform DER -out lab-ca.der
openssl pkcs8 -topk8 -nocrypt -in lab-ca.key -outform DER -out lab-ca-key.der

# mitmproxy: key and certificate together in ~/.mitmproxy/mitmproxy-ca.pem
cat lab-ca.key lab-ca.crt > ~/.mitmproxy/mitmproxy-ca.pem
```

(After replacing `mitmproxy-ca.pem`, delete the old `mitmproxy-ca-cert.*` files so mitmproxy regenerates them from the new CA.) Anyone with this private key can intercept every device that trusts it: keep it in the lab, give it a short validity, never install it on a personal phone, and remove it from test devices at the end of the engagement. MASTG-TECH-0011 also mentions Chrome's `NET::ERR_CERT_VALIDITY_TOO_LONG` with very long-lived Burp leaves; a custom CA imported this way avoids that class of problem.

## Non-HTTP and non-proxy-aware traffic

When the proxy stays empty, first find out where the traffic is going ([passive capture](#passive-eavesdropping-mastg-tech-0122)), then pick a position that puts you in that path. The techniques below come from [MASTG-TECH-0121](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0121/) to [MASTG-TECH-0125](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0125/).

### Rogue access point (MASTG-TECH-0124)

Making your host the device's access point puts every packet through you, for any app and any OS, with nothing configured on the phone except joining the network. [MASTG-TECH-0124](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0124/) describes two variants: a separate AP whose traffic you forward or mirror to your host, or your host acting as the AP with one interface serving the test network and another providing the uplink.

**macOS.** System Settings → General → Sharing → Internet Sharing, sharing your wired or second connection over Wi-Fi. The shared network appears as `bridge100`. Redirect web ports to a proxy on the Mac with pf:

```bash
echo "rdr pass on bridge100 inet proto tcp from any to any port {80, 443} -> 127.0.0.1 port 8080" | sudo pfctl -ef -
# restore the default rules afterwards
sudo pfctl -F all -f /etc/pf.conf
```

With Burp, the listener on `127.0.0.1:8080` needs invisible proxying.

**Linux.** Check that the adapter supports AP mode (`iw list` and look for `AP` under *Supported interface modes*; MASTG says `iwconfig`, but the command it shows is `iw`). A minimal setup with `wlan1` as the AP and `eth0` as the uplink:

```text
# hostapd.conf
interface=wlan1
driver=nl80211
ssid=gt-lab-intercept
hw_mode=g
channel=6
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=use-a-long-random-lab-passphrase
```

```text
# dnsmasq.conf
interface=wlan1
bind-interfaces
dhcp-range=10.0.0.10,10.0.0.250,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
log-queries
```

```bash
sudo ip addr add 10.0.0.1/24 dev wlan1
sudo ip link set wlan1 up
sudo hostapd hostapd.conf &
sudo dnsmasq -C dnsmasq.conf -d &
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i wlan1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o wlan1 -m state --state RELATED,ESTABLISHED -j ACCEPT
# interception: web ports to the proxy, QUIC blocked so clients fall back to TCP
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp -m multiport --dports 80,443 -j REDIRECT --to-port 8080
sudo iptables -A FORWARD -i wlan1 -p udp --dport 443 -j REJECT
mitmweb --mode transparent --showhost
```

Do not run `airmon-ng check kill` (as MASTG does) on a machine whose other connections you need; it stops NetworkManager and wpa_supplicant system-wide. If you use NetworkManager, mark `wlan1` as unmanaged instead. Do not route IPv6 on the lab network, or dual-stack apps will leave through a path you are not redirecting. Use a unique SSID and a strong passphrase so nobody else's device joins.

A travel router with OpenWrt or a firewall appliance does the same job and keeps your laptop's Wi-Fi free.

### ARP spoofing (MASTG-TECH-0123)

[MASTG-TECH-0123](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0123/) uses bettercap ([MASTG-TOOL-0076](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0076/)) to tell the device that your host is the gateway (and, in full-duplex mode, the gateway that your host is the device). It works on any OS because it happens at layer 2, and it is useful on a shared lab network where you cannot change the AP.

```bash
sudo bettercap -iface en0 -eval "set arp.spoof.targets 192.168.1.23; set arp.spoof.fullduplex true; arp.spoof on"
```

Set the `arp.spoof.*` options **before** `arp.spoof on`; MASTG's example sets `internal` and `fullduplex` after starting the module, where they do not take effect until it is restarted. bettercap enables IP forwarding itself. Then redirect the device's web traffic to your proxy:

```bash
# Linux
sudo iptables -t nat -A PREROUTING -i wlan0 -s 192.168.1.23 -p tcp -m multiport --dports 80,443 -j REDIRECT --to-port 8080
mitmweb --mode transparent --showhost

# macOS (Burp listener on 127.0.0.1:8080 with invisible proxying)
echo "rdr pass on en0 inet proto tcp from 192.168.1.23 to any port {80, 443} -> 127.0.0.1 port 8080" | sudo pfctl -ef -
```

Limits: ARP only covers IPv4, so disable IPv6 on the device's network or expect leaks; full duplex also poisons the gateway, which managed networks detect (dynamic ARP inspection, client isolation) and which disrupts other users — only do it on a network you own. OWASP's warning that encrypted DNS, MAC randomisation and ARP-spoofing detection reduce its effectiveness on modern devices is fair; a rogue AP or WireGuard mode is usually less trouble.

### DNS redirection

The third option in [MASTG-TECH-0125](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0125/) is generic: make the API hostname resolve to your host and run a listener on the original port that forwards to the real server. On a rooted Android device, a hosts entry (systemless via Magisk) does it; on a rogue AP, dnsmasq does it (`address=/api.example.com/10.0.0.1`). Then:

```bash
sudo mitmweb --mode reverse:https://api.example.com --listen-port 443
```

or a Burp listener on 443 with *Redirect to host* `api.example.com`, *Redirect to port* `443`, *Force use of TLS* and invisible proxying. Turn off Android's *Private DNS* and iOS encrypted-DNS profiles on the test device, or the app's lookups never reach your resolver. DNS redirection is precise (one host, nothing else disturbed) but fails against hard-coded IP addresses.

### Passive eavesdropping (MASTG-TECH-0122)

[MASTG-TECH-0122](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0122/) is capture without interception, using tcpdump ([MASTG-TOOL-0080](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0080/), [MASTG-TOOL-0075](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0075/) for the Android build) and Wireshark ([MASTG-TOOL-0081](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0081/)). It cannot read TLS, but it answers the questions you need answered before choosing a position: which hosts, which ports, TCP or UDP, cleartext or TLS, which SNI, and whether the app is ignoring your proxy. It is also how you test non-HTTP cleartext protocols (MQTT, XMPP, custom TCP/UDP) for [MASWE-0026](/mobile/maswe-0026-cleartext-network-traffic/).

On Android ([MASTG-TECH-0010](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0010/)), a rooted device needs a tcpdump binary (Magisk modules and some ROMs ship one; otherwise push a static ARM64 build to `/data/local/tmp/`). Instead of OWASP's tcpdump-to-netcat-to-`adb forward` pipeline, `adb exec-out` streams binary output directly:

```bash
# live into Wireshark
adb exec-out "su -c '/data/local/tmp/tcpdump -i any -U -s 0 -w - 2>/dev/null'" | wireshark -k -i -

# or to a file on the device
adb shell su -c "/data/local/tmp/tcpdump -i any -s 0 -w /data/local/tmp/app.pcap"
adb shell su -c "chmod 644 /data/local/tmp/app.pcap"
adb pull /data/local/tmp/app.pcap

# emulator, no root needed
emulator -avd Pixel_API_35 -tcpdump emulator.pcap
```

Without root, PCAPdroid (a VpnService-based capture app) writes pcaps on the device. iOS uses [`rvictl`](#packet-capture-with-rvictl). On a rogue AP, capture on the AP interface: `sudo tcpdump -i wlan1 -s 0 -w ap.pcap`.

Triage with tshark:

```bash
tshark -r app.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | sort | uniq -c | sort -rn
tshark -r app.pcap -Y 'tls.handshake.type == 1' -T fields -e ip.dst -e tcp.dstport -e tls.handshake.extensions_server_name | sort -u
tshark -r app.pcap -Y 'http.request' -T fields -e ip.dst -e http.host -e http.request.method -e http.request.uri
tshark -r app.pcap -Y 'quic' -T fields -e ip.dst -e udp.dstport | sort -u
tshark -r app.pcap -q -z conv,tcp
```

SNI values in ClientHellos tell you which hosts were contacted over TLS even when you cannot decrypt them; `http.request` output is cleartext HTTP; `quic` output means some traffic is bypassing any TCP proxy. To decrypt TLS in Wireshark you need the session secrets in NSS key-log format (Preferences → Protocols → TLS → (Pre)-Master-Secret log filename). Mobile apps do not honour `SSLKEYLOGFILE`; on Android you can extract keys by hooking BoringSSL's key-log callback with Frida, as the article linked from MASTG-TECH-0122 shows.

### Non-HTTP protocols through a proxy (MASTG-TECH-0121)

HTTP proxies do not decode arbitrary protocols. [MASTG-TECH-0121](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0121/) points to two extensions:

- **NoPE Proxy** ([MASTG-TOOL-0109](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0109/), formerly *Burp-non-HTTP-Extension*): a Burp extension that adds TCP/UDP listeners, a DNS server for redirecting app hosts to those listeners, and interception and modification of the raw streams.
- **mitm_relay** ([MASTG-TOOL-0078](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0078/)): a relay that wraps each non-HTTP message in an HTTP request so it can pass through Burp or another proxy and be edited there, with TLS and STARTTLS support.

mitmproxy handles raw TCP and UDP natively: in WireGuard or transparent mode, non-HTTP connections appear as TCP/UDP flows, and `--set tcp_hosts=` forces matching hosts to be treated as raw TCP (decrypting TLS first if the client trusts your CA). For MQTT over TLS, for example, that is often enough to read the topics and payloads. OWASP's own verdict — that this "can sometimes become very tedious" — is accurate; consider [application-layer hooking](#application-layer-hooking) before building a relay for an obscure protocol.

### Flutter (MASTG-TECH-0109 and MASTG-TECH-0110)

Flutter apps are the most common reason an otherwise standard lab sees nothing. As [MASTG-TECH-0109](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0109/) (Android) and [MASTG-TECH-0110](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0110/) (iOS) explain, Dart's HTTP client ignores the system proxy and verifies certificates inside the Flutter engine (`libflutter.so` on Android, `Flutter.framework` on iOS), which bundles BoringSSL. The NSC, user CAs and iOS trust settings are not consulted, so you have two problems: get the traffic to the proxy, and stop the engine rejecting your certificate. (Flutter apps that use the `cronet_http` or `cupertino_http` packages go through the platform stack instead and behave like native apps.)

**Option 1 — reFlutter** ([MASTG-TOOL-0100](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0100/)) replaces the engine with a patched build that sends traffic to a proxy IP you enter and skips certificate verification:

```bash
reflutter app.apk            # choose "Traffic monitoring and interception", enter 192.168.1.10
java -jar uber-apk-signer.jar --apks release.RE.apk
adb install -r release.RE-aligned-debugSigned.apk
```

The patched engine connects to port **8083**, so add a Burp listener on 8083, bound to the LAN interface, with invisible proxying. For iOS, `reflutter app.ipa` produces `release.RE.ipa`, which you re-sign and install. reFlutter only supports engine versions it has patched builds for; if it reports an unknown snapshot hash, move to option 2.

**Option 2 — Frida plus a redirect.** NVISO's `disable-flutter-tls.js` ([MASTG-TOOL-0101](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0101/)) finds BoringSSL's `ssl_verify_peer_cert` in the engine by pattern matching and forces it to succeed. It does not change routing, so combine it with something that does: iptables redirect or ProxyDroid on Android, WireGuard mode, a rogue AP or ARP spoofing on either platform.

```bash
frida -U -f com.example.flutterapp -l disable-flutter-tls.js
```

Both options disable verification entirely; a Flutter app that pins inside Dart code (for example with a custom `badCertificateCallback` or a pinning package) may need an additional hook.

### Xamarin (MASTG-TECH-0125)

OWASP has marked [MASTG-TECH-0125](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0125/) deprecated: Xamarin reached end of support on 1 May 2024 and new apps use .NET MAUI. You will still meet legacy Xamarin apps. Those built with the managed `HttpClientHandler` ignore the device proxy; those configured with the native handlers (`AndroidClientHandler` / `NSUrlSessionHandler`) generally behave like native apps. OWASP gives three routes:

1. Patch the app to set `WebRequest.DefaultWebProxy = new WebProxy("192.168.1.10", 8080);` at start-up and re-sign (or set it with a Frida hook into the Mono runtime). Effective, but it is IL patching and rarely the quickest route.
2. ARP spoofing (or better, a rogue AP) plus a redirect of port 443 to the proxy, with Burp's invisible proxying. MASTG's Linux rule (`iptables -t nat -A PREROUTING ... -j DNAT --to-destination 127.0.0.1:8080`) does not work as written: Linux drops packets DNATed from an external interface to loopback unless `net.ipv4.conf.<iface>.route_localnet=1` is set. Use `-j REDIRECT --to-port 8080` as in the [rogue AP](#rogue-access-point-mastg-tech-0124) example. The macOS pf rule in MASTG works.
3. DNS redirection, as [above](#dns-redirection).

MASTG's text says to enable "Support invisible proxy" in *Android Studio* (it links MASTG-TOOL-0007); it means Burp Suite. .NET MAUI apps on Android use `AndroidMessageHandler` by default and are usually proxy-aware.

### QUIC and HTTP/3

QUIC ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)) runs over UDP/443 and HTTP/3 ([RFC 9114](https://www.rfc-editor.org/rfc/rfc9114)) runs over QUIC. An HTTP proxy cannot carry it, and a TCP redirect rule does not touch it. Cronet (Chrome's network stack, also used by apps and some Google SDKs) and URLSession (which can negotiate HTTP/3 from iOS 15 when the server advertises it with `Alt-Svc`) both use it. The symptom is a proxy that shows some of the app's requests but not others, or only the first request to a host.

Clients fall back to TCP when QUIC fails, so the reliable fix is to **block UDP/443** in your interception path: on the rogue AP (`iptables -A FORWARD -i wlan1 -p udp --dport 443 -j REJECT`), on a rooted device for the app's UID (shown [earlier](#redirecting-with-iptables-on-a-rooted-device)), or on the network firewall. When an explicit HTTP proxy is configured, Chromium-based stacks do not attempt QUIC for proxied requests. Recent mitmproxy releases have added HTTP/3 support in some modes; check the documentation for the version you run before relying on it, and confirm with a capture (`tshark -Y quic`) that nothing is still leaving over UDP.

### Push notifications

MASTG-TECH-0010 describes intercepting Firebase Cloud Messaging by redirecting ports 5228–5230 and the XMPP ports 5235/5236 to the proxy. Treat that section with care. The HTTP and XMPP "connection server protocols" it refers to are the **server-side** APIs between the app's backend and FCM, not the device's traffic; the legacy XMPP and HTTP APIs were deprecated in 2023 and shut down in 2024 in favour of the HTTP v1 API. On the device, push messages arrive over a persistent TLS connection that Google Play services keeps to Google (port 5228, falling back to 443 and others), and APNs on iOS uses Apple's own TLS connection on 5223 or 443. Both are pinned to the vendor's infrastructure; you can see that the connection exists, not its content. To test what an app does with push payloads, look at its handlers (`FirebaseMessagingService.onMessageReceived`, `UNUserNotificationCenterDelegate`) and at the backend that sends them. If payloads carry sensitive data, recommend end-to-end encrypting them; MASTG mentions Google's Capillary library for that; check that it is still maintained before naming it in a recommendation.

## Application-layer hooking

[MASTG-TECH-0119](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0119/) makes a point worth repeating: if the question is "what does the app send?", you do not always need a MITM position. Hooking the networking API inside the app shows the plaintext before it is encrypted, without touching TLS or pinning. It is the right tool for custom network stacks, for protocols that are painful to proxy (MQTT, CoAP, WebSockets on a custom stack, BLE or NFC payloads), and for confirming what an app sends when interception would require more patching than the test justifies. The trade-offs: you see what the app hands to the library, not what goes on the wire (so it does not prove anything about TLS configuration), you cannot easily modify requests, and hooks need maintenance across app and library versions. Frida ([MASTG-TOOL-0031](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/)) needs `frida-server` on a rooted or jailbroken device, or Frida Gadget in a repackaged app.

### Android: logging OkHttp requests

OkHttp is behind most Android HTTP traffic (Retrofit uses it, and so does the platform's `HttpURLConnection` implementation, under a repackaged name). Hooking `OkHttpClient.newCall()` sees every request built by the app:

```javascript
// okhttp-log.js - frida -U -f com.example.app -l okhttp-log.js
Java.perform(function () {
  var OkHttpClient = Java.use('okhttp3.OkHttpClient');
  var Buffer = Java.use('okio.Buffer');

  OkHttpClient.newCall.implementation = function (request) {
    var out = request.method() + ' ' + request.url().toString() + '\n' + request.headers().toString();
    var body = request.body();
    if (body !== null) {
      var buf = Buffer.$new();
      body.writeTo(buf);
      out += '\n' + buf.readUtf8();
    }
    console.log('[okhttp]\n' + out);
    return this.newCall(request);
  };
});
```

If the app is obfuscated, `okhttp3.OkHttpClient` may be renamed; find it in jadx by OkHttp's distinctive string constants and exception messages, or by the shape of its classes and method signatures. One-shot or streaming request bodies (`RequestBody.isOneShot()` returning true) must not be written twice; skip them or log only their length. For responses, add an interceptor or hook the code that consumes the response body. Ready-made scripts for OkHttp interceptors are on Frida CodeShare, as MASTG notes, but expect to adapt them.

### iOS: logging URLSession requests

`NSURLSession` is a class cluster and the methods you want are implemented by private subclasses, so resolve them by pattern rather than hooking `NSURLSession` directly:

```javascript
// urlsession-log.js - frida -U -f com.example.app -l urlsession-log.js
var resolver = new ApiResolver('objc');
resolver.enumerateMatches('-[*URLSession* dataTaskWithRequest:*]').forEach(function (m) {
  Interceptor.attach(m.address, {
    onEnter: function (args) {
      var req = new ObjC.Object(args[2]);            // args[0] = self, args[1] = _cmd
      var line = req.HTTPMethod() + ' ' + req.URL().absoluteString();
      var headers = req.allHTTPHeaderFields();
      if (headers !== null) {
        line += '\n' + headers.toString();
      }
      var body = req.HTTPBody();
      if (body !== null) {
        line += '\n' + ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4);  // NSUTF8StringEncoding
      }
      console.log('[' + m.name + ']\n' + line);
    }
  });
});
```

`frida-trace -U -f com.example.app -m '-[*URLSession* *Task*]'` is a quick way to see which task-creation methods the app actually calls (`uploadTaskWithRequest:fromData:`, `dataTaskWithURL:`, the async variants used by Swift concurrency). Bodies sent through `HTTPBodyStream` or upload tasks are not in `HTTPBody`; hook the upload methods for those.

### Native TLS libraries

For apps with their own native stack, OWASP suggests hooking `SSL_write` and `SSL_read` from OpenSSL/BoringSSL, which see plaintext just before encryption and just after decryption. On Android, the platform's Conscrypt links BoringSSL statically into its own library, so hooks on the system `libssl.so` only catch native code that uses it; apps that bundle their own OpenSSL or BoringSSL (Flutter, many games and VoIP SDKs) need the functions located in their own libraries, often stripped, which is the signature-analysis work the hackmag article in MASTG-TECH-0119 describes. For WebView traffic, Chrome remote debugging (`chrome://inspect` for debuggable WebViews) or Safari Web Inspector (for inspectable WKWebViews) is easier than either a proxy or a hook.

## Capturing evidence

Every network finding needs evidence that someone else can verify, and evidence of the conditions under which you got it. Save:

- **Proxy history.** mitmproxy flow file (`-w flows.mitm`) and a HAR (`--set hardump=`); from Burp, select the relevant items in HTTP history and use *Save items*, plus the project file if you have Burp Professional. Include the full request and response for each finding, not just a screenshot.
- **Packet capture** for anything below HTTP: cleartext non-HTTP protocols, TLS versions and cipher suites (the ClientHello and ServerHello prove what was negotiated), DNS leaks, QUIC. Filter it to the relevant conversations for the report (`tshark -r all.pcap -Y 'ip.addr == 203.0.113.10' -w finding-01.pcap`) and keep the raw capture in engagement storage.
- **Hashes and times.** `shasum -a 256 *.pcap *.har *.mitm`, capture start and end in UTC, so the files can be matched to the report later.
- **Screenshots** of the app state that triggered the traffic, alongside the proxy entry.
- **Environment.** Device model and OS build (`adb shell getprop ro.build.fingerprint`; iOS: Settings → General → About, or `ideviceinfo -k ProductVersion`), app version (`adb shell dumpsys package com.example.app | grep versionName`), proxy and version.
- **What you changed to get the traffic.** None / user CA / system CA / NSC patched / pinning bypassed / Frida hook / rooted or jailbroken device. This line decides the attacker position, and therefore the severity, of every finding that depends on the capture: cleartext seen with no CA installed is a network attacker's finding; a token read after a pinning bypass on your own rooted device is an observation about the API, not a transport weakness.

**Redact** before anything leaves the engagement store. Tokens, cookies, API keys, passwords and personal data of test accounts are real credentials until the client rotates them. For HAR files:

```bash
jq '(.log.entries[].request.headers[] | select(.name | test("^(authorization|cookie|x-api-key)$"; "i")) | .value) |= "REDACTED"
  | (.log.entries[].response.headers[] | select(.name | test("^set-cookie$"; "i")) | .value) |= "REDACTED"' \
  flows.har > flows.redacted.har
```

Then check query strings and bodies by hand (`grep -iE 'token|secret|password|session' flows.redacted.har`), because no filter knows every field name. In screenshots, mask the value but leave the header name visible, so the reader can see what was exposed. Ask the client to rotate any credential that appeared in cleartext during the test.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Proxy log shows "client does not trust the proxy's certificate" / `certificate unknown` / "client failed to negotiate a TLS connection" for the app's hosts, while Chrome or Safari works | App does not trust user CAs (Android, target API 24+), or pins, or bundles its own trust store (Flutter) | Install the CA as a system CA (Android 14+: APEX method); check the NSC for `<pin-set>` and `<trust-anchors>`; if it still fails with a system CA, it pins — see [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/) |
| Same errors on iOS for every app and Safari | Profile installed but full trust not enabled | Settings → General → About → Certificate Trust Settings |
| CA installed in `/system/etc/security/cacerts` but nothing trusts it | Android 14+ reads CAs from `/apex/com.android.conscrypt/cacerts` | Use the [APEX bind-mount technique](#installing-the-ca-as-a-system-ca-on-android-14-and-later) |
| No requests at all from the app; the browser works | App ignores the proxy (Flutter, Xamarin, `NO_PROXY`, raw sockets) or uses QUIC | Capture packets to see where it goes; switch to WireGuard mode, iptables or a rogue AP; block UDP/443 |
| Some requests appear, others never do | QUIC/HTTP/3 for some hosts; separate client instance with `NO_PROXY`; connections pooled before the proxy was set | Block UDP/443; force-stop and relaunch the app; capture to find the missing hosts |
| Nothing at all, not even the browser | Wi-Fi client isolation; listener bound to `127.0.0.1`; host firewall; wrong IP | `adb reverse`; bind to the LAN address; allow the port in the macOS/Linux firewall; test with `curl -x` from another machine |
| Requests reach the proxy but upstream fails | Server uses a private CA, requires a client certificate (mTLS), or blocks your egress IP | `-k`/`--set client_certs=` in mitmproxy, Client TLS certificates in Burp; ask the client for allow-listing |
| Works on the emulator, not on the device | Emulator had root and a system CA, the device only a user CA; different Android version (APEX); device has stricter OEM settings | Install the CA the same way on both; compare `getprop ro.build.version.release` |
| Works on the device, not on the emulator | Emulator or root detection; ARM-only native libraries on an x86_64 image; no Google Play services | Use an `arm64-v8a` or Play image, or a physical device |
| Certificate "not yet valid" or "expired" errors on every host | Device clock wrong, or CA regenerated after it was installed | Enable automatic date and time; re-export and reinstall the CA |
| App shows "no connection" or a security warning as soon as the proxy or VPN is set, with no TLS errors | Proxy or VPN detection | Move to a position the app cannot see, or hook the check ([above](#proxy-and-vpn-detection)) |
| Flows look fine but the app misbehaves only through the proxy | HTTP/2 or WebSocket handling, request smuggling defences, compression differences, intercept left on | Turn intercept off; `--set http2=false` or Burp's HTTP/2 off; compare with a passive capture |
| Traffic vanished after an iptables or pf experiment | Stale redirect rules | `iptables -t nat -L -n -v` and delete your rules; `sudo pfctl -F all -f /etc/pf.conf`; `settings put global http_proxy :0`; `adb reverse --remove-all` |
| Flutter app: reFlutter build connects nowhere | Listener not on port 8083 or not invisible; unsupported engine version | Add the 8083 invisible listener; fall back to Frida plus redirect |

## Ethics and scope

Intercepting traffic is intercepting communications. Do it only with written authorisation that names the app, the backend environments, the devices and the techniques (rogue AP and ARP spoofing in particular), and only on devices and accounts provided or owned for the test.

- **Never intercept other people's traffic.** ARP spoofing and rogue APs affect everyone on the segment or in radio range. Use an isolated lab network or your own SSID with a strong passphrase; never run them on office, café, hotel or client production Wi-Fi. Do not send deauthentication frames to push devices onto your AP. Filter your rules and captures to the test device's address, and discard anything else you capture by accident.
- **Know the law where you test.** In the UK, intercepting communications in the course of transmission without lawful authority is an offence under section 3 of the Investigatory Powers Act 2016, and unauthorised access is covered by the Computer Misuse Act 1990. Other jurisdictions have equivalents.
- **Use test accounts and test data.** Captured tokens and personal data are sensitive engagement data: store them encrypted, redact them in reports, delete them at the end of the retention period.
- **Clean up.** Remove proxy settings, VPN profiles, CA certificates (user, system and iOS profiles), iptables/pf rules and Magisk modules from devices when the test ends, and delete or rotate the lab CA if it has left the lab.
- **Stay in scope upstream.** Through a proxy it is easy to start testing third-party SDK endpoints (analytics, payments, maps). Record what the app sends to them; do not attack them without their owner's permission.

## References

- OWASP MASVS — [MASVS-NETWORK-1](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/), [MASVS-NETWORK-2](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/) (CC BY-SA 4.0)
- OWASP MASTG — Android techniques [MASTG-TECH-0010: Basic Network Monitoring/Sniffing](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0010/), [MASTG-TECH-0011: Setting Up an Interception Proxy](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/), [MASTG-TECH-0012: Bypassing Certificate Pinning](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012/), [MASTG-TECH-0022: Information Gathering - Network Communication](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0022/), [MASTG-TECH-0100: Logging Sensitive Data from Network Traffic](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0100/), [MASTG-TECH-0109: Intercepting Flutter HTTPS Traffic](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0109/), [MASTG-TECH-0151: Analyzing the Network Security Configuration](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0151/) (CC BY-SA 4.0)
- OWASP MASTG — iOS techniques [MASTG-TECH-0062: Basic Network Monitoring/Sniffing](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0062/), [MASTG-TECH-0063: Setting up an Interception Proxy](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/), [MASTG-TECH-0064: Bypassing Certificate Pinning](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0064/), [MASTG-TECH-0074: Information Gathering - Network Communication](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0074/), [MASTG-TECH-0110: Intercepting Flutter HTTPS Traffic](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0110/) (CC BY-SA 4.0)
- OWASP MASTG — generic techniques [MASTG-TECH-0119: Intercepting HTTP Traffic by Hooking Network APIs at the Application Layer](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0119/), [MASTG-TECH-0120: Intercepting HTTP Traffic Using an Interception Proxy](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/), [MASTG-TECH-0121: Intercepting Non-HTTP Traffic Using an Interception Proxy](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0121/), [MASTG-TECH-0122: Passive Eavesdropping](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0122/), [MASTG-TECH-0123: Achieving a MITM Position via ARP Spoofing](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0123/), [MASTG-TECH-0124: Achieving a MITM Position Using a Rogue Access Point](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0124/), [MASTG-TECH-0125: Intercepting Xamarin Traffic](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0125/) (CC BY-SA 4.0)
- OWASP MASTG — tools [Burp Suite (MASTG-TOOL-0077)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/), [mitmproxy (MASTG-TOOL-0097)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/), [ZAP (MASTG-TOOL-0079)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0079/), [bettercap (MASTG-TOOL-0076)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0076/), [MITM Relay (MASTG-TOOL-0078)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0078/), [Nope-Proxy (MASTG-TOOL-0109)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0109/), [tcpdump (MASTG-TOOL-0080)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0080/), [tcpdump for Android (MASTG-TOOL-0075)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0075/), [Wireshark (MASTG-TOOL-0081)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0081/), [HTTP Toolkit (MASTG-TOOL-0115)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0115/), [adb (MASTG-TOOL-0004)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [apksigner (MASTG-TOOL-0123)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/), [uber-apk-signer (MASTG-TOOL-0103)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0103/), [ProxyDroid (MASTG-TOOL-0120)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0120/), [Apkleaks (MASTG-TOOL-0125)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0125/), [iproxy (MASTG-TOOL-0055)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0055/), [libimobiledevice suite (MASTG-TOOL-0126)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0126/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [reFlutter (MASTG-TOOL-0100)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0100/), [disable-flutter-tls-verification (MASTG-TOOL-0101)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0101/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) (CC BY-SA 4.0)
- [Android Developers — Network security configuration](https://developer.android.com/privacy-and-security/security-config); [Changes to Trusted Certificate Authorities in Android Nougat](https://android-developers.googleblog.com/2016/07/changes-to-trusted-certificate.html); [Start the emulator from the command line](https://developer.android.com/studio/run/emulator-commandline); [Android Debug Bridge (adb)](https://developer.android.com/tools/adb); [apksigner](https://developer.android.com/tools/apksigner); [zipalign](https://developer.android.com/tools/zipalign)
- HTTP Toolkit (Tim Perry) — [New ways to inject system CA certificates in Android 14](https://httptoolkit.com/blog/android-14-install-system-ca-certificate/) (the APEX mount-namespace technique)
- mitmproxy documentation — [Proxy modes](https://docs.mitmproxy.org/stable/concepts-modes/), [Certificates](https://docs.mitmproxy.org/stable/concepts-certificates/), [Transparent proxying](https://docs.mitmproxy.org/stable/howto-transparent/), [Install system CA on Android](https://docs.mitmproxy.org/stable/howto-install-system-trusted-ca-android/), [Options](https://docs.mitmproxy.org/stable/concepts-options/)
- PortSwigger — [Configuring an Android device to work with Burp Suite](https://portswigger.net/burp/documentation/desktop/mobile/config-android-device), [Configuring an iOS device to work with Burp Suite](https://portswigger.net/burp/documentation/desktop/mobile/config-ios-device), [Invisible proxying](https://portswigger.net/burp/documentation/desktop/tools/proxy/invisible)
- Apple — [Trust manually installed certificate profiles in iOS and iPadOS (HT204477)](https://support.apple.com/en-us/HT204477), [Requirements for trusted certificates in iOS 13 and macOS 10.15 (HT210176)](https://support.apple.com/en-us/HT210176), [Recording a packet trace](https://developer.apple.com/documentation/network/recording-a-packet-trace)
- NVISO — [Intercepting Flutter traffic on iOS and Android (HTTP/HTTPS/Dio pinning)](https://blog.nviso.eu/2022/08/18/intercept-flutter-traffic-on-ios-and-android-http-https-dio-pinning/); [disable-flutter-tls-verification](https://github.com/NVISOsecurity/disable-flutter-tls-verification); [reFlutter](https://github.com/Impact-I/reFlutter); [bettercap](https://github.com/bettercap/bettercap)
- Wireshark — [TLS decryption](https://wiki.wireshark.org/TLS#tls-decryption); [tshark manual](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Firebase — FAQ on the deprecated legacy FCM APIs](https://firebase.google.com/support/faq#fcm-23-deprecation)
- [RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000), [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [Investigatory Powers Act 2016, section 3](https://www.legislation.gov.uk/ukpga/2016/25/section/3); [Computer Misuse Act 1990](https://www.legislation.gov.uk/ukpga/1990/18)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
