---
title: "OS Command and Argument Injection"
date: 2026-11-15 20:04:00 +0000
subcategory: injection
summary: "Finding and safely confirming OS command and argument injection: shell-out features, blind time and DNS proofs, option injection, Windows and fixes."
refs: [WSTG-INJT-12, WSTG-INJT-14, WSTG-BUSL-09, v5.0.0-1.2.5, v5.0.0-1.3.3, v5.0.0-1.2.8, v5.0.0-5.3.2, v5.0.0-15.2.5, "A05:2025", CWE-78, CWE-88, CWE-77]
tags: [web, injection, command-injection, argument-injection, rce]
---

This note is part of our [Web Application Security testing guide](/web/web-application-security-testing-guide/) and sits under [Injection](/web/web-injection-testing-guide/). It covers the two ways untrusted input turns an application's call to an operating-system program into something the developer did not intend. **OS command injection** (`WSTG-INJT-12`, CWE-78) happens when the input reaches a shell and the shell's syntax lets it start new commands. **Argument injection** (CWE-88) happens when there is no shell at all, but the input becomes an option to the program (`--upload-pack=…` to `git`, `--output` to `curl`, `--checkpoint-action` to `tar`) and the program's own features do the damage. Both usually end in code execution on the server, which is why they sit at the top of the [rating](#rating-findings) scale. You get the model (how a feature turns into a process, where a shell gets involved, the metacharacter classes), the features that keep hiding shell calls (image and video processing, PDF generation, network diagnostics, archives, git integrations, conversions, backups, DNS lookups), twelve tests weighted towards finding *where* the application starts programs and *whether* input reaches them, each stopping at the least invasive proof (a bounded `sleep` or a DNS lookup to a collaborator you control), the Windows differences, and fixes in Node.js, Python/Django, Java/Spring and PHP/Laravel with regression tests. Code injection into a language interpreter (`eval`, expression languages) and template injection are in [server-side template injection](/web/web-server-side-template-injection/); SQL is in [SQL injection](/web/web-sql-injection/).

## Contents

- [How it works](#how-it-works)
  - [From a feature to a process](#from-a-feature-to-a-process)
  - [Shell or no shell](#shell-or-no-shell)
  - [Command injection and argument injection](#command-injection-and-argument-injection)
  - [Shell metacharacter classes](#shell-metacharacter-classes)
  - [Output-based and blind](#output-based-and-blind)
  - [Synchronous, asynchronous and second-order calls](#synchronous-asynchronous-and-second-order-calls)
- [What goes wrong](#what-goes-wrong)
  - [Where shell calls hide](#where-shell-calls-hide)
  - [String-built commands passed to a shell](#string-built-commands-passed-to-a-shell)
  - [Option injection without a shell](#option-injection-without-a-shell)
  - [Escaping and filtering that is not enough](#escaping-and-filtering-that-is-not-enough)
  - [Filenames, headers and stored values as sources](#filenames-headers-and-stored-values-as-sources)
  - [Interpreters behind the binary](#interpreters-behind-the-binary)
  - [Windows is different](#windows-is-different)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-WEB-CMD-1: Map features that call OS programs](#gt-web-cmd-1-map-features-that-call-os-programs)
  - [GT-WEB-CMD-2: Response, timing and error baselines](#gt-web-cmd-2-response-timing-and-error-baselines)
  - [GT-WEB-CMD-3: Blind confirmation with bounded time delays](#gt-web-cmd-3-blind-confirmation-with-bounded-time-delays)
  - [GT-WEB-CMD-4: Blind confirmation with out-of-band DNS](#gt-web-cmd-4-blind-confirmation-with-out-of-band-dns)
  - [GT-WEB-CMD-5: Typed fields and input context](#gt-web-cmd-5-typed-fields-and-input-context)
  - [GT-WEB-CMD-6: Option-like values and argument injection](#gt-web-cmd-6-option-like-values-and-argument-injection)
  - [GT-WEB-CMD-7: Filenames, headers and second-order sources](#gt-web-cmd-7-filenames-headers-and-second-order-sources)
  - [GT-WEB-CMD-8: Windows targets](#gt-web-cmd-8-windows-targets)
  - [GT-WEB-CMD-9: Quality of validation and filtering](#gt-web-cmd-9-quality-of-validation-and-filtering)
  - [GT-WEB-CMD-10: Source and greybox review](#gt-web-cmd-10-source-and-greybox-review)
  - [GT-WEB-CMD-11: Vulnerable wrappers and delegate configuration](#gt-web-cmd-11-vulnerable-wrappers-and-delegate-configuration)
  - [GT-WEB-CMD-12: Execution context, hardening and fix verification](#gt-web-cmd-12-execution-context-hardening-and-fix-verification)
- [Secure implementation](#secure-implementation)
  - [Design rules](#design-rules)
  - [Node.js](#nodejs)
  - [Python and Django](#python-and-django)
  - [Java and Spring](#java-and-spring)
  - [PHP and Laravel](#php-and-laravel)
  - [Closing the argument-injection gap](#closing-the-argument-injection-gap)
  - [Hardening image and document tools](#hardening-image-and-document-tools)
  - [Windows-specific fixes](#windows-specific-fixes)
  - [Sandboxing and least privilege](#sandboxing-and-least-privilege)
  - [Static analysis](#static-analysis)
  - [Regression tests](#regression-tests)
- [Practice labs](#practice-labs)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### From a feature to a process

Web applications start operating-system programs more often than their owners think. A "resize avatar" button calls ImageMagick or ffmpeg, a "download as PDF" link calls a headless browser, LibreOffice or LaTeX, a "test connection" page in an admin panel calls `ping` or `nslookup`, an "import from Git" field calls `git clone`, a nightly export calls `pg_dump` and `tar`. Each of those is a process started from application code, with arguments that partly come from the request.

At the operating-system level there are two ways to start a process:

1. **Direct execution.** The application names a program and passes a list of arguments (`execve()` on Unix, `CreateProcess()` on Windows). Each list element arrives in the child as one argument, whatever characters it contains. No shell parses anything.
2. **Through a shell.** The application hands one string to `/bin/sh -c` (Unix) or `cmd.exe /c` (Windows). The shell is an interpreter with its own language: it splits words, expands variables and wildcards, follows redirections and starts as many commands as the string describes.

Command injection needs the second path, or a program that behaves like a shell (see [Interpreters behind the binary](#interpreters-behind-the-binary)). Argument injection works on both paths.

### Shell or no shell

Which path you get depends on the API, and the names do not help much:

| Language | Goes through a shell | Executes directly (argument list) |
|---|---|---|
| PHP | `system()`, `exec()`, `shell_exec()`, `passthru()`, backticks, `popen()`, `proc_open()` with a string | `proc_open()` with an array (PHP 7.4 and later), Symfony `Process` with an array |
| Python | `os.system()`, `os.popen()`, `subprocess.*` with `shell=True` | `subprocess.run([...])` and friends (default `shell=False`) |
| Node.js | `child_process.exec()`, `execSync()`, `spawn()`/`execFile()` with `shell: true` | `execFile()`, `spawn()` with an argument array (default `shell: false`) |
| Java | Only if you start `sh -c` or `cmd.exe /c` yourself | `ProcessBuilder(List)`, `Runtime.exec(String[])` |
| Ruby | `system("one string")` with metacharacters, backticks, `%x()`, `IO.popen("string")`, `Kernel#open("|cmd")` | `system("prog", arg1, arg2)`, `Open3` with separate arguments |
| Perl | `system("one string")`, backticks, two-argument `open` with a pipe | `system("prog", @args)`, list-form `open` |
| Go | Only if you run `sh -c` yourself | `exec.Command(name, args...)` |
| C# / .NET | Only if you start `cmd.exe /c` or `powershell -Command` yourself | `ProcessStartInfo` with `ArgumentList` |

Two traps in that table. Java's `Runtime.exec(String)` does not use a shell but splits the string on whitespace, so a value with a space becomes extra arguments; the OWASP OS Command Injection Defense Cheat Sheet notes it has been deprecated since Java 18. And on Windows even the "direct" column ends up as a single command-line string, because Windows passes one string to the child and each program parses it itself (see [Windows is different](#windows-is-different)).

### Command injection and argument injection

CWE separates the two weaknesses, and the separation matters for both testing and fixing:

- **CWE-78, Improper Neutralization of Special Elements used in an OS Command** (Base, mapping allowed). Input changes the *structure* of a shell command: a `;`, `|`, `&&`, `$(…)` or newline in the input starts a command the developer never wrote. CWE describes two shapes: the application runs a fixed program and the input is meant to be an argument (the common web case), or the input selects the program itself.
- **CWE-88, Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')** (Base, mapping allowed). Input stays inside the intended program but adds or changes *options*: a value that starts with `-`, or contains a space where arguments are split, is read as a flag. Many programs have flags that run other programs, write files or read files.
- **CWE-77, Improper Neutralization of Special Elements used in a Command ('Command Injection')** is the Class-level parent of both (and of expression-language and LLM prompt injection). MITRE's mapping notes say to use it only with careful review; prefer CWE-78 or CWE-88 for a finding.

The cheat sheet puts the relationship well: every OS command injection is also an argument injection, but escaping shell metacharacters does nothing against option injection. A developer who "fixed" command injection with `escapeshellarg()` may still have a CWE-88 bug.

### Shell metacharacter classes

You do not need payload lists to test for this; you need to know which *classes* of syntax a shell interprets, so you can choose one or two probes per class. PortSwigger's topic page and WSTG-INJT-12 describe the same set:

| Class | Unix `sh`/`bash` | Windows `cmd.exe` | PowerShell | Why it matters to you |
|---|---|---|---|---|
| Command separator | `;` and newline (`%0a`) | `&` | `;` and newline | Ends the developer's command and starts yours |
| Background / unconditional | `&` (runs the first command in the background, then yours) | `&` | — | Works when the first command fails or hangs |
| Conditional chaining | `&&`, `||` | `&&`, `||` | `&&`, `||` (PowerShell 7 and later) | `||` runs yours only if the first command fails, useful when your input breaks it |
| Pipe | `|` | `|` | `|` | Starts yours with the first command's output as input |
| Command substitution | `$(…)` and backticks | none | `$(…)` subexpressions | Runs inside an argument, even inside double quotes on Unix |
| Redirection | `>`, `>>`, `<`, `2>` | `>`, `<` | `>` | Writes or reads files: never part of a proof on a client system |
| Quoting and escaping | `'`, `"`, `\` | `"`, `^` | `'`, `"`, backtick | Tells you whether you must close a quoted context first |
| Expansion | `$VAR`, `${…}`, `*`, `?`, `[…]`, `~`, `{a,b}` | `%VAR%`, `!VAR!` (delayed expansion) | `$var` | Can change arguments without any separator |
| Comment | `#` at the start of a word | `REM` (rarely useful) | `#` | Cuts off the rest of the developer's command |
| Word splitting | space, tab, `$IFS` | space, tab | space | An unquoted value with a space becomes two arguments |

On Unix both `;` and newline are separators, so a filter that blocks `;` but not `%0a` is incomplete. `cmd.exe` does not treat `;` as a separator at all, which is why a Unix-only probe set misses Windows targets.

### Output-based and blind

What you can observe decides how you prove execution:

- **Output-based (in-band):** the program's standard output or error comes back in the response (a ping result page, a "conversion log", an error that echoes stderr). A harmless command such as `id`, `whoami` or `hostname` gives a clear, low-impact proof.
- **Blind with timing:** the response waits for the command to finish, but its output is discarded. A `sleep` of a few seconds shows up as response time.
- **Blind, out-of-band:** the command runs asynchronously or its timing is hidden. A DNS lookup to a domain you control (Burp Collaborator, interactsh) proves execution without changing anything on the server.
- **Output redirection** (write the output to a file under the web root, then fetch it) is the textbook third blind method and is used in PortSwigger's labs. On client systems it is a file write, so it is out of scope for our proofs unless the client has agreed to it in writing; time and DNS give you the same certainty.

### Synchronous, asynchronous and second-order calls

The request you send and the process that runs are not always in the same place or time:

- **Synchronous:** the handler runs the command and waits. Time delays work.
- **Asynchronous:** the handler puts a job on a queue (Sidekiq, Celery, a Laravel queue, SQS) and returns `202 Accepted`. The process runs later, often on a different worker host. Time delays are invisible; DNS callbacks are the reliable signal, and they may arrive minutes later.
- **Second order (incubated, `WSTG-INJT-14`):** the value is stored first (a repository URL, a hostname in a monitoring check, a display name, a file name) and used in a command by a later feature or a scheduled job. The PAN-OS case in [Real-world cases](#real-world-cases) is exactly this: a value written by one component, used in a shell command by a cron job.

## What goes wrong

### Where shell calls hide

Almost nobody writes "execute this command" as a feature. The calls sit behind features that *process* something. When you map an application, treat these as likely shell-outs and ask (or look in the source) which program does the work:

| Feature | Typical programs | Inputs that tend to reach the command line |
|---|---|---|
| Image processing (resize, crop, thumbnails, watermark, format conversion) | ImageMagick (`convert`, `magick`, `identify`), GraphicsMagick, `exiftool`, `optipng`, `cwebp` | Width, height, quality, crop geometry, output format, watermark text, colour, the stored file name |
| Video and audio (transcoding, thumbnails, previews, waveforms) | `ffmpeg`, `ffprobe`, `sox` | Start time, duration, resolution, codec, the source URL for "import from URL" |
| PDF and document generation (invoices, reports, "export as PDF", certificates) | `wkhtmltopdf`, headless Chrome, LaTeX (`pdflatex`, `xelatex`), LibreOffice (`soffice --convert-to`), `pandoc`, Ghostscript, `pdftk`, `qpdf` | Page size, margins, header/footer text, document title, the template name, LaTeX content itself |
| Network diagnostics (admin panels, appliances, routers, hosting control panels, "test connection") | `ping`, `traceroute`/`tracert`, `nslookup`, `dig`, `host`, `whois`, `curl`, `nc`, `nmap` | Host name or IP, count, timeout, port, record type |
| DNS and domain features (domain verification, MX/SPF checks, "add a custom domain") | `dig`, `nslookup`, `host`, `whois` | Domain name, record type |
| Archive handling (upload a ZIP, bulk import, theme or plugin upload, "download all as ZIP") | `unzip`, `tar`, `7z`, `unrar`, `zip` | Archive name, entry names, the password field, output directory |
| Git and VCS integrations (import a repository, deploy from Git, show history, CI features) | `git clone`, `git ls-remote`, `git fetch`, `git log`, `git archive`, `hg`, `svn` | Repository URL, branch, tag or ref name, commit hash, file path, date filters |
| File conversion and inspection (document preview, text extraction, virus scan, MIME detection) | `file`, `pdftotext`, `pdfinfo`, `antiword`, `unoconv`, `clamscan`, `tesseract` | The stored file name, page range, language code |
| Backup, export and import (database export, site backup, migration tools) | `mysqldump`, `pg_dump`, `pg_restore`, `tar`, `rsync`, `scp`, `sftp` | Database or table name, schedule, destination host and path |
| Mail (contact forms, notifications in older PHP code) | `sendmail` through PHP `mail()` and its fifth parameter | The sender address, the "from" name |
| Certificates and crypto (CSR generation, "upload your certificate") | `openssl` | Common name and subject fields, passphrase, file names |
| Printing, signing, OCR, spreadsheets, package installs, custom "run script" buttons | `lp`, `gpg`, `tesseract`, `npm`/`pip` in plugin installers, site-specific shell scripts | Names, labels, versions, anything the script was given |

Appliances and embedded web interfaces (firewalls, VPN gateways, NAS boxes, printers, IoT controllers) are a special case: much of their management interface is a thin layer over shell scripts, and the web server often runs as root.

### String-built commands passed to a shell

**What happens:** the developer builds a string and passes it to a shell-invoking API:

```php
<?php
// Vulnerable: $host goes straight into a shell command
$host = $_POST['host'];
$output = shell_exec("ping -c 2 " . $host);
echo "<pre>$output</pre>";
```

A value of `192.0.2.10;id` makes the shell run `ping -c 2 192.0.2.10`, then `id`. Wrapping the value in quotes in the string (`"ping -c 2 \"$host\""`) changes the probe, not the outcome: on Unix, `$(…)` and backticks are still expanded inside double quotes, and a `"` in the input closes the quote.

**Why it matters:** the injected command runs with the privileges of the application process: it can read the application's configuration and secrets, reach internal networks the server can reach, and on badly configured hosts act as root. That is code execution on the server, the top of the rating scale.

**Where to look:** every feature in the table above, and particularly fields whose values look like command-line fragments: host names, sizes like `800x600`, time stamps like `00:00:05`, record types like `MX`, page ranges like `1-3`.

### Option injection without a shell

**What happens:** the application does the right thing and passes an argument list without a shell, but one list element is user input placed where the program parses options. A value starting with `-` is read as a flag. Getopt-style parsers also accept attached short options (`-u<value>`) and long options with `=` (`--option=value`), so a filter that only rejects values starting with `--` is not enough.

**Why it matters:** many common programs have *intended* options that run another program, write a file or read one. These are features, not bugs in those programs, and they are catalogued for researchers by the Sonar R&D team's [Argument Injection Vectors](https://sonarsource.github.io/argument-injection-vectors/) and the community-maintained [GTFOArgs](https://gtfoargs.github.io/). Examples of the risk, which you check for but do not chain on a client system:

- **`git`:** in `git clone`, `git ls-remote` and `git fetch`, a "repository URL" that starts with `-` can become `--upload-pack` (short form `-u`), which names the program Git runs to talk to the remote. Sonar's research on VS Code's Git integration (CVE-2022-30129) showed exactly this. Ref names, branch names and paths passed to `git log`, `git diff` or `git archive` are option positions too.
- **`curl`:** an injected `-o`/`--output` writes the response to a path of the attacker's choosing; `-K`/`--config` reads options from a file. The OWASP cheat sheet adds that `--` alone does not make curl safe: later arguments are still URLs, so the URL needs its own validation, `--globoff`, and SSRF controls.
- **`tar`:** GNU tar's `--checkpoint` and `--checkpoint-action` options can run a command during archive processing; `--use-compress-program` and `--to-command` also start programs. The same options become reachable through **wildcard injection** when a script runs `tar` with `*` in a directory where users choose file names: the shell expands a file named like an option into an option.
- **`ssh` and `scp`:** `-o` accepts configuration such as `ProxyCommand`, which runs a command. "Backup to remote host" features are the usual place.
- **`zip`:** its test options can run a command; Sonar's list notes that zip does not support `--` before the archive name, so most invocations with a user-controlled name are exposed.
- **`sendmail`** (through PHP `mail()`): `-X` writes a log file and `-O`/`-C` change configuration; the PHPMailer case in [Real-world cases](#real-world-cases) is this.
- **`find`, `wget`, `rsync`, `psql`, Chrome and others:** `-exec`, `--use-askpass` or `-O`, `-e`, `-o '|…'` and `--gpu-launcher` respectively (the last matters for PDF and screenshot features built on headless Chrome). If the binary is not in the catalogues, read its manual page for options that take a program name or an output path.

The end-of-options marker `--` (POSIX Utility Syntax Guideline 10) tells a well-behaved program that everything after it is an operand. It is the cheapest fix and the first thing to look for in code review, but it only works if the program honours it and if the user value comes after it.

### Escaping and filtering that is not enough

- **`escapeshellcmd()` instead of `escapeshellarg()`.** PHP's `escapeshellcmd()` escapes metacharacters in a whole command but lets the user add as many arguments as they like; the cheat sheet's `wget` example turns that into a second `--directory-prefix` option and code execution. `escapeshellarg()` makes the input a single argument.
- **`escapeshellarg()` alone.** It stops the shell from seeing metacharacters, but the single argument can still start with `-` and be an option. A PHP manual comment shows `-I bash -c …`-style option injection getting through it. On Windows it replaces `%`, `!` and `"` with spaces, which silently changes data, and its behaviour with multibyte strings depends on the locale.
- **Home-made quoting.** Wrapping the value in double quotes (still expands `$(…)` and backticks on Unix), stripping `;` and `&` (misses newline, `|`, `$(…)`), or "removing spaces" (misses `$IFS` and tabs).
- **Denylists of commands.** Blocking `cat`, `whoami` or `bash` misses the shell's own syntax; attackers do not need a specific program name.
- **Validation in the wrong place.** Client-side checks, checks before URL decoding (ASVS `v5.0.0-1.1.1` wants decoding exactly once, before validation), or validation of one parameter when the command is built from three.
- **Escaping for the wrong shell.** `shlex.quote()` is for POSIX shells; it does not make a string safe for `cmd.exe`. An escaped value placed inside an already-quoted context in the command string can still break out.

WSTG-INJT-12 has a long filter-evasion section. We do not reproduce one here: when a denylist is present, one or two variants are enough to show that the filter is incomplete (see [GT-WEB-CMD-9](#gt-web-cmd-9-quality-of-validation-and-filtering)), and the fix is the same either way.

### Filenames, headers and stored values as sources

The parameter in the form is not the only source:

- **Upload file names.** The `filename` in a multipart `Content-Disposition` header is attacker-controlled. Code that stores the upload under its original name and later runs `convert uploads/<name> …` through a shell has a command injection; code that passes the name as an argument without `--` may have an option injection. The `pdfinfojs` report in [Real-world cases](#real-world-cases) is a filename passed into a shell. ASVS `v5.0.0-5.3.2` (L1) asks for internally generated file names for file operations.
- **Archive entry names and metadata.** Names inside a ZIP or tar archive, and metadata read by one tool and passed to another (an image title read by `exiftool`, then used in an `ffmpeg` overlay), are second-hand user input.
- **HTTP headers and cookies.** `User-Agent`, `Referer`, `X-Forwarded-For`, `Host` and cookies get logged, then processed by shell scripts (log analysis, geo lookup, reverse DNS of the client IP). CGI passes headers to scripts as environment variables, which is how Shellshock (CVE-2014-6271) turned a header into a Bash command. PAN-OS CVE-2024-3400 started with a cookie value that ended up as a file name used in a command.
- **Stored values.** A hostname saved in a monitoring check, a repository URL in project settings, a printer name, a "custom ffmpeg preset": stored by one request, used in a command by a later job (`WSTG-INJT-14`).

### Interpreters behind the binary

Sometimes the program itself is the interpreter:

- **ImageMagick delegates.** ImageMagick hands some formats to external programs through command templates in `delegates.xml`. ImageTragick (CVE-2016-3714) was insufficient filtering of the file name or URL substituted into those templates, reachable by uploading an image file. Ghostscript, used for PostScript and PDF, has had its own sandbox escapes; the SEMrush report in [Real-world cases](#real-world-cases) is one.
- **LaTeX.** With shell escape enabled (`--shell-escape`, or `\write18` allowed), document content can run commands. ASVS `v5.0.0-1.2.8` (L2) requires LaTeX processors to be configured without it.
- **Git.** A cloned repository's configuration and hooks are not used on clone, but options such as `-c core.sshCommand=…` passed on the command line are, which is why argument positions in Git calls matter.
- **Scripting tools with "execute" switches.** `find -exec`, `awk`'s `system()`, `vim`/`less` escapes in "view file" features, `psql`'s `\!`.

These overlap with code injection and template injection (see [server-side template injection](/web/web-server-side-template-injection/)), and with file-upload handling, which belongs to the Server-Side Request and Files subcategory (not yet published).

### Windows is different

- **`cmd.exe` syntax.** `&`, `&&`, `|` and `||` chain commands; `;` does not. `%VAR%` is expanded even inside double quotes, `^` is the escape character, and there is no `$(…)` or backtick substitution. PowerShell is a third language again: `;` separates, `$(…)` is a subexpression, and the backtick escapes.
- **No argument vector.** Windows passes a single command-line string to the new process, and each program splits it with its own rules (the C runtime's, `CommandLineToArgvW`, or something custom). Language runtimes that accept an argument array have to *serialise* it into one string, and the escaping they choose may not match how the child parses it.
- **Batch files go through `cmd.exe`.** `CreateProcess()` runs `.bat` and `.cmd` files with `cmd.exe` implicitly, so a "no shell" call to a batch file is a shell call with `cmd.exe`'s rules. RyotaK's [BatBadBut](https://flatt.tech/research/posts/batbadbut-you-cant-securely-execute-commands-on-windows/) research (Flatt Security, April 2024) showed that several runtimes escaped arguments wrongly for that case. Node.js fixed it as CVE-2024-27980 (`spawn`/`spawnSync` could run injected commands through batch files "even if the shell option is not enabled"), and Python's documentation now warns that batch files may be launched in a shell regardless of the arguments.
- **Options start with `/` too.** Windows programs usually take `/flag` options, so a value starting with `/` is the Windows equivalent of a leading `-`.
- **Time delays.** `sleep` does not exist in `cmd.exe`. `ping -n 6 127.0.0.1` (about five seconds) is the usual substitute; `timeout /t 5` may refuse to run when its input is redirected, which is normal for a process started by a web server.

## Testing

Everything below assumes an **authorised** engagement with written scope and rules of engagement, a bug bounty programme whose rules allow injection testing, or a deliberately vulnerable lab. Requests and responses in this note are **illustrative**: hosts are fictional and outputs are shortened.

The tests are ordered the way the work usually goes. Most of the effort is in tests 1, 2, 10 and 11: finding *which* features start operating-system programs and *which* inputs reach their command lines. Black-box confirmation (tests 3 and 4) is short and deliberately boring: one bounded delay or one DNS lookup, repeated enough to rule out coincidence, and then you stop. Tests 5 to 9 refine where and how input reaches the program, and test 12 checks the blast radius and verifies the fix.

### Before you start

**Confirm the scope in writing.** A confirmed command injection means you made the client's server run something. Agree the following before the first probe:

| Item | What to agree |
|---|---|
| Targets | Hosts and API base paths in scope; whether production is in scope or a production-like staging copy is available (prefer staging for every black-box confirmation) |
| Proof level | Our default: stop at a bounded time delay or a DNS lookup of a unique name under your own collaborator domain. If the feature echoes program output, a read-only command that prints the host name or the current user may be agreed instead. Nothing that reads files, writes files, opens connections other than the one DNS lookup, or starts a shell |
| Techniques and tools | Manual probes in Burp Repeater; whether Burp Scanner active scans and commix are allowed, on which hosts and with which settings |
| Grey-box material | Source code or a list of the programs the application starts, the container or host image, the ImageMagick/Ghostscript/LaTeX configuration; with these, tests 10 and 11 find more with fewer requests |
| Windows and contacts | Testing hours, an emergency contact, and how to report a Critical immediately: an unauthenticated command injection on an internet-facing host should not wait for the final report |

**Proxy.** One Burp project per engagement with the target scope set; Logger on so every request is kept; Repeater for manual probes (its status bar shows the response time, which tests 2 and 3 need). Param Miner helps find unlinked parameters and headers in test 1. If Burp Scanner is allowed, give it a resource pool with one concurrent request and a delay, and point it at the requests you chose rather than letting it crawl.

**A collaborator you control.** Out-of-band confirmation needs a DNS listener whose interactions only you can see: **Burp Collaborator** (Burp Suite Professional) or a self-hosted **interactsh** server. Rules: one unique subdomain per request so you can tie an interaction to it; the label carries a static marker that you chose, never the output of a command or any data from the server (putting data into DNS names is exfiltration and out of scope); DNS only, no SMB or other listeners. This note writes the collaborator name as `<id>.oast.example`; replace it with your own.

**Safe-proof rules.**

- One proof per input. Once a delay or a DNS lookup is confirmed with its control, stop probing that input; more requests add risk, not evidence.
- Short delays: five seconds at most, a handful of requests per input, each delayed request paired with a zero-delay control. A delay inside a loop (a command run once per file in a batch job) multiplies; if a response takes far longer than expected, stop.
- No output redirection, no file creation, no downloads to the server, no reverse or bind shells, no persistence, no reading of configuration or secrets, no follow-on commands of any kind. Describe what an attacker *could* do in the report, from the process's privileges (test 12), instead of doing it.
- No denial of service: no fork-style probes, no long sleeps, no resource-heavy commands, no probes against features that fan out to many workers at once.
- Inputs that are stored (profile fields, project settings, uploaded file names) affect later jobs and possibly other users. Use only your own records, keep the probe inert (a delay or a DNS lookup), and restore the value afterwards. Label such steps **own test objects only**.

**Request-rate limits.** One or two requests per second for manual work unless the rules say otherwise. Automated tools: one thread and a delay between requests.

**Stop rules.**

- Stop everything and contact the client if error rates or response times climb across the application, if a job queue backs up, or if you trigger monitoring they asked you to avoid.
- If a response ever shows data that is not yours (another customer's file name in a conversion log, an environment dump in an error page), stop that line, keep only the minimum redacted evidence (endpoint, status, a masked excerpt), do not request more, and report it immediately.
- If a DNS interaction arrives for a probe you sent to an asynchronous feature, note the time and the source resolver and stop sending further probes to that feature; the job may run again on retries.

### GT-WEB-CMD-1: Map features that call OS programs

*Guler Tech methodology.* Implements the identification step of WSTG-INJT-12, using WSTG-INFO-06 (entry points) and WSTG-INFO-10 (application architecture), and lists the stored values that WSTG-INJT-14 (incubated vulnerabilities) needs.

#### What it checks

Which features plausibly start an operating-system program, which program, which inputs could reach its command line, and whether the call is synchronous, queued or scheduled. The output is the work list for every other test. Without it, black-box probing is guesswork across hundreds of parameters.

#### Prerequisites

A test account per role in scope (admin panels are where diagnostics features live); Burp Logger history of a full walk-through; API documentation if available.

#### Steps

1. Walk every feature with Logger on. Mark any feature from the [Where shell calls hide](#where-shell-calls-hide) table: uploads that are converted or thumbnailed, exports to PDF or archives, imports from URLs or repositories, diagnostics pages, domain and certificate features, backup and restore, mail settings, plugin or theme installers.
2. For each marked feature, ask which program does the work. Clues: product documentation ("requires ImageMagick 7", "uses wkhtmltopdf"), response headers and metadata in generated files (a PDF's `Producer` field, EXIF software tags, comments in generated images), error texts (test 2), installation guides that list system packages, and container images or Helm charts if the client shares them.
3. For each feature, list every input that could plausibly end up on that program's command line: dimensions, quality, format, page ranges, time stamps, host names, record types, repository URLs, branch names, the upload's file name, archive entry names, and any free-text field that appears *inside* the output (watermarks, headers and footers).
4. Note the timing model. A response that waits for the conversion is synchronous; `202 Accepted`, a job ID or a "we'll email you" message means a queue; values saved now and processed nightly are scheduled. This decides between test 3 (timing) and test 4 (DNS).
5. List stored values that a later job might use (monitoring host names, repository URLs, display names that end up in generated documents); they feed test 7.
6. Run Param Miner on the marked endpoints for unlinked parameters such as `format`, `quality`, `density`, `args`, `options` or `cmd`.

#### Observation

A work list like this (illustrative):

| Feature | Request | Input | Likely program | Timing | Notes |
|---|---|---|---|---|---|
| Avatar resize | `POST /api/me/avatar` | `width`, `height`, upload `filename` | ImageMagick | synchronous | PNG `Software` chunk names ImageMagick |
| Invoice PDF | `GET /invoices/{id}.pdf` | `paper`, footer text from settings | wkhtmltopdf | synchronous | PDF `Producer` field |
| Connectivity check (admin) | `POST /admin/diagnostics/ping` | `host`, `count` | `ping` | synchronous | Output shown in a `<pre>` block |
| Import from Git | `POST /api/projects/import` | `repo_url`, `branch` | `git clone` | queued | Returns `202` and a job ID |
| Custom domain | `POST /api/domains` | `domain` | `dig` or a DNS library | scheduled | Verified "within 15 minutes" |

#### Evaluation

No finding by itself. A feature whose output proves a program runs (a raw `ping` transcript, a stderr line) is a lead, not a vulnerability.

#### False positives

Features that look like shell-outs but use libraries: image resizing with Pillow, sharp (libvips bindings) or Java ImageIO; DNS lookups through the language's resolver; Git through libgit2 or JGit; PDFs through a library such as a pure-language PDF writer. Library calls can still have their own bugs, but not command injection. Grey-box access settles the question in minutes.

#### Automation

Logger exports and Param Miner. In CI the equivalent is an inventory of process-starting call sites (see [Static analysis](#static-analysis)): every one is a line on the work list and a candidate for test 10.

### GT-WEB-CMD-2: Response, timing and error baselines

*Guler Tech methodology.* Implements the "how to test" observation step of WSTG-INJT-12, together with WSTG-ERRH-01 (improper error handling), for the features on the work list from test 1.

#### What it checks

What normal looks like for each candidate input (status, body length, response time and its spread), and whether unusual but harmless values produce errors that reveal a program, its arguments or a shell. A shell or program error is the strongest black-box hint that input reaches a command line, and it costs nothing to collect.

#### Prerequisites

The work list from test 1; Burp Repeater; a spreadsheet or notes for timings.

#### Steps

1. **Timing baseline.** Send the unmodified request ten times, a second or two apart, and note the response times. Record the median and the slowest. Repeat at a different time of day if the application is busy; the spread decides how large a delay must be in test 3 to stand out.
2. **Content baseline.** Note the status code, length and any program output in the normal response (a `ping` transcript, a conversion log, a warning count).
3. **Invalid but harmless values.** For each input, send values the program would reject but that contain no shell syntax: a host name that does not resolve, a width with letters in it, an unknown output format, an empty value, an over-long value. Programs complain in recognisable ways (`ping: unknown host`, `convert: unable to open image`, `invalid geometry`, `fatal: repository … does not exist`).
4. **Quote balance.** Send the normal value with one unmatched single quote appended, then with a balanced pair of single quotes. A shell that receives an unterminated quote fails with a syntax error before any program starts; a balanced pair is harmless. The pair of responses is your signal: one errors, the other does not.
5. **Leading hyphen.** Send a value that starts with a hyphen followed by ordinary letters. A program that reads it as an unknown option usually says so (`invalid option`, `unrecognized option`, `unknown switch`); this is the cheapest hint for test 6.
6. Read every error page, JSON `detail` field, and log or "conversion report" that the application exposes for these requests.

#### Observation

Response fragments that point to a shell or a program command line (illustrative):

```text
sh: 1: Syntax error: Unterminated quoted string
convert: unrecognized option `-zz' @ error/convert.c/ConvertImageCommand/2875.
Command 'ping -c 2 198.51.100.7'' returned non-zero exit status 2.
fatal: repository 'nonexistent' does not exist
```

The first line comes from `/bin/sh` itself; the third shows the full command line the application built.

#### Evaluation

- **Finding (lead, then confirm with tests 3 or 4):** a shell syntax error appears for an unmatched quote and disappears for a balanced pair, or an error message shows the input embedded in a command line.
- **Finding in its own right:** errors that disclose full command lines, program paths, versions or internal host names are information disclosure (CWE-209), rated by what they reveal. ASVS `v5.0.0-13.4.6` (L3) covers detailed version disclosure of back-end components.
- **No evidence yet:** generic error pages for every malformed value. Continue with tests 3 and 4 for inputs on the work list.

#### False positives

- Validation messages that echo your input (`Invalid host: 198.51.100.7'`) without any program error text.
- Errors from a library rather than a program (a Python `ValueError`, a Java `NumberFormatException`): the input failed parsing before any process started.
- A single slow baseline request: cold starts, connection-pool waits and cache misses. That is why you take ten.

#### Automation

Burp Intruder with a small fixed list of the harmless values above, one thread, and a grep-match rule for shell and program error strings (`sh: `, `syntax error`, `unrecognized option`, `not found`, `returned non-zero`). In CI, a test that sends these values and asserts a uniform error response without program output catches verbose error handling early.

### GT-WEB-CMD-3: Blind confirmation with bounded time delays

*Guler Tech methodology.* Implements the blind command injection technique of WSTG-INJT-12 (time delays), limited to a short, repeated, controlled delay.

#### What it checks

Whether an input on the work list reaches a shell, for a synchronous feature whose response waits for the command to finish. The proof is a response time that follows the delay you asked for (five seconds → about five seconds longer, zero seconds → baseline), reproducibly, and nothing else.

#### Prerequisites

A synchronous candidate from test 1, its timing baseline from test 2, and agreement that time-based probes are in scope on this host.

#### Steps

1. Take the normal request in Repeater. Append to the input a Unix command separator followed by a five-second sleep (for example `;sleep 5`), and send it once.
2. Send the same request with a zero-second sleep in place of the five-second one. This is the control: it has the same length and syntax, so a WAF, a validator or an error path treats it the same way.
3. Alternate the two, three times each, with a few seconds between requests. Record each response time.
4. If there is no difference, repeat steps 1 to 3 once with a newline as the separator instead, then once with the probe wrapped as command substitution inside the value (a dollar sign and parentheses around the sleep). These cover the common contexts (end of command, inside a double-quoted argument). If you learned from test 2 that the value sits inside single quotes, close the quote before the separator and keep the rest of the command balanced. Stop after these variants; do not iterate through payload lists.
5. If a delay appears, repeat once with a three-second sleep to show proportionality.
6. For a Windows host, use the delay described in test 8 instead.

#### Observation

Response times for an illustrative `host` field on a diagnostics page (baseline median 0.21 s, slowest 0.34 s):

| Probe | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| separator + 5 s sleep | 5.24 s | 5.19 s | 5.31 s |
| separator + 0 s sleep | 0.22 s | 0.20 s | 0.25 s |
| separator + 3 s sleep | 3.23 s | — | — |

#### Evaluation

- **Pass (no finding):** delayed and control probes are indistinguishable from the baseline, for every variant in step 4.
- **Fail (confirmed command injection, CWE-78):** every delayed probe exceeds the baseline by roughly the requested delay, every control stays at the baseline, and the delay scales with the value you asked for. Stop testing this input and report.
- **Inconclusive:** one delayed response out of three, or delays that do not scale. Do not add requests; move to test 4 or to source review (test 10).

#### False positives

- **Network and platform jitter:** cold starts, garbage collection, connection-pool waits. They do not follow the requested value; the control pairs rule them out.
- **Rate limiting or throttling:** later requests get slower regardless of the probe. Space requests out and keep alternating.
- **A timeout in the application:** the request takes exactly the application's upstream timeout (often 30 or 60 seconds) for any malformed value. Proportionality rules this out.
- **The program itself is slow on invalid input:** `ping` waiting for a non-resolving name, `git` waiting for a TCP timeout. The zero-second control has the same malformation and shows the same slowness, so the difference between the two is what counts.

#### Automation

Burp Scanner's active scan includes OS command injection checks with time delays; scope it to the request you choose. **commix** can serve as an optional second opinion in a lab or with explicit client agreement, restricted to detection: limit it to the time-based technique (`--technique=t`; the default `rbtf` includes the file-based technique, which writes files to the target and is excluded on client systems), name the one parameter with `-p`, keep `--level=1`, set a short `--time-sec`, add `--delay` between requests, and avoid `--batch` (it auto-answers the "exploit?" prompts) or pin the answers with `--answers`. Never use `--os-cmd`, `--os-shell` or any option from commix's exploitation and post-exploitation groups on a client system. In CI, time-based probes belong in the regression tests of the [Regression tests](#regression-tests) section, where you assert the argument value instead of measuring time.

### GT-WEB-CMD-4: Blind confirmation with out-of-band DNS

*Guler Tech methodology.* Implements the out-of-band technique of WSTG-INJT-12, and WSTG-INJT-14 for values that a queued or scheduled job uses later.

#### What it checks

Whether an input reaches a shell when you cannot see timing: queued jobs, scheduled tasks, features whose response returns before the command runs, and inputs that test 3 left inconclusive. The proof is a DNS lookup of a unique name under your collaborator domain, arriving from the target's infrastructure, tied to one request.

#### Prerequisites

Burp Collaborator or your own interactsh server (see [Before you start](#before-you-start)); a fresh unique subdomain for every request; agreement that out-of-band probes are in scope.

#### Steps

1. Generate a unique collaborator subdomain and write down which request and input it belongs to.
2. **Control first.** Put the bare hostname into an input that should *not* reach a command (a comment field, a search box) and wait a few minutes. Any lookup now comes from mail scanners, link previewers, proxies or security products that resolve names they see; note their resolvers so you can tell them apart later.
3. Append to the candidate input a command separator followed by a DNS lookup of a second unique subdomain, using a standard resolver tool that is likely to exist on the host (for example `nslookup <id>.oast.example`). The label is a static marker you chose; never put command output, environment values or any server data into it.
4. For asynchronous features, wait. Jobs can run minutes later, on a different host, and sometimes several times because of retries.
5. If nothing arrives, try once with a newline separator and once with command substitution, each with its own fresh subdomain, as in test 3. Then stop.
6. Record the interaction: time, the full queried name, the resolver IP, and the record type.

#### Observation

An illustrative Collaborator entry:

```text
Type: DNS   Query: k7d2q9.oast.example   Record: A
From: 203.0.113.53 (target's resolver)   Time: 2026-03-04 10:42:17 UTC
```

The resolver is usually the target's DNS server or its cloud provider's resolver, not the application host itself.

#### Evaluation

- **Pass (no finding):** no interaction for the probe subdomains, while the control behaved as expected.
- **Fail (confirmed command injection, CWE-78):** a lookup for the unique probe subdomain arrives, the subdomain was never sent anywhere else, and the control subdomain shows no comparable lookup. Stop testing this input and report, including the delay between request and interaction (it shows the asynchronous path).
- **Inconclusive:** a lookup for the *control* subdomain, or lookups from resolvers you identified in step 2. Something resolves names it sees; it is not evidence of execution.

#### False positives

- Security products, URL scanners and link previewers resolving hostnames found in request bodies or stored fields. The step-2 control catches them.
- SSRF-like behaviour: the application resolves the value itself because it expects a host name (a "test connection" feature), which looks like execution but is not. Probe with the separator and with the bare hostname; only the separator form resolving points to a shell.
- Egress filtering: no DNS leaves the network, so a real injection produces nothing. Absence of interaction is not proof of safety; fall back to test 3 or test 10.

#### Automation

Burp Scanner uses Collaborator for out-of-band checks automatically. commix has an `--oob` option that can use a self-hosted interactsh server (`--oob-server`); the restrictions from test 3 apply. In CI, the equivalent of an out-of-band probe is a regression test that runs the queued job with a hostile-looking value and asserts the exact argument list (see [Regression tests](#regression-tests)).

### GT-WEB-CMD-5: Typed fields and input context

*Guler Tech methodology.* Supports WSTG-INJT-12 by checking the server-side validation of the inputs on the work list; maps to ASVS `v5.0.0-1.3.3` (sanitise data before it reaches a dangerous context).

#### What it checks

Whether inputs that *should* be narrow (a width, a page number, a time stamp, a record type, a format chosen from a drop-down) are actually validated on the server against that narrow format, or accepted as arbitrary strings. Developers often reason "it's only a number, so it can't be injected" and then build the command from the raw string. This test finds those inputs without sending any shell syntax at all.

#### Prerequisites

The work list from test 1 and the baselines from test 2.

#### Steps

1. For each narrow input, send values that break the expected format but contain only letters, digits and spaces: digits followed by letters for a width, a time stamp with extra text, a record type that is not in the drop-down, a format name that the UI never offers.
2. Change the JSON type: send a string where the API expects a number, an array where it expects a string, a nested object where it expects a scalar. Note whether the server rejects the request, coerces the value, or passes it on.
3. Check client-only constraints: `maxlength`, `pattern`, `<select>` options and JavaScript validation are not controls. Send the request directly from Repeater with a value outside them.
4. Look for inputs whose name suggests they are passed through: `options`, `args`, `flags`, `extra`, `preset`, `filter`, `quality`, `density`.
5. Note which inputs pass through unchanged: these are the inputs to prioritise in tests 3, 4 and 6.

#### Observation

| Input | Expected | Sent | Result (illustrative) |
|---|---|---|---|
| `width` | integer 16–2048 | digits followed by letters | `200 OK`, thumbnail generated, conversion log shows the raw value |
| `format` | `png`, `jpg`, `webp` | `tiff` (not in the UI) | `200 OK`, TIFF returned |
| `count` | integer 1–5 | JSON string with a space | `422`, "count must be an integer" |
| `record_type` | `A`, `MX`, `TXT` | `ANY` | `200 OK`, output of a full query |

#### Evaluation

- **Pass:** narrow inputs are rejected on the server unless they match the expected type and range, or an allow-list of values.
- **Finding (weak validation; severity depends on tests 3, 4 and 6):** inputs that reach a command are accepted outside their expected format. On its own this is a defence-in-depth gap against ASVS `v5.0.0-1.3.3`; combined with a confirmed probe, it is part of the CWE-78 or CWE-88 finding.

#### False positives

Lenient parsing that discards the extra text before the value is used (`parseInt` in JavaScript, `(int)` casts in PHP): the request succeeds, but the command receives only the number. The conversion log, an error message or source review tells you which value was used.

#### Automation

Schema-driven fuzzing with the OpenAPI definition (type-mismatch cases only); in CI, unit tests on the request validators that assert rejection of out-of-format values for every field that ends up in a command.

### GT-WEB-CMD-6: Option-like values and argument injection

*Guler Tech methodology.* Covers argument injection (CWE-88), which WSTG-INJT-12 does not test separately; checks ASVS `v5.0.0-1.2.5` (parameterised OS calls) together with `v5.0.0-1.3.3`.

#### What it checks

Whether a value that starts like an option (a leading hyphen, or a leading slash on Windows) is rejected before it reaches the program, and whether the call puts the end-of-options marker before user input. This is the gap left by applications that correctly avoid a shell, and by code "fixed" with `escapeshellarg()`. The proof never uses an option that runs a program, writes or reads a file, or changes configuration.

#### Prerequisites

The work list from test 1, especially inputs that sit in an argument position of `git`, `curl`, `wget`, `tar`, `zip`, `ssh`/`scp`, `rsync`, `ffmpeg`, ImageMagick, headless Chrome or `sendmail`; the program's manual page.

#### Steps

1. **Rejection check.** Send a value that begins with a hyphen and is otherwise ordinary (a hyphen followed by a few letters). A correct application rejects it with a validation error before any program starts. Note whether you get a validation error, a program error ("unknown option", from test 2), or a normal response.
2. **Harmless option probe.** If the hyphen value reached the program, choose an option that only changes *output*: the program's own version or help option is the usual choice, and many programs also have a "quiet" or "verbose" switch. Send it as the value. If the response, the conversion log or the error text now contains the program's version banner or help text, the value was parsed as an option.
3. **Attached and long forms.** If plain values starting with two hyphens are rejected but one hyphen is not (or the reverse), note it: getopt-style parsers accept short options with an attached value and long options with an `=` sign, so a filter that only checks one form is incomplete.
4. **Repository and URL inputs.** For `git`, `curl` and similar, check whether the application requires a scheme it recognises (`https://`, `ssh://`) at the start of the value. A required scheme is what closes the leading-hyphen gap for URLs, as in the VS Code fix in [Real-world cases](#real-world-cases).
5. **Windows.** Repeat step 1 with a leading slash for programs that take `/flag` options.
6. Look up the program in the [Argument Injection Vectors](https://sonarsource.github.io/argument-injection-vectors/) catalogue to judge impact for the report. Describe dangerous options there in prose; do not send them.

#### Observation

An illustrative "import from Git" feature that passed the value to `git ls-remote` as an argument. The value sent in step 1 was a hyphen followed by a letter that `git ls-remote` does not define; the job log returned:

```text
error: unknown switch `z'
usage: git ls-remote [--branches] [--tags] [--refs] [--upload-pack=<exec>]
                     [-q | --quiet] [--exit-code] [--get-url] [--sort=<key>]
                     [--symref] [<repository> [<patterns>...]]
```

The error and usage text show that the input was parsed as an option, and that `--upload-pack` (which names a program to run) is reachable from the same position.

#### Evaluation

- **Pass:** values that start with a hyphen (or a slash on Windows) are rejected for every input in an argument position, or the code places `--` before them and the program honours it, or the value must start with an allow-listed scheme or prefix.
- **Fail (argument injection, CWE-88):** a harmless option changes the program's behaviour or output. Rate it by the options reachable from that position according to the program's documentation and the catalogue (test 12 and [Rating findings](#rating-findings)); where documented options run programs, write files or change configuration, report it as a path to code execution without demonstrating it.
- **Weak finding:** the program reports "unknown option" for your value, which shows the value is parsed as an option, but no harmless option is accepted (for example because of a fixed format). Report as CWE-88 with lower confidence and recommend `--` and validation.

#### False positives

- The application's own validation message containing the word "option".
- Programs that treat the value as an operand because it follows `--` or because they take no options in that position: the response is a "file not found" or "repository not found" error for a path that literally begins with a hyphen.

#### Automation

Few scanners test argument injection. Source review (test 10) finds it faster: look for process calls whose argument list contains a request value without a preceding `--`. In CI, add a regression test that passes a value beginning with a hyphen and asserts a validation error (see [Regression tests](#regression-tests)).

### GT-WEB-CMD-7: Filenames, headers and second-order sources

*Guler Tech methodology.* Implements WSTG-INJT-14 (incubated vulnerabilities) and the file-name aspects of WSTG-BUSL-09 (upload of malicious files) for command sinks; checks ASVS `v5.0.0-5.3.2` (internally generated file names).

#### What it checks

Whether values that do not look like parameters reach a command line: the `filename` of an upload, names inside archives, HTTP headers and cookies that get logged and processed, and values stored now and used by a later job. These are the sources behind several of the cases in [Real-world cases](#real-world-cases).

#### Prerequisites

Upload, import and settings features from test 1; your collaborator (test 4); **own test objects only** for stored values.

#### Steps

1. **Upload file names.** Upload a valid, small file of the expected type. First check how the name is handled: does the application keep the original name (it appears in download links, `Content-Disposition` headers, conversion logs), or replace it with a generated identifier? If the original name is kept, repeat the upload with a name that contains a leading hyphen, then with the time-delay probe of test 3 placed in the name before the extension, with its zero-delay control. Keep the file content benign.
2. **Archive entries.** If the feature accepts archives that are unpacked or listed, check in a lab or staging copy whether entry names appear in logs or later commands. Use names with a leading hyphen only; do not test path traversal here (it belongs to the file-handling notes).
3. **Headers and cookies.** For features that log and later process client data (reverse DNS of the client address, log analysers, geo lookups, analytics jobs), place the out-of-band probe of test 4 in one header at a time (`User-Agent`, `Referer`, `X-Forwarded-For`), each with its own unique subdomain, and wait.
4. **Stored values.** For each stored value on the work list (repository URL, monitoring host, printer or device name, a display name that appears in generated PDFs), save the out-of-band probe with its own subdomain on your own test object, trigger or wait for the job that uses it, then restore the original value.
5. Record the time between storing the value and any interaction: it identifies the job.

#### Observation

An illustrative upload whose stored name later reached a thumbnail job:

```http
POST /api/me/avatar HTTP/1.1
Host: app.example.com
Cookie: session=<SESSION_USER_A>
Content-Type: multipart/form-data; boundary=x

--x
Content-Disposition: form-data; name="file"; filename="avatar$(sleep 5).png"
Content-Type: image/png

<valid PNG bytes>
--x--
```

The upload itself returned at once; the thumbnail endpoint polled afterwards took about five seconds longer than for the control upload whose name had a zero-second sleep.

#### Evaluation

- **Pass:** the application stores uploads under generated names (ASVS `v5.0.0-5.3.2`), passes stored values to programs as single arguments after `--`, and no probe produces a delay or interaction.
- **Fail (CWE-78 or CWE-88, second-order):** a delay or a DNS interaction follows from a file name, header, cookie or stored value. The finding belongs to the component that *uses* the value, even if another component stored it; say both in the report.

#### False positives

- Log processors that resolve host names they find, without a shell (control as in test 4 step 2).
- Delays caused by the larger processing work of a renamed file type rather than your probe; the zero-delay control upload rules it out.

#### Automation

Out-of-band checks in Burp Scanner cover headers when the scan is configured to insert into them. In CI, a test that uploads a file with a hostile-looking name and asserts that the stored name is generated and the processing call receives a single argument.

### GT-WEB-CMD-8: Windows targets

*Guler Tech methodology.* Adapts WSTG-INJT-12 to Windows hosts (`cmd.exe`, PowerShell and batch files), following the differences in [Windows is different](#windows-is-different).

#### What it checks

Whether inputs reach `cmd.exe` or PowerShell on a Windows host, including the indirect case where a "no shell" call starts a `.bat` or `.cmd` file. A Unix-only probe set misses these targets: `;` is not a separator in `cmd.exe` and `sleep` does not exist there.

#### Prerequisites

Signs of a Windows host from test 1 (IIS or ASP.NET headers, Windows paths or drive letters in errors, `.bat`/`.cmd` names in documentation); baselines from test 2.

#### Steps

1. **Separator.** Use `&` as the command separator for `cmd.exe` and `;` for PowerShell (in PowerShell `&` is the call operator, not a separator). If you do not know which shell is involved, test both, each with its own control.
2. **Delay without sleep.** In `cmd.exe`, the usual bounded delay is a `ping` of the loopback address with a count of six, which takes about five seconds; the control is the same `ping` with a count of one. PowerShell has a native sleep cmdlet. Apply the same pairing and repetition as test 3.
3. **Out-of-band.** `nslookup` exists on Windows hosts, so the DNS probe of test 4 works unchanged (for example `nslookup <id>.oast.example` after the separator), with its own unique subdomain and the same control.
4. **Option prefix.** Repeat test 6 with a leading slash, the Windows option prefix.
5. **Batch files (grey-box).** If you have source or documentation, look for process calls that start a `.bat` or `.cmd` file with user input in the arguments. Check the runtime version: Node.js fixed CVE-2024-27980 in its April 2024 security releases, after which `spawn` refuses `.bat` and `.cmd` files without the `shell` option; Python's documentation warns that batch files may run in a shell regardless of `shell=False`.

#### Observation

Paired timings as in test 3 (about five seconds for the six-count `ping`, baseline for the one-count control), or a DNS interaction from the target's resolver as in test 4.

#### Evaluation

- **Pass:** no delay or interaction for the `cmd.exe` and PowerShell variants; no batch-file calls with user input in their arguments, or batch files called only with allow-listed values.
- **Fail (CWE-78):** reproducible delays that follow the requested count, or a DNS interaction for the unique subdomain. For batch-file calls with user input on an unpatched runtime, report a CWE-78 risk from source review even if a black-box probe is inconclusive, and say so.

#### False positives

- `ping` against an unreachable address is slow for reasons that have nothing to do with you; always ping the loopback address, and keep the one-count control.
- `timeout /t` failing silently when its input is redirected, which is normal for a process started by a service: a "no delay" result with `timeout` is not evidence of safety.

#### Automation

Burp Scanner includes Windows variants in its OS command injection checks. commix supports Windows targets (`--os`), with the restrictions from test 3. In CI on Windows runners, a regression test that starts the real batch file with a value containing `&` and asserts the batch file received it as one literal argument.

### GT-WEB-CMD-9: Quality of validation and filtering

*Guler Tech methodology.* Covers the filter-assessment part of WSTG-INJT-12 as a finding about the filter, not an evasion exercise; checks ASVS `v5.0.0-1.2.5`, `v5.0.0-1.3.3` and `v5.0.0-1.1.1` (decode once, before validation).

#### What it checks

When an input that reaches a command is protected by a filter, whether that filter is an allow-list of the expected format (good) or a denylist of characters or words (incomplete by design), and whether it runs at the right point (after decoding, on the server, on every input that builds the command). The goal is to document the filter's design weakness with one or two variants, then recommend the structural fix; it is not to find "the" bypass.

#### Prerequisites

An input from tests 2 to 8 where probes are blocked or sanitised (a `400` with "invalid characters", a WAF block page, characters silently removed).

#### Steps

1. **Characterise the filter with harmless values.** Send the normal value with a single semicolon appended, then with a single pipe, then with a single newline (URL-encoded), each on its own and without any command after it. Note which are rejected, stripped or passed. A filter that stops `;` and `|` but passes a newline is a denylist with a gap, because a newline is a command separator in POSIX shells (see [Shell metacharacter classes](#shell-metacharacter-classes)).
2. **Allow-list or denylist?** Send a value that is valid for the format but unusual (an IPv6 address for a host field, a long but legal domain name). An allow-list based on the format accepts it; a crude denylist sometimes rejects it, and a lax one accepts anything else too.
3. **One confirming variant.** If step 1 found a separator class that passes, repeat the time-delay pair of test 3 once with that separator. One variant is enough to show the filter is incomplete; stop there.
4. **Decoding order.** Send the passing character URL-encoded twice. If the application decodes again after validating, ASVS `v5.0.0-1.1.1` is not met, whatever the outcome of the probe.
5. **Placement.** Check whether the filter applies to every input that builds the command (test 1 work list) and to the same input on every endpoint (the API, the mobile back end, the admin panel).
6. **WAF versus application.** If the block page comes from a WAF or CDN, record that the application itself is unprotected behind it; a WAF is not a fix.

#### Observation

| Probe | Result (illustrative) |
|---|---|
| value + `;` | `400` "Invalid characters in host" |
| value + `|` | `400` "Invalid characters in host" |
| value + newline (`%0a`) | `200`, normal output |
| value + newline + 5 s sleep / + 0 s sleep, three each | about 5.2 s / about 0.2 s |
| IPv6 literal | `400` "Invalid characters in host" (the colon is denied) |

#### Evaluation

- **Pass:** the input is validated on the server against an allow-list of the expected format (or of allowed values) after a single decode, for every endpoint, and the command is built without a shell.
- **Fail (CWE-78, with a filter finding):** a denylist filter lets one class of shell syntax through and the confirming probe succeeds. Report the injection and, separately in the recommendation, that the denylist approach cannot be fixed by adding characters.
- **Finding (defence in depth, Low to Medium):** a denylist is in place, no variant succeeded, but the command still goes through a shell. Recommend argument arrays and allow-list validation; the current state depends on a list nobody can prove complete.

#### False positives

A WAF in front of a correct implementation: the WAF blocks, but the application would pass the value as a single argument anyway. Grey-box review or a staging host without the WAF settles it.

#### Automation

Not worth automating as an evasion exercise. In CI, unit tests on the validator with the metacharacter classes from the table in [How it works](#how-it-works) (one value per class) assert rejection; the stronger test asserts the argument array (see [Regression tests](#regression-tests)).

### GT-WEB-CMD-10: Source and greybox review

*Guler Tech methodology.* The white-box counterpart of WSTG-INJT-12, following the "dangerous command execution APIs" list in that page; checks ASVS `v5.0.0-1.2.5` and `v5.0.0-1.3.3` at the code level.

#### What it checks

Every place the code starts a process: whether it goes through a shell, which arguments come from requests, stored data or files, whether those arguments are validated against an allow-list, and whether `--` precedes them. With source access this test finds more than all black-box tests together, with no risk to the client's systems.

#### Prerequisites

Read access to the application source (and its dependencies, where wrappers live), or a client engineer who can answer questions while you read; Semgrep and, if the client uses GitHub, CodeQL results.

#### Steps

1. **Inventory the sinks.** Search for the process-starting APIs of each language in the [Shell or no shell](#shell-or-no-shell) table, plus wrapper libraries (Symfony `Process`, Laravel `Process`, `execa`, `shelljs`, `sh`, `plumbum`, Apache Commons Exec). A plain search is a good start:

   ```bash
   grep -rnE "child_process|execSync|execFile|spawn\(|shell_exec|passthru|proc_open|popen|system\(|subprocess|os\.system|Runtime\.getRuntime|ProcessBuilder|Process::run|fromShellCommandline" \
     --include='*.js' --include='*.ts' --include='*.py' --include='*.php' --include='*.java' --include='*.kt' src/ app/ lib/
   ```

2. **Run Semgrep.** The registry's command-injection ruleset (`semgrep scan --config p/command-injection`) and the language rules cover the main sinks. Rules worth knowing by ID: `subprocess-shell-true` and `dangerous-subprocess-use-audit` (Python), `detect-child-process` (Node.js), `exec-use` (PHP), `command-injection-process-builder` (Java).
3. **Run CodeQL** where available. The relevant queries are `js/command-line-injection`, `js/second-order-command-line-injection` (despite the name, argument injection: user values passed to commands such as `git ls-remote` that can run programs through their options), `js/indirect-command-line-injection` (command-line arguments of a Node.js program forwarded to a shell), `js/shell-command-constructed-from-input` (library functions that build shell commands from their parameters), `py/command-line-injection`, `py/shell-command-constructed-from-input` and `java/command-line-injection`.
4. **Trace each hit.** For every sink, answer: shell or no shell? Which arguments are not literals? Where does each come from (request, database, file name, archive entry, header, environment)? Is it validated, and against an allow-list or a denylist? Is there a `--` before user values, and does the program honour it?
5. **Check wrappers and helpers.** A helper such as `runCommand(cmd: string)` that calls a shell turns every caller into a candidate; review the callers.
6. **Hand the results back to black-box.** For a suspicious sink with an unclear data flow, a single test-3 or test-4 probe on staging confirms it.

#### Observation

A Semgrep hit and the trace (illustrative):

```text
app/services/thumbnail.py:41
  python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
  subprocess.run(f"convert {src} -resize {w}x{h} {dst}", shell=True)

trace: w, h  <- request JSON (validated as int by the serializer)
       src   <- storage path built from upload.original_name (not validated)
```

#### Evaluation

- **Pass:** every sink uses an argument list without a shell, user-derived values are validated against an allow-list, `--` precedes positional user values for programs that support it, and file names are generated by the application.
- **Fail (CWE-78):** a shell-invoking call with a non-literal value derived from untrusted input without strict allow-list validation. Report from source even without a black-box probe; state which source the value comes from.
- **Fail (CWE-88):** an argument-list call where an untrusted value sits in an option position without `--` or a leading-character check.
- **Finding (defence in depth):** a shell-invoking call with values that are currently constants or strictly validated. Recommend moving to argument lists, since the next change can make it exploitable.

#### False positives

Static-analysis hits on constant command strings, on build or developer scripts that never run in production, or on values that are validated upstream in a way the tool cannot see. Confirm the data flow by reading the code; record why each dismissed hit is safe.

#### Automation

Semgrep and CodeQL in CI on every pull request, with the rules above set to block. Keep an allow-list of reviewed sinks in the repository so that a *new* process call always triggers review.

### GT-WEB-CMD-11: Vulnerable wrappers and delegate configuration

*Guler Tech methodology.* Complements WSTG-INJT-12 and WSTG-BUSL-09 for programs that interpret their input; checks ASVS `v5.0.0-1.2.8` (LaTeX without shell escape), `v5.0.0-15.2.1` (components within their remediation time frames) and `v5.0.0-15.2.5` (extra protection around risky components).

#### What it checks

Whether the programs and wrapper libraries behind the features in test 1 are versions with known command-execution flaws, and whether their own configuration lets document content start programs: ImageMagick delegates and coders, Ghostscript's SAFER mode, LaTeX shell escape, and wrapper packages that build shell strings. This is mostly a configuration and version review; you do not upload exploit files to prove it.

#### Prerequisites

Grey-box access to the image or host (package lists, `policy.xml`, `texmf.cnf`, lock files), or at least the version information gathered in test 1 (metadata in generated files, error banners).

#### Steps

1. **Inventory versions.** List the versions of ImageMagick or GraphicsMagick, Ghostscript, ffmpeg, LibreOffice, wkhtmltopdf or the headless browser, the TeX distribution, ExifTool, and the wrapper libraries in the application's lock files. Black-box clues: a PNG `Software` chunk, a PDF `Producer` field, an error banner.
2. **Dependency scanners.** Run the ecosystem's audit tool on the lock files (`npm audit`, `pip-audit`, `composer audit`, OWASP Dependency-Check for Java) and a container scanner such as Trivy on the image for operating-system packages. Look for advisories whose class is command injection, argument injection or arbitrary code execution through document parsing.
3. **ImageMagick policy.** On the host, `magick identify -list policy` (ImageMagick 7) shows the active security policy. Check that delegates are disabled (`<policy domain="delegate" rights="none" pattern="*"/>`) unless a specific one is needed, that coders the feature does not need (PostScript, PDF, EPS, XPS, MVG, MSL, SVG, URL-based coders) are not readable, and that resource limits are set. ImageMagick documents example policies (`open`, `limited`, `secure`, `websafe`); `open` is the default, and `websafe`, which limits I/O to GIF, JPEG and PNG, suits most avatar and thumbnail features.
4. **Ghostscript.** Since 9.50, Ghostscript runs with SAFER on by default. Search the code and delegate configuration for `-dNOSAFER` or `-dDELAYSAFER`, which turn file-access protection off, and check that the installed version is supported and patched.
5. **LaTeX.** Check that the processor runs without `--shell-escape` and that `shell_escape` in the TeX configuration is not set to fully enabled; if restricted shell escape is used, review its allowed command list (ASVS `v5.0.0-1.2.8`).
6. **Headless browsers and converters.** Check the flags the application passes to headless Chrome, wkhtmltopdf or LibreOffice (for example whether the sandbox is disabled, whether local file access is enabled), and whether user-supplied HTML or documents reach them.

#### Observation

An illustrative policy check on a staging host:

```text
$ magick identify -list policy
Path: /etc/ImageMagick-7/policy.xml
  Policy: Resource
    name: memory
    value: 256MiB
  Policy: Coder
    rights: None
    pattern: {PS,PS2,PS3,EPS,PDF,XPS}
```

Coders for PostScript and PDF are disabled; no delegate policy is listed, so delegates are still allowed.

#### Evaluation

- **Pass:** supported, patched versions; ImageMagick delegates off and unneeded coders disabled; Ghostscript without `-dNOSAFER`; LaTeX without shell escape; no wrapper with a known command-injection advisory.
- **Fail (rated by the advisory and reachability):** a version with a known command-execution flaw that a user-supplied file or value can reach (the ImageTragick and Ghostscript cases in [Real-world cases](#real-world-cases)); LaTeX with shell escape on user-controlled content; Ghostscript with SAFER disabled on user files. Use the advisory's CWE (often CWE-78 or CWE-94) and say that reachability was established from the feature map, not by exploitation.
- **Finding (hardening, Low to Medium):** current versions but a permissive policy (default `open` ImageMagick policy, all coders enabled) on a feature that processes user uploads.

#### False positives

- A vulnerable package installed in the image but never invoked by any feature; report it as patch hygiene, not as a command-execution path.
- Scanner advisories that apply only to a different build option or platform; read the advisory before rating.

#### Automation

Dependency and container scanning in CI (Dependabot or Renovate plus a scanner such as Trivy), with a policy that fails the build on known command-execution advisories in packages that process user files. Add a check that the deployed `policy.xml` matches the hardened version kept in the repository.

### GT-WEB-CMD-12: Execution context, hardening and fix verification

*Guler Tech methodology.* Supports the remediation and permissions guidance of WSTG-INJT-12; checks ASVS `v5.0.0-13.2.2` (least privilege for communication with operating-system services) and `v5.0.0-15.2.5` (sandboxing or isolation around dangerous functionality), and verifies fixes for findings from tests 2 to 11.

#### What it checks

Two things. First, the blast radius of a confirmed or suspected injection, established from configuration rather than by running commands: which account the process runs as, what it can read, where it can connect, and what else shares the host. Second, whether a fix actually removed the shell or option path, rather than adding a filter that happens to stop the original probe.

#### Prerequisites

Grey-box access to deployment configuration (Dockerfile, Kubernetes manifests, systemd units, IIS application pool settings), or a client engineer who can answer; for fix verification, the original finding with its probe and control, and the code change.

#### Steps

1. **Account and privileges.** From configuration, identify the user the web or worker process runs as (`USER` in the Dockerfile, `runAsNonRoot` and `runAsUser` in the pod `securityContext`, `User=` in the systemd unit, the application pool identity on IIS). Root or `LocalSystem` makes every finding worse.
2. **File system and secrets.** Check whether the root file system is read-only, which volumes are mounted, and whether secrets are available to the process as environment variables or files (database credentials, cloud keys, signing keys). These are what an attacker would reach; list them in the report without reading them.
3. **Network reach.** Check egress rules: can the worker reach the internet, the cloud metadata endpoint, internal admin services, the database of other applications? On cloud hosts, note whether the instance or pod has a cloud role attached: code execution on the host usually means access to that role's temporary credentials through the metadata service (our AWS series covers this under EC2 and IMDS).
4. **Neighbours.** Note whether other applications or systems share the host or the container's privileges; this decides Scope (other tenants of the same application raise the severity for scale, not Scope) in the CVSS vector (see [Rating findings](#rating-findings)).
5. **Fix verification.** Re-run the original probe and its control (same input, same method). Then re-run one variant from each relevant class (the alternate separators of test 3, the leading hyphen of test 6, the file-name path of test 7). Read the code change: the fix should replace the shell call with an argument list, validate against an allow-list, and add `--` where the program supports it; check for a new regression test that asserts the argument list.
6. **Sibling sinks.** Check that the same helper or pattern is fixed everywhere it is used, not only at the reported endpoint.

#### Observation

An illustrative excerpt from a pod specification that limits the damage of a worker compromise:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
```

#### Evaluation

- **Pass (hardening):** the process runs as a dedicated unprivileged account, with a read-only file system, dropped capabilities, no unnecessary secrets, and egress limited to what the feature needs. This does not make an injection acceptable, but it lowers the impact and belongs in the report.
- **Fail (hardening finding, Low to Medium on its own):** processes that start external programs run as root or `LocalSystem`, with write access to the application's code, with broad egress or with cloud credentials they do not need.
- **Fix verified:** the original probe and every variant show no delay, interaction or option parsing; the code uses an argument list without a shell; regression tests exist.
- **Fix incomplete:** the original probe fails but a variant from another class still works, or the code still builds a shell string with a new filter. Re-open the finding.

#### False positives

Security contexts in manifests that are overridden at deploy time (a Helm value, a mutating admission policy). Ask for the rendered manifest of the running workload, not the template.

#### Automation

Policy-as-code checks in CI (for example Kubernetes admission policies or a configuration scanner) that reject workloads running as root or without a read-only root file system. For fixes, the regression tests in [Regression tests](#regression-tests) are the automation: they fail if someone reintroduces a shell.

## Secure implementation

### Design rules

In order of preference, following the OWASP OS Command Injection Defense Cheat Sheet and ASVS `v5.0.0-1.2.5` (L1):

1. **Do not start a program.** Use a library for the job: Pillow, sharp or a Java imaging library for images; the language's resolver for DNS; a TCP connect with a timeout instead of `ping`; libgit2 or JGit instead of the `git` binary; a PDF library instead of a converter. No process, no command line, no injection.
2. **If you must, never use a shell.** Start the program directly with an **argument list**. Each element reaches the program as one argument, whatever it contains, so shell metacharacters are just characters.
3. **Put `--` before user values** for programs that honour it (POSIX Utility Syntax Guideline 10), and reject values that start with `-` (or `/` on Windows) anyway, because not every program honours `--`. For URLs, require an allow-listed scheme at the start.
4. **Validate against an allow-list** of the expected format or of allowed values: an integer range, a value from a fixed set, a host name pattern, a URL with an allowed scheme. Do this on the server, after decoding once (ASVS `v5.0.0-1.1.1`, `v5.0.0-1.3.3`).
5. **Generate file names** for anything you pass to a program (ASVS `v5.0.0-5.3.2`). Keep the user's name in the database for display only.
6. **Fix the program, not only the call:** a hardened ImageMagick policy, Ghostscript with SAFER, LaTeX without shell escape (ASVS `v5.0.0-1.2.8`).
7. **Limit the blast radius:** a dedicated unprivileged account, a sandbox or separate container for risky converters, restricted egress (ASVS `v5.0.0-13.2.2`, `v5.0.0-15.2.5`).
8. **Escaping is the last resort.** `escapeshellarg()` and `shlex.quote()` are correct for what they do (make one shell argument for a POSIX shell), but they do not stop option injection and they are easy to misuse. If you find yourself escaping, the call should probably be an argument list instead.

### Node.js

Use `execFile()` or `spawn()` with an argument array and the default `shell: false`. Never `exec()` or `execSync()` with request data, and never `shell: true` with arguments: Node.js deprecated passing `args` together with the `shell` option (DEP0190, documentation-only in v22.15.0 and v23.11.0, runtime deprecation from v24.0.0) because the values are only joined with spaces, not escaped.

```javascript
// Vulnerable
const { exec } = require('node:child_process');
app.post('/admin/diagnostics/ping', (req, res) => {
  exec(`ping -c 2 ${req.body.host}`, (err, stdout) => res.type('text').send(stdout));
});
```

```javascript
// Fixed: allow-listed input, argument array, no shell, end-of-options marker, timeout
const { execFile } = require('node:child_process');
const net = require('node:net');

const HOSTNAME = /^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

app.post('/admin/diagnostics/ping', (req, res) => {
  const host = String(req.body.host ?? '');
  const count = Number(req.body.count ?? 2);
  if (!(net.isIP(host) || HOSTNAME.test(host))) return res.status(400).json({ error: 'invalid host' });
  if (!Number.isInteger(count) || count < 1 || count > 5) return res.status(400).json({ error: 'invalid count' });

  execFile('ping', ['-c', String(count), '--', host], { timeout: 10_000, maxBuffer: 64 * 1024 },
    (err, stdout) => {
      if (err && err.killed) return res.status(504).json({ error: 'timeout' });
      res.type('text').send(stdout);
    });
});
```

The host pattern rejects a leading `-` on its own, so `--` is a second layer. On Windows, do not point `execFile()` or `spawn()` at a `.bat` or `.cmd` file with user input (see [Windows-specific fixes](#windows-specific-fixes)). Wrapper packages such as `execa` take an argument array by default; check that nobody turned their `shell` option on.

### Python and Django

Use `subprocess.run()` with a list and the default `shell=False`. Never `os.system()`, `os.popen()` or `shell=True` with user data. Validate in the form or serializer, not in the view.

```python
# Vulnerable
import subprocess

def thumbnail(src_path, width, height, dst_path):
    subprocess.run(f"convert {src_path} -resize {width}x{height} {dst_path}", shell=True, check=True)
```

```python
# Fixed: validated integers, generated file names, argument list, no shell, timeout
import subprocess
import uuid
from pathlib import Path

from django import forms
from django.conf import settings


class ThumbnailForm(forms.Form):
    width = forms.IntegerField(min_value=16, max_value=2048)
    height = forms.IntegerField(min_value=16, max_value=2048)


def thumbnail(upload, width: int, height: int) -> Path:
    workdir = Path(settings.MEDIA_ROOT) / "work"
    src = workdir / f"{uuid.uuid4().hex}.png"        # generated name, never the upload's name
    dst = workdir / f"{uuid.uuid4().hex}.png"
    with src.open("wb") as fh:
        for chunk in upload.chunks():
            fh.write(chunk)
    subprocess.run(
        ["magick", str(src), "-resize", f"{width}x{height}", str(dst)],
        check=True, capture_output=True, timeout=30,
    )
    return dst
```

Better still, do the resize in-process with Pillow and drop the external program entirely. Two notes from the Python documentation: on POSIX, `shlex.quote()` makes a safe single argument for a POSIX shell only (not for `cmd.exe`), and on Windows, batch files may be run through a shell regardless of `shell=False`.

### Java and Spring

Use `ProcessBuilder` with a `List<String>`. Avoid `Runtime.exec(String)`, which splits on whitespace (and is deprecated since Java 18), and never wrap the command in `sh -c` or `cmd.exe /c`. Validate the request with Bean Validation and check URL schemes explicitly.

```java
// Vulnerable: a shell, and the URL concatenated into it
new ProcessBuilder("sh", "-c", "git clone " + repoUrl + " " + dir).start();
```

```java
// Fixed: scheme allow-list, argument list, end-of-options marker, timeout
import java.net.URI;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Service
public class RepositoryImporter {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("https");

    public void cloneRepository(String repoUrl, Path targetDir) throws Exception {
        URI uri = URI.create(repoUrl);                     // throws on malformed input
        if (uri.getScheme() == null || !ALLOWED_SCHEMES.contains(uri.getScheme().toLowerCase())
                || uri.getHost() == null) {
            throw new IllegalArgumentException("unsupported repository URL");
        }
        List<String> cmd = List.of("git", "clone", "--depth=1", "--", uri.toString(), targetDir.toString());
        Process process = new ProcessBuilder(cmd)
                .redirectErrorStream(true)
                .start();
        if (!process.waitFor(60, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IllegalStateException("clone timed out");
        }
        if (process.exitValue() != 0) {
            throw new IllegalStateException("clone failed");
        }
    }
}
```

The scheme check is what closes the leading-hyphen gap for URLs: a value that must start with `https://` cannot start with `-`. `git clone` documents `[--]` before the repository in its synopsis. Keep SSRF in mind separately: an allowed scheme does not stop `https://10.0.0.5/` (the Server-Side Request and Files subcategory covers that).

### PHP and Laravel

In PHP, prefer Symfony's `Process` component with an **array** of arguments; its documentation calls this the recommended way to define commands and reserves `Process::fromShellCommandline()` for when you need shell features. PHP's own `proc_open()` also accepts an array (PHP 7.4 and later) and then starts the program directly.

```php
<?php
// Vulnerable: escapeshellcmd() lets the user add options; a shell runs the string
$cmd = escapeshellcmd("git clone " . $request->input('repo_url') . " " . $dir);
shell_exec($cmd);
```

```php
<?php
// Fixed (Symfony Process): validated URL, array command, no shell, end-of-options marker
use Symfony\Component\Process\Process;

$validated = $request->validate([
    'repo_url' => ['required', 'string', 'max:2048', 'url:https'],
]);

$process = new Process(['git', 'clone', '--depth=1', '--', $validated['repo_url'], $dir]);
$process->setTimeout(60);
$process->mustRun();   // throws ProcessFailedException on a non-zero exit
```

Laravel's `Process` facade is built on Symfony Process. Its documentation shows string commands; at the time of writing, the framework source passes an array straight to Symfony's `Process` constructor (no shell) and a string to `Process::fromShellCommandline()` (a shell), so `Process::timeout(60)->run(['git', 'clone', '--depth=1', '--', $url, $dir])` is the safe form. If you prefer not to rely on undocumented behaviour, use Symfony `Process` directly as above. A string command in the facade goes through a shell.

**Why `escapeshellarg()` alone is not enough.** It wraps the value in single quotes so the shell sees one argument, which stops `;`, `|` and `$(…)`. It does nothing about a value that *starts* with `-`: the program still receives `--upload-pack=…` as an option. On Windows it replaces `%`, `!` and `"` with spaces (silently changing data), and its behaviour with multibyte input depends on the locale. Use it only when you really must build a shell string, always together with `--` and allow-list validation, and never `escapeshellcmd()` on a string that contains user input.

### Closing the argument-injection gap

Avoiding the shell stops CWE-78, not CWE-88. For each user value in an argument list:

- **Put it after `--`** when the program supports the marker (most GNU and BSD tools, `git`, `curl`, `tar`, `rsync`). Check the manual: some programs ignore it, and some (Sonar's catalogue names `zip`) do not support it in the position you need.
- **Reject a leading `-`** (and a leading `/` for Windows programs) in validation, even when you use `--`, so that a later refactor that drops the marker does not reopen the hole.
- **Bind option values with `=`** where the program supports it (`--format=png` as one element), so the value is unambiguously that option's argument and never parsed on its own.
- **Require a scheme** for URLs (`https://`) and an absolute, application-generated path for files: neither can start with `-`.
- **Prefer allow-listed values** for anything with a small domain (format, codec, record type, page size): map the user's choice to a constant in code and pass the constant.
- **Watch wildcards in scripts.** A script that runs `tar` or `chown` with `*` in a directory of user-named files is an argument injection without any request parameter; pass `--` and `./*`, or generate file names.

### Hardening image and document tools

- **ImageMagick.** Ship a restrictive `policy.xml`. ImageMagick documents example policies (`open`, the default; `limited`; `secure`; `websafe`, which limits I/O to GIF, JPEG and PNG) that can be selected at build time. For an avatar or thumbnail feature, the core lines look like this:

  ```text
  <policy domain="delegate" rights="none" pattern="*"/>
  <policy domain="coder" rights="none" pattern="*"/>
  <policy domain="coder" rights="read | write" pattern="{GIF,JPEG,PNG,WEBP}"/>
  <policy domain="resource" name="memory" value="256MiB"/>
  <policy domain="resource" name="time" value="30"/>
  ```

  ImageMagick applies the last matching rule, so the broad denial of coders comes first and the allow-list after it. Check the exact syntax against the documentation for your ImageMagick version. Verify the active policy with `magick identify -list policy`. Pass formats explicitly (`png:/path/file`) so ImageMagick does not guess the format from the content.
- **Ghostscript.** Keep SAFER on (the default since 9.50), never pass `-dNOSAFER`, keep the version current, and disable PostScript, EPS and PDF coders in ImageMagick unless the feature needs them.
- **LaTeX.** Run without `--shell-escape`; set `shell_escape` to disabled (or restricted with a short command list) in the TeX configuration (ASVS `v5.0.0-1.2.8`, L2). Treat user-supplied LaTeX as code.
- **Headless browsers and converters.** Do not disable the browser sandbox for convenience, block `file://` and local network access from rendered documents, and run LibreOffice or wkhtmltopdf in a separate, network-restricted container.

### Windows-specific fixes

- **Do not start `.bat` or `.cmd` files with user input in their arguments.** `CreateProcess()` runs them through `cmd.exe`, whose parsing no runtime escapes perfectly (the BatBadBut research). Rewrite the batch logic in the application language, or pass user data through a file or standard input instead of the command line.
- **Keep runtimes patched.** Node.js fixed CVE-2024-27980 in its April 2024 security releases (after which `spawn` refuses `.bat` and `.cmd` files unless `shell` is set); other runtimes shipped fixes or documentation changes after the same research.
- **Never build `cmd.exe /c` or `powershell -Command` strings from user data.** If PowerShell is unavoidable, pass user values as parameters of a fixed script file (`-File script.ps1 -Name value`) rather than as part of a command string, and validate them first.
- **Use `ProcessStartInfo.ArgumentList` in .NET** (one element per argument) rather than the single `Arguments` string, and reject values that start with `/` or `-` for programs that take options.

### Sandboxing and least privilege

Assume one of the programs you start will eventually be exploitable, through your code or its own bugs (ASVS `v5.0.0-15.2.5`, L3; `v5.0.0-13.2.2`, L2):

- Run converters and other risky programs in a **separate worker** or container from the web application, with no access to the application's secrets, database credentials or source code.
- Use a **dedicated unprivileged account**, a read-only root file system, dropped capabilities, `allowPrivilegeEscalation: false`, and a seccomp profile (the container runtime's default at minimum).
- **Restrict egress**: the thumbnail worker needs no internet access and no access to the cloud metadata service.
- Set **timeouts and resource limits** on every process (the `timeout` options above, ImageMagick resource policies, container CPU and memory limits).
- Pass user files through a **work directory** that the worker can read and write and nothing else can, and clean it up after each job.

### Static analysis

- **Semgrep:** the `p/command-injection` ruleset, plus rules such as `subprocess-shell-true` and `dangerous-subprocess-use-audit` (Python), `detect-child-process` (Node.js), `exec-use` (PHP) and `command-injection-process-builder` (Java).
- **CodeQL:** `js/command-line-injection`, `js/second-order-command-line-injection`, `js/indirect-command-line-injection`, `js/shell-command-constructed-from-input`, `py/command-line-injection`, `py/shell-command-constructed-from-input`, `java/command-line-injection`.
- **A sink inventory as code:** a CI step that lists every process-starting call (the grep from [GT-WEB-CMD-10](#gt-web-cmd-10-source-and-greybox-review)) and fails when a new one appears that is not on the reviewed list.
- **Dependency and image scanning** for programs and wrappers with known command-execution advisories ([GT-WEB-CMD-11](#gt-web-cmd-11-vulnerable-wrappers-and-delegate-configuration)).

### Regression tests

A good regression test for this class does not measure time or call a real shell. It replaces the process-starting function with a test double, sends hostile-looking input through the real request handler, and asserts two things: the program was started **without a shell**, and the hostile value arrived as **exactly one argument after `--`** (or was rejected by validation). Use values that only *look* dangerous: they never run, because the process is never started.

Node.js with Jest and Supertest:

```javascript
jest.mock('node:child_process', () => ({ execFile: jest.fn((cmd, args, opts, cb) => cb(null, 'ok', '')) }));
const { execFile } = require('node:child_process');
const request = require('supertest');
const app = require('../app');

describe('POST /admin/diagnostics/ping', () => {
  const hostile = ['198.51.100.7;sleep 5', '$(sleep 5)', '198.51.100.7\nsleep 5', '-x'];

  test.each(hostile)('rejects or isolates %p', async (value) => {
    execFile.mockClear();
    const res = await request(app).post('/admin/diagnostics/ping')
      .set('Cookie', 'session=<SESSION_ADMIN>').send({ host: value, count: 2 });

    if (res.status === 400) {
      expect(execFile).not.toHaveBeenCalled();          // rejected by validation
    } else {
      const [cmd, args, opts] = execFile.mock.calls[0];
      expect(cmd).toBe('ping');
      expect(opts.shell).toBeFalsy();                    // no shell
      expect(args.slice(-2)).toEqual(['--', value]);     // one argument, after --
    }
  });
});
```

Python with pytest and Django's test client:

```python
import subprocess
import pytest

HOSTILE = ["198.51.100.7;sleep 5", "$(sleep 5)", "198.51.100.7\nsleep 5", "-x"]

@pytest.mark.parametrize("value", HOSTILE)
def test_ping_isolates_hostile_host(admin_client, monkeypatch, value):
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: calls.append((a, kw)) or subprocess.CompletedProcess(a, 0, b"", b""))

    response = admin_client.post("/admin/diagnostics/ping", {"host": value, "count": 2})

    if response.status_code == 400:
        assert calls == []
    else:
        (argv,), kwargs = calls[0]
        assert isinstance(argv, list) and not kwargs.get("shell", False)
        assert argv[-2:] == ["--", value]
```

In Laravel, `Process::fake()` replaces real processes in tests and `Process::assertRan()` lets you inspect what would have run; assert that the recorded command is an array whose last elements are `--` and the hostile value. In Java, wrap `ProcessBuilder` in a small interface (a `CommandRunner` that takes `List<String>`) so a test double can capture the list. Add one test per input that reaches a command, and one test per file-name path that asserts the stored name is generated.

## Practice labs

**PortSwigger Web Security Academy** (free, browser-based), starting from the [OS command injection](https://portswigger.net/web-security/os-command-injection) topic page:

- [OS command injection, simple case](https://portswigger.net/web-security/os-command-injection/lab-simple): output-based, the product stock checker passes a parameter to a shell.
- [Blind OS command injection with time delays](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays): practise the paired delay and control of GT-WEB-CMD-3.
- [Blind OS command injection with out-of-band interaction](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band): a DNS lookup to Burp Collaborator, as in GT-WEB-CMD-4 (the lab needs Burp Suite Professional's Collaborator).

The topic page lists further labs that use output redirection or carry data out through DNS. They are fine in the lab, but those techniques are outside our proof level on client systems, so this note does not build on them.

**DVWA** ([repository](https://github.com/digininja/DVWA)): the *Command Injection* module is a "ping a device" form with Low, Medium, High and Impossible security levels. The lower levels show denylist filters of increasing length (useful for GT-WEB-CMD-9); the Impossible level's source shows allow-list validation of an IP address, which is a good model for the fix. Run it locally.

**commix-testbed** ([repository](https://github.com/commixproject/commix-testbed)): a set of deliberately vulnerable pages from the commix project, covering many injection contexts; use it locally to learn what commix's detection does before you consider it on an engagement.

For source review practice, write a small service with one shell-invoking call and one argument-list call, then run the Semgrep and CodeQL rules from [Static analysis](#static-analysis) on it and compare what each tool reports.

## Real-world cases

- **ImageMagick and Ghostscript behind a logo upload (Semrush, HackerOne, 2018).** A report to Semrush showed remote code execution through the logo upload of a reports feature, where an uploaded file went through an insufficiently patched ImageMagick, which handed PostScript to Ghostscript. The report points out that `policy.xml` needed to disable the EPS, PS, PDF and XPS coders, because each of them can reach Ghostscript. Reported August 2018, disclosed June 2019, rated Critical. The case for GT-WEB-CMD-11: the vulnerable component was the image pipeline, not the application's own code. [HackerOne report 403417](https://hackerone.com/reports/403417).
- **File name into a shell (pdfinfojs, HackerOne, 2018).** The Node.js package `pdfinfojs` passed a file name into a shell command, so a crafted name ran commands (CVE-2018-3746). Reported to the Node.js third-party modules programme in March 2018, disclosed April 2018, rated High. The pattern behind GT-WEB-CMD-7 and the generated-file-name rule. [HackerOne report 330957](https://hackerone.com/reports/330957).
- **A cookie that became a file name that became a command (PAN-OS GlobalProtect, CVE-2024-3400, 2024).** Palo Alto Networks explained that the GlobalProtect service did not validate the format of session IDs before storing them, which let an attacker create an empty file with a chosen name; a separate component later used such file names in a command, run by a scheduled job. Disabling telemetry stopped the cron job and so the execution; the fix validated session IDs and rewrote the command code. A clear second-order (incubated) case. Sources: [Palo Alto Networks](https://www.paloaltonetworks.com/blog/2024/04/more-on-the-pan-os-cve/), [Volexity](https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/) (discovery of in-the-wild exploitation) and [watchTowr Labs](https://labs.watchtowr.com/palo-alto-putting-the-protecc-in-globalprotect-cve-2024-3400/) (root-cause analysis).
- **ImageTragick (CVE-2016-3714, 2016).** Insufficient filtering of file names and URLs passed to ImageMagick's delegate commands allowed command execution through crafted image files; the published mitigation was a restrictive `policy.xml` and checking magic bytes before processing. The origin of the ImageMagick policy advice in this note. [imagetragick.com](https://imagetragick.com/).
- **Sender address to sendmail options (PHPMailer, CVE-2016-10033, 2016).** Dawid Golunski showed that PHPMailer passed the sender address to PHP's `mail()`, which hands it to `sendmail` as part of its command line; a crafted address added sendmail options and led to code execution. An argument-injection case that escaping for the shell did not prevent. [Legal Hackers advisory](https://legalhackers.com/advisories/PHPMailer-Exploit-Remote-Code-Exec-CVE-2016-10033-Vuln.html).
- **Git option through a deep link (VS Code, CVE-2022-30129, 2022).** Sonar's Thomas Chauchefoin found that VS Code's Git extension took the repository URL from a `vscode://` link and passed it to `git clone`; a URL starting with dashes became an option such as `-u` (`--upload-pack`), which names a program for Git to run. Microsoft's fix parsed the URL and checked its scheme against an allow-list (`file`, `git`, `http`, `https`, `ssh`), released in VS Code 1.67.1. The model for GT-WEB-CMD-6 and the scheme rule. [Sonar](https://www.sonarsource.com/blog/securing-developer-tools-argument-injection-in-vscode/).

Background reading: Shellshock ([CVE-2014-6271](https://nvd.nist.gov/vuln/detail/CVE-2014-6271)), where Bash executed trailing commands in environment variables such as the CGI variables built from HTTP headers, and [BatBadBut](https://flatt.tech/research/posts/batbadbut-you-cant-securely-execute-commands-on-windows/) (Flatt Security, April 2024) for the Windows batch-file problem. More write-ups are collected in [Bug Bounty Writeups](/bug-bounty-writeups/).

## Rating findings

Command injection is code execution on a server, so confirmed findings start high. Rate on the preconditions (unauthenticated, any registered user, a specific role), what the process can reach (its account, secrets, network, neighbours on the host, from [GT-WEB-CMD-12](#gt-web-cmd-12-execution-context-hardening-and-fix-verification)), and how reliably the input reaches the command. The vectors below are examples, not fixed answers.

**Scope.** Our series convention is Scope Unchanged when the impact stays within the vulnerable application and its own host or container, and **Scope Changed** only when the impact clearly escapes that component: the worker runs on a host shared with other applications or systems (other tenants of the same application do not count by themselves), the container runs with host-level privileges, or the process holds credentials for systems that are separate security authorities (another team's database, a cloud account beyond the application). Say in the report which applies and why; do not assume Scope Changed just because "the server" is compromised.

| Finding | Typical severity | Example CVSS v3.1 vector | Reasoning |
|---|---|---|---|
| Unauthenticated OS command injection, internet-facing | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | Anyone can run commands as the application's account; full confidentiality, integrity and availability impact on the component |
| As above, on a host or container shared with other applications or systems | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (10.0) | The impact escapes the vulnerable application; explain the shared resource in the report |
| Command injection for any registered user | Critical (High only if the process is tightly sandboxed) | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Registration is usually open, so `PR:L` is a small barrier; the base score understates it on internet-facing SaaS |
| Command injection for any user, in a worker shared across tenants | Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | One tenant reaches every tenant's files and jobs through the shared worker; rate Critical for that scale. Other tenants of the same application do not by themselves make Scope Changed; use `S:C` (9.9) only when the worker host also runs other systems or holds credentials for them |
| Command injection in an admin-only feature (diagnostics, backup settings), operator administrators only | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (7.2) | An application administrator is not supposed to be an operating-system administrator: High when administrators are not meant to have server access, Medium where they already deploy code, which you state as an accepted design risk |
| As above, reachable by a self-service tenant or customer administrator | High; Critical at SaaS scale | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | A customer's admin is an outside party, so `PR:L` as for any registered user; rate it with the number of tenants in mind |
| Argument injection where documented options of the program run commands or write files, with a condition the attacker does not control (a second positional argument, a specific program version) | High | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` (7.5) | Code execution is a documented feature of the reachable option, but exploitation depends on conditions beyond the attacker's control, hence `AC:H`; rate as above (`AC:L`) when nothing stands in the way |
| Argument injection limited to reading files (an option that loads a configuration or input file whose content is reflected) | Medium to High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | Disclosure of server files, rated by what the process can read |
| Second-order or asynchronous command injection (stored value, queued job) | Same as the direct case for the same preconditions | as above | Delay and indirection do not reduce impact; the attacker only needs to store the value |
| Known-vulnerable ImageMagick, Ghostscript or wrapper reachable through an upload, not demonstrated | High (follow the advisory) | for example `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | Reachability shown from the feature map and versions; say that exploitation was not attempted |
| Shell-invoking call with a denylist filter and no successful probe | Low | none | Defence-in-depth gap; one future change from a Critical |
| Verbose errors disclosing command lines, paths or program versions | Low | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | Information that speeds up an attack; higher if secrets appear in the command line |
| Permissive ImageMagick policy, LaTeX shell escape restricted, process runs as root, with no injection found | Info to Low | none | Hardening findings that raise the severity of any future injection; report them alongside the main findings |

When you report, give: the feature and input, the probe and its control (with timings or the Collaborator interaction), the execution context from GT-WEB-CMD-12 (account, secrets, egress, neighbours), the reachable-option analysis for argument injection, and confirmation that nothing beyond the agreed proof level was run.

## Mapping

| Test | WSTG | ASVS 5.0 | CWE | OWASP Top 10 |
|---|---|---|---|---|
| GT-WEB-CMD-1 | WSTG-INJT-12, WSTG-INFO-06, WSTG-INFO-10, WSTG-INJT-14 | v5.0.0-1.2.5 (context) | CWE-78, CWE-88 (context) | A05:2025 |
| GT-WEB-CMD-2 | WSTG-INJT-12, WSTG-ERRH-01 | v5.0.0-13.4.6 | CWE-78 (lead), CWE-209 | A05:2025 |
| GT-WEB-CMD-3 | WSTG-INJT-12 | v5.0.0-1.2.5 | CWE-78 | A05:2025 |
| GT-WEB-CMD-4 | WSTG-INJT-12, WSTG-INJT-14 | v5.0.0-1.2.5 | CWE-78 | A05:2025 |
| GT-WEB-CMD-5 | WSTG-INJT-12 | v5.0.0-1.3.3, v5.0.0-1.2.5 | CWE-78, CWE-88 | A05:2025 |
| GT-WEB-CMD-6 | WSTG-INJT-12 | v5.0.0-1.2.5, v5.0.0-1.3.3 | CWE-88 | A05:2025 |
| GT-WEB-CMD-7 | WSTG-INJT-14, WSTG-BUSL-09, WSTG-INJT-12 | v5.0.0-5.3.2, v5.0.0-1.2.5 | CWE-78, CWE-88 | A05:2025 |
| GT-WEB-CMD-8 | WSTG-INJT-12 | v5.0.0-1.2.5 | CWE-78, CWE-88 | A05:2025 |
| GT-WEB-CMD-9 | WSTG-INJT-12 | v5.0.0-1.2.5, v5.0.0-1.3.3, v5.0.0-1.1.1 | CWE-78 | A05:2025 |
| GT-WEB-CMD-10 | WSTG-INJT-12 | v5.0.0-1.2.5, v5.0.0-1.3.3 | CWE-78, CWE-88 | A05:2025 |
| GT-WEB-CMD-11 | WSTG-INJT-12, WSTG-BUSL-09 | v5.0.0-1.2.8, v5.0.0-15.2.1, v5.0.0-15.2.5 | CWE-78 (or the advisory's CWE) | A05:2025 |
| GT-WEB-CMD-12 | WSTG-INJT-12 | v5.0.0-13.2.2, v5.0.0-15.2.5 | CWE-250 (if run with excessive privileges) | A05:2025 |

ASVS levels: `v5.0.0-1.2.5` L1 (protection against OS command injection, parameterised OS calls or contextual command-line encoding), `v5.0.0-1.3.3` L2 (sanitise data passed to a dangerous context), `v5.0.0-1.2.8` L2 (LaTeX without shell escape), `v5.0.0-1.1.1` L2 (decode once, before validation), `v5.0.0-5.3.2` L1 (internally generated file names for file operations), `v5.0.0-13.2.2` L2 (least privilege for back-end and operating-system communication), `v5.0.0-13.4.6` L3 (no detailed back-end version disclosure), `v5.0.0-15.2.1` L1 (components within remediation time frames), `v5.0.0-15.2.5` L3 (sandboxing or isolation around dangerous functionality).

CWE choice: use **CWE-78** (Improper Neutralization of Special Elements used in an OS Command; its CWE 5.0 name no longer carries the "('OS Command Injection')" suffix) when input changes the structure of a shell command, and **CWE-88** (Argument Injection) when input becomes an option of a program started without a shell; both are Base entries that MITRE allows for mapping. **CWE-77** is the Class-level parent, allowed only with review, so use it only when neither child fits. CWE-209 covers verbose errors and CWE-250 (Execution with Unnecessary Privileges) the hardening finding of test 12. `A05:2025` is Injection in the OWASP Top 10:2025, which lists CWE-77, CWE-78 and CWE-88 among its mapped CWEs.

## References

**OWASP**

- WSTG: [Testing for Command Injection (WSTG-INJT-12)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/12-Command_Injection), [Testing for Incubated Vulnerability (WSTG-INJT-14)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/14-Incubated_Vulnerability), [Testing for Code Injection (WSTG-INJT-11)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/11-Code_Injection), [Test Upload of Malicious Files (WSTG-BUSL-09)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/10-Business_Logic/09-Upload_of_Malicious_Files), [Testing for Improper Error Handling (WSTG-ERRH-01)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/08-Error_Handling/01-Improper_Error_Handling)
- ASVS 5.0: [V1 Encoding and Sanitization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md) and the [5.0 source tree](https://github.com/OWASP/ASVS/tree/master/5.0)
- [A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/)
- [OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)

**CWE and standards**

- [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CWE-88](https://cwe.mitre.org/data/definitions/88.html), [CWE-77](https://cwe.mitre.org/data/definitions/77.html), [CWE-209](https://cwe.mitre.org/data/definitions/209.html), [CWE-250](https://cwe.mitre.org/data/definitions/250.html)
- [POSIX Utility Conventions](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap12.html) (Guideline 10, the `--` end-of-options marker)
- NVD: [CVE-2014-6271](https://nvd.nist.gov/vuln/detail/CVE-2014-6271), [CVE-2016-3714](https://nvd.nist.gov/vuln/detail/CVE-2016-3714), [CVE-2016-10033](https://nvd.nist.gov/vuln/detail/CVE-2016-10033), [CVE-2018-3746](https://nvd.nist.gov/vuln/detail/CVE-2018-3746), [CVE-2022-30129](https://nvd.nist.gov/vuln/detail/CVE-2022-30129), [CVE-2024-3400](https://nvd.nist.gov/vuln/detail/CVE-2024-3400), [CVE-2024-27980](https://nvd.nist.gov/vuln/detail/CVE-2024-27980)

**PortSwigger**

- [OS command injection](https://portswigger.net/web-security/os-command-injection) and its labs
- [Burp Collaborator documentation](https://portswigger.net/burp/documentation/collaborator)

**Research and catalogues**

- Sonar R&D: [Argument Injection Vectors](https://sonarsource.github.io/argument-injection-vectors/) and [Securing Developer Tools: Argument Injection in Visual Studio Code](https://www.sonarsource.com/blog/securing-developer-tools-argument-injection-in-vscode/)
- [GTFOArgs](https://gtfoargs.github.io/)
- RyotaK (Flatt Security): [BatBadBut: You can't securely execute commands on Windows](https://flatt.tech/research/posts/batbadbut-you-cant-securely-execute-commands-on-windows/)
- [ImageTragick](https://imagetragick.com/); Dawid Golunski, [PHPMailer CVE-2016-10033 advisory](https://legalhackers.com/advisories/PHPMailer-Exploit-Remote-Code-Exec-CVE-2016-10033-Vuln.html)
- CVE-2024-3400: [Palo Alto Networks](https://www.paloaltonetworks.com/blog/2024/04/more-on-the-pan-os-cve/), [Volexity](https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/), [watchTowr Labs](https://labs.watchtowr.com/palo-alto-putting-the-protecc-in-globalprotect-cve-2024-3400/)

**Language and framework documentation**

- Node.js: [`child_process`](https://nodejs.org/api/child_process.html), [deprecations](https://nodejs.org/api/deprecations.html) (DEP0190), [April 2024 security releases](https://nodejs.org/en/blog/vulnerability/april-2024-security-releases-2) (CVE-2024-27980)
- Python: [`subprocess`](https://docs.python.org/3/library/subprocess.html) (security considerations, Windows batch files), [`shlex`](https://docs.python.org/3/library/shlex.html)
- Java 21: [`ProcessBuilder`](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/ProcessBuilder.html)
- PHP: [`escapeshellarg`](https://www.php.net/manual/en/function.escapeshellarg.php), [`escapeshellcmd`](https://www.php.net/manual/en/function.escapeshellcmd.php), [`proc_open`](https://www.php.net/manual/en/function.proc-open.php)
- [Symfony Process component](https://symfony.com/doc/current/components/process.html); [Laravel 12 processes](https://laravel.com/docs/12.x/processes)
- [ImageMagick security policy](https://imagemagick.org/security-policy/); [Ghostscript usage](https://ghostscript.readthedocs.io/en/latest/Use.html) (SAFER mode)
- [`git clone`](https://git-scm.com/docs/git-clone) (synopsis with `[--]`)

**Tools**

- [interactsh](https://github.com/projectdiscovery/interactsh) (self-hosted out-of-band listener)
- [commix](https://github.com/commixproject/commix) and [commix-testbed](https://github.com/commixproject/commix-testbed) (detection aid only, with the restrictions in GT-WEB-CMD-3)
- Semgrep: [command-injection ruleset](https://semgrep.dev/p/command-injection); rules [subprocess-shell-true](https://github.com/semgrep/semgrep-rules/blob/develop/python/lang/security/audit/subprocess-shell-true.yaml), [dangerous-subprocess-use-audit](https://github.com/semgrep/semgrep-rules/blob/develop/python/lang/security/audit/dangerous-subprocess-use-audit.yaml), [detect-child-process](https://github.com/semgrep/semgrep-rules/blob/develop/javascript/lang/security/detect-child-process.yaml), [exec-use](https://github.com/semgrep/semgrep-rules/blob/develop/php/lang/security/exec-use.yaml), [command-injection-process-builder](https://github.com/semgrep/semgrep-rules/blob/develop/java/lang/security/audit/command-injection-process-builder.yaml)
- CodeQL query help: [js/command-line-injection](https://codeql.github.com/codeql-query-help/javascript/js-command-line-injection/), [js/second-order-command-line-injection](https://codeql.github.com/codeql-query-help/javascript/js-second-order-command-line-injection/), [js/indirect-command-line-injection](https://codeql.github.com/codeql-query-help/javascript/js-indirect-command-line-injection/), [js/shell-command-constructed-from-input](https://codeql.github.com/codeql-query-help/javascript/js-shell-command-constructed-from-input/), [py/command-line-injection](https://codeql.github.com/codeql-query-help/python/py-command-line-injection/), [py/shell-command-constructed-from-input](https://codeql.github.com/codeql-query-help/python/py-shell-command-constructed-from-input/), [java/command-line-injection](https://codeql.github.com/codeql-query-help/java/java-command-line-injection/)
- Labs: [DVWA](https://github.com/digininja/DVWA)
