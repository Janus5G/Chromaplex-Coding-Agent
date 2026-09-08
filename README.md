# Chromaplex Coding Agent

[![Version](https://img.shields.io/badge/version-v0.4.0--alpha-orange)](https://github.com/Janus5G/Chromaplex-Coding-Agent/releases)
[![Tests](https://github.com/Janus5G/Chromaplex-Coding-Agent/actions/workflows/tests.yml/badge.svg)](https://github.com/Janus5G/Chromaplex-Coding-Agent/actions/workflows/tests.yml)
[![Tests Passed](https://img.shields.io/badge/tests-103%20passed-brightgreen)](TEST_REPORT.md)
[![Failures](https://img.shields.io/badge/failures-0-brightgreen)](TEST_REPORT.md)
[![Security](https://img.shields.io/badge/Secure%20Compile%20Gate-enabled-brightgreen)](SECURE_COMPILE_GATE.md)
[![SHA-256](https://img.shields.io/badge/SHA--256-verified-brightgreen)](TEST_REPORT.md)
[![Targets](https://img.shields.io/badge/targets-Desktop%20%7C%20Web%20%7C%20Embedded%20%7C%20CPL%2FCPA-blue)](#target-profiles)
[![Platform](https://img.shields.io/badge/platform-Linux-blue)](#run-from-source)
[![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Status](https://img.shields.io/badge/status-Alpha-orange)](#verification-status--v040-alpha)

**Chromaplex Coding Agent** is an open-source Linux desktop coding environment for generating, editing, testing, compiling and exporting Linux, Windows, Web, embedded and ChromaPlex CPL/CPA projects.

> **Status:** v0.4.0 Alpha — security-hardened public preview.  
> The release includes a fail-closed Secure Compile Gate, SHA-256 integrity chain, target-aware capability manifests, memory-safety policies, binary structure validation, embedded hardware profiles, sandboxed execution and local malware scanning.  
> Full GUI, live AI-provider, physical embedded-device, Raspberry Pi deployment and real-ISO acceptance testing are still required on target systems before Beta.

## Main capabilities

- **Linux:** Bash, C, Python, Makefile and multi-file projects.
- **Windows:** PowerShell, C#, Batch, Windows Python and multi-file projects.
- **Web:** HTML/CSS, JavaScript, Flask, React and WebAssembly-oriented workflows.
- **Embedded:** ESP32 / ESP32-S3, Arduino / MCU and Raspberry Pi Linux ARM targets.
- **ChromaPlex:** CPL and CPA through adapters based on the original ChromaPlex projects.
- **Built-in editor:** generated source is directly editable before review/build/export.
- **AI providers:** OpenAI by default; Caffeine is optional.
- **Normal Linux packaging:** the `.deb` can be imported into an ISO builder such as ChromaPress as an external application.

## Target profiles

Every project uses an explicit target profile. The target becomes part of `chromaplex-capabilities.json` and is included in the SHA-256-sealed project state.

Supported profiles:

- Linux Desktop
- Windows Desktop
- Web / WebAssembly
- ESP32 / ESP32-S3
- Arduino / MCU
- Raspberry Pi Linux ARM
- ChromaPlex VM

Security policy changes according to the selected target.

### Desktop targets

Desktop native code uses the strictest memory and capability policy.

Unsafe constructs that are not justified by the target or manifest can be blocked before compilation.

### ESP32 / Arduino targets

Embedded projects use a hardware-aware policy.

Legitimate low-level constructs such as raw pointers, MMIO, GPIO, SPI, I2C, UART and Wi-Fi are not automatically treated as malicious when they are consistent with the selected target and declared capabilities.

Classic unsafe buffer primitives remain blocked or require review.

Examples include:

- `gets`
- `strcpy`
- `strcat`
- `sprintf`

New company firmware is not blocked simply because online reputation is unknown.

### Raspberry Pi

Raspberry Pi is treated as **Linux ARM**, not bare metal.

The secure build path can validate:

- ARM ELF structure;
- SHA-256 integrity;
- declared capabilities;
- sandbox/runtime restrictions;
- generated AppArmor deployment profiles.

## Secure Compile Gate

Generated and imported code is treated as untrusted.

A releasable build follows:

```text
Source
  → target-aware static security analysis
  → memory-safety analysis
  → capability validation
  → local malware scan
  → SHA-256 source seal
  → quarantine compilation
  → binary structure validation
  → packer / entropy policy
  → malware scan of compiled output
  → optional hash-only online reputation lookup
  → SHA-256 binary seal
  → security manifest
  → release
```

The gate is **fail closed**.

If a mandatory security stage fails, errors or cannot be completed, the requested output is not released.

A `BLOCKED` result cannot be bypassed by the official application.

`REVIEW REQUIRED` code requires explicit human review and a new exact SHA-256 seal before the build can continue.

## Memory safety

The security model distinguishes between desktop code and embedded code.

For desktop targets, raw memory manipulation and known unsafe C patterns are subject to strict source analysis.

For embedded targets, legitimate hardware access is permitted when consistent with the selected board profile and declared hardware capabilities.

The project does **not** claim that arbitrary C or C++ can be mathematically proven memory-safe.

WebAssembly is supported as an additional constrained target where appropriate, but it is not forced on all workloads.

## Capability manifest

Projects use:

```text
chromaplex-capabilities.json
```

The manifest is part of the exact project state covered by SHA-256.

Example:

```json
{
  "target": "esp32",
  "board": "esp32:esp32:esp32s3",
  "network": true,
  "process_spawn": false,
  "allow_hardware": [
    "GPIO_2",
    "WIFI",
    "SPI",
    "I2C",
    "UART"
  ],
  "mmio_ranges": [
    {
      "name": "MY_PERIPHERAL",
      "start": "0x60000000",
      "end": "0x60000fff"
    }
  ]
}
```

The runtime and build system use the manifest as policy input rather than documentation only.

Capabilities that are not declared can be denied.

## Binary validation

Secure builds validate the expected output format before release.

Supported checks include:

- ELF structure for Linux targets;
- PE / PE32+ structure for Windows targets where applicable;
- ARM ELF validation for Raspberry Pi targets;
- WebAssembly preamble/version and section validation;
- ChromaPlex binary / bundle validation.

Executable packers such as UPX are not part of the official build path.

Known packer signatures can be rejected by the Secure Compile Gate.

High entropy is treated as a review signal rather than automatic proof of malware because legitimate compressed assets or firmware may also contain high-entropy data.

## Malware scanning

The official Debian build depends on **ClamAV**.

Source trees and quarantine output are scanned before release.

Scanner failure is not treated as a clean result.

Optional online reputation is **hash-only**.

The official application can look up the SHA-256 of an output without automatically uploading the file.

The VirusTotal adapter is disabled by default and requires the user to supply an API key/licence suitable for their own use case.

Unknown reputation does **not** automatically block legitimate previously unseen software or internal company firmware.

## SHA-256 integrity chain

After review, the exact source workspace is SHA-256 sealed.

Any editor change invalidates the seal.

Verified exports include:

- `chromaplex-integrity.json`
- `CHROMAPLEX-SHA256SUMS.txt`

Approved compiled outputs additionally receive:

- `<binary>.sha256`
- `<binary>.security.json`

The security manifest records:

- source hashes;
- binary hash;
- compiler / Secure Compile Gate identity;
- selected target;
- static-analysis status;
- memory-safety status;
- capability declarations;
- local malware-scan states;
- optional reputation state;
- binary structure validation;
- declared runtime/hardware capabilities.

Approved output can be independently checked without launching the GUI:

```bash
chromaplex-verify-build program.bin
```

The verifier recomputes the binary SHA-256 and checks it against the security manifest.

The Debian installation also contains:

```text
/opt/chromaplex-coding-agent/SHA256SUMS
```

The launcher verifies the installed application before startup and refuses to run if protected installed files were modified.

## Sandboxed execution

Supported host-language execution is isolated with `bubblewrap`.

Default policy includes:

- network off unless explicitly declared;
- cleared environment;
- user home hidden;
- project workspace as the controlled writable area;
- system/toolchain roots read-only;
- no automatic unsafe fallback;
- timeout and process controls.

C/C# output is compiled into quarantine, scanned and validated before sandboxed execution.

Windows code can be generated and exported on Linux without falsely pretending that it has been executed as native Windows software.

## ChromaPlex security boundary

For CPL/CPA, the compiler/runtime layer is intentionally capability-limited to documented VM/register/control-flow/crystal-storage operations.

Unknown CPA opcodes are rejected by the assembler/compiler path.

The official Secure Compile Gate does not add generic host shell, filesystem or network opcodes to CPL/CPA.

## ChromaPlex upstream sources

Authoritative upstream repositories:

- https://github.com/Janus5G/chromaplex-os
- https://github.com/Janus5G/Cplex
- https://github.com/Janus5G/chromaplex-os-compiler

See [`THIRD_PARTY_SOURCES.md`](THIRD_PARTY_SOURCES.md).

## Verification status — v0.4.0 Alpha

Automated release verification:

- **pytest:** 103 passed
- **security/path subtests:** 12 passed
- **pytest failures:** 0
- **pytest skipped:** 7
- **unittest:** 110 tests
- **unittest failures:** 0
- **unittest skipped:** 7
- **Debian internal SHA-256 manifest:** PASS
- **Debian payload / launchers:** PASS
- **clean-room source ZIP rebuild and test:** PASS
- **release ZIP integrity:** PASS
- **release checksum verification after extraction:** PASS

The skipped tests are environment- or hardware-dependent and are intentionally not reported as PASS.

Remaining target-specific verification includes:

- full PySide6 GUI acceptance;
- live OpenAI / Caffeine provider tests;
- live ClamAV database/runtime validation on target Linux;
- physical ESP32 / ESP32-S3 flashing and hardware tests;
- physical Arduino flashing and hardware tests;
- Raspberry Pi ARM deployment and AppArmor enforcement;
- complete ChromaLinux / ISO / VM hardening acceptance where applicable.

See [`TEST_REPORT.md`](TEST_REPORT.md) for the complete verification scope and remaining manual gates.

## Security documentation

Detailed security design:

- [`SECURITY.md`](SECURITY.md)
- [`SECURE_COMPILE_GATE.md`](SECURE_COMPILE_GATE.md)
- [`HARDENING.md`](HARDENING.md)
- [`TEST_REPORT.md`](TEST_REPORT.md)

## Run from source

On Debian/Ubuntu-family Linux:

```bash
sudo apt update
sudo apt install \
  python3 \
  python3-pyside6.qtwidgets \
  python3-pyside6.qtwebenginewidgets \
  bubblewrap \
  coreutils \
  clamav \
  clamav-freshclam \
  libsecret-tools \
  gcc \
  make

python3 -m chromaplex_agent
```

ClamAV signatures must be present and usable.

If the scanner/database is unavailable, the Secure Compile Gate blocks protected build/release operations instead of silently bypassing scanning.

## API keys

OpenAI is the default AI provider.

Caffeine is optional.

```bash
export OPENAI_API_KEY="..."
export CAFFEINE_API_KEY="..."
```

Optional hash reputation:

```bash
export VIRUSTOTAL_API_KEY="..."
```

Secrets can also be stored through Linux Secret Service when `secret-tool` is available.

Credentials are not intentionally written into generated projects, SHA manifests or exported project configuration.

## Build Debian package

```bash
chmod +x packaging/build_deb.sh
./packaging/build_deb.sh
```

The package installs into:

```text
/opt/chromaplex-coding-agent
```

and provides:

```text
/usr/bin/chromaplex-coding-agent
```

plus a desktop menu entry.

## ChromaPress / ISO builder import

Chromaplex Coding Agent remains an external Linux application.

ChromaPress can later import the `.deb` as a normal local application package and stage its dependencies without embedding Coding Agent source into ChromaPress itself.

See [`CHROMAPRESS_IMPORT.md`](CHROMAPRESS_IMPORT.md).

## Tests

Run the main suite with:

```bash
python3 -m unittest discover -s tests -v
```

or:

```bash
pytest -q
```

The suite covers areas including:

- project/path validation;
- Windows path traversal regression tests;
- editor/workspace integrity;
- SHA-256 tamper detection;
- capability-manifest validation;
- target-aware security policy;
- desktop memory-safety policy;
- embedded pointer/MMIO handling;
- GPIO/Wi-Fi/SPI/I2C/UART declaration enforcement;
- Raspberry Pi ARM target handling;
- binary structure validation;
- packer/entropy policy;
- sandbox policy;
- Debian-package verification;
- CPL/CPA dialects;
- Secure Compile Gate fail-closed behavior;
- quarantine release rules;
- local scanner adapter behavior;
- optional hash-only reputation behavior;
- compiled-binary scan-before-execution behavior.

## Disclaimer / security scope

Chromaplex Coding Agent v0.4.0 is an **Alpha release**.

The project is designed to reduce risk through defense-in-depth security controls, but no compiler, malware scanner, AI model, sandbox, static analyzer or integrity mechanism can guarantee that arbitrary software is completely free of defects, vulnerabilities or malicious behavior.

Users and organizations remain responsible for reviewing, testing and validating generated or imported code for its intended target, hardware, operating environment and regulatory requirements before production deployment.

Security verdicts such as `SAFE`, `REVIEW REQUIRED` and `BLOCKED` are engineering controls and do not constitute a legal, regulatory or formal security certification.

SHA-256 proves integrity relative to a trusted reference hash. It does not by itself prove publisher identity. Cryptographic release signing is a separate authenticity layer.

Open-source forks can modify or remove security gates. Only builds produced by an unmodified trusted release and verified against the official release hashes/manifests should be treated as official Chromaplex Coding Agent builds.

## License

MIT License — Copyright © 2026 Janus Rokkjær.

See [`LICENSE`](LICENSE).

Third-party components retain their own licence notices and terms.

See [`THIRD_PARTY_SOURCES.md`](THIRD_PARTY_SOURCES.md).
