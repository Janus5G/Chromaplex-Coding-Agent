# Security policy — Chromaplex Coding Agent v0.3.0

Chromaplex Coding Agent treats generated and imported source code as untrusted. v0.3.0 moves the security boundary in front of compilation and release rather than relying only on sandboxing after a binary already exists.

## 1. Secure Compile Gate

The official release path is:

`source → static review → local malware scan → SHA-256 source seal → quarantine compile → compiled-output scan → optional hash reputation → SHA-256 binary seal → security manifest → release`

The gate is fail closed. A binary is not copied from quarantine to its requested destination until every mandatory gate is green.

### Static outcomes

- `SAFE`: no high-risk policy pattern was detected.
- `REVIEW REQUIRED`: potentially sensitive functionality requires explicit human review before this exact source revision can be sealed.
- `BLOCKED`: the official application refuses to seal/compile/release it. There is no normal “compile anyway” button for this state.

Static rules are intentionally conservative and are not claimed to be a complete malware classifier.

## 2. Mandatory local malware scan

ClamAV is the default local scanner in the Debian package. The application scans the source set before compiler entry and the quarantine output before release/execution.

- scanner `CLEAN` → the next gate may proceed;
- scanner malware verdict → build is blocked;
- scanner missing/error/unknown → build is blocked when mandatory scanning is enabled.

The scanner operates locally; source/binary contents are not sent to a remote service by this layer.

## 3. Quarantine compilation

Compiled output is created in a private temporary quarantine directory. It is not placed at the user-selected release path until local scanning and any enabled reputation gate have completed.

Host C/C# runtime compilation follows the same principle: compile → scan binary → execute. A failed binary scan prevents the execution step.

## 4. CPL/CPA security by construction

The bundled ChromaPlex adapters route to the documented ChromaPlex compiler/assembler implementations. Unknown instructions are rejected.

The supported VM capability model is limited to registers, arithmetic/control flow, simulator buffer I/O and crystal/voxel storage. The current CPA `IN`/`OUT` instructions access the simulator input/output buffers; they do not provide arbitrary host network/filesystem/process access.

This is a stronger boundary than trying to detect every malicious intent after arbitrary operating-system primitives have already been exposed.

## 5. Optional online hash reputation

v0.3.0 implements an optional **hash-only** VirusTotal file reputation lookup using SHA-256. It is disabled by default.

The official adapter:

- performs a GET lookup by SHA-256;
- does not implement automatic file upload;
- blocks a release when an enabled lookup reports malicious detections;
- records the provider/state in the security manifest.

Users must ensure their API licence permits their intended usage. VirusTotal's public API has usage/licensing restrictions and must not simply be treated as a bundled commercial antivirus service.

## 6. SHA-256 chain

Source review seals the exact project files. Any edit invalidates the seal.

Project exports include `chromaplex-integrity.json` and `CHROMAPLEX-SHA256SUMS.txt`.

Approved compiled outputs receive a `.sha256` sidecar plus `.security.json` containing the source hashes, binary hash, gate/compiler identity, static-analysis result, scanner states, optional reputation state and VM capabilities.

The installed application has its own payload `SHA256SUMS`; the launcher refuses to start after installed-file tampering.

SHA-256 detects modification relative to a trusted expected digest; it does not prove publisher identity. Public-key release signing remains a separate future authenticity layer.

## 7. Safe execution

Non-ChromaPlex host code runs in fail-closed bubblewrap isolation with network disabled by default, a cleared environment, hidden user home, read-only toolchain/system roots and a writable temporary workspace only. No unsandboxed fallback is performed if bubblewrap is missing.

## 8. Secrets

OpenAI, Caffeine and optional reputation API keys are taken from environment variables or Linux Secret Service. They are not included in generated projects, logs, SHA manifests or security manifests.

## 9. Limits

No compiler security system can prove all arbitrary source code harmless. Static rules and malware signatures can have false positives/negatives. Open-source forks can remove safeguards. The goal of the official build is a verifiable fail-closed default, not a claim that third-party modified builds are equally protected.

## Reporting vulnerabilities

Use a private GitHub security advisory when available. Include the affected version/component, safe reproduction conditions and expected fail-closed behaviour. Do not publish weaponized exploit payloads as the initial report.
