# Secure Compile Gate — technical design

## Goal

A requested executable/bundle is not considered a build merely because a compiler emitted bytes. The official Chromaplex Coding Agent releases output only after a chain of source review, malware scanning and integrity evidence succeeds.

## State machine

```text
UNREVIEWED
  ↓ static analysis
SAFE / REVIEW REQUIRED / BLOCKED
  ↓ approved exact source revision
SOURCE_SCANNED
  ↓ SHA-256 source seal
SEALED
  ↓ compile into private quarantine
QUARANTINED_OUTPUT
  ↓ local malware scan
SCANNED_OUTPUT
  ↓ optional hash-only reputation
REPUTATION_CHECKED
  ↓ SHA-256 + security manifest
APPROVED_RELEASE
```

`BLOCKED`, scanner failure, malware verdict, compiler failure or a required reputation failure terminates the chain. No requested output file is released.

## ChromaPlex compiler boundary

CPL/CPA is validated by the original/vendored assembler/compiler paths. The official capability declaration contains only VM-level capabilities detected from the resulting CPA, such as registers/control flow, voxel storage and simulator-buffer I/O.

Unknown CPA opcodes fail assembler validation. The Secure Compile Gate does not add a host shell/filesystem/network opcode to CPL/CPA.

## Quarantine

`secure_build_chromaplex()` compiles to a private temporary directory. The output is scanned there. Only after mandatory gates pass is the file atomically copied/replaced at the user-selected destination.

On failure, the final binary, `.sha256`, and `.security.json` are absent.

## Security manifest

An approved output receives `<output>.security.json` with schema `chromaplex-secure-build-v1`.

Important fields:

- SHA-256 for every source file;
- SHA-256 for released output;
- language/dialect;
- Secure Compile Gate/compiler identity;
- static-analysis result;
- local source/binary scanner state;
- optional online reputation state;
- declared capabilities;
- `approved: true`.

## Independent verification

```bash
chromaplex-verify-build program.bin
```

The verifier recomputes the binary SHA-256 and checks it against the security manifest. It exits non-zero on mismatch or an invalid/unapproved manifest.

## Online reputation

The optional VirusTotal implementation performs only a SHA-256 file-report GET. It never uploads the binary. It is disabled by default and requires a user-supplied key/licence appropriate for the user's use case.

## What this does not claim

This design is defense in depth, not a mathematical proof that arbitrary general-purpose source code is benign. Open-source forks can remove the gate. SHA-256 proves integrity relative to trusted hashes, not publisher identity. Public-key release signing is a separate authenticity layer.
