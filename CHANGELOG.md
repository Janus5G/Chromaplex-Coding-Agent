# Changelog

## 0.3.0 — Secure Compile Gate

- Added fail-closed Secure Compile Gate before compiler release.
- Added mandatory local ClamAV source and compiled-output scanning.
- Added private quarantine compilation; output is released only after mandatory gates pass.
- Added `<binary>.security.json` with SHA-256 source/output evidence, scanner state, compiler/gate identity and VM capability declarations.
- Added optional hash-only VirusTotal reputation lookup; automatic file upload is not implemented.
- Added secure C/C# runtime compilation: compile → scan → sandbox execution.
- Expanded static policy for destructive host operations, credential dumping, process injection, persistence and sensitive OS capabilities.
- Preserved SHA-256 source sealing and installed-payload verification.
- Preserved bubblewrap network-off host execution.
- Added regression and adapter tests for scanner failure/malware verdicts, quarantine non-release, reputation blocking and scan-before-execution.
- Version bumped to 0.3.0 Alpha.

## 0.2.0

- Multi-mode Linux/Windows/Web/ChromaPlex coding application.
- Built-in PySide6 editor.
- CPL/CPA compiler/runtime adapters.
- SHA-256 workspace sealing and package integrity checks.
- Fail-closed bubblewrap host execution.

## 0.4.0 Alpha
- Added target-aware security profiles for desktop, Web/Wasm, ESP32, Arduino, Raspberry Pi and ChromaPlex VM.
- Added strict desktop memory-safety gate and embedded-aware pointer/MMIO policy.
- Added hardware capability declarations and MMIO range validation.
- Added ELF/PE/Wasm structure and architecture validation, packer rejection and entropy review.
- Added embedded quarantine builds via PlatformIO/Arduino CLI and Raspberry Pi cross-build path.
- Added Raspberry Pi capability-derived AppArmor deployment profile generation.
- Kept unseen/UNKNOWN firmware reputation non-blocking by default.
