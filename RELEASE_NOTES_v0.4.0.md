# Chromaplex Coding Agent v0.4.0 Alpha

v0.4.0 makes target-aware security part of the official build identity.

## Highlights

- Secure Compile Gate v2 with SHA-256 source/output evidence, quarantine builds, mandatory local malware scanning and independent build verification.
- Target profiles: Linux Desktop, Windows Desktop, Web/Wasm, ESP32/ESP32-S3, Arduino/MCU, Raspberry Pi Linux ARM and ChromaPlex VM.
- Strict desktop memory-safety gate; embedded-aware C/C++ policy that permits legitimate pointers/MMIO when declared while still blocking classic unbounded buffer primitives.
- Hardware capability manifest supports board identity, GPIO/Wi-Fi/SPI/I2C/UART declarations and explicit MMIO register ranges.
- UNKNOWN online reputation is informational by default and does not block new internal firmware; actual malicious verdicts still block.
- ELF/PE/Wasm structural validation, architecture checks, UPX/packer blocking and entropy review signals.
- Raspberry Pi cross-build path plus capability-derived AppArmor deployment-profile generator.
- ChromaLinux hardening hooks for AppArmor, kernel lockdown=integrity and dm-verity metadata. Activation on a real ISO remains a target/VM acceptance gate.
- Embedded projects use PlatformIO or Arduino CLI in quarantine and are never executed as host processes.

## Verification in the release environment

- pytest: 103 passed, 7 skipped, 12 subtests passed.
- unittest: 110 tests, 0 failures, 7 skipped.
- Skips are environment-dependent integrations such as PySide6/bubblewrap where unavailable in the container.

This is an Alpha release. Real ESP32/Arduino flashing, Raspberry Pi deployment, live ClamAV database operation, full GUI launch and real ISO/VM hardening activation must still be verified on the corresponding target systems.
