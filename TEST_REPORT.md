# Chromaplex Coding Agent v0.4.0 Alpha — Test Report

## Automated result

- `pytest`: **103 passed, 7 skipped, 12 subtests passed, 0 failed**.
- `python -m unittest discover -s tests -v`: **110 tests, 0 failures, 7 skipped**.

## Security coverage exercised

PASS coverage includes project/path traversal protection, editor/workspace integrity, SHA-256 sealing, Secure Compile Gate failure modes, malware scanner adapters, build verification, strict desktop memory-safety rules, managed-language unsafe escapes, ELF/PE/Wasm structure validation, UPX/packer rejection, capability manifests, sandbox command construction, AppArmor asset parsing where available, dm-verity helper output, hardened native C compilation, target profiles and embedded hardware policies.

Embedded regression coverage specifically verifies:

- raw embedded pointers are REVIEW rather than automatically BLOCKED;
- `gets`/`strcpy`/`strcat`/`sprintf` style unbounded primitives remain BLOCKED;
- declared MMIO ranges are accepted for review and undeclared numeric MMIO is BLOCKED;
- GPIO access requires the declared GPIO capability;
- ESP32 Wi-Fi requires both `WIFI` hardware permission and `network=true`;
- embedded `malloc` without observable `free` is REVIEW, not malware;
- Raspberry Pi remains on the strict Linux memory policy;
- UNKNOWN hash reputation does not block new firmware unless an administrator explicitly enables a known-clean-only policy;
- Raspberry Pi AppArmor deployment profiles reflect network/process/workspace capabilities and reject non-Pi targets.

## Environment-dependent / not claimed PASS

The following require the actual target/runtime and are not represented as end-to-end PASS merely because unit tests exist:

1. Full PySide6/Qt GUI launch on the supported desktop.
2. Real bubblewrap execution if bubblewrap is absent from the current runner.
3. ClamAV with a current production signature database.
4. Live OpenAI/Caffeine requests with user credentials.
5. Live optional reputation service.
6. Real PlatformIO ESP32 build and flash to physical hardware.
7. Real Arduino CLI build and flash to physical hardware.
8. Raspberry Pi ARM cross-build/deployment and AppArmor enforcement on the Pi.
9. ChromaLinux ISO integration of AppArmor/kernel lockdown/dm-verity and VM boot verification.

## Release rule

Unknown code or an unseen hash is **not** equivalent to malicious code. Release is blocked by concrete policy violations, invalid output structure, mandatory local scanner failure/malicious verdict, undeclared capabilities, or integrity mismatch. Reputation UNKNOWN is informational unless an explicit enterprise policy requires known-clean reputation.
