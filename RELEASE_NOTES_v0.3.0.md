# Chromaplex Coding Agent v0.3.0 Alpha

v0.3.0 is a security-architecture release.

The central addition is **Secure Compile Gate**: generated/imported source must pass static review and local malware scanning before compiler entry; compiled output remains in quarantine, is scanned again, and is released only after mandatory gates pass. Approved output receives SHA-256 evidence and a machine-readable security manifest.

For CPL/CPA, the gate additionally relies on the constrained ChromaPlex VM/assembler capability set rather than exposing arbitrary host OS primitives. Host C/C# compilation uses compile → scan → sandbox execution.

Optional online reputation is hash-only and disabled by default. No automatic file upload is implemented.

This remains an Alpha release because GUI/live-provider/real-ISO target-machine acceptance is not yet fully completed.
