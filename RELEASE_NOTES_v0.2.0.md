# Chromaplex Coding Agent v0.2.0 — Alpha

First public preview of the standalone Chromaplex Coding Agent Linux application.

## Highlights

- Generate and edit Linux, Windows, Web and ChromaPlex projects.
- Built-in editable multi-file code workspace.
- CPL/CPA compile, run and binary/bundle paths based on the original ChromaPlex sources.
- Static web preview where supported.
- Save folders and export project ZIP files.
- Build a normal Debian package for later import into ChromaPress or another Debian/Ubuntu ISO workflow.
- OpenAI-first AI provider architecture with optional Caffeine support.
- Fail-closed bubblewrap sandbox for supported host-language execution.
- Security review gate plus SHA-256 sealing of the exact reviewed workspace.
- SHA-256 manifests in project exports, binary sidecars and installed Debian payload verification.

## Validation

The expanded release suite passes project/path safety, Windows-path regression tests, workspace editing/export, SHA-256 sealing/tamper detection, Debian payload verification, defensive scanner rules, sandbox policy construction, AI response parsing and both ChromaPlex compiler/bundle paths. See `TEST_REPORT.md` for exact PASS/SKIP counts.

## Alpha limitations

Full GUI/API/real-ISO end-to-end testing is still in progress. Live bubblewrap execution and Qt GUI behaviour must still be verified on the intended Linux target before they are called PASS.
