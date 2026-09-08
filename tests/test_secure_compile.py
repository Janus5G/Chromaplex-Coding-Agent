from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from chromaplex_agent.integrity import sha256_file
from chromaplex_agent.malware_scan import (
    MalwareScanResult,
    MalwareScanState,
    ReputationResult,
    ReputationState,
)
from chromaplex_agent.secure_compile import (
    SecureCompileError,
    SecureCompilePolicy,
    preflight_sources,
    secure_build_chromaplex,
)


class CleanScanner:
    def scan_file(self, path: Path):
        return MalwareScanResult(MalwareScanState.CLEAN, "test-scanner", "clean")

    def scan_directory(self, path: Path):
        return MalwareScanResult(MalwareScanState.CLEAN, "test-scanner", "clean")


class UnavailableScanner:
    def scan_file(self, path: Path):
        return MalwareScanResult(MalwareScanState.UNAVAILABLE, "test-scanner", "offline")

    def scan_directory(self, path: Path):
        return MalwareScanResult(MalwareScanState.UNAVAILABLE, "test-scanner", "offline")


class MaliciousBinaryScanner(CleanScanner):
    def scan_file(self, path: Path):
        return MalwareScanResult(MalwareScanState.MALICIOUS, "test-scanner", "test detection", "TEST.Signature")


class MaliciousReputation:
    def lookup_sha256(self, digest: str):
        return ReputationResult(ReputationState.MALICIOUS, "test-reputation", "known bad hash", malicious=2)


class CleanReputation:
    def lookup_sha256(self, digest: str):
        return ReputationResult(ReputationState.CLEAN, "test-reputation", "known clean")


SIMPLE_CPL = """var x = 42;\nstore x at (1,2,3) colour GREEN;\nload y from (1,2,3) colour GREEN;\nprint y;\n"""


class SecureCompileGateTests(unittest.TestCase):
    def test_fail_closed_when_scanner_unavailable(self):
        with self.assertRaisesRegex(SecureCompileError, "source scan"):
            preflight_sources({"main.py": "print('ok')"}, scanner=UnavailableScanner())

    def test_clean_source_passes(self):
        result = preflight_sources({"main.py": "print('ok')"}, scanner=CleanScanner())
        self.assertEqual(result.malware.state, MalwareScanState.CLEAN)
        self.assertEqual(result.static.level.value, "SAFE")
        self.assertEqual(len(result.source_hashes["main.py"]), 64)

    def test_review_source_requires_explicit_review(self):
        source = "import requests\nprint('network client')\n"
        with self.assertRaisesRegex(SecureCompileError, "MANUAL REVIEW"):
            preflight_sources({"main.py": source}, scanner=CleanScanner())
        result = preflight_sources(
            {"main.py": source},
            scanner=CleanScanner(),
            policy=SecureCompilePolicy(allow_reviewed_source=True),
        )
        self.assertEqual(result.static.level.value, "REVIEW REQUIRED")

    def test_blocked_source_cannot_be_overridden(self):
        source = "rm -rf /\n"
        with self.assertRaisesRegex(SecureCompileError, "BLOCKED"):
            preflight_sources(
                {"danger.sh": source},
                scanner=CleanScanner(),
                policy=SecureCompilePolicy(allow_reviewed_source=True),
            )

    def test_secure_chromaplex_build_releases_only_after_scan(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "program.bin"
            result = secure_build_chromaplex(SIMPLE_CPL, "CPL", output, scanner=CleanScanner())
            self.assertTrue(output.exists())
            self.assertEqual(result.binary_sha256, sha256_file(output))
            self.assertTrue(result.sha256_path.exists())
            self.assertTrue(result.security_manifest_path.exists())
            manifest = json.loads(result.security_manifest_path.read_text(encoding="utf-8"))
            self.assertTrue(manifest["approved"])
            self.assertEqual(manifest["malware_scan"]["source"], "CLEAN")
            self.assertEqual(manifest["malware_scan"]["binary"], "CLEAN")
            self.assertNotIn("host:network", manifest["capabilities"])
            self.assertNotIn("host:filesystem", manifest["capabilities"])

    def test_malicious_binary_is_never_released(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "program.bin"
            with self.assertRaisesRegex(SecureCompileError, "malware detected"):
                secure_build_chromaplex(SIMPLE_CPL, "CPL", output, scanner=MaliciousBinaryScanner())
            self.assertFalse(output.exists())
            self.assertFalse(Path(str(output) + ".sha256").exists())
            self.assertFalse(Path(str(output) + ".security.json").exists())

    def test_malicious_online_reputation_blocks_release(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "program.bin"
            with self.assertRaisesRegex(SecureCompileError, "online reputation"):
                secure_build_chromaplex(
                    SIMPLE_CPL,
                    "CPL",
                    output,
                    scanner=CleanScanner(),
                    reputation_provider=MaliciousReputation(),
                    policy=SecureCompilePolicy(online_reputation_enabled=True),
                )
            self.assertFalse(output.exists())

    def test_clean_online_reputation_is_recorded(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "program.bin"
            result = secure_build_chromaplex(
                SIMPLE_CPL,
                "CPL",
                output,
                scanner=CleanScanner(),
                reputation_provider=CleanReputation(),
                policy=SecureCompilePolicy(online_reputation_enabled=True),
            )
            self.assertEqual(result.reputation.state, ReputationState.CLEAN)
            manifest = json.loads(result.security_manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["online_reputation"]["state"], "CLEAN")

    def test_invalid_cpa_never_releases_output(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "bad.bin"
            with self.assertRaises(Exception):
                secure_build_chromaplex("HOST.SHELL something", "CPA", output, scanner=CleanScanner())
            self.assertFalse(output.exists())

    def test_tamper_changes_released_binary_hash(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "program.bin"
            result = secure_build_chromaplex(SIMPLE_CPL, "CPL", output, scanner=CleanScanner())
            original = result.binary_sha256
            output.write_bytes(output.read_bytes() + b"tamper")
            self.assertNotEqual(original, sha256_file(output))


if __name__ == "__main__":
    unittest.main()

class ScannerAdapterTests(unittest.TestCase):
    def _scanner_script(self, body: str) -> Path:
        import os
        td = tempfile.mkdtemp(prefix="fake_clam_")
        path = Path(td) / "clamscan"
        path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
        os.chmod(path, 0o755)
        self.addCleanup(lambda: __import__('shutil').rmtree(td, ignore_errors=True))
        return path

    def test_clamav_adapter_clean_exit(self):
        from chromaplex_agent.malware_scan import ClamAVScanner
        script = self._scanner_script('echo "sample: OK"; exit 0')
        with tempfile.NamedTemporaryFile() as handle:
            result = ClamAVScanner(str(script)).scan_file(Path(handle.name))
        self.assertEqual(result.state, MalwareScanState.CLEAN)

    def test_clamav_adapter_infected_exit(self):
        from chromaplex_agent.malware_scan import ClamAVScanner
        script = self._scanner_script('echo "sample: Unit.Test.Signature FOUND"; exit 1')
        with tempfile.NamedTemporaryFile() as handle:
            result = ClamAVScanner(str(script)).scan_file(Path(handle.name))
        self.assertEqual(result.state, MalwareScanState.MALICIOUS)
        self.assertEqual(result.signature, "Unit.Test.Signature")

    def test_clamav_adapter_error_exit(self):
        from chromaplex_agent.malware_scan import ClamAVScanner
        script = self._scanner_script('echo "database unavailable" >&2; exit 2')
        with tempfile.NamedTemporaryFile() as handle:
            result = ClamAVScanner(str(script)).scan_file(Path(handle.name))
        self.assertEqual(result.state, MalwareScanState.ERROR)

    def test_virustotal_lookup_is_hash_only_get(self):
        from unittest import mock
        from chromaplex_agent.malware_scan import VirusTotalHashReputation

        class FakeResponse:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self):
                return json.dumps({"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1}}}}).encode()

        captured = {}
        def fake_urlopen(req, timeout=0):
            captured["method"] = req.get_method()
            captured["url"] = req.full_url
            return FakeResponse()

        digest = "a" * 64
        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = VirusTotalHashReputation("secret").lookup_sha256(digest)
        self.assertEqual(captured["method"], "GET")
        self.assertTrue(captured["url"].endswith("/" + digest))
        self.assertEqual(result.state, ReputationState.MALICIOUS)


class HostCompilerGateIntegrationTests(unittest.TestCase):
    def test_c_binary_is_scanned_before_execution(self):
        from unittest import mock
        import subprocess
        from chromaplex_agent.runtimes.host import run_project

        class TrackingScanner(CleanScanner):
            def __init__(self): self.binary_scans = 0
            def scan_file(self, path: Path):
                self.binary_scans += 1
                return MalwareScanResult(MalwareScanState.MALICIOUS, "test-scanner", "blocked", "Unit.Test")

        scanner = TrackingScanner()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            from chromaplex_agent.capabilities import CAPABILITY_FILENAME, default_manifest
            (root / CAPABILITY_FILENAME).write_text(default_manifest().to_json(), encoding="utf-8")
            calls = []
            def fake_sandbox(project_dir, command, timeout, policy=None):
                calls.append(list(command))
                if any("gcc" in str(part) for part in command):
                    (root / ".chromaplex_quarantine_program").write_bytes(b"compiled")
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, "EXECUTED", "")
            with mock.patch("chromaplex_agent.runtimes.host.run_sandboxed", side_effect=fake_sandbox):
                with self.assertRaisesRegex(SecureCompileError, "compiled output"):
                    run_project(root, "main.c", "C", 5, scanner=scanner)
            self.assertEqual(scanner.binary_scans, 1)
            self.assertEqual(len(calls), 1, "compiled binary must not execute after a malware verdict")

class CurrentCplSecureBuildTests(unittest.TestCase):
    DANISH_CPL = '''streng navn = "ChromaPlex"\ntal x = 100\npotens p = findEksponent(x)\nskriv_voxel(0, 0, 0) {\n    kanal rød = p, rest = 0;\n}\n'''

    def test_current_cpl_bundle_passes_secure_gate(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "current.bin"
            result = secure_build_chromaplex(self.DANISH_CPL, "CPL", output, scanner=CleanScanner())
            self.assertTrue(output.read_bytes().startswith(b"CHROMAPLEX_CPA_BUNDLE_V1"))
            self.assertEqual(result.binary_scan.state, MalwareScanState.CLEAN)
            self.assertTrue(result.dialect)

class IndependentVerificationTests(unittest.TestCase):
    def test_security_manifest_verifier_detects_tamper(self):
        from chromaplex_agent.secure_compile import verify_security_manifest
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "program.bin"
            result = secure_build_chromaplex(SIMPLE_CPL, "CPL", output, scanner=CleanScanner())
            ok, problems = verify_security_manifest(output, result.security_manifest_path)
            self.assertTrue(ok, problems)
            output.write_bytes(output.read_bytes() + b"changed")
            ok, problems = verify_security_manifest(output, result.security_manifest_path)
            self.assertFalse(ok)
            self.assertIn("binary SHA-256 mismatch", problems)

    def test_security_manifest_verifier_can_check_sources(self):
        from chromaplex_agent.secure_compile import verify_security_manifest
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "program.bin"
            result = secure_build_chromaplex(SIMPLE_CPL, "CPL", output, scanner=CleanScanner())
            sources = {"program.cpl": SIMPLE_CPL}
            ok, problems = verify_security_manifest(output, result.security_manifest_path, source_files=sources)
            self.assertTrue(ok, problems)
            sources["program.cpl"] += "\n// edit"
            ok, problems = verify_security_manifest(output, result.security_manifest_path, source_files=sources)
            self.assertFalse(ok)
            self.assertIn("source SHA-256 mismatch: program.cpl", problems)
