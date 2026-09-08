from pathlib import Path
import shutil
import tempfile
import unittest

from chromaplex_agent.ai_client import _extract_openai_text, strip_code_fence
from chromaplex_agent.project import Workspace, parse_project_json, validate_relative_path
from chromaplex_agent.integrity import IntegrityManifest, MANIFEST_NAME, SHA256SUMS_NAME, sha256_text
from chromaplex_agent.security import SafetyLevel, scan_files
from chromaplex_agent.sandbox import SandboxUnavailable, build_bwrap_command
from chromaplex_agent.runtimes.chromaplex import build_binary, compile_cpl, run_cpl
from chromaplex_agent.runtimes.host import run_project
from chromaplex_agent.malware_scan import MalwareScanResult, MalwareScanState
from chromaplex_agent.capabilities import CAPABILITY_FILENAME, default_manifest


class _CleanScanner:
    def scan_file(self, path):
        return MalwareScanResult(MalwareScanState.CLEAN, "test-scanner", "clean")
    def scan_directory(self, path):
        return MalwareScanResult(MalwareScanState.CLEAN, "test-scanner", "clean")


def _write_linux_manifest(root: Path) -> None:
    (root / CAPABILITY_FILENAME).write_text(
        default_manifest("linux-desktop").to_json(),
        encoding="utf-8",
    )


class ProjectTests(unittest.TestCase):
    def test_safe_path(self):
        self.assertEqual(validate_relative_path("src/main.py"), "src/main.py")
        for bad in ("../x", "/etc/passwd", "a/../../b"):
            with self.assertRaises(ValueError):
                validate_relative_path(bad)

    def test_project_parse(self):
        files, main, desc = parse_project_json(
            '{"files":{"src/main.py":"print(1)"},"main_file":"src/main.py","description":"x"}'
        )
        self.assertEqual(main, "src/main.py")
        self.assertEqual(files[main], "print(1)")
        self.assertEqual(desc, "x")

    def test_workspace_edits_are_exported(self):
        ws = Workspace()
        ws.load({"src/main.py": "print(1)"}, "src/main.py")
        ws.set_content("src/main.py", "print(2)")
        self.assertIn("src/main.py", ws.dirty)
        ws.seal()
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "project"
            ws.write_to(out)
            self.assertEqual((out / "src/main.py").read_text(encoding="utf-8"), "print(2)")

    def test_zip_export(self):
        ws = Workspace()
        ws.load({"src/main.py": "print(1)"}, "src/main.py")
        ws.seal()
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "p.zip"
            ws.export_zip(out)
            self.assertTrue(out.exists())
            import zipfile
            with zipfile.ZipFile(out) as zf:
                self.assertIn(MANIFEST_NAME, zf.namelist())
                self.assertIn(SHA256SUMS_NAME, zf.namelist())


class AIParsingTests(unittest.TestCase):
    def test_strip_code_fence(self):
        self.assertEqual(strip_code_fence("```python\nprint(1)\n```"), "print(1)")

    def test_openai_response_text_extraction(self):
        payload = {"output": [{"content": [{"type": "output_text", "text": "hello"}]}]}
        self.assertEqual(_extract_openai_text(payload), "hello")


class HostRuntimeTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("bwrap"), "bubblewrap not installed")
    def test_linux_python_runtime(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_linux_manifest(root)
            (root / "main.py").write_text('print("PY_OK")\n', encoding="utf-8")
            result = run_project(root, "main.py", "Python (Linux)", 10, scanner=_CleanScanner())
            self.assertTrue(result.success)
            self.assertIn("PY_OK", result.stdout)

    @unittest.skipUnless(shutil.which("gcc") and shutil.which("bwrap"), "gcc/bubblewrap not installed")
    def test_linux_c_runtime(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_linux_manifest(root)
            (root / "main.c").write_text(
                '#include <stdio.h>\nint main(void){puts("C_OK");return 0;}\n',
                encoding="utf-8",
            )
            result = run_project(root, "main.c", "C", 10, scanner=_CleanScanner())
            self.assertTrue(result.success)
            self.assertIn("C_OK", result.stdout)


class ChromaTests(unittest.TestCase):
    SIMPLE = "var x = 1000;\nstore x at (10,20,30) colour GREEN;\nload y from (10,20,30) colour GREEN;\nprint y;"

    def test_compile_and_run_simple_cpl(self):
        asm, dialect = compile_cpl(self.SIMPLE)
        self.assertEqual(dialect, "simple-cpl")
        self.assertIn("LASER_WRITE", asm)
        result = run_cpl(self.SIMPLE)
        self.assertIn("1000", result.output)

    DANISH = """
tal data = 1234567;
potens e = findEksponent(data);
tal rest = data - (2^e);
skriv_voxel(5, 5, 5) {
    kanal grøn = e, rest = rest;
}
"""

    def test_compile_run_and_bundle_danish_cpl(self):
        asm, dialect = compile_cpl(self.DANISH)
        self.assertEqual(dialect, "danish-cpl")
        self.assertIn("STORE.C", asm)
        result = run_cpl(self.DANISH)
        self.assertIn("5, 5, 5", result.output)
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "program.bin"
            path, _ = build_binary(self.DANISH, "CPL", out)
            payload = Path(path).read_bytes()
            self.assertTrue(payload.startswith(b"CHROMAPLEX_CPA_BUNDLE_V1\n"))

    def test_build_legacy_binary(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "program.bin"
            path, _ = build_binary(self.SIMPLE, "CPL", out)
            self.assertTrue(Path(path).exists())
            self.assertGreater(Path(path).stat().st_size, 0)


class IntegritySecurityTests(unittest.TestCase):
    def test_sha256_known_value(self):
        self.assertEqual(sha256_text("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_edit_invalidates_sha_seal(self):
        ws = Workspace()
        ws.load({"main.py": "print(1)"}, "main.py")
        manifest = ws.seal()
        self.assertTrue(manifest.verify_text_files(ws.files)[0])
        ws.set_content("main.py", "print(2)")
        ok, problems = ws.verify_seal()
        self.assertFalse(ok)
        self.assertIn("workspace is not SHA-256 sealed", problems)

    def test_manifest_detects_out_of_band_tamper(self):
        files = {"main.py": "print(1)"}
        manifest = IntegrityManifest.from_text_files(files)
        files["main.py"] = "print(999)"
        ok, problems = manifest.verify_text_files(files)
        self.assertFalse(ok)
        self.assertIn("hash mismatch: main.py", problems)

    def test_security_scanner_blocks_destructive_root_delete(self):
        report = scan_files({"bad.sh": "rm -rf /"})
        self.assertEqual(report.level, SafetyLevel.BLOCKED)

    def test_security_scanner_requires_review_for_network(self):
        report = scan_files({"fetch.sh": "curl https://example.invalid/file"})
        self.assertEqual(report.level, SafetyLevel.REVIEW)

    def test_security_scanner_accepts_normal_code(self):
        report = scan_files({"main.py": 'print("hello")'})
        self.assertEqual(report.level, SafetyLevel.SAFE)

    def test_bwrap_command_clears_environment_and_hides_home(self):
        with tempfile.TemporaryDirectory() as td:
            with unittest.mock.patch("chromaplex_agent.sandbox.bubblewrap_path", return_value="/usr/bin/bwrap"):
                cmd = build_bwrap_command(Path(td), ["/usr/bin/python3", "/workspace/main.py"])
        joined = " ".join(cmd)
        self.assertIn("--clearenv", cmd)
        self.assertIn("--unshare-all", cmd)
        self.assertIn("HOME /nonexistent", joined)
        self.assertNotIn(str(Path.home()), joined)
        self.assertNotIn("--share-net", cmd)


if __name__ == "__main__":
    unittest.main()
