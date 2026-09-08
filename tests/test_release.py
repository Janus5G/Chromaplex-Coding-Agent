from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from chromaplex_agent.ai_client import AIAgent, AIClientError, _extract_openai_text, strip_code_fence
from chromaplex_agent.credentials import CredentialStore
from chromaplex_agent.modes import MODES, default_filename, system_prompt
from chromaplex_agent.project import Workspace, parse_project_json, validate_relative_path
from chromaplex_agent.runtimes.chromaplex import build_binary, compile_cpl, run_cpa, run_cpl
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


ROOT = Path(__file__).resolve().parents[1]
DEB = ROOT / "dist" / "chromaplex-coding-agent_0.4.0_all.deb"


class PathSecurityTests(unittest.TestCase):
    def test_backslashes_are_normalized(self):
        self.assertEqual(validate_relative_path(r"src\\main.py"), "src/main.py")

    def test_rejects_windows_absolute_paths(self):
        for bad in (r"C:\\Windows\\system32\\x", "D:/temp/x", r"\\\\server\\share\\x"):
            with self.subTest(path=bad), self.assertRaises(ValueError):
                validate_relative_path(bad)

    def test_rejects_empty_dot_tilde_and_nul(self):
        for bad in ("", ".", "~", "src/./x", "bad\x00name"):
            with self.subTest(path=bad), self.assertRaises(ValueError):
                validate_relative_path(bad)

    def test_runtime_rejects_parent_traversal(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                run_project(Path(td), "../outside.py", "Python (Linux)", 5)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_workspace_blocks_symlink_escape(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as outside:
            root = Path(td)
            (root / "link").symlink_to(Path(outside), target_is_directory=True)
            ws = Workspace()
            ws.load({"link/escape.txt": "blocked"}, "link/escape.txt")
            with self.assertRaises(ValueError):
                ws.write_to(root)
            self.assertFalse((Path(outside) / "escape.txt").exists())


class ProjectRobustnessTests(unittest.TestCase):
    def test_fenced_project_json(self):
        files, main, desc = parse_project_json('```json\n{"files":{"main.py":"print(1)"},"main_file":"main.py","description":"demo"}\n```')
        self.assertEqual(main, "main.py")
        self.assertEqual(desc, "demo")
        self.assertEqual(files["main.py"], "print(1)")

    def test_project_json_falls_back_to_existing_main(self):
        files, main, _ = parse_project_json('{"files":{"a.py":"x"},"main_file":"missing.py"}')
        self.assertEqual(main, "a.py")
        self.assertIn(main, files)

    def test_project_json_rejects_non_text_content(self):
        with self.assertRaises(ValueError):
            parse_project_json('{"files":{"a.bin":123},"main_file":"a.bin"}')

    def test_project_json_rejects_invalid_payload(self):
        with self.assertRaises((ValueError, Exception)):
            parse_project_json("not a project")

    def test_dirty_only_after_change(self):
        ws = Workspace()
        ws.load({"a.py": "x"}, "a.py")
        ws.set_content("a.py", "x")
        self.assertEqual(ws.dirty, set())
        ws.set_content("a.py", "y")
        self.assertEqual(ws.dirty, {"a.py"})

    def test_runtime_directory_cleanup(self):
        ws = Workspace()
        ws.load({"a.py": "print(1)"}, "a.py")
        ws.seal()
        runtime = ws.runtime_dir()
        self.assertTrue(runtime.exists())
        ws.cleanup_runtime_dir()
        self.assertFalse(runtime.exists())

    def test_zip_contains_edited_content(self):
        ws = Workspace()
        ws.load({"src/main.py": "print(1)"}, "src/main.py")
        ws.set_content("src/main.py", "print(2)")
        ws.seal()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "project.zip"
            ws.export_zip(path)
            with zipfile.ZipFile(path) as zf:
                self.assertEqual(zf.read("src/main.py").decode(), "print(2)")
                self.assertNotIn("../", "\n".join(zf.namelist()))


class ModeTests(unittest.TestCase):
    def test_all_default_languages_are_supported(self):
        for key, mode in MODES.items():
            with self.subTest(mode=key):
                self.assertIn(mode.default_language, mode.languages)
                self.assertTrue(default_filename(key, mode.default_language))

    def test_project_prompt_requires_json(self):
        prompt = system_prompt("linux", "Projekt (flere filer)")
        self.assertIn('"files"', prompt)
        self.assertIn("safe relative paths", prompt)

    def test_chromaplex_prompt_does_not_invent_universal_syntax(self):
        prompt = system_prompt("chromaplex", "CPL")
        self.assertIn("documented ChromaPlex repositories", prompt)
        self.assertIn("RED/GREEN/BLUE/VIOLET/UV", prompt)


class AIClientTests(unittest.TestCase):
    def test_openai_top_level_output_text(self):
        self.assertEqual(_extract_openai_text({"output_text": "ok"}), "ok")

    def test_openai_multiple_output_pieces(self):
        data = {"output": [{"content": [{"type": "output_text", "text": "a"}, {"type": "text", "text": "b"}]}]}
        self.assertEqual(_extract_openai_text(data), "a\nb")

    def test_openai_no_text_is_error(self):
        with self.assertRaises(AIClientError):
            _extract_openai_text({"output": []})

    def test_unknown_provider_is_error(self):
        with self.assertRaises(ValueError):
            AIAgent("unknown", "key", "model")

    def test_timeout_is_clamped(self):
        self.assertEqual(AIAgent("openai", "k", "m", 1).timeout, 5)
        self.assertEqual(AIAgent("openai", "k", "m", 9999).timeout, 600)

    def test_code_fence_without_fence_is_unchanged(self):
        self.assertEqual(strip_code_fence("print(1)"), "print(1)")


class CredentialTests(unittest.TestCase):
    def setUp(self):
        CredentialStore._session.clear()

    def tearDown(self):
        CredentialStore._session.clear()

    def test_environment_wins(self):
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": " env-key "}, clear=False):
            self.assertEqual(CredentialStore.get("openai"), "env-key")

    def test_session_fallback_without_secret_tool(self):
        CredentialStore._session["caffeine"] = "session-key"
        with mock.patch("shutil.which", return_value=None):
            self.assertEqual(CredentialStore.get("caffeine"), "session-key")


class HostRuntimeExtendedTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("bash") and shutil.which("bwrap"), "bash/bubblewrap not installed")
    def test_bash_runtime(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_linux_manifest(root)
            (root / "main.sh").write_text('printf "BASH_OK\\n"\n', encoding="utf-8")
            result = run_project(root, "main.sh", "Bash", 10, scanner=_CleanScanner())
            self.assertTrue(result.success)
            self.assertIn("BASH_OK", result.stdout)

    @unittest.skipUnless(shutil.which("make") and shutil.which("bwrap"), "make/bubblewrap not installed")
    def test_makefile_runtime(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_linux_manifest(root)
            (root / "Makefile").write_text('all:\n\t@echo MAKE_OK\n', encoding="utf-8")
            result = run_project(root, "Makefile", "Makefile", 10, scanner=_CleanScanner())
            self.assertTrue(result.success)
            self.assertIn("MAKE_OK", result.stdout)

    @unittest.skipUnless(shutil.which("gcc") and shutil.which("bwrap"), "gcc/bubblewrap not installed")
    def test_c_compile_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_linux_manifest(root)
            (root / "bad.c").write_text("int main( {", encoding="utf-8")
            result = run_project(root, "bad.c", "C", 10, scanner=_CleanScanner())
            self.assertFalse(result.success)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(result.stderr)

    def test_missing_main_file_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(RuntimeError):
                run_project(Path(td), "missing.py", "Python (Linux)", 5)

    def test_windows_python_is_not_falsely_executed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "main.py").write_text("print(1)", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "not executed as Windows code"):
                run_project(root, "main.py", "Python (Windows)", 5)

    def test_unsupported_language_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "main.txt").write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "not supported"):
                run_project(root, "main.txt", "Unknown", 5)


class ChromaExtendedTests(unittest.TestCase):
    SIMPLE_CPA = "MOV R0, 42\nPRINT R0\nHALT"

    def test_direct_simple_cpa(self):
        result = run_cpa(self.SIMPLE_CPA)
        self.assertIn("42", result.output)

    def test_binary_simple_cpa(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "p.bin"
            path, _ = build_binary(self.SIMPLE_CPA, "CPA", out)
            self.assertGreater(Path(path).stat().st_size, 0)

    def test_invalid_cpl_fails(self):
        with self.assertRaises(Exception):
            compile_cpl("this is not valid CPL !!!")


class DebianPackageTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb not installed")
    def test_deb_metadata(self):
        self.assertTrue(DEB.exists(), "Build the .deb before running release tests")
        fields = {}
        for field in ("Package", "Version", "Architecture", "Depends"):
            value = subprocess.check_output(["dpkg-deb", "-f", str(DEB), field], text=True).strip()
            fields[field] = value
        self.assertEqual(fields["Package"], "chromaplex-coding-agent")
        self.assertEqual(fields["Version"], "0.4.0")
        self.assertEqual(fields["Architecture"], "all")
        self.assertIn("python3-pyside6.qtwidgets", fields["Depends"])
        self.assertIn("bubblewrap", fields["Depends"])
        self.assertIn("clamav", fields["Depends"])

    @unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb not installed")
    def test_deb_installed_layout(self):
        self.assertTrue(DEB.exists(), "Build the .deb before running release tests")
        with tempfile.TemporaryDirectory() as td:
            subprocess.run(["dpkg-deb", "-x", str(DEB), td], check=True)
            root = Path(td)
            launcher = root / "usr/bin/chromaplex-coding-agent"
            verifier = root / "usr/bin/chromaplex-verify-build"
            hardening = root / "usr/bin/chromaplex-hardening"
            desktop = root / "usr/share/applications/chromaplex-coding-agent.desktop"
            app_root = root / "opt/chromaplex-coding-agent"
            self.assertTrue(launcher.exists())
            self.assertTrue(launcher.stat().st_mode & stat.S_IXUSR)
            self.assertTrue(verifier.exists())
            self.assertTrue(verifier.stat().st_mode & stat.S_IXUSR)
            self.assertTrue(hardening.exists())
            self.assertTrue(hardening.stat().st_mode & stat.S_IXUSR)
            self.assertTrue(desktop.exists())
            desktop_text = desktop.read_text(encoding="utf-8")
            for required in ("Type=Application", "Name=Chromaplex Coding Agent", "Exec=chromaplex-coding-agent", "Terminal=false"):
                self.assertIn(required, desktop_text)
            self.assertTrue((app_root / "chromaplex_agent/__main__.py").exists())
            self.assertTrue((app_root / "LICENSE").exists())
            self.assertTrue((app_root / "THIRD_PARTY_SOURCES.md").exists())
            self.assertTrue((app_root / "HARDENING.md").exists())
            self.assertTrue((app_root / "hardening/apparmor.d/chromaplex-generated").exists())
            self.assertFalse(any(app_root.rglob("*.pyc")))
            self.assertFalse(any(p.name == "__pycache__" for p in app_root.rglob("__pycache__")))

    @unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb not installed")
    def test_deb_core_modules_compile_after_extraction(self):
        self.assertTrue(DEB.exists(), "Build the .deb before running release tests")
        with tempfile.TemporaryDirectory() as td:
            subprocess.run(["dpkg-deb", "-x", str(DEB), td], check=True)
            app_root = Path(td) / "opt/chromaplex-coding-agent"
            proc = subprocess.run(
                ["python3", "-m", "compileall", "-q", str(app_root / "chromaplex_agent")],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)


    @unittest.skipUnless(shutil.which("dpkg-deb") and shutil.which("sha256sum"), "dpkg-deb/sha256sum not installed")
    def test_deb_payload_sha256_manifest_passes_and_detects_tamper(self):
        self.assertTrue(DEB.exists(), "Build the .deb before running release tests")
        with tempfile.TemporaryDirectory() as td:
            subprocess.run(["dpkg-deb", "-x", str(DEB), td], check=True)
            app_root = Path(td) / "opt/chromaplex-coding-agent"
            manifest = app_root / "SHA256SUMS"
            self.assertTrue(manifest.exists())
            ok = subprocess.run(["sha256sum", "-c", "SHA256SUMS", "--quiet"], cwd=app_root).returncode
            self.assertEqual(ok, 0)
            target = app_root / "chromaplex_agent/__init__.py"
            target.write_text(target.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
            bad = subprocess.run(["sha256sum", "-c", "SHA256SUMS", "--quiet"], cwd=app_root, capture_output=True, text=True)
            self.assertNotEqual(bad.returncode, 0)


class OptionalGuiSmokeTests(unittest.TestCase):
    def test_gui_constructs_when_pyside6_available(self):
        try:
            from PySide6.QtWidgets import QApplication
            from chromaplex_agent.ui.main_window import MainWindow
        except ImportError:
            self.skipTest("PySide6 is not installed in this test environment")
        old = os.environ.get("QT_QPA_PLATFORM")
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
        try:
            app = QApplication.instance() or QApplication([])
            window = MainWindow()
            self.assertEqual(window.windowTitle(), "Chromaplex Coding Agent")
            self.assertGreaterEqual(window.width(), 1000)
            window.close()
            app.processEvents()
        finally:
            if old is None:
                os.environ.pop("QT_QPA_PLATFORM", None)
            else:
                os.environ["QT_QPA_PLATFORM"] = old
