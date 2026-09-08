from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from ..binary_validation import validate_binary
from ..capabilities import load_manifest
from ..malware_scan import ClamAVScanner, MalwareScanState, MalwareScanner
from ..memory_safety import SAFE_C_HARDENING_FLAGS
from ..project import validate_relative_path
from ..sandbox import SandboxPolicy, run_sandboxed
from ..secure_compile import SecureCompilePolicy, SecureCompileError, preflight_sources
from ..targets import get_target


@dataclass
class RunResult:
    success: bool
    command: list[str]
    stdout: str
    stderr: str
    returncode: int

    @property
    def text(self) -> str:
        parts = ["SECURE RUNTIME: capability manifest enforced, source scan=required, host home hidden unless declared", "$ " + " ".join(self.command)]
        if self.stdout:
            parts.append("\nSTDOUT:\n" + self.stdout)
        if self.stderr:
            parts.append("\nSTDERR:\n" + self.stderr)
        parts.append(f"\nRETURN CODE: {self.returncode}")
        return "\n".join(parts)


def _require(program: str) -> str:
    path = shutil.which(program)
    if not path:
        raise RuntimeError(f"Required runtime/tool is not installed: {program}")
    return path


def _sandbox_path(safe_main: str) -> str:
    return "/workspace/" + safe_main.replace("\\", "/")


def _project_text_files(project_dir: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    root = Path(project_dir).resolve()
    for path in root.rglob("*"):
        if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        files[path.relative_to(root).as_posix()] = text
    return files


def _require_binary_clean(scanner: MalwareScanner, path: Path, expected_format: str) -> None:
    scan = scanner.scan_file(path)
    if scan.state == MalwareScanState.MALICIOUS:
        raise SecureCompileError(f"SECURITY GATE BLOCKED compiled output: {scan.signature or scan.detail}")
    if scan.state != MalwareScanState.CLEAN:
        raise SecureCompileError(f"SECURITY GATE FAILED compiled output scan: {scan.engine}: {scan.detail}")
    validation = validate_binary(path, expected_format)
    if not validation.valid or validation.packed:
        raise SecureCompileError("BINARY STRUCTURE/PACKER GATE BLOCKED: " + "; ".join(validation.findings))
    if validation.requires_review:
        raise SecureCompileError("ENTROPY GATE REQUIRES REVIEW before execution: " + "; ".join(validation.findings))


def run_project(project_dir: Path, main_file: str, language: str, timeout: int, *, scanner: MalwareScanner | None = None, reviewed: bool = False, target: str | None = None) -> RunResult:
    safe_main = validate_relative_path(main_file)
    root = project_dir.resolve()
    path = (project_dir / safe_main).resolve(strict=False)
    if path != root and root not in path.parents:
        raise RuntimeError(f"Main file escapes project directory: {main_file}")
    if not path.exists():
        raise RuntimeError(f"Main file does not exist: {main_file}")
    if language == "Python (Windows)":
        raise RuntimeError("Windows Python is generated on Linux but is not executed as Windows code. Test it in an isolated Windows runtime.")
    supported = {"Bash", "Python (Linux)", "C", "Makefile", "PowerShell", "Batch", "C#"}
    if language not in supported:
        raise RuntimeError(f"Direct execution is not supported for {language}")

    caps = load_manifest(root, required=True, expected_target=target)
    target_profile = get_target(caps.target, mode="linux" if language in {"Bash", "Python (Linux)", "C", "Makefile"} else None)
    if target_profile.is_embedded:
        raise RuntimeError("Embedded firmware is never executed as a host process. Build it with the embedded target toolchain and deploy it to the declared device.")
    if target_profile.is_raspberry_pi:
        raise RuntimeError("Raspberry Pi ARM binaries are not executed on the build host. Use secure cross-build, verify the manifest, then deploy/test on the Pi target.")
    # Source-declared process spawning must match the capability manifest.
    scanner_impl = scanner or ClamAVScanner(timeout=timeout)
    source_files = _project_text_files(root)
    gate = preflight_sources(source_files or {safe_main: path.read_text(encoding="utf-8")}, language=language, target=target_profile, capability_manifest=caps, scanner=scanner_impl, policy=SecureCompilePolicy(malware_scan_required=True, allow_reviewed_source=reviewed))
    if not caps.process_spawn and any(f.rule == "process-spawn" for f in gate.static.findings):
        raise SecureCompileError("CAPABILITY GATE BLOCKED: source requests process spawning but manifest process_spawn=false")
    if not caps.network and any(f.rule in {"network-download", "network-socket-tool", "programmatic-network", "shell-network-device"} for f in gate.static.findings):
        raise SecureCompileError("CAPABILITY GATE BLOCKED: source requests network but manifest network=false")

    sandbox_policy = SandboxPolicy(capabilities=caps)
    sandbox_main = _sandbox_path(safe_main)
    if language == "Bash":
        command = [_require("bash"), sandbox_main]
    elif language == "Python (Linux)":
        command = [_require("python3"), sandbox_main]
    elif language == "C":
        gcc = _require("gcc")
        binary = "/workspace/.chromaplex_quarantine_program"
        host_binary = root / ".chromaplex_quarantine_program"
        compile_command = [gcc, sandbox_main, *SAFE_C_HARDENING_FLAGS, "-o", binary]
        compile_proc = run_sandboxed(project_dir, compile_command, timeout, sandbox_policy)
        if compile_proc.returncode != 0:
            return RunResult(False, compile_command, compile_proc.stdout, compile_proc.stderr, compile_proc.returncode)
        _require_binary_clean(scanner_impl, host_binary, "ELF")
        command = [binary]
    elif language == "Makefile":
        command = [_require("make"), "-f", sandbox_main]
    elif language == "PowerShell":
        command = [_require("pwsh"), "-NoProfile", "-File", sandbox_main]
    elif language == "Batch":
        command = [_require("wine"), "cmd", "/c", sandbox_main]
    elif language == "C#":
        compiler = shutil.which("csc") or shutil.which("mcs")
        if not compiler:
            raise RuntimeError("C# execution requires csc or mcs on this Linux system")
        exe = "/workspace/.chromaplex_quarantine_program.exe"
        host_exe = root / ".chromaplex_quarantine_program.exe"
        compile_command = [compiler, sandbox_main, "-out:" + exe]
        compile_proc = run_sandboxed(project_dir, compile_command, timeout, sandbox_policy)
        if compile_proc.returncode != 0:
            return RunResult(False, compile_command, compile_proc.stdout, compile_proc.stderr, compile_proc.returncode)
        _require_binary_clean(scanner_impl, host_exe, "PE")
        command = [exe] if os.name == "nt" else [_require("mono"), exe]
    proc = run_sandboxed(project_dir, command, timeout, sandbox_policy)
    return RunResult(proc.returncode == 0, command, proc.stdout, proc.stderr, proc.returncode)
