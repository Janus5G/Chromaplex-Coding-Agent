from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from .binary_validation import BinaryValidationResult, validate_binary
from .capabilities import CapabilityManifest, default_manifest
from .integrity import hash_text_files, sha256_file, write_file_sidecar
from .malware_scan import (
    ClamAVScanner, DisabledReputationProvider, HashReputationProvider,
    MalwareScanResult, MalwareScanState, MalwareScanner, ReputationResult,
    ReputationState, reputation_for_file,
)
from .memory_safety import MemorySafetyLevel, MemorySafetyReport, SAFE_C_HARDENING_FLAGS, scan_memory_safety
from .targets import TargetProfile, get_target
from .security import SafetyLevel, SafetyReport, scan_files
from .runtimes.chromaplex import build_binary, compile_cpl, run_cpa

SECURITY_MANIFEST_SCHEMA = "chromaplex-secure-build-v2"
SECURITY_MANIFEST_SUFFIX = ".security.json"


class SecureCompileError(RuntimeError):
    pass


@dataclass(frozen=True)
class SecureCompilePolicy:
    malware_scan_required: bool = True
    online_reputation_enabled: bool = False
    online_reputation_required: bool = False
    allow_reviewed_source: bool = False
    allow_high_entropy: bool = False
    require_memory_safe: bool = True


@dataclass(frozen=True)
class SourceGateResult:
    static: SafetyReport
    memory: MemorySafetyReport
    malware: MalwareScanResult
    source_hashes: dict[str, str]


@dataclass(frozen=True)
class SecureBuildResult:
    output_path: Path
    sha256_path: Path
    security_manifest_path: Path
    source_gate: SourceGateResult
    binary_scan: MalwareScanResult
    reputation: ReputationResult
    binary_validation: BinaryValidationResult
    binary_sha256: str
    dialect: str = ""
    assembly: str = ""


@dataclass(frozen=True)
class SecurityBuildManifest:
    source_hashes: dict[str, str]
    binary_sha256: str
    binary_name: str
    language: str
    compiler: str
    target: str
    static_level: str
    memory_safety_level: str
    malware_engine: str
    source_malware_state: str
    binary_malware_state: str
    reputation_provider: str
    reputation_state: str
    binary_format: str
    binary_entropy: float
    binary_packed: bool
    capability_manifest: dict
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    dialect: str = ""
    schema: str = SECURITY_MANIFEST_SCHEMA
    created_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_json(self) -> str:
        return json.dumps({
            "schema": self.schema,
            "created_utc": self.created_utc,
            "source": {"algorithm": "SHA-256", "files": self.source_hashes},
            "output": {"name": self.binary_name, "algorithm": "SHA-256", "sha256": self.binary_sha256},
            "compiler": self.compiler,
            "target": self.target,
            "language": self.language,
            "dialect": self.dialect,
            "static_analysis": self.static_level,
            "memory_safety": self.memory_safety_level,
            "malware_scan": {"engine": self.malware_engine, "source": self.source_malware_state, "binary": self.binary_malware_state},
            "online_reputation": {"provider": self.reputation_provider, "state": self.reputation_state},
            "binary_validation": {"format": self.binary_format, "entropy": round(self.binary_entropy, 4), "packed": self.binary_packed},
            "capability_manifest": self.capability_manifest,
            "capabilities": list(self.capabilities),
            "approved": True,
        }, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _scanner_or_default(scanner: MalwareScanner | None) -> MalwareScanner:
    return scanner or ClamAVScanner()


def _enforce_scan(result: MalwareScanResult, *, required: bool, stage: str) -> None:
    if result.state == MalwareScanState.MALICIOUS:
        signature = f" ({result.signature})" if result.signature else ""
        raise SecureCompileError(f"SECURITY GATE BLOCKED at {stage}: malware detected{signature}")
    if result.state in {MalwareScanState.ERROR, MalwareScanState.UNAVAILABLE, MalwareScanState.UNKNOWN} and required:
        raise SecureCompileError(f"SECURITY GATE FAILED at {stage}: {result.engine}: {result.detail}")


def _write_sources(files: Mapping[str, str], root: Path) -> None:
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def preflight_sources(files: Mapping[str, str], *, language: str = "", target: str | TargetProfile | None = None, capability_manifest: CapabilityManifest | None = None, scanner: MalwareScanner | None = None, policy: SecureCompilePolicy | None = None) -> SourceGateResult:
    if not files:
        raise SecureCompileError("SECURITY GATE FAILED: empty source set")
    policy = policy or SecureCompilePolicy()
    static = scan_files(files)
    if static.level == SafetyLevel.BLOCKED:
        raise SecureCompileError("SECURITY GATE BLOCKED by static analysis:\n" + static.summary)
    if static.level == SafetyLevel.REVIEW and not policy.allow_reviewed_source:
        raise SecureCompileError("SECURITY GATE REQUIRES MANUAL REVIEW:\n" + static.summary)
    profile = target if isinstance(target, TargetProfile) else get_target(target or (capability_manifest.target if capability_manifest else "linux-desktop"))
    memory = scan_memory_safety(files, language, target=profile, capability_manifest=capability_manifest)
    if policy.require_memory_safe and memory.level == MemorySafetyLevel.BLOCKED:
        raise SecureCompileError("MEMORY SAFETY GATE BLOCKED:\n" + memory.summary)
    if memory.level == MemorySafetyLevel.REVIEW and not policy.allow_reviewed_source:
        raise SecureCompileError("MEMORY SAFETY GATE REQUIRES REVIEW:\n" + memory.summary)
    scanner_impl = _scanner_or_default(scanner)
    with tempfile.TemporaryDirectory(prefix="chromaplex_source_scan_") as td:
        root = Path(td)
        _write_sources(files, root)
        malware = scanner_impl.scan_directory(root)
    _enforce_scan(malware, required=policy.malware_scan_required, stage="source scan")
    return SourceGateResult(static, memory, malware, hash_text_files(files))


def _chromaplex_capabilities(assembly: str) -> tuple[str, ...]:
    caps = {"vm:registers", "vm:control-flow"}
    upper = assembly.upper()
    if any(token in upper for token in ("STORE", "LOAD.C", "LASER_WRITE", "LASER_READ", "PACK", "UNPACK")):
        caps.add("chromaplex:voxel-storage")
    if "IN" in upper or "OUT" in upper or "PRINT" in upper:
        caps.add("vm:buffer-io")
    return tuple(sorted(caps))


def _validate_chromaplex_source(source: str, language: str) -> tuple[str, str, tuple[str, ...]]:
    if language == "CPL":
        assembly, dialect = compile_cpl(source)
    elif language == "CPA":
        validated = run_cpa(source)
        assembly, dialect = source, validated.dialect
    else:
        raise SecureCompileError(f"Secure ChromaPlex compiler does not support language: {language}")
    return assembly, dialect, _chromaplex_capabilities(assembly)


def _validate_release_binary(path: Path, expected: str, policy: SecureCompilePolicy, *, expected_arch: str | None = None, embedded: bool = False) -> BinaryValidationResult:
    result = validate_binary(path, expected, expected_arch=expected_arch)
    if not result.valid:
        raise SecureCompileError("BINARY STRUCTURE GATE BLOCKED: " + "; ".join(result.findings))
    if result.packed:
        raise SecureCompileError("PACKER POLICY BLOCKED: packed/runtime-compressed executable detected")
    if result.requires_review and not embedded and not policy.allow_high_entropy:
        raise SecureCompileError("ENTROPY GATE REQUIRES REVIEW: " + "; ".join(result.findings))
    return result


def _reputation(path: Path, provider: HashReputationProvider | None, policy: SecureCompilePolicy) -> ReputationResult:
    provider = provider or DisabledReputationProvider()
    rep = reputation_for_file(path, provider if policy.online_reputation_enabled else DisabledReputationProvider())
    if rep.state == ReputationState.MALICIOUS:
        raise SecureCompileError("SECURITY GATE BLOCKED by online reputation: " + rep.detail)
    if policy.online_reputation_required and rep.state != ReputationState.CLEAN:
        raise SecureCompileError("SECURITY GATE FAILED: required online reputation is not CLEAN: " + rep.detail)
    return rep


def _enforce_capability_findings(source_gate: SourceGateResult, caps: CapabilityManifest) -> None:
    rules = {f.rule for f in source_gate.static.findings}
    if not caps.network and rules & {"network-download", "network-socket-tool", "programmatic-network", "shell-network-device"}:
        raise SecureCompileError("CAPABILITY GATE BLOCKED: source requests network but manifest network=false")
    if not caps.process_spawn and "process-spawn" in rules:
        raise SecureCompileError("CAPABILITY GATE BLOCKED: source requests process spawning but manifest process_spawn=false")


def _release(quarantine_output: Path, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_release = output_path.with_name(output_path.name + ".releasing")
    try:
        shutil.copy2(quarantine_output, tmp_release)
        os.replace(tmp_release, output_path)
    finally:
        tmp_release.unlink(missing_ok=True)


def _finish(source_gate: SourceGateResult, built: Path, output_path: Path, *, scanner: MalwareScanner, reputation_provider: HashReputationProvider | None, policy: SecureCompilePolicy, language: str, compiler: str, expected_format: str, capabilities: tuple[str, ...], capability_manifest: CapabilityManifest, target: str | None = None, expected_arch: str | None = None, embedded: bool = False, dialect: str = "", assembly: str = "") -> SecureBuildResult:
    binary_scan = scanner.scan_file(built)
    _enforce_scan(binary_scan, required=policy.malware_scan_required, stage="compiled output scan")
    validation = _validate_release_binary(built, expected_format, policy, expected_arch=expected_arch, embedded=embedded)
    rep = _reputation(built, reputation_provider, policy)
    _release(built, output_path)
    sidecar = write_file_sidecar(output_path)
    manifest = SecurityBuildManifest(
        source_hashes=source_gate.source_hashes,
        binary_sha256=sha256_file(output_path), binary_name=output_path.name,
        language=language, compiler=compiler, target=target or capability_manifest.target,
        static_level=source_gate.static.level.value,
        memory_safety_level=source_gate.memory.level.value,
        malware_engine=binary_scan.engine,
        source_malware_state=source_gate.malware.state.value,
        binary_malware_state=binary_scan.state.value,
        reputation_provider=rep.provider, reputation_state=rep.state.value,
        binary_format=validation.format, binary_entropy=validation.entropy,
        binary_packed=validation.packed, capability_manifest=capability_manifest.to_dict(),
        capabilities=capabilities, dialect=dialect,
    )
    manifest_path = output_path.with_name(output_path.name + SECURITY_MANIFEST_SUFFIX)
    manifest_path.write_text(manifest.to_json(), encoding="utf-8")
    return SecureBuildResult(output_path, sidecar, manifest_path, source_gate, binary_scan, rep, validation, sha256_file(output_path), dialect, assembly)


def secure_build_chromaplex(source: str, language: str, output_path: Path, *, scanner: MalwareScanner | None = None, reputation_provider: HashReputationProvider | None = None, policy: SecureCompilePolicy | None = None) -> SecureBuildResult:
    policy = policy or SecureCompilePolicy()
    scanner_impl = _scanner_or_default(scanner)
    files = {"program.cpl" if language == "CPL" else "program.cpa": source}
    source_gate = preflight_sources(files, language=language, target="chromaplex-vm", capability_manifest=default_manifest("chromaplex-vm"), scanner=scanner_impl, policy=policy)
    assembly, dialect, capabilities = _validate_chromaplex_source(source, language)
    output_path = Path(output_path).resolve()
    with tempfile.TemporaryDirectory(prefix="chromaplex_quarantine_") as td:
        quarantine = Path(td); os.chmod(quarantine, 0o700)
        built_path, built_assembly = build_binary(source, language, quarantine / output_path.name)
        built = Path(built_path)
        if not built.exists() or built.stat().st_size <= 0:
            raise SecureCompileError("SECURITY GATE FAILED: compiler produced no output")
        return _finish(source_gate, built, output_path, scanner=scanner_impl, reputation_provider=reputation_provider, policy=policy, language=language, compiler="Chromaplex Secure Compile Gate 0.4", expected_format="CHROMAPLEX", capabilities=capabilities, capability_manifest=default_manifest("chromaplex-vm"), target="chromaplex-vm", dialect=dialect, assembly=built_assembly or assembly)


def secure_build_c(source: str, output_path: Path, *, scanner: MalwareScanner | None = None, reputation_provider: HashReputationProvider | None = None, policy: SecureCompilePolicy | None = None, capability_manifest: CapabilityManifest | None = None, timeout: int = 60) -> SecureBuildResult:
    policy = policy or SecureCompilePolicy()
    if capability_manifest is None:
        raise SecureCompileError("CAPABILITY GATE FAILED: explicit capability manifest is required")
    caps = capability_manifest; caps.validate()
    target_profile = get_target(caps.target, mode="linux")
    if target_profile.is_embedded:
        raise SecureCompileError("EMBEDDED TARGET REQUIRES PROJECT BUILD: use secure_build_embedded_project() with Arduino CLI or PlatformIO; source is not classified as unsafe")
    scanner_impl = _scanner_or_default(scanner)
    source_gate = preflight_sources({"main.c": source}, language="C", target=target_profile, capability_manifest=caps, scanner=scanner_impl, policy=policy)
    _enforce_capability_findings(source_gate, caps)
    if target_profile.is_raspberry_pi:
        gcc = shutil.which("aarch64-linux-gnu-gcc") or shutil.which("arm-linux-gnueabihf-gcc")
        if not gcc:
            raise SecureCompileError("TARGET TOOLCHAIN UNAVAILABLE: Raspberry Pi cross-compiler (aarch64-linux-gnu-gcc or arm-linux-gnueabihf-gcc) is not installed")
    else:
        gcc = shutil.which("gcc")
        if not gcc:
            raise SecureCompileError("SECURITY GATE FAILED: gcc is unavailable")
    output_path = Path(output_path).resolve()
    with tempfile.TemporaryDirectory(prefix="chromaplex_c_quarantine_") as td:
        root = Path(td); os.chmod(root, 0o700)
        src = root / "main.c"; built = root / output_path.name
        src.write_text(source, encoding="utf-8")
        # GCC's analyzer is a mandatory source-level companion when supported.
        analyze = subprocess.run([gcc, "-fanalyzer", "-fsyntax-only", "-Wall", "-Wextra", str(src)], capture_output=True, text=True, timeout=timeout, check=False)
        if analyze.returncode != 0 or "warning:" in (analyze.stderr or ""):
            raise SecureCompileError("MEMORY/STATIC ANALYZER GATE FAILED:\n" + (analyze.stderr or analyze.stdout))
        cmd = [gcc, str(src), *SAFE_C_HARDENING_FLAGS, "-o", str(built)]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode != 0:
            raise SecureCompileError("HARDENED C COMPILER FAILED:\n" + (proc.stderr or proc.stdout))
        return _finish(source_gate, built, output_path, scanner=scanner_impl, reputation_provider=reputation_provider, policy=policy, language="C", compiler=("Raspberry Pi cross-GCC via Chromaplex Gate 0.4" if target_profile.is_raspberry_pi else "GCC hardened safe-C via Chromaplex Gate 0.4"), expected_format="ELF", expected_arch=("ARM" if target_profile.is_raspberry_pi else None), capabilities=(("native:cpu", "filesystem:workspace", "target:raspberry-pi") if target_profile.is_raspberry_pi else ("native:cpu", "filesystem:workspace")), capability_manifest=caps, target=target_profile.key)


def secure_build_csharp(source: str, output_path: Path, *, scanner: MalwareScanner | None = None, reputation_provider: HashReputationProvider | None = None, policy: SecureCompilePolicy | None = None, capability_manifest: CapabilityManifest | None = None, timeout: int = 60) -> SecureBuildResult:
    policy = policy or SecureCompilePolicy()
    if capability_manifest is None:
        raise SecureCompileError("CAPABILITY GATE FAILED: explicit capability manifest is required")
    caps = capability_manifest; caps.validate()
    scanner_impl = _scanner_or_default(scanner)
    source_gate = preflight_sources({"Program.cs": source}, language="C#", target=caps.target, capability_manifest=caps, scanner=scanner_impl, policy=policy)
    _enforce_capability_findings(source_gate, caps)
    compiler = shutil.which("csc") or shutil.which("mcs")
    if not compiler:
        raise SecureCompileError("SECURITY GATE FAILED: csc/mcs is unavailable")
    output_path = Path(output_path).resolve()
    with tempfile.TemporaryDirectory(prefix="chromaplex_cs_quarantine_") as td:
        root = Path(td); os.chmod(root, 0o700)
        src = root / "Program.cs"; built = root / output_path.name
        src.write_text(source, encoding="utf-8")
        proc = subprocess.run([compiler, str(src), "-out:" + str(built)], capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode != 0:
            raise SecureCompileError("C# COMPILER FAILED:\n" + (proc.stderr or proc.stdout))
        return _finish(source_gate, built, output_path, scanner=scanner_impl, reputation_provider=reputation_provider, policy=policy, language="C#", compiler="Managed C# via Chromaplex Gate 0.4", expected_format="PE", capabilities=("managed:clr", "filesystem:workspace"), capability_manifest=caps, target=caps.target)


def secure_build_wasm(wat_source: str, output_path: Path, *, scanner: MalwareScanner | None = None, reputation_provider: HashReputationProvider | None = None, policy: SecureCompilePolicy | None = None, capability_manifest: CapabilityManifest | None = None, timeout: int = 60) -> SecureBuildResult:
    policy = policy or SecureCompilePolicy()
    if capability_manifest is None:
        raise SecureCompileError("CAPABILITY GATE FAILED: explicit capability manifest is required")
    caps = capability_manifest; caps.validate()
    scanner_impl = _scanner_or_default(scanner)
    source_gate = preflight_sources({"module.wat": wat_source}, language="WebAssembly (WAT)", target=caps.target, capability_manifest=caps, scanner=scanner_impl, policy=policy)
    _enforce_capability_findings(source_gate, caps)
    wat2wasm = shutil.which("wat2wasm")
    if not wat2wasm:
        raise SecureCompileError("SECURITY GATE FAILED: wat2wasm (WABT) is unavailable")
    output_path = Path(output_path).resolve()
    with tempfile.TemporaryDirectory(prefix="chromaplex_wasm_quarantine_") as td:
        root = Path(td); os.chmod(root, 0o700)
        src = root / "module.wat"; built = root / output_path.name
        src.write_text(wat_source, encoding="utf-8")
        proc = subprocess.run([wat2wasm, str(src), "-o", str(built)], capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode != 0:
            raise SecureCompileError("WASM COMPILER FAILED:\n" + (proc.stderr or proc.stdout))
        validator = shutil.which("wasm-validate")
        if validator:
            val = subprocess.run([validator, str(built)], capture_output=True, text=True, timeout=timeout, check=False)
            if val.returncode != 0:
                raise SecureCompileError("WASM VALIDATION FAILED:\n" + (val.stderr or val.stdout))
        return _finish(source_gate, built, output_path, scanner=scanner_impl, reputation_provider=reputation_provider, policy=policy, language="WebAssembly (WAT)", compiler="WABT + Chromaplex Gate 0.4", expected_format="WASM", capabilities=("wasm:linear-memory",), capability_manifest=caps, target=caps.target)



def _embedded_project_sources(project_dir: Path) -> dict[str, str]:
    root = Path(project_dir).resolve()
    files: dict[str, str] = {}
    for path in root.rglob("*"):
        if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            continue
        if any(part in {".git", ".pio", "build", "dist"} for part in path.relative_to(root).parts):
            continue
        try:
            files[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
    return files


def _find_embedded_artifact(root: Path) -> Path | None:
    candidates: list[Path] = []
    for pattern in ("**/firmware.bin", "**/*.bin", "**/*.hex", "**/firmware.elf", "**/*.elf"):
        candidates.extend(p for p in root.glob(pattern) if p.is_file() and p.stat().st_size > 0)
    if not candidates:
        return None
    # Prefer flashable raw images over ELF/debug artifacts.
    priority = {".bin": 0, ".hex": 1, ".elf": 2}
    candidates.sort(key=lambda p: (priority.get(p.suffix.lower(), 9), len(p.parts), str(p)))
    return candidates[0]


def secure_build_embedded_project(
    project_dir: Path,
    output_path: Path,
    *,
    scanner: MalwareScanner | None = None,
    reputation_provider: HashReputationProvider | None = None,
    policy: SecureCompilePolicy | None = None,
    capability_manifest: CapabilityManifest | None = None,
    timeout: int = 300,
) -> SecureBuildResult:
    """Build ESP32/Arduino firmware without treating new/unknown firmware as malicious.

    The selected target controls the memory policy. Low-level pointers/MMIO are
    reviewable for embedded targets, while classic unbounded buffer APIs remain
    blocked. The final firmware is still locally scanned and SHA-256 sealed.
    """
    policy = policy or SecureCompilePolicy(allow_reviewed_source=True)
    if capability_manifest is None:
        raise SecureCompileError("CAPABILITY GATE FAILED: explicit embedded capability manifest is required")
    caps = capability_manifest
    caps.validate()
    target_profile = get_target(caps.target, mode="linux")
    if not target_profile.is_embedded:
        raise SecureCompileError(f"EMBEDDED BUILD TARGET MISMATCH: {target_profile.key}")

    source_root = Path(project_dir).resolve()
    if not source_root.is_dir():
        raise SecureCompileError(f"EMBEDDED PROJECT MISSING: {source_root}")
    sources = _embedded_project_sources(source_root)
    if not sources:
        raise SecureCompileError("EMBEDDED PROJECT HAS NO TEXT SOURCE FILES")
    scanner_impl = _scanner_or_default(scanner)
    source_gate = preflight_sources(
        sources,
        language="C/C++ (Embedded)",
        target=target_profile,
        capability_manifest=caps,
        scanner=scanner_impl,
        policy=policy,
    )
    _enforce_capability_findings(source_gate, caps)

    output_path = Path(output_path).resolve()
    with tempfile.TemporaryDirectory(prefix="chromaplex_embedded_quarantine_") as td:
        quarantine = Path(td)
        os.chmod(quarantine, 0o700)
        qproject = quarantine / "project"
        shutil.copytree(source_root, qproject, ignore=shutil.ignore_patterns(".git", ".pio", "build", "dist", "__pycache__"))
        build_root = quarantine / "out"
        build_root.mkdir()

        compiler_identity = ""
        if (qproject / "platformio.ini").exists() and shutil.which("pio"):
            compiler = shutil.which("pio") or "pio"
            proc = subprocess.run(
                [compiler, "run", "-d", str(qproject)],
                capture_output=True, text=True, timeout=timeout, check=False,
                env={**os.environ, "PLATFORMIO_CORE_DIR": str(quarantine / ".platformio")},
            )
            compiler_identity = f"PlatformIO / {target_profile.name} via Chromaplex Gate 0.4"
        else:
            sketches = list(qproject.glob("*.ino")) + list(qproject.rglob("*.ino"))
            arduino = shutil.which("arduino-cli")
            if sketches and arduino and caps.board:
                sketch_dir = sketches[0].parent
                proc = subprocess.run(
                    [arduino, "compile", "--fqbn", caps.board, "--output-dir", str(build_root), str(sketch_dir)],
                    capture_output=True, text=True, timeout=timeout, check=False,
                )
                compiler_identity = f"Arduino CLI ({caps.board}) / {target_profile.name} via Chromaplex Gate 0.4"
            else:
                missing = []
                if not (qproject / "platformio.ini").exists():
                    missing.append("platformio.ini")
                if not shutil.which("pio"):
                    missing.append("PlatformIO (pio)")
                if not arduino:
                    missing.append("arduino-cli")
                if not caps.board:
                    missing.append("capability manifest board/FQBN")
                raise SecureCompileError(
                    "TARGET TOOLCHAIN UNAVAILABLE (not a security rejection): embedded source passed policy, "
                    "but no configured PlatformIO or Arduino CLI build path is available. Missing/needed: " + ", ".join(missing)
                )

        if proc.returncode != 0:
            raise SecureCompileError("EMBEDDED COMPILER FAILED:\n" + (proc.stderr or proc.stdout))
        artifact = _find_embedded_artifact(qproject) or _find_embedded_artifact(build_root)
        if artifact is None:
            raise SecureCompileError("EMBEDDED COMPILER PRODUCED NO RECOGNIZED FIRMWARE ARTIFACT")

        declared = tuple(f"hardware:{item}" for item in caps.allow_hardware)
        runtime_caps = tuple(sorted({
            "embedded:firmware",
            f"target:{target_profile.key}",
            *(declared),
            *(("network",) if caps.network else ()),
        }))
        expected = "ELF" if artifact.suffix.lower() == ".elf" else "EMBEDDED"
        expected_arch = "ESP32" if (target_profile.key == "esp32" and expected == "ELF") else None
        return _finish(
            source_gate,
            artifact,
            output_path,
            scanner=scanner_impl,
            reputation_provider=reputation_provider,
            policy=policy,
            language="Embedded C/C++",
            compiler=compiler_identity,
            expected_format=expected,
            expected_arch=expected_arch,
            embedded=True,
            capabilities=runtime_caps,
            capability_manifest=caps,
            target=target_profile.key,
        )

def verify_security_manifest(binary_path: Path, manifest_path: Path, *, source_files: Mapping[str, str] | None = None) -> tuple[bool, list[str]]:
    binary_path = Path(binary_path); manifest_path = Path(manifest_path); problems: list[str] = []
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, [f"invalid security manifest: {exc}"]
    if data.get("schema") not in {"chromaplex-secure-build-v1", SECURITY_MANIFEST_SCHEMA}:
        problems.append(f"unsupported schema: {data.get('schema')!r}")
    if not data.get("approved"):
        problems.append("manifest is not approved")
    expected = data.get("output", {}).get("sha256", "")
    if not binary_path.exists():
        problems.append(f"binary missing: {binary_path}")
    elif not expected or sha256_file(binary_path) != expected:
        problems.append("binary SHA-256 mismatch")
    if source_files is not None:
        expected_sources = data.get("source", {}).get("files", {})
        actual_sources = hash_text_files(source_files)
        for name in sorted(set(expected_sources) | set(actual_sources)):
            if expected_sources.get(name) != actual_sources.get(name):
                problems.append(f"source SHA-256 mismatch: {name}")
    return not problems, problems
