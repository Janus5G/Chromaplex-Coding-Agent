from __future__ import annotations

import json
import re
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .integrity import IntegrityManifest, MANIFEST_NAME, SHA256SUMS_NAME
from .capabilities import ensure_manifest_file


def validate_relative_path(name: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Empty project path")
    cleaned = name.replace("\\", "/").strip()
    if "\x00" in cleaned or cleaned.startswith("/") or re.match(r"^[A-Za-z]:", cleaned):
        raise ValueError(f"Unsafe project path: {name}")
    cleaned = re.sub(r"/+", "/", cleaned)
    raw_parts = cleaned.split("/")
    if any(part in {"", ".", "..", "~"} for part in raw_parts):
        raise ValueError(f"Unsafe project path: {name}")
    path = PurePosixPath(cleaned)
    if path.is_absolute():
        raise ValueError(f"Unsafe project path: {name}")
    return str(path)


def parse_project_json(raw: str) -> tuple[dict[str, str], str, str]:
    text = raw.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL | re.IGNORECASE)
    if fenced:
        text = fenced.group(1)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("AI project response is not valid JSON")
        data = json.loads(text[start : end + 1])
    files_raw = data.get("files")
    if not isinstance(files_raw, dict) or not files_raw:
        raise ValueError("Project JSON must contain a non-empty 'files' object")
    files: dict[str, str] = {}
    for name, content in files_raw.items():
        safe = validate_relative_path(name)
        if not isinstance(content, str):
            raise ValueError(f"File content must be text: {safe}")
        files[safe] = content
    main = validate_relative_path(data.get("main_file") or next(iter(files)))
    if main not in files:
        main = next(iter(files))
    description = data.get("description") if isinstance(data.get("description"), str) else ""
    return files, main, description


@dataclass
class Workspace:
    files: dict[str, str] = field(default_factory=dict)
    main_file: str = ""
    description: str = ""
    target: str = "linux-desktop"
    selected_file: str = ""
    dirty: set[str] = field(default_factory=set)
    _runtime_dir: Path | None = None
    sealed_manifest: IntegrityManifest | None = None

    def clear(self) -> None:
        self.files.clear()
        self.main_file = ""
        self.description = ""
        self.target = "linux-desktop"
        self.selected_file = ""
        self.dirty.clear()
        self.cleanup_runtime_dir()
        self.sealed_manifest = None

    def load(self, files: dict[str, str], main_file: str, description: str = "", target: str = "linux-desktop") -> None:
        self.clear()
        self.files = {validate_relative_path(k): v for k, v in files.items()}
        self.target = target
        ensure_manifest_file(self.files, target)
        self.main_file = main_file if main_file in self.files else next(iter(self.files), "")
        self.selected_file = self.main_file
        self.description = description

    def set_content(self, filename: str, content: str) -> None:
        if filename not in self.files:
            raise KeyError(filename)
        if self.files[filename] != content:
            self.files[filename] = content
            self.dirty.add(filename)
            self.sealed_manifest = None

    def write_to(self, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        root = directory.resolve()
        for name, content in self.files.items():
            safe_name = validate_relative_path(name)
            target = directory / safe_name
            resolved = target.resolve(strict=False)
            if resolved != root and root not in resolved.parents:
                raise ValueError(f"Project path escapes workspace: {name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return directory


    def seal(self) -> IntegrityManifest:
        if not self.files:
            raise ValueError("Cannot seal an empty workspace")
        self.sealed_manifest = IntegrityManifest.from_text_files(self.files)
        return self.sealed_manifest

    def verify_seal(self) -> tuple[bool, list[str]]:
        if self.sealed_manifest is None:
            return False, ["workspace is not SHA-256 sealed"]
        return self.sealed_manifest.verify_text_files(self.files)

    def require_verified_seal(self) -> IntegrityManifest:
        ok, problems = self.verify_seal()
        if not ok:
            raise RuntimeError("SHA-256 integrity verification failed: " + "; ".join(problems))
        assert self.sealed_manifest is not None
        return self.sealed_manifest

    def write_integrity_files(self, directory: Path) -> tuple[Path, Path]:
        manifest = self.require_verified_seal()
        manifest_path = directory / MANIFEST_NAME
        sums_path = directory / SHA256SUMS_NAME
        manifest_path.write_text(manifest.to_json(), encoding="utf-8")
        sums_path.write_text(manifest.sha256sums(), encoding="utf-8")
        return manifest_path, sums_path

    def runtime_dir(self) -> Path:
        self.require_verified_seal()
        self.cleanup_runtime_dir()
        self._runtime_dir = Path(tempfile.mkdtemp(prefix="chromaplex_agent_"))
        return self.write_to(self._runtime_dir)

    def cleanup_runtime_dir(self) -> None:
        if self._runtime_dir and self._runtime_dir.exists():
            shutil.rmtree(self._runtime_dir, ignore_errors=True)
        self._runtime_dir = None

    def export_zip(self, output: Path) -> None:
        manifest = self.require_verified_seal()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, content in self.files.items():
                archive.writestr(validate_relative_path(name), content)
            archive.writestr(MANIFEST_NAME, manifest.to_json())
            archive.writestr(SHA256SUMS_NAME, manifest.sha256sums())
