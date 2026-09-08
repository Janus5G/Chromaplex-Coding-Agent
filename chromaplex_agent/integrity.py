from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

MANIFEST_SCHEMA = "chromaplex-integrity-v1"
MANIFEST_NAME = "chromaplex-integrity.json"
SHA256SUMS_NAME = "CHROMAPLEX-SHA256SUMS.txt"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def hash_text_files(files: Mapping[str, str]) -> dict[str, str]:
    return {name: sha256_text(files[name]) for name in sorted(files)}


@dataclass(frozen=True)
class IntegrityManifest:
    files: dict[str, str]
    algorithm: str = "SHA-256"
    schema: str = MANIFEST_SCHEMA
    created_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    @classmethod
    def from_text_files(cls, files: Mapping[str, str]) -> "IntegrityManifest":
        return cls(files=hash_text_files(files))

    def verify_text_files(self, files: Mapping[str, str]) -> tuple[bool, list[str]]:
        current = hash_text_files(files)
        problems: list[str] = []
        expected_names = set(self.files)
        current_names = set(current)
        for missing in sorted(expected_names - current_names):
            problems.append(f"missing: {missing}")
        for added in sorted(current_names - expected_names):
            problems.append(f"unexpected: {added}")
        for name in sorted(expected_names & current_names):
            if current[name] != self.files[name]:
                problems.append(f"hash mismatch: {name}")
        return not problems, problems

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "algorithm": self.algorithm,
            "created_utc": self.created_utc,
            "files": dict(self.files),
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    def sha256sums(self) -> str:
        return "".join(f"{digest}  {name}\n" for name, digest in sorted(self.files.items()))


def write_file_sidecar(path: Path) -> Path:
    path = Path(path)
    digest = sha256_file(path)
    sidecar = path.with_name(path.name + ".sha256")
    sidecar.write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return sidecar
