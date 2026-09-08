from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .targets import TARGETS, get_target

CAPABILITY_SCHEMA = "chromaplex-capabilities-v2"
LEGACY_CAPABILITY_SCHEMAS = {"chromaplex-capabilities-v1"}
CAPABILITY_FILENAME = "chromaplex-capabilities.json"
_HARDWARE_TOKEN = re.compile(r"^[A-Za-z0-9_.:+/-]{1,96}$")


@dataclass(frozen=True)
class MMIORange:
    start: int
    end: int
    name: str = "declared-mmio"

    def validate(self) -> None:
        if not (0 <= self.start <= self.end <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError(f"Invalid MMIO range: {self.start:#x}-{self.end:#x}")
        if self.end - self.start > 0x10000000:  # 256 MiB is already unusually broad for a peripheral window.
            raise ValueError("MMIO capability range is too broad; use a board-specific register window")
        if not _HARDWARE_TOKEN.match(self.name):
            raise ValueError(f"Invalid MMIO range name: {self.name!r}")

    def contains(self, address: int) -> bool:
        return self.start <= address <= self.end

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "start": hex(self.start), "end": hex(self.end)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MMIORange":
        def parse(v: Any) -> int:
            if isinstance(v, int):
                return v
            if isinstance(v, str):
                return int(v, 0)
            raise ValueError("MMIO start/end must be integers or 0x-prefixed strings")
        obj = cls(parse(data.get("start")), parse(data.get("end")), str(data.get("name") or "declared-mmio"))
        obj.validate()
        return obj


@dataclass(frozen=True)
class CapabilityManifest:
    target: str = "linux-desktop"
    network: bool = False
    workspace_read: bool = True
    workspace_write: bool = True
    home_access: str = "none"  # none | read-only
    system_write: bool = False
    process_spawn: bool = False
    devices: tuple[str, ...] = field(default_factory=tuple)
    clipboard: bool = False
    board: str = ""
    allow_hardware: tuple[str, ...] = field(default_factory=tuple)
    mmio_ranges: tuple[MMIORange, ...] = field(default_factory=tuple)
    schema: str = CAPABILITY_SCHEMA

    def validate(self) -> None:
        if self.schema not in {CAPABILITY_SCHEMA, *LEGACY_CAPABILITY_SCHEMAS}:
            raise ValueError(f"Unsupported capability schema: {self.schema}")
        profile = get_target(self.target)
        if self.home_access not in {"none", "read-only"}:
            raise ValueError("home_access must be 'none' or 'read-only'")
        if self.system_write:
            raise ValueError("system_write is forbidden by the official v0.4 runtime")
        allowed_devices = {"null", "zero", "random", "urandom"}
        unknown = set(self.devices) - allowed_devices
        if unknown:
            raise ValueError(f"Unsupported host device capabilities: {sorted(unknown)}")
        if self.board and (not _HARDWARE_TOKEN.match(self.board) or profile.family not in {"embedded", "linux-arm"}):
            raise ValueError(f"Invalid/unsupported board identifier for target {self.target}: {self.board!r}")
        for item in self.allow_hardware:
            if not isinstance(item, str) or not _HARDWARE_TOKEN.match(item):
                raise ValueError(f"Invalid hardware capability: {item!r}")
        for item in self.mmio_ranges:
            item.validate()
        if (self.allow_hardware or self.mmio_ranges) and profile.family not in {"embedded", "linux-arm"}:
            raise ValueError("hardware/MMIO capabilities are only valid for embedded or Raspberry Pi targets")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": CAPABILITY_SCHEMA,
            "target": self.target,
            "network": self.network,
            "filesystem": {
                "workspace": "read-write" if self.workspace_write else "read-only" if self.workspace_read else "none",
                "home": self.home_access,
                "system": "read-only",
            },
            "process_spawn": self.process_spawn,
            "devices": list(self.devices),
            "clipboard": self.clipboard,
            "board": self.board,
            "allow_hardware": list(self.allow_hardware),
            "mmio_ranges": [item.to_dict() for item in self.mmio_ranges],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CapabilityManifest":
        fs = data.get("filesystem") or {}
        workspace = fs.get("workspace", "read-write")
        target = str(data.get("target") or "linux-desktop")
        mmio = tuple(MMIORange.from_dict(item) for item in (data.get("mmio_ranges") or ()))
        obj = cls(
            schema=str(data.get("schema") or "chromaplex-capabilities-v1"),
            target=target,
            network=bool(data.get("network", False)),
            workspace_read=workspace in {"read-only", "read-write"},
            workspace_write=workspace == "read-write",
            home_access=fs.get("home", "none"),
            system_write=fs.get("system", "read-only") == "read-write",
            process_spawn=bool(data.get("process_spawn", False)),
            devices=tuple(data.get("devices") or ()),
            clipboard=bool(data.get("clipboard", False)),
            board=str(data.get("board") or ""),
            allow_hardware=tuple(data.get("allow_hardware") or ()),
            mmio_ranges=mmio,
        )
        obj.validate()
        return obj

    @classmethod
    def from_json(cls, text: str) -> "CapabilityManifest":
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("Capability manifest must be a JSON object")
        return cls.from_dict(data)

    def with_target(self, target: str) -> "CapabilityManifest":
        get_target(target)
        return CapabilityManifest(
            target=target,
            network=self.network,
            workspace_read=self.workspace_read,
            workspace_write=self.workspace_write,
            home_access=self.home_access,
            system_write=self.system_write,
            process_spawn=self.process_spawn,
            devices=self.devices,
            clipboard=self.clipboard,
            board=self.board if TARGETS[target].family in {"embedded", "linux-arm"} else "",
            allow_hardware=self.allow_hardware if TARGETS[target].family in {"embedded", "linux-arm"} else (),
            mmio_ranges=self.mmio_ranges if TARGETS[target].family in {"embedded", "linux-arm"} else (),
        )


def default_manifest(target: str = "linux-desktop") -> CapabilityManifest:
    profile = get_target(target)
    return CapabilityManifest(
        target=profile.key,
        network=profile.network_default,
        process_spawn=profile.process_spawn_default,
    )


def load_manifest(project_dir: Path, *, required: bool = True, expected_target: str | None = None) -> CapabilityManifest:
    path = Path(project_dir) / CAPABILITY_FILENAME
    if not path.exists():
        if required:
            raise RuntimeError(f"Missing mandatory capability manifest: {CAPABILITY_FILENAME}")
        manifest = default_manifest(expected_target or "linux-desktop")
    else:
        manifest = CapabilityManifest.from_json(path.read_text(encoding="utf-8"))
    if expected_target and manifest.target != expected_target:
        raise RuntimeError(f"Capability target mismatch: manifest={manifest.target}, selected={expected_target}")
    return manifest


def ensure_manifest_file(files: dict[str, str], target: str = "linux-desktop") -> dict[str, str]:
    if CAPABILITY_FILENAME not in files:
        files[CAPABILITY_FILENAME] = default_manifest(target).to_json()
    else:
        current = CapabilityManifest.from_json(files[CAPABILITY_FILENAME])
        if current.target != target:
            files[CAPABILITY_FILENAME] = current.with_target(target).to_json()
    return files
