from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BinaryValidationResult:
    format: str
    valid: bool
    entropy: float
    packed: bool
    findings: tuple[str, ...] = ()
    architecture: str = ""

    @property
    def requires_review(self) -> bool:
        return self.entropy >= 7.60 or any("high entropy" in x.lower() for x in self.findings)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def _detect_packer(data: bytes) -> bool:
    markers = (b"UPX!", b"UPX0", b"UPX1", b"UPX2", b"MPRESS1", b"MPRESS2", b"ASPack")
    return any(marker in data for marker in markers)


_ELF_MACHINES = {
    0x03: "X86",
    0x28: "ARM",
    0x3E: "X86_64",
    0x5E: "XTENSA",
    0xB7: "AARCH64",
    0xF3: "RISCV",
}

_PE_MACHINES = {
    0x014C: "X86",
    0x01C4: "ARM",
    0x8664: "X86_64",
    0xAA64: "AARCH64",
}


def _validate_elf(data: bytes) -> tuple[bool, list[str], str]:
    findings: list[str] = []
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return False, ["invalid ELF magic/header length"], ""
    elf_class = data[4]
    endian = data[5]
    if elf_class not in {1, 2}:
        findings.append("invalid ELF class")
    if endian not in {1, 2}:
        findings.append("invalid ELF endianness")
        return False, findings, ""
    if data[6] != 1:
        findings.append("unsupported ELF identification version")
    order = "<" if endian == 1 else ">"
    try:
        e_machine = struct.unpack_from(order + "H", data, 18)[0]
        if elf_class == 2:
            if len(data) < 64:
                return False, ["truncated ELF64 header"], _ELF_MACHINES.get(e_machine, f"EM_{e_machine}")
            e_ehsize = struct.unpack_from(order + "H", data, 52)[0]
            e_phoff = struct.unpack_from(order + "Q", data, 32)[0]
            e_shoff = struct.unpack_from(order + "Q", data, 40)[0]
            e_phentsize, e_phnum = struct.unpack_from(order + "HH", data, 54)
            e_shentsize, e_shnum = struct.unpack_from(order + "HH", data, 58)
        else:
            e_ehsize = struct.unpack_from(order + "H", data, 40)[0]
            e_phoff = struct.unpack_from(order + "I", data, 28)[0]
            e_shoff = struct.unpack_from(order + "I", data, 32)[0]
            e_phentsize, e_phnum = struct.unpack_from(order + "HH", data, 42)
            e_shentsize, e_shnum = struct.unpack_from(order + "HH", data, 46)
    except struct.error:
        return False, ["truncated ELF header"], ""
    minimum = 64 if elf_class == 2 else 52
    if e_ehsize < minimum:
        findings.append("ELF header size is too small")
    if e_phnum and (e_phoff + e_phentsize * e_phnum > len(data)):
        findings.append("ELF program header table exceeds file")
    if e_shnum and (e_shoff + e_shentsize * e_shnum > len(data)):
        findings.append("ELF section header table exceeds file")
    return not findings, findings, _ELF_MACHINES.get(e_machine, f"EM_{e_machine}")


def _validate_pe(data: bytes) -> tuple[bool, list[str], str]:
    findings: list[str] = []
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False, ["invalid DOS/PE preamble"], ""
    try:
        peoff = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return False, ["truncated DOS header"], ""
    if peoff < 0x40 or peoff + 24 > len(data) or data[peoff:peoff+4] != b"PE\0\0":
        return False, ["invalid PE signature/offset"], ""
    try:
        machine = struct.unpack_from("<H", data, peoff + 4)[0]
        sections = struct.unpack_from("<H", data, peoff + 6)[0]
        opt_size = struct.unpack_from("<H", data, peoff + 20)[0]
        magic = struct.unpack_from("<H", data, peoff + 24)[0]
    except struct.error:
        return False, ["truncated PE COFF header"], ""
    if not 1 <= sections <= 96:
        findings.append("invalid PE section count")
    if magic not in {0x10B, 0x20B, 0x107}:
        findings.append("unknown PE optional-header magic")
    section_table = peoff + 24 + opt_size
    if section_table + sections * 40 > len(data):
        findings.append("PE section table exceeds file")
    return not findings, findings, _PE_MACHINES.get(machine, f"MACHINE_{machine:#x}")


def _read_uleb(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(5):
        if offset >= len(data):
            raise ValueError("truncated ULEB128")
        b = data[offset]
        offset += 1
        value |= (b & 0x7F) << shift
        if b < 0x80:
            return value, offset
        shift += 7
    raise ValueError("oversized ULEB128")


def _validate_wasm(data: bytes) -> tuple[bool, list[str], str]:
    if len(data) < 8 or data[:4] != b"\x00asm" or data[4:8] != b"\x01\x00\x00\x00":
        return False, ["invalid WebAssembly magic/version"], "WASM32"
    findings: list[str] = []
    offset = 8
    last_noncustom = 0
    seen: set[int] = set()
    try:
        while offset < len(data):
            sec_id = data[offset]
            offset += 1
            size, offset = _read_uleb(data, offset)
            end = offset + size
            if end > len(data):
                findings.append("WebAssembly section exceeds file")
                break
            if sec_id != 0:
                if sec_id in seen:
                    findings.append(f"duplicate WebAssembly section id {sec_id}")
                if sec_id < last_noncustom:
                    findings.append("WebAssembly standard sections are out of order")
                seen.add(sec_id)
                last_noncustom = sec_id
            offset = end
    except ValueError as exc:
        findings.append(str(exc))
    return not findings, findings, "WASM32"


def _arch_matches(actual: str, expected: str | None) -> bool:
    if not expected:
        return True
    exp = expected.upper()
    actual = actual.upper()
    if exp in {"ARM", "ARM/AARCH64", "RASPBERRY-PI"}:
        return actual in {"ARM", "AARCH64"}
    if exp in {"ESP32", "ESP32-FAMILY"}:
        return actual in {"XTENSA", "RISCV"}
    return actual == exp


def validate_binary(path: Path, expected: str | None = None, *, expected_arch: str | None = None) -> BinaryValidationResult:
    data = Path(path).read_bytes()
    packed = _detect_packer(data)
    entropy = shannon_entropy(data)
    if expected:
        fmt = expected.upper()
    elif data.startswith(b"\x7fELF"):
        fmt = "ELF"
    elif data.startswith(b"MZ"):
        fmt = "PE"
    elif data.startswith(b"\x00asm"):
        fmt = "WASM"
    elif data.startswith((b"CHROMAPLEX", b"CPXB", b"CPA")):
        fmt = "CHROMAPLEX"
    else:
        fmt = "UNKNOWN"
    if fmt == "ELF":
        valid, findings, arch = _validate_elf(data)
    elif fmt == "PE":
        valid, findings, arch = _validate_pe(data)
    elif fmt == "WASM":
        valid, findings, arch = _validate_wasm(data)
    elif fmt == "CHROMAPLEX":
        valid, findings, arch = (len(data) > 0, [] if data else ["empty ChromaPlex output"], "CPX-VM")
    elif fmt in {"EMBEDDED", "FIRMWARE"}:
        valid, findings, arch = (len(data) > 0, [] if data else ["empty embedded firmware output"], "RAW-FIRMWARE")
    else:
        valid, findings, arch = False, ["unrecognized executable/bundle format"], ""
    if expected_arch and arch and not _arch_matches(arch, expected_arch):
        findings.append(f"binary architecture mismatch: expected {expected_arch}, got {arch}")
        valid = False
    if packed:
        findings.append("runtime packer/packed executable signature detected")
        valid = False
    if entropy >= 7.60:
        findings.append(f"high entropy executable ({entropy:.3f} bits/byte) requires review")
    return BinaryValidationResult(fmt, valid, entropy, packed, tuple(findings), arch)
