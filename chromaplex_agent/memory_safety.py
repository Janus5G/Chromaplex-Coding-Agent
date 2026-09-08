from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from .capabilities import CapabilityManifest
from .targets import TargetProfile, get_target


class MemorySafetyLevel(str, Enum):
    SAFE = "SAFE"
    REVIEW = "REVIEW REQUIRED"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class MemorySafetyFinding:
    level: MemorySafetyLevel
    filename: str
    rule: str
    detail: str


@dataclass(frozen=True)
class MemorySafetyReport:
    level: MemorySafetyLevel
    findings: tuple[MemorySafetyFinding, ...]

    @property
    def summary(self) -> str:
        if not self.findings:
            return "SAFE: no forbidden raw-memory constructs detected for the selected target."
        return "\n".join(
            f"[{item.level.value}] {item.filename}: {item.rule} — {item.detail}"
            for item in self.findings
        )


# These APIs remain blocked even for embedded targets because they are classic
# unbounded buffer-overflow primitives and have safer replacements.
_C_ALWAYS_BLOCK = (
    (r"\b(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\(", "unbounded-memory-api", "unbounded C string/memory API is forbidden"),
)

_C_STRICT_BLOCK = (
    (r"\b(?:malloc|calloc|realloc|free|alloca)\s*\(", "manual-memory-management", "manual heap/stack memory management is outside the strict desktop Safe-C profile"),
    (r"\b(?:memcpy|memmove|memset)\s*\(", "raw-memory-api", "raw byte-memory operation requires a reviewed or embedded target"),
    (r"\b(?:void|char|short|int|long|float|double|struct\s+\w+)\s*\*+\s*\w+", "raw-pointer-declaration", "raw pointer declarations are forbidden in the strict desktop Safe-C profile"),
    (r"\([^\n()]*\*+\s*\)\s*[^;\n]+", "pointer-cast", "pointer casts are forbidden in the strict desktop Safe-C profile"),
    (r"\b(?:uintptr_t|intptr_t)\b", "pointer-integer-conversion", "pointer/integer conversion types are forbidden in the strict desktop Safe-C profile"),
)

_C_REVIEW = (
    (r"\b(?:scanf|sscanf|fscanf)\s*\(", "formatted-input", "formatted input requires bounds review"),
    (r"\b(?:strncpy|strncat|snprintf)\s*\(", "bounded-c-string", "bounded C string operations require review"),
    (r"\bunion\b", "union-aliasing", "union-based type punning can create undefined-behaviour risks"),
)

_EMBEDDED_REVIEW = (
    (r"\b(?:memcpy|memmove|memset)\s*\(", "embedded-raw-memory", "raw byte operation is common in firmware but requires bounds review"),
    (r"\b(?:void|char|short|int|long|float|double|struct\s+\w+)\s*\*+\s*\w+", "embedded-pointer", "raw pointer is permitted for embedded targets but remains reviewable"),
    (r"\b(?:uintptr_t|intptr_t)\b", "embedded-pointer-integer", "pointer/integer conversion is permitted only for declared hardware/MMIO use"),
)

_CSHARP_BLOCK = (
    (r"\bunsafe\b", "csharp-unsafe", "C# unsafe blocks are forbidden"),
    (r"\bstackalloc\b", "csharp-stackalloc", "stackalloc exposes unmanaged memory"),
    (r"\bfixed\s*\(", "csharp-fixed", "fixed pointer blocks are forbidden"),
)

_CSHARP_REVIEW = (
    (r"\b(?:IntPtr|UIntPtr|Marshal\.|DllImport|LibraryImport)\b", "native-interop", "native interop can bypass managed memory safety"),
)

_MANAGED_ESCAPE_BLOCK = (
    (r"\b(?:ctypes|cffi)\b", "native-memory-escape", "native FFI bypasses managed memory safety"),
)

# Numeric memory-mapped I/O pointer casts, for example
# *(volatile uint32_t *)0x60004000. On embedded targets these must land in a
# range explicitly declared in the hardware capability manifest.
_MMIO_CAST = re.compile(
    r"(?:\(\s*(?:volatile\s+)?[^()\n;]*\*\s*\)\s*|\*\s*\(\s*(?:volatile\s+)?[^()\n;]*\*\s*\)\s*)(0x[0-9a-fA-F]+)",
    re.MULTILINE,
)


def _embedded_alloc_findings(filename: str, source: str) -> list[MemorySafetyFinding]:
    findings: list[MemorySafetyFinding] = []
    allocs = len(re.findall(r"\b(?:malloc|calloc|realloc)\s*\(", source, flags=re.IGNORECASE))
    frees = len(re.findall(r"\bfree\s*\(", source, flags=re.IGNORECASE))
    if allocs:
        if frees == 0:
            findings.append(MemorySafetyFinding(
                MemorySafetyLevel.REVIEW, filename, "embedded-allocation-lifetime",
                "dynamic allocation is used without an observable free(); review lifetime/fragmentation intentionally",
            ))
        else:
            findings.append(MemorySafetyFinding(
                MemorySafetyLevel.REVIEW, filename, "embedded-dynamic-allocation",
                "dynamic allocation is allowed for embedded targets but requires lifetime/fragmentation review",
            ))
    if re.search(r"\balloca\s*\(", source, flags=re.IGNORECASE):
        findings.append(MemorySafetyFinding(
            MemorySafetyLevel.REVIEW, filename, "embedded-alloca",
            "stack allocation size must be reviewed against the selected MCU task/stack budget",
        ))
    return findings


def _embedded_mmio_findings(filename: str, source: str, caps: CapabilityManifest | None) -> list[MemorySafetyFinding]:
    findings: list[MemorySafetyFinding] = []
    for match in _MMIO_CAST.finditer(source):
        address = int(match.group(1), 16)
        if caps is None or not any(window.contains(address) for window in caps.mmio_ranges):
            findings.append(MemorySafetyFinding(
                MemorySafetyLevel.BLOCKED,
                filename,
                "undeclared-mmio-address",
                f"numeric MMIO pointer {address:#x} is outside every declared hardware register range",
            ))
    return findings



def _embedded_hardware_findings(filename: str, source: str, caps: CapabilityManifest | None) -> list[MemorySafetyFinding]:
    findings: list[MemorySafetyFinding] = []
    declared = {item.upper() for item in (caps.allow_hardware if caps else ())}

    def require(rule: str, capability: str, detail: str) -> None:
        if capability.upper() not in declared:
            findings.append(MemorySafetyFinding(MemorySafetyLevel.BLOCKED, filename, rule, detail))

    # Pin-specific Arduino/ESP-IDF forms. A generic GPIO capability may be used
    # when the exact pin is selected dynamically at runtime.
    pins = set(re.findall(r"\bGPIO_NUM_(\d+)\b", source, flags=re.IGNORECASE))
    pins.update(re.findall(r"\b(?:pinMode|digitalWrite|digitalRead|analogRead|analogWrite)\s*\(\s*(\d+)", source))
    for pin in sorted(pins):
        if "GPIO" not in declared and f"GPIO_{pin}" not in declared:
            findings.append(MemorySafetyFinding(
                MemorySafetyLevel.BLOCKED, filename, f"hardware-gpio-{pin}",
                f"GPIO {pin} is used but neither GPIO nor GPIO_{pin} is declared in allow_hardware",
            ))

    if re.search(r"\b(?:WiFi|esp_wifi|wifi_init|WIFI_)\b", source, flags=re.IGNORECASE):
        if "WIFI" not in declared or not (caps and caps.network):
            findings.append(MemorySafetyFinding(
                MemorySafetyLevel.BLOCKED, filename, "hardware-wifi",
                "Wi-Fi use requires allow_hardware=[WIFI] and network=true",
            ))
    if re.search(r"\b(?:SPI\.|spi_bus|spi_device|SPIClass)\b", source, flags=re.IGNORECASE):
        require("hardware-spi", "SPI", "SPI use requires allow_hardware=[SPI]")
    if re.search(r"\b(?:Wire\.|i2c_|I2C)\b", source, flags=re.IGNORECASE):
        require("hardware-i2c", "I2C", "I2C use requires allow_hardware=[I2C]")
    if re.search(r"\b(?:Serial\.|uart_|UART)\b", source, flags=re.IGNORECASE):
        if "UART" not in declared and "SERIAL" not in declared:
            findings.append(MemorySafetyFinding(MemorySafetyLevel.BLOCKED, filename, "hardware-uart", "UART/Serial use requires allow_hardware=[UART] or [SERIAL]"))
    return findings

def scan_memory_safety(
    files: Mapping[str, str],
    language: str = "",
    *,
    target: str | TargetProfile | None = None,
    capability_manifest: CapabilityManifest | None = None,
) -> MemorySafetyReport:
    findings: list[MemorySafetyFinding] = []
    lang = (language or "").lower()
    profile = target if isinstance(target, TargetProfile) else get_target(target or (capability_manifest.target if capability_manifest else "linux-desktop"))

    for filename, source in files.items():
        lower_name = filename.lower()
        is_c_family = lang in {"c", "c++", "c/c++ (embedded)", "arduino sketch"} or lower_name.endswith((".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".ino"))
        if is_c_family:
            for pattern, rule, detail in _C_ALWAYS_BLOCK:
                if re.search(pattern, source, flags=re.IGNORECASE | re.MULTILINE):
                    findings.append(MemorySafetyFinding(MemorySafetyLevel.BLOCKED, filename, rule, detail))
            if profile.memory_policy == "embedded":
                findings.extend(_embedded_alloc_findings(filename, source))
                findings.extend(_embedded_mmio_findings(filename, source, capability_manifest))
                findings.extend(_embedded_hardware_findings(filename, source, capability_manifest))
                for pattern, rule, detail in _EMBEDDED_REVIEW:
                    if re.search(pattern, source, flags=re.IGNORECASE | re.MULTILINE):
                        findings.append(MemorySafetyFinding(MemorySafetyLevel.REVIEW, filename, rule, detail))
            else:
                for pattern, rule, detail in _C_STRICT_BLOCK:
                    if re.search(pattern, source, flags=re.IGNORECASE | re.MULTILINE):
                        findings.append(MemorySafetyFinding(MemorySafetyLevel.BLOCKED, filename, rule, detail))
            for pattern, rule, detail in _C_REVIEW:
                if re.search(pattern, source, flags=re.IGNORECASE | re.MULTILINE):
                    findings.append(MemorySafetyFinding(MemorySafetyLevel.REVIEW, filename, rule, detail))

        if lang == "c#" or lower_name.endswith(".cs"):
            for pattern, rule, detail in _CSHARP_BLOCK:
                if re.search(pattern, source, flags=re.IGNORECASE | re.MULTILINE):
                    findings.append(MemorySafetyFinding(MemorySafetyLevel.BLOCKED, filename, rule, detail))
            for pattern, rule, detail in _CSHARP_REVIEW:
                if re.search(pattern, source, flags=re.IGNORECASE | re.MULTILINE):
                    findings.append(MemorySafetyFinding(MemorySafetyLevel.REVIEW, filename, rule, detail))
        if lang.startswith("python") or lower_name.endswith(".py"):
            for pattern, rule, detail in _MANAGED_ESCAPE_BLOCK:
                if re.search(pattern, source, flags=re.IGNORECASE | re.MULTILINE):
                    findings.append(MemorySafetyFinding(MemorySafetyLevel.BLOCKED, filename, rule, detail))

    if any(f.level == MemorySafetyLevel.BLOCKED for f in findings):
        level = MemorySafetyLevel.BLOCKED
    elif findings:
        level = MemorySafetyLevel.REVIEW
    else:
        level = MemorySafetyLevel.SAFE
    return MemorySafetyReport(level, tuple(findings))


SAFE_C_HARDENING_FLAGS = (
    "-O2",
    "-Wall",
    "-Wextra",
    "-Wformat=2",
    "-Wformat-security",
    "-Werror=format-security",
    "-Werror=return-type",
    "-fstack-protector-strong",
    "-D_FORTIFY_SOURCE=3",
    "-fPIE",
    "-fno-strict-overflow",
    "-fno-delete-null-pointer-checks",
    "-Wl,-z,relro",
    "-Wl,-z,now",
    "-pie",
)

# Embedded builds cannot assume glibc/PIE/RELRO. Keep warnings and explicit
# overflow semantics, then let the board toolchain/platform provide its ABI flags.
EMBEDDED_C_SAFETY_FLAGS = (
    "-Wall",
    "-Wextra",
    "-Wformat=2",
    "-Wformat-security",
    "-Werror=return-type",
    "-fno-strict-overflow",
)
