from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TargetProfile:
    key: str
    name: str
    family: str  # desktop | web | embedded | linux-arm | chromaplex
    os_kind: str
    architecture: str
    memory_policy: str  # strict | managed | embedded | vm
    expected_format: str
    network_default: bool = False
    process_spawn_default: bool = False
    notes: str = ""

    @property
    def is_embedded(self) -> bool:
        return self.family == "embedded"

    @property
    def is_raspberry_pi(self) -> bool:
        return self.family == "linux-arm"

    @property
    def is_desktop(self) -> bool:
        return self.family == "desktop"


TARGETS: dict[str, TargetProfile] = {
    "linux-desktop": TargetProfile(
        "linux-desktop", "Linux Desktop", "desktop", "linux", "host", "strict", "ELF",
        notes="Strict native desktop policy; raw memory manipulation is not accepted by the official safe-C path.",
    ),
    "windows-desktop": TargetProfile(
        "windows-desktop", "Windows Desktop", "desktop", "windows", "x86_64", "managed", "PE",
        notes="Managed-by-default Windows policy; unsafe/native interop requires review.",
    ),
    "web-wasm": TargetProfile(
        "web-wasm", "Web / WebAssembly", "web", "browser", "wasm32", "managed", "WASM",
        notes="Browser/Wasm target with explicit host-import capabilities.",
    ),
    "esp32": TargetProfile(
        "esp32", "ESP32 / ESP32-S3", "embedded", "bare-metal/rtos", "esp32-family", "embedded", "EMBEDDED",
        notes="Embedded policy permits legitimate low-level C/C++ and MMIO when declared; dangerous buffer patterns remain blocked.",
    ),
    "arduino": TargetProfile(
        "arduino", "Arduino / MCU", "embedded", "bare-metal/rtos", "mcu", "embedded", "EMBEDDED",
        notes="Embedded policy permits board-support low-level access when declared in the hardware capability manifest.",
    ),
    "raspberry-pi": TargetProfile(
        "raspberry-pi", "Raspberry Pi Linux (ARM)", "linux-arm", "linux", "arm/aarch64", "strict", "ELF",
        notes="Linux ARM target; cross-compiled ELF, SHA-256 evidence and optional generated AppArmor deployment profile.",
    ),
    "chromaplex-vm": TargetProfile(
        "chromaplex-vm", "ChromaPlex VM", "chromaplex", "vm", "cpa-vm", "vm", "CHROMAPLEX",
        notes="CPL/CPA VM capabilities only; no host shell/filesystem/network opcodes are added by the official gate.",
    ),
}


MODE_TARGETS: dict[str, tuple[str, ...]] = {
    "linux": ("linux-desktop", "raspberry-pi", "esp32", "arduino"),
    "windows": ("windows-desktop",),
    "web": ("web-wasm",),
    "chromaplex": ("chromaplex-vm",),
}


def get_target(key: str | None, *, mode: str | None = None) -> TargetProfile:
    if key and key in TARGETS:
        profile = TARGETS[key]
    else:
        default_key = (MODE_TARGETS.get(mode or "", ()) or ("linux-desktop",))[0]
        profile = TARGETS[default_key]
    if mode and profile.key not in MODE_TARGETS.get(mode, (profile.key,)):
        raise ValueError(f"Target {profile.key!r} is not valid for mode {mode!r}")
    return profile


def targets_for_mode(mode: str) -> tuple[TargetProfile, ...]:
    return tuple(TARGETS[key] for key in MODE_TARGETS.get(mode, ()))


def target_prompt(profile: TargetProfile) -> str:
    if profile.key == "esp32":
        return (
            " Target hardware is ESP32/ESP32-S3. Low-level embedded constructs, volatile register access, GPIO, SPI, I2C, UART, "
            "interrupts and Wi-Fi are legitimate when required, but declare required hardware/network capabilities. Avoid unbounded "
            "copy/string operations and obvious allocation lifetime errors. Do not assume desktop filesystem/process APIs."
        )
    if profile.key == "arduino":
        return (
            " Target hardware is an Arduino-class microcontroller. Board-support register access, volatile pointers, interrupts, GPIO, "
            "SPI, I2C and UART may be legitimate and must be represented in the hardware capability manifest. Avoid desktop OS APIs, "
            "unbounded buffer operations and unexplained dynamic allocation."
        )
    if profile.key == "raspberry-pi":
        return (
            " Target is Raspberry Pi Linux on ARM. Generate normal inspectable Linux source suitable for ARM/aarch64 cross-compilation. "
            "Use ordinary Linux APIs and declare filesystem/network/process capabilities explicitly; do not treat it as bare metal."
        )
    if profile.key == "linux-desktop":
        return " Target is a general Linux desktop/server. Use the strict memory-safe native policy and explicit runtime capabilities."
    if profile.key == "windows-desktop":
        return " Target is a general Windows desktop. Prefer managed memory-safe APIs and explicit runtime capabilities."
    if profile.key == "web-wasm":
        return " Target is browser/WebAssembly. Keep host imports explicit and capability-limited."
    return " Target is the ChromaPlex CPL/CPA VM; use only documented VM capabilities."
