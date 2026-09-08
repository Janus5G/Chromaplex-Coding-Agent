from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class SafetyLevel(str, Enum):
    SAFE = "SAFE"
    REVIEW = "REVIEW REQUIRED"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class SafetyFinding:
    level: SafetyLevel
    filename: str
    rule: str
    detail: str


@dataclass(frozen=True)
class SafetyReport:
    level: SafetyLevel
    findings: tuple[SafetyFinding, ...]

    @property
    def summary(self) -> str:
        if not self.findings:
            return "SAFE: no high-risk execution patterns detected."
        return "\n".join(
            f"[{item.level.value}] {item.filename}: {item.rule} — {item.detail}"
            for item in self.findings
        )


# Static policy is intentionally conservative. It is one layer of the Secure
# Compile Gate and is not presented as a complete malware classifier.
_BLOCK_RULES = (
    (r"\brm\s+-[^\n]*r[^\n]*f[^\n]*\s+/(?:\s|$|\*)", "destructive-root-delete", "recursive forced deletion targeting filesystem root"),
    (r"\bmkfs(?:\.|\s)", "filesystem-format", "filesystem formatting command"),
    (r"\bdd\b[^\n]*\bof=/dev/", "raw-device-write", "raw write to a block/device path"),
    (r"\b(?:shutdown|reboot|poweroff)\b", "host-power-control", "host shutdown/reboot command"),
    (r"\b(?:chmod\s+[0-7]*[4-7][0-7]{2,3}|setcap\s+)\b", "privilege-bit-change", "setuid/setgid/capability manipulation"),
    (r"\b(?:mimikatz|sekurlsa|lsass(?:\.exe)?)\b", "credential-dumping", "known credential-dumping/LSASS access indicator"),
    (r"\b(?:CreateRemoteThread|WriteProcessMemory|VirtualAllocEx)\b", "process-injection", "Windows remote-process injection primitive"),
    (r"/dev/tcp/|/dev/udp/", "shell-network-device", "shell pseudo-device network connection"),
    (r"\b(?:vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog|bcdedit\s+/set\s+\{default\}\s+recoveryenabled\s+no)\b", "recovery-destruction", "disables or removes recovery data"),
    (r"(?:^|[;&|\s])upx(?:\s|$)|--upx\b", "executable-packer", "runtime executable packers are forbidden by the official build policy"),
)

_REVIEW_RULES = (
    (r"\b(?:curl|wget)\b", "network-download", "downloads data from a network location"),
    (r"\b(?:nc|ncat|netcat|socat)\b", "network-socket-tool", "general-purpose socket/network utility"),
    (r"\b(?:sudo|su)\b", "privilege-escalation-request", "requests elevated privileges"),
    (r"\b(?:crontab|systemctl\s+enable|update-rc\.d|schtasks\b)\b", "persistence", "configures automatic/persistent execution"),
    (r"\b(?:eval|exec)\s*\(", "dynamic-code-execution", "executes dynamically constructed code"),
    (r"\b(?:subprocess\.|os\.system\s*\(|system\s*\(|popen\s*\(|CreateProcess(?:A|W)?\s*\()", "process-spawn", "spawns host processes"),
    (r"\b(?:socket\.|socket\s*\(|connect\s*\(|requests\b|urllib\.request|httpx\b|WinHttp|WSAStartup)", "programmatic-network", "uses programmatic network access"),
    (r"\b(?:reg\s+add|Set-ItemProperty\b)", "registry-modification", "modifies Windows registry state"),
    (r"\b(?:keyring|secret-tool|CredentialManager|Get-Credential)\b", "credential-store-access", "accesses a credential/secret store"),
    (r"\b(?:ptrace|process_vm_writev|OpenProcess\s*\()", "process-introspection", "accesses another process"),
    (r"data:[^;]{1,80};base64,[A-Za-z0-9+/=]{4096,}", "embedded-high-entropy-resource", "large encoded resource should remain a normal inspectable asset"),
)


def scan_files(files: Mapping[str, str]) -> SafetyReport:
    findings: list[SafetyFinding] = []
    for filename, source in files.items():
        for pattern, rule, detail in _BLOCK_RULES:
            if re.search(pattern, source, flags=re.IGNORECASE | re.MULTILINE):
                findings.append(SafetyFinding(SafetyLevel.BLOCKED, filename, rule, detail))
        for pattern, rule, detail in _REVIEW_RULES:
            if re.search(pattern, source, flags=re.IGNORECASE | re.MULTILINE):
                findings.append(SafetyFinding(SafetyLevel.REVIEW, filename, rule, detail))
    if any(item.level == SafetyLevel.BLOCKED for item in findings):
        level = SafetyLevel.BLOCKED
    elif findings:
        level = SafetyLevel.REVIEW
    else:
        level = SafetyLevel.SAFE
    return SafetyReport(level, tuple(findings))
