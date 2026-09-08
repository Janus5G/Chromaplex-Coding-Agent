from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .capabilities import CapabilityManifest, default_manifest


class SandboxUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class SandboxPolicy:
    capabilities: CapabilityManifest = default_manifest()
    max_processes: int = 64


def bubblewrap_path() -> str:
    path = shutil.which("bwrap")
    if not path:
        raise SandboxUnavailable(
            "Safe execution requires bubblewrap (bwrap). Execution is blocked because the sandbox is unavailable."
        )
    return path


def build_bwrap_command(project_dir: Path, command: list[str], policy: SandboxPolicy | None = None) -> list[str]:
    policy = policy or SandboxPolicy()
    caps = policy.capabilities
    caps.validate()
    root = Path(project_dir).resolve()
    if not root.is_dir():
        raise RuntimeError(f"Sandbox project directory does not exist: {root}")

    args = [
        bubblewrap_path(),
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--clearenv",
        "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
        "--setenv", "HOME", "/nonexistent" if caps.home_access == "none" else "/home-ro",
        "--setenv", "LANG", "C.UTF-8",
        "--setenv", "LC_ALL", "C.UTF-8",
        "--setenv", "TMPDIR", "/tmp",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--dir", "/nonexistent",
    ]
    if caps.workspace_write:
        args.extend(["--bind", str(root), "/workspace"])
    elif caps.workspace_read:
        args.extend(["--ro-bind", str(root), "/workspace"])
    else:
        args.extend(["--dir", "/workspace"])
    args.extend(["--chdir", "/workspace"])

    # Toolchain/runtime roots are immutable in the sandbox. /etc is not mounted
    # wholesale: only specific runtime data is exposed read-only.
    for host_path in ("/usr", "/usr/local", "/bin", "/sbin", "/lib", "/lib64"):
        if os.path.exists(host_path):
            args.extend(["--ro-bind", host_path, host_path])
    for host_path in ("/etc/ld.so.cache", "/etc/alternatives", "/etc/ssl/certs", "/etc/ca-certificates", "/etc/nsswitch.conf"):
        if os.path.exists(host_path):
            args.extend(["--ro-bind", host_path, host_path])

    if caps.home_access == "read-only":
        home = Path.home()
        if home.exists():
            args.extend(["--ro-bind", str(home), "/home-ro"])
    if caps.network:
        args.append("--share-net")
    # --unshare-all otherwise provides a private network namespace with no host
    # network interfaces. Device exposure is limited to bubblewrap's synthetic /dev.
    args.append("--")
    args.extend(command)
    return args


def run_sandboxed(project_dir: Path, command: list[str], timeout: int, policy: SandboxPolicy | None = None) -> subprocess.CompletedProcess[str]:
    wrapped = build_bwrap_command(project_dir, command, policy)
    return subprocess.run(
        wrapped,
        cwd=None,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
