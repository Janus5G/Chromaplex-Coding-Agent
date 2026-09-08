from __future__ import annotations

from dataclasses import dataclass, field

from .targets import get_target, target_prompt


@dataclass(frozen=True)
class ModeConfig:
    key: str
    name: str
    languages: tuple[str, ...]
    default_language: str
    file_extensions: dict[str, str] = field(default_factory=dict)
    project_capable: bool = True
    preview_capable: bool = False
    execution_capable: bool = False


MODES: dict[str, ModeConfig] = {
    "linux": ModeConfig(
        key="linux",
        name="Linux",
        languages=("Bash", "C", "Python (Linux)", "Makefile", "Projekt (flere filer)"),
        default_language="Python (Linux)",
        file_extensions={
            "Bash": ".sh",
            "C": ".c",
            "Python (Linux)": ".py",
            "Makefile": "Makefile",
            "Projekt (flere filer)": ".zip",
        },
        project_capable=True,
        execution_capable=True,
    ),
    "windows": ModeConfig(
        key="windows",
        name="Windows",
        languages=("PowerShell", "C#", "Batch", "Python (Windows)", "Projekt (flere filer)"),
        default_language="PowerShell",
        file_extensions={
            "PowerShell": ".ps1",
            "C#": ".cs",
            "Batch": ".bat",
            "Python (Windows)": ".py",
            "Projekt (flere filer)": ".zip",
        },
        project_capable=True,
        execution_capable=True,
    ),
    "web": ModeConfig(
        key="web",
        name="Web",
        languages=("HTML/CSS", "JavaScript", "Python/Flask", "React", "WebAssembly (WAT)", "Projekt (flere filer)"),
        default_language="HTML/CSS",
        file_extensions={
            "HTML/CSS": ".html",
            "JavaScript": ".js",
            "Python/Flask": ".py",
            "React": ".jsx",
            "WebAssembly (WAT)": ".wat",
            "Projekt (flere filer)": ".zip",
        },
        project_capable=True,
        preview_capable=True,
        execution_capable=False,
    ),
    "chromaplex": ModeConfig(
        key="chromaplex",
        name="ChromaPlex",
        languages=("CPL", "CPA"),
        default_language="CPL",
        file_extensions={"CPL": ".cpl", "CPA": ".cpa"},
        project_capable=False,
        execution_capable=True,
    ),
}


def default_filename(mode: str, language: str) -> str:
    if language == "Makefile":
        return "Makefile"
    ext = MODES[mode].file_extensions.get(language, ".txt")
    names = {
        "Bash": "main",
        "C": "main",
        "Python (Linux)": "main",
        "PowerShell": "main",
        "C#": "Program",
        "Batch": "main",
        "Python (Windows)": "main",
        "HTML/CSS": "index",
        "JavaScript": "main",
        "Python/Flask": "app",
        "React": "App",
        "WebAssembly (WAT)": "module",
        "CPL": "main",
        "CPA": "main",
    }
    return names.get(language, "generated") + ext


def system_prompt(mode: str, language: str, target: str | None = None) -> str:
    project = "Projekt" in language
    if mode == "linux":
        base = (
            "You are an expert Linux application developer. Generate production-quality, inspectable source code. "
            "Treat memory safety as mandatory: do not emit raw pointers, manual memory allocation, unbounded string APIs, ctypes/cffi, executable packers, self-modifying code, or encrypted/obfuscated payloads. "
            "For C use fixed-size values/arrays and bounded standard APIs compatible with the Chromaplex Safe-C profile. "
            "Target a normal Linux desktop/server environment and avoid destructive commands unless explicitly requested. "
            f"The selected output is {language}."
        )
    elif mode == "windows":
        base = (
            "You are an expert Windows application developer. Generate production-quality, inspectable source code. "
            "Treat memory safety as mandatory: for C# do not use unsafe, stackalloc, fixed pointers, P/Invoke or unmanaged memory unless the user explicitly requests reviewed native interop. "
            "Never use executable packers, encrypted/obfuscated payloads or self-modifying code. "
            "The code may be generated on Linux, so do not claim it was executed on Windows unless a Windows-compatible runtime is available. "
            f"The selected output is {language}."
        )
    elif mode == "web":
        base = (
            "You are an expert web developer. Generate complete, professional, inspectable source code. "
            "Keep HTML/CSS/JavaScript as normal inspectable resources; do not hide them in encrypted blobs, giant encoded byte arrays or runtime unpackers. "
            "For WebAssembly (WAT), emit standards-conforming WAT with no host imports unless explicitly permitted by the capability manifest. "
            "For static web output, prefer self-contained files unless the user explicitly asks for external dependencies. "
            f"The selected output is {language}."
        )
    else:
        base = (
            "You are an expert in the ChromaPlex CPL/CPA toolchain. Generate only syntax supported by the documented ChromaPlex repositories. "
            "For CPL, the default compact syntax is: var name = value; store name at (x,y,z) colour CHANNEL; "
            "load name from (x,y,z) colour CHANNEL; print name; with RED/GREEN/BLUE/VIOLET/UV. "
            "The current specification dialect with Danish keywords such as streng, tal, potens, skriv_voxel and kanal is also supported when explicitly requested. "
            "For CPA, use only opcodes supported by the matching assembler. Do not invent instructions. "
            f"The selected output is {language}."
        )

    base += target_prompt(get_target(target, mode=mode))

    if project:
        return base + (
            " Return ONLY one valid JSON object, no Markdown fences, with this exact shape: "
            '{"files":{"relative/path.ext":"file content"},"main_file":"relative/path.ext","description":"short description"}. '
            "Use only safe relative paths."
        )
    return base + " Return only the source code, without Markdown fences or explanation."
