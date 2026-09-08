"""Adapter around the vendored original ChromaPlex compiler/runtime code.

The compiler/runtime modules under chromaplex_agent/vendor are kept separate.
Compatibility and dialect routing live here, following the bridge architecture
from https://github.com/Janus5G/Cplex.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

VENDOR = Path(__file__).resolve().parents[1] / "vendor"
if str(VENDOR) not in sys.path:
    sys.path.insert(0, str(VENDOR))


@dataclass
class ChromaRunResult:
    dialect: str
    assembly: str
    output: str
    storage: dict[str, Any] = field(default_factory=dict)
    registers: Any = None


def normalise_simple_cpl(source: str) -> str:
    cleaned: list[str] = []
    for raw in source.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            cleaned.append(line)
            continue
        if stripped.endswith(";"):
            line = line[: line.rfind(";")]
        cleaned.append(line)
    return "\n".join(cleaned)


def detect_cpl_dialect(source: str) -> str:
    text = source.lower()
    markers = ["streng ", "skriv_voxel", "kanal ", "findeksponent", "strengtiltal", "potens ", "konstant ", "pixel "]
    return "danish-cpl" if any(marker in text for marker in markers) else "simple-cpl"


def compile_cpl(source: str, dialect: str | None = None) -> tuple[str, str]:
    dialect = dialect or detect_cpl_dialect(source)
    if dialect == "danish-cpl":
        from chromaplex.cpl_compiler import compile_cpl as current_compile
        return current_compile(source), dialect
    from chromaplex_os.compiler import CPLCompiler
    return CPLCompiler().compile(normalise_simple_cpl(source)), "simple-cpl"


def _parse_reg(token: str) -> int:
    match = re.fullmatch(r"R(\d+)", token.strip().upper())
    if not match:
        raise SyntaxError(f"Ugyldigt register: {token}")
    index = int(match.group(1))
    if not 0 <= index <= 7:
        raise SyntaxError(f"Register udenfor R0-R7: {token}")
    return index


def _value(token: str, registers: list[int]) -> int:
    token = token.strip()
    return registers[_parse_reg(token)] if token.upper().startswith("R") else int(token, 0)


def normalise_simple_cpa_for_assembler(assembly: str) -> str:
    """Normalize named colours for the original assembler's eager fallback.

    This belongs in the compatibility adapter; the vendored assembler remains
    byte-for-byte untouched.
    """
    from chromaplex_os.spec import COLOUR_NAMES

    def replace_colour(match):
        name = match.group(1).upper()
        return f"SET_COLOR {COLOUR_NAMES[name]}"

    return re.sub(
        r"(?mi)^\s*SET_COLOR\s+(UV|VIOLET|BLUE|GREEN|RED)\s*$",
        replace_colour,
        assembly,
    )


def run_simple_cpa(assembly: str) -> ChromaRunResult:
    from chromaplex_os.spec import COLOUR_NAMES
    from chromaplex_os.storage import CrystalStorage

    regs = [0] * 8
    storage = CrystalStorage()
    current_colour = COLOUR_NAMES["GREEN"]
    position = (0, 0, 0)
    out: list[str] = []
    for lineno, raw in enumerate(assembly.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        op, _, rest = line.partition(" ")
        op = op.upper()
        args = [item.strip() for item in rest.split(",") if item.strip()]
        if op == "HALT":
            break
        if op == "MOV":
            regs[_parse_reg(args[0])] = _value(args[1], regs)
        elif op == "ADD":
            regs[_parse_reg(args[0])] += _value(args[1], regs)
        elif op == "SUB":
            regs[_parse_reg(args[0])] -= _value(args[1], regs)
        elif op == "SET_COLOR":
            current_colour = COLOUR_NAMES[args[0].upper()]
        elif op == "POSITION":
            position = (int(args[0]), int(args[1]), int(args[2]))
        elif op == "LASER_WRITE":
            storage.write_voxel(*position, current_colour, regs[_parse_reg(args[0])])
        elif op == "LASER_READ":
            regs[_parse_reg(args[0])] = storage.read_voxel(*position, current_colour)
        elif op == "PRINT":
            out.append(str(regs[_parse_reg(args[0])]))
        else:
            raise SyntaxError(f"Ikke-understøttet legacy CPA-instruktion på linje {lineno}: {line}")
    dump = {
        f"{x},{y},{z}": {str(color): value for color, value in vox.items()}
        for (x, y, z), vox in storage.data.items()
    }
    output = "\n".join(out) if out else "Program kørte uden PRINT-output."
    output += "\nRegistre: " + repr(regs)
    output += "\nStorage: " + repr(dump)
    return ChromaRunResult("simple-cpa", assembly, output, dump, regs)


def run_current_cpa(assembly: str) -> ChromaRunResult:
    from chromaplex.cpa_assembler import assemble
    from chromaplex.crystal_simulator import CrystalSimulator

    instructions = assemble(assembly)
    simulator = CrystalSimulator()
    output_values = simulator.execute_program(instructions)
    grid: dict[str, Any] = {}
    for coords, voxel in getattr(simulator, "_grid", {}).items():
        grid[str(coords)] = {color: pair for color, pair in voxel.channels.items()}
    output = "Output: " + repr(output_values)
    output += "\nRegistre: " + repr(getattr(simulator, "registers", None))
    output += "\nStorage: " + repr(grid)
    return ChromaRunResult("current-cpa", assembly, output, grid, getattr(simulator, "registers", None))


def run_cpl(source: str) -> ChromaRunResult:
    assembly, dialect = compile_cpl(source)
    if dialect == "danish-cpl":
        result = run_current_cpa(assembly)
        result.dialect = dialect
        return result
    result = run_simple_cpa(assembly)
    result.dialect = dialect
    return result


def run_cpa(source: str) -> ChromaRunResult:
    if re.search(r"(?mi)^\s*(?:LOAD\.|STORE\.|OUT\b|IN\b|JMP\.IF\b|PACK\b|UNPACK\b)", source):
        return run_current_cpa(source)
    return run_simple_cpa(source)


def build_binary(source: str, language: str, output_path: Path) -> tuple[str, str]:
    if language == "CPL":
        assembly, dialect = compile_cpl(source)
    else:
        assembly = source
        dialect = "current-cpa" if re.search(r"(?mi)^\s*(?:LOAD\.|STORE\.|OUT\b|IN\b|JMP\.IF\b|PACK\b|UNPACK\b)", source) else "simple-cpa"

    if dialect in {"simple-cpl", "simple-cpa"}:
        from chromaplex_os.assembler import assemble
        assembly_for_binary = "\n".join(
            line for line in assembly.splitlines() if not line.strip().upper().startswith("PRINT")
        )
        output_path.write_bytes(assemble(normalise_simple_cpa_for_assembler(assembly_for_binary)))
        return str(output_path), assembly_for_binary

    from chromaplex.cpa_assembler import assemble
    instructions = assemble(assembly)
    bundle = {
        "format": "chromaplex-cpa-bundle",
        "version": 1,
        "dialect": dialect,
        "assembly": assembly,
        "instructions": instructions,
    }
    payload = b"CHROMAPLEX_CPA_BUNDLE_V1\n" + json.dumps(bundle, ensure_ascii=False, indent=2).encode("utf-8")
    output_path.write_bytes(payload)
    return str(output_path), assembly
