"""CPL (ChromaPlex Language) compiler.

Dette er en begrænset parser til demo-syntaks. Den accepterer kun de understøttede
konstruktioner eksplicit og ignorerer ikke ukendt kode lydløst.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .utils import exponent_remainder_to_number, number_to_exponent_remainder

_MAX_SOURCE_LENGTH = 1_000_000
_MAX_STRING_LENGTH = 4_096
_IDENT = r"[A-Za-z_ÆØÅæøå][\wÆØÅæøå]*"
_ALLOWED_COLORS = {"rød", "grøn", "blå", "violet", "uv"}
_COLOR_ALIASES = {
    "red": "rød",
    "green": "grøn",
    "blue": "blå",
    "violet": "violet",
    "uv": "uv",
    "rød": "rød",
    "grøn": "grøn",
    "blå": "blå",
}
_RUNTIME_REGISTERS = ("rød", "grøn", "blå", "violet", "uv", "r", "b")


@dataclass(frozen=True)
class _Symbol:
    kind: str
    value: int | str | dict[str, Any] | None
    register: str | None = None


def _allocate_register(symbols: dict[str, _Symbol], name: str, lineno: int) -> str:
    existing = symbols.get(name)
    if existing is not None and existing.register is not None:
        return existing.register
    used = {symbol.register for symbol in symbols.values() if symbol.register is not None}
    try:
        return next(register for register in _RUNTIME_REGISTERS if register not in used)
    except StopIteration as exc:
        raise SyntaxError(
            f"For mange samtidige runtime-variabler på linje {lineno}; "
            f"den nuværende CPA-model har {len(_RUNTIME_REGISTERS)} registre"
        ) from exc


def _parse_color(value: str, lineno: int) -> str:
    try:
        return _COLOR_ALIASES[value.lower()]
    except KeyError as exc:
        allowed = ", ".join(sorted(_COLOR_ALIASES))
        raise SyntaxError(
            f"Ukendt farve '{value}' på linje {lineno}; tilladt: {allowed}"
        ) from exc


def _runtime_register_for_token(
    symbols: dict[str, _Symbol],
    token: str,
    lineno: int,
    cpa_lines: list[str],
) -> str:
    """Find eller materialisér et register for en runtime-værdi."""
    token = token.strip()
    if token.isdigit():
        name = f"__literal_{lineno}_{len(symbols)}"
        value = _parse_int(token)
        register = _allocate_register(symbols, name, lineno)
        symbols[name] = _Symbol("literal", value, register)
        cpa_lines.append(f"LOAD.IMM {register}, {value}")
        return register

    symbol = symbols.get(token)
    if symbol is None:
        raise SyntaxError(f"Ukendt variabel '{token}' på linje {lineno}")
    if symbol.register is not None:
        return symbol.register
    if not isinstance(symbol.value, int):
        raise SyntaxError(f"Variablen '{token}' er ikke numerisk på linje {lineno}")

    register = _allocate_register(symbols, token, lineno)
    symbols[token] = _Symbol(symbol.kind, symbol.value, register)
    cpa_lines.append(f"LOAD.IMM {register}, {symbol.value}")
    return register


def _parse_int(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise SyntaxError(f"Forventede heltal, fik: {value}") from exc
    if parsed < 0:
        raise SyntaxError("Negative heltal understøttes ikke i denne demo-compiler")
    return parsed


def _string_to_number(value: str) -> int:
    """Konverter en tekst til et deterministisk heltal via UTF-8 bytes."""
    if len(value) > _MAX_STRING_LENGTH:
        raise ValueError("Streng er for lang")
    return int.from_bytes(value.encode("utf-8"), "big") if value else 0


def _demo_pixel_at(x: int, y: int) -> dict[str, int]:
    """Deterministisk demo-pixelgenerator til full_potential_demo."""
    return {
        "rød": (x * 23 + y * 17) % 256,
        "grøn": (x * 11 + y * 29 + 64) % 256,
        "blå": (x * 7 + y * 13 + 128) % 256,
    }


def _resolve_numeric(symbols: dict[str, _Symbol], token: str, lineno: int) -> int:
    token = token.strip()

    if token.isdigit():
        return _parse_int(token)

    pixel_match = re.fullmatch(rf"({_IDENT})\.(rød|grøn|blå)", token)
    if pixel_match:
        name, channel = pixel_match.groups()
        symbol = symbols.get(name)
        if symbol is None or not isinstance(symbol.value, dict):
            raise SyntaxError(f"Ukendt pixelvariabel '{name}' på linje {lineno}")
        try:
            return int(symbol.value[channel])
        except KeyError as exc:
            raise SyntaxError(f"Ukendt pixelkanal '{channel}' på linje {lineno}") from exc

    symbol = symbols.get(token)
    if symbol is None:
        raise SyntaxError(f"Ukendt variabel '{token}' på linje {lineno}")
    if not isinstance(symbol.value, int):
        raise SyntaxError(f"Variablen '{token}' er ikke numerisk på linje {lineno}")
    return symbol.value


def _eval_tal_expr(symbols: dict[str, _Symbol], expr: str, lineno: int) -> int:
    expr = expr.strip()

    match = re.fullmatch(rf"potens_til_tal\((.+?)\s*,\s*(.+?)\)", expr)
    if match:
        exponent = _resolve_numeric(symbols, match.group(1), lineno)
        rest = _resolve_numeric(symbols, match.group(2), lineno)
        return exponent_remainder_to_number(exponent, rest)

    match = re.fullmatch(rf"strengTilTal\(({_IDENT})\)", expr)
    if match:
        name = match.group(1)
        symbol = symbols.get(name)
        if symbol is None or not isinstance(symbol.value, str):
            raise SyntaxError(f"strengTilTal kræver en kendt streng på linje {lineno}")
        return _string_to_number(symbol.value)

    match = re.fullmatch(rf"({_IDENT}|\d+)\s*-\s*\(2\^({_IDENT}|\d+)\)", expr)
    if match:
        left = _resolve_numeric(symbols, match.group(1), lineno)
        exponent = _resolve_numeric(symbols, match.group(2), lineno)
        value = left - (2**exponent)
        if value < 0:
            raise SyntaxError(f"Udtryk giver negativ værdi på linje {lineno}")
        return value

    return _resolve_numeric(symbols, expr, lineno)


def _eval_potens_expr(symbols: dict[str, _Symbol], expr: str, lineno: int) -> int:
    expr = expr.strip()

    match = re.fullmatch(rf"findEksponent\(({_IDENT}|\d+)\)", expr)
    if match:
        value = _resolve_numeric(symbols, match.group(1), lineno)
        exponent, _ = number_to_exponent_remainder(value)
        return exponent

    return _resolve_numeric(symbols, expr, lineno)


def _eval_bound_expr(symbols: dict[str, _Symbol], expr: str, lineno: int) -> int:
    expr = expr.strip()
    match = re.fullmatch(rf"({_IDENT}|\d+)\s*-\s*(\d+)", expr)
    if match:
        left = _resolve_numeric(symbols, match.group(1), lineno)
        right = _parse_int(match.group(2))
        value = left - right
        if value < 0:
            raise SyntaxError(f"For-grænse giver negativ værdi på linje {lineno}")
        return value
    return _resolve_numeric(symbols, expr, lineno)


def _expand_compile_time_for_loops(cpl_code: str) -> str:
    """Udvid simple compile-time for-loops til gentagne linjer.

    Understøttet form:
        for x = 0 to BREDDE-1 {
            ...
        }

    Dette er bevidst en tidlig, sikker løsning til demoer med konstante grænser.
    """
    symbols: dict[str, _Symbol] = {}
    source_lines = cpl_code.splitlines()
    output: list[str] = []
    stack: list[dict[str, Any]] = []

    for lineno, raw_line in enumerate(source_lines, 1):
        line = raw_line.split("//", 1)[0].strip()

        const_match = re.fullmatch(rf"konstant\s+({_IDENT})\s*=\s*(.+?)\s*;?", line)
        if const_match and not stack:
            name, expr = const_match.groups()
            symbols[name] = _Symbol("konstant", _eval_tal_expr(symbols, expr, lineno))
            output.append(raw_line)
            continue

        for_match = re.fullmatch(rf"for\s+({_IDENT})\s*=\s*(\d+)\s+to\s+(.+?)\s*\{{", line)
        if for_match:
            name, start_text, end_expr = for_match.groups()
            stack.append({
                "name": name,
                "start": _parse_int(start_text),
                "end": _eval_bound_expr(symbols, end_expr, lineno),
                "body": [],
                "line": lineno,
            })
            continue

        if line == "}" and stack:
            frame = stack.pop()
            expanded: list[str] = []
            for value in range(frame["start"], frame["end"] + 1):
                for body_line in frame["body"]:
                    expanded.append(re.sub(rf"\b{re.escape(frame['name'])}\b", str(value), body_line))
            if stack:
                stack[-1]["body"].extend(expanded)
            else:
                output.extend(expanded)
            continue

        if stack:
            stack[-1]["body"].append(raw_line)
        else:
            output.append(raw_line)

    if stack:
        frame = stack[-1]
        raise SyntaxError(f"Uafsluttet for-loop startet på linje {frame['line']}")

    return "\n".join(output)


def compile_cpl(cpl_code: str) -> str:
    """Compile de dokumenterede CPL-lagerkonstruktioner til CPA assembler."""
    if not isinstance(cpl_code, str):
        raise TypeError("cpl_code skal være en tekststreng")
    if len(cpl_code) > _MAX_SOURCE_LENGTH:
        raise ValueError("CPL-kilde er for stor")

    cpl_code = _expand_compile_time_for_loops(cpl_code)

    cpa_lines = ["; === CPL → CPA kompilering ===", ""]
    symbols: dict[str, _Symbol] = {}
    current_coords: tuple[str, str, str] | None = None

    for lineno, raw_line in enumerate(cpl_code.splitlines(), 1):
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line == "}":
            current_coords = None
            continue

        # Kompakt lager-syntaks: var/store/load/print.
        match = re.fullmatch(rf"var\s+({_IDENT})\s*=\s*(.+?)\s*;?", line, re.IGNORECASE)
        if match:
            name, expr = match.groups()
            if name in symbols:
                raise SyntaxError(f"Variablen '{name}' er allerede defineret på linje {lineno}")
            value = _eval_tal_expr(symbols, expr, lineno)
            register = _allocate_register(symbols, name, lineno)
            symbols[name] = _Symbol("var", value, register)
            cpa_lines.append(f"LOAD.IMM {register}, {value}")
            continue

        match = re.fullmatch(
            rf"store\s+({_IDENT}|\d+)\s+at\s*"
            rf"\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)\s+"
            rf"(?:colour|color|farve)\s+([A-Za-z_ÆØÅæøå]+)\s*;?",
            line,
            re.IGNORECASE,
        )
        if match:
            source, x, y, z, color_name = match.groups()
            register = _runtime_register_for_token(symbols, source, lineno, cpa_lines)
            color = _parse_color(color_name, lineno)
            cpa_lines.append(f"STORE.C ({x},{y},{z}), {color}, {register}")
            continue

        match = re.fullmatch(
            rf"load\s+({_IDENT})\s+from\s*"
            rf"\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)\s+"
            rf"(?:colour|color|farve)\s+([A-Za-z_ÆØÅæøå]+)\s*;?",
            line,
            re.IGNORECASE,
        )
        if match:
            name, x, y, z, color_name = match.groups()
            register = _allocate_register(symbols, name, lineno)
            symbols[name] = _Symbol("runtime", None, register)
            color = _parse_color(color_name, lineno)
            cpa_lines.append(f"LOAD.C {register}, ({x},{y},{z}), {color}")
            continue

        match = re.fullmatch(rf"print\s+({_IDENT}|\d+)\s*;?", line, re.IGNORECASE)
        if match:
            register = _runtime_register_for_token(
                symbols, match.group(1), lineno, cpa_lines
            )
            cpa_lines.append(f"OUT {register}")
            continue

        match = re.fullmatch(rf"streng\s+({_IDENT})\s*=\s*\"([^\"]{{0,{_MAX_STRING_LENGTH}}})\"\s*;?", line)
        if match:
            name, value = match.groups()
            symbols[name] = _Symbol("streng", value)
            safe_value = value.replace("\\", "\\\\").replace('"', '\\"')
            cpa_lines.append(f"; streng {name} = \"{safe_value}\"")
            continue

        match = re.fullmatch(rf"konstant\s+({_IDENT})\s*=\s*(.+?)\s*;?", line)
        if match:
            name, expr = match.groups()
            value = _eval_tal_expr(symbols, expr, lineno)
            symbols[name] = _Symbol("konstant", value)
            cpa_lines.append(f"; konstant {name} = {value}")
            continue

        match = re.fullmatch(rf"tal\s+({_IDENT})\s*=\s*(.+?)\s*;?", line)
        if match:
            name, expr = match.groups()
            value = _eval_tal_expr(symbols, expr, lineno)
            symbols[name] = _Symbol("tal", value)
            cpa_lines.append(f"; tal {name} = {value}")
            continue

        match = re.fullmatch(rf"pixel\s+({_IDENT})\s*=\s*hent_pixel\((\d+)\s*,\s*(\d+)\)\s*;?", line)
        if match:
            name, x_text, y_text = match.groups()
            pixel = _demo_pixel_at(_parse_int(x_text), _parse_int(y_text))
            symbols[name] = _Symbol("pixel", pixel)
            cpa_lines.append(f"; pixel {name} = hent_pixel({x_text}, {y_text}) -> {pixel}")
            continue

        match = re.fullmatch(
            rf"potens\s+({_IDENT})\s*,\s*rest\s+({_IDENT})\s*=\s*komponent_til_potens\((.+?)\)\s*;?",
            line,
        )
        if match:
            exp_name, rest_name, expr = match.groups()
            value = _resolve_numeric(symbols, expr, lineno)
            exponent, rest = number_to_exponent_remainder(value)
            symbols[exp_name] = _Symbol("potens", exponent)
            symbols[rest_name] = _Symbol("rest", rest)
            cpa_lines.append(
                f"; komponent_til_potens {expr} -> {exp_name}={exponent}, {rest_name}={rest}"
            )
            continue

        match = re.fullmatch(rf"potens\s+({_IDENT})\s*=\s*(.+?)\s*;?", line)
        if match:
            name, expr = match.groups()
            value = _eval_potens_expr(symbols, expr, lineno)
            symbols[name] = _Symbol("potens", value)
            cpa_lines.append(f"; potens {name} = {value}")
            continue

        match = re.fullmatch(r"skriv_voxel\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)\s*\{?", line)
        if match:
            current_coords = match.groups()
            cpa_lines.append(f"; skriv voxel ({','.join(current_coords)})")
            continue

        match = re.fullmatch(
            rf"kanal\s+({_IDENT})\s*=\s*({_IDENT}|\d+)"
            rf"(?:\s*,\s*rest\s*=\s*({_IDENT}|\d+))?\s*;?",
            line,
        )
        if match:
            if current_coords is None:
                raise SyntaxError(f"kanal må kun bruges inde i skriv_voxel-blok på linje {lineno}")
            color, exponent_token, rest_token = match.groups()
            color = color.lower()
            if color not in _ALLOWED_COLORS:
                raise SyntaxError(f"Ukendt farvekanal '{color}' på linje {lineno}")

            exponent = _resolve_numeric(symbols, exponent_token, lineno)
            rest = _resolve_numeric(symbols, rest_token, lineno) if rest_token else 0
            coords = ",".join(current_coords)
            cpa_lines.append(f"LOAD.PAIR {color}, {exponent}, {rest}")
            cpa_lines.append(f"STORE.C ({coords}), {color}, {color}")
            continue

        match = re.fullmatch(rf"hologram\s*=\s*opret_hologram\((.+?)\s*,\s*(.+?)\)\s*;?", line)
        if match:
            width = _resolve_numeric(symbols, match.group(1), lineno)
            height = _resolve_numeric(symbols, match.group(2), lineno)
            symbols["hologram"] = _Symbol("hologram", {"bredde": width, "højde": height, "pixels": {}})
            cpa_lines.append(f"; hologram = opret_hologram({width}, {height})")
            continue

        match = re.fullmatch(
            rf"læs_voxel\((.+?)\s*,\s*(.+?)\s*,\s*(.+?)\)\s*->\s*"
            rf"kanal\s+rød:\s*({_IDENT})\s*,\s*({_IDENT})\s*;\s*"
            rf"kanal\s+grøn:\s*({_IDENT})\s*,\s*({_IDENT})\s*;\s*"
            rf"kanal\s+blå:\s*({_IDENT})\s*,\s*({_IDENT})\s*;?",
            line,
        )
        if match:
            x_expr, y_expr, z_expr, r_e, r_rest, g_e, g_rest, b_e, b_rest = match.groups()
            x = _resolve_numeric(symbols, x_expr, lineno)
            y = _resolve_numeric(symbols, y_expr, lineno)
            z = _resolve_numeric(symbols, z_expr, lineno)
            cpa_lines.append(f"LOAD.C rød, ({x},{y},{z}), rød")
            cpa_lines.append(f"LOAD.C grøn, ({x},{y},{z}), grøn")
            cpa_lines.append(f"LOAD.C blå, ({x},{y},{z}), blå")
            symbols[r_e] = _Symbol("potens", 0)
            symbols[r_rest] = _Symbol("rest", 0)
            symbols[g_e] = _Symbol("potens", 0)
            symbols[g_rest] = _Symbol("rest", 0)
            symbols[b_e] = _Symbol("potens", 0)
            symbols[b_rest] = _Symbol("rest", 0)
            cpa_lines.append(f"; læs_voxel ({x},{y},{z}) -> {r_e},{r_rest},{g_e},{g_rest},{b_e},{b_rest}")
            continue

        match = re.fullmatch(rf"({_IDENT})\s*=\s*potens_til_tal\((.+?)\s*,\s*(.+?)\)\s*;?", line)
        if match:
            name, exp_expr, rest_expr = match.groups()
            exponent = _resolve_numeric(symbols, exp_expr, lineno)
            rest = _resolve_numeric(symbols, rest_expr, lineno)
            value = exponent_remainder_to_number(exponent, rest)
            symbols[name] = _Symbol("tal", value)
            cpa_lines.append(f"; {name} = potens_til_tal({exponent}, {rest}) -> {value}")
            continue

        match = re.fullmatch(rf"hologram\.sæt_pixel\((.+?)\s*,\s*(.+?)\s*,\s*(.+?)\s*,\s*(.+?)\s*,\s*(.+?)\)\s*;?", line)
        if match:
            x_expr, y_expr, r_expr, g_expr, b_expr = match.groups()
            x = _resolve_numeric(symbols, x_expr, lineno)
            y = _resolve_numeric(symbols, y_expr, lineno)
            r = _resolve_numeric(symbols, r_expr, lineno)
            g = _resolve_numeric(symbols, g_expr, lineno)
            b = _resolve_numeric(symbols, b_expr, lineno)
            h = symbols.get("hologram")
            if h is not None and isinstance(h.value, dict):
                h.value.setdefault("pixels", {})[(x, y)] = (r, g, b)
            cpa_lines.append(f"; hologram.sæt_pixel({x}, {y}, {r}, {g}, {b})")
            continue

        match = re.fullmatch(r"vis_hologram\(hologram\)\s*;?", line)
        if match:
            cpa_lines.append("; vis_hologram(hologram)")
            continue

        if line.startswith(("for ",)):
            raise SyntaxError(
                f"Ikke-understøttet CPL på linje {lineno}: '{line}'. "
                "Denne compiler understøtter det dokumenterede CPL-subset."
            )

        raise SyntaxError(f"Ikke-understøttet CPL på linje {lineno}: {line}")

    if current_coords is not None:
        raise SyntaxError("Uafsluttet skriv_voxel-blok")

    cpa_lines.append("")
    cpa_lines.append("HALT")
    return "\n".join(cpa_lines)


def main_compile() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Compile en CPL-fil til CPA")
    parser.add_argument("file", help="Sti til .cpl fil")
    parser.add_argument("-o", "--output", help="Skriv CPA-koden til denne fil")
    args = parser.parse_args()

    with open(args.file, encoding="utf-8") as f:
        cpl = f.read()
    cpa = compile_cpl(cpl)
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(cpa)
            f.write("\n")
    else:
        print(cpa)


def main_run_cpl() -> None:
    """CLI: compile og kør en CPL-fil direkte i simulatoren."""
    import argparse

    from .cpa_assembler import assemble
    from .crystal_simulator import CrystalSimulator

    parser = argparse.ArgumentParser(description="Compile og kør en CPL-fil")
    parser.add_argument("file", help="Sti til .cpl fil")
    parser.add_argument("--size", type=int, default=100, help="Krystalstørrelse (standard: 100)")
    args = parser.parse_args()

    with open(args.file, encoding="utf-8") as f:
        cpl = f.read()
    simulator = CrystalSimulator(size=args.size)
    output = simulator.execute_program(assemble(compile_cpl(cpl)))
    print("Output:", output)


if __name__ == "__main__":
    main_compile()
