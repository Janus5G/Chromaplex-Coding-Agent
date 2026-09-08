"""CPA (ChromaPlex Assembly) assembler.

Assembleren returnerer en liste af instruktions-dicts til simulatoren.
Den udfører eksplicit validering, så ugyldig input fejler kontrolleret i stedet
for at blive ignoreret eller blive til delvist definerede instruktioner.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple, Union

Instruction = Dict[str, Union[str, int, tuple, list]]

REGISTERS = {"rød", "grøn", "blå", "violet", "uv", "r", "b"}
COLORS = {"rød", "grøn", "blå", "violet", "uv"}
VALID_CONDITIONS = {"EQ", "NE", "GT", "LT", "GE", "LE"}
SUPPORTED_OPCODES = frozenset({
    "LOAD.IMM",
    "LOAD.PAIR",
    "ADD.IMM",
    "SUB.IMM",
    "STORE.C",
    "LOAD.C",
    "PACK",
    "UNPACK",
    "MUL.P",
    "DIV.P",
    "POW.P",
    "ADD.R",
    "SUB.R",
    "CMP.IMM",
    "CMP.P",
    "JMP",
    "JMP.IF",
    "OUT",
    "IN",
    "HALT",
    "SHIFT.COLOR",
    "POW2.ADD",
})
MAX_INT_LITERAL = 10**12
MAX_REST_LITERAL = 10**200
MAX_EXPONENT = 10_000

_COORD_RE = re.compile(r"\(\s*([^,\s]+)\s*,\s*([^,\s]+)\s*,\s*([^,\s]+)\s*\)")
_LABEL_NAME_RE = re.compile(r"^[A-Za-z_ÆØÅæøå][\wÆØÅæøå]*$")


def _strip_comment(line: str) -> str:
    return line.split(";", 1)[0].strip()


def _split_operands(text: str) -> List[str]:
    """Split operandliste på kommaer uden at splitte inde i parenteser."""
    operands: List[str] = []
    current: List[str] = []
    depth = 0
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                raise SyntaxError("Ubalancerede parenteser")
        if char == "," and depth == 0:
            operand = "".join(current).strip()
            if not operand:
                raise SyntaxError("Tom operand")
            operands.append(operand)
            current = []
        else:
            current.append(char)
    if depth != 0:
        raise SyntaxError("Ubalancerede parenteser")
    operand = "".join(current).strip()
    if operand:
        operands.append(operand)
    return operands


def _split_label(line: str) -> Tuple[str | None, str]:
    """Returner eventuelt label og resten af linjen."""
    stripped = _strip_comment(line)
    if not stripped:
        return None, ""
    first = stripped.split(maxsplit=1)[0]
    if first.endswith(":"):
        label = first[:-1].strip()
        if not _LABEL_NAME_RE.fullmatch(label):
            raise SyntaxError(f"Ugyldigt labelnavn: {label}")
        rest = stripped[len(first):].strip()
        return label, rest
    return None, stripped


def _parse_line(line: str) -> Tuple[str, List[str]]:
    _, line = _split_label(line)
    if not line:
        return "", []
    parts = line.split(maxsplit=1)
    opcode = parts[0].upper()
    operands = _split_operands(parts[1]) if len(parts) > 1 else []
    return opcode, operands


def _parse_int(
    value: str,
    *,
    allow_register: bool = False,
    max_value: int = MAX_INT_LITERAL,
) -> Union[int, str]:
    value = value.strip()
    if allow_register and value.lower() in REGISTERS:
        return value.lower()
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise SyntaxError(f"Forventede heltal, fik: {value}") from exc
    if parsed < 0:
        raise SyntaxError("Negative værdier understøttes ikke i CPA-koordinater/immediates")
    if parsed > max_value:
        raise SyntaxError(f"Heltal er for stort: maks {max_value}")
    return parsed


def _parse_reg(value: str) -> str:
    reg = value.strip().lower()
    if reg not in REGISTERS:
        raise SyntaxError(f"Ukendt register: {value}")
    return reg


def _parse_color(value: str) -> str:
    color = value.strip().lower()
    if color not in COLORS:
        raise SyntaxError(f"Ukendt farvekanal: {value}")
    return color


def _parse_coords(value: str, *, allow_register: bool = False) -> Tuple[Union[int, str], Union[int, str], Union[int, str]]:
    match = _COORD_RE.fullmatch(value.strip())
    if not match:
        raise SyntaxError(f"Ugyldigt koordinatformat: {value}")
    return tuple(_parse_int(part, allow_register=allow_register) for part in match.groups())  # type: ignore[return-value]


def _collect_labels(lines: List[str]) -> Dict[str, int]:
    labels: Dict[str, int] = {}
    instruction_index = 0
    for raw in lines:
        label, rest = _split_label(raw)
        if label is not None:
            if label in labels:
                raise SyntaxError(f"Duplicate label: {label}")
            labels[label] = instruction_index
        if rest:
            instruction_index += 1
    return labels


def assemble(asm_code: str) -> List[Instruction]:
    """Assembler CPA-kode til en liste af instruktions-dicts."""
    if not isinstance(asm_code, str):
        raise TypeError("asm_code skal være en tekststreng")

    lines = asm_code.splitlines()
    labels = _collect_labels(lines)
    instructions: List[Instruction] = []

    for lineno, raw_line in enumerate(lines, 1):
        original_line = raw_line.strip()
        opcode, operands = _parse_line(raw_line)
        if not opcode:
            continue

        try:
            if opcode == "LOAD.IMM":
                if len(operands) != 2:
                    raise SyntaxError("LOAD.IMM kræver 2 operander")
                instructions.append({"op": "load_imm", "reg": _parse_reg(operands[0]), "value": _parse_int(operands[1])})

            elif opcode == "LOAD.PAIR":
                if len(operands) != 3:
                    raise SyntaxError("LOAD.PAIR kræver 3 operander")
                instructions.append({
                    "op": "load_pair",
                    "reg": _parse_reg(operands[0]),
                    "exp": _parse_int(operands[1], max_value=MAX_EXPONENT),
                    "rest": _parse_int(operands[2], max_value=MAX_REST_LITERAL),
                })

            elif opcode == "ADD.IMM":
                if len(operands) != 3:
                    raise SyntaxError("ADD.IMM kræver 3 operander")
                instructions.append({"op": "add_imm", "dest": _parse_reg(operands[0]), "src": _parse_reg(operands[1]), "value": _parse_int(operands[2])})

            elif opcode == "SUB.IMM":
                if len(operands) != 3:
                    raise SyntaxError("SUB.IMM kræver 3 operander")
                instructions.append({"op": "sub_imm", "dest": _parse_reg(operands[0]), "src": _parse_reg(operands[1]), "value": _parse_int(operands[2])})

            elif opcode == "STORE.C":
                if len(operands) != 3:
                    raise SyntaxError("STORE.C kræver 3 operander")
                instructions.append({"op": "store_c", "coords": _parse_coords(operands[0], allow_register=True), "color": _parse_color(operands[1]), "reg": _parse_reg(operands[2])})

            elif opcode == "LOAD.C":
                if len(operands) != 3:
                    raise SyntaxError("LOAD.C kræver 3 operander")
                instructions.append({"op": "load_c", "reg": _parse_reg(operands[0]), "coords": _parse_coords(operands[1], allow_register=True), "color": _parse_color(operands[2])})

            elif opcode == "PACK":
                if len(operands) < 2:
                    raise SyntaxError("PACK kræver koordinater og mindst én farve")
                instructions.append({"op": "pack", "coords": _parse_coords(operands[0]), "colors": [_parse_color(item) for item in operands[1:]]})

            elif opcode == "UNPACK":
                if len(operands) < 2:
                    raise SyntaxError("UNPACK kræver koordinater og mindst ét register")
                instructions.append({"op": "unpack", "coords": _parse_coords(operands[0]), "regs": [_parse_reg(item) for item in operands[1:]]})

            elif opcode in {"MUL.P", "DIV.P", "POW.P", "ADD.R", "SUB.R"}:
                if len(operands) != 3:
                    raise SyntaxError(f"{opcode} kræver 3 operander")
                op_map = {"MUL.P": "mul_p", "DIV.P": "div_p", "POW.P": "pow_p", "ADD.R": "add_r", "SUB.R": "sub_r"}
                instructions.append({"op": op_map[opcode], "dest": _parse_reg(operands[0]), "src1": _parse_reg(operands[1]), "src2": _parse_reg(operands[2])})

            elif opcode == "CMP.IMM":
                if len(operands) != 2:
                    raise SyntaxError("CMP.IMM kræver 2 operander")
                instructions.append({"op": "cmp_imm", "reg": _parse_reg(operands[0]), "value": _parse_int(operands[1])})

            elif opcode == "CMP.P":
                if len(operands) != 2:
                    raise SyntaxError("CMP.P kræver 2 operander")
                instructions.append({"op": "cmp_p", "reg1": _parse_reg(operands[0]), "reg2": _parse_reg(operands[1])})

            elif opcode == "JMP":
                if len(operands) != 1:
                    raise SyntaxError("JMP kræver 1 operand")
                instructions.append({"op": "jmp", "target": operands[0]})

            elif opcode == "JMP.IF":
                if len(operands) != 2:
                    raise SyntaxError("JMP.IF kræver 2 operander")
                cond = operands[0].upper()
                if cond not in VALID_CONDITIONS:
                    raise SyntaxError(f"Ukendt jump condition: {operands[0]}")
                instructions.append({"op": "jmp_if", "cond": cond, "target": operands[1]})

            elif opcode == "OUT":
                if len(operands) != 1:
                    raise SyntaxError("OUT kræver 1 operand")
                instructions.append({"op": "out", "reg": _parse_reg(operands[0])})

            elif opcode == "IN":
                if len(operands) != 1:
                    raise SyntaxError("IN kræver 1 operand")
                instructions.append({"op": "in", "reg": _parse_reg(operands[0])})

            elif opcode == "HALT":
                if operands:
                    raise SyntaxError("HALT tager ingen operander")
                instructions.append({"op": "halt"})

            elif opcode == "SHIFT.COLOR":
                if len(operands) != 2:
                    raise SyntaxError("SHIFT.COLOR kræver 2 operander")
                instructions.append({"op": "shift_color", "dest": _parse_reg(operands[0]), "src": _parse_reg(operands[1])})

            elif opcode == "POW2.ADD":
                if len(operands) != 2:
                    raise SyntaxError("POW2.ADD kræver 2 operander")
                instructions.append({"op": "pow2_add", "dest_e": _parse_reg(operands[0]), "src_rest": _parse_reg(operands[1])})

            else:
                raise SyntaxError(f"Ukendt CPA opcode: {opcode}")

        except (IndexError, ValueError, SyntaxError) as exc:
            raise SyntaxError(f"Fejl i CPA kode linje {lineno}: {original_line}\nFejl: {exc}") from exc

    for instr in instructions:
        if instr["op"] in ("jmp", "jmp_if"):
            target = str(instr["target"])
            if target not in labels:
                raise SyntaxError(f"Ukendt label: {target}")
            instr["_target_addr"] = labels[target]

    return instructions
