"""3D krystalsimulator til ChromaPlex.

Simulatoren er en softwaremodel. Den allokerer voxels sparsomt for at undgå
unødigt hukommelsesforbrug ved store størrelser og validerer input eksplicit.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple, Union

import numpy as np

from .utils import exponent_remainder_to_number, number_to_exponent_remainder

Coordinate = Union[int, str]


class Voxel:
    """En enkelt voxel i krystallen med multiple farvekanaler."""

    def __init__(self) -> None:
        self.channels: Dict[str, dict] = {}

    def write(self, color: str, exponent: int, rest: int = 0) -> None:
        self.channels[color] = {"exp": exponent, "rest": rest}

    def read(self, color: str) -> Tuple[int, int]:
        if color in self.channels:
            channel = self.channels[color]
            return (channel["exp"], channel["rest"])
        return (0, 0)


class _GridZProxy:
    def __init__(self, simulator: "CrystalSimulator", x: int, y: int) -> None:
        self._sim = simulator
        self._x = x
        self._y = y

    def __getitem__(self, z: int) -> Voxel:
        xi, yi, zi = self._sim._check_coords(self._x, self._y, z)
        return self._sim._voxel(xi, yi, zi)


class _GridYProxy:
    def __init__(self, simulator: "CrystalSimulator", x: int) -> None:
        self._sim = simulator
        self._x = x

    def __getitem__(self, y: int) -> _GridZProxy:
        return _GridZProxy(self._sim, self._x, y)


class _GridProxy:
    """Bagudkompatibel adgang: sim.grid[x][y][z]."""

    def __init__(self, simulator: "CrystalSimulator") -> None:
        self._sim = simulator

    def __getitem__(self, x: int) -> _GridYProxy:
        return _GridYProxy(self._sim, x)


class CrystalSimulator:
    """Simulator for en 3D-krystal med farvekodet, eksponentiel lagring."""

    VALID_COLORS = {"rød", "grøn", "blå", "violet", "uv"}
    MAX_SIZE = 10_000
    MAX_EXPONENT = 10_000
    MAX_REST = 10**200
    MAX_IMMEDIATE = 10**12

    def __init__(self, size: int = 100) -> None:
        if not isinstance(size, int):
            raise TypeError("size skal være et heltal")
        if size <= 0 or size > self.MAX_SIZE:
            raise ValueError(f"size skal være mellem 1 og {self.MAX_SIZE}")
        self.size = size
        self._grid: Dict[Tuple[int, int, int], Voxel] = {}
        self.grid = _GridProxy(self)
        self.registers: Dict[str, Tuple[int, int]] = {
            "rød": (0, 0),
            "grøn": (0, 0),
            "blå": (0, 0),
            "violet": (0, 0),
            "uv": (0, 0),
            "r": (0, 0),
            "b": (0, 0),
        }
        self.status: Dict[str, Any] = {"eq": False, "gt": False, "lt": False}
        self.output_buffer: List[int] = []
        self.input_buffer: List[int] = []
        self.pc: int = 0

    def _resolve_coord(self, coord: Coordinate) -> int:
        if isinstance(coord, int):
            return coord
        if not isinstance(coord, str):
            raise TypeError("Koordinater skal være heltal eller register-navne")
        reg = coord.lower()
        if reg not in self.registers:
            raise IndexError(f"Ukendt koordinat-register: {coord}")
        return exponent_remainder_to_number(*self.registers[reg])

    def _check_coords(self, x: Coordinate, y: Coordinate, z: Coordinate) -> Tuple[int, int, int]:
        xi, yi, zi = self._resolve_coord(x), self._resolve_coord(y), self._resolve_coord(z)
        if not (0 <= xi < self.size and 0 <= yi < self.size and 0 <= zi < self.size):
            raise IndexError(f"Koordinater ({xi},{yi},{zi}) udenfor krystal (0-{self.size - 1})")
        return xi, yi, zi

    def _check_color(self, color: str) -> str:
        if not isinstance(color, str):
            raise TypeError("Farvekanal skal være en tekststreng")
        color = color.lower()
        if color not in self.VALID_COLORS:
            raise ValueError(f"Ukendt farvekanal: {color}")
        return color

    def _check_register(self, reg: str) -> str:
        if not isinstance(reg, str):
            raise TypeError("Register skal være en tekststreng")
        reg = reg.lower()
        if reg not in self.registers:
            raise ValueError(f"Ukendt register: {reg}")
        return reg

    def _validate_pair(self, exponent: int, rest: int) -> Tuple[int, int]:
        if not isinstance(exponent, int) or not isinstance(rest, int):
            raise TypeError("Eksponent og rest skal være heltal")
        if exponent < 0 or rest < 0:
            raise ValueError("Eksponent og rest skal være ikke-negative")
        if exponent > self.MAX_EXPONENT:
            raise OverflowError(f"Eksponent må højst være {self.MAX_EXPONENT}")
        if rest > self.MAX_REST:
            raise OverflowError(f"Rest må højst være {self.MAX_REST}")
        # Validerer repræsentationen uden at tillade ubegrænset eksponentielt arbejde.
        exponent_remainder_to_number(exponent, rest)
        return exponent, rest

    def _voxel(self, x: int, y: int, z: int) -> Voxel:
        return self._grid.setdefault((x, y, z), Voxel())

    def write_voxel(
        self,
        x: Coordinate,
        y: Coordinate,
        z: Coordinate,
        color: str,
        exponent: int,
        rest: int = 0,
    ) -> None:
        xi, yi, zi = self._check_coords(x, y, z)
        color = self._check_color(color)
        exponent, rest = self._validate_pair(exponent, rest)
        self._voxel(xi, yi, zi).write(color, exponent, rest)

    def read_voxel(self, x: Coordinate, y: Coordinate, z: Coordinate, color: str) -> Tuple[int, int]:
        xi, yi, zi = self._check_coords(x, y, z)
        color = self._check_color(color)
        voxel = self._grid.get((xi, yi, zi))
        return voxel.read(color) if voxel else (0, 0)

    def pack(self, x: Coordinate, y: Coordinate, z: Coordinate, color_exp_pairs: List[Tuple[str, int]]) -> None:
        xi, yi, zi = self._check_coords(x, y, z)
        voxel = self._voxel(xi, yi, zi)
        for color, exp in color_exp_pairs:
            color = self._check_color(color)
            exp, _ = self._validate_pair(exp, 0)
            voxel.write(color, exp, 0)

    def unpack(self, x: Coordinate, y: Coordinate, z: Coordinate) -> Dict[str, Tuple[int, int]]:
        xi, yi, zi = self._check_coords(x, y, z)
        voxel = self._grid.get((xi, yi, zi))
        if not voxel:
            return {}
        return {color: voxel.read(color) for color in voxel.channels}

    def load_plane(
        self,
        z: Coordinate,
        x_range: Tuple[int, int],
        y_range: Tuple[int, int],
        colors: List[str],
    ) -> np.ndarray:
        zi = self._resolve_coord(z)
        x1, x2 = x_range
        y1, y2 = y_range
        self._check_coords(x1, y1, zi)
        self._check_coords(x2, y2, zi)
        if x2 < x1 or y2 < y1:
            raise ValueError("x_range/y_range skal være stigende")
        safe_colors = [self._check_color(color) for color in colors]
        data = np.zeros((len(safe_colors), x2 - x1 + 1, y2 - y1 + 1), dtype=np.float64)
        for ci, color in enumerate(safe_colors):
            for xi, x in enumerate(range(x1, x2 + 1)):
                for yi, y in enumerate(range(y1, y2 + 1)):
                    e, rest = self.read_voxel(x, y, zi, color)
                    data[ci, xi, yi] = float(exponent_remainder_to_number(e, rest))
        return data

    def _register_number(self, reg: str) -> int:
        reg = self._check_register(reg)
        return exponent_remainder_to_number(*self.registers[reg])

    def _store_number(self, reg: str, value: int) -> None:
        reg = self._check_register(reg)
        if not isinstance(value, int):
            raise TypeError("Registerværdi skal være et heltal")
        if value < 0:
            value = 0
        if value > self.MAX_IMMEDIATE:
            raise OverflowError(f"Registerværdi må højst være {self.MAX_IMMEDIATE}")
        self.registers[reg] = number_to_exponent_remainder(value)

    def _store_pair(self, reg: str, exponent: int, rest: int) -> None:
        reg = self._check_register(reg)
        self.registers[reg] = self._validate_pair(exponent, rest)

    def execute_instruction(self, instr: Dict) -> bool:
        op = instr["op"]

        if op == "halt":
            return False

        if op == "load_imm":
            self._store_number(instr["reg"], instr["value"])

        elif op == "load_pair":
            self._store_pair(instr["reg"], instr["exp"], instr["rest"])

        elif op == "add_imm":
            self._store_number(instr["dest"], self._register_number(instr["src"]) + instr["value"])

        elif op == "sub_imm":
            self._store_number(instr["dest"], self._register_number(instr["src"]) - instr["value"])

        elif op == "store_c":
            x, y, z = instr["coords"]
            e, rest = self.registers[instr.get("reg", "rød")]
            self.write_voxel(x, y, z, instr["color"], e, rest)

        elif op == "load_c":
            x, y, z = instr["coords"]
            self.registers[instr["reg"]] = self.read_voxel(x, y, z, instr["color"])

        elif op == "pack":
            x, y, z = instr["coords"]
            pairs = []
            for color in instr["colors"]:
                e, _ = self.registers.get(color, (0, 0))
                pairs.append((color, e))
            self.pack(x, y, z, pairs)

        elif op == "unpack":
            x, y, z = instr["coords"]
            channels = self.unpack(x, y, z)
            for reg, (_, value) in zip(instr["regs"], channels.items()):
                self.registers[reg] = value

        elif op == "cmp_imm":
            current = self._register_number(instr["reg"])
            val = instr["value"]
            self.status["eq"] = current == val
            self.status["gt"] = current > val
            self.status["lt"] = current < val

        elif op == "cmp_p":
            left = self._register_number(instr["reg1"])
            right = self._register_number(instr["reg2"])
            self.status["eq"] = left == right
            self.status["gt"] = left > right
            self.status["lt"] = left < right

        elif op == "jmp":
            target = instr["_target_addr"]
            if target < 0:
                raise RuntimeError("Ugyldigt jump target")
            self.pc = target
            return True

        elif op == "jmp_if":
            cond = instr["cond"]
            should_jump = {
                "EQ": self.status["eq"],
                "NE": not self.status["eq"],
                "GT": self.status["gt"],
                "LT": self.status["lt"],
                "GE": self.status["gt"] or self.status["eq"],
                "LE": self.status["lt"] or self.status["eq"],
            }.get(cond, False)
            if should_jump:
                target = instr["_target_addr"]
                if target < 0:
                    raise RuntimeError("Ugyldigt jump target")
                self.pc = target
                return True

        elif op == "out":
            self.output_buffer.append(self._register_number(instr["reg"]))

        elif op == "in":
            if self.input_buffer:
                self._store_number(instr["reg"], self.input_buffer.pop(0))

        elif op == "add_r":
            self._store_number(instr["dest"], self._register_number(instr["src1"]) + self._register_number(instr["src2"]))

        elif op == "sub_r":
            self._store_number(instr["dest"], self._register_number(instr["src1"]) - self._register_number(instr["src2"]))

        elif op == "mul_p":
            self._store_number(instr["dest"], self._register_number(instr["src1"]) * self._register_number(instr["src2"]))

        elif op == "div_p":
            divisor = self._register_number(instr["src2"])
            if divisor == 0:
                raise ZeroDivisionError("Division med nul")
            self._store_number(instr["dest"], self._register_number(instr["src1"]) // divisor)

        elif op == "pow_p":
            exponent = self._register_number(instr["src2"])
            if exponent > self.MAX_EXPONENT:
                raise OverflowError("Eksponent for stor")
            self._store_number(instr["dest"], self._register_number(instr["src1"]) ** exponent)

        elif op == "shift_color":
            self.registers[instr["dest"]] = self.registers[instr["src"]]

        elif op == "pow2_add":
            exponent = self._register_number(instr["dest_e"])
            rest = self._register_number(instr["src_rest"])
            self._store_number(
                instr["dest_e"],
                exponent_remainder_to_number(exponent, rest),
            )

        else:
            raise RuntimeError(f"Ukendt simulator-instruktion: {op}")

        self.pc += 1
        return True

    def execute_program(self, instructions: List[Dict]) -> List[int]:
        self.pc = 0
        self.output_buffer = []
        max_steps = max(10_000, len(instructions) * 1_000)
        steps = 0
        while self.pc < len(instructions):
            steps += 1
            if steps > max_steps:
                raise RuntimeError("Program stoppet: maksimum antal instruktionstrin overskredet")
            if not self.execute_instruction(instructions[self.pc]):
                break
        return self.output_buffer

    def reset(self) -> None:
        self.__init__(self.size)


def main_run_cpa() -> None:
    import argparse

    from chromaplex.cpa_assembler import assemble

    parser = argparse.ArgumentParser(description="Kør en CPA-fil i ChromaPlex-simulatoren")
    parser.add_argument("file", help="Sti til .cpa fil")
    args = parser.parse_args()

    with open(args.file, encoding="utf-8") as f:
        asm = f.read()
    instrs = assemble(asm)
    sim = CrystalSimulator()
    output = sim.execute_program(instrs)
    print("Output:", output)
