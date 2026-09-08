"""ChromaPlex Virtual Machine - udfører CPA bytecode mod simuleret krystallager."""

from .spec import (
    Opcode, NUM_REGISTERS, DIM_X, DIM_Y, DIM_Z, WAVELENGTH_LIST, COLOUR_NAMES_REVERSE,
    encode_value, decode_value
)
from .storage import CrystalStorage
from .hardware import LaserControl

class VirtualMachine:
    def __init__(self, storage=None):
        self.storage = storage if storage else CrystalStorage(DIM_X, DIM_Y, DIM_Z)
        self.laser = LaserControl()
        self.registers = [0] * NUM_REGISTERS
        self.pc = 0
        self.running = False
        self.program = b''
        self.call_stack = []
        self.current_colour = 2
        self.pos_x = 0
        self.pos_y = 0
        self.pos_z = 0

    def load_program(self, bytecode: bytes):
        self.program = bytecode
        self.pc = 0

    def run(self):
        self.running = True
        while self.running and self.pc < len(self.program):
            self.step()

    def step(self):
        if self.pc >= len(self.program):
            self.running = False
            return
        opcode_byte = self.program[self.pc]
        self.pc += 1
        try:
            opcode = Opcode(opcode_byte)
        except ValueError:
            raise RuntimeError(f"Ugyldig opcode {opcode_byte} ved PC={self.pc-1}")

        if opcode == Opcode.NOP:
            pass
        elif opcode == Opcode.HALT:
            self.running = False
        elif opcode == Opcode.LOAD:
            reg = self.program[self.pc]; self.pc += 1
            addr = int.from_bytes(self.program[self.pc:self.pc+4], 'big'); self.pc += 4
            x, y, z = self._linear_to_voxel(addr)
            value = self.storage.read_voxel(x, y, z, self.current_colour)
            self.registers[reg] = value
        elif opcode == Opcode.STORE:
            reg = self.program[self.pc]; self.pc += 1
            addr = int.from_bytes(self.program[self.pc:self.pc+4], 'big'); self.pc += 4
            x, y, z = self._linear_to_voxel(addr)
            value = self.registers[reg]
            self.storage.write_voxel(x, y, z, self.current_colour, value)
        elif opcode == Opcode.MOV:
            flag = self.program[self.pc]; self.pc += 1
            dst = self.program[self.pc]; self.pc += 1
            if flag == 0:
                src = self.program[self.pc]; self.pc += 1
                self.registers[dst] = self.registers[src]
            else:
                imm = int.from_bytes(self.program[self.pc:self.pc+4], 'big'); self.pc += 4
                self.registers[dst] = imm
        elif opcode == Opcode.ADD:
            dst = self.program[self.pc]; self.pc += 1
            src = self.program[self.pc]; self.pc += 1
            self.registers[dst] += self.registers[src]
        elif opcode == Opcode.SUB:
            dst = self.program[self.pc]; self.pc += 1
            src = self.program[self.pc]; self.pc += 1
            self.registers[dst] -= self.registers[src]
        elif opcode == Opcode.MUL:
            dst = self.program[self.pc]; self.pc += 1
            src = self.program[self.pc]; self.pc += 1
            self.registers[dst] *= self.registers[src]
        elif opcode == Opcode.DIV:
            dst = self.program[self.pc]; self.pc += 1
            src = self.program[self.pc]; self.pc += 1
            self.registers[dst] //= self.registers[src]
        elif opcode == Opcode.ENCODE:
            reg = self.program[self.pc]; self.pc += 1
            val = self.registers[reg]
            self.registers[reg] = encode_value(val)
        elif opcode == Opcode.DECODE:
            reg = self.program[self.pc]; self.pc += 1
            val = self.registers[reg]
            self.registers[reg] = decode_value(val)
        elif opcode == Opcode.JMP:
            addr = int.from_bytes(self.program[self.pc:self.pc+4], 'big'); self.pc += 4
            self.pc = addr
        elif opcode == Opcode.JZ:
            reg = self.program[self.pc]; self.pc += 1
            addr = int.from_bytes(self.program[self.pc:self.pc+4], 'big'); self.pc += 4
            if self.registers[reg] == 0:
                self.pc = addr
        elif opcode == Opcode.JNZ:
            reg = self.program[self.pc]; self.pc += 1
            addr = int.from_bytes(self.program[self.pc:self.pc+4], 'big'); self.pc += 4
            if self.registers[reg] != 0:
                self.pc = addr
        elif opcode == Opcode.CALL:
            addr = int.from_bytes(self.program[self.pc:self.pc+4], 'big'); self.pc += 4
            self.call_stack.append(self.pc)
            self.pc = addr
        elif opcode == Opcode.RET:
            if not self.call_stack:
                self.running = False
            else:
                self.pc = self.call_stack.pop()
        elif opcode == Opcode.SET_COLOR:
            idx = self.program[self.pc]; self.pc += 1
            self.current_colour = idx
            wl = WAVELENGTH_LIST[idx]
            self.laser.set_wavelength(wl)
        elif opcode == Opcode.SET_POWER:
            reg = self.program[self.pc]; self.pc += 1
            power = self.registers[reg]
            self.laser.set_power(power)
        elif opcode == Opcode.POSITION:
            x = int.from_bytes(self.program[self.pc:self.pc+2], 'big'); self.pc += 2
            y = int.from_bytes(self.program[self.pc:self.pc+2], 'big'); self.pc += 2
            z = int.from_bytes(self.program[self.pc:self.pc+2], 'big'); self.pc += 2
            self.pos_x = x
            self.pos_y = y
            self.pos_z = z
            self.laser.move_to(x, y, z)
        elif opcode == Opcode.LASER_WRITE:
            reg = self.program[self.pc]; self.pc += 1
            value = self.registers[reg]
            self.laser.write_pulse()
            self.storage.write_voxel(self.pos_x, self.pos_y, self.pos_z, self.current_colour, value)
        elif opcode == Opcode.LASER_READ:
            reg = self.program[self.pc]; self.pc += 1
            self.laser.read_pulse()
            value = self.storage.read_voxel(self.pos_x, self.pos_y, self.pos_z, self.current_colour)
            self.registers[reg] = value
        elif opcode == Opcode.WAIT:
            ms = int.from_bytes(self.program[self.pc:self.pc+2], 'big'); self.pc += 2

    def _linear_to_voxel(self, linear: int) -> tuple:
        z = linear // (DIM_X * DIM_Y)
        remainder = linear % (DIM_X * DIM_Y)
        y = remainder // DIM_X
        x = remainder % DIM_X
        return x, y, z

    def print_state(self):
        print(f"PC={self.pc}, registre: {self.registers}")
        print(f"Position: ({self.pos_x},{self.pos_y},{self.pos_z}), farve={COLOUR_NAMES_REVERSE[self.current_colour]}")
