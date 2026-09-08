"""Specifikationer for ChromaPlex Assembly (CPA) instruktioner og konstanter."""

from enum import IntEnum

# Krystaldimensioner
DIM_X = 1024
DIM_Y = 1024
DIM_Z = 1024

# Bølgelængder i nanometer
WAVELENGTHS = {
    "UV": 350,
    "VIOLET": 405,
    "BLUE": 473,
    "GREEN": 532,
    "RED": 650,
}
WAVELENGTHS_REVERSE = {v: k for k, v in WAVELENGTHS.items()}
WAVELENGTH_LIST = list(WAVELENGTHS.values())
WAVELENGTH_INDEX = {wl: i for i, wl in enumerate(WAVELENGTH_LIST)}

# Farvekoder
COLOUR_NAMES = {
    "UV": 0,
    "VIOLET": 1,
    "BLUE": 2,
    "GREEN": 3,
    "RED": 4,
}
COLOUR_NAMES_REVERSE = {v: k for k, v in COLOUR_NAMES.items()}

# Opcodes
class Opcode(IntEnum):
    NOP = 0x00
    LOAD = 0x01
    STORE = 0x02
    MOV = 0x03
    ADD = 0x04
    SUB = 0x05
    MUL = 0x06
    DIV = 0x07
    ENCODE = 0x08
    DECODE = 0x09
    JMP = 0x0A
    JZ = 0x0B
    JNZ = 0x0C
    CALL = 0x0D
    RET = 0x0E
    SET_COLOR = 0x0F
    SET_POWER = 0x10
    POSITION = 0x11
    LASER_WRITE = 0x12
    LASER_READ = 0x13
    WAIT = 0x14
    HALT = 0xFF

NUM_REGISTERS = 8
MAX_RAW_VALUE = 2**32 - 1

def encode_value(value: int) -> int:
    """Kod et positivt heltal til 32-bit pakket format (exponent<<24 | remainder)."""
    if value < 0:
        raise ValueError("Kun ikke-negative tal kan kodes.")
    if value == 0:
        return 0
    e = value.bit_length() - 1
    remainder = value - (1 << e)
    packed = (e << 24) | (remainder & 0xFFFFFF)
    return packed

def decode_value(packed: int) -> int:
    """Afkod et 32-bit pakket tal tilbage til original værdi."""
    e = (packed >> 24) & 0xFF
    remainder = packed & 0xFFFFFF
    if e == 0 and remainder == 0:
        return 0
    return (1 << e) + remainder
