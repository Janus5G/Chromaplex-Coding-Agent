"""
ChromaPlex OS - Krystalbaseret programmeringssprog
"""

from .crystal_simulator import CrystalSimulator, Voxel
from .cpa_assembler import assemble
from .cpl_compiler import compile_cpl
from .utils import (
    number_to_exponent_remainder,
    exponent_remainder_to_number,
    find_optimal_exponent,
    luminance_to_ascii,
)

__version__ = "1.0.1"
__all__ = [
    "CrystalSimulator",
    "Voxel",
    "assemble",
    "compile_cpl",
    "number_to_exponent_remainder",
    "exponent_remainder_to_number",
    "find_optimal_exponent",
    "luminance_to_ascii",
]
