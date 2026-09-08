"""Krystalsimulering - 3D array af voxels med værdier per bølgelængde."""

from typing import Dict

class CrystalStorage:
    def __init__(self, size_x=1024, size_y=1024, size_z=1024):
        self.size_x = size_x
        self.size_y = size_y
        self.size_z = size_z
        self.data: Dict[tuple, Dict[int, int]] = {}
        self.access_count = 0

    def write_voxel(self, x: int, y: int, z: int, colour_index: int, value: int):
        self._check_bounds(x, y, z)
        key = (x, y, z)
        if key not in self.data:
            self.data[key] = {}
        self.data[key][colour_index] = value
        self.access_count += 1

    def read_voxel(self, x: int, y: int, z: int, colour_index: int) -> int:
        self._check_bounds(x, y, z)
        key = (x, y, z)
        vox = self.data.get(key, {})
        return vox.get(colour_index, 0)

    def _check_bounds(self, x, y, z):
        if not (0 <= x < self.size_x and 0 <= y < self.size_y and 0 <= z < self.size_z):
            raise IndexError(f"Voxel ({x},{y},{z}) uden for område.")

    def stats(self):
        return f"Krystal: {len(self.data)} voxels skrevet, {self.access_count} adgange."
