"""Hardwareabstraktion for laser, SLM, kamera (simuleret)."""

class LaserControl:
    def __init__(self):
        self.wavelength = 532
        self.power = 50
        self.current_position = (0, 0, 0)

    def set_wavelength(self, wl_nm: int):
        self.wavelength = wl_nm

    def set_power(self, power: int):
        self.power = max(0, min(100, power))

    def move_to(self, x, y, z):
        self.current_position = (x, y, z)

    def write_pulse(self):
        pass

    def read_pulse(self):
        pass
