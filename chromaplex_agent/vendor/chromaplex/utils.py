"""Fælles, tabsfri hjælpefunktioner til ChromaPlex-data."""

from __future__ import annotations

from numbers import Real


def _validate_base(base: int) -> int:
    if not isinstance(base, int) or isinstance(base, bool):
        raise TypeError("base skal være et heltal")
    if base < 2:
        raise ValueError("base skal være mindst 2")
    return base


def number_to_exponent_remainder(n: int, base: int = 2) -> tuple[int, int]:
    """Konverter et ikke-negativt heltal til den kanoniske CPL-repræsentation.

    For ``n < base`` bruges ``(0, n)``. Det gør nul og én entydige:
    ``(0, 0)`` er 0, og ``(0, 1)`` er 1. For større værdier findes den største
    eksponent ``e`` hvor ``base**e <= n``, hvorefter resten gemmes separat.
    """
    _validate_base(base)
    if not isinstance(n, int) or isinstance(n, bool):
        raise TypeError("n skal være et heltal")
    if n < 0:
        raise ValueError("Kan ikke konvertere negative tal")
    if n < base:
        return (0, n)

    if base == 2:
        exponent = n.bit_length() - 1
    else:
        exponent = 0
        power = 1
        while power * base <= n:
            power *= base
            exponent += 1
        return (exponent, n - power)

    return (exponent, n - (1 << exponent))


def exponent_remainder_to_number(e: int, rest: int, base: int = 2) -> int:
    """Rekonstruer et heltal fra den kanoniske eksponent/rest-repræsentation."""
    _validate_base(base)
    if not isinstance(e, int) or isinstance(e, bool):
        raise TypeError("e skal være et heltal")
    if not isinstance(rest, int) or isinstance(rest, bool):
        raise TypeError("rest skal være et heltal")
    if e < 0 or rest < 0:
        raise ValueError("e og rest skal være ikke-negative")
    if e == 0:
        if rest >= base:
            raise ValueError(f"Ved e=0 skal rest være mindre end base ({base})")
        return rest
    return base**e + rest


def find_optimal_exponent(value: int, max_exponent: int = 1000) -> int:
    """Find optimal eksponent for en given værdi."""
    if not isinstance(max_exponent, int) or isinstance(max_exponent, bool):
        raise TypeError("max_exponent skal være et heltal")
    if max_exponent < 0:
        raise ValueError("max_exponent skal være ikke-negativ")
    e, _ = number_to_exponent_remainder(value)
    return min(e, max_exponent)


def luminance_to_ascii(luminance: int | float) -> str:
    """Omsæt luminans 0-255 til den fælles ASCII-hologramskala."""
    if not isinstance(luminance, Real) or isinstance(luminance, bool):
        raise TypeError("luminance skal være et tal")
    if not 0 <= luminance <= 255:
        raise ValueError("luminance skal være mellem 0 og 255")
    if luminance >= 200:
        return "@"
    if luminance >= 150:
        return "#"
    if luminance >= 100:
        return "+"
    if luminance >= 50:
        return "."
    return " "
