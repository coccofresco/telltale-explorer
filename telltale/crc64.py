"""
CRC64 ECMA-182 hashing as used by Telltale Games.

The lookup table is computed from the ECMA-182 polynomial 0x42F0E1EBA9EA3693.
Telltale uses CRC64 for Symbol name hashing, where input is lowercased before
hashing (see crc64_str).
"""

POLY = 0x42F0E1EBA9EA3693

# Build the 256-entry CRC64 lookup table from the polynomial.
_table = [0] * 256
for _i in range(256):
    _crc = _i << 56
    for _ in range(8):
        if _crc & (1 << 63):
            _crc = (_crc << 1) ^ POLY
        else:
            _crc <<= 1
        _crc &= 0xFFFFFFFFFFFFFFFF
    _table[_i] = _crc

TABLE = tuple(_table)
del _table, _i, _crc


def crc64(data: bytes, crc: int = 0) -> int:
    """Compute CRC64 ECMA-182 over raw bytes.

    Args:
        data: Input bytes to hash.
        crc: Initial CRC value (default 0).

    Returns:
        64-bit CRC value.
    """
    t = TABLE
    for byte in data:
        crc = t[((crc >> 56) ^ byte) & 0xFF] ^ (crc << 8)
        crc &= 0xFFFFFFFFFFFFFFFF
    return crc


def crc64_str(s: str, crc: int = 0) -> int:
    """Compute CRC64 ECMA-182 over a string, case-insensitive.

    Uppercase A-Z are lowered before hashing; all other characters are passed
    through unchanged. This matches Telltale's Symbol hashing behaviour.

    Args:
        s: Input string to hash.
        crc: Initial CRC value (default 0).

    Returns:
        64-bit CRC value.
    """
    return crc64(s.lower().encode("ascii"), crc)
