"""Little-endian packing helpers."""

from __future__ import annotations

import struct


def _mask(value: int, bits: int) -> int:
    return int(value) & ((1 << bits) - 1)


def p32(value: int) -> bytes:
    return struct.pack("<I", _mask(value, 32))


def p64(value: int) -> bytes:
    return struct.pack("<Q", _mask(value, 64))


def u32(data) -> int:
    raw = bytes(data)
    if len(raw) != 4:
        raise ValueError(f"u32() requires exactly 4 bytes, got {len(raw)}")
    return struct.unpack("<I", raw)[0]


def u64(data) -> int:
    raw = bytes(data)
    if len(raw) != 8:
        raise ValueError(f"u64() requires exactly 8 bytes, got {len(raw)}")
    return struct.unpack("<Q", raw)[0]
