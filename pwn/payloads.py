"""Helpers for payload generation."""

from __future__ import annotations

from .context import context
from .packing import p32, p64


def cyclic(length: int) -> bytes:
    length = int(length)
    if length < 0:
        raise ValueError("cyclic() length must be non-negative")
    if length == 0:
        return b""

    charset = b"abcdefghijklmnopqrstuvwxyz"
    pattern = bytearray()

    for d in charset:
        for c in charset:
            for b in charset:
                for a in charset:
                    pattern.extend((a, b, c, d))
                    if len(pattern) >= length:
                        return bytes(pattern[:length])

    repeated = bytearray()
    while len(repeated) < length:
        repeated.extend(pattern)
    return bytes(repeated[:length])


def _pack_int(value: int) -> bytes:
    arch = str(getattr(context, "arch", "amd64")).lower()
    if arch == "x86":
        return p32(value)
    if arch == "amd64":
        return p64(value)
    raise ValueError(f"unsupported architecture for flat(): {arch}")


def _flatten_item(item) -> bytes:
    if isinstance(item, int):
        return _pack_int(item)
    if isinstance(item, (bytes, bytearray, memoryview)):
        return bytes(item)
    if isinstance(item, (list, tuple)):
        return b"".join(_flatten_item(value) for value in item)
    raise TypeError(f"unsupported item type for flat(): {type(item)!r}")


def flat(items) -> bytes:
    return _flatten_item(items)
