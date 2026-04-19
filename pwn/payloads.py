"""Helpers for payload generation."""

from __future__ import annotations

from .context import context
from .packing import p32, p64


def _de_bruijn(alphabet: bytes, n: int) -> bytes:
    k = len(alphabet)
    a = [0] * (k * n)
    sequence = bytearray()

    def db(t: int, p: int) -> None:
        if t > n:
            if n % p == 0:
                for index in a[1 : p + 1]:
                    sequence.append(alphabet[index])
            return

        a[t] = a[t - p]
        db(t + 1, p)

        for j in range(a[t - p] + 1, k):
            a[t] = j
            db(t + 1, t)

    db(1, 1)
    return bytes(sequence)


_CYCLIC_CHARSET = b"abcdefghijklmnopqrstuvwxyz"
_CYCLIC_SUBSEQUENCE_SIZE = 4
_CYCLIC_MAX_LENGTH = len(_CYCLIC_CHARSET) ** _CYCLIC_SUBSEQUENCE_SIZE
_CYCLIC_PATTERN = _de_bruijn(_CYCLIC_CHARSET, _CYCLIC_SUBSEQUENCE_SIZE)


def cyclic(length: int) -> bytes:
    length = int(length)
    if length < 0:
        raise ValueError("cyclic() length must be non-negative")
    if length == 0:
        return b""

    if length > _CYCLIC_MAX_LENGTH:
        raise ValueError(
            "cyclic() length exceeds the unique de Bruijn sequence size "
            f"for alphabet={len(_CYCLIC_CHARSET)} and n={_CYCLIC_SUBSEQUENCE_SIZE}"
        )

    return _CYCLIC_PATTERN[:length]


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
