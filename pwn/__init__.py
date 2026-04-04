"""
Minimal pwntools-compatible interface for this repository.

Only the subset needed by the current testcase `exp.py` files is exported.
"""

from .context import context
from .log import info, log, success
from .packing import p32, p64, u32, u64
from .payloads import cyclic, flat
from .remote import remote
from .util import pause

__version__ = "0.1.0"

__all__ = [
    "context",
    "log",
    "remote",
    "p32",
    "p64",
    "u32",
    "u64",
    "cyclic",
    "flat",
    "success",
    "info",
    "pause",
]
