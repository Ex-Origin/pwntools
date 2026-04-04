"""Minimal logging helpers."""

from __future__ import annotations

import sys

from .context import context


_LEVELS = {
    "debug": 10,
    "info": 20,
    "success": 20,
    "warning": 30,
    "error": 40,
}


class Logger:
    """Tiny logger with pwntools-like top-level helpers."""

    def _current_level(self) -> int:
        return _LEVELS.get(str(getattr(context, "log_level", "info")).lower(), 20)

    def _should_emit(self, level: str) -> bool:
        return _LEVELS[level] >= self._current_level()

    def _emit(self, level: str, prefix: str, message) -> None:
        if not self._should_emit(level):
            return
        stream = sys.stdout
        print(f"{prefix} {message}", file=stream, flush=True)

    def debug(self, message) -> None:
        self._emit("debug", "[DEBUG]", message)

    def info(self, message) -> None:
        self._emit("info", "[*]", message)

    def success(self, message) -> None:
        self._emit("success", "[+]", message)

    def warning(self, message) -> None:
        self._emit("warning", "[!]", message)

    warn = warning

    def error(self, message) -> None:
        self._emit("error", "[-]", message)


log = Logger()


def success(message) -> None:
    log.success(message)


def info(message) -> None:
    log.info(message)
