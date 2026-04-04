"""Execution context used by the compatibility layer."""


class Context:
    """Lightweight replacement for pwntools context."""

    DEFAULTS = {
        "arch": "amd64",
        "os": "linux",
        "log_level": "info",
    }

    def __init__(self) -> None:
        self.clear()

    def clear(self, **kwargs):
        for key, value in self.DEFAULTS.items():
            setattr(self, key, value)
        for key, value in kwargs.items():
            setattr(self, key, value)
        return self


context = Context()
