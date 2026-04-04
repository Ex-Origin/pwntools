"""Utility functions."""

import sys


def pause(message: str = "Press Enter to continue...") -> None:
    """Pause execution and wait for user input."""
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    try:
        sys.stdout.write(message)
        sys.stdout.flush()
        stream.readline()
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()
        raise
    except EOFError:
        sys.stdout.write("\n")
        sys.stdout.flush()
