import io
import unittest
from unittest import mock

from pwn.util import pause


class _FakeStdin:
    def __init__(self, *events):
        self._events = list(events)
        self.buffer = self

    def readline(self):
        if not self._events:
            return b""
        event = self._events.pop(0)
        if isinstance(event, BaseException):
            raise event
        return event


class PauseTests(unittest.TestCase):
    def test_pause_reraises_keyboard_interrupt(self):
        fake_stdout = io.StringIO()
        with mock.patch("sys.stdin", new=_FakeStdin(KeyboardInterrupt())):
            with mock.patch("sys.stdout", fake_stdout):
                with self.assertRaises(KeyboardInterrupt):
                    pause("wait> ")

        self.assertEqual(fake_stdout.getvalue(), "wait> \n")

    def test_pause_swallows_eof_error(self):
        fake_stdout = io.StringIO()
        with mock.patch("sys.stdin", new=_FakeStdin(EOFError())):
            with mock.patch("sys.stdout", fake_stdout):
                pause("wait> ")

        self.assertEqual(fake_stdout.getvalue(), "wait> \n")

    def test_pause_uses_enter_prompt_and_reads_stdin_stream(self):
        fake_stdout = io.StringIO()
        with mock.patch("sys.stdin", new=_FakeStdin(b"\n")):
            with mock.patch("sys.stdout", fake_stdout):
                pause()

        self.assertEqual(fake_stdout.getvalue(), "Press Enter to continue...")


if __name__ == "__main__":
    unittest.main()
