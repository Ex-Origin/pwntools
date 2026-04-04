import io as text_io
import errno
import signal
import socket
import threading
import time
import unittest
from unittest import mock

from pwn.remote import RemoteConnection, remote


class _TcpServer:
    def __init__(self, handler):
        self._handler = handler
        self._server = socket.socket()
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(1)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._connection = None

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self._connection is not None:
                self._connection.close()
        finally:
            self._server.close()
            self._thread.join(timeout=1.0)

    def _serve(self):
        try:
            connection, _ = self._server.accept()
            self._connection = connection
            self._handler(connection)
        except OSError:
            pass
        finally:
            if self._connection is not None:
                try:
                    self._connection.close()
                except OSError:
                    pass


class _PipeStdin:
    def __init__(self, *chunks):
        self._chunks = list(chunks)
        self.buffer = self

    def isatty(self):
        return False

    def fileno(self):
        return 0

    def readline(self):
        if self._chunks:
            return self._chunks.pop(0)
        return b""


class RemoteConnectionTests(unittest.TestCase):
    def _make_mock_connection(self):
        connection = RemoteConnection.__new__(RemoteConnection)
        connection.host = "127.0.0.1"
        connection.port = 31337
        connection._closed = False
        connection._socket = mock.Mock()
        connection._buffer = bytearray()
        connection._interactive_input_buffer = bytearray()
        connection._interactive_input_eof = False
        connection._interactive_input_queue = None
        connection._interactive_input_thread = None
        connection._recv_lock = threading.Lock()
        connection._send_lock = threading.Lock()
        return connection

    def test_remote_connect_is_interruptible_by_sigint(self):
        fake_socket = mock.Mock()
        fake_socket.connect_ex.return_value = getattr(errno, "WSAEWOULDBLOCK", errno.EWOULDBLOCK)

        def fake_select(_read, _write, _error, timeout):
            time.sleep(timeout)
            return [], [], []

        with mock.patch("pwn.remote.socket.getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 31337))
        ]):
            with mock.patch("pwn.remote.socket.socket", return_value=fake_socket):
                with mock.patch("pwn.remote.select.select", side_effect=fake_select):
                    timer = threading.Timer(0.3, lambda: signal.raise_signal(signal.SIGINT))
                    timer.start()
                    try:
                        with self.assertRaises(KeyboardInterrupt):
                            remote("127.0.0.1", 31337)
                    finally:
                        timer.cancel()

        fake_socket.close.assert_called()

    def test_recvuntil_returns_data(self):
        def handler(connection):
            time.sleep(0.1)
            connection.sendall(b"hello!")

        with _TcpServer(handler) as server:
            io = remote("127.0.0.1", server.port)
            try:
                self.assertEqual(io.recvuntil(b"!"), b"hello!")
            finally:
                io.close()

    def test_recv_returns_requested_bytes(self):
        def handler(connection):
            time.sleep(0.1)
            connection.sendall(b"hello!")

        with _TcpServer(handler) as server:
            io = remote("127.0.0.1", server.port)
            try:
                self.assertEqual(io.recv(3), b"hel")
                self.assertEqual(io.recv(3), b"lo!")
            finally:
                io.close()

    def test_recv_timeout_returns_empty_bytes(self):
        def handler(connection):
            time.sleep(0.3)
            connection.sendall(b"late-data")

        with _TcpServer(handler) as server:
            io = remote("127.0.0.1", server.port)
            try:
                self.assertEqual(io.recv(timeout=0.05), b"")
                self.assertEqual(io.recv(timeout=1.0), b"late-data")
            finally:
                io.close()

    def test_recvn_returns_exact_length(self):
        def handler(connection):
            time.sleep(0.1)
            connection.sendall(b"abcdef")

        with _TcpServer(handler) as server:
            io = remote("127.0.0.1", server.port)
            try:
                self.assertEqual(io.recvn(4), b"abcd")
                self.assertEqual(io.recvn(2), b"ef")
            finally:
                io.close()

    def test_recvline_supports_drop(self):
        def handler(connection):
            time.sleep(0.1)
            connection.sendall(b"first\nsecond\n")

        with _TcpServer(handler) as server:
            io = remote("127.0.0.1", server.port)
            try:
                self.assertEqual(io.recvline(), b"first\n")
                self.assertEqual(io.recvline(drop=True), b"second")
            finally:
                io.close()

    def test_recvuntil_treats_connection_reset_as_eof(self):
        io = self._make_mock_connection()
        io._wait_for_socket_data = mock.Mock(return_value=True)
        io._socket.recv.side_effect = ConnectionResetError(
            getattr(errno, "WSAECONNRESET", 10054),
            "forcibly closed by remote host",
        )

        with self.assertRaises(EOFError):
            io.recvuntil(b"!")

    def test_recvuntil_treats_connection_aborted_as_eof(self):
        io = self._make_mock_connection()
        io._wait_for_socket_data = mock.Mock(return_value=True)
        io._socket.recv.side_effect = ConnectionAbortedError(
            getattr(errno, "WSAECONNABORTED", 10053),
            "software caused connection abort",
        )

        with self.assertRaises(EOFError):
            io.recvuntil(b"!")

    def test_send_treats_connection_reset_as_eof(self):
        io = self._make_mock_connection()
        io._wait_for_socket_writable = mock.Mock(return_value=True)
        io._socket.send.side_effect = ConnectionResetError(
            getattr(errno, "WSAECONNRESET", 10054),
            "forcibly closed by remote host",
        )

        with self.assertRaises(EOFError):
            io.send(b"payload")

    def test_send_treats_connection_aborted_as_eof(self):
        io = self._make_mock_connection()
        io._wait_for_socket_writable = mock.Mock(return_value=True)
        io._socket.send.side_effect = ConnectionAbortedError(
            getattr(errno, "WSAECONNABORTED", 10053),
            "software caused connection abort",
        )

        with self.assertRaises(EOFError):
            io.send(b"payload")

    def test_recvuntil_is_interruptible_by_sigint(self):
        def handler(connection):
            time.sleep(2.0)

        with _TcpServer(handler) as server:
            io = remote("127.0.0.1", server.port)
            timer = threading.Timer(0.3, lambda: signal.raise_signal(signal.SIGINT))
            started = time.monotonic()
            timer.start()
            try:
                with self.assertRaises(KeyboardInterrupt):
                    io.recvuntil(b"never-arrives")
            finally:
                timer.cancel()
                io.close()

        self.assertLess(time.monotonic() - started, 2.0)

    def test_sendafter_is_interruptible_by_sigint(self):
        def handler(connection):
            time.sleep(2.0)

        with _TcpServer(handler) as server:
            io = remote("127.0.0.1", server.port)
            timer = threading.Timer(0.3, lambda: signal.raise_signal(signal.SIGINT))
            timer.start()
            try:
                with self.assertRaises(KeyboardInterrupt):
                    io.sendafter(b"never-arrives", b"payload")
            finally:
                timer.cancel()
                io.close()

    def test_sendlineafter_is_interruptible_by_sigint(self):
        def handler(connection):
            time.sleep(2.0)

        with _TcpServer(handler) as server:
            io = remote("127.0.0.1", server.port)
            timer = threading.Timer(0.3, lambda: signal.raise_signal(signal.SIGINT))
            timer.start()
            try:
                with self.assertRaises(KeyboardInterrupt):
                    io.sendlineafter(b"never-arrives", b"payload")
            finally:
                timer.cancel()
                io.close()

    def test_interactive_exits_cleanly_on_keyboard_interrupt(self):
        def handler(connection):
            time.sleep(2.0)

        with _TcpServer(handler) as server:
            io = remote("127.0.0.1", server.port)
            with mock.patch.object(io, "_read_interactive_input", side_effect=KeyboardInterrupt):
                io.interactive()

            self.assertTrue(io._closed)

    def test_interactive_logs_eof_while_reading(self):
        io = self._make_mock_connection()
        io._recv_chunk = mock.Mock(side_effect=EOFError("remote connection closed while receiving data"))
        io._read_interactive_input = mock.Mock(return_value=None)

        with mock.patch("sys.stdout", new_callable=text_io.StringIO) as stdout:
            io.interactive()

        self.assertIn("[*] Got EOF while reading in interactive", stdout.getvalue())
        self.assertTrue(io._closed)

    def test_interactive_reads_from_windows_pipe_stdin(self):
        io = self._make_mock_connection()
        io.send = mock.Mock(return_value=len(b"whoami\n"))

        def fake_recv_chunk(stop_event=None):
            time.sleep(0.2)
            return None

        available_values = iter([7])

        def fake_windows_pipe_bytes_available():
            return next(available_values, 0)

        io._recv_chunk = mock.Mock(side_effect=fake_recv_chunk)

        with mock.patch("pwn.remote.sys.platform", "win32"):
            with mock.patch("sys.stdin", new=_PipeStdin(b"whoami\n", b"")):
                with mock.patch.object(io, "_windows_pipe_bytes_available", side_effect=fake_windows_pipe_bytes_available):
                    with mock.patch("pwn.remote.os.read", side_effect=[b"whoami\n", b""]):
                        with mock.patch("sys.stdout", new_callable=text_io.StringIO):
                            io.interactive()

        io.send.assert_called_once_with(b"whoami\n")
        self.assertTrue(io._closed)


if __name__ == "__main__":
    unittest.main()
