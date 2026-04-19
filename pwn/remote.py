"""TCP remote connection helpers."""

from __future__ import annotations

import errno
import os
import queue
import select
import socket
import sys
import threading
import time
from typing import Optional

from .log import log


_SOCKET_POLL_INTERVAL = 0.1
_CONNECT_IN_PROGRESS_ERRNOS = {
    errno.EINPROGRESS,
    errno.EALREADY,
    errno.EWOULDBLOCK,
    getattr(errno, "WSAEINPROGRESS", errno.EINPROGRESS),
    getattr(errno, "WSAEALREADY", errno.EALREADY),
    getattr(errno, "WSAEWOULDBLOCK", errno.EWOULDBLOCK),
}
_CONNECT_SUCCESS_ERRNOS = {
    0,
    errno.EISCONN,
    getattr(errno, "WSAEISCONN", errno.EISCONN),
}
_RECV_EOF_ERRNOS = {
    errno.ECONNABORTED,
    errno.ECONNRESET,
    errno.ECONNREFUSED,
    getattr(errno, "WSAECONNABORTED", errno.ECONNABORTED),
    getattr(errno, "WSAECONNRESET", errno.ECONNRESET),
    getattr(errno, "WSAECONNREFUSED", errno.ECONNREFUSED),
}
_SEND_EOF_ERRNOS = _RECV_EOF_ERRNOS | {
    errno.EPIPE,
    getattr(errno, "WSAESHUTDOWN", errno.EPIPE),
}


def _normalize_socket_family(fam) -> int:
    if fam in (None, "any", "all", socket.AF_UNSPEC):
        return socket.AF_UNSPEC
    if fam in ("ipv4", "ip4", "inet", socket.AF_INET):
        return socket.AF_INET
    if fam in ("ipv6", "ip6", "inet6", socket.AF_INET6):
        return socket.AF_INET6
    raise ValueError(f"unsupported socket family: {fam!r}")


def _normalize_socket_type(typ) -> int:
    if typ in (None, "tcp", "stream", socket.SOCK_STREAM):
        return socket.SOCK_STREAM
    if typ in ("udp", "dgram", socket.SOCK_DGRAM):
        return socket.SOCK_DGRAM
    raise ValueError(f"unsupported socket type: {typ!r}")


def _set_tcp_nodelay(sock: Optional[socket.socket]) -> None:
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except (AttributeError, OSError):
        pass


def _coerce_bytes(data) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("utf-8")
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    raise TypeError(f"expected bytes-like object or str, got {type(data)!r}")


def _format_ascii(chunk: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)


def _hexdump_lines(data: bytes, width: int = 16):
    raw = bytes(data)
    for offset in range(0, len(raw), width):
        chunk = raw[offset : offset + width]
        hex_values = [f"{byte:02x}" for byte in chunk]
        left = " ".join(hex_values[:8])
        right = " ".join(hex_values[8:])
        if right:
            hex_part = f"{left:<23}  {right:<23}"
        else:
            hex_part = f"{left:<23}  {'':<23}"
        yield f"{offset:08x}  {hex_part}  |{_format_ascii(chunk)}|"


def _is_socket_eof_error(exc: OSError, *, sending: bool) -> bool:
    errnos = {
        getattr(exc, "errno", None),
        getattr(exc, "winerror", None),
    }
    expected = _SEND_EOF_ERRNOS if sending else _RECV_EOF_ERRNOS
    if errnos & expected:
        return True
    if sending and isinstance(exc, BrokenPipeError):
        return True
    return False


def _raise_for_socket_error(exc: OSError, *, sending: bool) -> None:
    if _is_socket_eof_error(exc, sending=sending):
        action = "sending" if sending else "receiving"
        raise EOFError(f"remote connection closed while {action} data") from exc
    raise exc


class RemoteConnection:
    """Small pwntools-like remote TCP wrapper."""

    def __init__(self, host: str, port: int, *args, **kwargs) -> None:
        timeout = kwargs.pop("timeout", None)
        self.host = host
        self.port = int(port)
        self._closed = False
        log.info(f"Opening connection to {self.host} on port {self.port}")
        self._initialize_socket_state(self._open_socket(timeout=timeout))
        log.success(f"Opening connection to {self.host} on port {self.port}: Done")

    def _initialize_socket_state(self, sock: Optional[socket.socket]) -> None:
        self._closed = False
        self._socket = sock
        _set_tcp_nodelay(sock)
        self._buffer = bytearray()
        self._interactive_input_buffer = bytearray()
        self._interactive_input_eof = False
        self._interactive_input_queue: Optional[queue.Queue[object]] = None
        self._interactive_input_thread: Optional[threading.Thread] = None
        self._recv_lock = threading.Lock()
        self._send_lock = threading.Lock()

    def _ensure_connected(self) -> None:
        return None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        sock = getattr(self, "_socket", None)
        try:
            if sock is not None:
                sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        if sock is not None:
            sock.close()
        log.info(f"Closed connection to {self.host} port {self.port}")

    def send(self, data) -> int:
        self._ensure_connected()
        payload = _coerce_bytes(data)
        with self._send_lock:
            self._send_all(payload)
        self._debug_io("Sent", payload)
        return len(payload)

    def sendline(self, data=b"") -> int:
        return self.send(_coerce_bytes(data) + b"\n")

    def _recv_more(self, deadline: Optional[float] = None) -> None:
        chunk = self._recv_chunk(deadline=deadline)
        if not chunk:
            raise EOFError("remote connection closed while receiving data")
        self._buffer.extend(chunk)
        self._debug_io("Received", chunk)

    def _recv_chunk(
        self,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
    ) -> Optional[bytes]:
        self._ensure_connected()
        while True:
            if not self._wait_for_socket_data(stop_event=stop_event, deadline=deadline):
                return None
            try:
                chunk = self._socket.recv(4096)
            except BlockingIOError:
                continue
            except OSError as exc:
                _raise_for_socket_error(exc, sending=False)
            if not chunk:
                raise EOFError("remote connection closed while receiving data")
            return chunk

    def _send_all(self, payload: bytes) -> None:
        if not payload:
            return

        view = memoryview(payload)
        total_sent = 0
        while total_sent < len(view):
            if not self._wait_for_socket_writable():
                raise EOFError("remote connection closed while sending data")
            try:
                sent = self._socket.send(view[total_sent:])
            except BlockingIOError:
                continue
            except OSError as exc:
                _raise_for_socket_error(exc, sending=True)
            if sent == 0:
                raise EOFError("remote connection closed while sending data")
            total_sent += sent

    def _open_socket(self, timeout=None) -> socket.socket:
        deadline = self._deadline_from_timeout(timeout)
        infos = self._resolve_addresses(deadline=deadline)
        if not infos:
            raise OSError(f"no addresses found for {self.host}:{self.port}")

        last_error = None
        for family, socktype, proto, _, sockaddr in infos:
            sock = socket.socket(family, socktype, proto)
            try:
                sock.setblocking(False)
                err = sock.connect_ex(sockaddr)
                if err not in _CONNECT_SUCCESS_ERRNOS and err not in _CONNECT_IN_PROGRESS_ERRNOS:
                    raise OSError(err, os.strerror(err))
                if err not in _CONNECT_SUCCESS_ERRNOS:
                    self._wait_for_socket(sock=sock, writable=True, deadline=deadline)
                    err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if err not in _CONNECT_SUCCESS_ERRNOS:
                        raise OSError(err, os.strerror(err))
                return sock
            except KeyboardInterrupt:
                sock.close()
                raise
            except BaseException as exc:
                sock.close()
                last_error = exc

        if last_error is None:
            raise OSError(f"failed to connect to {self.host}:{self.port}")
        raise last_error

    def _resolve_addresses(self, deadline: Optional[float]):
        outcome = {}
        done = threading.Event()

        def resolver() -> None:
            try:
                outcome["infos"] = socket.getaddrinfo(
                    self.host,
                    self.port,
                    0,
                    socket.SOCK_STREAM,
                )
            except BaseException as exc:
                outcome["error"] = exc
            finally:
                done.set()

        thread = threading.Thread(target=resolver, name="pwn-remote-resolve", daemon=True)
        thread.start()

        while True:
            timeout = self._next_wait_timeout(deadline)
            if done.wait(timeout):
                break

        error = outcome.get("error")
        if error is not None:
            raise error
        return outcome.get("infos", [])

    @staticmethod
    def _deadline_from_timeout(timeout) -> Optional[float]:
        if timeout is None:
            return None
        return time.monotonic() + float(timeout)

    @staticmethod
    def _next_wait_timeout(deadline: Optional[float]) -> float:
        if deadline is None:
            return _SOCKET_POLL_INTERVAL
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("timed out")
        return min(_SOCKET_POLL_INTERVAL, remaining)

    def _wait_for_socket_data(
        self,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
    ) -> bool:
        return self._wait_for_socket(readable=True, stop_event=stop_event, deadline=deadline)

    def _wait_for_socket_writable(self, stop_event: Optional[threading.Event] = None) -> bool:
        return self._wait_for_socket(writable=True, stop_event=stop_event)

    def _wait_for_socket(
        self,
        *,
        sock: Optional[socket.socket] = None,
        readable: bool = False,
        writable: bool = False,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
    ) -> bool:
        current_socket = getattr(self, "_socket", None)
        target = current_socket if sock is None else sock
        while True:
            if target is current_socket and self._closed:
                return False
            if stop_event is not None and stop_event.is_set():
                return False

            timeout = self._next_wait_timeout(deadline)
            try:
                ready_read, ready_write, _ = select.select(
                    [target] if readable else [],
                    [target] if writable else [],
                    [],
                    timeout,
                )
            except (OSError, ValueError):
                if target is current_socket and self._closed:
                    return False
                if stop_event is not None and stop_event.is_set():
                    return False
                raise

            if ready_read or ready_write:
                return True

    def recv(self, numb: int = 4096, timeout=None) -> bytes:
        count = int(numb)
        if count < 0:
            raise ValueError("recv() numb must be >= 0")
        if count == 0:
            return b""

        deadline = self._deadline_from_timeout(timeout)
        with self._recv_lock:
            if not self._buffer:
                try:
                    self._recv_more(deadline=deadline)
                except socket.timeout:
                    return b""

            result = bytes(self._buffer[:count])
            del self._buffer[:count]
            return result

    def recvn(self, numb: int, timeout=None) -> bytes:
        count = int(numb)
        if count < 0:
            raise ValueError("recvn() numb must be >= 0")
        if count == 0:
            return b""

        deadline = self._deadline_from_timeout(timeout)
        with self._recv_lock:
            while len(self._buffer) < count:
                try:
                    self._recv_more(deadline=deadline)
                except socket.timeout:
                    # Match pwntools' behavior: keep partial data buffered and
                    # report the timeout with an empty result.
                    return b""

            result = bytes(self._buffer[:count])
            del self._buffer[:count]
            return result

    def recvuntil(self, delim, drop: bool = False, timeout=None) -> bytes:
        token = _coerce_bytes(delim)
        if not token:
            raise ValueError("recvuntil() delimiter must not be empty")

        deadline = self._deadline_from_timeout(timeout)
        with self._recv_lock:
            while True:
                index = self._buffer.find(token)
                if index != -1:
                    end = index + len(token)
                    if drop:
                        result = bytes(self._buffer[:index])
                    else:
                        result = bytes(self._buffer[:end])
                    del self._buffer[:end]
                    return result
                try:
                    self._recv_more(deadline=deadline)
                except socket.timeout:
                    return b""

    def recvline(self, keepends: bool = True, drop: Optional[bool] = None, timeout=None) -> bytes:
        if drop is not None:
            keepends = not drop
        return self.recvuntil(b"\n", drop=not keepends, timeout=timeout)

    def sendafter(self, delim, data) -> int:
        self.recvuntil(delim)
        return self.send(data)

    def sendlineafter(self, delim, data) -> int:
        self.recvuntil(delim)
        return self.sendline(data)

    def interactive(self) -> None:
        self._ensure_connected()
        stop_event = threading.Event()
        self._interactive_input_buffer.clear()
        self._interactive_input_eof = False

        with self._recv_lock:
            if self._buffer:
                self._write_stdout(bytes(self._buffer))
                self._buffer.clear()

        log.info("Switching to interactive mode")

        def receiver() -> None:
            try:
                while not stop_event.is_set():
                    chunk = self._recv_chunk(stop_event=stop_event)
                    if chunk is None:
                        break
                    self._debug_io("Received", chunk)
                    self._write_stdout(chunk)
            except EOFError:
                log.info("Got EOF while reading in interactive")
            except OSError:
                pass
            finally:
                stop_event.set()

        recv_thread = threading.Thread(target=receiver, name="pwn-remote-recv", daemon=True)
        recv_thread.start()

        try:
            while not stop_event.is_set():
                data = self._read_interactive_input()
                if data is None:
                    if not recv_thread.is_alive():
                        stop_event.set()
                        break
                    time.sleep(0.02)
                    continue
                if data == b"":
                    stop_event.set()
                    break
                try:
                    self.send(data)
                except EOFError:
                    log.info("Got EOF while sending in interactive")
                    stop_event.set()
                    break
        except KeyboardInterrupt:
            stop_event.set()
            self._write_stdout(b"\n")
        except EOFError:
            stop_event.set()
        except OSError:
            stop_event.set()
        finally:
            self.close()
            self._stop_windows_interactive_input_thread()
            recv_thread.join(timeout=0.2)

    @staticmethod
    def _write_stdout(data: bytes) -> None:
        stream = getattr(sys.stdout, "buffer", None)
        if stream is not None:
            stream.write(data)
            stream.flush()
            return
        sys.stdout.write(data.decode("utf-8", errors="replace"))
        sys.stdout.flush()

    @staticmethod
    def _debug_io(direction: str, data: bytes) -> None:
        if not data:
            return
        log.debug(f"{direction} {len(data):#x} bytes:")
        for line in _hexdump_lines(data):
            log.debug(f"    {line}")

    def _read_interactive_input(self) -> Optional[bytes]:
        if sys.platform == "win32":
            return self._read_interactive_input_windows()
        return self._read_interactive_input_posix()

    @staticmethod
    def _read_interactive_input_stream() -> bytes:
        stream = getattr(sys.stdin, "buffer", sys.stdin)
        data = stream.readline()
        if isinstance(data, str):
            return data.encode("utf-8")
        return data

    def _start_windows_interactive_input_thread(self) -> queue.Queue[object]:
        input_queue = queue.Queue()
        self._interactive_input_queue = input_queue
        self._interactive_input_thread = threading.Thread(
            target=self._queue_windows_interactive_input,
            args=(input_queue,),
            name="pwn-remote-stdin",
            daemon=True,
        )
        self._interactive_input_thread.start()
        return input_queue

    def _queue_windows_interactive_input(self, input_queue: queue.Queue[object]) -> None:
        while True:
            try:
                data = self._read_interactive_input_stream()
            except BaseException as exc:
                input_queue.put(exc)
                return
            input_queue.put(data)
            if data == b"":
                return

    def _read_interactive_input_windows(self) -> Optional[bytes]:
        stdin = getattr(sys, "stdin", None)
        if stdin is None:
            return None

        try:
            if stdin.isatty():
                import msvcrt

                if not msvcrt.kbhit():
                    return None
                return self._read_interactive_input_stream()
        except OSError:
            return None

        return self._read_interactive_input_windows_pipe()

    def _stop_windows_interactive_input_thread(self) -> None:
        self._interactive_input_thread = None
        self._interactive_input_queue = None

    @staticmethod
    def _windows_pipe_bytes_available() -> int:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        stdin = getattr(sys, "stdin", None)
        if stdin is None:
            return 0

        try:
            handle = msvcrt.get_osfhandle(stdin.fileno())
        except OSError:
            return 0

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_file_type = kernel32.GetFileType
        get_file_type.argtypes = [wintypes.HANDLE]
        get_file_type.restype = wintypes.DWORD

        peek_named_pipe = kernel32.PeekNamedPipe
        peek_named_pipe.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        peek_named_pipe.restype = wintypes.BOOL

        file_type = get_file_type(handle)
        if file_type == 0x0003:
            available = wintypes.DWORD()
            ok = peek_named_pipe(handle, None, 0, None, ctypes.byref(available), None)
            if ok:
                return int(available.value)
            return 0

        return 1

    def _read_interactive_input_windows_pipe(self) -> Optional[bytes]:
        if b"\n" in self._interactive_input_buffer:
            return self._drain_interactive_input_line()

        if self._interactive_input_eof:
            if self._interactive_input_buffer:
                data = bytes(self._interactive_input_buffer)
                self._interactive_input_buffer.clear()
                return data
            return b""

        stdin = getattr(sys, "stdin", None)
        if stdin is None:
            return None

        available = self._windows_pipe_bytes_available()
        if available <= 0:
            return None

        try:
            chunk = os.read(stdin.fileno(), available)
        except OSError:
            return None

        if not chunk:
            self._interactive_input_eof = True
            if self._interactive_input_buffer:
                data = bytes(self._interactive_input_buffer)
                self._interactive_input_buffer.clear()
                return data
            return b""

        self._interactive_input_buffer.extend(chunk)
        if b"\n" in self._interactive_input_buffer:
            return self._drain_interactive_input_line()
        return None

    def _drain_interactive_input_line(self) -> bytes:
        newline = self._interactive_input_buffer.index(b"\n") + 1
        data = bytes(self._interactive_input_buffer[:newline])
        del self._interactive_input_buffer[:newline]
        return data

    def _read_interactive_input_posix(self) -> Optional[bytes]:
        import select

        ready, _, _ = select.select([sys.stdin], [], [], 0)
        if not ready:
            return None

        return self._read_interactive_input_stream()


def remote(host: str, port: int, *args, **kwargs) -> RemoteConnection:
    return RemoteConnection(host, port, *args, **kwargs)
