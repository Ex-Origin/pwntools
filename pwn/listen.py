"""TCP listener helpers."""

from __future__ import annotations

import socket
import threading
from typing import Optional

from .log import log
from .remote import (
    RemoteConnection,
    _SOCKET_POLL_INTERVAL,
    _normalize_socket_family,
    _normalize_socket_type,
    _set_tcp_nodelay,
)


class ListenConnection(RemoteConnection):
    """Small pwntools-like TCP listener wrapper."""

    def __init__(self, port: int = 0, bindaddr: str = "::", fam="any", typ="tcp", *args, **kwargs) -> None:
        timeout = kwargs.pop("timeout", None)
        self.timeout = timeout
        self.host = bindaddr
        self.port = int(port)
        self.bindaddr = bindaddr
        self.lhost = bindaddr
        self.lport = int(port)
        self.rhost: Optional[str] = None
        self.rport: Optional[int] = None
        self.family = None
        self.type = None
        self.protocol = None
        self.canonname = ""
        self.sockaddr = None
        self._listen_socket: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._connected_event = threading.Event()
        self._accept_error: Optional[BaseException] = None
        self._initialize_socket_state(None)
        self._open_listener(port=self.port, bindaddr=bindaddr, fam=fam, typ=typ)
        self._accept_thread = threading.Thread(
            target=self._accept_connection,
            name="pwn-listen-accept",
            daemon=True,
        )
        self._accept_thread.start()

    def _open_listener(self, *, port: int, bindaddr: str, fam, typ) -> None:
        family = _normalize_socket_family(fam)
        socktype = _normalize_socket_type(typ)
        if socktype != socket.SOCK_STREAM:
            raise NotImplementedError("listen() only supports TCP sockets")

        log.info(f"Trying to bind to {bindaddr} on port {port}")
        infos = socket.getaddrinfo(
            bindaddr,
            port,
            family,
            socktype,
            0,
            socket.AI_PASSIVE,
        )
        if not infos:
            raise OSError(f"no addresses found for {bindaddr}:{port}")

        last_error = None
        for resolved_family, resolved_type, proto, canonname, sockaddr in infos:
            listen_sock = socket.socket(resolved_family, resolved_type, proto)
            try:
                listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if resolved_family == socket.AF_INET6 and family == socket.AF_UNSPEC:
                    try:
                        listen_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    except (AttributeError, OSError):
                        pass
                listen_sock.bind(sockaddr)
                listen_sock.listen(1)
                listen_sock.settimeout(_SOCKET_POLL_INTERVAL)
                self._listen_socket = listen_sock
                self.family = resolved_family
                self.type = resolved_type
                self.protocol = proto
                self.canonname = canonname
                self.sockaddr = sockaddr
                local_address = listen_sock.getsockname()
                self.lhost = local_address[0]
                self.lport = int(local_address[1])
                log.success(f"Listening on {self.lhost}:{self.lport}")
                log.info(f"Waiting for connections on {self.lhost}:{self.lport}")
                return
            except BaseException as exc:
                listen_sock.close()
                last_error = exc

        if last_error is None:
            raise OSError(f"failed to bind to {bindaddr}:{port}")
        raise last_error

    def _accept_connection(self) -> None:
        while not self._closed:
            listen_sock = self._listen_socket
            if listen_sock is None:
                return

            try:
                client, address = listen_sock.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if self._closed:
                    return
                self._accept_error = exc
                self._connected_event.set()
                return

            if self._closed:
                client.close()
                return

            client.setblocking(False)
            _set_tcp_nodelay(client)
            self._socket = client
            self.sockaddr = address
            self.rhost = address[0]
            self.rport = int(address[1])
            self.host = self.rhost
            self.port = self.rport

            try:
                listen_sock.close()
            except OSError:
                pass
            self._listen_socket = None
            self._connected_event.set()
            log.success(f"Got connection from {self.rhost} on port {self.rport}")
            return

    def _ensure_connected(self) -> None:
        self.wait_for_connection()

    def wait_for_connection(self, timeout=None) -> "ListenConnection":
        if self._socket is not None:
            return self
        if self._accept_error is not None:
            raise self._accept_error
        if self._closed:
            raise EOFError("listen socket closed before a connection was established")

        effective_timeout = self.timeout if timeout is None else timeout
        if effective_timeout is None:
            while not self._connected_event.wait(_SOCKET_POLL_INTERVAL):
                if self._closed and self._socket is None:
                    raise EOFError("listen socket closed before a connection was established")
        else:
            if not self._connected_event.wait(float(effective_timeout)):
                raise socket.timeout("timed out")

        if self._accept_error is not None:
            raise self._accept_error
        if self._socket is None:
            if self._closed:
                raise EOFError("listen socket closed before a connection was established")
            raise socket.timeout("timed out")
        return self

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._connected_event.set()

        listen_sock = self._listen_socket
        self._listen_socket = None
        if listen_sock is not None:
            try:
                listen_sock.close()
            except OSError:
                pass

        client = getattr(self, "_socket", None)
        try:
            if client is not None:
                client.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        if client is not None:
            client.close()

        accept_thread = self._accept_thread
        self._accept_thread = None
        if accept_thread is not None and accept_thread.is_alive() and accept_thread is not threading.current_thread():
            accept_thread.join(timeout=0.2)

        if self.rhost is not None and self.rport is not None:
            log.info(f"Closed connection to {self.rhost} port {self.rport}")
        else:
            log.info(f"Closed listening socket on {self.lhost}:{self.lport}")


def listen(port: int = 0, bindaddr: str = "::", fam="any", typ="tcp", *args, **kwargs) -> ListenConnection:
    return ListenConnection(port=port, bindaddr=bindaddr, fam=fam, typ=typ, *args, **kwargs)
