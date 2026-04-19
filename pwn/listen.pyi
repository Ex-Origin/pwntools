from .remote import RemoteConnection


class ListenConnection(RemoteConnection):
    bindaddr: str
    lhost: str
    lport: int
    rhost: str | None
    rport: int | None
    timeout: object

    def __init__(self, port: int = ..., bindaddr: str = ..., fam=..., typ=..., *args, **kwargs) -> None: ...
    def wait_for_connection(self, timeout=...) -> "ListenConnection": ...
    def close(self) -> None: ...


def listen(port: int = ..., bindaddr: str = ..., fam=..., typ=..., *args, **kwargs) -> ListenConnection: ...
