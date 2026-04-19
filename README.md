# Minimal pwntools-compatible package

This package is a small `pwntools`-compatible implementation built for
`windows`. It does not aim to fully replace upstream
`pwntools`; it only implements some basic functions.

Implemented features:

- `from pwn import *`
- `context.clear(...)`
- `remote(...)`
- `listen(...)`
- `send`, `sendline`, `sendafter`, `sendlineafter`
- `recv`, `recvn`, `recvline`, `recvuntil`
- `interactive`
- `p32`, `p64`, `u32`, `u64`
- `cyclic`
- `flat`
- `log.info`, `success`, `info`

Install from this directory:

```bash
pip install .
```

Editable install:

```bash
pip install -e .
```

Example:

```python
from pwn import *

context.clear(arch="amd64", os="windows", log_level="debug")
io = remote("127.0.0.1", 31337)
io.sendline(cyclic(32) + p64(0x4141414141414141))
io.interactive()
```

Reverse shell style listener:

```python
from pwn import *

context.clear(arch="amd64", os="windows", log_level="debug")
sh = listen(12001)
sh.interactive()
```
