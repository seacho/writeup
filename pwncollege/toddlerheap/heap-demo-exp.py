from pwn import *

p = process("./heap-demo")
for i in range(8):
    p.sendline(f"malloc {i} 128")

for i in range(8):
    p.sendline(f"free {i}")
