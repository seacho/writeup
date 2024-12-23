from pwn import *
context.arch = 'aarch64'
p = process('/challenge/run')
all = p.recv()
print(all.decode())

asm_bytes = asm("""
movz x0, #0x0040, lsl #16     // Load upper 16 bits of 0x404000
movk x0, #0x4000              // Load lower 16 bits to complete 0x404000
ldp x1, x2, [x0]              // Load values from 0x404000 and 0x404008
stp x1, x2, [x0, #16]         // Store values to 0x404010 and 0x404018

  """)
p.send(asm_bytes)
p.stdin.close()
p.interactive()