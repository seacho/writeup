from pwn import *
context.arch = 'aarch64'
p = process('/challenge/run')
all = p.recv()
print(all.decode())

asm_bytes = asm("""
movz x0, #0x1337, lsl #32  // Load upper 16 bits
movk x0, #0x4000, lsl #16  // Load next 16 bits
add x0, x0, #0x4000  // Load next 16 bits
add x1, x0, #8
add x2, x0, #0x10
ldr x0, [x0]
ldr x1, [x1]
add x3, x0, x1
str x3, [x2]
  """)
p.send(asm_bytes)
p.stdin.close()
p.interactive()