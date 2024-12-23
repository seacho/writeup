from pwn import *
context.arch = 'aarch64'
p = process('/challenge/run')
all = p.recv()
print(all.decode())

asm_bytes = asm("""
stp x0, x1, [sp, #-16]!  // Push x0 and x1 onto the stack, adjust SP by -16
ldp x1, x0, [sp], #16    // Pop values from the stack into x1 and x0, adjust SP by +16

  """)
p.send(asm_bytes)
p.stdin.close()
p.interactive()