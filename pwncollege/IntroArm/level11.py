from pwn import *
context.arch = 'aarch64'
p = process('/challenge/run')
all = p.recv()
print(all.decode())

asm_bytes = asm("""
mov x2, 0            // Initialize sum register (x2 = 0)

loop:
    ldr x3, [x0], #8  // Load QWORD from address in x0 into x3, then increment x0 by 8
    add x2, x2, x3    // Add x3 to the sum in x2
    subs x1, x1, #1   // Decrement loop counter (x1) and update flags
    b.ne loop         // If x1 is not zero, branch back to the loop

mov x0, x2           // Move the sum from x2 into x0
  """)
p.send(asm_bytes)
p.stdin.close()
p.interactive()