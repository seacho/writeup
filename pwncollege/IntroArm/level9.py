from pwn import *
context.arch = 'aarch64'
p = process('/challenge/run')
all = p.recv()
print(all.decode())

asm_bytes = asm("""
// Assume stack contains 8 QWORDs at the top before this code executes
mov x9, 0           // Initialize sum (x9 = 0)

ldp x0, x1, [sp], #16  // Pop first two QWORDs into x0, x1; increment SP by 16
add x9, x9, x0         // Add x0 to the sum
add x9, x9, x1         // Add x1 to the sum

ldp x0, x1, [sp], #16  // Pop next two QWORDs into x0, x1; increment SP by 16
add x9, x9, x0         // Add x0 to the sum
add x9, x9, x1         // Add x1 to the sum

ldp x0, x1, [sp], #16  // Pop next two QWORDs into x0, x1; increment SP by 16
add x9, x9, x0         // Add x0 to the sum
add x9, x9, x1         // Add x1 to the sum

ldp x0, x1, [sp], #16  // Pop last two QWORDs into x0, x1; increment SP by 16
add x9, x9, x0         // Add x0 to the sum
add x9, x9, x1         // Add x1 to the sum

mov x0, 8              // Set divisor (8)
udiv x9, x9, x0        // Compute average: x9 = x9 / x0

sub sp, sp, #8         // Decrement SP to create space for the result
str x9, [sp]           // Push the result back onto the stack

  """)
p.send(asm_bytes)
p.stdin.close()
p.interactive()