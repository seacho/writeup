from pwn import *
context.arch = 'aarch64'
p = process('/challenge/run')
all = p.recv()
print(all.decode())

asm_bytes = asm("""
.global calc_avg          // Declare the function to be globally accessible

// Function: calc_avg(ptr, count)
calc_avg:
    mov x2, 0              // Initialize sum register (x2 = 0)
    mov x4, x1
loop:
    ldr x3, [x0], #8       // Load the 64-bit value from the array (ptr) into x3, increment ptr by 8
    add x2, x2, x3         // Add the value in x3 to the sum (x2)

    subs x1, x1, #1        // Decrement the count (x1) and update flags
    b.ne loop              // If count (x1) is not zero, branch to loop

    // Compute average: sum / count
    udiv x0, x2, x4       // Divide the sum (x2) by the count (x1) and store result in x0

    ret                    // Return with the result in x0
""")
p.send(asm_bytes)
p.stdin.close()
p.interactive()