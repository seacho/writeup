from pwn import *
context.arch = 'aarch64'
p = process('/challenge/run')
all = p.recv()
print(all.decode())

asm_bytes = asm("""
b 0x40                     // Relative jump to the instruction at offset 0x40

.space 60                // Reserve 0x40 bytes for space, ensuring the jump lands correctly
                         // (This effectively ensures the code starts at 0x40 from the current position)

ldr x1, [sp]               // Load the top value from the stack into x1
ldr x2, =0x403000          // Load the absolute address 0x403000 into x2
br x2                      // Jump to the address in x2

  """)
p.send(asm_bytes)
p.stdin.close()
p.interactive()