from pwn import *
context.arch = 'aarch64'
p = process('/challenge/run')
all = p.recv()
print(all.decode())

asm_bytes = asm("""
fib:
stp     x29, x30, [sp, #-0x30]!
mov     x29, sp
str     x19, [sp, #0x10]
str     w0, [sp, #0x2c]
ldr     w0, [sp, #0x2c]
cmp     w0, #0
b.ne    lab1

mov     x0, #0
b       lab3
lab1:
ldr     w0, [sp, #0x2c]
cmp     w0, #1
b.ne    lab2
mov     x0, #1
b       lab3
lab2:
ldr     w0, [sp, #0x2c]
sub     w0, w0, #1
bl      fib
mov     x19, x0
ldr     w0, [sp, #0x2c]
sub     w0, w0, #2
bl      fib
add     x0, x19, x0
lab3:
ldr     x19, [sp, #0x10]
ldp     x29, x30, [sp], #0x30
ret

""")
p.send(asm_bytes)
p.stdin.close()
p.interactive()
