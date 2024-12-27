from pwn import *
from Crypto.Util.strxor import strxor

p = process("/challenge/run")
p.recvuntil(b"Challenge number")
i = 0
while True:
    i+=1
    if p.poll() == 0:
        break
    p.recvuntil(b"- Encrypted String: ")
    en = p.recvuntil(b"\n")[:-1]
    p.recvuntil(b"- XOR Key String: ")
    key = p.recvuntil(b"\n")[:-1]   
    de = strxor(en, key)
    p.sendline(de)
    sleep(0.1)

print(p.clean().decode())




for i in range(len(s)):
    print(chr(ord(s[i]) ^ ord(key[i])), end="")