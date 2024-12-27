
#!/usr/bin/python
from pwn import *  #引入pwntools

d = []
valid_ascii = (
    list(range(48, 58))+
    list(range(65, 91))+
    list(range(97, 123))+ 
    [45, 46, 95, 173, 175]
)
def encryascii_http(number):
    for i in range(number):
        p = remote('challenge.localhost', 80)
        query = "query='" + chr(valid_ascii[i]) + "'"
        request = b"GET /?" + query.encode() + b" HTTP/1.1\r\n"
        request += b"Host: challenge.localhost\r\n"
        request += b"Connection: close\r\n"
        request += b"\r\n"
        p.send(request)
        response = p.recvall(timeout=2)  # 设置超时，避免卡住
        response = response.decode()
        print("Full Response:")
        print(response)
        result_data = response.split('Results:</b>')[1].strip().split()[0]
        print(f"Result for {chr(valid_ascii[i])}: {result_data}")
        d.append((chr(valid_ascii[i]),result_data))
        if chr(valid_ascii[i]) == '_':
            break

def encrypt_flag_char_http(inde):
    p = remote('challenge.localhost', 80)
    query = "query=substr(flag," + str(inde) + ",1)"
    request = b"GET /?" + query.encode() + b" HTTP/1.1\r\n" 
    request += b"Host: challenge.localhost\r\n"
    request += b"Connection: close\r\n"
    request += b"\r\n"
    p.send(request)
    response = p.recvall(timeout=2) 
    response = response.decode()
    return response.split('Results:</b>')[1].strip().split()[0]
encryascii_http(len(valid_ascii)) 
flag = ''
for idx in range(58):
    encry_char = encrypt_flag_char_http(idx)
    for char, enc_data in d:
        if enc_data == encry_char:
            flag += char
            print(f"Found character {char} at index {idx}")
            break

print(f"the flag {flag}")