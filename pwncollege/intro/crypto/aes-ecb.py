
from pwn import *  #ÒýÈëpwntools

d = []
valid_ascii = (
    list(range(48, 58))+
    list(range(65, 91))+
    list(range(97, 123))+
    [45, 46, 95, 173, 175, 123, 125]
)

context(os='linux',arch='AMD64',log_level='debug')        

p = process('/challenge/run')

def encryascii(number):
    for i in range(number):
        p.recvline(b'Choice?')
        p.sendline(b'1')
        p.recvuntil(b'Data?')
        p.sendline(chr(valid_ascii[i]))
        p.recvuntil(b'Result:')
        data=p.recvline().strip()
        d.append((chr(valid_ascii[i]),data))
        if chr(valid_ascii[i]) == '_':
            break

def encrypt_flag_char(index,length):
    p.recvline(b'Choice?')
    p.sendline(b'2')          
    p.recvline(b'Index?')
    p.sendline(str(index).encode()) 
    p.recvuntil(b'Length?')
    p.sendline(str(length).encode()) 
    p.recvuntil(b'Result:')
    return p.recvline().strip() 

encryascii(len(valid_ascii)) 

flag = '' 
for idx in range(58):
    encry_char = encrypt_flag_char(idx, 1)
    for char, enc_data in d:
        if enc_data == encry_char:      
            flag += char         
            print(f"Found character {char} at index {idx}")
            break


print(f"the flag {flag}")

