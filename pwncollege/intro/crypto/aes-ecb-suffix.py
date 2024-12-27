
from pwn import *  #ÒýÈëpwntools
from base64 import b64encode


valid_ascii = (
    list(range(48, 58))+
    list(range(65, 91))+
    list(range(97, 123))+
    [45, 46, 95,  123, 125]
)

context(os='linux',arch='AMD64',log_level='debug')        

p = process('/challenge/run')

def encryascii(tmp_flag):

    p.recvline(b'Choice?')
    p.sendline(b'1')
    p.recvuntil(b'Data?')
    p.sendline(tmp_flag)
    p.recvuntil(b'Result:')
    data=p.recvline().strip()
    return data

def encrypt_flag_char(length):
    p.recvline(b'Choice?')
    p.sendline(b'2')          
    p.recvuntil(b'Length?')
    p.sendline(str(length).encode()) 
    p.recvuntil(b'Result:')
    return p.recvline().strip() 

# encryascii(len(valid_ascii)) 

flag = ''
for length in range(57):
    encry_chr = encrypt_flag_char(length + 1)
    for i in valid_ascii:
        tmp = chr(i) + flag
        enc_data = encryascii(tmp)
        if enc_data == encry_chr:      
            flag = tmp         
            print(f"Found character {tmp} at index {length}")
            break

    if len(flag) <= length:
        assert(0)


print(f"the flag {flag}")
            