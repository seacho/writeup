
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

def encrypt_with_prefix(prefix):
    p.recvline(b'Choice?')
    p.sendline(b'2')
    p.recvline(b'Data?')
    p.sendline(prefix.encode())
    p.recvuntil(b'Result: ')
    result = p.recvline().strip().decode()
    base_result = base64.b64decode(result)
    first_16_chars = base_result[0:64]
    print(first_16_chars)
    return first_16_chars
flag = ""
for lengt in range(1,64):
    target_block = encrypt_with_prefix('a' * (64-lengt))
    for char in valid_ascii:
        tmp_char = chr(char)
        guess_block = encrypt_with_prefix('a' * (64-lengt) + flag + tmp_char)
        if guess_block == target_block:
            flag = flag + tmp_char
            print(f"Found character {chr(char)} at index {lengt}")
            break