import base64
from pwn import *

def decode_base64(data):
    return base64.b64decode(data)

def encode_base64(data):
    return base64.b64encode(data).decode()

conn = process("/challenge/run")

# ��֪�Ĳ��� flag
known_flag = b""
block_size = 16

while True:
    # �������룺ʹ��Ŀ���ֽ�λ�ڿ�߽�
    pad_length = block_size - (len(known_flag) % block_size) - 1
    crafted_input = b"A" * pad_length
    conn.sendlineafter("Data? ", encode_base64(crafted_input))
    
    # ��ȡ����
    ciphertext = decode_base64(conn.recvline().strip().split(b": ")[1])
    
    # �ҳ�Ŀ���
    target_block = len(known_flag) // block_size

    # �������ܵ��ַ�������ƥ������
    for i in range(256):
        test_input = crafted_input + known_flag + bytes([i])
        conn.sendlineafter("Data? ", encode_base64(test_input))
        test_ciphertext = decode_base64(conn.recvline().strip().split(b": ")[1])
        
        if test_ciphertext[:(target_block + 1) * block_size] == ciphertext[:(target_block + 1) * block_size]:
            known_flag += bytes([i])
            print(f"Known flag so far: {known_flag.decode(errors='ignore')}")
            break
    else:
        # ���ѭ������û��ƥ�䣬����Ϊ flag ��ȡ���
        print("Flag extraction complete!")
        print(f"Flag: {known_flag.decode()}")
        break

# �ر�����
conn.close()
