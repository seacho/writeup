import base64
from pwn import *

def decode_base64(data):
    return base64.b64decode(data)

def encode_base64(data):
    return base64.b64encode(data).decode()

conn = process("/challenge/run")

# 已知的部分 flag
known_flag = b""
block_size = 16

while True:
    # 构造输入：使得目标字节位于块边界
    pad_length = block_size - (len(known_flag) % block_size) - 1
    crafted_input = b"A" * pad_length
    conn.sendlineafter("Data? ", encode_base64(crafted_input))
    
    # 获取密文
    ciphertext = decode_base64(conn.recvline().strip().split(b": ")[1])
    
    # 找出目标块
    target_block = len(known_flag) // block_size

    # 遍历可能的字符，尝试匹配密文
    for i in range(256):
        test_input = crafted_input + known_flag + bytes([i])
        conn.sendlineafter("Data? ", encode_base64(test_input))
        test_ciphertext = decode_base64(conn.recvline().strip().split(b": ")[1])
        
        if test_ciphertext[:(target_block + 1) * block_size] == ciphertext[:(target_block + 1) * block_size]:
            known_flag += bytes([i])
            print(f"Known flag so far: {known_flag.decode(errors='ignore')}")
            break
    else:
        # 如果循环结束没有匹配，则认为 flag 提取完成
        print("Flag extraction complete!")
        print(f"Flag: {known_flag.decode()}")
        break

# 关闭连接
conn.close()
