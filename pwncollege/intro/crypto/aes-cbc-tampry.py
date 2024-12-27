from Crypto.Util.Padding import pad

from base64 import b64decode, b64encode

# 获取密文和 IV
ciphertext_b64 = "TASK: 1IoRmcj6fCFulll0vzq+WgLoCJ/Zw65HfzA+d63tOn4="  # 您提供的密文
ciphertext = b64decode(ciphertext_b64[6:])
iv = bytearray(ciphertext[:16])  # 提取 IV
encrypted_message = ciphertext[16:]  # 提取密文

# 原始明文和目标明文
original_plaintext = b"sleep\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
target_plaintext = b"flag\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"

# 计算 delta
delta = bytes(o ^ t for o, t in zip(original_plaintext, target_plaintext))

# 修改 IV
for i in range(len(delta)):
    iv[i] ^= delta[i]

# 构造新的密文
new_ciphertext = bytes(iv) + encrypted_message
print(f"TASK: {b64encode(new_ciphertext).decode()}")