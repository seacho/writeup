from Crypto.Util.Padding import pad

from base64 import b64decode, b64encode

# ��ȡ���ĺ� IV
ciphertext_b64 = "TASK: 1IoRmcj6fCFulll0vzq+WgLoCJ/Zw65HfzA+d63tOn4="  # ���ṩ������
ciphertext = b64decode(ciphertext_b64[6:])
iv = bytearray(ciphertext[:16])  # ��ȡ IV
encrypted_message = ciphertext[16:]  # ��ȡ����

# ԭʼ���ĺ�Ŀ������
original_plaintext = b"sleep\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
target_plaintext = b"flag\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"

# ���� delta
delta = bytes(o ^ t for o, t in zip(original_plaintext, target_plaintext))

# �޸� IV
for i in range(len(delta)):
    iv[i] ^= delta[i]

# �����µ�����
new_ciphertext = bytes(iv) + encrypted_message
print(f"TASK: {b64encode(new_ciphertext).decode()}")