from Crypto.Cipher import AES
import base64

def decrypt_cbc(ciphertext_b64, key_b64):
    key = base64.b64decode(key_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    cipher = AES.new(key, AES.MODE_CBC)
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext)


key_b64 = "balS1x/2jowFe727sfQ5Qw=="
secret_ciphertext_b64 = "yHgXXUuLQ0TKY50+K+qulGsmGEwYg1xNIUm2GADzgvWvus4J6ySF+l4X1SpsnxpZhQOtL6OGWPPggaz0DYkP7sGXtCpRKD9yVAc5FNhjjCc="
decrypted_secret = decrypt_cbc(secret_ciphertext_b64, key_b64)
