from Crypto.Cipher import AES
import base64

def decrypt_ecb(ciphertext_b64, key_b64):
    key = base64.b64decode(key_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)

    # Removing padding
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]

    return plaintext.decode('utf-8')

key_b64 = "uJORuygOdY9d69+Z6QYlDQ=="
secret_ciphertext_b64 = "955EHOcMIjgo4k7ZkX9GQeePsAz9S0vTVqUBIlx4bvY8F6Odpr4qCeqJau2v0kiWZO22PKBs9t7QE5+CxzT6bA=="
decrypted_secret = decrypt_ecb(secret_ciphertext_b64, key_b64)
print(decrypted_secret)