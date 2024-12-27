from pwn import *
from Crypto.Util.number import getPrime, bytes_to_long
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def decrypt_cbc(ciphertext, key):

    cipher = AES.new(key, AES.MODE_CBC)
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext)

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff
g = 2
b = 12345
A = 0x806ccacbee7efec8cda0d6fa8bcd3cf7f8a26180da5fdecb6f77a71b69ef120233b79220a4a87a5c7e5fa770c0ef8a1336f15f889f36ef4b4c30181d3a65974fb1fb020cb1ba94ce9f08fdf542b43c8f2fbd99d12af3fdff83fe301d756b0cfec15b7295f2c741207e6a70ff4b998987fac9a9bf59d19431babee7590ff123bee94df1ea2289d88084e05f364fa431c53a62095ad97c5a4f1bb415a343227175fb7d4e98e7236ee7aac2fce04dbd098ccb449e71341a3918e2723381403b892f5261bbf2922d7686cedc026a2b512fdb42f516a5ba324645e1da5047d9a5007f3fb8162820882f4aab52a3bc2455c09bda5f6c662f986c3ef6ee99a14742da19
b = 12345
B = pow(g, b, p)

hex(B)

s = pow(A,b, p)
hex(s)
key = s.to_bytes(256, "little")[:16]
cipher = AES.new(key=key, mode=AES.MODE_CBC)
enflag = b"8rpl0++qJFDj+cPINkHZPpKPYiGtEXhZXNCw7xik7+hFe6QM7vKqw5+Qo+kA1PB6twOajQIwlxr2vY5A3P+Jfh/vCfZM96IrLaURcKpAlp4="
enflag = b64decode(enflag)
decrypt_cbc(enflag, key)
