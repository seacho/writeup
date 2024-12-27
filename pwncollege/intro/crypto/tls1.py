import base64
import json
import os
import re
from Crypto.Cipher import AES
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey import RSA
from Crypto.Random.random import getrandbits
from Crypto.Util.Padding import pad, unpad

b = getrandbits(2048)
g = 2
p = None
A = None
d = None
e = None
n = None
name = None
user_key = RSA.generate(1024)
pat0 = re.compile(r".*p: 0x(.*)\n")
pat1 = re.compile(r".*root key d: 0x(.*)\n")
pat2 = re.compile(r".*root certificate \(b64\): (.*)\n")
pat3 = re.compile(r".*name: (.*)\n")
pat4 = re.compile(r".*A: (.*)\n")
pat5 = re.compile(r".*secret ciphertext \(b64\): (.*)\n")
r_pipe0, w_pipe0 = os.pipe()
r_pipe1, w_pipe1 = os.pipe()

pid = os.fork()

if pid == -1:
    print("Error fork.")
    exit(1)

if pid == 0:
    os.close(w_pipe0)
    os.close(r_pipe1)

    os.dup2(r_pipe0, 0)
    os.close(r_pipe0)

    os.dup2(w_pipe1, 1)
    os.close(w_pipe1)

    os.execv("/challenge/run", ["/challenge/run"])
    print("Error execv.")
    exit(1)

os.close(r_pipe0)
os.close(w_pipe1)

output = os.fdopen(r_pipe1, "r")
input = os.fdopen(w_pipe0, "wb")

while True:
    line = output.readline()
    print(line)
    m = pat0.match(line)
    if m:
        p = int(m.group(1), 16)
        print(f"p = {p}")
    m = pat1.match(line)
    if m:
        d = int(m.group(1), 16)
        print(f"d = {d}")
    m = pat2.match(line)
    if m:
        cert = base64.standard_b64decode(m.group(1).encode("utf-8")).decode("utf-8")
        cert = json.loads(cert)
        e = cert["key"]["e"]
        n = cert["key"]["n"]
        print(f"cert = {cert}, e = {e}, n = {n}")
    m = pat3.match(line)
    if m:
        name = m.group(1)
    m = pat4.match(line)
    if m:
        A = int(m.group(1), 16)
        s = pow(A, b, p)
        key = SHA256Hash(s.to_bytes(256, "little")).digest()[:16]
        cipher_encrypt = AES.new(key=key, mode=AES.MODE_CBC, iv=b"\0"*16)
        cipher_decrypt = AES.new(key=key, mode=AES.MODE_CBC, iv=b"\0"*16)
        print(f"A = {A}, s = {s}, key = {key}")
        B = pow(g, b, p)
        input.write(hex(B).encode("utf-8") + b"\n")
        input.flush()
        user_certificate = {
            "name": name,
            "key": {
                "e": user_key.e,
                "n": user_key.n,
            },
            "signer": "root",
        }
        user_certificate_data = json.dumps(user_certificate).encode()
        user_certificate_hash = SHA256Hash(user_certificate_data).digest()
        user_certificate_signature = pow(int.from_bytes(user_certificate_hash, "little"), d, n).to_bytes(256, "little")
        user_signature_data = name.encode().ljust(256, b"\0") + A.to_bytes(256, "little") + B.to_bytes(256, "little")
        user_signature_hash = SHA256Hash(user_signature_data).digest()
        user_signature = pow(int.from_bytes(user_signature_hash, "little"), user_key.d, user_key.n).to_bytes(256, "little")
        user_certificate_data_cipher = cipher_encrypt.encrypt(pad(user_certificate_data, cipher_encrypt.block_size))
        user_certificate_signature_cipher = cipher_encrypt.encrypt(pad(user_certificate_signature, cipher_encrypt.block_size))
        user_signature_cipher = cipher_encrypt.encrypt(pad(user_signature, cipher_encrypt.block_size))
        input.write(base64.standard_b64encode(user_certificate_data_cipher) + b"\n")
        input.flush()
        input.write(base64.standard_b64encode(user_certificate_signature_cipher) + b"\n")
        input.flush()
        input.write(base64.standard_b64encode(user_signature_cipher) + b"\n")
        input.flush()
    m = pat5.match(line)
    if m:
        flag = unpad(cipher_decrypt.decrypt(base64.standard_b64decode(m.group(1).encode("utf-8"))), cipher_decrypt.block_size)
        print(flag)
        break