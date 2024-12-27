#!/opt/pwn.college/python
from base64 import b64decode
from Crypto.PublicKey import RSA

# flag = open("/flag", "rb").read()
# assert len(flag) <= 256

# key = RSA.generate(2048)
# print(f"e = {key.e:#x}")
# print(f"p = {key.p:#x}")
# print(f"q = {key.q:#x}")

# ciphertext = pow(int.from_bytes(flag, "little"), key.e, key.n).to_bytes(256, "little")
# print(f"Flag Ciphertext (b64): {b64encode(ciphertext).decode()}")


e = 0x10001
p = 0xc7780df2666b09edb7127f7b3eb2d2e828265eb4581caa44a3241aed82069179f43a9ad65fb262cf7f45d4736c14c554251862ecfdeda41f54005e799a9a2e0337e6f9d0c7eca1cc696f1e4ecccc6417f6b9429bfa8a867f458c1ada4fca4dd7b270a69abc836511903d45b2aa1b542f1d720c17cdcd255bbccaf81c5fea53d7
q = 0xf8e8ccf5e750725a79a17cca70ccf20de4b7eba17947672f7905d13b9edce04e9aab13e2c8134587e49bee314a34a469180e70e9cc7bc84af1d2ea98b22bc6b8de545b3f9a2249528eeffd27d179d668322fea82852d8e2dead9373845739896f57240a380c0486abd284831105047fff9e850aae5e09585a923c66417b0cd09
ciphertext_bs4 = "LkkPoennw7wdKHc6e1oazmCgRyeurRu6Jrm86jkJnjpNxI+Nw1S3VnQ/SB13weeSXjFTYGUQh/Gm7pV6Bjhpea6rF6CRWRjlXnYYOL3/POwG/qksG/cwtIM2gOcMSIrFzJkbVs3T7BKBIh9DH8GiFYyeYf6CJQ7Thn8G2SI1eBXAfa5fNSMO5AciTX6Jm3YiU9p2dgxMCxISe/hI2TlfHkghODigNajEaWM6u6aMmw06r3cVbMAnR635H15oiF7LLQE6qqPw6M+bxE0xc4HyInLSpWpuL798xuP0bVIDb1Vz2XbxSyErRNWKyw2t2BzTobBHKF8J97Ej1167hysbTQ=="
ciphertext = b64decode(ciphertext_bs4)
i = 0
while True:
    if (i * (p-1)*(q-1) +1) % e == 0:
        break
    i+=1



d = (i * (p-1)*(q-1) +1) // e
text = pow(int.from_bytes(ciphertext, "little"), d, p*q)
text.to_bytes(256, "little")