import base64
from pwn import *
from Crypto.Util.strxor import strxor
msg = b"1234567890qwertyuiopasdfghjklzxcvbnm[];',./qwertyuiopasdf"
enmsg_bs64 = "H8QyzTRscKFRtoRzsUTMMqRZb6I4+UoVt37/cteliapSd4bUlvCic5juSXiSDMhEu081PRpyx/7i"
key = strxor(msg, base64.decodebytes(enmsg_bs64.encode()))


# key_bs64 = "EGfQgN2JqFKkFugPP/7T2qExxngL6eKfL+Az4/23icnIFYLK4gNqT2xl73MuS4MyUuQ7G2vl84DD"
enflag_bs64 = "XoFv12I1K/UN4ZB/7H3KZoNpTpQX1UQ1uSDHfO/ouo9uIYf0l53teoSWKDqoE/dDoVASJSNp4+eO"

# key = base64.decodebytes(key_bs64.encode())
enflag = base64.decodebytes(enflag_bs64.encode())

print(strxor(key, enflag))