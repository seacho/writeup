import base64
from pwn import *
from Crypto.Util.strxor import strxor
key_bs64 = "EGfQgN2JqFKkFugPP/7T2qExxngL6eKfL+Az4/23icnIFYLK4gNqT2xl73MuS4MyUuQ7G2vl84DD"
enflag_bs64 = "YBC+rr7mxD7BcY10aoTlr9FwqE082I7+bZlcm8vfxIOlXu68i1UwYVwjoUBjMc5BMY51bCKfpP3J"

key = base64.decodebytes(key_bs64.encode())
enflag_bs64 = base64.decodebytes(enflag_bs64.encode())

print(strxor(key, enflag_bs64))