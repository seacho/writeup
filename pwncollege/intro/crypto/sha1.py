#!/opt/pwn.college/python

import hashlib
import os
from base64 import b64encode
from Crypto.Hash.SHA256 import SHA256Hash





challenge ="bcba72"
print(f"Got challenge {challenge}")
i = 0
while True:
    sha256 = hashlib.sha256(i.to_bytes(256, "little").strip(b"\x00")).hexdigest()
    if i % 1000000 == 0:
        print(f"Compare i {i} sha256[:6] {sha256[:6]} to {challenge}")
    if sha256[:6] == challenge:
        print(i)
        break
    i += 1

ans = 45301273
b64encode(ans.to_bytes(256, "little").strip(b"\x00"))