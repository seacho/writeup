d=b'.\xfaG\xf1\xfe \x14NR\x1b\xeff1\xddXq\x11\xe8[\x17#'
e=b"\xed\x7b\x56\x2a\x5e\xeb\x72\x79\x6c\x1a\x76\xc9\x94\x06\xd3\x29\xd3\xb5\x7b\x31\x4f"
c=bytearray()
for i in range(0, len(d)):
    t = (d[i] - e[i]) & 0x000000ff
    c+=t.to_bytes(1, "little")

print(c)
# display the bytes
fd = open("ttt-raw","wb+")
fd.write(c)
fd.close()

import os
os.system("cat ttt-raw | /challenge/babyrev_level20.0")