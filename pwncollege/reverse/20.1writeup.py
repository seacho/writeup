d=b'\x9f\xcd\xdcl\xd5\x0fB\x8e\xa3H&\x11*kM\xba\x94a-\xf2n\x14\x1c2O\x84&Q'
e=b"\xbc\x40\x58\xcc\x30\xbc\xec\xdd\x8c\x21\x36\x16\xb3\x16\x4a\x2f\xb1\x17\xe8\xe1\x7a\x8b\xbe\x2d\x58\x48\x68\x71"
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