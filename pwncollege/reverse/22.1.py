import os
bc=b"\x01\x02\x04\x08\x10\x20\x40\x80"

for arg1 in bc:
    op = bc[0]
    arg2=0xff
    c=bytearray()
    c+=(arg1.to_bytes(1, "little") + arg2.to_bytes(1, "little")+op.to_bytes(1, "little"))
    print(c, flush=True)
    # display the bytes
    fd = open("ttt-raw","wb+")
    fd.write(c)
    fd.close()
    os.system("cat ttt-raw | /challenge/babyrev_level22.1")