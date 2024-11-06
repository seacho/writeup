c=b"\xbb\xf8\x8d\xb4\x84\x19\xac\x57\x00\xd6\x80\x24"

print(c)
# display the bytes
fd = open("ttt-raw","wb+")
fd.write(c)
fd.close()

import os
os.system("cat ttt-raw | /challenge/babyrev_level19.0")