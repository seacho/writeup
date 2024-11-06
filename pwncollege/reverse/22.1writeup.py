'''
srand的固定值，所以随机是固定的通过不断的测试得到部分op reg syscall 
op :0x04:JMP
    0x08:IMM
    0x20:STK
    0x80:SYS
sys:0x01:read_code
    0x02:read_mem
    0x04,0x20: return
    0x40:exit
    0x10:sleep
    0x08:open
    0x80:write
reg:0x01:NULL
    0x04:i
    0x80:a
    0x08:c
    0x40:b

'''

def getarg(arg):
    if arg[0:2] == "0x":
        return int(arg, 16).to_bytes(1, "little")
    if arg[0] == "*":
        arg=arg[1:]

    reg="Nsdbfica"
    if reg.find(arg) != -1:
        if arg == "a":
            ireg = 0x80
        elif arg == "c":
            ireg = 0x08
        elif arg == "N":
            ireg = 0x00
        elif arg == "b":
            ireg = 0x40
        else:
            assert(False)
        return ireg.to_bytes(1, "little")
    elif arg == "open":
        return b"\x08"
    elif arg == "read_memory":
        return b"\x02" #
    elif arg == "write":
        return b"\x80"
    elif arg == "exit":
        return b"\x40"
    return None
def assembly(ass):
    if ass == "":
        return b""
    bc = bytearray()
    ass = ass.split(" ")
    if(ass[0] == "IMM"):
        bc += b"\x08" #
    elif(ass[0] == "STK"):
        bc += b"\x20"
    elif(ass[0] == "SYS"):
        bc += b"\x80"
    arg=bytearray()
    for i in ass:
        c = getarg(i)
        if c != None:
            arg = arg + c
    assert(len(arg)==2)
    bc = arg + bc

    return bc
c = bytearray()
f = open("/home/hacker/22.1.asm", "r")
asm = f.read()
asm = asm.split("\n")
for i in asm:
    c+=assembly(i)

c += b"\x80\x23\x22"
print(c)
# display the bytes
fd = open("/home/hacker/ttt-raw","wb+")
fd.write(c)
fd.close()

import os
ret = os.system("cat /home/hacker/ttt-raw | /challenge/babyrev_level22.1")

print("ret: %d"%int(ret/256))
