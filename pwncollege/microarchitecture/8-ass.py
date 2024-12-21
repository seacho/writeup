'''
op   : op[0]
arg1 : op[1]
arg2 : op[2]
'''

def getarg(arg):
    if arg[0:2] == "0x":
        return int(arg, 16).to_bytes(1, "little")
    if arg[0] == "*":
        arg=arg[1:]
    ireg = 1
    reg="idscfab"
    if reg.find(arg) != -1:
        ireg = ireg << reg.find(arg)
        return ireg.to_bytes(1, "little")
    elif arg == "open":
        return b"\x10"
    elif arg == "read_memory":
        return b"\x02"
    elif arg == "write":
        return b"\x20"
    elif arg == "exit":
        return b"\x08"
    return None
def assembly(ass):
    if ass == "":
        return b""
    bc = bytearray()
    ass = ass.split(" ")
    if(ass[0] == "IMM"):
        op = b"\x20"
    elif(ass[0] == "ADD"):
        op = b"\x01"
    elif(ass[0] == "STK"):
        op = b"\x40"
    elif(ass[0] == "STM"):
        op = b"\x08"
    elif(ass[0] == "LDM"):
        op = b"\x80"
    elif(ass[0] == "CMP"):
        op = b"\x02"
    elif(ass[0] == "JMP"):
        op = b"\x10"
    elif(ass[0] == "SYS"):
        op = b"\x04"
    
    for i in ass:
        c = getarg(i)
        if c != None:
            bc += c

    bc.insert(0,op[0])
    return bc
c = bytearray()

asm = '''
IMM a = 0x01
IMM b = 0xff
IMM c = 0xff
SYS write d
IMM a = 0x00
IMM b = 0xff
IMM c = 0xff
SYS read_memory d
SYS exit d
'''
asm = asm.split("\n")
for i in asm:
    c+=assembly(i)

print(c)


