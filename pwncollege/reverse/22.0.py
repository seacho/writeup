# bc=b"\x01\x02\x04\x08\x10\x20\x40\x80"
# c=bytearray()
# for i in bc:
#     for j in bc:
#         for k in bc:
#             c+=(i.to_bytes(1, "little") + j.to_bytes(1, "little")+k.to_bytes(1, "little"))

# print(c)
# fd = open("ttt-raw","wb+")
# fd.write(c)
# fd.close()

# import os
# os.system("cat ttt-raw | /challenge/babyrev_level21.1 > ttt.out")

# import idc
# addr = 0x5020
# size = 0x243
# bytes_data = idc.get_bytes(addr, size)
def describe_register(rg):
    i = 0
    while(rg != 0):
        rg >>= 1
        i+=1
    #return "Nbidacfd"[i]
    return "Niabdfsc"[i]
def describe_flag(rg):
    desc = ""
    if(rg & 8 != 0):
        desc += "L"
    if(rg & 2 != 0):
        desc += "G"
    if(rg & 1 != 0):
        desc += "E" 
    if(rg & 10 != 0):
        desc += "N"
    if(rg &0x4 != 0):
        desc += "Z"
    if(rg == 0 != 0):
        desc += "*"
    return desc
def jmp_print(rg, value):
    print("[j] JMP %s %c" % (describe_flag(rg),describe_register(value)))
def imm_print(rg, value):
    print("[s] IMM %c = 0x%x(%c)" % (describe_register(rg),value, value))

def stk_print(rg, value):
    print("[s] STK %c %c" % (describe_register(rg), describe_register(value)))
def stm_print(rg, value):
    print("[s] STM *%c = %c" % (describe_register(rg), describe_register(value)))
def add_print(rg, value):
    print("[s] ADD %c %c" % (describe_register(rg), describe_register(value)))
def ldm_print(rg, value):
    print("[s] LDM %c = *%c" % (describe_register(rg), describe_register(value)))
def sys_print(rg, value):
    if (rg & 0x10 != 0):
        print("open")
    if (rg & 0x20 != 0):
        print("read_code")
    if (rg & 0x04 != 0):
        print("read_memory")
    if (rg & 0x02 != 0):
        print("write")
    if (rg & 0x08 != 0):
        print("sleep")
    if (rg & 0x01 != 0):
        print("exit")
    
def cmp_print(rg, value):
    print("[s] CMP %c %c" % (describe_register(rg), describe_register(value)))
def disass(a):
    byte_length = len(a)
    i=0
    while i < byte_length:
        op = a[i]
        print("%4x %4x:%2x %2x %2x  " % (int(i/3), i, a[i], a[i+1], a[i+2]),end ="")
        if(op == 0x02):
            imm_print(a[i+1], a[i+2])
        elif(op == 0x08):
            add_print(a[i+1], a[i+2])
        elif(op == 0x20):
            stk_print(a[i+1], a[i+2])
        elif(op == 0x80):
            stm_print(a[i+1], a[i+2])
        elif(op == 0x10):
            ldm_print(a[i+1], a[i+2])
        elif(op == 0x4):
            cmp_print(a[i+1], a[i+2])
        elif(op == 0x1):#jmp
            jmp_print(a[i+1], a[i+2])
        elif(op == 0x40):
            sys_print(a[i+1], a[i+2])
        i+=3
#disass(bytes_data)

def getarg(arg):
    if arg[0:2] == "0x":
        return int(arg, 16).to_bytes(1, "little")
    if arg[0] == "*":
        arg=arg[1:]
    ireg = 1
    reg="sdbfica"
    if reg.find(arg) != -1:
        ireg = ireg << reg.find(arg)
        return ireg.to_bytes(1, "little")
    elif arg == "open":
        return b"\x80"
    elif arg == "read_memory":
        return b"\x04" #
    elif arg == "write":
        return b"\x10"
    return None
def assembly(ass):
    if ass == "":
        return b""
    bc = bytearray()
    ass = ass.split(" ")
    if(ass[0] == "IMM"):
        bc += b"\x04" #
    elif(ass[0] == "ADD"):
        bc += b"\x20"
    elif(ass[0] == "STK"):
        bc += b"\x01"
    elif(ass[0] == "STM"):
        bc += b"\x10"
    elif(ass[0] == "LDM"):
        bc += b"\x02"
    elif(ass[0] == "CMP"):
        bc += b"\x80"
    elif(ass[0] == "JMP"):
        bc += b"\x08" #
    elif(ass[0] == "SYS"):
        bc += b"\x40"
    
    for i in ass:
        c = getarg(i)
        if c != None:
            bc = c + bc

    return bc
c = bytearray()
f = open("./21.0.asm", "r")
asm = f.read()
asm = asm.split("\n")
for i in asm:
    c+=assembly(i)

c += b"\x80\x23\x22"
print(c)
# display the bytes
fd = open("ttt-raw","wb+")
fd.write(c)
fd.close()

import os
os.system("cat ttt-raw | /challenge/babyrev_level22.0")