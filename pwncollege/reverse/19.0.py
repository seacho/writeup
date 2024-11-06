import idc
addr = 0x5020
size = 0x2B2
bytes_data = idc.get_bytes(addr, size)
def describe_register(rg):
    i = 0
    while(rg != 0):
        rg >>= 1
        i+=1
    return "Nsicbdaf"[i]
def describe_flag(rg):
    desc = ""
    if(rg & 8 != 0):
        desc += "L"
    if(rg & 1 != 0):
        desc += "G"
    if(rg & 2 != 0):
        desc += "E" 
    if(rg & 4 != 0):
        desc += "N"
    if(rg &0x10 != 0):
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
    if (rg & 0x20 != 0):
        print("open %c"% (describe_register(value)))
    if (rg & 0x8 != 0):
        print("read_code %c"% (describe_register(value)))
    if (rg & 0x4 != 0):
        print("read_memory %c"% (describe_register(value)))
    if (rg & 0x10 != 0):
        print("write %c"% (describe_register(value)))
    if (rg & 1 != 0):
        print("sleep %c"% (describe_register(value)))
    if (rg & 2 != 0):
        print("exit %c"% (describe_register(value)))
    
def cmp_print(rg, value):
    print("[s] CMP %c %c" % (describe_register(rg), describe_register(value)))
def disass(a):
    byte_length = len(a)
    i=0
    while i < byte_length:
        op = a[i + 1]
        print("%4x:%2x %2x %2x  " % (i, a[i], a[i+1], a[i+2]),end ="")
        if(op == 0x10):
            imm_print(a[i], a[i+2])
        elif(op == 0x8):
            add_print(a[i], a[i+2])
        elif(op == 0x2):
            stk_print(a[i], a[i+2])
        elif(op == 0x4):
            stm_print(a[i], a[i+2])
        elif(op == 0x20):
            ldm_print(a[i], a[i+2])
        elif(op == 0x80):
            cmp_print(a[i], a[i+2])
        elif(op == 0x01):#jmp
            jmp_print(a[i], a[i+2])
        elif(op == 0x40):
            sys_print(a[i], a[i+2])
        i+=3



disass(bytes_data)