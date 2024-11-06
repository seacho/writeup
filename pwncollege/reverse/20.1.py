import idc
addr = 0x4020
size = 0x2AC
bytes_data = idc.get_bytes(addr, size)
def describe_register(rg):
    i = 0
    while(rg != 0):
        rg >>= 1
        i+=1
    #return "Nbidacfd"[i]
    return "Ncdabisf"[i]
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
    if (rg & 0x20 != 0):
        print("open")
    if (rg & 0x08 != 0):
        print("read_code")
    if (rg & 0x02 != 0):
        print("read_memory")
    if (rg & 0x10 != 0):
        print("write")
    if (rg & 0x01 != 0):
        print("sleep")
    if (rg & 0x04 != 0):
        print("exit")
    
def cmp_print(rg, value):
    print("[s] CMP %c %c" % (describe_register(rg), describe_register(value)))
def disass(a):
    byte_length = len(a)
    i=0
    while i < byte_length:
        op = a[i + 2]
        print("%4x %4x:%2x %2x %2x  " % (int(i/3), i, a[i], a[i+1], a[i+2]),end ="")
        if(op == 0x80):
            imm_print(a[i+1], a[i])
        elif(op == 0x04):
            add_print(a[i+1], a[i])
        elif(op == 0x10):
            stk_print(a[i+1], a[i])
        elif(op == 0x40):
            stm_print(a[i+1], a[i])
        elif(op == 0x02):
            ldm_print(a[i+1], a[i])
        elif(op == 0x08):
            cmp_print(a[i+1], a[i])
        elif(op == 0x20):#jmp
            jmp_print(a[i+1], a[i])
        elif(op == 0x01):
            sys_print(a[i+1], a[i])
        i+=3
disass(bytes_data)