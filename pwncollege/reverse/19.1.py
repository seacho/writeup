#import idc
#addr = 0x4020
#size = 0x2A9
#bytes_data = idc.get_bytes(addr, size)
bytes_data = b" \xb8\x10@\x04\x00@@\x00@\x08\x00@\x00\x08@\x00@@\x00\x04 \x08\x10 0\x04 |@ \x0c\x08 \x02 \x10\x10 @ \x00 R\x10 \x00\x08\x02\x08  h \x80 \x02 5 \x80 \x18@\x04\x00@@\x00@\x08\x00 \x01@\x10\x01@ K @ \x00 E @ \x00 Y @ \x00 : @ \x00   @ \x00 \x05\x08 \x01\x04\x01 \x01@\x00\x08@\x00@@\x00\x04@\x04\x00@@\x00@\x08\x00 0@ \x0e\x08 \x00\x04\x01  @\x00\x08@\x00@@\x00\x04 \x01\x10 \x01@\x10\x01@ I @ \x00 N @ \x00 C @ \x00 O @ \x00 R @ \x00 R @ \x00 E @ \x00 C @ \x00 T @ \x00 ! @ \x00 \n @ \x00 \x0b\x08 \x01\x04\x01 \x01 \x01\x04\x01\x00\x04\x10\x08\x04\x10\x08@ \xff \x10 \x04\x10 @@\x04\x00@@\x00\x04\x04\x04\x04@@\x02@\x04@\x00@@\x00\x04 f \x80 \x01 \xff \x10 \x08 \x00 \x02 \x08 T \x80 \x01@\x08 @\x00\x10 \x01@\x10\x01@ C @ \x00 O @ \x00 R @ \x00 R @ \x00 E @ \x00 C @ \x00 T @ \x00 ! @ \x00   @ \x00 Y @ \x00 o @ \x00 u @ \x00 r @ \x00   @ \x00 f @ \x00 l @ \x00 a @ \x00 g @ \x00 : @ \x00 \n @ \x00 \x14\x08 \x01\x04\x01 \x01 /  \x80\x08\x08 \x08 f  \x81\x08\x08 \x08 l  \x82\x08\x08 \x08 a  \x83\x08\x08 \x08 g  \x84\x08\x08 \x08 \x00  \x85\x08\x08 \x08 \x80\x04 \x00@\x01 \x02 \x00@\x10\x01@ \xff\x08 \x00\x04\x10 \x04\x01   \x00@\x10\x01@ \x00\x08\x10 \x08 \x01\x04\x01 \x01 \x00\x04\x01\x00\x04 q  z\x08\x08 \x08 \xf9  {\x08\x08 \x08 \xb4  |\x08\x08 \x08 \xa5  }\x08\x08 \x08 \xed  ~\x08\x08 \x08 Z  \x7f\x08\x08 \x08 a  \x80\x08\x08 \x08 \xaa  \x81\x08\x08 \x08 \x8c  \x82\x08\x08 \x08 '  \x83\x08\x08 \x08 \xf8  \x84\x08\x08 \x08 \xdf  \x85\x08\x08 \x08 \xa3  \x86\x08\x08 \x08 \xf2  \x87\x08\x08 \x08 \x15\x10"
def describe_register(rg):
    i = 0
    while(rg != 0):
        rg >>= 1
        i+=1
    #return "Nsicbdaf"[i]
    return "Nsfacidb"[i]
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
    if (rg & 0x02 != 0):
        print("open")
    if (rg & 0x08 != 0):
        print("read_code")
    if (rg & 0x20 != 0):
        print("read_memory")
    if (rg & 0x1 != 0):
        print("write")
    if (rg & 10 != 0):
        print("sleep")
    if (rg & 0x04 != 0):
        print("exit")
    
def cmp_print(rg, value):
    print("[s] CMP %c %c" % (describe_register(rg), describe_register(value)))
def disass(a):
    byte_length = len(a)
    i=0
    while i < byte_length:
        op = a[i]
        print("%4x:%2x %2x %2x  " % (i, a[i], a[i+1], a[i+2]),end ="")
        if(op == 0x80):#jmp
            jmp_print(a[i+2], a[i+1])
        elif(op == 0x40):
            stk_print(a[i+2], a[i+1])
        elif(op == 0x08):
            stm_print(a[i+2], a[i+1])
        elif(op == 0x10):
            add_print(a[i+2], a[i+1])
        elif(op == 0x20):
            imm_print(a[i+2], a[i+1])
        elif(op == 0x04):
            ldm_print(a[i+2], a[i+1])
        elif(op == 0x01):
            sys_print(a[i+2], a[i+1])
        elif(op == 0x02):
            cmp_print(a[i+2], a[i+1])
        i+=3



disass(bytes_data)