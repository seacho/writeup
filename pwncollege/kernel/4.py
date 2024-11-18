from pwn import *
import os
import fcntl


fd = os.open("/proc/pwncollege", 0)

old_termios = fcntl.ioctl(fd, 1337, "jksrvazoqblqfusu")

# ¹Ø±ÕÎÄ¼şÃèÊö·û
os.close(fd)
fd1 = os.open("/flag", 0)
os.sendfile(1, fd1, 0, 0x40)