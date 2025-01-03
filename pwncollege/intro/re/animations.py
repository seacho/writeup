with open('/challenge/flag.cimg', 'rb') as f:
    data = f.read()

data= bytearray(data)
data = data.replace(b"\x06\x00\x01\x07\x00\x93\x30\x0b\x00", b"")
data = data.replace(b"\x37\x2c", b"\xbd\x0e")

with open('input.bin', 'wb') as f:
    f.write(data)