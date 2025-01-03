with open('flag.cimg', 'rb') as f:
    data = f.read(2786)

data= bytearray(data)
index = data.find(b"\xff\xff\xff\x00\x00")
i = 0
j = 0
k = 0
while index != -1:
    data[index + 3] = k*7
    data[index + 4] = i*8
    index = data.find( b"\xff\xff\xff\x00\x00", index + 4)
    j += 1
    k=j % 2
    i = j//2
with open('input.bin', 'wb') as f:
    f.write(data)