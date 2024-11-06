a = [
0x0F1,
0x0D0,
0x65,
0x66,
0x5C,
0x61,
0x0F0,
0x57,
0x94,
0x1C,
0x52,
0x6E,
0x76,
0x9D,
0x0D2,
0x18,
0x0DB,
0x0E2,
0x8E,
0x56,
0x0E6,
0x19,
0x0C0,
0x3,
0x0E6,
0x0C7,
0x0FB,
0x8D,
0x3E,
0x76,
0x0E7,
0x0C1,
0x75,
0x77,
0x4D,
0x7F,
0x0EB,
0x41
]


dd = a[16]
a[16] = a[19]
a[19] = dd



c = bytearray()
for i in range(0, 38):
    if (i % 6 == 0):
        xor = 0x14
    elif (i % 6 == 1):
        xor = 0x05
    elif (i % 6 == 2):
        xor = 0x09
    elif (i % 6 == 3):
        xor = 0xc6
    elif (i % 6 == 4):
        xor = 0xb8
    elif (i % 6 == 5):
        xor = 0xb5
    a[i]=(a[i] ^ xor)

for i in range(0, 38):
    if (i % 5 == 0):
        xor = 0xea
    elif (i % 5 == 1):
        xor = 0xe9
    elif (i % 5 == 2):
        xor = 0x63
    elif (i % 5 == 3):
        xor = 0x9e
    elif (i % 5 == 4):
        xor = 0xe9
    a[i]=(a[i] ^ xor)
for i in range(0, 19):
    dd= a[i]
    a[i]=a[37-i]
    a[37-i] = dd

dd = a[23]
a[23] = a[24]
a[24] = dd
for i in range(0, 38):
    if (i % 2 == 0):
        xor = 0x46
    elif (i % 2 == 1):
        xor = 0x75
    c+=(a[i] ^ xor).to_bytes(1, "little")

c.reverse()
dd= c[2]
c[2]=c[35]
c[35] = dd

print(c)